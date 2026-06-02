//! Load balancer: accept on :9999, round-robin, hand the raw fd to a worker via
//! SCM_RIGHTS. Off the request path.

use std::os::raw::c_void;
use std::time::Duration;

use crate::fdpass::send_fd;
use crate::hardening;

fn env_str(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}
fn env_parse<T: std::str::FromStr>(k: &str, default: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn connect_ctrl(path: &str) -> i32 {
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return -1;
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, &b) in path.as_bytes().iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if libc::connect(fd, &addr as *const _ as *const libc::sockaddr, len) != 0 {
            libc::close(fd);
            return -1;
        }
        fd
    }
}

pub(crate) fn connect_wait(path: &str) -> i32 {
    loop {
        let fd = connect_ctrl(path);
        if fd >= 0 {
            return fd;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn make_listen(port: u16) -> i32 {
    unsafe {
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            panic!("listen socket");
        }
        let yes: i32 = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &yes as *const i32 as *const c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = port.to_be();
        addr.sin_addr = libc::in_addr { s_addr: 0 }; // INADDR_ANY
        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len) < 0 {
            panic!("bind :{port} -> {}", errno());
        }
        let secs: i32 = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            &secs as *const i32 as *const c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        libc::listen(fd, 65535);
        fd
    }
}

pub fn run() {
    hardening::ignore_sigpipe();
    let port: u16 = env_parse("PORT", 9999);
    let backends = env_str("BACKENDS", "/run/sock/api0.ctrl,/run/sock/api1.ctrl");
    if let Ok(cpu) = std::env::var("CPU") {
        if let Ok(c) = cpu.parse::<usize>() {
            hardening::set_affinity(c);
        }
    }

    let paths: Vec<String> = backends.split(',').map(|s| s.to_string()).collect();
    let mut ups: Vec<i32> = paths.iter().map(|p| connect_wait(p)).collect();
    eprintln!("[lb] conectado a {} workers, listen :{port}", ups.len());

    let listen = make_listen(port);
    let mut rr: u64 = 0;

    loop {
        let cfd = unsafe {
            libc::accept4(
                listen,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if cfd < 0 {
            let e = errno();
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                let mut pfd = libc::pollfd {
                    fd: listen,
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, -1) };
            }
            continue;
        }
        hardening::tune_tcp(cfd);

        let n = ups.len();
        let first = (rr as usize) % n;
        rr = rr.wrapping_add(1);

        let mut ok = false;
        for off in 0..n {
            let idx = (first + off) % n;
            if send_fd(ups[idx], cfd) >= 0 {
                ok = true;
                break;
            }
            // ctrl died: reconnect and retry once on the same backend
            unsafe { libc::close(ups[idx]) };
            ups[idx] = connect_ctrl(&paths[idx]);
            if ups[idx] >= 0 && send_fd(ups[idx], cfd) >= 0 {
                ok = true;
                break;
            }
        }
        let _ = ok;
        unsafe { libc::close(cfd) }; // worker now owns the fd
    }
}
