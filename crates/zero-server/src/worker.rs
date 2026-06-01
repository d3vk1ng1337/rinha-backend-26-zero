use std::os::raw::{c_int, c_void};

use zero_index::normalize::normalize;
use zero_index::search::Index;

use crate::fdpass::recv_fd;
use crate::hardening;
use crate::http::{self, Parsed};

const BUF_CAP: usize = 8192;
const MAX_EVENTS: usize = 256;

struct Conn {
    buf: [u8; BUF_CAP],
    have: usize,
}

impl Conn {
    fn new() -> Box<Conn> {
        Box::new(Conn {
            buf: [0; BUF_CAP],
            have: 0,
        })
    }
}

fn env_str(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}
fn env_parse<T: std::str::FromStr>(k: &str, default: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn epoll_add(epfd: i32, fd: i32, events: u32) {
    let mut ev = libc::epoll_event {
        events,
        u64: fd as u64,
    };
    unsafe {
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev);
    }
}
fn epoll_del(epfd: i32, fd: i32) {
    unsafe {
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
    }
}

pub(crate) fn create_ctrl_socket(path: &str) -> i32 {
    unsafe {
        if let Some(slash) = path.rfind('/') {
            let dir = std::ffi::CString::new(&path[..slash]).unwrap();
            libc::mkdir(dir.as_ptr(), 0o755);
        }
        let cpath = std::ffi::CString::new(path).unwrap();
        libc::unlink(cpath.as_ptr());
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            panic!("ctrl socket");
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len) < 0 {
            panic!("ctrl bind {}", errno());
        }
        libc::chmod(cpath.as_ptr(), 0o777);
        libc::listen(fd, 64);
        fd
    }
}

#[repr(C)]
struct EpollParams {
    busy_poll_usecs: u32,
    busy_poll_budget: u16,
    prefer_busy_poll: u8,
    pad: u8,
}
fn set_busy_poll(epfd: i32, usecs: u32) {
    const EPIOCSPARAMS: libc::c_ulong = 0x4008_7001; // _IOW('p', 0x01, struct epoll_params)
    let p = EpollParams {
        busy_poll_usecs: usecs,
        busy_poll_budget: 8,
        prefer_busy_poll: 1,
        pad: 0,
    };
    unsafe {
        if libc::ioctl(epfd, EPIOCSPARAMS, &p as *const _) < 0 {
            eprintln!("[worker] EPIOCSPARAMS falhou (kernel <6.9?): {}", errno());
        } else {
            eprintln!("[worker] epoll busy_poll={}us", usecs);
        }
    }
}

pub fn run() {
    hardening::ignore_sigpipe();
    let ctrl_path = env_str("CTRL", "/run/sock/api.ctrl");
    let index_path = env_str("INDEX_PATH", "/index/index.bin");
    let nprobe: usize = env_parse("NPROBE", 12);
    let repair_min: u8 = env_parse("REPAIR_MIN", 1);
    let repair_max: u8 = env_parse("REPAIR_MAX", 4);
    let busy_poll: u32 = env_parse("BUSY_POLL_US", 0);
    if let Ok(cpu) = std::env::var("CPU") {
        if let Ok(c) = cpu.parse::<usize>() {
            hardening::set_affinity(c);
        }
    }

    let index_bytes = hardening::read_index_to_ram(&index_path).expect("read index");
    hardening::mlock_all();
    let index = Index::from_bytes(&index_bytes).expect("parse index");
    eprintln!(
        "[worker] index k={} n={} nprobe={} repair=[{},{}]",
        index.k, index.n, nprobe, repair_min, repair_max
    );

    let warmup: usize = env_parse("WARMUP_ITERS", 4000);
    if warmup > 0 {
        index.warmup(warmup, nprobe, repair_min, repair_max);
        eprintln!("[worker] warmup {warmup} iters ok");
    }

    let ctrl_listen = create_ctrl_socket(&ctrl_path);
    let epfd = unsafe { libc::epoll_create1(0) };
    if busy_poll > 0 {
        set_busy_poll(epfd, busy_poll);
    }
    epoll_add(epfd, ctrl_listen, libc::EPOLLIN as u32);
    eprintln!("[worker] ctrl={ctrl_path} pronto");

    let mut conns: Vec<Option<Box<Conn>>> = Vec::new();
    let mut is_ctrl: Vec<bool> = Vec::new();
    let ensure = |conns: &mut Vec<Option<Box<Conn>>>, is_ctrl: &mut Vec<bool>, fd: usize| {
        if conns.len() <= fd {
            conns.resize_with(fd + 1, || None);
            is_ctrl.resize(fd + 1, false);
        }
    };

    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];
    loop {
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), MAX_EVENTS as c_int, -1) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break;
        }
        for ev in events.iter().take(n as usize) {
            let fd = ev.u64 as i32;
            let e = ev.events;

            if fd == ctrl_listen {
                accept_ctrl(epfd, ctrl_listen, &mut conns, &mut is_ctrl, &ensure);
                continue;
            }
            if (fd as usize) < is_ctrl.len() && is_ctrl[fd as usize] {
                if e & (libc::EPOLLRDHUP as u32 | libc::EPOLLHUP as u32 | libc::EPOLLERR as u32) != 0
                {
                    epoll_del(epfd, fd);
                    unsafe { libc::close(fd) };
                    is_ctrl[fd as usize] = false;
                } else if e & libc::EPOLLIN as u32 != 0 {
                    drain_fds(epfd, fd, &mut conns, &mut is_ctrl, &ensure);
                }
                continue;
            }
            if e & (libc::EPOLLHUP as u32 | libc::EPOLLERR as u32 | libc::EPOLLRDHUP as u32) != 0 {
                close_client(epfd, fd, &mut conns);
                continue;
            }
            if e & libc::EPOLLIN as u32 != 0 {
                handle_read(epfd, fd, &mut conns, &index, nprobe, repair_min, repair_max);
            }
        }
    }
}

fn accept_ctrl(
    epfd: i32,
    listen_fd: i32,
    conns: &mut Vec<Option<Box<Conn>>>,
    is_ctrl: &mut Vec<bool>,
    ensure: &impl Fn(&mut Vec<Option<Box<Conn>>>, &mut Vec<bool>, usize),
) {
    loop {
        let cfd = unsafe {
            libc::accept4(listen_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK)
        };
        if cfd < 0 {
            return;
        }
        ensure(conns, is_ctrl, cfd as usize);
        is_ctrl[cfd as usize] = true;
        epoll_add(epfd, cfd, libc::EPOLLIN as u32 | libc::EPOLLRDHUP as u32);
    }
}

fn drain_fds(
    epfd: i32,
    ctrl_fd: i32,
    conns: &mut Vec<Option<Box<Conn>>>,
    is_ctrl: &mut Vec<bool>,
    ensure: &impl Fn(&mut Vec<Option<Box<Conn>>>, &mut Vec<bool>, usize),
) {
    loop {
        let cfd = recv_fd(ctrl_fd);
        if cfd < 0 {
            return;
        }
        hardening::set_nonblocking(cfd);
        hardening::tune_tcp(cfd);
        ensure(conns, is_ctrl, cfd as usize);
        conns[cfd as usize] = Some(Conn::new());
        epoll_add(epfd, cfd, libc::EPOLLIN as u32 | libc::EPOLLRDHUP as u32);
    }
}

fn close_client(epfd: i32, fd: i32, conns: &mut Vec<Option<Box<Conn>>>) {
    epoll_del(epfd, fd);
    unsafe { libc::close(fd) };
    if (fd as usize) < conns.len() {
        conns[fd as usize] = None;
    }
}

fn handle_read(
    epfd: i32,
    fd: i32,
    conns: &mut Vec<Option<Box<Conn>>>,
    index: &Index,
    nprobe: usize,
    repair_min: u8,
    repair_max: u8,
) {
    let conn = match conns.get_mut(fd as usize).and_then(|c| c.as_mut()) {
        Some(c) => c,
        None => {
            close_client(epfd, fd, conns);
            return;
        }
    };

    let room = BUF_CAP - conn.have;
    if room == 0 {
        close_client(epfd, fd, conns);
        return;
    }
    let n = unsafe {
        libc::recv(
            fd,
            conn.buf.as_mut_ptr().add(conn.have) as *mut c_void,
            room,
            0,
        )
    };
    if n < 0 {
        if errno() == libc::EAGAIN || errno() == libc::EWOULDBLOCK {
            return;
        }
        close_client(epfd, fd, conns);
        return;
    }
    if n == 0 {
        close_client(epfd, fd, conns);
        return;
    }
    conn.have += n as usize;

    let mut consumed_total = 0usize;
    let mut should_close = false;
    loop {
        let view = &conn.buf[consumed_total..conn.have];
        match http::parse(view) {
            Parsed::Incomplete => break,
            Parsed::Ready { consumed } => {
                if !send_all(fd, http::READY_RESP) {
                    should_close = true;
                    break;
                }
                consumed_total += consumed;
            }
            Parsed::Fraud {
                body_start,
                body_len,
                consumed,
            } => {
                let body = &view[body_start..body_start + body_len];
                let count = match normalize(body) {
                    Some(q) => index.search(&q, nprobe, repair_min, repair_max),
                    None => 0,
                };
                if !send_all(fd, http::score_resp(count)) {
                    should_close = true;
                    break;
                }
                consumed_total += consumed;
            }
            Parsed::Bad { consumed } => {
                let _ = send_all(fd, http::BAD_RESP);
                consumed_total += consumed;
                should_close = true;
                break;
            }
        }
        if consumed_total >= conn.have {
            break;
        }
    }

    if consumed_total > 0 {
        let leftover = conn.have - consumed_total;
        if leftover > 0 {
            conn.buf.copy_within(consumed_total..conn.have, 0);
        }
        conn.have = leftover;
    }
    if should_close {
        close_client(epfd, fd, conns);
    }
}

fn send_all(fd: i32, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let n = unsafe {
            libc::send(fd, data.as_ptr() as *const c_void, data.len(), libc::MSG_NOSIGNAL)
        };
        if n > 0 {
            data = &data[n as usize..];
            continue;
        }
        if n < 0 && (errno() == libc::EAGAIN || errno() == libc::EWOULDBLOCK) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let r = unsafe { libc::poll(&mut pfd, 1, 50) };
            if r > 0 {
                continue;
            }
            return false;
        }
        if n < 0 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
    true
}
