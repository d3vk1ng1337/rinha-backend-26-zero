use std::fs;
use std::io;
use std::os::raw::c_void;

pub fn mlock_all() {
    unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

pub fn set_affinity(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

pub fn ignore_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

// Pages stay resident only once mlock_all() runs afterward; madvise just hints THP + prefault.
pub fn read_index_to_ram(path: &str) -> io::Result<Vec<u8>> {
    let buf = fs::read(path)?;
    if !buf.is_empty() {
        unsafe {
            libc::madvise(
                buf.as_ptr() as *mut c_void,
                buf.len(),
                libc::MADV_HUGEPAGE,
            );
            libc::madvise(buf.as_ptr() as *mut c_void, buf.len(), libc::MADV_WILLNEED);
        }
    }
    Ok(buf)
}

pub fn tune_tcp(fd: i32) {
    let one: i32 = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const i32 as *const c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &one as *const i32 as *const c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

pub fn set_nonblocking(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}
