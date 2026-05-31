//! Hardening Linux: mlockall, CPU affinity, índice em RAM (hugepages + prefault).
//! Mata as fontes não-algorítmicas de cauda: page-fault (mmap), migração de CPU.

use std::fs;
use std::io;
use std::os::raw::c_void;

/// Trava todas as páginas atuais e futuras na RAM (sem swap/eviction).
pub fn mlock_all() {
    unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

/// Fixa a thread atual no core `cpu` (reduz jitter de migração).
pub fn set_affinity(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Ignora SIGPIPE (send em peer fechado não derruba o processo).
pub fn ignore_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Lê o índice inteiro pra RAM privada, sugere THP e pré-carrega.
/// `mlock_all()` (chamado depois) garante o lock das páginas.
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

/// TCP_NODELAY + TCP_QUICKACK num fd já conectado.
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

/// Marca um fd como non-blocking.
pub fn set_nonblocking(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}
