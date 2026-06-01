//! io_uring load balancer: multishot accept on :9999, round-robin the raw client
//! fd to a worker via SCM_RIGHTS sendmsg. Off the request path.

use std::mem;
use std::os::raw::c_void;

use io_uring::{cqueue, opcode, squeue, types, IoUring};

use crate::hardening;
use crate::lb::{connect_wait, make_listen};

const SQ_ENTRIES: u32 = 1024;
const CMSG_BUF: usize = 64;

const T_ACCEPT: u64 = 1 << 56;
const T_SEND: u64 = 2 << 56;
const T_MASK: u64 = 0xFFu64 << 56;
const P_MASK: u64 = !T_MASK;

fn env_str(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}
fn env_parse<T: std::str::FromStr>(k: &str, default: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Pinned SCM_RIGHTS message; the kernel reads it asynchronously, so it must
/// outlive the SQE until the send CQE arrives.
struct FdSend {
    byte: u8,
    iov: libc::iovec,
    cbuf: [u8; CMSG_BUF],
    msg: libc::msghdr,
    client_fd: i32,
}
impl FdSend {
    fn new(client_fd: i32) -> Box<FdSend> {
        let mut b = Box::new(FdSend {
            byte: 1,
            iov: unsafe { mem::zeroed() },
            cbuf: [0; CMSG_BUF],
            msg: unsafe { mem::zeroed() },
            client_fd,
        });
        b.iov.iov_base = &mut b.byte as *mut u8 as *mut c_void;
        b.iov.iov_len = 1;
        b.msg.msg_iov = &mut b.iov;
        b.msg.msg_iovlen = 1;
        b.msg.msg_control = b.cbuf.as_mut_ptr() as *mut c_void;
        b.msg.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<i32>() as u32) } as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&b.msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<i32>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                &client_fd as *const i32 as *const u8,
                libc::CMSG_DATA(cmsg),
                mem::size_of::<i32>(),
            );
        }
        b
    }
}

struct SendSlab {
    slots: Vec<Option<Box<FdSend>>>,
    free: Vec<usize>,
}
impl SendSlab {
    fn new() -> Self {
        SendSlab { slots: Vec::new(), free: Vec::new() }
    }
    fn alloc(&mut self, s: Box<FdSend>) -> usize {
        if let Some(i) = self.free.pop() {
            self.slots[i] = Some(s);
            i
        } else {
            self.slots.push(Some(s));
            self.slots.len() - 1
        }
    }
    fn take(&mut self, i: usize) -> Option<Box<FdSend>> {
        let s = self.slots.get_mut(i).and_then(|x| x.take());
        if s.is_some() {
            self.free.push(i);
        }
        s
    }
}

#[inline]
unsafe fn push(ring: &mut IoUring, e: &squeue::Entry) {
    while ring.submission().push(e).is_err() {
        let _ = ring.submit();
    }
}

fn build_ring() -> IoUring {
    if let Ok(r) = IoUring::builder()
        .setup_single_issuer()
        .setup_defer_taskrun()
        .setup_coop_taskrun()
        .build(SQ_ENTRIES)
    {
        eprintln!("[lb-uring] ring: defer_taskrun + single_issuer");
        return r;
    }
    let r = IoUring::builder().build(SQ_ENTRIES).expect("io_uring build");
    eprintln!("[lb-uring] ring: plain (kernel <6.1?)");
    r
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
    let ups: Vec<i32> = paths.iter().map(|p| connect_wait(p)).collect();
    eprintln!("[lb-uring] conectado a {} workers, listen :{port}", ups.len());

    let listen = make_listen(port);
    let mut ring = build_ring();
    unsafe {
        let e = opcode::AcceptMulti::new(types::Fd(listen))
            .build()
            .user_data(T_ACCEPT);
        push(&mut ring, &e);
    }

    let mut slab = SendSlab::new();
    let mut rr: usize = 0;
    let n = ups.len();
    let mut done: Vec<(u64, i32, u32)> = Vec::with_capacity(1024);

    loop {
        if ring.submit_and_wait(1).is_err() {
            if errno() == libc::EINTR {
                continue;
            }
            break;
        }
        done.clear();
        for cqe in ring.completion() {
            done.push((cqe.user_data(), cqe.result(), cqe.flags()));
        }
        for &(ud, res, flags) in done.iter() {
            match ud & T_MASK {
                T_ACCEPT => {
                    if res >= 0 {
                        let cfd = res;
                        hardening::tune_tcp(cfd);
                        let worker = ups[rr % n];
                        rr = rr.wrapping_add(1);
                        let s = FdSend::new(cfd);
                        let msg_ptr: *const libc::msghdr = &s.msg;
                        let idx = slab.alloc(s);
                        unsafe {
                            let e = opcode::SendMsg::new(types::Fd(worker), msg_ptr)
                                .flags(libc::MSG_NOSIGNAL as u32)
                                .build()
                                .user_data(T_SEND | (idx as u64 & P_MASK));
                            push(&mut ring, &e);
                        }
                    }
                    if !cqueue::more(flags) {
                        unsafe {
                            let e = opcode::AcceptMulti::new(types::Fd(listen))
                                .build()
                                .user_data(T_ACCEPT);
                            push(&mut ring, &e);
                        }
                    }
                }
                T_SEND => {
                    let idx = (ud & P_MASK) as usize;
                    if let Some(s) = slab.take(idx) {
                        // worker now owns the fd via the dup'd descriptor; drop ours.
                        unsafe { libc::close(s.client_fd) };
                    }
                    let _ = res;
                }
                _ => {}
            }
        }
    }
}
