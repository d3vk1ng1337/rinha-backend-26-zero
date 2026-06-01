//! io_uring worker: multishot recv off a provided-buffer ring, batched sends,
//! one io_uring_enter per wakeup. No SQPOLL (would burn the cgroup budget).

use std::collections::HashMap;
use std::mem;
use std::os::raw::c_void;

use io_uring::types::BufRingEntry;
use io_uring::{cqueue, opcode, squeue, types, IoUring};

use zero_index::normalize::normalize;
use zero_index::search::Index;

use crate::hardening;
use crate::http::{self, Parsed};
use crate::worker::create_ctrl_socket;

const BUF_CAP: usize = 8192;
const BUF_LEN: usize = 8192;
const BUF_ENTRIES: u16 = 1024; // provided buffers (power of two)
const SQ_ENTRIES: u32 = 1024;
const BGID: u16 = 0;
const CMSG_BUF: usize = 64;

const T_ACCEPT: u64 = 1 << 56;
const T_CTRL: u64 = 2 << 56;
const T_RECV: u64 = 3 << 56;
const T_SEND: u64 = 4 << 56;
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

struct Conn {
    buf: [u8; BUF_CAP],
    have: usize,
}
impl Conn {
    fn new() -> Box<Conn> {
        Box::new(Conn { buf: [0; BUF_CAP], have: 0 })
    }
}

/// One persistent recvmsg buffer per ctrl connection (carries the SCM_RIGHTS fd).
struct CtrlBuf {
    byte: u8,
    iov: libc::iovec,
    cbuf: [u8; CMSG_BUF],
    msg: libc::msghdr,
}
impl CtrlBuf {
    fn new() -> Box<CtrlBuf> {
        let mut b = Box::new(CtrlBuf {
            byte: 0,
            iov: unsafe { mem::zeroed() },
            cbuf: [0; CMSG_BUF],
            msg: unsafe { mem::zeroed() },
        });
        b.iov.iov_base = &mut b.byte as *mut u8 as *mut c_void;
        b.iov.iov_len = 1;
        b.msg.msg_iov = &mut b.iov;
        b.msg.msg_iovlen = 1;
        b.msg.msg_control = b.cbuf.as_mut_ptr() as *mut c_void;
        b.msg.msg_controllen = CMSG_BUF as _;
        b
    }
    /// Extract the SCM_RIGHTS fd after a completed recvmsg; -1 if none.
    unsafe fn take_fd(&mut self) -> i32 {
        let cmsg = libc::CMSG_FIRSTHDR(&self.msg);
        let fd = if !cmsg.is_null() && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
            let mut fd: i32 = -1;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                &mut fd as *mut i32 as *mut u8,
                mem::size_of::<i32>(),
            );
            fd
        } else {
            -1
        };
        self.msg.msg_controllen = CMSG_BUF as _; // reset for the next recvmsg
        fd
    }
}

/// Provided-buffer ring shared by all multishot recvs.
struct BufPool {
    ring: *mut BufRingEntry,
    pool: *const u8,
    _backing: Vec<u8>,
    mask: u16,
}
impl BufPool {
    unsafe fn new(submitter: &io_uring::Submitter) -> std::io::Result<BufPool> {
        let entries = BUF_ENTRIES as usize;
        let ring_sz = entries * mem::size_of::<BufRingEntry>();
        let ring = libc::mmap(
            std::ptr::null_mut(),
            ring_sz,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        );
        if ring == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let ring = ring as *mut BufRingEntry;
        let backing = vec![0u8; entries * BUF_LEN];
        let pool = backing.as_ptr();
        submitter.register_buf_ring_with_flags(ring as u64, BUF_ENTRIES, BGID, 0)?;
        let mask = BUF_ENTRIES - 1;
        for bid in 0..entries {
            let e = &mut *ring.add(bid);
            e.set_addr(pool.add(bid * BUF_LEN) as u64);
            e.set_len(BUF_LEN as u32);
            e.set_bid(bid as u16);
        }
        let tail = BufRingEntry::tail(ring) as *mut u16;
        std::ptr::write_volatile(tail, BUF_ENTRIES);
        Ok(BufPool { ring, pool, _backing: backing, mask })
    }
    #[inline]
    unsafe fn slice(&self, bid: u16, n: usize) -> &[u8] {
        std::slice::from_raw_parts(self.pool.add(bid as usize * BUF_LEN), n)
    }
    #[inline]
    unsafe fn recycle(&self, bid: u16) {
        let tail_ptr = BufRingEntry::tail(self.ring) as *mut u16;
        let tail = std::ptr::read_volatile(tail_ptr);
        let slot = (tail & self.mask) as usize;
        let e = &mut *self.ring.add(slot);
        e.set_addr(self.pool.add(bid as usize * BUF_LEN) as u64);
        e.set_len(BUF_LEN as u32);
        e.set_bid(bid);
        std::ptr::write_volatile(tail_ptr, tail.wrapping_add(1));
    }
}

#[inline]
unsafe fn push(ring: &mut IoUring, e: &squeue::Entry) {
    while ring.submission().push(e).is_err() {
        let _ = ring.submit();
    }
}

unsafe fn arm_recv(ring: &mut IoUring, fd: i32) {
    let e = opcode::RecvMulti::new(types::Fd(fd), BGID)
        .build()
        .user_data(T_RECV | (fd as u64 & P_MASK));
    push(ring, &e);
}

unsafe fn arm_ctrl_recv(ring: &mut IoUring, fd: i32, cb: &mut CtrlBuf) {
    let e = opcode::RecvMsg::new(types::Fd(fd), &mut cb.msg as *mut libc::msghdr)
        .build()
        .user_data(T_CTRL | (fd as u64 & P_MASK));
    push(ring, &e);
}

unsafe fn send_resp(ring: &mut IoUring, fd: i32, resp: &'static [u8]) {
    // Responses are 'static, so the pointer outlives the SQE — no pinning needed.
    let e = opcode::Send::new(types::Fd(fd), resp.as_ptr(), resp.len() as u32)
        .flags(libc::MSG_NOSIGNAL)
        .build()
        .user_data(T_SEND | (fd as u64 & P_MASK));
    push(ring, &e);
}

fn build_ring() -> IoUring {
    if let Ok(r) = IoUring::builder()
        .setup_single_issuer()
        .setup_defer_taskrun()
        .setup_coop_taskrun()
        .build(SQ_ENTRIES)
    {
        eprintln!("[worker-uring] ring: defer_taskrun + single_issuer");
        return r;
    }
    let r = IoUring::builder()
        .build(SQ_ENTRIES)
        .expect("io_uring build");
    eprintln!("[worker-uring] ring: plain (no defer_taskrun; kernel <6.1?)");
    r
}

pub fn run() {
    hardening::ignore_sigpipe();
    let ctrl_path = env_str("CTRL", "/run/sock/api.ctrl");
    let index_path = env_str("INDEX_PATH", "/index/index.bin");
    let nprobe: usize = env_parse("NPROBE", 12);
    let repair_min: u8 = env_parse("REPAIR_MIN", 1);
    let repair_max: u8 = env_parse("REPAIR_MAX", 4);
    if let Ok(cpu) = std::env::var("CPU") {
        if let Ok(c) = cpu.parse::<usize>() {
            hardening::set_affinity(c);
        }
    }

    let index_bytes = hardening::read_index_to_ram(&index_path).expect("read index");
    hardening::mlock_all();
    let index = Index::from_bytes(&index_bytes).expect("parse index");
    eprintln!(
        "[worker-uring] index k={} n={} nprobe={} repair=[{},{}]",
        index.k, index.n, nprobe, repair_min, repair_max
    );

    let warmup: usize = env_parse("WARMUP_ITERS", 4000);
    if warmup > 0 {
        index.warmup(warmup, nprobe, repair_min, repair_max);
        eprintln!("[worker-uring] warmup {warmup} iters ok");
    }

    let ctrl_listen = create_ctrl_socket(&ctrl_path);

    let mut ring = build_ring();
    let pool = unsafe { BufPool::new(&ring.submitter()).expect("buf ring") };

    // multishot accept on the ctrl listen socket
    unsafe {
        let e = opcode::AcceptMulti::new(types::Fd(ctrl_listen))
            .build()
            .user_data(T_ACCEPT);
        push(&mut ring, &e);
    }
    eprintln!("[worker-uring] ctrl={ctrl_path} pronto");

    let mut conns: Vec<Option<Box<Conn>>> = Vec::new();
    let mut ctrls: HashMap<i32, Box<CtrlBuf>> = HashMap::new();
    let ensure = |conns: &mut Vec<Option<Box<Conn>>>, fd: usize| {
        if conns.len() <= fd {
            conns.resize_with(fd + 1, || None);
        }
    };
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
                        let mut cb = CtrlBuf::new();
                        unsafe {
                            hardening::set_nonblocking(cfd);
                            arm_ctrl_recv(&mut ring, cfd, &mut cb);
                        }
                        ctrls.insert(cfd, cb);
                    }
                    if !cqueue::more(flags) {
                        unsafe {
                            let e = opcode::AcceptMulti::new(types::Fd(ctrl_listen))
                                .build()
                                .user_data(T_ACCEPT);
                            push(&mut ring, &e);
                        }
                    }
                }
                T_CTRL => {
                    let cfd = (ud & P_MASK) as i32;
                    if res <= 0 {
                        ctrls.remove(&cfd);
                        unsafe { libc::close(cfd) };
                        continue;
                    }
                    let client_fd = match ctrls.get_mut(&cfd) {
                        Some(cb) => unsafe { cb.take_fd() },
                        None => -1,
                    };
                    if client_fd >= 0 {
                        hardening::set_nonblocking(client_fd);
                        hardening::tune_tcp(client_fd);
                        ensure(&mut conns, client_fd as usize);
                        conns[client_fd as usize] = Some(Conn::new());
                        unsafe { arm_recv(&mut ring, client_fd) };
                    }
                    // re-arm the ctrl recvmsg for the next fd
                    if let Some(cb) = ctrls.get_mut(&cfd) {
                        let cb: *mut CtrlBuf = &mut **cb;
                        unsafe { arm_ctrl_recv(&mut ring, cfd, &mut *cb) };
                    }
                }
                T_RECV => {
                    let fd = (ud & P_MASK) as i32;
                    if res <= 0 {
                        close_client(&mut ring, fd, &mut conns);
                        continue;
                    }
                    let bid = match cqueue::buffer_select(flags) {
                        Some(b) => b,
                        None => {
                            close_client(&mut ring, fd, &mut conns);
                            continue;
                        }
                    };
                    let n = res as usize;
                    let closed = unsafe {
                        let data = pool.slice(bid, n);
                        let r = serve(&mut ring, fd, data, &mut conns, &index, nprobe, repair_min, repair_max);
                        pool.recycle(bid);
                        r
                    };
                    if closed {
                        close_client(&mut ring, fd, &mut conns);
                    } else if !cqueue::more(flags) {
                        // multishot terminated (e.g. -ENOBUFS) — re-arm
                        if (fd as usize) < conns.len() && conns[fd as usize].is_some() {
                            unsafe { arm_recv(&mut ring, fd) };
                        }
                    }
                }
                T_SEND => {
                    if res < 0 {
                        let fd = (ud & P_MASK) as i32;
                        close_client(&mut ring, fd, &mut conns);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Feed freshly-recv'd bytes into the conn buffer and serve complete requests.
/// Returns true if the connection should be closed.
unsafe fn serve(
    ring: &mut IoUring,
    fd: i32,
    data: &[u8],
    conns: &mut [Option<Box<Conn>>],
    index: &Index,
    nprobe: usize,
    repair_min: u8,
    repair_max: u8,
) -> bool {
    let conn = match conns.get_mut(fd as usize).and_then(|c| c.as_mut()) {
        Some(c) => c,
        None => return true,
    };
    if conn.have + data.len() > BUF_CAP {
        return true;
    }
    conn.buf[conn.have..conn.have + data.len()].copy_from_slice(data);
    conn.have += data.len();

    let mut consumed_total = 0usize;
    let mut should_close = false;
    loop {
        let view = &conn.buf[consumed_total..conn.have];
        match http::parse(view) {
            Parsed::Incomplete => break,
            Parsed::Ready { consumed } => {
                send_resp(ring, fd, http::READY_RESP);
                consumed_total += consumed;
            }
            Parsed::Fraud { body_start, body_len, consumed } => {
                let body = &view[body_start..body_start + body_len];
                let count = match normalize(body) {
                    Some(q) => index.search(&q, nprobe, repair_min, repair_max),
                    None => 0,
                };
                send_resp(ring, fd, http::score_resp(count));
                consumed_total += consumed;
            }
            Parsed::Bad { consumed } => {
                send_resp(ring, fd, http::BAD_RESP);
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
    should_close
}

fn close_client(_ring: &mut IoUring, fd: i32, conns: &mut Vec<Option<Box<Conn>>>) {
    unsafe { libc::close(fd) };
    if (fd as usize) < conns.len() {
        conns[fd as usize] = None;
    }
}
