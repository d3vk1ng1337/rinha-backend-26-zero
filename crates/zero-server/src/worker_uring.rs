//! Worker io_uring (braço A1, headline). Ring único com DEFER_TASKRUN +
//! SINGLE_ISSUER + COOP_TASKRUN. Hot path (recv/send do request) é io_uring;
//! o intake de fd (SCM_RIGHTS do LB) é detectado por PollAdd multishot no ctrl
//! socket e drenado com recv_fd (raro, só no setup de conexão).
//!
//! Fase 1 (este arquivo): recv re-armado por conexão + Send das respostas
//! estáticas. Fase 2 (upgrade): multishot recv + provided-buffer ring (PBUF)
//! pro zero-syscall pleno — medido no box amd64.

use io_uring::{cqueue, opcode, types, IoUring};
use zero_index::normalize::normalize;
use zero_index::search::Index;

use crate::fdpass::recv_fd;
use crate::hardening;
use crate::http::{self, Parsed};

const BUF_CAP: usize = 8192;
const RING_ENTRIES: u32 = 1024;

// op no byte alto do user_data; fd nos 32 bits baixos.
const OP_RECV: u64 = 0;
const OP_SEND: u64 = 1;
const OP_CTRL_POLL: u64 = 2;
const OP_LISTEN_POLL: u64 = 3;

#[inline]
fn ud(op: u64, fd: i32) -> u64 {
    (op << 56) | (fd as u32 as u64)
}
#[inline]
fn ud_op(u: u64) -> u64 {
    u >> 56
}
#[inline]
fn ud_fd(u: u64) -> i32 {
    (u & 0xFFFF_FFFF) as u32 as i32
}

struct Conn {
    buf: Box<[u8; BUF_CAP]>,
    have: usize,
}
impl Conn {
    fn new() -> Conn {
        Conn {
            buf: Box::new([0u8; BUF_CAP]),
            have: 0,
        }
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

fn create_ctrl_socket(path: &str) -> i32 {
    unsafe {
        if let Some(slash) = path.rfind('/') {
            let dir = std::ffi::CString::new(&path[..slash]).unwrap();
            libc::mkdir(dir.as_ptr(), 0o755);
        }
        let cpath = std::ffi::CString::new(path).unwrap();
        libc::unlink(cpath.as_ptr());
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        assert!(fd >= 0, "ctrl socket");
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, &b) in path.as_bytes().iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        assert!(
            libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len) >= 0,
            "ctrl bind {}",
            errno()
        );
        libc::chmod(cpath.as_ptr(), 0o777);
        libc::listen(fd, 64);
        fd
    }
}

pub struct Worker<'a> {
    ring: IoUring,
    index: &'a Index<'a>,
    nprobe: usize,
    repair_min: u8,
    repair_max: u8,
    conns: Vec<Option<Box<Conn>>>,
    is_ctrl: Vec<bool>,
    ctrl_listen: i32,
}

impl<'a> Worker<'a> {
    fn ensure(&mut self, fd: usize) {
        if self.conns.len() <= fd {
            self.conns.resize_with(fd + 1, || None);
            self.is_ctrl.resize(fd + 1, false);
        }
    }

    /// Push de um SQE; se a SQ estiver cheia, submete e tenta de novo.
    fn push(&mut self, entry: &io_uring::squeue::Entry) {
        loop {
            let ok = unsafe { self.ring.submission().push(entry).is_ok() };
            if ok {
                return;
            }
            let _ = self.ring.submit();
            self.ring.submission().sync();
        }
    }

    fn arm_recv(&mut self, fd: i32) {
        let conn = match self.conns.get_mut(fd as usize).and_then(|c| c.as_mut()) {
            Some(c) => c,
            None => return,
        };
        let ptr = unsafe { conn.buf.as_mut_ptr().add(conn.have) };
        let room = (BUF_CAP - conn.have) as u32;
        let e = opcode::Recv::new(types::Fd(fd), ptr, room)
            .build()
            .user_data(ud(OP_RECV, fd));
        self.push(&e);
    }

    fn arm_poll(&mut self, fd: i32, op: u64) {
        let e = opcode::PollAdd::new(types::Fd(fd), libc::POLLIN as u32)
            .multi(true)
            .build()
            .user_data(ud(op, fd));
        self.push(&e);
    }

    fn close_client(&mut self, fd: i32) {
        unsafe { libc::close(fd) };
        if (fd as usize) < self.conns.len() {
            self.conns[fd as usize] = None;
        }
    }

    fn drain_fds(&mut self, ctrl_fd: i32) {
        loop {
            let cfd = recv_fd(ctrl_fd);
            if cfd < 0 {
                return;
            }
            hardening::set_nonblocking(cfd);
            hardening::tune_tcp(cfd);
            self.ensure(cfd as usize);
            self.conns[cfd as usize] = Some(Box::new(Conn::new()));
            self.arm_recv(cfd);
        }
    }

    fn accept_ctrl(&mut self) {
        loop {
            let cfd = unsafe {
                libc::accept4(
                    self.ctrl_listen,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK,
                )
            };
            if cfd < 0 {
                return;
            }
            self.ensure(cfd as usize);
            self.is_ctrl[cfd as usize] = true;
            self.arm_poll(cfd, OP_CTRL_POLL);
        }
    }

    /// Processa requests completos no buffer e enfileira os Sends. Retorna
    /// false se a conexão deve fechar.
    fn process(&mut self, fd: i32) -> bool {
        let (mut consumed_total, mut close) = (0usize, false);
        loop {
            let conn = match self.conns.get(fd as usize).and_then(|c| c.as_ref()) {
                Some(c) => c,
                None => return false,
            };
            let have = conn.have;
            if consumed_total >= have {
                break;
            }
            // SAFE: buf vive no slab; parse/normalize não mexem no slab.
            let view: &[u8] =
                unsafe { std::slice::from_raw_parts(conn.buf.as_ptr().add(consumed_total), have - consumed_total) };
            match http::parse(view) {
                Parsed::Incomplete => break,
                Parsed::Ready { consumed } => {
                    self.send_static(fd, http::READY_RESP);
                    consumed_total += consumed;
                }
                Parsed::Fraud {
                    body_start,
                    body_len,
                    consumed,
                } => {
                    let body = &view[body_start..body_start + body_len];
                    let count = match normalize(body) {
                        Some(q) => self.index.search(&q, self.nprobe, self.repair_min, self.repair_max),
                        None => 0,
                    };
                    self.send_static(fd, http::score_resp(count));
                    consumed_total += consumed;
                }
                Parsed::Bad { consumed } => {
                    self.send_static(fd, http::BAD_RESP);
                    consumed_total += consumed;
                    close = true;
                    break;
                }
            }
        }
        // compacta leftover
        if consumed_total > 0 {
            if let Some(conn) = self.conns.get_mut(fd as usize).and_then(|c| c.as_mut()) {
                let leftover = conn.have - consumed_total;
                if leftover > 0 {
                    conn.buf.copy_within(consumed_total..conn.have, 0);
                }
                conn.have = leftover;
            }
        }
        !close
    }

    fn send_static(&mut self, fd: i32, data: &'static [u8]) {
        // respostas são 'static (vivem o processo todo) → ptr estável p/ o kernel
        let e = opcode::Send::new(types::Fd(fd), data.as_ptr(), data.len() as u32)
            .build()
            .user_data(ud(OP_SEND, fd));
        self.push(&e);
    }

    fn run_loop(&mut self) {
        // arma poll multishot no ctrl listen
        self.arm_poll(self.ctrl_listen, OP_LISTEN_POLL);
        let _ = self.ring.submit();

        loop {
            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => {
                    eprintln!("[uring] submit_and_wait: {e}");
                    break;
                }
            }
            // drena completions
            let mut completed: Vec<(u64, i32, u32)> = Vec::new();
            {
                let cq = self.ring.completion();
                for cqe in cq {
                    completed.push((cqe.user_data(), cqe.result(), cqe.flags()));
                }
            }
            for (u, res, flags) in completed {
                match ud_op(u) {
                    OP_LISTEN_POLL => {
                        self.accept_ctrl();
                        if !cqueue::more(flags) {
                            self.arm_poll(self.ctrl_listen, OP_LISTEN_POLL);
                        }
                    }
                    OP_CTRL_POLL => {
                        let fd = ud_fd(u);
                        if res < 0 {
                            // ctrl caiu
                            unsafe { libc::close(fd) };
                            if (fd as usize) < self.is_ctrl.len() {
                                self.is_ctrl[fd as usize] = false;
                            }
                        } else {
                            self.drain_fds(fd);
                            if !cqueue::more(flags) {
                                self.arm_poll(fd, OP_CTRL_POLL);
                            }
                        }
                    }
                    OP_RECV => {
                        let fd = ud_fd(u);
                        if res <= 0 {
                            self.close_client(fd);
                        } else {
                            if let Some(conn) =
                                self.conns.get_mut(fd as usize).and_then(|c| c.as_mut())
                            {
                                conn.have += res as usize;
                                if conn.have > BUF_CAP {
                                    conn.have = BUF_CAP;
                                }
                            }
                            if self.process(fd) {
                                self.arm_recv(fd); // keep-alive: próxima requisição
                            } else {
                                self.close_client(fd);
                            }
                        }
                    }
                    OP_SEND => {
                        if res < 0 {
                            self.close_client(ud_fd(u));
                        }
                    }
                    _ => {}
                }
            }
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
    if let Ok(cpu) = std::env::var("CPU") {
        if let Ok(c) = cpu.parse::<usize>() {
            hardening::set_affinity(c);
        }
    }

    let index_bytes = hardening::read_index_to_ram(&index_path).expect("read index");
    hardening::mlock_all();
    let index = Index::from_bytes(&index_bytes).expect("parse index");
    eprintln!(
        "[uring] index k={} n={} nprobe={} repair=[{},{}]",
        index.k, index.n, nprobe, repair_min, repair_max
    );

    let ring = IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .build(RING_ENTRIES)
        .expect("io_uring build");

    let ctrl_listen = create_ctrl_socket(&ctrl_path);
    eprintln!("[uring] ctrl={ctrl_path} pronto");

    let mut worker = Worker {
        ring,
        index: &index,
        nprobe,
        repair_min,
        repair_max,
        conns: Vec::new(),
        is_ctrl: Vec::new(),
        ctrl_listen,
    };
    worker.run_loop();
}
