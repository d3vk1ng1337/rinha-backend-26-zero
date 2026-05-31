//! zero-server: binário multi-modo (lb | worker). I/O é Linux-only
//! (io_uring/epoll). No macOS só o parser HTTP compila (testável); os módulos
//! de I/O são compilados/validados no box amd64.

mod http;

#[cfg(target_os = "linux")]
mod fdpass;
#[cfg(target_os = "linux")]
mod hardening;
#[cfg(target_os = "linux")]
mod lb;
#[cfg(target_os = "linux")]
mod worker_epoll;
#[cfg(target_os = "linux")]
mod worker_uring;

#[cfg(target_os = "linux")]
fn main() {
    let role = std::env::args().nth(1).unwrap_or_default();
    match role.as_str() {
        "lb" => lb::run(),
        "worker" => match std::env::var("WORKER_IO").as_deref() {
            Ok("uring") => worker_uring::run(),
            _ => worker_epoll::run(),
        },
        _ => {
            eprintln!("uso: zero-server <lb|worker>  (worker: WORKER_IO=epoll|uring)");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    let _ = (http::READY_RESP, http::BAD_RESP, &http::SCORE_RESP);
    eprintln!(
        "zero-server roda apenas em Linux (io_uring/epoll). \
         Use o box amd64 — ver tools/provision-box.md."
    );
    std::process::exit(1);
}
