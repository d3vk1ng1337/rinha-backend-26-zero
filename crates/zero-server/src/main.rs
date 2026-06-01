mod http;

#[cfg(target_os = "linux")]
mod fdpass;
#[cfg(target_os = "linux")]
mod hardening;
#[cfg(target_os = "linux")]
mod lb;
#[cfg(target_os = "linux")]
mod lb_uring;
#[cfg(target_os = "linux")]
mod worker;
#[cfg(target_os = "linux")]
mod worker_uring;

#[cfg(target_os = "linux")]
fn main() {
    let want_uring = std::env::var("ENGINE").as_deref() == Ok("uring");
    let uring = want_uring && worker_uring::uring_available();
    if want_uring && !uring {
        eprintln!("[main] io_uring unavailable (seccomp/kernel) -> epoll fallback");
    }
    match std::env::args().nth(1).as_deref() {
        Some("lb") if uring => lb_uring::run(),
        Some("lb") => lb::run(),
        Some("worker") if uring => worker_uring::run(),
        Some("worker") => worker::run(),
        _ => {
            eprintln!("usage: zero-server <lb|worker>  (ENGINE=uring|epoll)");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    let _ = &http::SCORE_RESP;
    eprintln!("zero-server requires Linux");
    std::process::exit(1);
}
