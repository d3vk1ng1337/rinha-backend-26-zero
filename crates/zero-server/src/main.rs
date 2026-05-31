mod http;

#[cfg(target_os = "linux")]
mod fdpass;
#[cfg(target_os = "linux")]
mod hardening;
#[cfg(target_os = "linux")]
mod lb;
#[cfg(target_os = "linux")]
mod worker;

#[cfg(target_os = "linux")]
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("lb") => lb::run(),
        Some("worker") => worker::run(),
        _ => {
            eprintln!("usage: zero-server <lb|worker>");
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
