//! Release measurements for the typed control API. Run: `api-bench wire | rtt | subs`.
//! The peers are Unix sockets, so there is nothing to run on Windows.

#[cfg(unix)]
mod bench;

#[cfg(unix)]
fn main() {
    bench::main();
}

#[cfg(not(unix))]
fn main() {
    eprintln!("api-bench needs Unix sockets");
    std::process::exit(2);
}
