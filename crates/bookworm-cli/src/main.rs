use bookworm_cli::Cli;
use clap::Parser;

/// Bookworm output is designed to be piped (`bookworm read x | head`); Rust
/// ignores SIGPIPE by default, which turns a closed pipe into a panic.
#[cfg(unix)]
fn reset_sigpipe() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

fn main() {
    reset_sigpipe();
    let cli = Cli::parse();
    match bookworm_cli::run(&cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("bookworm: {e}");
            std::process::exit(1);
        }
    }
}
