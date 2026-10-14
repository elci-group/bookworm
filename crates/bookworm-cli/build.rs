use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let version_path = manifest_dir.join("../../VERSION");
    println!("cargo:rerun-if-changed={}", version_path.display());
    let version = fs::read_to_string(&version_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", version_path.display()));
    println!("cargo:rustc-env=BOOKWORM_VERSION={}", version.trim());
}
