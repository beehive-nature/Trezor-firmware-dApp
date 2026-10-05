// Copies beehive-nature's crates/bsigner/src/bpq.rs into OUT_DIR so main.rs can
// include it as a module. The only change is dropping `//!` lines, which are
// not allowed inside an included module body; no code line is touched.

use std::{env, fs, path::PathBuf};

fn main() {
    let bn = env::var("BEEHIVE_NATURE").expect("set BEEHIVE_NATURE to a beehive-nature checkout");
    println!("cargo:rerun-if-env-changed=BEEHIVE_NATURE");
    // bpq.rs and the one crate module it uses (b64.rs)
    for name in ["bpq.rs", "b64.rs"] {
        let src = PathBuf::from(&bn).join("crates/bsigner/src").join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        let text = fs::read_to_string(&src).expect("read bsigner source");
        let body: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//!"))
            .map(|l| format!("{l}\n"))
            .collect();
        fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join(name), body).unwrap();
    }
    println!(
        "cargo:rustc-env=BPQ_RS_PATH={}",
        PathBuf::from(&bn).join("crates/bsigner/src/bpq.rs").display()
    );
}
