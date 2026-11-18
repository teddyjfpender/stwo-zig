fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker = if std::env::var_os("CARGO_FEATURE_TRANSITION_PROGRAM").is_some() {
        "linker-transition.ld"
    } else {
        "linker.ld"
    };
    println!("cargo:rerun-if-changed={linker}");
    println!("cargo:rustc-link-arg=-T{manifest}/{linker}");
}
