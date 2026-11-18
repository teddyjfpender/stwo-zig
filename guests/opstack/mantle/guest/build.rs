fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let linker = format!("{manifest}/../../kona/guest/linker.ld");
    println!("cargo:rerun-if-changed={linker}");
    println!("cargo:rustc-link-arg=-T{linker}");
}
