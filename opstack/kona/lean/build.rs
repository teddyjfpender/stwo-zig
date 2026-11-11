fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=../guest/linker.ld");
    println!("cargo:rustc-link-arg=-T{manifest}/../guest/linker.ld");
}
