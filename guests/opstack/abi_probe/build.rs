fn main() {
    // Same OP guest ABI as the Kona guest: 16 MiB input window, halt flag at
    // the window end, output length at +4 and output bytes at +8.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=../kona/guest/linker.ld");
    println!("cargo:rustc-link-arg=-T{manifest}/../kona/guest/linker.ld");
}
