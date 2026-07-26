#[test]
fn idempotent_block_generation() {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/prover/src/witness/components/assert_eq_opcode.rs"
    ));
    if !path.exists() {
        return;
    }
    let first = analyze_file(&path, true);
    let second = analyze_file(&path, true);
    assert!(first.matched, "assert_eq_opcode should match");
    assert_eq!(
        first.block, second.block,
        "block generation must be deterministic"
    );
}
