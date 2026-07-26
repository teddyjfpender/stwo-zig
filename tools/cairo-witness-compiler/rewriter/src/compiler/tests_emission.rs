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

#[test]
fn generic_ec_deduce_uses_explicit_width_27_words() {
    let p = "add_opcode_input.pc";
    let scalar = vec![p; 10].join(", ");
    let body = format!(
        "let f = memory_id_to_big_state.deduce_output(\
             memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
         let scalar = PackedFelt252Width27::from_limbs([{scalar}]); \
         let out = PackedPartialEcMulGeneric::deduce_output((\
             add_opcode_input.pc, add_opcode_input.ap, \
             (scalar, [f, f], [f, f], add_opcode_input.fp))); \
         let scalar_limb = out.2.0.get_m31(9); \
         let point_limb = out.2.1[1].get_m31(27); \
         let counter = out.2.3; \
         let output = scalar_limb + point_limb + counter;"
    );
    let lw = lower_snippet(&[], &body);
    assert_eq!(lw.deduce_sites, 0, "skips: {:?}", lw.skips);
    assert_eq!(lw.w27_sites, 0, "skips: {:?}", lw.skips);
    assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
    assert_eq!(lw.env["output"], Ty::M31);
    let body = lw.out.iter().map(|token| token.to_string()).collect::<String>();
    assert!(
        body.contains("eval . deduce_partial_ec_mul_generic ("),
        "body: {body}"
    );
}
