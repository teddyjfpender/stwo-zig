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

#[test]
fn add_mod_biguint_boundary_lowers_to_one_semantic_hook() {
    let body = "\
        let f = memory_id_to_big_state.deduce_output(\
            memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
        let a = PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&[f, f, f, f]); \
        let b = PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&[f, f, f, f]); \
        let c = PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&[f, f, f, f]); \
        let diff = (a + b) - c; \
        let zero = diff.eq(BigUInt_384_6_32_0_0_0_0_0_0); \
        let output = zero.as_m31();";
    let lw = lower_snippet(&[], body);
    assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
    assert_eq!(lw.env["output"], Ty::M31);
    let emitted = lw.out.iter().map(|token| token.to_string()).collect::<String>();
    assert_eq!(emitted.matches("deduce_add_mod_is_zero").count(), 1);
}

#[test]
fn mul_mod_biguint_boundary_lowers_to_one_semantic_hook() {
    let felt4 = "[f, f, f, f]";
    let body = format!(
        "let f = memory_id_to_big_state.deduce_output(\
             memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
         let quotient = PackedBigUInt::<384, 6, 32>::from_packed_biguint::<768, 12, 64>(\
             (PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&{felt4})\
                 .widening_mul(PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&{felt4}))\
              - PackedBigUInt::<768, 12, 64>::from_packed_biguint::<384, 6, 32>(\
                    PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&{felt4})))\
             / PackedBigUInt::<768, 12, 64>::from_packed_biguint::<384, 6, 32>(\
                    PackedBigUInt::<384, 6, 32>::from_packed_felt252_array(&{felt4}))); \
         let output = quotient.get_m31(31);"
    );
    let lw = lower_snippet(&[], &body);
    assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
    assert_eq!(lw.env["output"], Ty::M31);
    let emitted = lw.out.iter().map(|token| token.to_string()).collect::<String>();
    assert_eq!(emitted.matches("deduce_mul_mod_quotient").count(), 1);
}
