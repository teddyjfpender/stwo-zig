// ======================================================================================
// Tests
// ======================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn lower_snippet_full(
        consts: &[(&str, ConstKind, u32)],
        felt_consts: BTreeMap<String, [u32; FELT252_LIMBS]>,
        input_ty: Ty,
        body: &str,
        sub_slots: Vec<SubSlot>,
    ) -> Lowerer {
        let mut cmap = BTreeMap::new();
        for (n, k, v) in consts {
            cmap.insert(
                n.to_string(),
                ConstVal {
                    kind: *k,
                    value: *v,
                },
            );
        }
        let mut lw = Lowerer::new(
            cmap,
            felt_consts,
            ["seq".to_string()].into_iter().collect(),
            BTreeMap::new(),
            BTreeMap::new(),
            Some("memory_address_to_id_state".to_string()),
            Some("memory_id_to_big_state".to_string()),
            "add_opcode_input".to_string(),
            input_ty,
            "row_index".to_string(),
            "row".to_string(),
            "lookup_data".to_string(),
            "sub_component_inputs".to_string(),
            WriterShape::LookupSubInput,
            vec![],
            sub_slots,
        );
        let block: syn::Block = syn::parse_str(&format!("{{ {body} }}")).unwrap();
        lw.lower_body(&block.stmts);
        lw
    }

    fn lower_snippet_with_slots(
        consts: &[(&str, ConstKind, u32)],
        body: &str,
        sub_slots: Vec<SubSlot>,
    ) -> Lowerer {
        lower_snippet_full(consts, BTreeMap::new(), Ty::Unknown, body, sub_slots)
    }

    fn lower_snippet(consts: &[(&str, ConstKind, u32)], body: &str) -> Lowerer {
        lower_snippet_with_slots(consts, body, vec![])
    }

    fn lower_preprocessed_snippet(body: &str) -> Lowerer {
        let mut lw = Lowerer::new(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            [
                ("first_table".to_string(), 0),
                ("second_table".to_string(), 1),
            ]
            .into_iter()
            .collect(),
            BTreeMap::new(),
            None,
            None,
            "__no_row_input".to_string(),
            Ty::Tuple(Vec::new()),
            "row_index".to_string(),
            "row".to_string(),
            "lookup_data".to_string(),
            "__no_sub_component_inputs".to_string(),
            WriterShape::Lookup,
            Vec::new(),
            Vec::new(),
        );
        let block: syn::Block = syn::parse_str(&format!("{{ {body} }}")).unwrap();
        lw.lower_body(&block.stmts);
        lw
    }

    #[test]
    fn writer_shapes_expose_only_owned_row_inputs() {
        assert!(!WriterShape::Lookup.has_sub_inputs());
        assert!(!WriterShape::Lookup.has_row_input());
        assert!(WriterShape::LookupSub.has_sub_inputs());
        assert!(!WriterShape::LookupSub.has_row_input());
        assert!(WriterShape::LookupSubInput.has_sub_inputs());
        assert!(WriterShape::LookupSubInput.has_row_input());
    }

    #[test]
    fn preprocessed_columns_use_declaration_order_slots() {
        let lw = lower_preprocessed_snippet(
            "let a = first_table.packed_at(row_index); \
             let b = second_table.packed_at(row_index); \
             let c = a + b;",
        );
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        assert_eq!(lw.env["a"], Ty::M31);
        assert_eq!(lw.env["b"], Ty::M31);
        assert_eq!(lw.env["c"], Ty::M31);
        let body = lw.out.iter().map(|token| token.to_string()).collect::<String>();
        assert!(body.contains("eval . input (2)"), "body: {body}");
        assert!(body.contains("eval . input (3)"), "body: {body}");
    }

    #[test]
    fn preprocessed_column_binding_is_narrow() {
        let block: syn::Block = syn::parse_str(
            "{ \
                let canonical = preprocessed_trace.get_column(&column_id); \
                let unrelated = another_trace.get_column(&column_id); \
             }",
        )
        .unwrap();
        let Stmt::Local(canonical) = &block.stmts[0] else {
            panic!("canonical binding must parse as a local");
        };
        let Stmt::Local(unrelated) = &block.stmts[1] else {
            panic!("unrelated binding must parse as a local");
        };
        assert_eq!(
            local_preprocessed_column_ident(canonical),
            Some("canonical".to_string())
        );
        assert_eq!(local_preprocessed_column_ident(unrelated), None);
    }

    #[test]
    fn uniform_segment_input_has_a_stable_slot() {
        let writer: ItemFn = syn::parse_str(
            "fn write_trace_simd(
                log_size: u32,
                poseidon_builtin_segment_start: u32,
                unrelated: u32,
            ) {}",
        )
        .unwrap();
        let slots = writer_uniform_m31_inputs(&writer);
        assert_eq!(
            slots,
            [("poseidon_builtin_segment_start".to_string(), 0)]
                .into_iter()
                .collect()
        );

        let expression: Expr =
            syn::parse_str("PackedM31::broadcast(M31::from(poseidon_builtin_segment_start))")
                .unwrap();
        let Expr::Call(call) = expression else {
            panic!("broadcast must parse as a call");
        };
        assert_eq!(
            m31_broadcast_input_ident(&call),
            Some("poseidon_builtin_segment_start".to_string())
        );

        let mut lw = Lowerer::new(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            slots,
            None,
            None,
            "__no_row_input".to_string(),
            Ty::Tuple(Vec::new()),
            "row_index".to_string(),
            "row".to_string(),
            "lookup_data".to_string(),
            "sub_component_inputs".to_string(),
            WriterShape::LookupSub,
            Vec::new(),
            Vec::new(),
        );
        let block: syn::Block = syn::parse_str(
            "{ let address =
                PackedM31::broadcast(M31::from(poseidon_builtin_segment_start)); }",
        )
        .unwrap();
        lw.lower_body(&block.stmts);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        assert_eq!(lw.env["address"], Ty::M31);
        assert_eq!(lw.enabler_slot(), 1);
        assert_eq!(lw.iota_slot(), 2);
        let body = lw.out.iter().map(ToString::to_string).collect::<String>();
        assert!(body.contains("eval . input (0)"), "body: {body}");
    }

    #[test]
    fn positive_single_logup_fraction_is_admitted_exactly() {
        let file: syn::File = syn::parse_str(
            "impl InteractionClaimGenerator {
                fn write_interaction_trace(&self) {
                    let mut col_gen = logup_gen.new_col();
                    (
                        col_gen.par_iter_mut(),
                        &self.lookup_data.poseidon_aggregator_6,
                        self.lookup_data.mults_0,
                    )
                        .into_par_iter()
                        .for_each(|(writer, values, mult)| {
                            let denom = common_lookup_elements.combine(values);
                            writer.write_frac((mult).into(), denom);
                        });
                    col_gen.finalize_col();
                }
            }",
        )
        .unwrap();
        assert_eq!(
            parse_logup_descs(&file),
            Some(vec![(
                "poseidon_aggregator_6".to_string(),
                "mults_0".to_string(),
                false,
                String::new(),
                String::new(),
                false,
            )])
        );
    }

    #[test]
    fn infer_input_fields() {
        let lw = lower_snippet(
            &[],
            "let a = add_opcode_input.pc; let b = add_opcode_input.fp;",
        );
        assert_eq!(lw.env["a"], Ty::M31);
        assert_eq!(lw.env["b"], Ty::M31);
        assert!(lw.skips.is_empty());
        assert!(lw.used_slots.contains("SLOT_PC"));
        assert!(lw.used_slots.contains("SLOT_FP"));
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(s.contains("eval . input (SLOT_PC)"));
        assert!(s.contains("eval . input (SLOT_FP)"));
    }

    #[test]
    fn infer_u16_bit_ops() {
        let lw = lower_snippet(
            &[("UInt16_127", ConstKind::U16, 127), ("UInt16_9", ConstKind::U16, 9)],
            "let f = memory_id_to_big_state.deduce_output(memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let x = ((PackedUInt16::from_m31(f.get_m31(1))) & (UInt16_127)) << (UInt16_9); \
             let y = x.as_m31();",
        );
        assert_eq!(lw.env["f"], Ty::Felt252);
        assert_eq!(lw.env["x"], Ty::U16);
        assert_eq!(lw.env["y"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        assert_eq!(lw.u32_sites, 0);
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(s.contains("u16_and"));
        assert!(s.contains("u16_shl"));
        assert!(s.contains("u16_as_m31"));
        assert!(s.contains("mem_addr_to_id"));
        assert!(s.contains("mem_id_to_value"));
        assert!(s.contains("felt_get_m31"));
    }

    #[test]
    fn u16_const_mask_on_left_of_and() {
        // add_opcode's sub_p_bit idiom: (UInt16_1) & (xor_chain)
        let lw = lower_snippet(
            &[("UInt16_1", ConstKind::U16, 1)],
            "let f = memory_id_to_big_state.deduce_output(memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let x = ((UInt16_1) & ((PackedUInt16::from_m31(f.get_m31(0))) ^ (PackedUInt16::from_m31(f.get_m31(1))))); \
             let y = x.as_m31();",
        );
        assert_eq!(lw.env["x"], Ty::U16);
        assert_eq!(lw.env["y"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(s.contains("u16_xor"));
        assert!(s.contains("u16_and"));
    }

    #[test]
    fn infer_m31_arith_and_consts() {
        let lw = lower_snippet(
            &[("M31_1", ConstKind::M31, 1), ("M31_8", ConstKind::M31, 8)],
            "let a = add_opcode_input.ap; let b = ((a) * (M31_8)) + ((M31_1) - (a));",
        );
        assert_eq!(lw.env["b"], Ty::M31);
        assert!(lw.skips.is_empty());
        assert!(lw.referenced_m31.contains(&1));
        assert!(lw.referenced_m31.contains(&8));
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(s.contains("m31_mul"));
        assert!(s.contains("m31_add"));
        assert!(s.contains("m31_sub"));
        assert!(s.contains("m31_8"), "const binding should be named m31_8");
    }

    #[test]
    fn infer_mask_ops() {
        let lw = lower_snippet(
            &[("M31_256", ConstKind::M31, 256), ("M31_511", ConstKind::M31, 511)],
            "let f = memory_id_to_big_state.deduce_output(memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let m = f.get_m31(27).eq(M31_256); \
             let n = (f.get_m31(20).eq(M31_511)) & (m); \
             let mc = m.as_m31();",
        );
        assert_eq!(lw.env["m"], Ty::Mask);
        assert_eq!(lw.env["n"], Ty::Mask);
        assert_eq!(lw.env["mc"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(s.contains("m31_eq"));
        assert!(s.contains("mask_and"));
        assert!(s.contains("mask_as_m31"));
    }

    #[test]
    fn tuple_projection_types() {
        let lw = lower_snippet(
            &[("M31_1", ConstKind::M31, 1), ("M31_0", ConstKind::M31, 0)],
            "let a = add_opcode_input.ap; \
             let t = ([a, a, a], [a, M31_1, M31_0], M31_0); \
             let u = (t.0[2]) + (t.1[1]);",
        );
        assert!(matches!(lw.env["t"], Ty::Tuple(_)));
        assert_eq!(lw.env["u"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
    }

    #[test]
    fn casm_state_struct_is_typed_and_projectable() {
        let lw = lower_snippet(
            &[],
            "let state = PackedCasmState { \
                 fp: add_opcode_input.fp, pc: add_opcode_input.pc, ap: add_opcode_input.ap, \
             }; \
             let next = state.pc + state.ap + state.fp;",
        );
        assert_eq!(lw.env["state"], Ty::CasmState);
        assert_eq!(lw.env["next"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        let body = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(body.contains("let state = ("), "body: {body}");
        assert!(body.contains("state . 0"), "body: {body}");
        assert!(body.contains("state . 1"), "body: {body}");
        assert!(body.contains("state . 2"), "body: {body}");
    }

    #[test]
    fn malformed_casm_state_struct_fails_closed() {
        for body in [
            "let state = PackedCasmState { pc: add_opcode_input.pc, ap: add_opcode_input.ap };",
            "let state = PackedCasmState { pc: add_opcode_input.pc, ap: add_opcode_input.ap, fp: add_opcode_input.fp, extra: add_opcode_input.pc };",
            "let state = OtherState { pc: add_opcode_input.pc, ap: add_opcode_input.ap, fp: add_opcode_input.fp };",
        ] {
            let lw = lower_snippet(&[], body);
            assert!(!lw.skips.is_empty(), "malformed struct was admitted: {body}");
        }
    }

    #[test]
    fn felt_from_m31_is_a_real_trait_op() {
        let lw = lower_snippet(
            &[],
            "let value = PackedFelt252::from_m31(add_opcode_input.ap); \
             let high = value.get_m31(3);",
        );
        assert_eq!(lw.env["value"], Ty::Felt252);
        assert_eq!(lw.env["high"], Ty::M31);
        assert_eq!(lw.u32_sites, 0);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        let body = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(body.contains("eval . felt_from_m31 ("), "body: {body}");
    }

    #[test]
    fn unknown_deduce_is_skip() {
        // A deduce whose signature is NOT in `known_deduce_output_ty` must stay a loud
        // skip (the fictional name keeps this test valid as the table grows).
        let lw = lower_snippet(
            &[],
            "let x = PackedNotInTheTable::deduce_output(add_opcode_input.pc);",
        );
        assert!(!lw.skips.is_empty());
        assert!(lw.skips.iter().any(|s| s.category == "deduce_output"));
        assert_eq!(lw.deduce_sites, 0);
    }

    #[test]
    fn known_deduce_types_result_and_counts_site() {
        // G5: a KNOWN-signature deduce types its result (here (M31, M31, ([M31;14],
        // [Felt252;2]))) so downstream projections resolve — .0 is M31 (usable in real
        // M31 ops), .2.1[0].get_m31(3) is a felt limb — with NO skips; the call itself
        // is census-only via `deduce_sites`, which blocks emission.
        let p = "add_opcode_input.pc";
        let windows = vec![p; 14].join(", ");
        let body = format!(
            "let f = memory_id_to_big_state.deduce_output(\
                 memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let out = PackedPartialEcMulWindowBits18::deduce_output((add_opcode_input.pc, \
             add_opcode_input.ap, ([{windows}], [f, f]))); \
             let chain = out.0; \
             let win0 = out.2.0[0]; \
             let acc_limb = out.2.1[0].get_m31(3); \
             let s = ((chain) + (win0)) + ((acc_limb) + (chain)); \
             let pt = PackedPedersenPointsTableWindowBits18::deduce_output([add_opcode_input.fp]); \
             let ptl = pt[1].get_m31(27);",
        );
        let lw = lower_snippet(&[], &body);
        // W18 + points-table are HOOKED: real trait calls, zero census-only sites.
        assert_eq!(
            lw.deduce_sites, 0,
            "hooked deduces are real ops; skips: {:?}",
            lw.skips
        );
        assert!(
            lw.skips.is_empty(),
            "projections off a typed deduce result must not skip: {:?}",
            lw.skips
        );
        let body = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(
            body.contains("eval . deduce_partial_ec_mul_w18 ("),
            "body: {body}"
        );
        assert!(
            body.contains("eval . deduce_pedersen_points_table_w18 ("),
            "body: {body}"
        );
    }

    #[test]
    fn window_bits_9_deduces_are_real_trait_ops() {
        let p = "add_opcode_input.pc";
        let windows = vec![p; 28].join(", ");
        let body = format!(
            "let f = memory_id_to_big_state.deduce_output(\
                 memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let out = PackedPartialEcMulWindowBits9::deduce_output((add_opcode_input.pc, \
             add_opcode_input.ap, ([{windows}], [f, f]))); \
             let chain = out.0; \
             let point = PackedPedersenPointsTableWindowBits9::deduce_output([chain]); \
             let limb = point[1].get_m31(27);",
        );
        let lw = lower_snippet(&[], &body);
        assert_eq!(lw.deduce_sites, 0, "skips: {:?}", lw.skips);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        let body = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(
            body.contains("eval . deduce_partial_ec_mul_w9 ("),
            "body: {body}"
        );
        assert!(
            body.contains("eval . deduce_pedersen_points_table_w9 ("),
            "body: {body}"
        );
    }

    #[test]
    fn poseidon_deduces_use_fixed_w27_word_shapes() {
        let lw = lower_snippet(
            &[],
            "let f = memory_id_to_big_state.deduce_output(\
                 memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let w = PackedFelt252Width27::from_packed_felt252(f); \
             let keys = PackedPoseidonRoundKeys::deduce_output([add_opcode_input.ap]); \
             let cube = PackedCube252::deduce_output(w); \
             let full = PackedPoseidonFullRoundChain::deduce_output((\
                 add_opcode_input.pc, add_opcode_input.ap, [cube, keys[1], keys[2]])); \
             let partial = PackedPoseidon3PartialRoundsChain::deduce_output((\
                 full.0, full.1, [full.2[0], full.2[1], full.2[2], cube])); \
             let output = partial.2[3].get_m31(9);",
        );
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        assert_eq!(lw.deduce_sites, 0);
        assert_eq!(lw.env["output"], Ty::M31);
        let body = lw.out.iter().map(|token| token.to_string()).collect::<String>();
        for operation in [
            "deduce_poseidon_round_keys",
            "deduce_poseidon_cube",
            "deduce_poseidon_full_round_chain",
            "deduce_poseidon_3_partial_rounds_chain",
        ] {
            assert!(body.contains(operation), "missing {operation}: {body}");
        }
    }

    #[test]
    fn u32_family_lowers_to_real_trait_ops() {
        let lw = lower_snippet(
            &[
                ("UInt32_511", ConstKind::U32, 511),
                ("UInt32_9", ConstKind::U32, 9),
            ],
            "let a = add_opcode_input.ap; \
             let x = PackedUInt32::from_m31(a); \
             let y = ((x) & (UInt32_511)) + ((x) << (UInt32_9)); \
             let z = y.low().as_m31(); \
             let w = y.high().as_m31();",
        );
        assert!(
            lw.skips.is_empty(),
            "u32 family must not skip: {:?}",
            lw.skips
        );
        // The whole family is REAL now (fp256-cohort u32 extension): from_m31,
        // masked and, const shl, wrapping add, low/high — zero census sites.
        assert_eq!(lw.u32_sites, 0, "u32 census sites");
        let body = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(body.contains("eval . u32_from_m31 ("), "body: {body}");
        assert!(body.contains("eval . u32_and_imm ("), "body: {body}");
        assert!(body.contains("eval . u32_shl_imm ("), "body: {body}");
        assert!(body.contains("eval . u32_add ("), "body: {body}");
        assert!(body.contains("eval . u32_low ("), "body: {body}");
        assert!(body.contains("eval . u32_high ("), "body: {body}");
        assert_eq!(lw.env["z"], Ty::M31);
        assert_eq!(lw.env["w"], Ty::M31);
    }

    #[test]
    fn shape_scalar_count_is_correct() {
        let s = Shape::Tuple(vec![
            Shape::Scalar,
            Shape::Array(vec![Shape::Scalar, Shape::Scalar, Shape::Scalar]),
            Shape::Array(vec![Shape::Scalar, Shape::Scalar]),
            Shape::Scalar,
            Shape::FeltW27,
        ]);
        assert_eq!(s.scalar_count(), 17);
    }

    #[test]
    fn lookup_field_width_parse() {
        let ty: Type = syn::parse_str("Vec<[PackedM31; 30]>").unwrap();
        assert_eq!(lookup_field_width(&ty), Some((30, false)));
        let ty2: Type = syn::parse_str("Vec<PackedM31>").unwrap();
        assert_eq!(lookup_field_width(&ty2), Some((1, true)));
    }

    /// Declaration-order layout: assignments interleaved in FILE order must still get
    /// bases from the struct declaration order (the shape-spec's documented layout).
    #[test]
    fn sub_layout_is_declaration_order() {
        let file: syn::File = syn::parse_str(
            "struct SubComponentInputs {\n\
                 verify_instruction: [Vec<(PackedM31, [PackedM31; 3], [PackedM31; 2], \
                 PackedM31)>; 1],\n\
                 memory_address_to_id: [Vec<PackedM31>; 2],\n\
                 memory_id_to_big: [Vec<PackedM31>; 2],\n\
             }",
        )
        .unwrap();
        let body: syn::Block = syn::parse_str(
            "{\n\
               *sub_component_inputs.verify_instruction[0] = (pc, [a, b, c], [d, e], z);\n\
               *sub_component_inputs.memory_address_to_id[0] = x0;\n\
               *sub_component_inputs.memory_id_to_big[0] = y0;\n\
               *sub_component_inputs.memory_address_to_id[1] = x1;\n\
               *sub_component_inputs.memory_id_to_big[1] = y1;\n\
             }",
        )
        .unwrap();
        let slots = build_sub_layout(&file, &body.stmts, "sub_component_inputs", None).unwrap();
        let got: Vec<(String, usize, usize)> = slots
            .iter()
            .map(|s| (s.field.clone(), s.index, s.base))
            .collect();
        assert_eq!(
            got,
            vec![
                ("verify_instruction".to_string(), 0, 0),
                ("memory_address_to_id".to_string(), 0, 7),
                ("memory_address_to_id".to_string(), 1, 8),
                ("memory_id_to_big".to_string(), 0, 9),
                ("memory_id_to_big".to_string(), 1, 10),
            ]
        );
        assert_eq!(
            slots.iter().map(|s| s.shape.scalar_count()).sum::<usize>(),
            11
        );
    }

    #[test]
    fn sub_layout_missing_assignment_is_loud() {
        let file: syn::File = syn::parse_str(
            "struct SubComponentInputs { memory_address_to_id: [Vec<PackedM31>; 2] }",
        )
        .unwrap();
        let body: syn::Block =
            syn::parse_str("{ *sub_component_inputs.memory_address_to_id[0] = x0; }").unwrap();
        let err = build_sub_layout(&file, &body.stmts, "sub_component_inputs", None).unwrap_err();
        assert!(err.detail.contains("never assigned"), "{}", err.detail);
    }

    #[test]
    fn sub_words_use_declaration_order_bases() {
        let file: syn::File = syn::parse_str(
            "struct SubComponentInputs {\n\
                 memory_address_to_id: [Vec<PackedM31>; 1],\n\
                 memory_id_to_big: [Vec<PackedM31>; 1],\n\
             }",
        )
        .unwrap();
        // FILE order writes memory_id_to_big FIRST; its flat base must still be 1.
        let body_src = "*sub_component_inputs.memory_id_to_big[0] = add_opcode_input.pc;\n\
                        *sub_component_inputs.memory_address_to_id[0] = add_opcode_input.ap;";
        let block: syn::Block = syn::parse_str(&format!("{{ {body_src} }}")).unwrap();
        let slots = build_sub_layout(&file, &block.stmts, "sub_component_inputs", None).unwrap();
        let lw = lower_snippet_with_slots(&[], body_src, slots);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        let s = lw
            .out
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let big_pos = s.find("set_sub_input_word (1").expect("big word at flat 1");
        let addr_pos = s
            .find("set_sub_input_word (0")
            .expect("addr word at flat 0");
        // File order: big (flat 1) is EMITTED before addr (flat 0).
        assert!(
            big_pos < addr_pos,
            "emission must follow file order with decl-order indices"
        );
    }

    // ---- Step-2 front-end: felt widths, felt consts, width conversions, seq ---------

    /// Bit-window decomposition mirrors `Felt252::from([u64;4])` + `get_m31` exactly
    /// (hand-computed vectors; the tool is standalone so no differential dep on the
    /// prover types — the per-component byte-equality gate is the end-to-end arbiter).
    #[test]
    fn felt_const_limb_decomposition() {
        // value = 1 → limb0 = 1, rest 0.
        let l = felt252_const_limbs([1, 0, 0, 0]);
        assert_eq!(l[0], 1);
        assert!(l[1..].iter().all(|&v| v == 0));

        // limb0 = 0x1FF, limb1 = 3 (value = 0x1FF | 3<<9).
        let l = felt252_const_limbs([0x1FF | (3 << 9), 0, 0, 0]);
        assert_eq!((l[0], l[1]), (0x1FF, 3));

        // Word-boundary window: limb 7 spans bits 63..72 → (w0>>63) | (w1<<1).
        let l = felt252_const_limbs([1u64 << 63, 0b1010, 0, 0]);
        assert_eq!(l[7], 1 | (0b1010 << 1));

        // Top word masked to 60 bits (252-bit value): all-ones w3 gives limb27 = 511
        // and no bits beyond 252 leak in.
        let l = felt252_const_limbs([0, 0, 0, u64::MAX]);
        assert_eq!(l[27], 511);
        // Every limb is a canonical 9-bit value.
        assert!(l.iter().all(|&v| v < 512));
    }

    #[test]
    fn felt_const_get_m31_is_const_limb() {
        let mut felts = BTreeMap::new();
        // value 1 → limb0 = 1, limb5 = 0.
        felts.insert(
            "Felt252_1_0_0_0".to_string(),
            felt252_const_limbs([1, 0, 0, 0]),
        );
        let lw = lower_snippet_full(
            &[],
            felts,
            Ty::Unknown,
            "let a = Felt252_1_0_0_0.get_m31(0); let b = Felt252_1_0_0_0.get_m31(5);",
            vec![],
        );
        assert_eq!(lw.env["a"], Ty::ConstM31(1));
        assert_eq!(lw.env["b"], Ty::ConstM31(0));
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        assert!(lw.referenced_m31.contains(&1));
        // No felt materialization needed for limb reads.
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(!s.contains("felt_from_limbs"));
    }

    #[test]
    fn felt_const_bare_use_materializes_from_limbs() {
        let mut felts = BTreeMap::new();
        felts.insert(
            "Felt252_1_0_0_0".to_string(),
            felt252_const_limbs([1, 0, 0, 0]),
        );
        let lw = lower_snippet_full(&[], felts, Ty::Unknown, "let f = Felt252_1_0_0_0;", vec![]);
        assert!(matches!(lw.env["f"], Ty::ConstFelt252(_)));
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(s.contains("felt_from_limbs"));
    }

    #[test]
    fn hoisted_felt_const_is_parsed() {
        let stmt: Stmt = syn::parse_str(
            "let Felt252_1_2_3_4 = PackedFelt252::broadcast(Felt252::from([1, 2, 3, 4]));",
        )
        .unwrap();
        let Stmt::Local(local) = stmt else { panic!() };
        assert_eq!(local_felt_const(&local), Some([1, 2, 3, 4]));
    }

    /// W27 get_m31: in-range is a census-only site (typed M31, blocks emission — the
    /// recording layer is 28x9 only); out-of-range is a LOUD skip (source bug).
    #[test]
    fn w27_input_get_m31_widths() {
        let lw = lower_snippet_full(
            &[],
            BTreeMap::new(),
            Ty::FeltW27,
            "let a = add_opcode_input.get_m31(9);",
            vec![],
        );
        assert_eq!(lw.env["a"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        // Real now: the input projects to 10 input reads; get_m31(9) is a plain
        // array index on the word tokens.
        assert_eq!(lw.w27_sites, 0);
        assert_eq!(lw.input_sites, 0);

        let lw = lower_snippet_full(
            &[],
            BTreeMap::new(),
            Ty::FeltW27,
            "let a = add_opcode_input.get_m31(10);",
            vec![],
        );
        assert!(
            lw.skips
                .iter()
                .any(|s| s.detail.contains("out of range for Felt252Width27")),
            "skips: {:?}",
            lw.skips
        );
    }

    /// Felt252 get_m31(i >= 28) is a loud skip, never a wrap.
    #[test]
    fn felt252_get_m31_out_of_range_is_loud() {
        let lw = lower_snippet(
            &[],
            "let f = memory_id_to_big_state.deduce_output(memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let a = f.get_m31(28);",
        );
        assert!(
            lw.skips
                .iter()
                .any(|s| s.detail.contains("out of range for Felt252")),
            "skips: {:?}",
            lw.skips
        );
    }

    /// f252 → w27 conversion (G2): 10 limbs, each `f9[3j] + f9[3j+1]*2^9 + f9[3j+2]*2^18`
    /// (j=9 → f9[27] alone); pure felt_get_m31 + m31_mul/m31_add — REAL lowering.
    #[test]
    fn from_packed_felt252_lowers_to_limb_schoolbook() {
        let lw = lower_snippet(
            &[],
            "let f = memory_id_to_big_state.deduce_output(memory_address_to_id_state.deduce_output(add_opcode_input.pc)); \
             let w = PackedFelt252Width27::from_packed_felt252(f); \
             let x = w.get_m31(0); let y = w.get_m31(9);",
        );
        assert_eq!(lw.env["w"], Ty::FeltW27Limbs);
        assert_eq!(lw.env["x"], Ty::M31);
        assert_eq!(lw.env["y"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        assert_eq!(lw.w27_sites, 0, "limb-backed W27 must not be census-only");
        let s = lw
            .out
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        // 28 limb extractions, weighted by 2^9 / 2^18.
        assert_eq!(s.matches("felt_get_m31").count(), 28);
        assert!(lw.referenced_m31.contains(&512));
        assert!(lw.referenced_m31.contains(&262144));
        // get_m31 on the limb-backed value is an array projection, not an eval op.
        assert!(s.contains("[9]"), "limb projection: {s}");
    }

    /// w27 → f252 needs 27-bit shift/mask (u32 extension) — census-only, typed Felt252.
    #[test]
    fn from_packed_felt252width27_lowers_to_real_trait_op() {
        let lw = lower_snippet_full(
            &[],
            BTreeMap::new(),
            Ty::FeltW27,
            "let f = PackedFelt252::from_packed_felt252width27(add_opcode_input); \
             let a = f.get_m31(20);",
            vec![],
        );
        assert_eq!(lw.env["f"], Ty::Felt252);
        assert_eq!(lw.env["a"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        // W27 inputs materialize as 10 real input reads; the conversion is the
        // REAL felt_from_w27_words trait op — nothing censused.
        assert_eq!(lw.w27_sites, 0);
        assert_eq!(lw.input_sites, 0);
        let body = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(body.contains("eval . felt_from_w27_words ("), "body: {body}");
        assert!(body.contains("eval . input ("), "body: {body}");
    }

    /// `seq.packed_at(row_index)` is the packed row index — a REAL `eval.iota()` op
    /// (G4); the record/driver assign its input slot after the flattened input words.
    #[test]
    fn seq_packed_at_is_real_iota() {
        let lw = lower_snippet(&[], "let s = seq.packed_at(row_index); let t = (s) * (s);");
        assert_eq!(lw.env["s"], Ty::M31);
        assert_eq!(lw.env["t"], Ty::M31);
        assert!(lw.skips.is_empty(), "skips: {:?}", lw.skips);
        assert!(lw.uses_iota);
        let s = lw.out.iter().map(|t| t.to_string()).collect::<String>();
        assert!(s.contains("eval . iota ()"), "body: {s}");
    }

    /// from_limbs with the wrong arity is a loud skip (the trait op is `[M31; 28]`).
    #[test]
    fn felt_from_limbs_arity_is_checked() {
        let lw = lower_snippet(
            &[],
            "let a = add_opcode_input.ap; let f = PackedFelt252::from_limbs([a, a, a]);",
        );
        assert!(
            lw.skips.iter().any(|s| s.detail.contains("!= 28 limbs")),
            "skips: {:?}",
            lw.skips
        );
    }

    include!("tests_emission.rs");
}
