use stwo::core::utils::offset_bit_reversed_circle_domain_index;

use super::*;
use crate::backend::jit::program::{
    MetalEvaluationProgramBaseInstV1, MetalEvaluationProgramExtInstV1,
    MetalEvaluationProgramHeaderV1,
};

#[test]
fn generated_m31_fast32_candidate_is_default_off_and_preserves_fallback() {
    let mut source = String::new();
    emit_preamble(&mut source);
    for required in [
        "#define STWO_M31_FAST32_GLOBAL 0",
        "#if STWO_M31_FAST32_GLOBAL",
        "unsigned hi = __umulhi(lhs, rhs);",
        "u64 product = (u64)lhs * (u64)rhs;",
        "#error \"STWO_M31_FAST32_GLOBAL must be 0 or 1\"",
    ] {
        assert!(
            source.contains(required),
            "missing preamble gate: {required}"
        );
    }
    assert!(
        source.find("#if STWO_M31_FAST32_GLOBAL").unwrap()
            < source.find("u64 product = (u64)lhs * (u64)rhs;").unwrap()
    );
}

#[test]
fn shifted_trace_codegen_threads_the_true_trace_log() {
    let header = MetalEvaluationProgramHeaderV1::new(0, 0x1234, 0, 1, 0, 0, 1, 1, 1);
    let program = OwnedMetalEvaluationProgramV1::from_parts(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![MetalEvaluationProgramBaseInstV1::trace_col(0, 0, 0, -1)],
        vec![MetalEvaluationProgramExtInstV1::secure_col(0, 0, 0, 0, 0)],
        vec![0],
    );
    let source = compile_v1_to_cuda_source(&program).unwrap();
    assert!(source.contains("interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, -1);"));
    assert!(source.contains(
        "unsigned log_n_rows, unsigned interaction, unsigned column, unsigned row_index"
    ));
    assert!(!source.contains("domain_log_size = eval_log_size - 1u"));
}

#[test]
fn composition_wave_keeps_parts_ordered_and_writes_each_accumulator_row_once() {
    let program = |semantic_hash, trace_column| {
        OwnedMetalEvaluationProgramV1::from_parts(
            MetalEvaluationProgramHeaderV1::new(0, semantic_hash, 0, 1, 0, 0, 1, 1, 1),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![MetalEvaluationProgramBaseInstV1::trace_col(
                0,
                0,
                trace_column,
                0,
            )],
            vec![MetalEvaluationProgramExtInstV1::secure_col(0, 0, 0, 0, 0)],
            vec![0],
        )
    };
    let first = program(0x1111, 3);
    let second = program(0x2222, 7);
    let source =
        compile_composition_wave_to_cuda_source(&[&first, &second], "stwo_composition_wave_test")
            .unwrap();
    let global = source.find("extern \"C\" __global__").unwrap();
    let first_call = source[global..]
        .find("wave_acc = stwo_qm31_add(wave_acc, stwo_composition_wave_part_0(")
        .unwrap();
    let second_call = source[global..]
        .find("wave_acc = stwo_qm31_add(wave_acc, stwo_composition_wave_part_1(")
        .unwrap();
    assert!(first_call < second_call);
    assert_eq!(source.matches("__device__ __noinline__").count(), 2);
    assert!(source.contains("static_assert(sizeof(StwoCudaCompositionWavePart) == 48"));
    assert!(source.contains("parts[0u], random_coeff_powers"));
    assert!(source.contains("parts[1u], random_coeff_powers"));
    assert!(source.contains("unsigned rc_base = part.rc_base;"));
    assert!(source.contains("return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);"));
    assert!(source.contains("unsigned full_domain_rows,"));
    assert!(source.contains("unsigned shard_start,"));
    assert!(source.contains("unsigned shard_rows"));
    assert!(source.contains("shard_rows > full_domain_rows - shard_start"));
    assert!(source.contains("unsigned row_index = shard_start + local_row;"));
    assert!(source.contains("parts[0u], random_coeff_powers, full_domain_rows, row_index"));
    assert!(source.contains("coord_0[local_row] = wave_acc.a;"));
    assert!(!source.contains("coord_0[row_index]"));
    assert!(!source.contains("local_row, row_index"));
    assert!(!source.contains("part_count"));
}

#[test]
fn ext_stream_is_emitted_in_order_at_its_base_dependency_frontier() {
    let header = MetalEvaluationProgramHeaderV1::new(0, 0x5678, 0, 1, 0, 1, 1, 3, 5);
    let base = vec![
        MetalEvaluationProgramBaseInstV1::trace_col(0, 0, 0, 0),
        MetalEvaluationProgramBaseInstV1::trace_col(1, 0, 1, 0),
        MetalEvaluationProgramBaseInstV1::binary(BaseOp::Add, 2, 0, 1),
    ];
    let ext = vec![
        MetalEvaluationProgramExtInstV1::secure_col(0, 0, 0, 0, 0),
        MetalEvaluationProgramExtInstV1 {
            op: ExtOp::Param as u8,
            reserved0: 0,
            dst: 1,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
        },
        MetalEvaluationProgramExtInstV1 {
            op: ExtOp::Add as u8,
            reserved0: 0,
            dst: 2,
            a: 0,
            b: 1,
            c: 0,
            d: 0,
        },
        MetalEvaluationProgramExtInstV1::secure_col(3, 2, 2, 2, 2),
        MetalEvaluationProgramExtInstV1 {
            op: ExtOp::Add as u8,
            reserved0: 0,
            dst: 4,
            a: 2,
            b: 3,
            c: 0,
            d: 0,
        },
    ];
    let program = OwnedMetalEvaluationProgramV1::from_parts(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        base,
        ext,
        vec![4],
    );
    let source = compile_v1_to_cuda_source(&program).unwrap();
    let at = |needle| {
        source
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };

    assert!(at("unsigned b0 =") < at("StwoCudaQm31 e0 ="));
    assert!(at("StwoCudaQm31 e0 =") < at("StwoCudaQm31 e1 ="));
    assert!(at("StwoCudaQm31 e1 =") < at("StwoCudaQm31 e2 ="));
    assert!(at("StwoCudaQm31 e2 =") < at("unsigned b1 ="));
    assert!(at("unsigned b2 =") < at("StwoCudaQm31 e3 ="));
    assert!(at("StwoCudaQm31 e3 =") < at("StwoCudaQm31 e4 ="));
    assert!(at("StwoCudaQm31 e4 =") < at("rc_base + 0u"));
}

#[test]
fn versioned_base_cones_load_at_first_secure_use() {
    let header = MetalEvaluationProgramHeaderV1::new(0, 0x6789, 0, 1, 1, 0, 1, 4, 3);
    let base = vec![
        MetalEvaluationProgramBaseInstV1::trace_col(0, 0, 0, 0),
        MetalEvaluationProgramBaseInstV1::trace_col(1, 0, 1, 0),
        MetalEvaluationProgramBaseInstV1::trace_col(2, 0, 2, 0),
        MetalEvaluationProgramBaseInstV1 {
            op: BaseOp::Param as u8,
            interaction: 0,
            dst: 3,
            a: 0,
            b: 0,
            imm: 0,
        },
        // Reuse compact register 1. The SecureCol must reference this final
        // definition, whose dependency remains the earlier trace definition.
        MetalEvaluationProgramBaseInstV1::binary(BaseOp::Mul, 1, 1, 3),
    ];
    let ext = vec![
        MetalEvaluationProgramExtInstV1::secure_col(0, 0, 3, 3, 3),
        MetalEvaluationProgramExtInstV1::secure_col(1, 1, 3, 3, 3),
        MetalEvaluationProgramExtInstV1::secure_col(2, 2, 3, 3, 3),
    ];
    let program = OwnedMetalEvaluationProgramV1::from_parts(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        base,
        ext,
        vec![2],
    );
    let source = compile_v1_to_cuda_source(&program).unwrap();
    let at = |needle| {
        source
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };

    // Late base Param definition 3 is pulled next to the first trace use;
    // unrelated traces 1 and 2 are not loaded until their SecureCols.
    assert!(at("unsigned b0 = stwo_trace_value") < at("unsigned b3 = base_params[0u]"));
    assert!(at("unsigned b3 = base_params[0u]") < at("StwoCudaQm31 e0 ="));
    assert!(at("StwoCudaQm31 e0 =") < at("unsigned b1 = stwo_trace_value"));
    assert!(at("unsigned b1 = stwo_trace_value") < at("unsigned b4 = stwo_m31_mul(b1, b3)"));
    assert!(at("unsigned b4 = stwo_m31_mul(b1, b3)") < at("StwoCudaQm31 e1 ="));
    assert!(at("StwoCudaQm31 e1 =") < at("unsigned b2 = stwo_trace_value"));
}

#[test]
fn dead_pure_base_definition_is_deliberately_omitted() {
    let header = MetalEvaluationProgramHeaderV1::new(0, 0x789a, 0, 1, 0, 0, 1, 2, 1);
    let program = OwnedMetalEvaluationProgramV1::from_parts(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![
            MetalEvaluationProgramBaseInstV1::trace_col(0, 0, 0, 0),
            MetalEvaluationProgramBaseInstV1::trace_col(1, 0, 1, 0),
        ],
        vec![MetalEvaluationProgramExtInstV1::secure_col(0, 0, 0, 0, 0)],
        vec![0],
    );
    let source = compile_v1_to_cuda_source(&program).unwrap();
    assert!(source.contains("0u, 0u, row_index, 0"));
    assert!(!source.contains("0u, 1u, row_index, 0"));
}

#[test]
fn production_depth_base_cone_uses_an_iterative_host_traversal() {
    const DEPTH: usize = 32_768;
    let mut base = Vec::with_capacity(DEPTH + 1);
    base.push(MetalEvaluationProgramBaseInstV1::const_value(0, 1));
    base.extend((0..DEPTH).map(|_| MetalEvaluationProgramBaseInstV1::binary(BaseOp::Add, 0, 0, 0)));
    let header = MetalEvaluationProgramHeaderV1::new(0, 0x8abc, 0, 0, 0, 0, 1, 1, 1);
    let program = OwnedMetalEvaluationProgramV1::from_parts(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        base,
        vec![MetalEvaluationProgramExtInstV1::secure_col(0, 0, 0, 0, 0)],
        vec![0],
    );
    let source = compile_v1_to_cuda_source(&program).expect("deep valid cone must emit");
    assert!(source.contains(&format!("unsigned b{DEPTH} =")));
    assert!(source.contains("rc_base + 0u"));
}

#[test]
fn versioned_schedule_matches_conventional_execution_with_reuse_and_shared_cones() {
    let base = vec![
        MetalEvaluationProgramBaseInstV1::const_value(0, 2),
        MetalEvaluationProgramBaseInstV1::const_value(1, 3),
        MetalEvaluationProgramBaseInstV1::binary(BaseOp::Add, 2, 0, 1),
        MetalEvaluationProgramBaseInstV1::binary(BaseOp::Mul, 0, 0, 2),
        MetalEvaluationProgramBaseInstV1::binary(BaseOp::Add, 0, 0, 1),
        MetalEvaluationProgramBaseInstV1::binary(BaseOp::Mul, 1, 1, 2),
    ];
    let ext = vec![
        MetalEvaluationProgramExtInstV1::secure_col(0, 0, 1, 2, 2),
        ext_binary(ExtOp::Add, 0, 0, 0),
        ext_const(1, 7),
        ext_binary(ExtOp::Add, 2, 0, 1),
        ext_binary(ExtOp::Mul, 1, 1, 2),
    ];
    // Duplicate e0, root later consumed, and non-monotonic definitions [1, 3, 1].
    let roots = vec![0, 2, 0];
    let header =
        MetalEvaluationProgramHeaderV1::new(0, 0xa123, 0, 0, 0, 0, roots.len() as u32, 3, 3);
    let program = OwnedMetalEvaluationProgramV1::from_parts(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        base,
        ext,
        roots,
    );

    let mut conventional_base = [0i64; 3];
    for inst in program.base_insts() {
        conventional_base[inst.dst as usize] = match BaseOp::from_raw(inst.op).unwrap() {
            BaseOp::Const => i64::from(inst.a),
            BaseOp::Add => conventional_base[inst.a as usize] + conventional_base[inst.b as usize],
            BaseOp::Mul => conventional_base[inst.a as usize] * conventional_base[inst.b as usize],
            opcode => panic!("unexpected base opcode {opcode:?}"),
        };
    }
    assert_eq!(conventional_base, [13, 15, 5]);

    let schedule = BaseDefinitionSchedule::build(&program).unwrap();
    let mut definition_values = vec![None; schedule.nodes.len()];
    let scheduled_base = std::array::from_fn(|register| {
        evaluate_base_definition(
            schedule.final_definition(register as u32).unwrap(),
            &schedule,
            &mut definition_values,
        )
    });
    assert_eq!(scheduled_base, conventional_base);

    let coefficients = [5i64, 7, 11];
    let definitions = constraint_root_final_definitions(&program).unwrap();
    assert_eq!(definitions, [1, 3, 1]);
    let mut ext_values = [0i64; 3];
    let mut next_root = 0usize;
    let mut scheduled_acc = 0i64;
    for (ext_i, inst) in program.ext_insts().iter().enumerate() {
        ext_values[inst.dst as usize] = match ExtOp::from_raw(inst.op).unwrap() {
            ExtOp::SecureCol => [inst.a, inst.b, inst.c, inst.d]
                .into_iter()
                .map(|register| scheduled_base[register as usize])
                .sum(),
            ExtOp::Const => i64::from(inst.a),
            ExtOp::Add => ext_values[inst.a as usize] + ext_values[inst.b as usize],
            ExtOp::Mul => ext_values[inst.a as usize] * ext_values[inst.b as usize],
            opcode => panic!("unexpected ext opcode {opcode:?}"),
        };
        while definitions
            .get(next_root)
            .is_some_and(|&definition| definition <= ext_i)
        {
            scheduled_acc += ext_values[program.constraint_roots()[next_root] as usize]
                * coefficients[next_root];
            next_root += 1;
        }
    }
    let conventional_acc = program
        .constraint_roots()
        .iter()
        .zip(coefficients)
        .map(|(&root, coefficient)| ext_values[root as usize] * coefficient)
        .sum::<i64>();
    assert_eq!(scheduled_acc, conventional_acc);

    let source = compile_v1_to_cuda_source(&program).unwrap();
    assert!(source.find("rc_base + 0u").unwrap() < source.find("e2 =").unwrap());
    assert!(source.find("rc_base + 1u").unwrap() < source.find("rc_base + 2u").unwrap());
}

#[test]
fn malformed_definition_sources_and_roots_fail_closed() {
    let undefined_base = OwnedMetalEvaluationProgramV1::from_parts(
        MetalEvaluationProgramHeaderV1::new(0, 0xb123, 0, 0, 0, 0, 1, 1, 1),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![MetalEvaluationProgramBaseInstV1::binary(
            BaseOp::Add,
            0,
            0,
            0,
        )],
        vec![MetalEvaluationProgramExtInstV1::secure_col(0, 0, 0, 0, 0)],
        vec![0],
    );
    assert!(compile_v1_to_cuda_source(&undefined_base).is_none());

    let undefined_secure_base = OwnedMetalEvaluationProgramV1::from_parts(
        MetalEvaluationProgramHeaderV1::new(0, 0xb124, 0, 0, 0, 0, 1, 2, 1),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![MetalEvaluationProgramBaseInstV1::const_value(0, 1)],
        vec![MetalEvaluationProgramExtInstV1::secure_col(0, 1, 0, 0, 0)],
        vec![0],
    );
    assert!(compile_v1_to_cuda_source(&undefined_secure_base).is_none());

    let undefined_ext = OwnedMetalEvaluationProgramV1::from_parts(
        MetalEvaluationProgramHeaderV1::new(0, 0xb125, 0, 0, 0, 0, 1, 1, 2),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![MetalEvaluationProgramBaseInstV1::const_value(0, 1)],
        vec![ext_binary(ExtOp::Add, 0, 1, 1)],
        vec![0],
    );
    assert!(compile_v1_to_cuda_source(&undefined_ext).is_none());

    let undefined_root = OwnedMetalEvaluationProgramV1::from_parts(
        MetalEvaluationProgramHeaderV1::new(0, 0xb126, 0, 0, 0, 0, 1, 0, 2),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![ext_const(0, 1)],
        vec![1],
    );
    assert!(compile_v1_to_cuda_source(&undefined_root).is_none());
}

#[test]
fn roots_accumulate_in_canonical_order_at_their_final_definitions() {
    let ext = vec![
        ext_const(0, 2),
        ext_const(1, 3),
        ext_binary(ExtOp::Add, 0, 0, 1), // Final e0 is 5, not the first write.
        ext_const(2, 7),
        ext_binary(ExtOp::Mul, 3, 0, 2),
    ];
    let roots = vec![0, 3, 1];
    let header =
        MetalEvaluationProgramHeaderV1::new(0, 0x9abc, 0, 0, 0, 0, roots.len() as u32, 0, 4);
    let program = OwnedMetalEvaluationProgramV1::from_parts(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        ext,
        roots,
    );
    assert_eq!(
        constraint_root_final_definitions(&program),
        Some(vec![2, 4, 1])
    );

    let source = compile_v1_to_cuda_source(&program).unwrap();
    let at = |needle| {
        source
            .find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };
    let first_e0 = at("StwoCudaQm31 e0 =");
    let final_e0 = at("e0 = stwo_qm31_add(e0, e1);");
    assert!(first_e0 < final_e0);
    assert!(final_e0 < at("rc_base + 0u"));
    assert!(at("rc_base + 0u") < at("StwoCudaQm31 e2 ="));
    assert!(at("StwoCudaQm31 e3 =") < at("rc_base + 1u"));
    assert!(at("rc_base + 1u") < at("rc_base + 2u"));

    // A tiny structural interpreter verifies that moving the same ordered
    // multiply-adds to these frontiers preserves the end-of-program sum.
    let coefficients = [5i64, 7, 11];
    let mut values = [0i64; 4];
    let definitions = constraint_root_final_definitions(&program).unwrap();
    let mut next_root = 0usize;
    let mut early = 0i64;
    for (ext_i, inst) in program.ext_insts().iter().enumerate() {
        values[inst.dst as usize] = match ExtOp::from_raw(inst.op).unwrap() {
            ExtOp::Const => i64::from(inst.a),
            ExtOp::Add => values[inst.a as usize] + values[inst.b as usize],
            ExtOp::Mul => values[inst.a as usize] * values[inst.b as usize],
            opcode => panic!("unexpected test opcode {opcode:?}"),
        };
        while definitions
            .get(next_root)
            .is_some_and(|&definition| definition <= ext_i)
        {
            early +=
                values[program.constraint_roots()[next_root] as usize] * coefficients[next_root];
            next_root += 1;
        }
    }
    let conventional = program
        .constraint_roots()
        .iter()
        .zip(coefficients)
        .map(|(&root, coefficient)| values[root as usize] * coefficient)
        .sum::<i64>();
    assert_eq!(early, conventional);
    assert_eq!(next_root, program.constraint_roots().len());
}

fn ext_const(dst: u16, value: u32) -> MetalEvaluationProgramExtInstV1 {
    MetalEvaluationProgramExtInstV1 {
        op: ExtOp::Const as u8,
        reserved0: 0,
        dst,
        a: value,
        b: 0,
        c: 0,
        d: 0,
    }
}

fn ext_binary(op: ExtOp, dst: u16, a: u32, b: u32) -> MetalEvaluationProgramExtInstV1 {
    MetalEvaluationProgramExtInstV1 {
        op: op as u8,
        reserved0: 0,
        dst,
        a,
        b,
        c: 0,
        d: 0,
    }
}

fn evaluate_base_definition(
    definition: usize,
    schedule: &BaseDefinitionSchedule,
    values: &mut [Option<i64>],
) -> i64 {
    if let Some(value) = values[definition] {
        return value;
    }
    let node = schedule.nodes[definition];
    let dependency = |index: usize, values: &mut [Option<i64>]| {
        evaluate_base_definition(
            node.dependencies[index].expect("test dependency"),
            schedule,
            values,
        )
    };
    let value = match BaseOp::from_raw(node.inst.op).unwrap() {
        BaseOp::Const => i64::from(node.inst.a),
        BaseOp::Add => dependency(0, values) + dependency(1, values),
        BaseOp::Sub => dependency(0, values) - dependency(1, values),
        BaseOp::Mul => dependency(0, values) * dependency(1, values),
        BaseOp::Neg => -dependency(0, values),
        opcode => panic!("unexpected scheduled base opcode {opcode:?}"),
    };
    values[definition] = Some(value);
    value
}

#[test]
fn two_bit_expansion_disproves_the_legacy_shifted_index() {
    const TRACE_LOG_SIZE: u32 = 6;
    const EVALUATION_LOG_SIZE: u32 = 8;
    let first_difference = (0..1usize << EVALUATION_LOG_SIZE)
        .find_map(|row| {
            let expected = offset_bit_reversed_circle_domain_index(
                row,
                TRACE_LOG_SIZE,
                EVALUATION_LOG_SIZE,
                -1,
            );
            let legacy = offset_bit_reversed_circle_domain_index(
                row,
                EVALUATION_LOG_SIZE - 1,
                EVALUATION_LOG_SIZE,
                -1,
            );
            (expected != legacy).then_some((row, expected, legacy))
        })
        .expect("two-bit expansion must distinguish the true trace domain");
    assert_eq!(first_difference, (0, 126, 254));
}
