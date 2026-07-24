//! Native CUDA correctness/capture gate for the prepared OODS primitive.

#![cfg(stwo_cuda_link)]

use num_traits::One;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::cpu::CpuCirclePoly;
use stwo_backend_cuda::{
    oods_workspace_requirements, ArenaLayout, ArenaSlotId, ArenaSlotSpec, CudaExecContext,
    DeviceArena, OodsArenaSlotRequirement, OodsColumnSource, OodsColumnTopology,
    OodsPassCollapseProgram, OodsPolynomialColumn, OodsWorkspaceConfig, OodsWorkspaceRequirements,
    OodsWorkspaceSlots, PreparedOodsGraph,
};

const PARAMETER: ArenaSlotId = ArenaSlotId(50_000);
const COLUMN_A: ArenaSlotId = ArenaSlotId(50_001);
const COLUMN_B: ArenaSlotId = ArenaSlotId(50_002);
const COLUMN_C: ArenaSlotId = ArenaSlotId(50_003);
const COLUMN_D: ArenaSlotId = ArenaSlotId(50_004);
const COLUMN_E: ArenaSlotId = ArenaSlotId(50_005);

fn workspace_slots() -> OodsWorkspaceSlots {
    OodsWorkspaceSlots {
        source_pointers: ArenaSlotId(1),
        offset_points: ArenaSlotId(2),
        fold_counts: ArenaSlotId(3),
        output_indices: ArenaSlotId(4),
        folding_factors: ArenaSlotId(5),
        scratch_a: ArenaSlotId(6),
        scratch_b: ArenaSlotId(7),
        sample_points: ArenaSlotId(8),
        sampled_values: ArenaSlotId(9),
        evaluation_points: ArenaSlotId(10),
        barycentric_numerators: ArenaSlotId(11),
        barycentric_weights: ArenaSlotId(12),
        barycentric_scales: ArenaSlotId(13),
        barycentric_partials: ArenaSlotId(14),
    }
}

fn arena(requirements: &OodsWorkspaceRequirements, slots: &OodsWorkspaceSlots) -> DeviceArena {
    let mut requested = requirements.arena_slot_requirements(slots).unwrap();
    requested.extend([
        OodsArenaSlotRequirement {
            id: PARAMETER,
            len_words: 4,
            alignment_words: 4,
        },
        OodsArenaSlotRequirement {
            id: COLUMN_A,
            len_words: 1 << 6,
            alignment_words: 1,
        },
        OodsArenaSlotRequirement {
            id: COLUMN_B,
            len_words: 1 << 11,
            alignment_words: 1,
        },
        OodsArenaSlotRequirement {
            id: COLUMN_C,
            len_words: 1 << 8,
            alignment_words: 1,
        },
        OodsArenaSlotRequirement {
            id: COLUMN_D,
            len_words: 1 << 4,
            alignment_words: 1,
        },
        OodsArenaSlotRequirement {
            id: COLUMN_E,
            len_words: 1 << 7,
            alignment_words: 1,
        },
    ]);
    let mut offset = 0usize;
    let mut specs = Vec::with_capacity(requested.len());
    for requirement in requested {
        offset = offset.next_multiple_of(requirement.alignment_words);
        specs.push(ArenaSlotSpec {
            id: requirement.id,
            offset_words: offset,
            len_words: requirement.len_words,
            alignment_words: requirement.alignment_words,
        });
        offset += requirement.len_words;
    }
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

fn upload_words(arena: &DeviceArena, slot: ArenaSlotId, words: &[u32]) {
    let destination = arena.bind(slot).unwrap();
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                words.as_ptr().cast(),
                core::mem::size_of_val(words),
            )
            .unwrap();
    }
}

fn write_parameter(arena: &DeviceArena, parameter: SecureField) {
    let words = parameter.to_m31_array().map(|coordinate| coordinate.0);
    upload_words(arena, PARAMETER, &words);
}

fn read_secure_fields(arena: &DeviceArena, slot: ArenaSlotId, count: usize) -> Vec<SecureField> {
    let source = arena.bind(slot).unwrap();
    let mut words = vec![0u32; 4 * count];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                source.as_void_ptr(),
                core::mem::size_of_val(words.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    words
        .chunks_exact(4)
        .map(|words| SecureField::from_u32_unchecked(words[0], words[1], words[2], words[3]))
        .collect()
}

fn read_points(
    arena: &DeviceArena,
    slot: ArenaSlotId,
    count: usize,
) -> Vec<CirclePoint<SecureField>> {
    let coordinates = read_secure_fields(arena, slot, 2 * count);
    coordinates
        .chunks_exact(2)
        .map(|point| CirclePoint {
            x: point[0],
            y: point[1],
        })
        .collect()
}

fn random_circle_point(parameter: SecureField) -> CirclePoint<SecureField> {
    let square = parameter.square();
    let denominator_inverse = (SecureField::one() + square).inverse();
    CirclePoint {
        x: (SecureField::one() - square) * denominator_inverse,
        y: (parameter + parameter) * denominator_inverse,
    }
}

fn expected(
    config: OodsWorkspaceConfig,
    parameter: SecureField,
    columns: &[(&[u32], u32, u32, &[isize])],
) -> (Vec<CirclePoint<SecureField>>, Vec<SecureField>) {
    let base = random_circle_point(parameter);
    let step = CanonicCoset::new(config.mask_log_size).step();
    let mut points = Vec::new();
    let mut values = Vec::new();
    for &(words, coefficient_log_size, evaluation_log_size, offsets) in columns {
        // Coefficient sources use CircleCoefficients' FFT basis in bit-reversed
        // order; they are neither monomial coefficients nor domain evaluations.
        assert_eq!(words.len(), 1 << coefficient_log_size);
        let poly = CpuCirclePoly::new(
            words
                .iter()
                .copied()
                .map(BaseField::from_u32_unchecked)
                .collect(),
        );
        for &offset in offsets {
            let point = base + step.mul_signed(offset).into_ef();
            points.push(point);
            values.push(poly.eval_at_point(
                point.repeated_double(config.lifting_log_size - evaluation_log_size),
            ));
        }
    }
    (points, values)
}

#[test]
fn exact_points_values_log4_lifting24_and_capture_replay() {
    let config = OodsWorkspaceConfig {
        lifting_log_size: 24,
        mask_log_size: 9,
    };
    let offsets_d = [0];
    let offsets_a = [-1, 0, 2];
    let offsets_b = [0, 5];
    let offsets_c = [-2, 0, 3];
    let topology = [
        OodsColumnTopology::coefficient_signed_offsets(4, 5, &offsets_d),
        OodsColumnTopology::coefficient_signed_offsets(6, 7, &offsets_a),
        OodsColumnTopology::coefficient_signed_offsets(11, 12, &offsets_b),
        OodsColumnTopology::evaluation_signed_offsets(8, &offsets_c),
        OodsColumnTopology::evaluation_signed_offsets(7, &offsets_a),
    ];
    let requirements = oods_workspace_requirements(config, &topology).unwrap();
    let pass_collapse = OodsPassCollapseProgram::compile(config, &topology).unwrap();
    let log8_cohort = pass_collapse
        .receipt()
        .same_log_cohorts
        .iter()
        .find(|cohort| cohort.log_size == 8)
        .unwrap();
    assert!(log8_cohort.batches.len() > 1);
    assert!(log8_cohort
        .batches
        .iter()
        .any(|batch| batch.first_group > log8_cohort.first_group));
    let mut arena_requirements = requirements.clone();
    let collapsed_requirements = pass_collapse.collapsed_requirements();
    arena_requirements.barycentric_numerator_words = arena_requirements
        .barycentric_numerator_words
        .max(collapsed_requirements.barycentric_numerator_words);
    arena_requirements.barycentric_weight_words = arena_requirements
        .barycentric_weight_words
        .max(collapsed_requirements.barycentric_weight_words);
    arena_requirements.barycentric_scale_words = arena_requirements
        .barycentric_scale_words
        .max(collapsed_requirements.barycentric_scale_words);
    let slots = workspace_slots();
    let arena = arena(&arena_requirements, &slots);
    let host_d: Vec<u32> = (0..1 << 4).map(|i| (13 * i + 7) & 0x7fff_ffff).collect();
    let host_a: Vec<u32> = (0..1 << 6).map(|i| (17 * i + 3) & 0x7fff_ffff).collect();
    let host_b: Vec<u32> = (0..1 << 11)
        .map(|i| (7919 * i + 11) & 0x7fff_ffff)
        .collect();
    let host_c_coefficients: Vec<u32> = (0..1 << 8)
        .map(|i| (104_729 * i + 29) & 0x7fff_ffff)
        .collect();
    let host_c_evaluations: Vec<u32> = CpuCirclePoly::new(
        host_c_coefficients
            .iter()
            .copied()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    )
    .evaluate(CanonicCoset::new(8).circle_domain())
    .values
    .into_iter()
    .map(|value| value.0)
    .collect();
    let host_a_evaluations: Vec<u32> = CpuCirclePoly::new(
        host_a
            .iter()
            .copied()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    )
    .evaluate(CanonicCoset::new(7).circle_domain())
    .values
    .into_iter()
    .map(|value| value.0)
    .collect();
    upload_words(&arena, COLUMN_D, &host_d);
    upload_words(&arena, COLUMN_A, &host_a);
    upload_words(&arena, COLUMN_B, &host_b);
    upload_words(&arena, COLUMN_C, &host_c_evaluations);
    upload_words(&arena, COLUMN_E, &host_a_evaluations);
    arena.context().sync().unwrap();

    let columns = [
        OodsPolynomialColumn {
            source: OodsColumnSource::Coefficients(arena.bind(COLUMN_D).unwrap()),
            topology: topology[0],
        },
        OodsPolynomialColumn {
            source: OodsColumnSource::Coefficients(arena.bind(COLUMN_A).unwrap()),
            topology: topology[1],
        },
        OodsPolynomialColumn {
            source: OodsColumnSource::Coefficients(arena.bind(COLUMN_B).unwrap()),
            topology: topology[2],
        },
        OodsPolynomialColumn {
            source: OodsColumnSource::Evaluations(arena.bind(COLUMN_C).unwrap()),
            topology: topology[3],
        },
        OodsPolynomialColumn {
            source: OodsColumnSource::Evaluations(arena.bind(COLUMN_E).unwrap()),
            topology: topology[4],
        },
    ];
    let legacy = PreparedOodsGraph::prepare_mixed(
        &arena,
        config,
        &columns,
        arena.bind(PARAMETER).unwrap(),
        &slots,
    )
    .unwrap();

    let first_parameter = SecureField::from_u32_unchecked(2, 3, 5, 7);
    write_parameter(&arena, first_parameter);
    legacy.launch().unwrap();
    let (first_points, first_values) = expected(
        config,
        first_parameter,
        &[
            (&host_d, 4, 5, &offsets_d),
            (&host_a, 6, 7, &offsets_a),
            (&host_b, 11, 12, &offsets_b),
            (&host_c_coefficients, 8, 8, &offsets_c),
            (&host_a, 6, 7, &offsets_a),
        ],
    );
    let first_actual_points = read_points(&arena, slots.sample_points, requirements.sample_count);
    let first_actual_values =
        read_secure_fields(&arena, slots.sampled_values, requirements.sample_count);
    assert_eq!(first_actual_points, first_points);
    assert_eq!(first_actual_values, first_values);

    // Preparing the collapsed graph after the legacy launch refreshes the
    // immutable descriptor-offset table in the retired scale slot. This also
    // proves that a nonzero batch base selects the same canonical groups.
    let collapsed = PreparedOodsGraph::prepare_mixed_pass_collapsed(
        &arena,
        config,
        &columns,
        arena.bind(PARAMETER).unwrap(),
        &slots,
        &pass_collapse,
    )
    .unwrap();
    assert_eq!(
        collapsed.requirements(),
        pass_collapse.collapsed_requirements()
    );
    write_parameter(&arena, first_parameter);
    collapsed.launch().unwrap();
    assert_eq!(
        read_points(&arena, slots.sample_points, requirements.sample_count),
        first_actual_points
    );
    assert_eq!(
        read_secure_fields(&arena, slots.sampled_values, requirements.sample_count),
        first_actual_values
    );
    let coefficient_range = requirements.column_ranges[1];
    let evaluation_range = requirements.column_ranges[4];
    assert_eq!(
        coefficient_range.sample_count,
        evaluation_range.sample_count
    );
    assert_eq!(
        &first_actual_points[coefficient_range.first_sample
            ..coefficient_range.first_sample + coefficient_range.sample_count],
        &first_actual_points[evaluation_range.first_sample
            ..evaluation_range.first_sample + evaluation_range.sample_count]
    );
    assert_eq!(
        &first_actual_values[coefficient_range.first_sample
            ..coefficient_range.first_sample + coefficient_range.sample_count],
        &first_actual_values[evaluation_range.first_sample
            ..evaluation_range.first_sample + evaluation_range.sample_count]
    );

    let capture = arena.context().capture().unwrap();
    collapsed.launch().unwrap();
    let graph = capture.finish().unwrap();
    let second_parameter = SecureField::from_u32_unchecked(13, 17, 19, 23);
    write_parameter(&arena, second_parameter);
    graph.launch(arena.context()).unwrap();
    let (second_points, second_values) = expected(
        config,
        second_parameter,
        &[
            (&host_d, 4, 5, &offsets_d),
            (&host_a, 6, 7, &offsets_a),
            (&host_b, 11, 12, &offsets_b),
            (&host_c_coefficients, 8, 8, &offsets_c),
            (&host_a, 6, 7, &offsets_a),
        ],
    );
    assert_eq!(
        read_points(&arena, slots.sample_points, requirements.sample_count),
        second_points
    );
    assert_eq!(
        read_secure_fields(&arena, slots.sampled_values, requirements.sample_count),
        second_values
    );
}
