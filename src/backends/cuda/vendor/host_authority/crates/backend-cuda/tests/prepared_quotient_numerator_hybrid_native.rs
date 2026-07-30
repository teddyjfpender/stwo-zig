//! Native CUDA gate for the mixed-source quotient-numerator schedule.
//! gpu-lab-cohesion-review: one fixture must own all three schedules and both launches so shared
//! topology cannot hide a descriptor, capture, mutability, or warm-path regression.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};
use stwo_backend_cuda::{
    quotient_numerator_hybrid_plan, quotient_numerator_workspace_requirements, ArenaLayout,
    ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, CudaGraphExec, DeviceArena,
    PreparedQuotientNumeratorGraph, QuotientNumeratorColumn, QuotientNumeratorColumnSource,
    QuotientNumeratorColumnTopology, QuotientNumeratorDestination, QuotientNumeratorSourceKind,
    QuotientNumeratorWorkspaceConfig, QuotientNumeratorWorkspaceSlots, QuotientOodsSample,
};

const OODS_POINTS: ArenaSlotId = ArenaSlotId(50_000);
const OODS_VALUES: ArenaSlotId = ArenaSlotId(50_001);
const RANDOM_COEFFICIENT: ArenaSlotId = ArenaSlotId(50_002);
const SAMPLE_POINTS_OUTPUT: ArenaSlotId = ArenaSlotId(50_003);
const FIRST_TERMS_OUTPUT: ArenaSlotId = ArenaSlotId(50_004);
const TWIDDLES: ArenaSlotId = ArenaSlotId(50_005);
const EVAL_A: ArenaSlotId = ArenaSlotId(50_006);
const COEFF_A: ArenaSlotId = ArenaSlotId(50_007);
const COEFF_B: ArenaSlotId = ArenaSlotId(50_008);
const COEFF_C: ArenaSlotId = ArenaSlotId(50_009);
const OUTPUT_BASE: u32 = 60_000;
const SLOT_WORDS: usize = 4096;

#[test]
fn mixed_hybrid_is_byte_identical_warm_capture_safe_and_source_immutable() {
    use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

    let config = QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 6,
        log_blowup_factor: 2,
        max_lde_tile_words: 256,
    };
    let p0 = SECURE_FIELD_CIRCLE_GEN.mul(3);
    let p1 = SECURE_FIELD_CIRCLE_GEN.mul(7);
    let coefficient_topology = vec![
        topology(4, QuotientNumeratorSourceKind::Coefficients, 0, p0),
        topology(3, QuotientNumeratorSourceKind::Coefficients, 1, p1),
        topology(4, QuotientNumeratorSourceKind::Coefficients, 2, p1),
    ];
    let mut mixed_topology = coefficient_topology.clone();
    mixed_topology[0].source_kind = QuotientNumeratorSourceKind::Evaluation;
    let coefficient_requirements =
        quotient_numerator_workspace_requirements(config, &coefficient_topology).unwrap();
    let mixed_requirements =
        quotient_numerator_workspace_requirements(config, &mixed_topology).unwrap();
    assert_eq!(coefficient_requirements.groups, mixed_requirements.groups);
    assert_eq!(
        mixed_requirements
            .groups
            .iter()
            .filter(|group| group.coefficient_source_count == 0)
            .count(),
        1
    );
    assert_eq!(
        mixed_requirements
            .groups
            .iter()
            .filter(|group| group.coefficient_source_count != 0)
            .count(),
        1
    );
    let report = quotient_numerator_hybrid_plan(config, &mixed_topology)
        .unwrap()
        .report();
    assert_eq!(
        (report.eligible_group_count, report.legacy_group_count),
        (1, 1)
    );
    let coefficient_batches = mixed_requirements
        .batches
        .iter()
        .filter(|batch| batch.coefficient_count != 0)
        .collect::<Vec<_>>();
    assert_eq!(coefficient_batches.len(), 2);
    assert_ne!(
        coefficient_batches[0].evaluation_log_size,
        coefficient_batches[1].evaluation_log_size
    );

    // External mixed inputs and outputs are shared. The live A/B schedules are not: hybrid setup
    // rewrites schedule descriptors, so both prepared graphs need independently owned workspaces.
    let coefficient_slots = slots_for(&coefficient_requirements, 1);
    let legacy_slots = slots_for(&mixed_requirements, 1);
    let hybrid_slots = slots_for(&mixed_requirements, 100);
    let coefficient_arena = arena(&[&coefficient_slots]);
    let mixed_arena = arena(&[&legacy_slots, &hybrid_slots]);
    let coefficient_destinations = destinations(&coefficient_arena, &coefficient_requirements);
    let mixed_destinations = destinations(&mixed_arena, &mixed_requirements);
    let coefficient_columns = columns(
        &coefficient_topology,
        QuotientNumeratorColumnSource::Coefficients(coefficient_arena.bind(COEFF_A).unwrap()),
        QuotientNumeratorColumnSource::Coefficients(coefficient_arena.bind(COEFF_B).unwrap()),
        QuotientNumeratorColumnSource::Coefficients(coefficient_arena.bind(COEFF_C).unwrap()),
    );
    let mixed_columns = columns(
        &mixed_topology,
        QuotientNumeratorColumnSource::Evaluation(mixed_arena.bind(EVAL_A).unwrap()),
        QuotientNumeratorColumnSource::Coefficients(mixed_arena.bind(COEFF_B).unwrap()),
        QuotientNumeratorColumnSource::Coefficients(mixed_arena.bind(COEFF_C).unwrap()),
    );

    let coefficient = PreparedQuotientNumeratorGraph::prepare(
        &coefficient_arena,
        config,
        &coefficient_columns,
        coefficient_arena.bind(OODS_POINTS).unwrap(),
        coefficient_arena.bind(OODS_VALUES).unwrap(),
        coefficient_arena.bind(RANDOM_COEFFICIENT).unwrap(),
        coefficient_arena.bind(SAMPLE_POINTS_OUTPUT).unwrap(),
        coefficient_arena.bind(FIRST_TERMS_OUTPUT).unwrap(),
        &coefficient_destinations,
        coefficient_arena.bind(TWIDDLES).unwrap(),
        &coefficient_slots,
    )
    .unwrap();
    let legacy = PreparedQuotientNumeratorGraph::prepare(
        &mixed_arena,
        config,
        &mixed_columns,
        mixed_arena.bind(OODS_POINTS).unwrap(),
        mixed_arena.bind(OODS_VALUES).unwrap(),
        mixed_arena.bind(RANDOM_COEFFICIENT).unwrap(),
        mixed_arena.bind(SAMPLE_POINTS_OUTPUT).unwrap(),
        mixed_arena.bind(FIRST_TERMS_OUTPUT).unwrap(),
        &mixed_destinations,
        mixed_arena.bind(TWIDDLES).unwrap(),
        &legacy_slots,
    )
    .unwrap();
    let hybrid = PreparedQuotientNumeratorGraph::prepare_hybrid_candidate(
        &mixed_arena,
        config,
        &mixed_columns,
        mixed_arena.bind(OODS_POINTS).unwrap(),
        mixed_arena.bind(OODS_VALUES).unwrap(),
        mixed_arena.bind(RANDOM_COEFFICIENT).unwrap(),
        mixed_arena.bind(SAMPLE_POINTS_OUTPUT).unwrap(),
        mixed_arena.bind(FIRST_TERMS_OUTPUT).unwrap(),
        &mixed_destinations,
        mixed_arena.bind(TWIDDLES).unwrap(),
        &hybrid_slots,
    )
    .unwrap();

    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(config.lifting_log_size)
            .circle_domain()
            .half_coset,
    );
    let twiddle_words = twiddles
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    let coefficient_a = words(1 << 4, 104_729, 7_919);
    let coefficient_b = words(1 << 3, 130_363, 5_003);
    let coefficient_c = words(1 << 4, 262_147, 3_019);
    let evaluation_a = canonical_lde(config, &twiddles, &coefficient_a, 4);
    let values = [
        SecureField::from_u32_unchecked(2, 3, 5, 7),
        SecureField::from_u32_unchecked(11, 13, 17, 19),
        SecureField::from_u32_unchecked(23, 29, 31, 37),
    ];
    upload_inputs(
        &coefficient_arena,
        &twiddle_words,
        &[p0, p1, p1],
        &values,
        &coefficient_a,
        &coefficient_b,
        &coefficient_c,
        None,
    );
    upload_inputs(
        &mixed_arena,
        &twiddle_words,
        &[p0, p1, p1],
        &values,
        &coefficient_a,
        &coefficient_b,
        &coefficient_c,
        Some(&evaluation_a),
    );

    let eager_alpha = SecureField::from_u32_unchecked(41, 43, 47, 53);
    upload(
        &coefficient_arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[eager_alpha]),
    );
    poison_outputs(
        &coefficient_arena,
        &coefficient_destinations,
        &mixed_requirements,
        0xdead_beef,
    );
    coefficient_arena.context().sync().unwrap();
    coefficient_arena.context().reset_telemetry();
    coefficient.launch().unwrap();
    coefficient_arena.context().sync().unwrap();
    assert_warm(&coefficient_arena);
    let eager = snapshot(
        &coefficient_arena,
        &coefficient_destinations,
        &mixed_requirements,
    );
    upload(
        &mixed_arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[eager_alpha]),
    );
    let legacy_eager = run_prepared(
        &legacy,
        &mixed_arena,
        &mixed_destinations,
        &mixed_requirements,
        0xdead_beef,
    );
    assert_eq!(legacy_eager, eager);
    let hybrid_eager = run_prepared(
        &hybrid,
        &mixed_arena,
        &mixed_destinations,
        &mixed_requirements,
        0xa5a5_5a5a,
    );
    assert_eq!(hybrid_eager, eager);
    assert_ne!(legacy_eager[2][0], 0xdead_beef);
    assert_ne!(hybrid_eager[2][0], 0xa5a5_5a5a);
    assert_sources(
        &coefficient_arena,
        &coefficient_a,
        &coefficient_b,
        &coefficient_c,
        None,
    );
    assert_sources(
        &mixed_arena,
        &coefficient_a,
        &coefficient_b,
        &coefficient_c,
        Some(&evaluation_a),
    );

    let capture = coefficient_arena.context().capture().unwrap();
    coefficient.launch().unwrap();
    let coefficient_graph = capture.finish().unwrap();
    let capture = mixed_arena.context().capture().unwrap();
    legacy.launch().unwrap();
    let legacy_graph = capture.finish().unwrap();
    let capture = mixed_arena.context().capture().unwrap();
    hybrid.launch().unwrap();
    let hybrid_graph = capture.finish().unwrap();

    let replay_alpha = SecureField::from_u32_unchecked(59, 61, 67, 71);
    let replay_coefficient_a = words(1 << 4, 1_000_003, 9_973);
    let replay_coefficient_b = words(1 << 3, 2_000_033, 6_997);
    let replay_coefficient_c = words(1 << 4, 3_000_017, 4_991);
    let replay_evaluation_a = canonical_lde(config, &twiddles, &replay_coefficient_a, 4);
    let replay_values = [
        SecureField::from_u32_unchecked(73, 79, 83, 89),
        SecureField::from_u32_unchecked(97, 101, 103, 107),
        SecureField::from_u32_unchecked(109, 113, 127, 131),
    ];
    upload_inputs(
        &coefficient_arena,
        &twiddle_words,
        &[p0, p1, p1],
        &replay_values,
        &replay_coefficient_a,
        &replay_coefficient_b,
        &replay_coefficient_c,
        None,
    );
    upload_inputs(
        &mixed_arena,
        &twiddle_words,
        &[p0, p1, p1],
        &replay_values,
        &replay_coefficient_a,
        &replay_coefficient_b,
        &replay_coefficient_c,
        Some(&replay_evaluation_a),
    );
    upload(
        &coefficient_arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[replay_alpha]),
    );
    let replay = run_graph(
        &coefficient_graph,
        &coefficient_arena,
        &coefficient_destinations,
        &mixed_requirements,
        0x1357_9bdf,
    );
    upload(
        &mixed_arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[replay_alpha]),
    );
    let legacy_replay = run_graph(
        &legacy_graph,
        &mixed_arena,
        &mixed_destinations,
        &mixed_requirements,
        0x2468_ace0,
    );
    let hybrid_replay = run_graph(
        &hybrid_graph,
        &mixed_arena,
        &mixed_destinations,
        &mixed_requirements,
        0x0bad_f00d,
    );
    assert_eq!(legacy_replay, replay);
    assert_eq!(hybrid_replay, replay);
    assert_ne!(replay, eager);
    assert_sources(
        &coefficient_arena,
        &replay_coefficient_a,
        &replay_coefficient_b,
        &replay_coefficient_c,
        None,
    );
    assert_sources(
        &mixed_arena,
        &replay_coefficient_a,
        &replay_coefficient_b,
        &replay_coefficient_c,
        Some(&replay_evaluation_a),
    );
}

fn topology(
    coefficient_log_size: u32,
    source_kind: QuotientNumeratorSourceKind,
    input_index: u32,
    shape_point: stwo::core::circle::CirclePoint<SecureField>,
) -> QuotientNumeratorColumnTopology {
    QuotientNumeratorColumnTopology {
        coefficient_log_size,
        source_kind,
        samples: vec![QuotientOodsSample {
            input_index,
            shape_point,
        }],
    }
}

fn columns(
    topology: &[QuotientNumeratorColumnTopology],
    first: QuotientNumeratorColumnSource,
    second: QuotientNumeratorColumnSource,
    third: QuotientNumeratorColumnSource,
) -> Vec<QuotientNumeratorColumn> {
    [first, second, third]
        .into_iter()
        .zip(topology)
        .map(|(source, topology)| QuotientNumeratorColumn {
            coefficient_log_size: topology.coefficient_log_size,
            source,
            samples: topology.samples.clone(),
        })
        .collect()
}

fn slots_for(
    requirements: &stwo_backend_cuda::QuotientNumeratorWorkspaceRequirements,
    base: u32,
) -> QuotientNumeratorWorkspaceSlots {
    let mut next = base;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    QuotientNumeratorWorkspaceSlots {
        runtime_terms: id(),
        group_term_indices: id(),
        group_offsets: id(),
        line_coefficients: id(),
        term_points: id(),
        batch_terms: id(),
        batch_group_offsets: id(),
        batch_source_ptrs: id(),
        output_ptrs: id(),
        output_log_sizes: id(),
        coefficient_ptrs: (requirements.coefficient_pointer_words != 0).then_some(id()),
        coefficient_sizes: (requirements.coefficient_size_words != 0).then_some(id()),
        coefficient_output_ptrs: (requirements.coefficient_output_pointer_words != 0)
            .then_some(id()),
        lde_tile: (requirements.lde_tile_words != 0).then_some(id()),
    }
}

fn arena(workspaces: &[&QuotientNumeratorWorkspaceSlots]) -> DeviceArena {
    let mut ids = workspaces
        .iter()
        .flat_map(|slots| {
            [
                Some(slots.runtime_terms),
                Some(slots.group_term_indices),
                Some(slots.group_offsets),
                Some(slots.line_coefficients),
                Some(slots.term_points),
                Some(slots.batch_terms),
                Some(slots.batch_group_offsets),
                Some(slots.batch_source_ptrs),
                Some(slots.output_ptrs),
                Some(slots.output_log_sizes),
                slots.coefficient_ptrs,
                slots.coefficient_sizes,
                slots.coefficient_output_ptrs,
                slots.lde_tile,
            ]
        })
        .flatten()
        .collect::<Vec<_>>();
    ids.extend([
        OODS_POINTS,
        OODS_VALUES,
        RANDOM_COEFFICIENT,
        SAMPLE_POINTS_OUTPUT,
        FIRST_TERMS_OUTPUT,
        TWIDDLES,
        EVAL_A,
        COEFF_A,
        COEFF_B,
        COEFF_C,
    ]);
    for group in 0..8 {
        for coordinate in 0..4 {
            ids.push(output_id(group, coordinate));
        }
    }
    let specs = ids
        .into_iter()
        .enumerate()
        .map(|(index, id)| ArenaSlotSpec {
            id,
            offset_words: index * SLOT_WORDS,
            len_words: if id == TWIDDLES { 1 << 5 } else { SLOT_WORDS },
            alignment_words: 8,
        })
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(specs.len() * SLOT_WORDS, &specs).unwrap(),
    )
    .unwrap()
}

fn destinations(
    arena: &DeviceArena,
    requirements: &stwo_backend_cuda::QuotientNumeratorWorkspaceRequirements,
) -> Vec<QuotientNumeratorDestination> {
    requirements
        .groups
        .iter()
        .enumerate()
        .map(|(group, requirement)| QuotientNumeratorDestination {
            log_size: requirement.log_size,
            coordinates: std::array::from_fn(|coordinate| {
                arena.bind(output_id(group, coordinate)).unwrap()
            }),
        })
        .collect()
}

fn run_prepared(
    graph: &PreparedQuotientNumeratorGraph<'_>,
    arena: &DeviceArena,
    destinations: &[QuotientNumeratorDestination],
    requirements: &stwo_backend_cuda::QuotientNumeratorWorkspaceRequirements,
    poison: u32,
) -> Vec<Vec<u32>> {
    poison_outputs(arena, destinations, requirements, poison);
    arena.context().sync().unwrap();
    arena.context().reset_telemetry();
    graph.launch().unwrap();
    arena.context().sync().unwrap();
    assert_warm(arena);
    snapshot(arena, destinations, requirements)
}

fn run_graph(
    graph: &CudaGraphExec,
    arena: &DeviceArena,
    destinations: &[QuotientNumeratorDestination],
    requirements: &stwo_backend_cuda::QuotientNumeratorWorkspaceRequirements,
    poison: u32,
) -> Vec<Vec<u32>> {
    poison_outputs(arena, destinations, requirements, poison);
    arena.context().sync().unwrap();
    arena.context().reset_telemetry();
    graph.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    assert_warm(arena);
    snapshot(arena, destinations, requirements)
}

fn upload_inputs(
    arena: &DeviceArena,
    twiddles: &[u32],
    points: &[stwo::core::circle::CirclePoint<SecureField>],
    values: &[SecureField],
    coefficient_a: &[u32],
    coefficient_b: &[u32],
    coefficient_c: &[u32],
    evaluation_a: Option<&[u32]>,
) {
    upload(arena, OODS_POINTS, &point_words(points));
    upload(arena, OODS_VALUES, &secure_words(values));
    upload(arena, TWIDDLES, twiddles);
    upload(arena, COEFF_A, coefficient_a);
    upload(arena, COEFF_B, coefficient_b);
    upload(arena, COEFF_C, coefficient_c);
    if let Some(evaluation_a) = evaluation_a {
        upload(arena, EVAL_A, evaluation_a);
    }
}

fn poison_outputs(
    arena: &DeviceArena,
    destinations: &[QuotientNumeratorDestination],
    requirements: &stwo_backend_cuda::QuotientNumeratorWorkspaceRequirements,
    poison: u32,
) {
    let mut outputs = vec![
        (
            arena.bind(SAMPLE_POINTS_OUTPUT).unwrap(),
            8 * requirements.groups.len(),
        ),
        (
            arena.bind(FIRST_TERMS_OUTPUT).unwrap(),
            4 * requirements.groups.len(),
        ),
    ];
    outputs.extend(destinations.iter().flat_map(|destination| {
        destination
            .coordinates
            .map(|coordinate| (coordinate, 1usize << destination.log_size))
    }));
    for (output, words) in outputs {
        unsafe {
            arena
                .context()
                .fill_u32_async(output.as_u32_ptr(), poison, words)
                .unwrap();
        }
    }
}

fn snapshot(
    arena: &DeviceArena,
    destinations: &[QuotientNumeratorDestination],
    requirements: &stwo_backend_cuda::QuotientNumeratorWorkspaceRequirements,
) -> Vec<Vec<u32>> {
    let mut result = vec![
        read(arena, SAMPLE_POINTS_OUTPUT, 8 * requirements.groups.len()),
        read(arena, FIRST_TERMS_OUTPUT, 4 * requirements.groups.len()),
    ];
    result.extend(destinations.iter().flat_map(|destination| {
        destination
            .coordinates
            .map(|coordinate| read_slice(arena, coordinate, 1usize << destination.log_size))
    }));
    result
}

fn assert_warm(arena: &DeviceArena) {
    let telemetry = arena.context().telemetry();
    assert_eq!(telemetry.allocations, 0);
    assert_eq!(telemetry.h2d_bytes, 0);
    assert_eq!(telemetry.d2h_bytes, 0);
}

fn assert_sources(
    arena: &DeviceArena,
    coefficient_a: &[u32],
    coefficient_b: &[u32],
    coefficient_c: &[u32],
    evaluation_a: Option<&[u32]>,
) {
    assert_eq!(read(arena, COEFF_A, coefficient_a.len()), coefficient_a);
    assert_eq!(read(arena, COEFF_B, coefficient_b.len()), coefficient_b);
    assert_eq!(read(arena, COEFF_C, coefficient_c.len()), coefficient_c);
    if let Some(evaluation_a) = evaluation_a {
        assert_eq!(read(arena, EVAL_A, evaluation_a.len()), evaluation_a);
    }
}

fn canonical_lde(
    config: QuotientNumeratorWorkspaceConfig,
    twiddles: &stwo::prover::poly::twiddles::TwiddleTree<CpuBackend>,
    words: &[u32],
    log_size: u32,
) -> Vec<u32> {
    CircleCoefficients::<CpuBackend>::new(
        words
            .iter()
            .copied()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    )
    .evaluate_with_twiddles(
        CanonicCoset::new(log_size + config.log_blowup_factor).circle_domain(),
        twiddles,
    )
    .values
    .iter()
    .map(|value| value.0)
    .collect()
}

fn words(len: usize, base: u32, step: u32) -> Vec<u32> {
    (0..len)
        .map(|index| (base + step * index as u32) % 0x7fff_ffff)
        .collect()
}

fn output_id(group: usize, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(OUTPUT_BASE + (4 * group + coordinate) as u32)
}

fn upload(arena: &DeviceArena, slot: ArenaSlotId, words: &[u32]) {
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

fn read(arena: &DeviceArena, slot: ArenaSlotId, words: usize) -> Vec<u32> {
    read_slice(arena, arena.bind(slot).unwrap(), words)
}

fn read_slice(arena: &DeviceArena, slice: ArenaSlice, words: usize) -> Vec<u32> {
    let mut host = vec![0u32; words];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                host.as_mut_ptr().cast(),
                slice.as_void_ptr(),
                words * core::mem::size_of::<u32>(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    host
}

fn secure_words(values: &[SecureField]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn point_words(values: &[stwo::core::circle::CirclePoint<SecureField>]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|point| [point.x, point.y])
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}
