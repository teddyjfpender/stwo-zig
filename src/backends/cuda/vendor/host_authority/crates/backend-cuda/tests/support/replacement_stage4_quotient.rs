use std::collections::BTreeMap;

use stwo::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_GEN};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};
use stwo_backend_cuda::{
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    quotient_numerator_workspace_requirements, ArenaSlotId, DeviceArena, PreparedNumeratorSchedule,
    PreparedQuotientNumeratorGraph, QuotientNumeratorColumn, QuotientNumeratorColumnSource,
    QuotientNumeratorColumnTopology, QuotientNumeratorDestination, QuotientNumeratorSourceKind,
    QuotientNumeratorWorkspaceConfig, QuotientNumeratorWorkspaceRequirements,
    QuotientNumeratorWorkspaceSlots, QuotientOodsSample,
};

use super::quotient_numerator_oracle::{expected_group, OracleTerm};
#[cfg(stwo_cuda_link)]
use super::replacement_stage4_common::PerformanceReceipt;
use super::replacement_stage4_common::{
    arena, fill, hash_words, read_words, upload_words, FixtureReceipt, SlotRequest,
};

pub(super) const OODS_POINTS: ArenaSlotId = ArenaSlotId(100);
pub(super) const OODS_VALUES: ArenaSlotId = ArenaSlotId(101);
pub(super) const ALPHA: ArenaSlotId = ArenaSlotId(102);
pub(super) const SAMPLE_POINTS: ArenaSlotId = ArenaSlotId(103);
pub(super) const FIRST_TERMS: ArenaSlotId = ArenaSlotId(104);
pub(super) const TWIDDLES: ArenaSlotId = ArenaSlotId(105);
const SOURCE_BASE: u32 = 110;
const OUTPUT_BASE: u32 = 200;
pub(super) const OVERFLOW: ArenaSlotId = ArenaSlotId(300);
pub(super) const GUARD: ArenaSlotId = ArenaSlotId(301);
const GUARD_WORDS: usize = 64;
const COEFFICIENT_LOGS: [u32; 4] = [3, 3, 5, 3];

pub fn run() -> FixtureReceipt {
    let config = QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 10,
        log_blowup_factor: 2,
        max_lde_tile_words: 32 * (1 << 10),
    };
    let points = [
        SECURE_FIELD_CIRCLE_GEN.mul(3),
        SECURE_FIELD_CIRCLE_GEN.mul(5),
        SECURE_FIELD_CIRCLE_GEN.mul(7),
        SECURE_FIELD_CIRCLE_GEN.mul(11),
    ];
    let topology = topology(points);
    let requirements = quotient_numerator_workspace_requirements(config, &topology).unwrap();
    let plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        &topology,
        &[128],
    )
    .unwrap();
    assert_eq!(plan.overflow_role_words(), vec![128]);
    assert_eq!(plan.report().total_staging_words, 192);
    assert_eq!(plan.report().primary_staging_words, 64);
    assert_eq!(plan.report().unused_factor32_staging_words, 64);
    assert_eq!(plan.report().candidate_output_passes, 1);

    let slots = workspace_slots(&requirements);
    let source_words = [1 << 3, 1 << 5, 1 << 5, 1 << 3];
    let (legacy_arena, legacy_bytes) = make_arena(&requirements, &slots, source_words, 128);
    let (candidate_arena, candidate_bytes) = make_arena(&requirements, &slots, source_words, 128);
    let values = [
        SecureField::from_u32_unchecked(2, 3, 5, 7),
        SecureField::from_u32_unchecked(11, 13, 17, 19),
        SecureField::from_u32_unchecked(23, 29, 31, 37),
        SecureField::from_u32_unchecked(41, 43, 47, 53),
        SecureField::from_u32_unchecked(59, 61, 67, 71),
    ];
    let first_sources = source_set(0x1234_5678);
    let second_sources = source_set(0x6a09_e667);
    let third_sources = source_set(0xbb67_ae85);
    let twiddle_words = required_forward_twiddle_words(config, &requirements);

    for device in [&legacy_arena, &candidate_arena] {
        upload_words(
            device,
            device.bind(OODS_POINTS).unwrap(),
            &point_words(&[points[0], points[1], points[0], points[2], points[3]]),
        );
        upload_words(
            device,
            device.bind(OODS_VALUES).unwrap(),
            &secure_words(&values),
        );
        upload_words(device, device.bind(TWIDDLES).unwrap(), &twiddle_words);
        upload_sources(device, &first_sources);
        fill(device, device.bind(GUARD).unwrap(), 0xa5);
        device.context().sync().unwrap();
    }

    let legacy_columns = columns(&legacy_arena, &topology);
    let candidate_columns = columns(&candidate_arena, &topology);
    let legacy_destinations = destinations(&legacy_arena, &requirements);
    let candidate_destinations = destinations(&candidate_arena, &requirements);
    let legacy = prepare_legacy(
        &legacy_arena,
        config,
        &slots,
        &legacy_columns,
        &legacy_destinations,
    );
    let candidate = PreparedQuotientNumeratorGraph::prepare_staged_group_direct(
        &candidate_arena,
        config,
        &candidate_columns,
        candidate_arena.bind(OODS_POINTS).unwrap(),
        candidate_arena.bind(OODS_VALUES).unwrap(),
        candidate_arena.bind(ALPHA).unwrap(),
        candidate_arena.bind(SAMPLE_POINTS).unwrap(),
        candidate_arena.bind(FIRST_TERMS).unwrap(),
        &candidate_destinations,
        candidate_arena.bind(TWIDDLES).unwrap(),
        &slots,
        &[candidate_arena.bind(OVERFLOW).unwrap()],
    )
    .unwrap();
    assert_eq!(
        candidate.schedule(),
        PreparedNumeratorSchedule::StagedGroupDirect {
            output_rows: plan.packed_output_rows()
        }
    );
    assert!(candidate.group_direct_run_sum_receipt().is_none());

    let eager_alpha = SecureField::from_u32_unchecked(73, 79, 83, 89);
    for device in [&legacy_arena, &candidate_arena] {
        upload_words(
            device,
            device.bind(ALPHA).unwrap(),
            &secure_words(&[eager_alpha]),
        );
    }
    legacy.launch().unwrap();
    candidate.launch().unwrap();
    let eager_legacy = snapshot(
        &legacy_arena,
        &requirements,
        &legacy_destinations,
        &values,
        eager_alpha,
        &evaluations(config, &first_sources),
    );
    let eager_candidate = snapshot(
        &candidate_arena,
        &requirements,
        &candidate_destinations,
        &values,
        eager_alpha,
        &evaluations(config, &first_sources),
    );
    assert_eq!(eager_candidate, eager_legacy);
    assert_preserved(&legacy_arena, &first_sources);
    assert_preserved(&candidate_arena, &first_sources);

    let legacy_capture = legacy_arena.context().capture().unwrap();
    legacy.launch().unwrap();
    let legacy_graph = legacy_capture.finish().unwrap();
    let candidate_capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = candidate_capture.finish().unwrap();
    let direct_capture = candidate_arena.context().capture().unwrap();
    candidate.launch_group_direct_baseline().unwrap();
    let direct_graph = direct_capture.finish().unwrap();
    assert_eq!(candidate_graph.kernel_nodes(), direct_graph.kernel_nodes());
    let replay_alpha = SecureField::from_u32_unchecked(97, 101, 103, 107);
    for device in [&legacy_arena, &candidate_arena] {
        upload_sources(device, &second_sources);
        upload_words(
            device,
            device.bind(ALPHA).unwrap(),
            &secure_words(&[replay_alpha]),
        );
    }
    legacy_graph.launch(legacy_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    let second_evaluations = evaluations(config, &second_sources);
    let replay_legacy = snapshot(
        &legacy_arena,
        &requirements,
        &legacy_destinations,
        &values,
        replay_alpha,
        &second_evaluations,
    );
    let replay_candidate = snapshot(
        &candidate_arena,
        &requirements,
        &candidate_destinations,
        &values,
        replay_alpha,
        &second_evaluations,
    );
    assert_eq!(replay_candidate, replay_legacy);
    assert_ne!(eager_candidate, replay_candidate);
    assert_preserved(&legacy_arena, &second_sources);
    assert_preserved(&candidate_arena, &second_sources);

    let third_alpha = SecureField::from_u32_unchecked(109, 113, 127, 131);
    for device in [&legacy_arena, &candidate_arena] {
        upload_sources(device, &third_sources);
        upload_words(
            device,
            device.bind(ALPHA).unwrap(),
            &secure_words(&[third_alpha]),
        );
    }
    legacy_graph.launch(legacy_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    let third_evaluations = evaluations(config, &third_sources);
    let third_legacy = snapshot(
        &legacy_arena,
        &requirements,
        &legacy_destinations,
        &values,
        third_alpha,
        &third_evaluations,
    );
    let third_candidate = snapshot(
        &candidate_arena,
        &requirements,
        &candidate_destinations,
        &values,
        third_alpha,
        &third_evaluations,
    );
    assert_eq!(third_candidate, third_legacy);
    assert_ne!(third_candidate, eager_candidate);
    assert_ne!(third_candidate, replay_candidate);
    assert_preserved(&legacy_arena, &third_sources);
    assert_preserved(&candidate_arena, &third_sources);

    let mut hashes = BTreeMap::new();
    hashes.insert("eager_outputs".to_owned(), hash_words(&eager_candidate));
    hashes.insert(
        "mutated_graph_outputs".to_owned(),
        hash_words(&replay_candidate),
    );
    hashes.insert(
        "third_generation_outputs".to_owned(),
        hash_words(&third_candidate),
    );
    let checks = [
        ("eager_reference", true),
        ("legacy_candidate_byte_identity", true),
        ("missing_run_sum_binding_fallback", true),
        ("production_fallback_graph_topology", true),
        ("captured_graph_mutation", true),
        ("third_generation_graph_replay", true),
        ("source_preservation", true),
        ("guard_preservation", true),
    ]
    .into_iter()
    .map(|(name, passed)| (name.to_owned(), passed))
    .collect();
    FixtureReceipt {
        name: "staged-group-direct-quotient-mixed-topology",
        production_apis: vec![
            "quotient_numerator_staged_single_write_plan_with_overflow_capacities",
            "PreparedQuotientNumeratorGraph::prepare_staged_group_direct",
        ],
        cases: 3,
        arena_bytes: legacy_bytes + candidate_bytes,
        checks,
        hashes,
    }
}

pub(super) fn required_forward_twiddle_words(
    config: QuotientNumeratorWorkspaceConfig,
    requirements: &QuotientNumeratorWorkspaceRequirements,
) -> Vec<u32> {
    let full = forward_twiddle_words(config.lifting_log_size);
    assert!(full.len() >= requirements.forward_twiddle_words);
    full[full.len() - requirements.forward_twiddle_words..].to_vec()
}

fn forward_twiddle_words(log_size: u32) -> Vec<u32> {
    CpuBackend::precompute_twiddles(CanonicCoset::new(log_size).circle_domain().half_coset)
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect()
}

#[test]
fn compact_forward_twiddles_match_lifting_tree_tail() {
    let config = QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 10,
        log_blowup_factor: 2,
        max_lde_tile_words: 32 * (1 << 10),
    };
    let points = [
        SECURE_FIELD_CIRCLE_GEN.mul(3),
        SECURE_FIELD_CIRCLE_GEN.mul(5),
        SECURE_FIELD_CIRCLE_GEN.mul(7),
        SECURE_FIELD_CIRCLE_GEN.mul(11),
    ];
    let requirements =
        quotient_numerator_workspace_requirements(config, &topology(points)).unwrap();
    let compact = forward_twiddle_words(7);

    assert_eq!(requirements.forward_twiddle_words, 64);
    assert_eq!(
        required_forward_twiddle_words(config, &requirements),
        compact
    );
}

#[test]
fn corrected_oracle_reproduces_h100_row_mapping() {
    let config = QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 10,
        log_blowup_factor: 2,
        max_lde_tile_words: 32 * (1 << 10),
    };
    let points = [
        SECURE_FIELD_CIRCLE_GEN.mul(3),
        SECURE_FIELD_CIRCLE_GEN.mul(5),
        SECURE_FIELD_CIRCLE_GEN.mul(7),
        SECURE_FIELD_CIRCLE_GEN.mul(11),
    ];
    let requirements =
        quotient_numerator_workspace_requirements(config, &topology(points)).unwrap();
    let values = [
        SecureField::from_u32_unchecked(2, 3, 5, 7),
        SecureField::from_u32_unchecked(11, 13, 17, 19),
        SecureField::from_u32_unchecked(23, 29, 31, 37),
        SecureField::from_u32_unchecked(41, 43, 47, 53),
        SecureField::from_u32_unchecked(59, 61, 67, 71),
    ];
    let coefficient_sources = source_set(0x1234_5678);
    let sources = evaluations(config, &coefficient_sources);
    let terms = oracle_terms(config, points, &values, &sources);
    let (_, output) = expected_group(
        requirements.groups[0].shape_point,
        requirements.groups[0].log_size,
        SecureField::from_u32_unchecked(73, 79, 83, 89),
        &terms,
    );

    assert_eq!(
        output[0],
        [
            1_790_766_119,
            1_387_108_145,
            1_876_986_603,
            176_746_994,
            1_407_476_242,
            1_406_155_035,
            1_738_690_807,
            457_455_165,
        ]
    );
}

#[cfg(stwo_cuda_link)]
pub fn benchmark(lifting_log_size: u32, warmups: usize, iterations: usize) -> PerformanceReceipt {
    super::replacement_stage4_bench::benchmark_quotient(lifting_log_size, warmups, iterations)
}

pub(super) fn topology(
    points: [CirclePoint<SecureField>; 4],
) -> Vec<QuotientNumeratorColumnTopology> {
    let sample = |input_index, shape_point| QuotientOodsSample {
        input_index,
        shape_point,
    };
    vec![
        QuotientNumeratorColumnTopology {
            coefficient_log_size: COEFFICIENT_LOGS[0],
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            samples: vec![sample(0, points[0]), sample(1, points[1])],
        },
        QuotientNumeratorColumnTopology {
            coefficient_log_size: COEFFICIENT_LOGS[1],
            source_kind: QuotientNumeratorSourceKind::Evaluation,
            samples: vec![sample(2, points[0])],
        },
        QuotientNumeratorColumnTopology {
            coefficient_log_size: COEFFICIENT_LOGS[2],
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            samples: vec![sample(3, points[2])],
        },
        QuotientNumeratorColumnTopology {
            coefficient_log_size: COEFFICIENT_LOGS[3],
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            samples: vec![sample(4, points[3])],
        },
    ]
}

#[cfg(stwo_cuda_link)]
pub(super) fn scaled_topology(
    points: [CirclePoint<SecureField>; 4],
    lifting_log_size: u32,
) -> Vec<QuotientNumeratorColumnTopology> {
    assert!(lifting_log_size >= 4);
    let mut topology = topology(points);
    topology[0].coefficient_log_size = lifting_log_size - 3;
    topology[1].coefficient_log_size = lifting_log_size - 3;
    topology[2].coefficient_log_size = lifting_log_size - 2;
    topology[3].coefficient_log_size = lifting_log_size - 3;
    topology
}

pub(super) fn workspace_slots(
    requirements: &QuotientNumeratorWorkspaceRequirements,
) -> QuotientNumeratorWorkspaceSlots {
    let mut next = 1u32;
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
        coefficient_ptrs: (requirements.coefficient_pointer_words != 0).then(&mut id),
        coefficient_sizes: (requirements.coefficient_size_words != 0).then(&mut id),
        coefficient_output_ptrs: (requirements.coefficient_output_pointer_words != 0).then(&mut id),
        lde_tile: (requirements.lde_tile_words != 0).then(&mut id),
    }
}

pub(super) fn make_arena(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    slots: &QuotientNumeratorWorkspaceSlots,
    source_words: [usize; 4],
    overflow_words: usize,
) -> (DeviceArena, usize) {
    let mut requests = requirements
        .arena_slot_requirements(slots)
        .unwrap()
        .into_iter()
        .map(|entry| SlotRequest {
            id: entry.id,
            words: entry.len_words,
            alignment_words: entry.alignment_words,
        })
        .collect::<Vec<_>>();
    requests.extend([
        request(OODS_POINTS, 8 * requirements.input_sample_count, 1),
        request(OODS_VALUES, 4 * requirements.input_sample_count, 1),
        request(ALPHA, 4, 1),
        request(SAMPLE_POINTS, 8 * requirements.groups.len(), 1),
        request(FIRST_TERMS, 4 * requirements.groups.len(), 1),
        request(TWIDDLES, requirements.forward_twiddle_words, 1),
        request(source_id(0), source_words[0], 1),
        request(source_id(1), source_words[1], 1),
        request(source_id(2), source_words[2], 1),
        request(source_id(3), source_words[3], 1),
        request(OVERFLOW, overflow_words, 1),
        request(GUARD, GUARD_WORDS, 8),
    ]);
    for (group, requirement) in requirements.groups.iter().enumerate() {
        for coordinate in 0..4 {
            requests.push(request(
                output_id(group, coordinate),
                1usize << requirement.log_size,
                1,
            ));
        }
    }
    arena(requests)
}

pub(super) fn prepare_legacy<'a>(
    arena: &'a DeviceArena,
    config: QuotientNumeratorWorkspaceConfig,
    slots: &QuotientNumeratorWorkspaceSlots,
    columns: &[QuotientNumeratorColumn],
    destinations: &[QuotientNumeratorDestination],
) -> PreparedQuotientNumeratorGraph<'a> {
    PreparedQuotientNumeratorGraph::prepare(
        arena,
        config,
        columns,
        arena.bind(OODS_POINTS).unwrap(),
        arena.bind(OODS_VALUES).unwrap(),
        arena.bind(ALPHA).unwrap(),
        arena.bind(SAMPLE_POINTS).unwrap(),
        arena.bind(FIRST_TERMS).unwrap(),
        destinations,
        arena.bind(TWIDDLES).unwrap(),
        slots,
    )
    .unwrap()
}

pub(super) fn columns(
    arena: &DeviceArena,
    topology: &[QuotientNumeratorColumnTopology],
) -> Vec<QuotientNumeratorColumn> {
    topology
        .iter()
        .enumerate()
        .map(|(column, shape)| QuotientNumeratorColumn {
            coefficient_log_size: shape.coefficient_log_size,
            source: match shape.source_kind {
                QuotientNumeratorSourceKind::Coefficients => {
                    QuotientNumeratorColumnSource::Coefficients(
                        arena.bind(source_id(column)).unwrap(),
                    )
                }
                QuotientNumeratorSourceKind::Evaluation => {
                    QuotientNumeratorColumnSource::Evaluation(
                        arena.bind(source_id(column)).unwrap(),
                    )
                }
            },
            samples: shape.samples.clone(),
        })
        .collect()
}

pub(super) fn destinations(
    arena: &DeviceArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
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

pub(super) fn source_set(seed: u32) -> [Vec<u32>; 4] {
    source_set_for_words(seed, [1 << 3, 1 << 5, 1 << 5, 1 << 3])
}

pub(super) fn source_set_for_words(seed: u32, source_words: [usize; 4]) -> [Vec<u32>; 4] {
    std::array::from_fn(|column| {
        (0..source_words[column])
            .map(|row| {
                seed.wrapping_add((column as u32 + 1) * 104_729)
                    .wrapping_add(row as u32 * 7_919)
                    % 0x7fff_ffff
            })
            .collect()
    })
}

pub(super) fn evaluations(
    config: QuotientNumeratorWorkspaceConfig,
    sources: &[Vec<u32>; 4],
) -> [Vec<u32>; 4] {
    let full_twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(config.lifting_log_size)
            .circle_domain()
            .half_coset,
    );
    std::array::from_fn(|column| {
        if column == 1 {
            return sources[column].clone();
        }
        let log_size = COEFFICIENT_LOGS[column];
        CircleCoefficients::<CpuBackend>::new(
            sources[column]
                .iter()
                .copied()
                .map(BaseField::from_u32_unchecked)
                .collect(),
        )
        .evaluate_with_twiddles(
            CanonicCoset::new(log_size + config.log_blowup_factor).circle_domain(),
            &full_twiddles,
        )
        .values
        .iter()
        .map(|value| value.0)
        .collect()
    })
}

fn oracle_terms<'a>(
    config: QuotientNumeratorWorkspaceConfig,
    points: [CirclePoint<SecureField>; 4],
    values: &'a [SecureField; 5],
    sources: &'a [Vec<u32>; 4],
) -> [OracleTerm<'a>; 6] {
    let periodic_second = points[1]
        + CanonicCoset::new(config.lifting_log_size)
            .step()
            .repeated_double(COEFFICIENT_LOGS[0] + config.log_blowup_factor)
            .into_ef();
    [
        OracleTerm {
            exponent: 0,
            source_log: COEFFICIENT_LOGS[0],
            value: values[1],
            point: periodic_second,
            source: &sources[0],
        },
        OracleTerm {
            exponent: 1,
            source_log: COEFFICIENT_LOGS[0],
            value: values[0],
            point: points[0],
            source: &sources[0],
        },
        OracleTerm {
            exponent: 2,
            source_log: COEFFICIENT_LOGS[0],
            value: values[1],
            point: points[1],
            source: &sources[0],
        },
        OracleTerm {
            exponent: 3,
            source_log: COEFFICIENT_LOGS[1],
            value: values[2],
            point: points[0],
            source: &sources[1],
        },
        OracleTerm {
            exponent: 4,
            source_log: COEFFICIENT_LOGS[2],
            value: values[3],
            point: points[2],
            source: &sources[2],
        },
        OracleTerm {
            exponent: 5,
            source_log: COEFFICIENT_LOGS[3],
            value: values[4],
            point: points[3],
            source: &sources[3],
        },
    ]
}

pub(super) fn snapshot(
    arena: &DeviceArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    destinations: &[QuotientNumeratorDestination],
    values: &[SecureField; 5],
    alpha: SecureField,
    sources: &[Vec<u32>; 4],
) -> Vec<u32> {
    let points = [
        SECURE_FIELD_CIRCLE_GEN.mul(3),
        SECURE_FIELD_CIRCLE_GEN.mul(5),
        SECURE_FIELD_CIRCLE_GEN.mul(7),
        SECURE_FIELD_CIRCLE_GEN.mul(11),
    ];
    let terms = oracle_terms(requirements.config, points, values, sources);
    snapshot_from_terms(arena, requirements, destinations, alpha, terms.as_slice())
}

pub(super) fn snapshot_from_terms(
    arena: &DeviceArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    destinations: &[QuotientNumeratorDestination],
    alpha: SecureField,
    terms: &[OracleTerm<'_>],
) -> Vec<u32> {
    let point_output = read_words(
        arena,
        arena.bind(SAMPLE_POINTS).unwrap(),
        8 * requirements.groups.len(),
    );
    let first_output = read_words(
        arena,
        arena.bind(FIRST_TERMS).unwrap(),
        4 * requirements.groups.len(),
    );
    let mut result = Vec::new();
    result.extend_from_slice(&point_output);
    result.extend_from_slice(&first_output);
    for (group_index, group) in requirements.groups.iter().enumerate() {
        let point_words = &point_output[8 * group_index..8 * group_index + 8];
        assert_eq!(
            CirclePoint {
                x: secure_from_words(&point_words[..4]),
                y: secure_from_words(&point_words[4..]),
            },
            group.shape_point
        );
        let (first, expected) = expected_group(group.shape_point, group.log_size, alpha, &terms);
        assert_eq!(
            secure_from_words(&first_output[4 * group_index..4 * group_index + 4]),
            first
        );
        for coordinate in 0..4 {
            let actual = read_words(
                arena,
                destinations[group_index].coordinates[coordinate],
                1usize << group.log_size,
            );
            assert_eq!(actual, expected[coordinate]);
            result.extend(actual);
        }
    }
    result
}

#[cfg(stwo_cuda_link)]
pub(super) fn raw_snapshot(
    arena: &DeviceArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    destinations: &[QuotientNumeratorDestination],
) -> Vec<u32> {
    let mut result = read_words(
        arena,
        arena.bind(SAMPLE_POINTS).unwrap(),
        8 * requirements.groups.len(),
    );
    result.extend(read_words(
        arena,
        arena.bind(FIRST_TERMS).unwrap(),
        4 * requirements.groups.len(),
    ));
    for destination in destinations {
        for coordinate in destination.coordinates {
            result.extend(read_words(
                arena,
                coordinate,
                1usize << destination.log_size,
            ));
        }
    }
    result
}

pub(super) fn upload_sources(arena: &DeviceArena, sources: &[Vec<u32>; 4]) {
    for (column, words) in sources.iter().enumerate() {
        upload_words(arena, arena.bind(source_id(column)).unwrap(), words);
    }
}

pub(super) fn assert_preserved(arena: &DeviceArena, sources: &[Vec<u32>; 4]) {
    for (column, expected) in sources.iter().enumerate() {
        assert_eq!(
            read_words(
                arena,
                arena.bind(source_id(column)).unwrap(),
                expected.len()
            ),
            *expected
        );
    }
    assert_eq!(
        read_words(arena, arena.bind(GUARD).unwrap(), GUARD_WORDS),
        vec![0xa5a5_a5a5; GUARD_WORDS]
    );
}

pub(super) fn point_words(points: &[CirclePoint<SecureField>]) -> Vec<u32> {
    points
        .iter()
        .flat_map(|point| [point.x, point.y])
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

pub(super) fn secure_words(values: &[SecureField]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn secure_from_words(words: &[u32]) -> SecureField {
    SecureField::from_u32_unchecked(words[0], words[1], words[2], words[3])
}

const fn source_id(column: usize) -> ArenaSlotId {
    ArenaSlotId(SOURCE_BASE + column as u32)
}

const fn output_id(group: usize, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(OUTPUT_BASE + (4 * group + coordinate) as u32)
}

const fn request(id: ArenaSlotId, words: usize, alignment_words: usize) -> SlotRequest {
    SlotRequest {
        id,
        words,
        alignment_words,
    }
}
