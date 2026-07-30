use std::collections::BTreeSet;

use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

use super::*;
use crate::backend::prepared_quotient_numerator::{
    QuotientNumeratorSourceKind, QuotientOodsSample,
};

const M31_MODULUS: u64 = 0x7fff_ffff;
type Qm31Words = [u32; 4];

fn sample(input_index: u32, multiple: u128) -> QuotientOodsSample {
    QuotientOodsSample {
        input_index,
        shape_point: SECURE_FIELD_CIRCLE_GEN.mul(multiple),
    }
}

fn column(
    coefficient_log_size: u32,
    source_kind: QuotientNumeratorSourceKind,
    samples: Vec<QuotientOodsSample>,
) -> QuotientNumeratorColumnTopology {
    QuotientNumeratorColumnTopology {
        coefficient_log_size,
        source_kind,
        samples,
    }
}

fn config() -> QuotientNumeratorWorkspaceConfig {
    QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 10,
        log_blowup_factor: 2,
        max_lde_tile_words: 32 * (1 << 10),
    }
}

fn mixed_topology() -> Vec<QuotientNumeratorColumnTopology> {
    vec![
        column(
            3,
            QuotientNumeratorSourceKind::Coefficients,
            vec![sample(0, 3), sample(1, 5)],
        ),
        column(
            3,
            QuotientNumeratorSourceKind::Evaluation,
            vec![sample(2, 3)],
        ),
        column(
            5,
            QuotientNumeratorSourceKind::Coefficients,
            vec![sample(3, 7)],
        ),
        column(
            3,
            QuotientNumeratorSourceKind::Coefficients,
            vec![sample(4, 11)],
        ),
    ]
}

#[test]
fn cumulative_staging_layout_is_exact_and_disjoint() {
    let layout = coefficient_staging_layout([(7, 5), (3, 7), (9, 4)], 160, &[usize::MAX]).unwrap();
    assert_eq!(
        layout,
        vec![
            QuotientNumeratorStagedLde {
                column: 7,
                evaluation_log_size: 5,
                staging_role: QuotientNumeratorStagingRole::Primary,
                role_offset_words: 0,
                offset_words: 0,
                len_words: 32,
            },
            QuotientNumeratorStagedLde {
                column: 3,
                evaluation_log_size: 7,
                staging_role: QuotientNumeratorStagingRole::Primary,
                role_offset_words: 32,
                offset_words: 32,
                len_words: 128,
            },
            QuotientNumeratorStagedLde {
                column: 9,
                evaluation_log_size: 4,
                staging_role: QuotientNumeratorStagingRole::Overflow(0),
                role_offset_words: 0,
                offset_words: 160,
                len_words: 16,
            },
        ]
    );
    assert!(layout.windows(2).all(|pair| {
        pair[0].end_words() == pair[1].offset_words && pair[0].end_words() <= pair[1].offset_words
    }));
    assert_eq!(layout[1].role_end_words(), 160);
    assert_eq!(layout[2].role_end_words(), 16);
}

#[test]
fn overflow_roles_are_dense_and_capacities_are_largest_first() {
    assert_eq!(
        coefficient_staging_layout([(0, 4), (1, 5)], 16, &[31, 32]),
        Err(QuotientNumeratorStagedSingleWriteError::OverflowCapacitiesNotDescending)
    );
    let layout = coefficient_staging_layout([(0, 4), (1, 5)], 16, &[32, 31]).unwrap();
    assert_eq!(
        layout[1].staging_role(),
        QuotientNumeratorStagingRole::Overflow(0)
    );
    assert_eq!(layout[1].role_offset_words(), 0);
    assert_eq!(layout[1].len_words(), 32);

    assert_eq!(
        coefficient_staging_layout([(0, 4), (1, 5), (2, 5), (3, 5)], 16, &[64, 31, 16]),
        Err(
            QuotientNumeratorStagedSingleWriteError::InsufficientOverflowCapacity {
                column: 3,
                required_words: 32,
            }
        )
    );
}

#[test]
fn whole_lde_fails_closed_when_no_named_role_can_hold_it() {
    assert_eq!(
        coefficient_staging_layout([(0, 4), (1, 5)], 16, &[31, 31]),
        Err(
            QuotientNumeratorStagedSingleWriteError::InsufficientOverflowCapacity {
                column: 1,
                required_words: 32,
            }
        )
    );
}

#[test]
fn multi_role_report_reconciles_dense_used_extents() {
    let topology = (0..34)
        .map(|index| {
            column(
                8,
                QuotientNumeratorSourceKind::Coefficients,
                vec![sample(index, u128::from(index) + 1)],
            )
        })
        .collect::<Vec<_>>();
    let plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config(),
        &topology,
        &[1 << 10, 1 << 10],
    )
    .unwrap();
    let report = plan.report();
    assert_eq!(report.primary_staging_words, 32 << 10);
    assert_eq!(report.overflow_staging_words, 2 << 10);
    assert_eq!(report.overflow_staging_role_count, 2);
    assert_eq!(report.max_overflow_staging_role_words, 1 << 10);
    assert_eq!(plan.overflow_role_words(), vec![1 << 10, 1 << 10]);
    assert_eq!(
        report.primary_staging_words + report.overflow_staging_words,
        report.total_staging_words
    );
}

#[test]
fn staging_layout_rejects_duplicate_columns() {
    assert_eq!(
        coefficient_staging_layout([(4, 5), (4, 6)], 64, &[usize::MAX]),
        Err(QuotientNumeratorStagedSingleWriteError::DuplicateCoefficientColumn(4))
    );
}

#[test]
fn staging_layout_rejects_shift_and_cumulative_overflow() {
    assert!(matches!(
        coefficient_staging_layout([(4, usize::BITS)], usize::MAX, &[usize::MAX]),
        Err(
            QuotientNumeratorStagedSingleWriteError::StagingSizeOverflow {
                column: 4,
                evaluation_log_size,
            }
        ) if evaluation_log_size == usize::BITS
    ));
    assert!(matches!(
        coefficient_staging_layout(
            [(4, usize::BITS - 1), (9, usize::BITS - 1)],
            usize::MAX,
            &[usize::MAX],
        ),
        Err(
            QuotientNumeratorStagedSingleWriteError::StagingSizeOverflow {
                column: 9,
                evaluation_log_size,
            }
        ) if evaluation_log_size == usize::BITS - 1
    ));
}

#[test]
fn planner_rejects_a_non_factor32_baseline() {
    let mut wrong = config();
    wrong.max_lde_tile_words /= 2;
    assert_eq!(
        quotient_numerator_staged_single_write_plan(wrong, &mixed_topology()),
        Err(
            QuotientNumeratorStagedSingleWriteError::Factor32ConfigMismatch {
                expected_words: 32 * (1 << 10),
                actual_words: 16 * (1 << 10),
            }
        )
    );
}

#[test]
fn mixed_plan_preserves_every_legacy_term_and_reports_exact_passes() {
    let topology = mixed_topology();
    let legacy = build_plan(config(), &topology).unwrap();
    let candidate = quotient_numerator_staged_single_write_plan(config(), &topology).unwrap();

    assert_eq!(candidate.group_offsets(), legacy.group_offsets);
    assert_exact_legacy_term_order(&legacy, &candidate);
    assert_eq!(
        candidate
            .sources()
            .iter()
            .map(|source| source.column())
            .collect::<BTreeSet<_>>()
            .len(),
        candidate.sources().len()
    );
    for source in candidate.sources() {
        assert_eq!(
            source.evaluation_log_size(),
            topology[source.column()].coefficient_log_size + config().log_blowup_factor
        );
    }

    let ldes = candidate.coefficient_ldes();
    assert_eq!(
        ldes.iter().map(|lde| lde.column()).collect::<Vec<_>>(),
        vec![0, 3, 2]
    );
    assert_eq!(
        ldes.iter()
            .map(|lde| (lde.offset_words(), lde.len_words()))
            .collect::<Vec<_>>(),
        vec![(0, 32), (32, 32), (64, 128)]
    );

    let report = candidate.report();
    assert_eq!(report.coefficient_source_count, 3);
    assert_eq!(report.total_staging_words, 192);
    assert_eq!(report.factor32_staging_words, 128);
    assert_eq!(report.primary_staging_words, 64);
    assert_eq!(report.unused_factor32_staging_words, 64);
    assert_eq!(report.overflow_staging_words, 128);
    assert_eq!(report.incremental_staging_words_over_factor32, 64);
    assert_eq!(report.factor32_batch_count, legacy.batches.len());
    assert_eq!(report.factor32_accumulation_passes, legacy.batches.len());
    let coefficient_groups = legacy
        .requirements
        .groups
        .iter()
        .enumerate()
        .filter_map(|(group, requirements)| {
            (requirements.coefficient_source_count != 0).then_some(group)
        })
        .collect::<Vec<_>>();
    assert!(legacy.batches.iter().any(|batch| coefficient_groups
        .iter()
        .any(|&group| batch.group_offsets[group] == batch.group_offsets[group + 1])));
    assert_eq!(
        report.factor32_accumulation_passes,
        legacy.batches.len(),
        "current factor-32 launches and writes every coefficient-backed group for every batch, \
         including empty-term group spans"
    );
    assert_eq!(
        report.factor32_total_output_passes,
        legacy.batches.len() + 1
    );
    assert_eq!(report.candidate_output_passes, 1);
    let mut covered_ldes = 0;
    for operation in candidate.operations() {
        match operation {
            QuotientNumeratorStagedOperation::MaterializeLdes(launch) => {
                assert_eq!(launch.first_lde(), covered_ldes);
                assert!(launch.lde_count() > 0);
                assert!(candidate.coefficient_ldes()
                    [launch.first_lde()..launch.first_lde() + launch.lde_count()]
                    .iter()
                    .all(|lde| lde.evaluation_log_size() == launch.evaluation_log_size()));
                covered_ldes += launch.lde_count();
            }
            QuotientNumeratorStagedOperation::AccumulatePackedRows {
                group_count,
                term_count,
                packed_output_rows,
            } => {
                assert_eq!(covered_ldes, candidate.coefficient_ldes().len());
                assert_eq!(*group_count, legacy.requirements.groups.len());
                assert_eq!(*term_count, legacy.requirements.term_count);
                assert_eq!(*packed_output_rows, candidate.packed_output_rows());
            }
        }
    }
    assert_eq!(
        report.factor32_logical_output_bytes,
        report.output_rows as u64 * 16
            + report.coefficient_output_rows as u64 * 32 * legacy.batches.len() as u64
    );
    assert_eq!(
        report.candidate_logical_output_bytes,
        report.output_rows as u64 * 16
    );
    assert_eq!(
        report.logical_output_bytes_saved,
        report.factor32_logical_output_bytes - report.candidate_logical_output_bytes
    );
    assert_eq!(
        report.rectangular_launch_rows,
        (legacy.requirements.groups.len() * legacy.requirements.max_output_size) as u64
    );
    assert_eq!(
        report.inactive_rectangular_launch_rows,
        report.rectangular_launch_rows - report.output_rows as u64
    );
    assert_eq!(
        report.rectangular_row_term_capacity,
        (legacy.requirements.max_output_size * legacy.requirements.term_count) as u64
    );
}

#[test]
fn packed_row_oracle_covers_every_heterogeneous_group_boundary_once() {
    let plan = quotient_numerator_staged_single_write_plan(config(), &mixed_topology()).unwrap();
    let offsets = plan.packed_group_row_offsets();
    assert_eq!(offsets.len(), plan.requirements().groups.len() + 1);
    assert_eq!(offsets[0], 0);
    assert_eq!(offsets.last().copied(), Some(plan.packed_output_rows()));
    for (group, requirements) in plan.requirements().groups.iter().enumerate() {
        assert_eq!(
            offsets[group + 1] - offsets[group],
            requirements.value_words as u64
        );
        assert_eq!(plan.packed_row_location(offsets[group]), Some((group, 0)));
        assert_eq!(
            plan.packed_row_location(offsets[group + 1] - 1),
            Some((group, requirements.value_words as u64 - 1))
        );
    }
    assert_eq!(plan.packed_row_location(plan.packed_output_rows()), None);
    assert_eq!(plan.packed_row_location(u64::MAX), None);
}

#[test]
fn evaluation_only_and_unsampled_coefficient_columns_need_no_staging() {
    let mut topology = mixed_topology();
    for column in &mut topology {
        column.source_kind = QuotientNumeratorSourceKind::Evaluation;
    }
    let evaluation_only = quotient_numerator_staged_single_write_plan(config(), &topology).unwrap();
    assert!(evaluation_only.coefficient_ldes().is_empty());
    assert_eq!(evaluation_only.report().total_staging_words, 0);
    assert_eq!(evaluation_only.report().factor32_staging_words, 0);
    assert_eq!(evaluation_only.report().primary_staging_words, 0);
    assert_eq!(evaluation_only.report().overflow_staging_words, 0);
    assert_eq!(
        evaluation_only
            .report()
            .incremental_staging_words_over_factor32,
        0
    );
    assert_eq!(evaluation_only.report().factor32_accumulation_passes, 0);
    assert_eq!(evaluation_only.report().factor32_total_output_passes, 1);

    topology[0].source_kind = QuotientNumeratorSourceKind::Coefficients;
    topology[0].samples.clear();
    let unsampled = quotient_numerator_staged_single_write_plan(config(), &topology).unwrap();
    assert!(unsampled.coefficient_ldes().is_empty());
    assert!(!unsampled
        .sources()
        .iter()
        .any(|source| source.column() == 0));
}

#[test]
fn randomized_mixed_source_plan_is_canonical_byte_identical() {
    let mut state = 0x8a51_2cc7_09d4_ef31u64;
    for case in 0..128u32 {
        let topology = randomized_topology(&mut state, case);
        let legacy = build_plan(config(), &topology).unwrap();
        let candidate = quotient_numerator_staged_single_write_plan(config(), &topology).unwrap();
        assert_exact_legacy_term_order(&legacy, &candidate);
        for source in candidate.sources() {
            assert_eq!(
                source.evaluation_log_size(),
                topology[source.column()].coefficient_log_size + config().log_blowup_factor
            );
        }

        let source_evaluations = topology
            .iter()
            .map(|column| {
                (0..1usize << (column.coefficient_log_size + config().log_blowup_factor))
                    .map(|_| next_m31(&mut state))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut staging = vec![0; candidate.report().total_staging_words];
        for lde in candidate.coefficient_ldes() {
            let source = &source_evaluations[lde.column()];
            assert_eq!(source.len(), lde.len_words());
            staging[lde.offset_words()..lde.end_words()].copy_from_slice(source);
        }
        let line_coefficients = (0..legacy.requirements.term_count)
            .map(|_| {
                (
                    std::array::from_fn(|_| next_m31(&mut state)),
                    std::array::from_fn(|_| next_m31(&mut state)),
                )
            })
            .collect::<Vec<(Qm31Words, Qm31Words)>>();

        let expected = evaluate_legacy(&legacy, &source_evaluations, &line_coefficients);
        let actual = evaluate_candidate(
            &candidate,
            &source_evaluations,
            &staging,
            &line_coefficients,
        );
        let packed = evaluate_candidate_packed(
            &candidate,
            &source_evaluations,
            &staging,
            &line_coefficients,
        );
        assert_eq!(canonical_bytes(&actual), canonical_bytes(&expected));
        assert_eq!(canonical_bytes(&packed), canonical_bytes(&expected));

        let expected_coefficients = topology
            .iter()
            .enumerate()
            .filter_map(|(column, topology)| {
                (topology.source_kind == QuotientNumeratorSourceKind::Coefficients
                    && !topology.samples.is_empty())
                .then_some(column)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            candidate
                .coefficient_ldes()
                .iter()
                .map(|lde| lde.column())
                .collect::<BTreeSet<_>>(),
            expected_coefficients
        );
    }
}

fn randomized_topology(state: &mut u64, case: u32) -> Vec<QuotientNumeratorColumnTopology> {
    let column_count = 4 + (next_u64(state) as usize % 68);
    (0..column_count)
        .map(|column_index| {
            let coefficient_log_size = 2 + next_u64(state) as u32 % 5;
            let source_kind = if column_index == 0 || next_u64(state) % 3 == 0 {
                QuotientNumeratorSourceKind::Coefficients
            } else {
                QuotientNumeratorSourceKind::Evaluation
            };
            let sample_count = if column_index == 0 {
                1
            } else {
                next_u64(state) as usize % 3
            };
            let samples = (0..sample_count)
                .map(|sample_index| {
                    sample(
                        case * 256 + (column_index * 2 + sample_index) as u32,
                        1 + (next_u64(state) % 13) as u128,
                    )
                })
                .collect();
            column(coefficient_log_size, source_kind, samples)
        })
        .collect()
}

fn assert_exact_legacy_term_order(
    legacy: &crate::backend::prepared_quotient_numerator::NumeratorPlan,
    candidate: &QuotientNumeratorStagedSingleWritePlan,
) {
    for group in 0..legacy.requirements.groups.len() {
        let mut expected = Vec::new();
        for batch in &legacy.batches {
            let begin = batch.group_offsets[group] as usize;
            let end = batch.group_offsets[group + 1] as usize;
            expected.extend(
                batch.terms[begin * TERM_WORDS..end * TERM_WORDS]
                    .chunks_exact(TERM_WORDS)
                    .map(|descriptor| {
                        (
                            batch.columns[descriptor[0] as usize],
                            descriptor[1],
                            descriptor[2],
                        )
                    }),
            );
        }
        let begin = candidate.group_offsets()[group] as usize;
        let end = candidate.group_offsets()[group + 1] as usize;
        let actual = candidate.term_descriptors()[begin * TERM_WORDS..end * TERM_WORDS]
            .chunks_exact(TERM_WORDS)
            .map(|descriptor| {
                (
                    candidate.sources()[descriptor[0] as usize].column(),
                    descriptor[1],
                    descriptor[2],
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}

fn evaluate_legacy(
    plan: &crate::backend::prepared_quotient_numerator::NumeratorPlan,
    sources: &[Vec<u32>],
    coefficients: &[(Qm31Words, Qm31Words)],
) -> Vec<Vec<Qm31Words>> {
    let mut output = zero_outputs(&plan.requirements);
    for batch in &plan.batches {
        for (group, rows) in output.iter_mut().enumerate() {
            let begin = batch.group_offsets[group] as usize;
            let end = batch.group_offsets[group + 1] as usize;
            for (row, numerator) in rows.iter_mut().enumerate() {
                let mut batch_numerator = [0; 4];
                for descriptor in
                    batch.terms[begin * TERM_WORDS..end * TERM_WORDS].chunks_exact(TERM_WORDS)
                {
                    add_term(
                        &mut batch_numerator,
                        row,
                        plan.requirements.groups[group].log_size,
                        descriptor,
                        &sources[batch.columns[descriptor[0] as usize]],
                        coefficients,
                    );
                }
                for coordinate in 0..4 {
                    numerator[coordinate] =
                        m31_add(numerator[coordinate], batch_numerator[coordinate]);
                }
            }
        }
    }
    output
}

fn evaluate_candidate(
    plan: &QuotientNumeratorStagedSingleWritePlan,
    evaluations: &[Vec<u32>],
    staging: &[u32],
    coefficients: &[(Qm31Words, Qm31Words)],
) -> Vec<Vec<Qm31Words>> {
    let mut output = zero_outputs(plan.requirements());
    for (group, rows) in output.iter_mut().enumerate() {
        let begin = plan.group_offsets()[group] as usize;
        let end = plan.group_offsets()[group + 1] as usize;
        for (row, numerator) in rows.iter_mut().enumerate() {
            for descriptor in plan.term_descriptors()[begin * TERM_WORDS..end * TERM_WORDS]
                .chunks_exact(TERM_WORDS)
            {
                let source = match plan.sources()[descriptor[0] as usize] {
                    QuotientNumeratorStagedSource::Evaluation { column, .. } => {
                        evaluations[column].as_slice()
                    }
                    QuotientNumeratorStagedSource::StagedCoefficient(lde) => {
                        &staging[lde.offset_words()..lde.end_words()]
                    }
                };
                add_term(
                    numerator,
                    row,
                    plan.requirements().groups[group].log_size,
                    descriptor,
                    source,
                    coefficients,
                );
            }
        }
    }
    output
}

fn evaluate_candidate_packed(
    plan: &QuotientNumeratorStagedSingleWritePlan,
    evaluations: &[Vec<u32>],
    staging: &[u32],
    coefficients: &[(Qm31Words, Qm31Words)],
) -> Vec<Vec<Qm31Words>> {
    let mut output = zero_outputs(plan.requirements());
    for packed_row in 0..plan.packed_output_rows() {
        let (group, row) = plan
            .packed_row_location(packed_row)
            .expect("every sealed packed row maps to exactly one group row");
        let row = usize::try_from(row).unwrap();
        let begin = plan.group_offsets()[group] as usize;
        let end = plan.group_offsets()[group + 1] as usize;
        let numerator = &mut output[group][row];
        for descriptor in
            plan.term_descriptors()[begin * TERM_WORDS..end * TERM_WORDS].chunks_exact(TERM_WORDS)
        {
            let source = match plan.sources()[descriptor[0] as usize] {
                QuotientNumeratorStagedSource::Evaluation { column, .. } => {
                    evaluations[column].as_slice()
                }
                QuotientNumeratorStagedSource::StagedCoefficient(lde) => {
                    &staging[lde.offset_words()..lde.end_words()]
                }
            };
            add_term(
                numerator,
                row,
                plan.requirements().groups[group].log_size,
                descriptor,
                source,
                coefficients,
            );
        }
    }
    output
}

fn zero_outputs(requirements: &QuotientNumeratorWorkspaceRequirements) -> Vec<Vec<Qm31Words>> {
    requirements
        .groups
        .iter()
        .map(|group| vec![[0; 4]; group.value_words])
        .collect()
}

fn add_term(
    numerator: &mut Qm31Words,
    row: usize,
    group_log: u32,
    descriptor: &[u32],
    source: &[u32],
    coefficients: &[(Qm31Words, Qm31Words)],
) {
    let source_log = descriptor[2];
    let log_ratio = group_log - source_log;
    let source_row = (row >> (log_ratio + 1) << 1) + (row & 1);
    let (b, c) = coefficients[descriptor[1] as usize];
    for coordinate in 0..4 {
        let contribution = m31_sub(m31_mul(c[coordinate], source[source_row]), b[coordinate]);
        numerator[coordinate] = m31_add(numerator[coordinate], contribution);
    }
}

fn canonical_bytes(output: &[Vec<Qm31Words>]) -> Vec<u8> {
    output
        .iter()
        .flatten()
        .flatten()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn next_m31(state: &mut u64) -> u32 {
    (next_u64(state) % M31_MODULUS) as u32
}

fn m31_add(lhs: u32, rhs: u32) -> u32 {
    let sum = lhs as u64 + rhs as u64;
    (if sum >= M31_MODULUS {
        sum - M31_MODULUS
    } else {
        sum
    }) as u32
}

fn m31_sub(lhs: u32, rhs: u32) -> u32 {
    m31_add(lhs, (M31_MODULUS as u32).wrapping_sub(rhs))
}

fn m31_mul(lhs: u32, rhs: u32) -> u32 {
    (lhs as u64 * rhs as u64 % M31_MODULUS) as u32
}
