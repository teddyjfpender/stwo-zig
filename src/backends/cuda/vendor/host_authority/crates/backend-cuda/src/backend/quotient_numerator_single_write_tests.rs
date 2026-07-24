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
        max_lde_tile_words: 1 << 10,
    }
}

fn evaluation_topology() -> Vec<QuotientNumeratorColumnTopology> {
    vec![
        column(
            5,
            QuotientNumeratorSourceKind::Evaluation,
            vec![sample(0, 3), sample(1, 7)],
        ),
        column(
            3,
            QuotientNumeratorSourceKind::Evaluation,
            vec![sample(2, 7)],
        ),
        column(
            4,
            QuotientNumeratorSourceKind::Evaluation,
            vec![sample(3, 3)],
        ),
        column(
            3,
            QuotientNumeratorSourceKind::Evaluation,
            vec![sample(4, 11)],
        ),
    ]
}

#[test]
fn plan_preserves_the_exact_legacy_term_sequence_per_group() {
    let topology = evaluation_topology();
    let legacy = build_plan(config(), &topology).unwrap();
    let candidate = quotient_numerator_single_write_plan(config(), &topology).unwrap();
    assert!(legacy.batches.len() > 1);
    assert_eq!(candidate.group_offsets, legacy.group_offsets);
    assert_eq!(
        candidate.source_columns,
        legacy
            .batches
            .iter()
            .flat_map(|batch| batch.columns.iter().copied())
            .collect::<Vec<_>>()
    );

    for group in 0..candidate.report.group_count {
        let mut expected = Vec::new();
        for batch in &legacy.batches {
            let begin = batch.group_offsets[group] as usize;
            let end = batch.group_offsets[group + 1] as usize;
            expected.extend(
                batch.terms[begin * 3..end * 3]
                    .chunks_exact(3)
                    .map(|descriptor| (descriptor[1], descriptor[2])),
            );
        }
        let begin = candidate.group_offsets[group] as usize;
        let end = candidate.group_offsets[group + 1] as usize;
        let actual = candidate.term_descriptors[begin * 3..end * 3]
            .chunks_exact(3)
            .map(|descriptor| (descriptor[1], descriptor[2]))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
    assert_eq!(
        candidate.term_descriptors.len(),
        legacy.requirements.term_count * 3
    );
}

#[test]
fn report_accounts_for_output_passes_and_logical_bytes_exactly() {
    let report = quotient_numerator_single_write_report(config(), &evaluation_topology()).unwrap();
    assert_eq!(
        report.eligibility,
        QuotientNumeratorSingleWriteEligibility::Eligible
    );
    assert_eq!(report.legacy_output_passes, report.legacy_batch_count + 1);
    assert_eq!(report.candidate_output_passes, 1);
    assert_eq!(
        report.legacy_logical_output_bytes,
        report.output_rows as u64 * (16 + 32 * report.legacy_batch_count as u64)
    );
    assert_eq!(
        report.candidate_logical_output_bytes,
        report.output_rows as u64 * 16
    );
    assert!(report.candidate_descriptor_bytes < report.legacy_descriptor_bytes);
    assert_eq!(report.candidate_warm_host_preparation_bytes, 0);
}

#[test]
fn sampled_coefficients_fail_closed_but_unsampled_coefficients_do_not_matter() {
    let mut topology = evaluation_topology();
    topology[1].source_kind = QuotientNumeratorSourceKind::Coefficients;
    assert!(matches!(
        quotient_numerator_single_write_plan(config(), &topology),
        Err(
            QuotientNumeratorSingleWriteError::RequiresRetainedEvaluations {
                coefficient_columns: 1,
                coefficient_batches: 1,
            }
        )
    ));

    topology[1].samples.clear();
    let plan = quotient_numerator_single_write_plan(config(), &topology).unwrap();
    assert_eq!(
        plan.report.eligibility,
        QuotientNumeratorSingleWriteEligibility::Eligible
    );
    assert!(!plan.source_columns.contains(&1));
}

#[test]
fn flattened_single_write_is_byte_identical_to_batched_read_modify_write() {
    let topology = evaluation_topology();
    let legacy = build_plan(config(), &topology).unwrap();
    let candidate = quotient_numerator_single_write_plan(config(), &topology).unwrap();
    let mut state = 0x5eed_cafe_dead_beefu64;

    for _ in 0..128 {
        let sources = topology
            .iter()
            .map(|column| {
                (0..1usize << column.coefficient_log_size)
                    .map(|_| next_m31(&mut state))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let coefficients = (0..legacy.requirements.term_count)
            .map(|_| {
                (
                    std::array::from_fn(|_| next_m31(&mut state)),
                    std::array::from_fn(|_| next_m31(&mut state)),
                )
            })
            .collect::<Vec<(Qm31Words, Qm31Words)>>();

        let expected = evaluate_legacy(&legacy, &sources, &coefficients);
        let actual = evaluate_candidate(&candidate, &sources, &coefficients);
        assert_eq!(actual, expected);
    }
}

#[test]
fn hybrid_partition_is_complete_disjoint_and_byte_identical() {
    let mut topology = evaluation_topology();
    topology[1].source_kind = QuotientNumeratorSourceKind::Coefficients;
    let legacy = build_plan(config(), &topology).unwrap();
    let hybrid = quotient_numerator_hybrid_plan(config(), &topology).unwrap();
    let report = hybrid.report();
    assert_eq!(report.legacy_group_count, 1);
    assert_eq!(
        report.eligible_group_count + report.legacy_group_count,
        report.group_count
    );
    assert_eq!(
        hybrid.packed_terms.len(),
        legacy.requirements.batch_term_words
    );
    assert!(hybrid.packed_group_offsets.len() <= legacy.requirements.batch_group_offset_words);

    let eligible = &hybrid.schedule_groups[..report.eligible_group_count];
    let legacy_groups = &hybrid.schedule_groups[report.eligible_group_count..];
    assert!(eligible.windows(2).all(|groups| groups[0] < groups[1]));
    assert!(legacy_groups.windows(2).all(|groups| groups[0] < groups[1]));
    let mut partition = hybrid.schedule_groups.clone();
    partition.sort_unstable();
    assert_eq!(partition, (0..report.group_count).collect::<Vec<_>>());

    let init_offsets = &hybrid.packed_group_offsets[..report.group_count + 1];
    for position in 0..report.eligible_group_count {
        let begin = init_offsets[position] as usize;
        let end = init_offsets[position + 1] as usize;
        for descriptor in hybrid.packed_terms[begin * 3..end * 3].chunks_exact(3) {
            assert_eq!(
                topology[hybrid.source_columns[descriptor[0] as usize]].source_kind,
                QuotientNumeratorSourceKind::Evaluation
            );
        }
    }
    for position in report.eligible_group_count..report.group_count {
        assert_eq!(init_offsets[position], init_offsets[position + 1]);
    }

    let expected_legacy_bytes = report.legacy_logical_output_bytes;
    assert_eq!(
        expected_legacy_bytes,
        (report.eligible_output_rows + report.legacy_output_rows) as u64
            * (16 + 32 * report.legacy_batch_count as u64)
    );
    assert_eq!(
        report.hybrid_logical_output_bytes,
        (report.eligible_output_rows + report.legacy_output_rows) as u64 * 16
            + report.legacy_output_rows as u64 * 32 * report.legacy_batch_count as u64
    );
    assert!(report.hybrid_logical_output_bytes < report.legacy_logical_output_bytes);

    let mut state = 0x96c4_56a1_deaf_beefu64;
    for _ in 0..128 {
        let sources = topology
            .iter()
            .map(|column| {
                (0..1usize << column.coefficient_log_size)
                    .map(|_| next_m31(&mut state))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let coefficients = (0..legacy.requirements.term_count)
            .map(|_| {
                (
                    std::array::from_fn(|_| next_m31(&mut state)),
                    std::array::from_fn(|_| next_m31(&mut state)),
                )
            })
            .collect::<Vec<(Qm31Words, Qm31Words)>>();
        assert_eq!(
            evaluate_hybrid(&legacy, &hybrid, &sources, &coefficients),
            evaluate_legacy(&legacy, &sources, &coefficients)
        );
    }
}

#[test]
fn hybrid_handles_all_evaluation_and_rejects_all_coefficient_edges() {
    let topology = evaluation_topology();
    let plan = quotient_numerator_hybrid_plan(config(), &topology).unwrap();
    assert_eq!(plan.report.legacy_group_count, 0);
    assert!(plan.batches.iter().all(|batch| batch.term_count == 0));

    let all_coefficients = topology
        .into_iter()
        .map(|mut column| {
            column.source_kind = QuotientNumeratorSourceKind::Coefficients;
            column
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        quotient_numerator_hybrid_plan(config(), &all_coefficients),
        Err(QuotientNumeratorSingleWriteError::NoEligibleGroups)
    ));
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
                for descriptor in batch.terms[begin * 3..end * 3].chunks_exact(3) {
                    let column = batch.columns[descriptor[0] as usize];
                    add_term(
                        &mut batch_numerator,
                        row,
                        plan.requirements.groups[group].log_size,
                        descriptor,
                        &sources[column],
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
    plan: &QuotientNumeratorSingleWritePlan,
    sources: &[Vec<u32>],
    coefficients: &[(Qm31Words, Qm31Words)],
) -> Vec<Vec<Qm31Words>> {
    let mut output = zero_outputs(&plan.requirements);
    for (group, rows) in output.iter_mut().enumerate() {
        let begin = plan.group_offsets[group] as usize;
        let end = plan.group_offsets[group + 1] as usize;
        for (row, numerator) in rows.iter_mut().enumerate() {
            for descriptor in plan.term_descriptors[begin * 3..end * 3].chunks_exact(3) {
                let column = plan.source_columns[descriptor[0] as usize];
                add_term(
                    numerator,
                    row,
                    plan.requirements.groups[group].log_size,
                    descriptor,
                    &sources[column],
                    coefficients,
                );
            }
        }
    }
    output
}

fn evaluate_hybrid(
    legacy: &crate::backend::prepared_quotient_numerator::NumeratorPlan,
    hybrid: &QuotientNumeratorHybridPlan,
    sources: &[Vec<u32>],
    coefficients: &[(Qm31Words, Qm31Words)],
) -> Vec<Vec<Qm31Words>> {
    let report = hybrid.report;
    let mut output = zero_outputs(&legacy.requirements);
    let init_offsets = &hybrid.packed_group_offsets[..report.group_count + 1];
    for (position, &group) in hybrid.schedule_groups.iter().enumerate() {
        let begin = init_offsets[position] as usize;
        let end = init_offsets[position + 1] as usize;
        for (row, numerator) in output[group].iter_mut().enumerate() {
            for descriptor in hybrid.packed_terms[begin * 3..end * 3].chunks_exact(3) {
                let column = hybrid.source_columns[descriptor[0] as usize];
                add_term(
                    numerator,
                    row,
                    legacy.requirements.groups[group].log_size,
                    descriptor,
                    &sources[column],
                    coefficients,
                );
            }
        }
    }

    for (batch, placement) in legacy.batches.iter().zip(&hybrid.batches) {
        for legacy_position in 0..report.legacy_group_count {
            let group = hybrid.schedule_groups[report.eligible_group_count + legacy_position];
            let begin = placement.term_offset
                + hybrid.packed_group_offsets[placement.group_offset + legacy_position] as usize;
            let end = placement.term_offset
                + hybrid.packed_group_offsets[placement.group_offset + legacy_position + 1]
                    as usize;
            for (row, numerator) in output[group].iter_mut().enumerate() {
                let mut batch_numerator = [0; 4];
                for descriptor in hybrid.packed_terms[begin * 3..end * 3].chunks_exact(3) {
                    let column = batch.columns[descriptor[0] as usize];
                    add_term(
                        &mut batch_numerator,
                        row,
                        legacy.requirements.groups[group].log_size,
                        descriptor,
                        &sources[column],
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
    let ratio = group_log - source_log;
    let source_row = (row >> (ratio + 1) << 1) + (row & 1);
    let (b, c) = coefficients[descriptor[1] as usize];
    for coordinate in 0..4 {
        let contribution = m31_sub(m31_mul(c[coordinate], source[source_row]), b[coordinate]);
        numerator[coordinate] = m31_add(numerator[coordinate], contribution);
    }
}

fn next_m31(state: &mut u64) -> u32 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (*state % M31_MODULUS) as u32
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
