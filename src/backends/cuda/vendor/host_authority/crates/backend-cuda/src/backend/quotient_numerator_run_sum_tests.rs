use stwo::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_GEN};
use stwo::core::fields::qm31::SecureField;

use super::*;
use crate::backend::prepared_quotient_numerator::{
    QuotientNumeratorColumnTopology, QuotientNumeratorSourceKind, QuotientNumeratorWorkspaceConfig,
    QuotientOodsSample,
};
use crate::backend::quotient_numerator_staged_single_write::quotient_numerator_staged_single_write_plan;

fn liveness(capacity_words: usize) -> QuotientNumeratorRunSumLiveness {
    QuotientNumeratorRunSumLiveness {
        same_stream_canonical_group_order: true,
        external_destination_ids_unique: true,
        victim_unread_before_own_producer: true,
        victim_fully_overwritten_by_own_producer: true,
        downstream_consumers_after_all_group_producers: true,
        victim_coordinate_capacity_words: [capacity_words; 4],
    }
}

fn topology(logs: &[u32], point: CirclePoint<SecureField>) -> Vec<QuotientNumeratorColumnTopology> {
    logs.iter()
        .enumerate()
        .map(
            |(input_index, &coefficient_log_size)| QuotientNumeratorColumnTopology {
                coefficient_log_size,
                source_kind: QuotientNumeratorSourceKind::Evaluation,
                samples: vec![QuotientOodsSample {
                    input_index: input_index as u32,
                    shape_point: point,
                }],
            },
        )
        .collect()
}

fn staged_for_groups(target_logs: &[u32]) -> super::QuotientNumeratorStagedSingleWritePlan {
    let zero = CirclePoint {
        x: SecureField::from(0),
        y: SecureField::from(0),
    };
    let mut columns = topology(target_logs, zero);
    columns.push(QuotientNumeratorColumnTopology {
        coefficient_log_size: *target_logs.last().unwrap(),
        source_kind: QuotientNumeratorSourceKind::Evaluation,
        samples: vec![QuotientOodsSample {
            input_index: target_logs.len() as u32,
            shape_point: SECURE_FIELD_CIRCLE_GEN,
        }],
    });
    quotient_numerator_staged_single_write_plan(
        QuotientNumeratorWorkspaceConfig {
            lifting_log_size: 30,
            log_blowup_factor: 1,
            max_lde_tile_words: 32usize << 30,
        },
        &columns,
    )
    .unwrap()
}

#[test]
fn rejects_every_unproven_liveness_fact() {
    let plan = staged_for_groups(&[4, 4, 6, 6, 8]);
    let mut facts = liveness(1 << 8);
    facts.same_stream_canonical_group_order = false;
    assert!(matches!(
        quotient_numerator_run_sum_plan(&plan, 0, 1, facts),
        Err(QuotientNumeratorRunSumError::LivenessNotProven(_))
    ));
    let mut facts = liveness(1 << 8);
    facts.external_destination_ids_unique = false;
    assert!(matches!(
        quotient_numerator_run_sum_plan(&plan, 0, 1, facts),
        Err(QuotientNumeratorRunSumError::LivenessNotProven(_))
    ));
    let mut facts = liveness(1 << 8);
    facts.victim_unread_before_own_producer = false;
    assert!(matches!(
        quotient_numerator_run_sum_plan(&plan, 0, 1, facts),
        Err(QuotientNumeratorRunSumError::LivenessNotProven(_))
    ));
    let mut facts = liveness(1 << 8);
    facts.victim_fully_overwritten_by_own_producer = false;
    assert!(matches!(
        quotient_numerator_run_sum_plan(&plan, 0, 1, facts),
        Err(QuotientNumeratorRunSumError::LivenessNotProven(_))
    ));
    let mut facts = liveness(1 << 8);
    facts.downstream_consumers_after_all_group_producers = false;
    assert!(matches!(
        quotient_numerator_run_sum_plan(&plan, 0, 1, facts),
        Err(QuotientNumeratorRunSumError::LivenessNotProven(_))
    ));
}

#[test]
fn rejects_unsafe_order_capacity_singletons_and_manifest_overflow() {
    let plan = staged_for_groups(&[4, 4, 6, 6, 8]);
    assert!(matches!(
        quotient_numerator_run_sum_plan(&plan, 1, 0, liveness(1 << 8)),
        Err(QuotientNumeratorRunSumError::VictimNotLater { .. })
    ));
    assert!(matches!(
        quotient_numerator_run_sum_plan(&plan, 0, 1, liveness(79)),
        Err(QuotientNumeratorRunSumError::VictimCoordinateTooSmall {
            required_words: 80,
            ..
        })
    ));

    let singleton = staged_for_groups(&[4, 6, 6]);
    assert!(matches!(
        quotient_numerator_run_sum_plan(&singleton, 0, 1, liveness(1 << 6)),
        Err(QuotientNumeratorRunSumError::SingletonAggregatedRun { source_log_size: 4 })
    ));

    let log_zero = staged_for_groups(&[0, 0, 2, 2]);
    assert!(matches!(
        quotient_numerator_run_sum_plan(&log_zero, 0, 1, liveness(1 << 2)),
        Err(QuotientNumeratorRunSumError::UnsupportedAggregatedSourceLogZero)
    ));

    let logs = (1..=26)
        .flat_map(|source_log| [source_log, source_log])
        .collect::<Vec<_>>();
    let overflow = staged_for_groups(&logs);
    assert!(matches!(
        quotient_numerator_run_sum_plan(&overflow, 0, 1, liveness(1 << 25)),
        Err(QuotientNumeratorRunSumError::TooManyRuns {
            actual: 25,
            maximum: QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS
        })
    ));
}

#[test]
fn receipt_identity_covers_capacity_descriptors_and_bounded_manifest() {
    let plan = staged_for_groups(&[4, 4, 6, 6, 8]);
    let receipt = quotient_numerator_run_sum_plan(&plan, 0, 1, liveness(1 << 8)).unwrap();
    assert_eq!(receipt.manifest.run_count, 2);
    assert_eq!(receipt.manifest.direct_term_begin, 4);
    assert_eq!(receipt.manifest.direct_term_end, 5);
    assert_eq!(
        receipt.manifest.active_entries(),
        &[
            QuotientNumeratorRunSumExpansionEntry {
                term_begin: 0,
                term_end: 2,
                source_log_size: 4,
                scratch_offset_words: 0,
            },
            QuotientNumeratorRunSumExpansionEntry {
                term_begin: 2,
                term_end: 4,
                source_log_size: 6,
                scratch_offset_words: 16,
            },
        ]
    );
    assert!(receipt.manifest.entries[2..]
        .iter()
        .all(|entry| *entry == QuotientNumeratorRunSumExpansionEntry::default()));
    assert_eq!(receipt.scratch_words_per_coordinate, 80);
    assert_eq!(receipt.expansion_manifest_bytes, 400);
    assert_eq!(receipt.expansion_kernel_parameter_bytes, 496);
    assert_eq!(receipt.baseline_row_terms, 5 * 256);
    assert_eq!(receipt.precompute_products, 2 * 16 + 2 * 64);
    assert_eq!(receipt.direct_products, 256);
    assert_eq!(receipt.expansion_adds, 2 * 256);

    let repeated = quotient_numerator_run_sum_plan(&plan, 0, 1, liveness(1 << 8)).unwrap();
    assert_eq!(receipt.identity, repeated.identity);
    let larger = quotient_numerator_run_sum_plan(&plan, 0, 1, liveness((1 << 8) + 1)).unwrap();
    assert_ne!(receipt.identity, larger.identity);
}
