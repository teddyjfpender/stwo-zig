use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;

use super::*;

fn slice(id: u32, words: usize) -> ArenaSlice {
    ArenaSlice::dangling_for_test(id, words)
}

fn sample(index: u32, multiple: u128) -> QuotientOodsSample {
    QuotientOodsSample {
        input_index: index,
        shape_point: SECURE_FIELD_CIRCLE_GEN.mul(multiple),
    }
}

fn config() -> QuotientNumeratorWorkspaceConfig {
    QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 8,
        log_blowup_factor: 2,
        max_lde_tile_words: 1 << 9,
    }
}

fn topology(columns: &[QuotientNumeratorColumn]) -> Vec<QuotientNumeratorColumnTopology> {
    columns
        .iter()
        .map(QuotientNumeratorColumnTopology::from)
        .collect()
}

#[test]
fn plan_preserves_alpha_order_but_batches_by_stable_evaluation_log() {
    let columns = vec![
        QuotientNumeratorColumn {
            coefficient_log_size: 6,
            source: QuotientNumeratorColumnSource::Evaluation(slice(1, 256)),
            samples: vec![sample(0, 3), sample(1, 5)],
        },
        QuotientNumeratorColumn {
            coefficient_log_size: 4,
            source: QuotientNumeratorColumnSource::Coefficients(slice(2, 16)),
            samples: vec![sample(2, 3)],
        },
    ];
    let plan = build_plan(config(), &topology(&columns)).unwrap();
    assert_eq!(
        plan.terms
            .iter()
            .map(|term| term.exponent)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    assert_eq!(
        plan.batches
            .iter()
            .map(|batch| batch.evaluation_log_size)
            .collect::<Vec<_>>(),
        vec![6, 8]
    );
    assert_eq!(plan.requirements.forward_twiddle_words, 32);
    assert_eq!(plan.requirements.input_sample_count, 3);
}

#[test]
fn unsampled_column_may_exceed_lifting_but_sampled_column_may_not() {
    let mut columns = vec![
        QuotientNumeratorColumnTopology {
            coefficient_log_size: 25,
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            samples: vec![],
        },
        QuotientNumeratorColumnTopology {
            coefficient_log_size: 6,
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            samples: vec![sample(0, 3)],
        },
    ];
    let plan = build_plan(config(), &columns).unwrap();
    assert_eq!(plan.terms.len(), 1);
    assert_eq!(plan.batches.len(), 1);
    assert_eq!(plan.batches[0].evaluation_log_size, 8);

    columns[0].samples.push(sample(1, 5));
    assert!(matches!(
        build_plan(config(), &columns),
        Err(PreparedQuotientNumeratorError::ColumnLogTooLarge {
            column: 0,
            log_size: 25,
            maximum: 6,
        })
    ));
}

#[test]
fn periodicity_and_duplicate_points_group_and_lift_exactly() {
    let repeated = sample(2, 9);
    let columns = vec![
        QuotientNumeratorColumn {
            coefficient_log_size: 4,
            source: QuotientNumeratorColumnSource::Evaluation(slice(1, 64)),
            samples: vec![sample(0, 7), repeated],
        },
        QuotientNumeratorColumn {
            coefficient_log_size: 6,
            source: QuotientNumeratorColumnSource::Evaluation(slice(2, 256)),
            samples: vec![repeated],
        },
    ];
    let plan = build_plan(config(), &topology(&columns)).unwrap();
    let repeated_group = plan
        .requirements
        .groups
        .iter()
        .find(|group| group.shape_point == repeated.shape_point)
        .unwrap();
    assert_eq!(repeated_group.log_size, 6);
    assert_eq!(repeated_group.value_words, 64);
    assert_eq!(plan.terms.len(), 4);
    assert!(plan.terms[0].period.is_some());
    assert_eq!(plan.terms[1].shape_point, sample(0, 7).shape_point);
    assert_eq!(plan.terms[2].shape_point, repeated.shape_point);
}

#[test]
fn groups_count_distinct_coefficient_sources_and_zero_means_evaluation_only() {
    let shared = sample(0, 3);
    let evaluation_only = sample(3, 5);
    let columns = vec![
        QuotientNumeratorColumnTopology {
            coefficient_log_size: 4,
            source_kind: QuotientNumeratorSourceKind::Evaluation,
            samples: vec![shared, evaluation_only],
        },
        QuotientNumeratorColumnTopology {
            coefficient_log_size: 4,
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            // Two terms from one column still count as one source.
            samples: vec![sample(1, 3), sample(2, 3)],
        },
        QuotientNumeratorColumnTopology {
            coefficient_log_size: 4,
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            samples: vec![sample(4, 3)],
        },
        QuotientNumeratorColumnTopology {
            coefficient_log_size: 25,
            source_kind: QuotientNumeratorSourceKind::Coefficients,
            samples: vec![],
        },
    ];
    let plan = build_plan(config(), &columns).unwrap();

    let shared_group = plan
        .requirements
        .groups
        .iter()
        .find(|group| group.shape_point == shared.shape_point)
        .unwrap();
    assert_eq!(shared_group.coefficient_source_count, 2);
    let evaluation_only_group = plan
        .requirements
        .groups
        .iter()
        .find(|group| group.shape_point == evaluation_only.shape_point)
        .unwrap();
    assert_eq!(evaluation_only_group.coefficient_source_count, 0);

    for (group, requirements) in plan.requirements.groups.iter().enumerate() {
        let evaluation_only = plan
            .terms
            .iter()
            .filter(|term| term.group == group)
            .all(|term| {
                columns[term.column].source_kind == QuotientNumeratorSourceKind::Evaluation
            });
        assert_eq!(requirements.coefficient_source_count == 0, evaluation_only);
    }
}

#[test]
fn coefficient_batches_respect_the_exact_tile_ceiling() {
    let columns = (0..3)
        .map(|index| QuotientNumeratorColumn {
            coefficient_log_size: 4,
            source: QuotientNumeratorColumnSource::Coefficients(slice(index + 1, 16)),
            samples: vec![sample(index, index as u128 + 2)],
        })
        .collect::<Vec<_>>();
    let mut config = config();
    config.max_lde_tile_words = 2 * 64;
    let requirements =
        quotient_numerator_workspace_requirements(config, &topology(&columns)).unwrap();
    assert_eq!(
        requirements
            .batches
            .iter()
            .map(|batch| batch.coefficient_count)
            .collect::<Vec<_>>(),
        vec![2, 1]
    );
    assert_eq!(requirements.lde_tile_words, 128);
}

#[test]
fn coefficient_slots_are_present_iff_the_plan_materializes_coefficients() {
    let columns = vec![QuotientNumeratorColumn {
        coefficient_log_size: 4,
        source: QuotientNumeratorColumnSource::Evaluation(slice(1, 64)),
        samples: vec![sample(0, 2)],
    }];
    let requirements =
        quotient_numerator_workspace_requirements(config(), &topology(&columns)).unwrap();
    let mut next = 10;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    let slots = QuotientNumeratorWorkspaceSlots {
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
        coefficient_ptrs: None,
        coefficient_sizes: None,
        coefficient_output_ptrs: None,
        lde_tile: None,
    };
    assert_eq!(
        requirements.arena_slot_requirements(&slots).unwrap().len(),
        10
    );
}
