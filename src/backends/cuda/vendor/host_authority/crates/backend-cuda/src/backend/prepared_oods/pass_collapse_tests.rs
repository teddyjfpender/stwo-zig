use super::*;

fn config() -> OodsWorkspaceConfig {
    OodsWorkspaceConfig {
        lifting_log_size: 24,
        mask_log_size: 12,
    }
}

#[test]
fn canonical_oracle_orders_sources_groups_and_outputs_exactly() {
    let coefficient_offsets = [2, 0];
    let evaluation_offsets = [1, 0];
    let columns = [
        OodsColumnTopology::evaluation_signed_offsets(8, &evaluation_offsets),
        OodsColumnTopology::signed_offsets(11, &coefficient_offsets),
        OodsColumnTopology::evaluation_signed_offsets(8, &[0]),
        OodsColumnTopology::signed_offsets(7, &[0]),
    ];
    let order = oods_canonical_sample_order(config(), &columns).unwrap();
    assert_eq!(
        order
            .iter()
            .map(|sample| {
                (
                    sample.source_kind,
                    sample.source_log_size,
                    sample.column_index,
                    sample.mask_index,
                    sample.output_index,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (OodsSourceKind::Coefficients, 7, 3, 0, 5),
            (OodsSourceKind::Coefficients, 11, 1, 0, 2),
            (OodsSourceKind::Coefficients, 11, 1, 1, 3),
            (OodsSourceKind::Evaluations, 8, 0, 1, 1),
            (OodsSourceKind::Evaluations, 8, 2, 0, 4),
            (OodsSourceKind::Evaluations, 8, 0, 0, 0),
        ]
    );
}

#[test]
fn receipt_covers_every_group_and_accounts_exact_pass_deltas() {
    let columns = [
        OodsColumnTopology::signed_offsets(11, &[0]),
        OodsColumnTopology::evaluation_signed_offsets(8, &[0, 1]),
        OodsColumnTopology::evaluation_signed_offsets(8, &[0]),
        OodsColumnTopology::evaluation_signed_offsets(10, &[0]),
    ];
    let program = OodsPassCollapseProgram::compile(config(), &columns).unwrap();
    let receipt = program.receipt();
    assert_eq!(receipt.coefficient_group_count, 1);
    assert_eq!(receipt.evaluation_group_count, 3);
    assert_eq!(receipt.covered_evaluation_group_count, 3);
    assert_eq!(receipt.evaluation_sample_count, 4);
    assert_eq!(receipt.same_log_cohorts.len(), 2);
    assert_eq!(receipt.same_log_cohorts[0].log_size, 8);
    assert_eq!(receipt.same_log_cohorts[0].group_count, 2);
    assert_eq!(receipt.same_log_cohorts[0].sample_count, 3);
    assert_eq!(receipt.unchanged_coefficient_kernel_launches, 4);
    assert_eq!(receipt.unchanged_evaluation_kernel_launches, 9);
    assert_eq!(receipt.legacy_weight_kernel_launches, 12);
    assert_eq!(receipt.collapsed_weight_kernel_launches, 2);
    assert_eq!(receipt.kernel_launches_removed, 10);
    assert_eq!(receipt.legacy_total_kernel_launches, 25);
    assert_eq!(receipt.collapsed_total_kernel_launches, 15);
    assert_eq!(receipt.legacy_weight_logical_bytes, 196_704);
    assert_eq!(receipt.collapsed_weight_logical_bytes, 24_576);
    assert_eq!(receipt.logical_bytes_removed, 172_128);
    assert_eq!(receipt.workspace_bytes_removed, 16_384);
    assert_eq!(receipt.retained_weight_bytes, 16_384);
    assert!(receipt
        .same_log_cohorts
        .iter()
        .all(|cohort| cohort.full_cohort_fusion_admitted));
    assert_eq!(receipt.large_kernel_dynamic_shared_bytes, 48_704);
    assert_eq!(receipt.cuda_default_dynamic_shared_limit_bytes, 49_152);
    assert!(receipt.dynamic_shared_admitted);
    assert_eq!(receipt.legacy_scale_evaluations, 3);
    assert_eq!(receipt.collapsed_scale_evaluations, 3);
    assert_eq!(
        program.collapsed_requirements().barycentric_numerator_words,
        SECURE_WORDS
    );
    assert_eq!(
        program.collapsed_requirements().barycentric_scale_words,
        SECURE_WORDS
    );
}

#[test]
fn topology_and_canonical_order_mutations_fail_identity() {
    let original = [
        OodsColumnTopology::signed_offsets(11, &[0]),
        OodsColumnTopology::evaluation_signed_offsets(8, &[0, 1]),
    ];
    let program = OodsPassCollapseProgram::compile(config(), &original).unwrap();
    assert_eq!(program.validate_against(config(), &original), Ok(()));

    let changed_order = [
        OodsColumnTopology::evaluation_signed_offsets(8, &[0, 1]),
        OodsColumnTopology::signed_offsets(11, &[0]),
    ];
    assert_eq!(
        program.validate_against(config(), &changed_order),
        Err(OodsPassCollapseError::ProgramIdentity)
    );
    let changed_mask = [
        OodsColumnTopology::signed_offsets(11, &[0]),
        OodsColumnTopology::evaluation_signed_offsets(8, &[0, 2]),
    ];
    assert_eq!(
        program.validate_against(config(), &changed_mask),
        Err(OodsPassCollapseError::ProgramIdentity)
    );
}

#[test]
fn oversized_same_log_cohort_is_batched_without_workspace_expansion() {
    let columns = [OodsColumnTopology::evaluation_signed_offsets(
        10,
        &[0, 1, 2],
    )];
    let program = OodsPassCollapseProgram::compile(config(), &columns).unwrap();
    let receipt = program.receipt();
    let cohort = &receipt.same_log_cohorts[0];
    assert_eq!(cohort.group_count, 3);
    assert!(!cohort.full_cohort_fusion_admitted);
    assert_eq!(cohort.max_groups_per_launch, 2);
    assert_eq!(cohort.collapsed_weight_kernel_launches, 2);
    assert_eq!(
        cohort.batches,
        vec![
            OodsPassCollapseBatchReceipt {
                first_group: 0,
                group_count: 2,
                log_size: 10,
                weight_words: 8_192,
            },
            OodsPassCollapseBatchReceipt {
                first_group: 2,
                group_count: 1,
                log_size: 10,
                weight_words: 4_096,
            },
        ]
    );
    assert_eq!(
        cohort.full_cohort_rejection,
        Some(OodsPassCollapseCohortRejection::WorkspaceCapacity {
            required_weight_words: 12_288,
            available_weight_words: 8_192,
        })
    );
    assert_eq!(receipt.legacy_weight_kernel_launches, 12);
    assert_eq!(receipt.collapsed_weight_kernel_launches, 2);
    assert_eq!(receipt.workspace_bytes_removed, 0);
}

#[test]
fn scale_recomputation_is_explicit_in_the_work_receipt() {
    let columns = [OodsColumnTopology::evaluation_signed_offsets(12, &[0])];
    let receipt = OodsPassCollapseProgram::compile(config(), &columns)
        .unwrap()
        .receipt()
        .clone();
    assert_eq!(receipt.legacy_scale_evaluations, 1);
    assert_eq!(receipt.collapsed_scale_evaluations, 4);
    assert_eq!(receipt.additional_scale_evaluations, 3);
    assert_eq!(receipt.legacy_scale_secure_squares, 11);
    assert_eq!(receipt.collapsed_scale_secure_squares, 44);
}

#[test]
fn coefficient_only_shape_is_rejected_instead_of_claiming_zero_credit() {
    let columns = [OodsColumnTopology::signed_offsets(11, &[0])];
    assert!(matches!(
        OodsPassCollapseProgram::compile(config(), &columns),
        Err(OodsPassCollapseError::NoEvaluationGroups)
    ));
}
