use super::*;
use crate::backend::prepared_decommit::TraceTreeRole;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};

fn programs() -> (
    CommitProgram,
    DomainCooperativeProgram,
    CompactDomainProgram,
    FusedCompactDomainProgram,
    DirectRetainedB2nProgram,
    DirectCompactTerminalProgram,
    DirectTerminalExpandAbsorbProgram,
) {
    let logs = [vec![3; 1], vec![12; 16], vec![13; 1]].concat();
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 14,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 14,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: logs,
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let fused = FusedCompactDomainProgram::compile(&base, &domain, &compact).unwrap();
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &base).unwrap();
    let terminal = DirectCompactTerminalProgram::compile(&compact, &direct).unwrap();
    let composed = DirectTerminalExpandAbsorbProgram::compile(
        &base, &domain, &compact, &fused, &direct, &terminal,
    )
    .unwrap();
    (base, domain, compact, fused, direct, terminal, composed)
}

fn prepared_batches(direct: &DirectRetainedB2nProgram) -> Vec<DirectPreparedBatch> {
    direct
        .batches()
        .iter()
        .map(|batch| DirectPreparedBatch {
            input_pointers: ArenaSlice::dangling_for_test(
                100 + batch.batch_index,
                batch.pointer_words,
            ),
            output_pointers: ArenaSlice::dangling_for_test(
                200 + batch.batch_index,
                batch.pointer_words,
            ),
            batch_index: batch.batch_index,
            first_column: batch.canonical_columns[0] as u32,
            source_log_size: batch.source_log_size,
            retained_log_size: batch.retained_log_size,
            columns: batch.canonical_columns.len() as u32,
        })
        .collect()
}

fn retained_outputs(plan: &ProgressiveCommitPlan) -> Vec<Option<ArenaSlice>> {
    plan.columns
        .iter()
        .enumerate()
        .map(|(canonical, column)| {
            Some(ArenaSlice::dangling_at_for_test(
                300 + canonical as u32,
                1_000_000 + canonical * (1 << 15),
                1usize << column.evaluation_log_size,
            ))
        })
        .collect()
}

#[test]
fn prepared_execution_preserves_fixed16_and_binds_one_materialized_rise() {
    let (base, domain, _compact, _fused, direct, terminal, composed) = programs();
    let slab = ArenaSlice::dangling_at_for_test(1, 10_000, domain.slab_words());
    let scratch = slab.checked_subslice(domain.slab_words() - 48, 48).unwrap();
    let retained = retained_outputs(&base.requirements().leaves.plan);
    let (execution, semantic) = PreparedDirectCompactTerminalExecution::bind_expand_absorb(
        &composed,
        terminal,
        &prepared_batches(&direct),
        &base.requirements().leaves.plan,
        &retained,
        slab,
        scratch,
    )
    .unwrap();
    assert_eq!(execution.steps.len(), 4);
    assert!(matches!(
        execution.steps[0],
        PreparedDirectCompactTerminalStep::Materialized { .. }
    ));
    assert!(matches!(
        execution.steps[1],
        PreparedDirectCompactTerminalStep::Fixed16Hybrid {
            expansion: Some(_),
            ..
        }
    ));
    assert!(matches!(
        execution.steps[2],
        PreparedDirectCompactTerminalStep::MaterializedExpandAbsorb { .. }
    ));
    assert!(matches!(
        execution.steps[3],
        PreparedDirectCompactTerminalStep::QualifiedState(
            CompactStatePreparedLaunch::FinalizeInPlace { states_and_hashes, .. }
        ) if states_and_hashes.as_u32_ptr() == slab.as_u32_ptr()
    ));
    assert_eq!(semantic.len(), 5);
}

#[test]
fn prepared_binding_rejects_scratch_drift() {
    let (base, domain, _compact, _fused, direct, terminal, composed) = programs();
    let slab = ArenaSlice::dangling_at_for_test(1, 10_000, domain.slab_words());
    let scratch = slab.checked_subslice(domain.slab_words() - 49, 48).unwrap();
    let retained = retained_outputs(&base.requirements().leaves.plan);
    assert!(matches!(
        PreparedDirectCompactTerminalExecution::bind_expand_absorb(
            &composed,
            terminal,
            &prepared_batches(&direct),
            &base.requirements().leaves.plan,
            &retained,
            slab,
            scratch,
        ),
        Err(DirectCompactTerminalError::ProgramIdentity)
    ));
}
