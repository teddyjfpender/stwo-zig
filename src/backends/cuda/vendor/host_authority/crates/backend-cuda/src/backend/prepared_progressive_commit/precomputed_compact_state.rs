//! Compact state binding for canonical evaluations produced upstream.

use std::collections::{BTreeMap, BTreeSet};

use super::domain_compact_binding::{
    bind_tail_descriptor, CompactOutputBatch, CompactStatePreparedLaunch,
};
use super::*;

/// Bind only the compact state/Merkle predecessor for evaluations that were
/// materialized by another exact producer. Every planned LDE step remains a
/// required receipt, but no coefficient-backed LDE launch is emitted here.
pub(super) fn bind_precomputed_compact_state_launches(
    steps: &[CompactDomainStep],
    requirements: &ProgressiveCommitWorkspaceRequirements,
    prepared_batches: &[CompactOutputBatch],
    retained_outputs: &[Option<ArenaSlice>],
    slab: ArenaSlice,
    scratch_pair: ArenaSlice,
) -> Result<Vec<CompactStatePreparedLaunch>, CompactDomainBindingError> {
    let plan = &requirements.leaves.plan;
    validate_outputs(plan, retained_outputs)?;
    let batches = exact_batches(plan, prepared_batches)?;

    let mut receipts = BTreeSet::new();
    let mut launches = Vec::with_capacity(steps.len().saturating_sub(batches.len()));
    for step in steps {
        match step.operation {
            CompactDomainOperation::LdeBatch {
                batch_index,
                first_column,
                columns,
                log_size,
            } => {
                exact_output_batch(&batches, batch_index, first_column, columns, log_size)?;
                if !receipts.insert(batch_index) {
                    return Err(CompactDomainBindingError::DuplicateLdeReceipt(batch_index));
                }
            }
            CompactDomainOperation::AbsorbDomainBatch {
                batch_index,
                first_column,
                columns,
                log_size,
                absorbed_columns_before,
                initializes_state,
                reconstructed_tail,
                ..
            } => {
                let batch =
                    exact_output_batch(&batches, batch_index, first_column, columns, log_size)?;
                if absorbed_columns_before != first_column {
                    return Err(CompactDomainBindingError::InvalidBatch(batch_index));
                }
                let (tail_columns, tail) = bind_tail_descriptor(
                    reconstructed_tail,
                    log_size,
                    first_column,
                    plan,
                    retained_outputs,
                )?;
                launches.push(CompactStatePreparedLaunch::Absorb {
                    batch,
                    initializes_state,
                    tail_columns,
                    tail,
                    states: slab,
                });
            }
            CompactDomainOperation::StateExpandInPlace {
                from_log_size,
                to_log_size,
                absorbed_columns,
                bands,
            } => launches.push(CompactStatePreparedLaunch::ExpandInPlace {
                from_log: from_log_size,
                to_log: to_log_size,
                absorbed_columns,
                bands,
                states: slab,
                scratch_pair,
            }),
            CompactDomainOperation::FinalizeInPlace {
                log_size,
                absorbed_columns,
                reconstructed_tail,
                ..
            } => {
                let (tail_columns, tail) = bind_tail_descriptor(
                    Some(reconstructed_tail),
                    log_size,
                    absorbed_columns,
                    plan,
                    retained_outputs,
                )?;
                launches.push(CompactStatePreparedLaunch::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    tail_columns,
                    tail,
                    states_and_hashes: slab,
                });
            }
        }
    }
    for &batch_index in batches.keys() {
        if !receipts.contains(&batch_index) {
            return Err(CompactDomainBindingError::MissingLdeReceipt(batch_index));
        }
    }
    Ok(launches)
}

fn validate_outputs(
    plan: &ProgressiveCommitPlan,
    retained_outputs: &[Option<ArenaSlice>],
) -> Result<(), CompactDomainBindingError> {
    if retained_outputs.len() != plan.columns.len() {
        return Err(CompactDomainBindingError::InvalidRetainedOutput(
            retained_outputs.len(),
        ));
    }
    for (canonical, (output, column)) in retained_outputs.iter().zip(&plan.columns).enumerate() {
        let output = output.ok_or(CompactDomainBindingError::MissingTailOutput(canonical))?;
        let expected_words = 1usize
            .checked_shl(column.evaluation_log_size)
            .ok_or(CompactDomainBindingError::InvalidRetainedOutput(canonical))?;
        if output.len_words() != expected_words {
            return Err(CompactDomainBindingError::InvalidRetainedOutput(canonical));
        }
    }
    Ok(())
}

fn exact_batches(
    plan: &ProgressiveCommitPlan,
    prepared_batches: &[CompactOutputBatch],
) -> Result<BTreeMap<u32, CompactOutputBatch>, CompactDomainBindingError> {
    if prepared_batches.len() != plan.lde_batches.len() {
        return Err(CompactDomainBindingError::InvalidBatch(
            u32::try_from(prepared_batches.len()).unwrap_or(u32::MAX),
        ));
    }
    let mut batches = BTreeMap::new();
    for (batch_index, (&prepared, planned)) in
        prepared_batches.iter().zip(&plan.lde_batches).enumerate()
    {
        let batch_index = u32::try_from(batch_index)
            .map_err(|_| CompactDomainBindingError::InvalidBatch(u32::MAX))?;
        let first_column = planned
            .columns
            .first()
            .copied()
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        let end_column = first_column
            .checked_add(planned.columns.len())
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        let expected_pointer_words = planned
            .columns
            .len()
            .checked_mul(POINTER_WORDS)
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        if prepared.batch_index != batch_index
            || prepared.first_column as usize != first_column
            || planned.columns != (first_column..end_column).collect::<Vec<_>>()
            || prepared.columns as usize != planned.columns.len()
            || prepared.log_size != planned.evaluation_log_size
            || prepared.output_ptrs.len_words() != expected_pointer_words
        {
            return Err(CompactDomainBindingError::InvalidBatch(batch_index));
        }
        if batches.insert(prepared.batch_index, prepared).is_some() {
            return Err(CompactDomainBindingError::DuplicateBatch(batch_index));
        }
    }
    Ok(batches)
}

fn exact_output_batch(
    batches: &BTreeMap<u32, CompactOutputBatch>,
    batch_index: u32,
    first_column: u32,
    columns: u32,
    log_size: u32,
) -> Result<CompactOutputBatch, CompactDomainBindingError> {
    let batch = *batches
        .get(&batch_index)
        .ok_or(CompactDomainBindingError::MissingBatch(batch_index))?;
    if batch.first_column != first_column || batch.columns != columns || batch.log_size != log_size
    {
        return Err(CompactDomainBindingError::InvalidBatch(batch_index));
    }
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::progressive_commit::ProgressiveCommitGroupGeometry;
    use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

    fn fixture() -> (
        CompactDomainProgram,
        ProgressiveCommitWorkspaceRequirements,
        Vec<CompactOutputBatch>,
        Vec<Option<ArenaSlice>>,
        ArenaSlice,
        ArenaSlice,
    ) {
        let base = CommitProgram::compile(
            CommitWorkspaceConfig {
                log_blowup_factor: 1,
                lifting_log_size: 7,
                unretained_bottom_layers: 4,
                max_fused_tail_levels: 2,
            },
            ProgressiveCommitGeometry {
                lifting_log_size: 7,
                log_blowup_factor: 1,
                groups: vec![ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: [vec![3; 17], vec![4; 16], vec![5; 1]].concat(),
                    retain_evaluations: true,
                }],
            },
            ProgressiveNttLeafFusionMode::Fused16,
            true,
        )
        .unwrap();
        let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
        let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
        let requirements = base.requirements().clone();
        let batches = requirements
            .leaves
            .plan
            .lde_batches
            .iter()
            .enumerate()
            .map(|(batch_index, batch)| CompactOutputBatch {
                output_ptrs: ArenaSlice::dangling_at_for_test(
                    100 + batch_index as u32,
                    10_000 + batch_index * 256,
                    batch.columns.len() * POINTER_WORDS,
                ),
                batch_index: batch_index as u32,
                first_column: batch.columns[0] as u32,
                columns: batch.columns.len() as u32,
                log_size: batch.evaluation_log_size,
            })
            .collect();
        let outputs = requirements
            .leaves
            .plan
            .columns
            .iter()
            .enumerate()
            .map(|(canonical, column)| {
                Some(ArenaSlice::dangling_at_for_test(
                    1_000 + canonical as u32,
                    100_000 + canonical * 1_024,
                    1usize << column.evaluation_log_size,
                ))
            })
            .collect();
        let slab = ArenaSlice::dangling_at_for_test(9_000, 1_000_000, compact.slab_words());
        let scratch = slab
            .checked_subslice(
                compact.slab_words() - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
                PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            )
            .unwrap();
        (compact, requirements, batches, outputs, slab, scratch)
    }

    #[test]
    fn precomputed_state_consumes_every_lde_receipt_without_emitting_an_lde() {
        let (compact, requirements, batches, outputs, slab, scratch) = fixture();
        let launches = bind_precomputed_compact_state_launches(
            compact.steps(),
            &requirements,
            &batches,
            &outputs,
            slab,
            scratch,
        )
        .unwrap();
        assert_eq!(
            launches.len(),
            compact
                .steps()
                .iter()
                .filter(|step| !matches!(step.operation, CompactDomainOperation::LdeBatch { .. }))
                .count()
        );
        assert!(launches.iter().all(|launch| !matches!(
            launch.kind(),
            CompactDomainPreparedLaunchKind::LdeBatch { .. }
        )));
        assert!(matches!(
            launches.last().map(|launch| launch.kind()),
            Some(CompactDomainPreparedLaunchKind::FinalizeInPlace { .. })
        ));
    }

    #[test]
    fn precomputed_state_rejects_missing_output_and_batch_shape_drift() {
        let (compact, requirements, batches, mut outputs, slab, scratch) = fixture();
        outputs[3] = None;
        assert!(matches!(
            bind_precomputed_compact_state_launches(
                compact.steps(),
                &requirements,
                &batches,
                &outputs,
                slab,
                scratch,
            ),
            Err(CompactDomainBindingError::MissingTailOutput(3))
        ));

        let (_, _, mut batches, outputs, ..) = fixture();
        batches[0].columns += 1;
        assert!(matches!(
            bind_precomputed_compact_state_launches(
                compact.steps(),
                &requirements,
                &batches,
                &outputs,
                slab,
                scratch,
            ),
            Err(CompactDomainBindingError::InvalidBatch(0))
        ));
    }
}
