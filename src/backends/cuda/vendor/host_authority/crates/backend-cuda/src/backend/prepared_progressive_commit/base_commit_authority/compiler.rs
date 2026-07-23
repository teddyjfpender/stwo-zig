use super::effect::{
    direct_b2n_effect, direct_n2b_effect, merkle_effect, merkle_in_place_effect,
    state_absorb_effect, state_expand_effect, state_finalize_effect, state_init_effect,
};
use super::encoding::{
    launch_identity, operation_abi_identity, operation_identity, operation_source_identity,
};
use super::execution::execution_manifest;
use super::invocation::compile_invocation;
use super::*;

struct PendingLde {
    batch_index: u32,
    segment_offset: u32,
    columns: u32,
    log_size: u32,
    canonical_columns: Vec<u32>,
}

pub(super) struct Compiler<'a> {
    commit: &'a CommitProgram,
    direct: &'a DirectRetainedB2nProgram,
    source_identity: [u8; 32],
    pub(super) operations: Vec<BaseCommitOperation>,
    state: Option<BaseCommitValueRole>,
    next_state_version: u32,
    next_batch: usize,
    next_segment_offset: usize,
    hash: Option<BaseCommitValueRole>,
}

impl<'a> Compiler<'a> {
    pub(super) fn new(
        commit: &'a CommitProgram,
        direct: &'a DirectRetainedB2nProgram,
        source_identity: [u8; 32],
    ) -> Self {
        Self {
            commit,
            direct,
            source_identity,
            operations: Vec::new(),
            state: None,
            next_state_version: 0,
            next_batch: 0,
            next_segment_offset: 0,
            hash: None,
        }
    }

    pub(super) fn compile_steps(&mut self) -> Result<(), BaseCommitAuthorityError> {
        let mut pending_lde: Option<PendingLde> = None;
        for (step_index, step) in self.commit.steps().iter().enumerate() {
            match step.operation {
                CommitProgramOperation::StateInit { log_size } => {
                    if self.state.is_some() || pending_lde.is_some() {
                        return Err(BaseCommitAuthorityError::InvalidProgramOrder);
                    }
                    let destination = self.new_state(log_size)?;
                    self.push(
                        BaseCommitOperationKind::StateInit { log_size },
                        BaseCommitAbi::StateInitV1,
                        state_init_effect(log_size, destination)?,
                        BaseCommitPartitionAuthority::Monolithic,
                    )?;
                    self.state = Some(destination);
                }
                CommitProgramOperation::Lde {
                    batch_index,
                    segment_offset,
                    columns,
                    log_size,
                } => {
                    if pending_lde.is_some() {
                        return Err(BaseCommitAuthorityError::InvalidProgramOrder);
                    }
                    let (source_log_size, retained_log_size, canonical_columns) = self
                        .consume_direct_segment(
                            step_index,
                            batch_index,
                            segment_offset,
                            columns,
                            log_size,
                        )?;
                    self.push_direct_transforms(
                        batch_index,
                        segment_offset,
                        source_log_size,
                        retained_log_size,
                        &canonical_columns,
                    )?;
                    pending_lde = Some(PendingLde {
                        batch_index,
                        segment_offset,
                        columns,
                        log_size,
                        canonical_columns,
                    });
                }
                CommitProgramOperation::Absorb {
                    batch_index,
                    segment_offset,
                    columns,
                    log_size,
                    absorbed_columns_before,
                } => {
                    let pending = pending_lde
                        .take()
                        .filter(|pending| {
                            pending.batch_index == batch_index
                                && pending.segment_offset == segment_offset
                                && pending.columns == columns
                                && pending.log_size == log_size
                        })
                        .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)?;
                    self.push_absorb(
                        batch_index,
                        segment_offset,
                        log_size,
                        absorbed_columns_before,
                        pending.canonical_columns,
                    )?;
                }
                CommitProgramOperation::FusedLdeAbsorb16 {
                    batch_index,
                    segment_offset,
                    log_size,
                    absorbed_columns_before,
                    retained_write_mask,
                } => {
                    if pending_lde.is_some() || retained_write_mask != u32::from(u16::MAX) {
                        return Err(BaseCommitAuthorityError::InvalidProgramOrder);
                    }
                    let (source_log_size, retained_log_size, canonical_columns) = self
                        .consume_direct_segment(
                            step_index,
                            batch_index,
                            segment_offset,
                            16,
                            log_size,
                        )?;
                    self.push_direct_transforms(
                        batch_index,
                        segment_offset,
                        source_log_size,
                        retained_log_size,
                        &canonical_columns,
                    )?;
                    self.push_absorb(
                        batch_index,
                        segment_offset,
                        log_size,
                        absorbed_columns_before,
                        canonical_columns,
                    )?;
                }
                CommitProgramOperation::StateExpandInPlace {
                    from_log_size,
                    to_log_size,
                    absorbed_columns,
                    bands,
                } => {
                    let source = exact_state(self.state, from_log_size)?;
                    let destination = self.new_state(to_log_size)?;
                    self.push(
                        BaseCommitOperationKind::StateExpandInPlace {
                            from_log_size,
                            to_log_size,
                            absorbed_columns,
                            bands,
                        },
                        BaseCommitAbi::StateExpandInPlaceV1,
                        state_expand_effect(from_log_size, to_log_size, source, destination)?,
                        BaseCommitPartitionAuthority::Monolithic,
                    )?;
                    self.state = Some(destination);
                }
                CommitProgramOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    bands,
                } => {
                    let source = exact_state(self.state, log_size)?;
                    let destination = BaseCommitValueRole::HashLayer { log_size };
                    self.push(
                        BaseCommitOperationKind::StateFinalizeInPlace {
                            log_size,
                            absorbed_columns,
                            bands,
                        },
                        BaseCommitAbi::StateFinalizeInPlaceV1,
                        state_finalize_effect(log_size, source, destination)?,
                        BaseCommitPartitionAuthority::Monolithic,
                    )?;
                    self.hash = Some(destination);
                }
                CommitProgramOperation::MerkleLayerInPlace {
                    level,
                    output_hashes,
                    bands,
                } => {
                    let (source, destination) = self.merkle_transition(output_hashes)?;
                    self.push(
                        BaseCommitOperationKind::MerkleLayerInPlace {
                            level,
                            output_hashes,
                            bands,
                        },
                        BaseCommitAbi::MerkleLayerInPlaceV1,
                        merkle_in_place_effect(source, destination)?,
                        BaseCommitPartitionAuthority::Monolithic,
                    )?;
                    self.hash = Some(destination);
                }
                CommitProgramOperation::MerkleLayer {
                    level,
                    output_hashes,
                } => {
                    let (source, destination) = self.merkle_transition(output_hashes)?;
                    self.push(
                        BaseCommitOperationKind::MerkleLayer {
                            level,
                            output_hashes,
                        },
                        BaseCommitAbi::MerkleLayerV1,
                        merkle_effect(source, destination)?,
                        BaseCommitPartitionAuthority::Monolithic,
                    )?;
                    self.hash = Some(destination);
                }
                CommitProgramOperation::MerkleTail {
                    first_hashes,
                    levels,
                } => self.push_merkle_tail(first_hashes, levels)?,
                CommitProgramOperation::MerkleInterior4 { .. } => {
                    return Err(BaseCommitAuthorityError::UnsupportedOperation(
                        step.operation,
                    ))
                }
            }
        }
        if pending_lde.is_some()
            || self.next_batch != self.direct.batches().len()
            || self.next_segment_offset != 0
            || self.hash != Some(BaseCommitValueRole::HashLayer { log_size: 0 })
        {
            return Err(BaseCommitAuthorityError::InvalidProgramOrder);
        }
        Ok(())
    }

    fn consume_direct_segment(
        &mut self,
        step_index: usize,
        batch_index: u32,
        segment_offset: u32,
        columns: u32,
        retained_log_size: u32,
    ) -> Result<(u32, u32, Vec<u32>), BaseCommitAuthorityError> {
        let begin =
            usize::try_from(segment_offset).map_err(|_| BaseCommitAuthorityError::SizeOverflow)?;
        let end = begin
            .checked_add(columns as usize)
            .ok_or(BaseCommitAuthorityError::SizeOverflow)?;
        let batch = self
            .direct
            .batches()
            .get(self.next_batch)
            .filter(|batch| {
                batch.batch_index == batch_index
                    && batch.retained_log_size == retained_log_size
                    && begin == self.next_segment_offset
                    && end <= batch.canonical_columns.len()
                    && self.commit.canonical_columns_for_step(step_index)
                        == batch.canonical_columns.get(begin..end)
            })
            .ok_or(BaseCommitAuthorityError::ProgramMismatch)?;
        let source_log_size = batch.source_log_size;
        let canonical_columns = canonical_u32(
            batch
                .canonical_columns
                .get(begin..end)
                .ok_or(BaseCommitAuthorityError::ProgramMismatch)?,
        )?;
        if end == batch.canonical_columns.len() {
            self.next_batch += 1;
            self.next_segment_offset = 0;
        } else {
            self.next_segment_offset = end;
        }
        Ok((source_log_size, retained_log_size, canonical_columns))
    }

    fn push_direct_transforms(
        &mut self,
        batch_index: u32,
        segment_offset: u32,
        source_log_size: u32,
        retained_log_size: u32,
        canonical_columns: &[u32],
    ) -> Result<(), BaseCommitAuthorityError> {
        self.push(
            BaseCommitOperationKind::DirectB2n {
                batch_index,
                segment_offset,
                source_log_size,
                retained_log_size,
                canonical_columns: canonical_columns.to_vec(),
            },
            BaseCommitAbi::DirectB2nV1,
            direct_b2n_effect(
                batch_index,
                segment_offset,
                canonical_columns,
                source_log_size,
                retained_log_size,
            )?,
            BaseCommitPartitionAuthority::Monolithic,
        )?;
        self.push(
            BaseCommitOperationKind::DirectN2b {
                batch_index,
                segment_offset,
                source_log_size,
                retained_log_size,
                canonical_columns: canonical_columns.to_vec(),
            },
            BaseCommitAbi::DirectN2bV1,
            direct_n2b_effect(
                batch_index,
                segment_offset,
                canonical_columns,
                retained_log_size,
            )?,
            BaseCommitPartitionAuthority::Monolithic,
        )
    }

    fn push_absorb(
        &mut self,
        batch_index: u32,
        segment_offset: u32,
        log_size: u32,
        absorbed_columns_before: u32,
        canonical_columns: Vec<u32>,
    ) -> Result<(), BaseCommitAuthorityError> {
        let source = self
            .state
            .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)?;
        let destination = self.new_state(log_size)?;
        self.push(
            BaseCommitOperationKind::StateAbsorb {
                batch_index,
                segment_offset,
                log_size,
                absorbed_columns_before,
                canonical_columns: canonical_columns.clone(),
            },
            BaseCommitAbi::StateAbsorbV1,
            state_absorb_effect(
                batch_index,
                segment_offset,
                log_size,
                source,
                destination,
                &canonical_columns,
            )?,
            BaseCommitPartitionAuthority::Monolithic,
        )?;
        self.state = Some(destination);
        Ok(())
    }

    fn push_merkle_tail(
        &mut self,
        first_hashes: u32,
        levels: u32,
    ) -> Result<(), BaseCommitAuthorityError> {
        let source_log = hash_log(
            self.hash
                .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)?,
        )?;
        let expected_first_hashes = 1u32
            .checked_shl(levels)
            .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)?;
        if levels == 0 || source_log != levels || first_hashes != expected_first_hashes {
            return Err(BaseCommitAuthorityError::InvalidProgramOrder);
        }
        let first_level = self
            .commit
            .identity()
            .config
            .lifting_log_size
            .checked_sub(levels)
            .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)?;
        for offset in 0..levels {
            let output_hashes = first_hashes >> (offset + 1);
            let (source, destination) = self.merkle_transition(output_hashes)?;
            let level = first_level
                .checked_add(offset)
                .ok_or(BaseCommitAuthorityError::SizeOverflow)?;
            self.push(
                BaseCommitOperationKind::MerkleLayer {
                    level,
                    output_hashes,
                },
                BaseCommitAbi::MerkleLayerV1,
                merkle_effect(source, destination)?,
                BaseCommitPartitionAuthority::Monolithic,
            )?;
            self.hash = Some(destination);
        }
        Ok(())
    }

    fn new_state(
        &mut self,
        log_size: u32,
    ) -> Result<BaseCommitValueRole, BaseCommitAuthorityError> {
        let version = self.next_state_version;
        self.next_state_version = version
            .checked_add(1)
            .ok_or(BaseCommitAuthorityError::SizeOverflow)?;
        Ok(BaseCommitValueRole::State { version, log_size })
    }

    fn merkle_transition(
        &self,
        output_hashes: u32,
    ) -> Result<(BaseCommitValueRole, BaseCommitValueRole), BaseCommitAuthorityError> {
        let source = self
            .hash
            .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)?;
        let source_log = hash_log(source)?;
        let destination_log = output_hashes
            .checked_ilog2()
            .filter(|_| output_hashes.is_power_of_two())
            .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)?;
        if source_log != destination_log + 1 {
            return Err(BaseCommitAuthorityError::InvalidProgramOrder);
        }
        Ok((
            source,
            BaseCommitValueRole::HashLayer {
                log_size: destination_log,
            },
        ))
    }

    fn push(
        &mut self,
        kind: BaseCommitOperationKind,
        abi: BaseCommitAbi,
        effect: BaseCommitEffect,
        partition: BaseCommitPartitionAuthority,
    ) -> Result<(), BaseCommitAuthorityError> {
        let source_identity = operation_source_identity(self.source_identity, abi);
        let abi_identity = operation_abi_identity(abi, &kind)?;
        let invocation = compile_invocation(abi, &kind, &effect)?;
        let execution = execution_manifest(&kind)?;
        let launch_identity = launch_identity(abi, &kind, &execution)?;
        let identity = operation_identity(
            source_identity,
            abi_identity,
            effect.identity,
            invocation.identity,
            launch_identity,
            &partition,
        )?;
        self.operations.push(BaseCommitOperation {
            kind,
            abi,
            effect,
            invocation,
            partition,
            execution,
            source_identity,
            abi_identity,
            launch_identity,
            identity,
        });
        Ok(())
    }

    pub(super) fn finish_values(
        &self,
    ) -> Result<
        (
            Vec<BaseCommitLayout>,
            Vec<BaseCommitRetainedEvaluation>,
            Vec<BaseCommitRetainedLayer>,
            BaseCommitValueRole,
        ),
        BaseCommitAuthorityError,
    > {
        let mut roles = std::collections::BTreeSet::new();
        for access in self
            .operations
            .iter()
            .flat_map(|operation| &operation.effect.accesses)
        {
            roles.insert(access.role);
        }
        let layouts = roles
            .into_iter()
            .map(|role| layout(self.commit, role))
            .collect::<Result<Vec<_>, _>>()?;
        let retained_evaluations = self
            .commit
            .requirements()
            .leaves
            .plan
            .columns
            .iter()
            .enumerate()
            .map(|(canonical, column)| {
                if !column.retained_evaluation {
                    return Err(BaseCommitAuthorityError::InvalidRetainedOutput);
                }
                Ok(BaseCommitRetainedEvaluation {
                    canonical_column: u32_value(canonical)?,
                    role: BaseCommitValueRole::RetainedEvaluation {
                        canonical_column: u32_value(canonical)?,
                    },
                    words: words(column.evaluation_log_size)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let retained_layers_bottom_up = self
            .commit
            .retained_layers_bottom_up()
            .iter()
            .map(|layer| {
                let expected = hash_words(layer.log_size)?;
                if layer.words != expected {
                    return Err(BaseCommitAuthorityError::InvalidRetainedOutput);
                }
                Ok(BaseCommitRetainedLayer {
                    log_size: layer.log_size,
                    role: BaseCommitValueRole::HashLayer {
                        log_size: layer.log_size,
                    },
                    words: layer.words,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let root = retained_layers_bottom_up
            .last()
            .filter(|layer| layer.log_size == 0 && layer.words == HASH_WORDS)
            .map(|layer| layer.role)
            .ok_or(BaseCommitAuthorityError::InvalidRetainedOutput)?;
        Ok((
            layouts,
            retained_evaluations,
            retained_layers_bottom_up,
            root,
        ))
    }
}

fn layout(
    commit: &CommitProgram,
    role: BaseCommitValueRole,
) -> Result<BaseCommitLayout, BaseCommitAuthorityError> {
    let (rows, words_per_row, alignment_words) = match role {
        BaseCommitValueRole::SourceEvaluation { canonical_column } => (
            column_words(commit, canonical_column, false)?,
            1,
            HASH_WORDS,
        ),
        BaseCommitValueRole::RetainedStageTwo { canonical_column }
        | BaseCommitValueRole::RetainedEvaluation { canonical_column } => {
            (column_words(commit, canonical_column, true)?, 1, HASH_WORDS)
        }
        BaseCommitValueRole::State { log_size, .. } => (words(log_size)?, STATE_WORDS, HASH_WORDS),
        BaseCommitValueRole::HashLayer { log_size } => (words(log_size)?, HASH_WORDS, HASH_WORDS),
    };
    Ok(BaseCommitLayout {
        role,
        rows,
        words_per_row,
        logical_words: rows
            .checked_mul(words_per_row)
            .ok_or(BaseCommitAuthorityError::SizeOverflow)?,
        alignment_words,
    })
}

fn canonical_u32(values: &[usize]) -> Result<Vec<u32>, BaseCommitAuthorityError> {
    values.iter().copied().map(u32_value).collect()
}

pub(super) fn u32_value(value: usize) -> Result<u32, BaseCommitAuthorityError> {
    u32::try_from(value).map_err(|_| BaseCommitAuthorityError::SizeOverflow)
}

fn words(log_size: u32) -> Result<usize, BaseCommitAuthorityError> {
    1usize
        .checked_shl(log_size)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn hash_words(log_size: u32) -> Result<usize, BaseCommitAuthorityError> {
    words(log_size)?
        .checked_mul(HASH_WORDS)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn hash_log(role: BaseCommitValueRole) -> Result<u32, BaseCommitAuthorityError> {
    match role {
        BaseCommitValueRole::HashLayer { log_size } => Ok(log_size),
        _ => Err(BaseCommitAuthorityError::InvalidProgramOrder),
    }
}

fn column_words(
    commit: &CommitProgram,
    canonical_column: u32,
    retained: bool,
) -> Result<usize, BaseCommitAuthorityError> {
    let column = commit
        .requirements()
        .leaves
        .plan
        .columns
        .get(canonical_column as usize)
        .ok_or(BaseCommitAuthorityError::InvalidRetainedOutput)?;
    words(if retained {
        column.evaluation_log_size
    } else {
        column.coefficient_log_size
    })
}

fn exact_state(
    state: Option<BaseCommitValueRole>,
    log_size: u32,
) -> Result<BaseCommitValueRole, BaseCommitAuthorityError> {
    state
        .filter(|role| matches!(role, BaseCommitValueRole::State { log_size: actual, .. } if *actual == log_size))
        .ok_or(BaseCommitAuthorityError::InvalidProgramOrder)
}

/// Exact physical launch count of
/// `stwo_ntt_b2n_columns_to_retained_on`, including its 65,535-column tiling.
#[cfg(test)]
pub(super) fn b2n_columns_to_retained_launches(
    log_size: u32,
    columns: u32,
) -> Result<u32, BaseCommitAuthorityError> {
    let per_chunk = match log_size {
        3..=12 => log_size,
        13..=18 => 2,
        19..=24 => 3,
        25..=29 => 4,
        30 => 30,
        _ => return Err(BaseCommitAuthorityError::SizeOverflow),
    };
    per_chunk
        .checked_mul(ntt_column_chunks(columns)?)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

/// Exact physical launch count of
/// `stwo_ntt_n2b_columns_from_stage_two_on`, including its 65,535-column
/// tiling. Native logs launch stages `2..=log_size`; optimized logs retain the
/// audited fused-interval schedule.
#[cfg(test)]
pub(super) fn n2b_from_stage_two_launches(
    log_size: u32,
    columns: u32,
) -> Result<u32, BaseCommitAuthorityError> {
    let per_chunk = match log_size {
        3..=12 => log_size - 1,
        13..=19 => 2,
        20..=27 => 3,
        28..=30 => 4,
        _ => return Err(BaseCommitAuthorityError::SizeOverflow),
    };
    per_chunk
        .checked_mul(ntt_column_chunks(columns)?)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

#[cfg(test)]
pub(super) fn ntt_column_chunks(columns: u32) -> Result<u32, BaseCommitAuthorityError> {
    const MAX_COLUMNS: u64 = 65_535;
    if columns == 0 {
        return Err(BaseCommitAuthorityError::SizeOverflow);
    }
    u32::try_from(u64::from(columns).div_ceil(MAX_COLUMNS))
        .map_err(|_| BaseCommitAuthorityError::SizeOverflow)
}
