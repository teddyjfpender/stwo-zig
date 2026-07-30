//! Default-off native binding for the retained-only Mode-A leaf program.
//!
//! Preparation deliberately reuses the qualified one-slab constructor. This
//! module then proves the address-free legacy launch set is exactly the one
//! required by [`DomainCooperativeProgram`], reorders complete LDEs ahead of
//! hashing, and replaces only the scalar absorb launches.

use super::*;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainCooperativeBindingError {
    Program(DomainCooperativeProgramError),
    Prepared(PreparedProgressiveCommitError),
    RequiresFused16Baseline {
        actual: ProgressiveNttLeafFusionMode,
    },
    MissingInitialization,
    DuplicateInitialization,
    InvalidInitialization,
    MissingLegacyLaunch(ProgressiveLeafLaunchKind),
    DuplicateLegacyLaunch(ProgressiveLeafLaunchKind),
    UnexpectedLegacyLaunch(ProgressiveLeafLaunchKind),
    InvalidProgramOperation,
    UnsupportedLogSize(u32),
    CounterRange {
        columns: u32,
        absorbed_columns_before: u32,
    },
    StateSlice {
        offset_words: usize,
        len_words: usize,
        slab_words: usize,
    },
    StateSlab,
    ScratchPair,
}

impl core::fmt::Display for DomainCooperativeBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid native Mode-A CUDA commitment binding: {self:?}")
    }
}

impl std::error::Error for DomainCooperativeBindingError {}

impl From<DomainCooperativeProgramError> for DomainCooperativeBindingError {
    fn from(value: DomainCooperativeProgramError) -> Self {
        Self::Program(value)
    }
}

impl From<PreparedProgressiveCommitError> for DomainCooperativeBindingError {
    fn from(value: PreparedProgressiveCommitError) -> Self {
        Self::Prepared(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PromotionPlan {
    init_index: usize,
    replacements: Vec<(usize, ProgressiveLeafLaunchKind)>,
}

impl<'a> PreparedProgressiveCommitGraph<'a> {
    /// Bind the retained-only cooperative replacement explicitly. No runtime
    /// selector or legacy constructor reaches this path by default.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_in_place_slab_domain_cooperative_mode_a(
        arena: &'a DeviceArena,
        base: &CommitProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
    ) -> Result<Self, DomainCooperativeBindingError> {
        let program = admit_base(base)?;
        program.bind(arena, base, slots, coefficients, retained_outputs, twiddles)
    }
}

impl DomainCooperativeProgram {
    /// Bind this exact address-free Mode-A program. The caller supplies the
    /// Fused16 base identity it was compiled from; any program/base drift is
    /// rejected before CUDA preparation, and no legacy fallback exists.
    pub fn bind<'a>(
        &self,
        arena: &'a DeviceArena,
        base: &CommitProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
    ) -> Result<PreparedProgressiveCommitGraph<'a>, DomainCooperativeBindingError> {
        admit_program(self, base)?;
        let identity = base.identity();
        let mut prepared =
            PreparedProgressiveCommitGraph::prepare_in_place_slab_with_modes_and_ntt_fusion(
                arena,
                identity.config,
                base.requirements(),
                slots,
                coefficients,
                retained_outputs,
                twiddles,
                ProgressiveCommitMode::DomainProgressive,
                identity.interior4_fused,
                ProgressiveNttLeafFusionMode::Separate,
            )?;
        promote_leaves(self, &mut prepared.leaves)?;
        Ok(prepared)
    }
}

fn admit_base(
    base: &CommitProgram,
) -> Result<DomainCooperativeProgram, DomainCooperativeBindingError> {
    let program = DomainCooperativeProgram::compile_mode_a(base)?;
    admit_program(&program, base)?;
    Ok(program)
}

fn admit_program(
    program: &DomainCooperativeProgram,
    base: &CommitProgram,
) -> Result<(), DomainCooperativeBindingError> {
    if base.identity().ntt_leaf_fusion != ProgressiveNttLeafFusionMode::Fused16 {
        return Err(DomainCooperativeBindingError::RequiresFused16Baseline {
            actual: base.identity().ntt_leaf_fusion,
        });
    }
    program.validate_against(base)?;
    Ok(())
}

fn promote_leaves(
    program: &DomainCooperativeProgram,
    leaves: &mut PreparedProgressiveLeaves<'_>,
) -> Result<(), DomainCooperativeBindingError> {
    if leaves.storage != ProgressiveCommitStorageMode::InPlaceSlab {
        return Err(DomainCooperativeBindingError::StateSlab);
    }
    let legacy_kinds = leaves.launch_sequence().collect::<Vec<_>>();
    let plan = promotion_plan(program, &legacy_kinds)?;
    let mut legacy = core::mem::take(&mut leaves.launches)
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    let init = legacy[plan.init_index]
        .take()
        .ok_or(DomainCooperativeBindingError::MissingInitialization)?;
    let Launch::Init {
        log_size: _,
        states: slab,
    } = init
    else {
        return Err(DomainCooperativeBindingError::InvalidInitialization);
    };
    validate_slab(program, slab)?;

    let mut promoted = Vec::with_capacity(plan.replacements.len());
    for (legacy_index, replacement) in plan.replacements {
        let launch = legacy[legacy_index]
            .take()
            .ok_or(DomainCooperativeBindingError::InvalidProgramOperation)?;
        let launch = match (launch, replacement) {
            (Launch::Lde(batch), ProgressiveLeafLaunchKind::Lde { .. }) => Launch::Lde(batch),
            (
                Launch::Absorb {
                    log_size,
                    batch,
                    states,
                },
                ProgressiveLeafLaunchKind::DomainAbsorb {
                    initializes_state, ..
                },
            ) => {
                validate_state(slab, states)?;
                Launch::DomainAbsorb {
                    log_size,
                    batch,
                    initializes_state,
                    states,
                }
            }
            (
                Launch::ExpandInPlace {
                    from_log,
                    to_log,
                    states,
                    scratch_pair,
                },
                ProgressiveLeafLaunchKind::ExpandInPlace { .. },
            ) => {
                validate_state(slab, states)?;
                validate_scratch(slab, scratch_pair)?;
                Launch::ExpandInPlace {
                    from_log,
                    to_log,
                    states,
                    scratch_pair,
                }
            }
            (
                Launch::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    states_and_hashes,
                    scratch_pair,
                },
                ProgressiveLeafLaunchKind::FinalizeInPlace { .. },
            ) => {
                validate_state(slab, states_and_hashes)?;
                validate_scratch(slab, scratch_pair)?;
                Launch::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    states_and_hashes,
                    scratch_pair,
                }
            }
            _ => return Err(DomainCooperativeBindingError::InvalidProgramOperation),
        };
        promoted.push(launch);
    }
    if legacy.iter().flatten().next().is_some() {
        return Err(DomainCooperativeBindingError::InvalidProgramOperation);
    }
    leaves.launches = promoted;
    leaves.cache_key = program.cache_key();
    Ok(())
}

fn validate_slab(
    program: &DomainCooperativeProgram,
    slab: ArenaSlice,
) -> Result<(), DomainCooperativeBindingError> {
    if slab.len_words() != program.slab_words() {
        return Err(DomainCooperativeBindingError::StateSlab);
    }
    Ok(())
}

fn validate_state(
    slab: ArenaSlice,
    state: ArenaSlice,
) -> Result<(), DomainCooperativeBindingError> {
    if state.id() != slab.id()
        || state.as_u32_ptr() != slab.as_u32_ptr()
        || state.len_words() != slab.len_words()
    {
        return Err(DomainCooperativeBindingError::StateSlab);
    }
    Ok(())
}

fn validate_scratch(
    slab: ArenaSlice,
    scratch: ArenaSlice,
) -> Result<(), DomainCooperativeBindingError> {
    let offset = slab
        .len_words()
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .ok_or(DomainCooperativeBindingError::ScratchPair)?;
    if scratch.id() != slab.id()
        || scratch.len_words() != PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        || scratch.as_u32_ptr() != slab.as_u32_ptr().wrapping_add(offset)
    {
        return Err(DomainCooperativeBindingError::ScratchPair);
    }
    Ok(())
}

fn promotion_plan(
    program: &DomainCooperativeProgram,
    legacy: &[ProgressiveLeafLaunchKind],
) -> Result<PromotionPlan, DomainCooperativeBindingError> {
    let replacements = expected_domain_launches(program)?;
    let first_log = replacements
        .iter()
        .find_map(|launch| match launch {
            ProgressiveLeafLaunchKind::DomainAbsorb { log_size, .. } => Some(*log_size),
            _ => None,
        })
        .ok_or(DomainCooperativeBindingError::MissingInitialization)?;
    let init_indices = legacy
        .iter()
        .enumerate()
        .filter_map(|(index, launch)| {
            matches!(launch, ProgressiveLeafLaunchKind::Init { .. }).then_some(index)
        })
        .collect::<Vec<_>>();
    let init_index = match init_indices.as_slice() {
        [] => return Err(DomainCooperativeBindingError::MissingInitialization),
        [index] => *index,
        _ => return Err(DomainCooperativeBindingError::DuplicateInitialization),
    };
    if legacy[init_index]
        != (ProgressiveLeafLaunchKind::Init {
            log_size: first_log,
        })
    {
        return Err(DomainCooperativeBindingError::InvalidInitialization);
    }

    let mut used = vec![false; legacy.len()];
    used[init_index] = true;
    let mut selected = Vec::with_capacity(replacements.len());
    for replacement in replacements {
        let wanted = legacy_twin(replacement)?;
        let matches = legacy
            .iter()
            .enumerate()
            .filter_map(|(index, launch)| (!used[index] && *launch == wanted).then_some(index))
            .collect::<Vec<_>>();
        let index = match matches.as_slice() {
            [] => return Err(DomainCooperativeBindingError::MissingLegacyLaunch(wanted)),
            [index] => *index,
            _ => return Err(DomainCooperativeBindingError::DuplicateLegacyLaunch(wanted)),
        };
        used[index] = true;
        selected.push((index, replacement));
    }
    if let Some((index, _)) = used.iter().enumerate().find(|(_, used)| !**used) {
        return Err(DomainCooperativeBindingError::UnexpectedLegacyLaunch(
            legacy[index],
        ));
    }
    Ok(PromotionPlan {
        init_index,
        replacements: selected,
    })
}

fn expected_domain_launches(
    program: &DomainCooperativeProgram,
) -> Result<Vec<ProgressiveLeafLaunchKind>, DomainCooperativeBindingError> {
    program
        .steps()
        .iter()
        .map(|step| project_operation(step.operation, program.slab_words()))
        .collect()
}

fn project_operation(
    operation: DomainCooperativeOperation,
    slab_words: usize,
) -> Result<ProgressiveLeafLaunchKind, DomainCooperativeBindingError> {
    Ok(match operation {
        DomainCooperativeOperation::LdeBatch {
            batch_index,
            columns,
            log_size,
            ..
        } => ProgressiveLeafLaunchKind::Lde {
            batch_index,
            segment_offset: 0,
            log_size,
            columns,
        },
        DomainCooperativeOperation::AbsorbDomainBatch {
            batch_index,
            columns,
            log_size,
            absorbed_columns_before,
            initializes_state,
            state,
            ..
        } => {
            if log_size >= 31 {
                return Err(DomainCooperativeBindingError::UnsupportedLogSize(log_size));
            }
            if !stwo_backend_cuda_kernels::raw::blake2s_progressive_absorb_quad_counts_valid(
                columns,
                absorbed_columns_before,
                initializes_state,
            ) {
                return Err(DomainCooperativeBindingError::CounterRange {
                    columns,
                    absorbed_columns_before,
                });
            }
            let expected_words = (1usize << log_size)
                .checked_mul(STATE_WORDS)
                .ok_or(DomainCooperativeBindingError::StateSlab)?;
            if state.offset_words != 0
                || state.len_words != expected_words
                || state.end_words().is_none_or(|end| end > slab_words)
            {
                return Err(DomainCooperativeBindingError::StateSlice {
                    offset_words: state.offset_words,
                    len_words: state.len_words,
                    slab_words,
                });
            }
            ProgressiveLeafLaunchKind::DomainAbsorb {
                batch_index,
                log_size,
                columns,
                absorbed_columns_before,
                initializes_state,
            }
        }
        DomainCooperativeOperation::StateExpandInPlace {
            from_log_size,
            to_log_size,
            ..
        } => ProgressiveLeafLaunchKind::ExpandInPlace {
            from_log_size,
            to_log_size,
        },
        DomainCooperativeOperation::FinalizeInPlace {
            log_size,
            absorbed_columns,
            ..
        } => ProgressiveLeafLaunchKind::FinalizeInPlace {
            log_size,
            absorbed_columns,
        },
    })
}

fn legacy_twin(
    replacement: ProgressiveLeafLaunchKind,
) -> Result<ProgressiveLeafLaunchKind, DomainCooperativeBindingError> {
    match replacement {
        ProgressiveLeafLaunchKind::DomainAbsorb {
            batch_index,
            log_size,
            columns,
            absorbed_columns_before,
            ..
        } => Ok(ProgressiveLeafLaunchKind::Absorb {
            batch_index,
            segment_offset: 0,
            log_size,
            columns,
            absorbed_columns_before,
        }),
        ProgressiveLeafLaunchKind::Lde { .. }
        | ProgressiveLeafLaunchKind::ExpandInPlace { .. }
        | ProgressiveLeafLaunchKind::FinalizeInPlace { .. } => Ok(replacement),
        _ => Err(DomainCooperativeBindingError::InvalidProgramOperation),
    }
}

#[cfg(test)]
#[path = "domain_cooperative_binding_tests.rs"]
mod tests;
