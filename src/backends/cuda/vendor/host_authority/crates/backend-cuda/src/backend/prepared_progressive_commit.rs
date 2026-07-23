//! Prepared domain-progressive commitment leaves.
//!
//! This is intentionally an additive producer for the existing Merkle graph:
//! it ends at the ordinary `Blake2sHash` leaf layer, so the qualified interior
//! and fused-tail kernels remain unchanged.  Topology and mode are sealed by
//! [`progressive_leaf_workspace_requirements`] before arena allocation.

use core::ffi::c_void;
use std::collections::BTreeSet;

use stwo::core::vcs::blake2_hash::Blake2sHash;

use super::exec_context::{check_cuda, ArenaSlice, ArenaSlotId, DeviceArena};
use super::prepared_commit::{
    bind_slot, merkle_from_leaves_requirements, CommitArenaSlotRequirement,
    CommitCoefficientColumn, CommitWorkspaceConfig, CommitWorkspaceRequirements,
    CommitWorkspaceSlots, MerkleFromLeavesRequirements, MerkleFromLeavesSlots,
    PreparedMerkleFromLeaves, COMMIT_HASH_ALIGNMENT_WORDS,
};
use super::progressive_commit::{
    plan_progressive_commit, validate_progressive_plan, ProgressiveCommitError,
    ProgressiveCommitGeometry, ProgressiveCommitMode, ProgressiveCommitPlan,
    PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
};
use super::progressive_ntt_leaf_fusion::{
    progressive_lde_segments, ProgressiveLdeSegment, ProgressiveLdeSegmentKind,
    ProgressiveNttLeafFusionMode, ProgressiveNttLeafFusionTelemetry,
};

mod base_commit_authority;
mod composition_split;
mod direct_compact_domain_binding;
mod direct_compact_terminal_fused;
mod direct_retained_b2n;
mod direct_terminal_expand_absorb;
mod direct_terminal_expand_absorb_binding;
mod domain_compact;
mod domain_compact_binding;
mod domain_cooperative;
mod domain_cooperative_binding;
mod domain_expand_absorb;
mod domain_expand_absorb_binding;
mod in_place;
mod precomputed_compact_domain_binding;
mod precomputed_compact_state;
mod program;
mod program_binding;
mod program_oracle;
mod shape_wide;

pub use base_commit_authority::{
    BaseCommitAbi, BaseCommitAbiAccess, BaseCommitAbiArgument, BaseCommitAbiArgumentKind,
    BaseCommitAccess, BaseCommitAccessKind, BaseCommitAliasAuthority, BaseCommitAliasDiscipline,
    BaseCommitAliasRequirement, BaseCommitAuthorityError, BaseCommitDependencyRange,
    BaseCommitDependencyRole, BaseCommitEffect, BaseCommitExecutionBuffer, BaseCommitExecutionStep,
    BaseCommitInstalledAccess, BaseCommitInvocation, BaseCommitInvocationArgument,
    BaseCommitInvocationValue, BaseCommitKernelArgument, BaseCommitKernelArgumentValue,
    BaseCommitKernelLaunch, BaseCommitLayout, BaseCommitLinkedAuthority, BaseCommitOperation,
    BaseCommitOperationKind, BaseCommitPartitionAuthority, BaseCommitPointerBinding,
    BaseCommitPointerTarget, BaseCommitProgramAuthority, BaseCommitRetainedEvaluation,
    BaseCommitRetainedLayer, BaseCommitValueRole,
};
pub use composition_split::{
    CompositionSplitColumns, CompositionSplitError, CompositionSplitLaunchMode,
    CompositionSplitOracle, CompositionSplitPointerSlots, CompositionSplitProgram,
    CompositionSplitSchedule, CompositionSplitTraffic, PreparedCompositionSplitGraph,
    COMPOSITION_RETAINED_COLUMNS, COMPOSITION_SOURCE_COORDINATES,
};
pub use direct_compact_domain_binding::{
    direct_compact_domain_arena_slot_requirements, DirectCompactDomainBindingError,
    PreparedDirectCompactDomainCommitGraph,
};
pub use direct_compact_terminal_fused::{
    DirectCompactTerminalBatchMode, DirectCompactTerminalBatchReceipt, DirectCompactTerminalError,
    DirectCompactTerminalFallbackReason, DirectCompactTerminalProgram,
    DirectCompactTerminalReceipt, DirectCompactTerminalSupport,
};
pub use direct_retained_b2n::{
    DirectRetainedB2nBatchPlan, DirectRetainedB2nColumn, DirectRetainedB2nError,
    DirectRetainedB2nLaunchKind, DirectRetainedB2nOracle, DirectRetainedB2nProgram,
    PreparedDirectRetainedB2nGraph,
};
pub use direct_terminal_expand_absorb::{
    DirectTerminalExpandAbsorbError, DirectTerminalExpandAbsorbOperation,
    DirectTerminalExpandAbsorbProgram, DirectTerminalExpandAbsorbReceipt,
    DirectTerminalExpandAbsorbTransition,
};
pub use direct_terminal_expand_absorb_binding::{
    direct_terminal_expand_absorb_arena_slot_requirements, PreparedDirectTerminalExpandAbsorbGraph,
};
pub use domain_compact::{
    CompactDomainComparison, CompactDomainOperation, CompactDomainProgram,
    CompactDomainProgramError, CompactDomainStep, CompactDomainTail,
};
pub use domain_compact_binding::{
    compact_domain_arena_slot_requirements, CompactBlake2sTailDescriptor,
    CompactDomainBindingError, CompactDomainPreparedLaunchKind, PreparedCompactDomainCommitGraph,
};
pub use domain_cooperative::{
    DomainCooperativeComparison, DomainCooperativeOperation, DomainCooperativeProgram,
    DomainCooperativeProgramError, DomainCooperativeResourceModel, DomainCooperativeSlabSlice,
    DomainCooperativeStep,
};
pub use domain_cooperative_binding::DomainCooperativeBindingError;
pub use domain_expand_absorb::{
    FusedCompactDomainOperation, FusedCompactDomainProgram, FusedCompactDomainProgramError,
    FusedCompactDomainReceipt, FusedCompactDomainStep, FusedCompactDomainTransition,
};
pub use domain_expand_absorb_binding::{
    fused_compact_domain_arch_supported, fused_compact_domain_arena_slot_requirements,
    fused_compact_domain_materialized_only_admission, FusedCompactDomainBindingError,
    PreparedFusedCompactDomainCommitGraph, FUSED_COMPACT_DOMAIN_MIN_SM_MAJOR,
};
pub use precomputed_compact_domain_binding::PreparedPrecomputedCompactDomainCommitGraph;
pub use program::{
    CommitProgram, CommitProgramError, CommitProgramIdentity, CommitProgramLayer,
    CommitProgramOperation, CommitProgramStep, CommitProgramTraffic,
};
pub use program_binding::{CommitProgramBindingError, PreparedCommitProgramView};
pub use program_oracle::{CommitProgramFixture, CommitProgramOracle, CommitProgramOracleLayer};
pub use shape_wide::{
    ShapeWideColumn, ShapeWideColumnDescriptorAbi, ShapeWideColumnStorage,
    ShapeWideCommitComparison, ShapeWideCommitProgram, ShapeWideCommitProgramError,
    ShapeWideLeafOperation, ShapeWideLeafStep, ShapeWideSlabLayout,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);
const HASH_WORDS: usize = core::mem::size_of::<Blake2sHash>() / WORD_BYTES;
const STATE_WORDS: usize = PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES / WORD_BYTES;
// The 96-byte state extent is a stride, not an alignment. Keep every state row
// 32-byte aligned so the one-slab lane can safely become aligned Blake2sHash
// storage without moving it; 96 is an exact multiple of 32.
const STATE_ALIGNMENT_WORDS: usize = COMMIT_HASH_ALIGNMENT_WORDS;
const _: () = assert!(STATE_ALIGNMENT_WORDS.is_power_of_two());
const _: () = assert!(STATE_WORDS % STATE_ALIGNMENT_WORDS == 0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressiveBatchRequirements {
    pub coefficient_pointer_words: usize,
    pub coefficient_size_words: usize,
    pub output_pointer_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveLeafWorkspaceRequirements {
    pub plan: ProgressiveCommitPlan,
    pub twiddle_words: usize,
    pub lde_scratch_words: Option<usize>,
    pub state_ping_words: usize,
    pub state_pong_words: Option<usize>,
    pub leaf_hash_words: usize,
    pub batches: Vec<ProgressiveBatchRequirements>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressiveBatchSlots {
    pub coefficient_ptrs: ArenaSlotId,
    pub coefficient_sizes: ArenaSlotId,
    pub output_ptrs: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveLeafWorkspaceSlots {
    pub lde_scratch: Option<ArenaSlotId>,
    pub state_ping: ArenaSlotId,
    pub state_pong: Option<ArenaSlotId>,
    pub leaf_hashes: ArenaSlotId,
    pub batches: Vec<ProgressiveBatchSlots>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveCommitWorkspaceRequirements {
    pub leaves: ProgressiveLeafWorkspaceRequirements,
    pub merkle: MerkleFromLeavesRequirements,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveCommitWorkspaceSlots {
    pub leaves: ProgressiveLeafWorkspaceSlots,
    pub merkle: MerkleFromLeavesSlots,
}

/// Mode-tagged workspace shapes for later production dispatch. Each variant
/// owns exactly one leaf layout; no fake group and no dual allocation exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModeAwareCommitWorkspaceRequirements {
    FullLifting(CommitWorkspaceRequirements),
    DomainProgressive(ProgressiveCommitWorkspaceRequirements),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModeAwareCommitWorkspaceSlots {
    FullLifting(CommitWorkspaceSlots),
    DomainProgressive(ProgressiveCommitWorkspaceSlots),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressiveLeafLaunchKind {
    Init {
        log_size: u32,
    },
    Expand {
        from_log_size: u32,
        to_log_size: u32,
    },
    ExpandInPlace {
        from_log_size: u32,
        to_log_size: u32,
    },
    Lde {
        batch_index: u32,
        segment_offset: u32,
        log_size: u32,
        columns: u32,
    },
    Absorb {
        batch_index: u32,
        segment_offset: u32,
        log_size: u32,
        columns: u32,
        absorbed_columns_before: u32,
    },
    DomainAbsorb {
        batch_index: u32,
        log_size: u32,
        columns: u32,
        absorbed_columns_before: u32,
        initializes_state: bool,
    },
    FusedLdeAbsorb {
        batch_index: u32,
        segment_offset: u32,
        log_size: u32,
        columns: u32,
        absorbed_columns_before: u32,
        retained_write_mask: u32,
    },
    Finalize {
        log_size: u32,
        absorbed_columns: u32,
    },
    FinalizeInPlace {
        log_size: u32,
        absorbed_columns: u32,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProgressiveCommitStorageMode {
    #[default]
    Separate = 0,
    InPlaceSlab = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedProgressiveCommitError {
    Disabled,
    Planner(ProgressiveCommitError),
    InvalidSlotShape,
    SizeOverflow,
    ContextMismatch(ArenaSlotId),
    MissingRetainedOutput(usize),
    UnexpectedRetainedOutput(usize),
    GeometryMismatch,
    SlotTooSmall {
        slot: ArenaSlotId,
        required: usize,
        actual: usize,
    },
    AliasedSlot(ArenaSlotId),
    Arena(super::exec_context::ArenaError),
    Prepared(super::prepared_commit::PreparedCommitError),
    Cuda(super::exec_context::CudaRuntimeError),
}

pub fn progressive_commit_workspace_requirements_for_mode(
    mode: ProgressiveCommitMode,
    config: CommitWorkspaceConfig,
    geometry: ProgressiveCommitGeometry,
) -> Result<ProgressiveCommitWorkspaceRequirements, PreparedProgressiveCommitError> {
    if geometry.lifting_log_size != config.lifting_log_size
        || geometry.log_blowup_factor != config.log_blowup_factor
    {
        return Err(PreparedProgressiveCommitError::GeometryMismatch);
    }
    Ok(ProgressiveCommitWorkspaceRequirements {
        leaves: progressive_leaf_workspace_requirements_for_mode(mode, geometry)?,
        merkle: merkle_from_leaves_requirements(config)?,
    })
}

impl ProgressiveCommitWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &ProgressiveCommitWorkspaceSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedProgressiveCommitError> {
        if slots.leaves.leaf_hashes != slots.merkle.leaves {
            return Err(PreparedProgressiveCommitError::GeometryMismatch);
        }
        let mut output = self.leaves.arena_slot_requirements(&slots.leaves)?;
        let merkle = self.merkle.arena_slot_requirements(&slots.merkle)?;
        let mut ids = output.iter().map(|entry| entry.id).collect::<BTreeSet<_>>();
        for entry in merkle {
            if entry.id == slots.merkle.leaves {
                let leaf = output
                    .iter()
                    .find(|candidate| candidate.id == entry.id)
                    .ok_or(PreparedProgressiveCommitError::GeometryMismatch)?;
                if leaf.len_words != entry.len_words {
                    return Err(PreparedProgressiveCommitError::GeometryMismatch);
                }
                continue;
            }
            if !ids.insert(entry.id) {
                return Err(PreparedProgressiveCommitError::AliasedSlot(entry.id));
            }
            output.push(entry);
        }
        Ok(output)
    }
}

impl ModeAwareCommitWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &ModeAwareCommitWorkspaceSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedProgressiveCommitError> {
        match (self, slots) {
            (
                Self::FullLifting(requirements),
                ModeAwareCommitWorkspaceSlots::FullLifting(slots),
            ) => Ok(requirements.arena_slot_requirements(slots)?),
            (
                Self::DomainProgressive(requirements),
                ModeAwareCommitWorkspaceSlots::DomainProgressive(slots),
            ) => requirements.arena_slot_requirements(slots),
            _ => Err(PreparedProgressiveCommitError::GeometryMismatch),
        }
    }
}

impl core::fmt::Display for PreparedProgressiveCommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared progressive CUDA commitment: {self:?}")
    }
}

impl std::error::Error for PreparedProgressiveCommitError {}

impl From<ProgressiveCommitError> for PreparedProgressiveCommitError {
    fn from(value: ProgressiveCommitError) -> Self {
        Self::Planner(value)
    }
}
impl From<super::exec_context::ArenaError> for PreparedProgressiveCommitError {
    fn from(value: super::exec_context::ArenaError) -> Self {
        Self::Arena(value)
    }
}
impl From<super::exec_context::CudaRuntimeError> for PreparedProgressiveCommitError {
    fn from(value: super::exec_context::CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}
impl From<super::prepared_commit::PreparedCommitError> for PreparedProgressiveCommitError {
    fn from(value: super::prepared_commit::PreparedCommitError) -> Self {
        Self::Prepared(value)
    }
}

/// Seal the environment-selected mode and complete topology before allocating
/// any arena storage.  The default (`FullLifting`) fails closed: callers must
/// continue through the legacy prepared commitment, never silently reinterpret
/// progressive slots as a fallback layout.
pub fn progressive_leaf_workspace_requirements(
    geometry: ProgressiveCommitGeometry,
) -> Result<ProgressiveLeafWorkspaceRequirements, PreparedProgressiveCommitError> {
    let mode = ProgressiveCommitMode::from_env();
    if mode != ProgressiveCommitMode::DomainProgressive {
        return Err(PreparedProgressiveCommitError::Disabled);
    }
    progressive_leaf_workspace_requirements_for_mode(mode, geometry)
}

/// Explicit-mode twin used by topology tests and process-level mode dispatch.
pub fn progressive_leaf_workspace_requirements_for_mode(
    mode: ProgressiveCommitMode,
    geometry: ProgressiveCommitGeometry,
) -> Result<ProgressiveLeafWorkspaceRequirements, PreparedProgressiveCommitError> {
    if mode != ProgressiveCommitMode::DomainProgressive {
        return Err(PreparedProgressiveCommitError::Disabled);
    }
    let plan = plan_progressive_commit(mode, geometry)?;
    let twiddle_words = plan
        .columns
        .iter()
        .map(|column| pow2(column.evaluation_log_size - 1))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    let lde_scratch_words = plan
        .lde_batches
        .iter()
        .map(|batch| {
            let words = pow2(batch.evaluation_log_size)?;
            batch
                .retained_columns
                .iter()
                .filter(|destination| destination.is_none())
                .count()
                .checked_mul(words)
                .ok_or(PreparedProgressiveCommitError::SizeOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .filter(|words| *words != 0);

    let first_log = plan.columns[0].evaluation_log_size;
    let mut ping_words = state_words(first_log)?;
    let mut pong_words = 0usize;
    let mut current_is_ping = true;
    for expansion in &plan.state_expansions {
        let destination_words = state_words(expansion.domain.to_log_size)?;
        if current_is_ping {
            pong_words = pong_words.max(destination_words);
        } else {
            ping_words = ping_words.max(destination_words);
        }
        current_is_ping = !current_is_ping;
    }
    let leaf_hash_words = pow2(plan.geometry.lifting_log_size)?
        .checked_mul(HASH_WORDS)
        .ok_or(PreparedProgressiveCommitError::SizeOverflow)?;
    let batches = plan
        .lde_batches
        .iter()
        .map(|batch| ProgressiveBatchRequirements {
            coefficient_pointer_words: batch.columns.len() * POINTER_WORDS,
            coefficient_size_words: batch.columns.len(),
            output_pointer_words: batch.columns.len() * POINTER_WORDS,
        })
        .collect();
    Ok(ProgressiveLeafWorkspaceRequirements {
        plan,
        twiddle_words,
        lde_scratch_words,
        state_ping_words: ping_words,
        state_pong_words: (pong_words != 0).then_some(pong_words),
        leaf_hash_words,
        batches,
    })
}

/// Shared fail-closed admission used as the first step of preparation. This is
/// public so a process can prove its default-off posture before CUDA resources
/// exist; it does not allocate, launch, or select a fallback implementation.
pub fn progressive_prepare_mode_admission(
    requirements: &ProgressiveLeafWorkspaceRequirements,
) -> Result<(), PreparedProgressiveCommitError> {
    progressive_prepare_mode_admission_for_mode(ProgressiveCommitMode::from_env(), requirements)
}

/// Explicit-mode admission for a process-level dispatcher. This path never
/// consults the environment and rejects a mode/topology mismatch.
pub fn progressive_prepare_mode_admission_for_mode(
    mode: ProgressiveCommitMode,
    requirements: &ProgressiveLeafWorkspaceRequirements,
) -> Result<(), PreparedProgressiveCommitError> {
    if mode != ProgressiveCommitMode::DomainProgressive || requirements.plan.mode != mode {
        return Err(PreparedProgressiveCommitError::Disabled);
    }
    validate_progressive_requirements(requirements)?;
    Ok(())
}

fn validate_progressive_requirements(
    requirements: &ProgressiveLeafWorkspaceRequirements,
) -> Result<(), PreparedProgressiveCommitError> {
    validate_progressive_plan(&requirements.plan)?;
    let expected = progressive_leaf_workspace_requirements_for_mode(
        requirements.plan.mode,
        requirements.plan.geometry.clone(),
    )?;
    if *requirements != expected {
        return Err(PreparedProgressiveCommitError::InvalidSlotShape);
    }
    Ok(())
}

impl ProgressiveLeafWorkspaceRequirements {
    pub fn cache_key(&self) -> u64 {
        self.plan.cache_key
    }

    pub fn arena_slot_requirements(
        &self,
        slots: &ProgressiveLeafWorkspaceSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedProgressiveCommitError> {
        validate_slots(self, slots)?;
        let mut output = Vec::new();
        if let (Some(id), Some(len_words)) = (slots.lde_scratch, self.lde_scratch_words) {
            output.push(slot_requirement(id, len_words, 1));
        }
        output.push(slot_requirement(
            slots.state_ping,
            self.state_ping_words,
            STATE_ALIGNMENT_WORDS,
        ));
        if let (Some(id), Some(len_words)) = (slots.state_pong, self.state_pong_words) {
            output.push(slot_requirement(id, len_words, STATE_ALIGNMENT_WORDS));
        }
        output.push(slot_requirement(
            slots.leaf_hashes,
            self.leaf_hash_words,
            HASH_WORDS,
        ));
        for (batch, batch_slots) in self.batches.iter().zip(&slots.batches) {
            output.push(slot_requirement(
                batch_slots.coefficient_ptrs,
                batch.coefficient_pointer_words,
                POINTER_WORDS,
            ));
            output.push(slot_requirement(
                batch_slots.coefficient_sizes,
                batch.coefficient_size_words,
                1,
            ));
            output.push(slot_requirement(
                batch_slots.output_ptrs,
                batch.output_pointer_words,
                POINTER_WORDS,
            ));
        }
        let mut distinct = BTreeSet::new();
        for entry in &output {
            if !distinct.insert(entry.id) {
                return Err(PreparedProgressiveCommitError::AliasedSlot(entry.id));
            }
        }
        Ok(output)
    }

    /// Address-free launch topology used by arena planning and cache admission.
    pub fn launch_sequence(&self) -> Vec<ProgressiveLeafLaunchKind> {
        let first_log = self.plan.columns[0].evaluation_log_size;
        let mut current_log = first_log;
        let mut absorbed_columns = 0u32;
        let mut launches = vec![ProgressiveLeafLaunchKind::Init {
            log_size: first_log,
        }];
        for (batch_index, batch) in self.plan.lde_batches.iter().enumerate() {
            if batch.evaluation_log_size > current_log {
                launches.push(ProgressiveLeafLaunchKind::Expand {
                    from_log_size: current_log,
                    to_log_size: batch.evaluation_log_size,
                });
                current_log = batch.evaluation_log_size;
            }
            let columns =
                u32::try_from(batch.columns.len()).expect("planner column count fits u32");
            let batch_index = u32::try_from(batch_index).expect("planner batch count fits u32");
            launches.push(ProgressiveLeafLaunchKind::Lde {
                batch_index,
                segment_offset: 0,
                log_size: current_log,
                columns,
            });
            launches.push(ProgressiveLeafLaunchKind::Absorb {
                batch_index,
                segment_offset: 0,
                log_size: current_log,
                columns,
                absorbed_columns_before: absorbed_columns,
            });
            absorbed_columns = absorbed_columns
                .checked_add(columns)
                .expect("planner column count fits u32");
        }
        if current_log < self.plan.geometry.lifting_log_size {
            launches.push(ProgressiveLeafLaunchKind::Expand {
                from_log_size: current_log,
                to_log_size: self.plan.geometry.lifting_log_size,
            });
        }
        launches.push(ProgressiveLeafLaunchKind::Finalize {
            log_size: self.plan.geometry.lifting_log_size,
            absorbed_columns,
        });
        launches
    }
}

#[derive(Clone, Copy)]
struct PreparedBatch {
    coefficient_ptrs: ArenaSlice,
    coefficient_sizes: ArenaSlice,
    output_ptrs: ArenaSlice,
    batch_index: u32,
    segment_offset: u32,
    log_size: u32,
    columns: u32,
    absorbed_columns_before: u32,
}

impl PreparedBatch {
    fn checked_subbatch(
        self,
        offset: usize,
        columns: usize,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        let pointer_offset = offset
            .checked_mul(POINTER_WORDS)
            .ok_or(PreparedProgressiveCommitError::SizeOverflow)?;
        let pointer_words = columns
            .checked_mul(POINTER_WORDS)
            .ok_or(PreparedProgressiveCommitError::SizeOverflow)?;
        Ok(Self {
            coefficient_ptrs: self
                .coefficient_ptrs
                .checked_subslice(pointer_offset, pointer_words)?,
            coefficient_sizes: self.coefficient_sizes.checked_subslice(offset, columns)?,
            output_ptrs: self
                .output_ptrs
                .checked_subslice(pointer_offset, pointer_words)?,
            batch_index: self.batch_index,
            segment_offset: self
                .segment_offset
                .checked_add(
                    u32::try_from(offset)
                        .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?,
                )
                .ok_or(PreparedProgressiveCommitError::SizeOverflow)?,
            log_size: self.log_size,
            columns: u32::try_from(columns)
                .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?,
            absorbed_columns_before: self
                .absorbed_columns_before
                .checked_add(
                    u32::try_from(offset)
                        .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?,
                )
                .ok_or(PreparedProgressiveCommitError::SizeOverflow)?,
        })
    }
}

struct PreparedProgressiveInputs {
    batches: Vec<(PreparedBatch, Vec<ProgressiveLdeSegment>)>,
    uploads: Vec<(ArenaSlice, HostDescriptor)>,
    twiddle_words: u32,
    fusion_telemetry: ProgressiveNttLeafFusionTelemetry,
    absorbed_columns: u32,
}

#[allow(clippy::too_many_arguments)]
fn prepare_progressive_inputs(
    arena: &DeviceArena,
    requirements: &ProgressiveLeafWorkspaceRequirements,
    slots: &ProgressiveLeafWorkspaceSlots,
    coefficients: &[CommitCoefficientColumn],
    retained_outputs: &[Option<ArenaSlice>],
    twiddles: ArenaSlice,
    ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
    workspace_ids: &BTreeSet<ArenaSlotId>,
) -> Result<PreparedProgressiveInputs, PreparedProgressiveCommitError> {
    if coefficients.len() != requirements.plan.columns.len()
        || retained_outputs.len() != requirements.plan.columns.len()
    {
        return Err(PreparedProgressiveCommitError::InvalidSlotShape);
    }
    let token = arena.context().identity_token();
    if twiddles.context_token() != token {
        return Err(PreparedProgressiveCommitError::ContextMismatch(
            twiddles.id(),
        ));
    }
    if workspace_ids.contains(&twiddles.id()) {
        return Err(PreparedProgressiveCommitError::AliasedSlot(twiddles.id()));
    }
    if twiddles.len_words() < requirements.twiddle_words {
        return Err(PreparedProgressiveCommitError::SlotTooSmall {
            slot: twiddles.id(),
            required: requirements.twiddle_words,
            actual: twiddles.len_words(),
        });
    }
    let twiddle_words = u32::try_from(twiddles.len_words())
        .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?;
    let scratch = match (slots.lde_scratch, requirements.lde_scratch_words) {
        (Some(id), Some(words)) => Some(bind_slot(arena, id, words, 1)?),
        (None, None) => None,
        _ => return Err(PreparedProgressiveCommitError::InvalidSlotShape),
    };

    let mut uploads = Vec::new();
    let mut external_ids = BTreeSet::from([twiddles.id()]);
    let mut batches = Vec::with_capacity(requirements.batches.len());
    let mut fusion_telemetry = ProgressiveNttLeafFusionTelemetry::default();
    let mut absorbed_columns = 0u32;
    for (batch_index, ((batch, batch_requirement), batch_slots)) in requirements
        .plan
        .lde_batches
        .iter()
        .zip(&requirements.batches)
        .zip(&slots.batches)
        .enumerate()
    {
        let coefficient_ptrs = bind_slot(
            arena,
            batch_slots.coefficient_ptrs,
            batch_requirement.coefficient_pointer_words,
            POINTER_WORDS,
        )?;
        let coefficient_sizes = bind_slot(
            arena,
            batch_slots.coefficient_sizes,
            batch_requirement.coefficient_size_words,
            1,
        )?;
        let output_ptrs = bind_slot(
            arena,
            batch_slots.output_ptrs,
            batch_requirement.output_pointer_words,
            POINTER_WORDS,
        )?;
        let evaluation_words = pow2(batch.evaluation_log_size)?;
        let mut scratch_offset = 0usize;
        let mut coefficient_addresses = Vec::with_capacity(batch.columns.len());
        let mut coefficient_lengths = Vec::with_capacity(batch.columns.len());
        let mut output_addresses = Vec::with_capacity(batch.columns.len());
        for (&canonical, retained_destination) in batch.columns.iter().zip(&batch.retained_columns)
        {
            let coefficient = coefficients[canonical];
            let column = requirements.plan.columns[canonical];
            if coefficient.log_size != column.coefficient_log_size
                || coefficient.coefficients.context_token() != token
            {
                return Err(PreparedProgressiveCommitError::ContextMismatch(
                    coefficient.coefficients.id(),
                ));
            }
            if workspace_ids.contains(&coefficient.coefficients.id())
                || !external_ids.insert(coefficient.coefficients.id())
            {
                return Err(PreparedProgressiveCommitError::AliasedSlot(
                    coefficient.coefficients.id(),
                ));
            }
            let coefficient_words = pow2(column.coefficient_log_size)?;
            if coefficient.coefficients.len_words() < coefficient_words {
                return Err(PreparedProgressiveCommitError::SlotTooSmall {
                    slot: coefficient.coefficients.id(),
                    required: coefficient_words,
                    actual: coefficient.coefficients.len_words(),
                });
            }
            coefficient_addresses.push(coefficient.coefficients.as_u32_ptr() as usize);
            coefficient_lengths.push(
                u32::try_from(coefficient_words)
                    .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?,
            );
            let output = match (*retained_destination, retained_outputs[canonical]) {
                (Some(_), Some(output)) => {
                    if output.context_token() != token {
                        return Err(PreparedProgressiveCommitError::ContextMismatch(output.id()));
                    }
                    if output.len_words() < evaluation_words {
                        return Err(PreparedProgressiveCommitError::SlotTooSmall {
                            slot: output.id(),
                            required: evaluation_words,
                            actual: output.len_words(),
                        });
                    }
                    if workspace_ids.contains(&output.id()) || !external_ids.insert(output.id()) {
                        return Err(PreparedProgressiveCommitError::AliasedSlot(output.id()));
                    }
                    output.as_u32_ptr()
                }
                (Some(_), None) => {
                    return Err(PreparedProgressiveCommitError::MissingRetainedOutput(
                        canonical,
                    ));
                }
                (None, Some(_)) => {
                    return Err(PreparedProgressiveCommitError::UnexpectedRetainedOutput(
                        canonical,
                    ));
                }
                (None, None) => {
                    let base = scratch.ok_or(PreparedProgressiveCommitError::InvalidSlotShape)?;
                    let next_offset = scratch_offset
                        .checked_add(evaluation_words)
                        .ok_or(PreparedProgressiveCommitError::SizeOverflow)?;
                    if next_offset > base.len_words() {
                        return Err(PreparedProgressiveCommitError::SlotTooSmall {
                            slot: base.id(),
                            required: next_offset,
                            actual: base.len_words(),
                        });
                    }
                    let pointer = unsafe { base.as_u32_ptr().add(scratch_offset) };
                    scratch_offset = next_offset;
                    pointer
                }
            };
            output_addresses.push(output as usize);
        }
        uploads.push((
            coefficient_ptrs,
            HostDescriptor::Pointers(coefficient_addresses),
        ));
        uploads.push((coefficient_sizes, HostDescriptor::U32(coefficient_lengths)));
        uploads.push((output_ptrs, HostDescriptor::Pointers(output_addresses)));
        let (segments, batch_telemetry) = progressive_lde_segments(batch, ntt_leaf_fusion)?;
        fusion_telemetry = fusion_telemetry.checked_add(batch_telemetry)?;
        batches.push((
            PreparedBatch {
                coefficient_ptrs,
                coefficient_sizes,
                output_ptrs,
                batch_index: u32::try_from(batch_index)
                    .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?,
                segment_offset: 0,
                log_size: batch.evaluation_log_size,
                columns: u32::try_from(batch.columns.len())
                    .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?,
                absorbed_columns_before: absorbed_columns,
            },
            segments,
        ));
        absorbed_columns = absorbed_columns
            .checked_add(
                u32::try_from(batch.columns.len())
                    .map_err(|_| PreparedProgressiveCommitError::SizeOverflow)?,
            )
            .ok_or(PreparedProgressiveCommitError::SizeOverflow)?;
    }
    Ok(PreparedProgressiveInputs {
        batches,
        uploads,
        twiddle_words,
        fusion_telemetry,
        absorbed_columns,
    })
}

#[derive(Clone, Copy)]
enum Launch {
    Init {
        log_size: u32,
        states: ArenaSlice,
    },
    Expand {
        from_log: u32,
        to_log: u32,
        input: ArenaSlice,
        output: ArenaSlice,
    },
    ExpandInPlace {
        from_log: u32,
        to_log: u32,
        states: ArenaSlice,
        scratch_pair: ArenaSlice,
    },
    Lde(PreparedBatch),
    Absorb {
        log_size: u32,
        batch: PreparedBatch,
        states: ArenaSlice,
    },
    DomainAbsorb {
        log_size: u32,
        batch: PreparedBatch,
        initializes_state: bool,
        states: ArenaSlice,
    },
    FusedLdeAbsorb {
        batch: PreparedBatch,
        retained_write_mask: u32,
        states: ArenaSlice,
    },
    Finalize {
        log_size: u32,
        absorbed_columns: u32,
        states: ArenaSlice,
        output: ArenaSlice,
    },
    FinalizeInPlace {
        log_size: u32,
        absorbed_columns: u32,
        states_and_hashes: ArenaSlice,
        scratch_pair: ArenaSlice,
    },
}

pub struct PreparedProgressiveLeaves<'a> {
    arena: &'a DeviceArena,
    launches: Vec<Launch>,
    leaf_hashes: ArenaSlice,
    twiddles: ArenaSlice,
    twiddle_words: u32,
    cache_key: u64,
    storage: ProgressiveCommitStorageMode,
    in_place_scratch: Option<ArenaSlice>,
    ntt_leaf_fusion: ProgressiveNttLeafFusionTelemetry,
}

impl<'a> PreparedProgressiveLeaves<'a> {
    /// Bind a pre-sealed topology, upload all descriptor tables, and drain setup
    /// once. `retained_outputs` is in canonical column order and must be `Some`
    /// exactly where the sealed geometry says the evaluation remains resident.
    pub fn prepare(
        arena: &'a DeviceArena,
        requirements: &ProgressiveLeafWorkspaceRequirements,
        slots: &ProgressiveLeafWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_with_mode(
            arena,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            ProgressiveCommitMode::from_env(),
        )
    }

    /// Bind an explicitly selected progressive topology without consulting
    /// the environment. Admission remains fail-closed on mode mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_mode(
        arena: &'a DeviceArena,
        requirements: &ProgressiveLeafWorkspaceRequirements,
        slots: &ProgressiveLeafWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        mode: ProgressiveCommitMode,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_with_mode_and_ntt_fusion(
            arena,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            mode,
            ProgressiveNttLeafFusionMode::Separate,
        )
    }

    /// Bind an explicitly selected progressive topology and final-NTT sink.
    /// Fusion is sealed into the prepared launch vector; no launch-time ambient
    /// state can change eager or captured topology.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_mode_and_ntt_fusion(
        arena: &'a DeviceArena,
        requirements: &ProgressiveLeafWorkspaceRequirements,
        slots: &ProgressiveLeafWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        mode: ProgressiveCommitMode,
        ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_impl(
            arena,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            mode,
            ntt_leaf_fusion,
            ProgressiveCommitStorageMode::Separate,
        )
    }

    /// Dormant single-slab twin. Callers must seal this storage mode into the
    /// protocol identity before constructing the aliased slot tuple.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_in_place_slab_with_mode_and_ntt_fusion(
        arena: &'a DeviceArena,
        requirements: &ProgressiveLeafWorkspaceRequirements,
        slots: &ProgressiveLeafWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        mode: ProgressiveCommitMode,
        ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_impl(
            arena,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            mode,
            ntt_leaf_fusion,
            ProgressiveCommitStorageMode::InPlaceSlab,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_impl(
        arena: &'a DeviceArena,
        requirements: &ProgressiveLeafWorkspaceRequirements,
        slots: &ProgressiveLeafWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        mode: ProgressiveCommitMode,
        ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
        storage: ProgressiveCommitStorageMode,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        progressive_prepare_mode_admission_for_mode(mode, requirements)?;
        let workspace = match storage {
            ProgressiveCommitStorageMode::Separate => requirements.arena_slot_requirements(slots),
            ProgressiveCommitStorageMode::InPlaceSlab => {
                requirements.arena_slot_requirements_in_place(slots)
            }
        }?;
        let workspace_ids: BTreeSet<_> = workspace.iter().map(|entry| entry.id).collect();
        let (ping, pong, leaf_hashes, in_place_scratch) = match storage {
            ProgressiveCommitStorageMode::Separate => {
                let ping = bind_slot(
                    arena,
                    slots.state_ping,
                    requirements.state_ping_words,
                    STATE_ALIGNMENT_WORDS,
                )?;
                let pong = match (slots.state_pong, requirements.state_pong_words) {
                    (Some(id), Some(words)) => {
                        Some(bind_slot(arena, id, words, STATE_ALIGNMENT_WORDS)?)
                    }
                    (None, None) => None,
                    _ => return Err(PreparedProgressiveCommitError::InvalidSlotShape),
                };
                let leaf_hashes = bind_slot(
                    arena,
                    slots.leaf_hashes,
                    requirements.leaf_hash_words,
                    HASH_WORDS,
                )?;
                (ping, pong, leaf_hashes, None)
            }
            ProgressiveCommitStorageMode::InPlaceSlab => {
                let slab_words = requirements.in_place_slab_words()?;
                let slab = bind_slot(arena, slots.state_ping, slab_words, STATE_ALIGNMENT_WORDS)?;
                let scratch_offset = slab_words
                    .checked_sub(
                        super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
                    )
                    .ok_or(PreparedProgressiveCommitError::SizeOverflow)?;
                let scratch_pair = slab.checked_subslice(
                    scratch_offset,
                    super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
                )?;
                let leaf_hashes = slab.checked_subslice(0, requirements.leaf_hash_words)?;
                (
                    slab,
                    requirements.state_pong_words.map(|_| slab),
                    leaf_hashes,
                    Some(scratch_pair),
                )
            }
        };
        let PreparedProgressiveInputs {
            batches: prepared_batches,
            uploads,
            twiddle_words,
            fusion_telemetry,
            absorbed_columns,
        } = prepare_progressive_inputs(
            arena,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            ntt_leaf_fusion,
            &workspace_ids,
        )?;

        let mut launches = Vec::new();
        let first_log = requirements.plan.columns[0].evaluation_log_size;
        let mut current_log = first_log;
        let mut current = ping;
        let mut next = pong;
        let mut fused_log_sizes = BTreeSet::new();
        launches.push(Launch::Init {
            log_size: first_log,
            states: current,
        });
        for (batch, segments) in prepared_batches {
            if batch.log_size > current_log {
                match storage {
                    ProgressiveCommitStorageMode::Separate => {
                        let output =
                            next.ok_or(PreparedProgressiveCommitError::InvalidSlotShape)?;
                        launches.push(Launch::Expand {
                            from_log: current_log,
                            to_log: batch.log_size,
                            input: current,
                            output,
                        });
                        next = Some(current);
                        current = output;
                    }
                    ProgressiveCommitStorageMode::InPlaceSlab => {
                        launches.push(Launch::ExpandInPlace {
                            from_log: current_log,
                            to_log: batch.log_size,
                            states: current,
                            scratch_pair: in_place_scratch
                                .ok_or(PreparedProgressiveCommitError::InvalidSlotShape)?,
                        });
                    }
                }
                current_log = batch.log_size;
            }
            for segment in segments {
                let subbatch = batch.checked_subbatch(segment.offset, segment.columns)?;
                match segment.kind {
                    ProgressiveLdeSegmentKind::Separate => {
                        launches.push(Launch::Lde(subbatch));
                        launches.push(Launch::Absorb {
                            log_size: current_log,
                            batch: subbatch,
                            states: current,
                        });
                    }
                    ProgressiveLdeSegmentKind::Fused16 {
                        retained_write_mask,
                    } => {
                        fused_log_sizes.insert(subbatch.log_size);
                        launches.push(Launch::FusedLdeAbsorb {
                            batch: subbatch,
                            retained_write_mask,
                            states: current,
                        });
                    }
                }
            }
        }
        if current_log < requirements.plan.geometry.lifting_log_size {
            match storage {
                ProgressiveCommitStorageMode::Separate => {
                    let output = next.ok_or(PreparedProgressiveCommitError::InvalidSlotShape)?;
                    launches.push(Launch::Expand {
                        from_log: current_log,
                        to_log: requirements.plan.geometry.lifting_log_size,
                        input: current,
                        output,
                    });
                    current = output;
                }
                ProgressiveCommitStorageMode::InPlaceSlab => {
                    launches.push(Launch::ExpandInPlace {
                        from_log: current_log,
                        to_log: requirements.plan.geometry.lifting_log_size,
                        states: current,
                        scratch_pair: in_place_scratch
                            .ok_or(PreparedProgressiveCommitError::InvalidSlotShape)?,
                    });
                }
            }
        }
        match storage {
            ProgressiveCommitStorageMode::Separate => launches.push(Launch::Finalize {
                log_size: requirements.plan.geometry.lifting_log_size,
                absorbed_columns,
                states: current,
                output: leaf_hashes,
            }),
            ProgressiveCommitStorageMode::InPlaceSlab => launches.push(Launch::FinalizeInPlace {
                log_size: requirements.plan.geometry.lifting_log_size,
                absorbed_columns,
                states_and_hashes: current,
                scratch_pair: in_place_scratch
                    .ok_or(PreparedProgressiveCommitError::InvalidSlotShape)?,
            }),
        }

        // Dynamic shared-memory admission is setup-only and occurs before any
        // capture. Unsupported devices reject the selected topology here.
        for log_size in fused_log_sizes {
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_ntt_progressive_leaf_fused_configure(log_size)
            };
            check_cuda("progressive_ntt_leaf_fused_configure", code)?;
        }

        for (destination, descriptor) in &uploads {
            let (source, bytes) = descriptor.bytes();
            unsafe {
                arena
                    .context()
                    .memcpy_h2d_async(destination.as_void_ptr(), source, bytes)?;
            }
        }
        arena.context().sync()?;
        Ok(Self {
            arena,
            launches,
            leaf_hashes,
            twiddles,
            twiddle_words,
            cache_key: match storage {
                ProgressiveCommitStorageMode::Separate => requirements.plan.cache_key,
                ProgressiveCommitStorageMode::InPlaceSlab => {
                    super::progressive_commit_in_place::progressive_in_place_cache_key(
                        requirements.plan.cache_key,
                    )
                }
            },
            storage,
            in_place_scratch,
            ntt_leaf_fusion: fusion_telemetry,
        })
    }

    pub fn launch(&self) -> Result<(), PreparedProgressiveCommitError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        for launch in &self.launches {
            let (operation, code) = unsafe {
                match *launch {
                    Launch::Init { log_size, states } => (
                        "progressive_leaf_init",
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_init_on(
                            1u32 << log_size,
                            states.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    Launch::Expand {
                        from_log,
                        to_log,
                        input,
                        output,
                    } => (
                        "progressive_leaf_expand",
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_expand_on(
                            from_log,
                            to_log,
                            input.as_u32_ptr().cast(),
                            output.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    Launch::ExpandInPlace {
                        from_log,
                        to_log,
                        states,
                        scratch_pair,
                    } => (
                        "progressive_leaf_expand_in_place",
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_expand_in_place_on(
                            from_log,
                            to_log,
                            states.as_u32_ptr().cast(),
                            scratch_pair.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    Launch::Lde(batch) => (
                        "progressive_lde_n2b",
                        stwo_backend_cuda_kernels::raw::stwo_lde_n2b_columns_on(
                            batch.coefficient_ptrs.as_u32_ptr().cast(),
                            batch.coefficient_sizes.as_u32_ptr(),
                            batch.output_ptrs.as_u32_ptr().cast(),
                            batch.log_size,
                            batch.columns,
                            self.twiddles.as_u32_ptr(),
                            self.twiddle_words,
                            1u32 << (batch.log_size - 1),
                            stream,
                        ),
                    ),
                    Launch::Absorb {
                        log_size,
                        batch,
                        states,
                    } => (
                        "progressive_leaf_absorb",
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_absorb_on(
                            1u32 << log_size,
                            batch.columns,
                            batch.absorbed_columns_before,
                            batch.output_ptrs.as_u32_ptr().cast(),
                            states.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    Launch::DomainAbsorb {
                        log_size,
                        batch,
                        initializes_state,
                        states,
                    } => {
                        if log_size >= 31 {
                            return Err(PreparedProgressiveCommitError::SizeOverflow);
                        }
                        (
                            "progressive_leaf_absorb_quad",
                            stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_absorb_quad_on(
                                1u32 << log_size,
                                batch.columns,
                                batch.absorbed_columns_before,
                                batch.output_ptrs.as_u32_ptr().cast(),
                                u32::from(initializes_state),
                                states.as_u32_ptr().cast(),
                                stream,
                            ),
                        )
                    }
                    Launch::FusedLdeAbsorb {
                        batch,
                        retained_write_mask,
                        states,
                    } => (
                        "progressive_ntt_leaf_fused",
                        stwo_backend_cuda_kernels::raw::stwo_ntt_progressive_leaf_fused_on(
                            batch.coefficient_ptrs.as_u32_ptr().cast(),
                            batch.coefficient_sizes.as_u32_ptr(),
                            batch.output_ptrs.as_u32_ptr().cast(),
                            batch.log_size,
                            self.twiddles.as_u32_ptr(),
                            self.twiddle_words,
                            1u32 << (batch.log_size - 1),
                            batch.absorbed_columns_before,
                            retained_write_mask,
                            states.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    Launch::Finalize {
                        log_size,
                        absorbed_columns,
                        states,
                        output,
                    } => (
                        "progressive_leaf_finalize",
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_finalize_on(
                            1u32 << log_size,
                            absorbed_columns,
                            states.as_u32_ptr().cast(),
                            output.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    Launch::FinalizeInPlace {
                        log_size,
                        absorbed_columns,
                        states_and_hashes,
                        scratch_pair,
                    } => (
                        "progressive_leaf_finalize_in_place",
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_finalize_in_place_on(
                            1u32 << log_size,
                            absorbed_columns,
                            states_and_hashes.as_u32_ptr().cast(),
                            scratch_pair.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                }
            };
            check_cuda(operation, code)?;
        }
        Ok(())
    }

    pub fn launch_sequence(&self) -> impl ExactSizeIterator<Item = ProgressiveLeafLaunchKind> + '_ {
        self.launches.iter().map(|launch| match *launch {
            Launch::Init { log_size, .. } => ProgressiveLeafLaunchKind::Init { log_size },
            Launch::Expand {
                from_log, to_log, ..
            } => ProgressiveLeafLaunchKind::Expand {
                from_log_size: from_log,
                to_log_size: to_log,
            },
            Launch::ExpandInPlace {
                from_log, to_log, ..
            } => ProgressiveLeafLaunchKind::ExpandInPlace {
                from_log_size: from_log,
                to_log_size: to_log,
            },
            Launch::Lde(batch) => ProgressiveLeafLaunchKind::Lde {
                batch_index: batch.batch_index,
                segment_offset: batch.segment_offset,
                log_size: batch.log_size,
                columns: batch.columns,
            },
            Launch::Absorb {
                log_size, batch, ..
            } => ProgressiveLeafLaunchKind::Absorb {
                batch_index: batch.batch_index,
                segment_offset: batch.segment_offset,
                log_size,
                columns: batch.columns,
                absorbed_columns_before: batch.absorbed_columns_before,
            },
            Launch::DomainAbsorb {
                log_size,
                batch,
                initializes_state,
                ..
            } => ProgressiveLeafLaunchKind::DomainAbsorb {
                batch_index: batch.batch_index,
                log_size,
                columns: batch.columns,
                absorbed_columns_before: batch.absorbed_columns_before,
                initializes_state,
            },
            Launch::FusedLdeAbsorb {
                batch,
                retained_write_mask,
                ..
            } => ProgressiveLeafLaunchKind::FusedLdeAbsorb {
                batch_index: batch.batch_index,
                segment_offset: batch.segment_offset,
                log_size: batch.log_size,
                columns: batch.columns,
                absorbed_columns_before: batch.absorbed_columns_before,
                retained_write_mask,
            },
            Launch::Finalize {
                log_size,
                absorbed_columns,
                ..
            } => ProgressiveLeafLaunchKind::Finalize {
                log_size,
                absorbed_columns,
            },
            Launch::FinalizeInPlace {
                log_size,
                absorbed_columns,
                ..
            } => ProgressiveLeafLaunchKind::FinalizeInPlace {
                log_size,
                absorbed_columns,
            },
        })
    }
    pub fn leaf_hashes(&self) -> ArenaSlice {
        self.leaf_hashes
    }
    pub fn cache_key(&self) -> u64 {
        self.cache_key
    }
    pub fn storage_mode(&self) -> ProgressiveCommitStorageMode {
        self.storage
    }
    pub fn in_place_scratch_pair(&self) -> Option<ArenaSlice> {
        self.in_place_scratch
    }
    pub fn ntt_leaf_fusion_telemetry(&self) -> ProgressiveNttLeafFusionTelemetry {
        self.ntt_leaf_fusion
    }
}

/// Additive full commitment composed from progressive leaves and the qualified
/// legacy Merkle suffix. Production dispatch is deliberately outside this API.
pub struct PreparedProgressiveCommitGraph<'a> {
    leaves: PreparedProgressiveLeaves<'a>,
    merkle: PreparedMerkleFromLeaves<'a>,
    retained_evaluations: Vec<Option<ArenaSlice>>,
}

impl<'a> PreparedProgressiveCommitGraph<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &ProgressiveCommitWorkspaceRequirements,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_with_mode(
            arena,
            config,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            ProgressiveCommitMode::from_env(),
        )
    }

    /// Prepare with the progressive mode selected explicitly. The legacy
    /// interior-fusion environment switch remains in effect; immutable runtime
    /// generations use [`Self::prepare_with_modes`] instead.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_mode(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &ProgressiveCommitWorkspaceRequirements,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        mode: ProgressiveCommitMode,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_with_modes(
            arena,
            config,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            mode,
            super::blake2s::blake2s_interior_fused_enabled(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_interior_mode(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &ProgressiveCommitWorkspaceRequirements,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        interior_fused: bool,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_with_modes(
            arena,
            config,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            ProgressiveCommitMode::from_env(),
            interior_fused,
        )
    }

    /// Prepare with both launch-topology axes selected explicitly. This is the
    /// environment-free constructor for immutable runtime generations.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_modes(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &ProgressiveCommitWorkspaceRequirements,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        progressive_mode: ProgressiveCommitMode,
        interior_fused: bool,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        Self::prepare_with_modes_and_ntt_fusion(
            arena,
            config,
            requirements,
            slots,
            coefficients,
            retained_outputs,
            twiddles,
            progressive_mode,
            interior_fused,
            ProgressiveNttLeafFusionMode::Separate,
        )
    }

    /// Immutable-generation constructor including the final NTT sink topology.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_modes_and_ntt_fusion(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &ProgressiveCommitWorkspaceRequirements,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        progressive_mode: ProgressiveCommitMode,
        interior_fused: bool,
        ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        progressive_prepare_mode_admission_for_mode(progressive_mode, &requirements.leaves)?;
        let workspace = requirements.arena_slot_requirements(slots)?;
        let workspace_ids = workspace
            .iter()
            .map(|entry| entry.id)
            .collect::<BTreeSet<_>>();
        let mut external = BTreeSet::new();
        for source in coefficients
            .iter()
            .map(|column| column.coefficients)
            .chain(retained_outputs.iter().flatten().copied())
            .chain(core::iter::once(twiddles))
        {
            if workspace_ids.contains(&source.id()) || !external.insert(source.id()) {
                return Err(PreparedProgressiveCommitError::AliasedSlot(source.id()));
            }
        }
        let leaves = PreparedProgressiveLeaves::prepare_with_mode_and_ntt_fusion(
            arena,
            &requirements.leaves,
            &slots.leaves,
            coefficients,
            retained_outputs,
            twiddles,
            progressive_mode,
            ntt_leaf_fusion,
        )?;
        let merkle = PreparedMerkleFromLeaves::prepare_with_interior_mode(
            arena,
            config,
            &requirements.merkle,
            &slots.merkle,
            interior_fused,
        )?;
        if leaves.leaf_hashes().id() != merkle.leaves().id()
            || leaves.leaf_hashes().as_u32_ptr() != merkle.leaves().as_u32_ptr()
        {
            return Err(PreparedProgressiveCommitError::GeometryMismatch);
        }
        Ok(Self {
            leaves,
            merkle,
            retained_evaluations: retained_outputs.to_vec(),
        })
    }

    /// Dormant complete one-slab constructor. Interior fusion is pinned by the
    /// caller and admitted only across the unretained-to-retained boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_in_place_slab_with_modes_and_ntt_fusion(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &ProgressiveCommitWorkspaceRequirements,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
        progressive_mode: ProgressiveCommitMode,
        interior_fused: bool,
        ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
    ) -> Result<Self, PreparedProgressiveCommitError> {
        progressive_prepare_mode_admission_for_mode(progressive_mode, &requirements.leaves)?;
        let workspace = requirements.arena_slot_requirements_in_place(slots)?;
        let workspace_ids = workspace
            .iter()
            .map(|entry| entry.id)
            .collect::<BTreeSet<_>>();
        let mut external = BTreeSet::new();
        for source in coefficients
            .iter()
            .map(|column| column.coefficients)
            .chain(retained_outputs.iter().flatten().copied())
            .chain(core::iter::once(twiddles))
        {
            if workspace_ids.contains(&source.id()) || !external.insert(source.id()) {
                return Err(PreparedProgressiveCommitError::AliasedSlot(source.id()));
            }
        }
        let leaves = PreparedProgressiveLeaves::prepare_in_place_slab_with_mode_and_ntt_fusion(
            arena,
            &requirements.leaves,
            &slots.leaves,
            coefficients,
            retained_outputs,
            twiddles,
            progressive_mode,
            ntt_leaf_fusion,
        )?;
        let scratch_pair = leaves
            .in_place_scratch_pair()
            .ok_or(PreparedProgressiveCommitError::InvalidSlotShape)?;
        let merkle = PreparedMerkleFromLeaves::prepare_in_place_slab_with_interior_mode(
            arena,
            config,
            &requirements.merkle,
            &slots.merkle,
            scratch_pair,
            interior_fused,
        )?;
        if leaves.leaf_hashes().id() != merkle.leaves().id()
            || leaves.leaf_hashes().as_u32_ptr() != merkle.leaves().as_u32_ptr()
        {
            return Err(PreparedProgressiveCommitError::GeometryMismatch);
        }
        Ok(Self {
            leaves,
            merkle,
            retained_evaluations: retained_outputs.to_vec(),
        })
    }

    pub fn launch(&self) -> Result<(), PreparedProgressiveCommitError> {
        self.leaves.launch()?;
        self.merkle.launch()?;
        Ok(())
    }

    pub fn leaf_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = ProgressiveLeafLaunchKind> + '_ {
        self.leaves.launch_sequence()
    }

    pub fn merkle_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = super::commit_graph::CommitLaunchKind> + '_ {
        self.merkle.launch_sequence()
    }

    pub fn leaf_hashes(&self) -> ArenaSlice {
        self.leaves.leaf_hashes()
    }

    pub fn root_slice(&self) -> ArenaSlice {
        self.merkle.root_slice()
    }

    pub fn retained_layers_bottom_up(&self) -> &[ArenaSlice] {
        self.merkle.retained_layers_bottom_up()
    }

    pub fn retained_evaluations(&self) -> &[Option<ArenaSlice>] {
        &self.retained_evaluations
    }

    pub fn ntt_leaf_fusion_telemetry(&self) -> ProgressiveNttLeafFusionTelemetry {
        self.leaves.ntt_leaf_fusion_telemetry()
    }

    pub fn read_root_at_transcript_boundary(
        &self,
    ) -> Result<Blake2sHash, PreparedProgressiveCommitError> {
        let mut root = Blake2sHash::default();
        let arena = self.leaves.arena;
        unsafe {
            arena.context().memcpy_d2h_async(
                root.0.as_mut_ptr().cast(),
                self.root_slice().as_void_ptr().cast_const(),
                core::mem::size_of::<Blake2sHash>(),
            )?;
        }
        arena.context().sync()?;
        Ok(root)
    }
}

enum HostDescriptor {
    Pointers(Vec<usize>),
    U32(Vec<u32>),
}
impl HostDescriptor {
    fn bytes(&self) -> (*const c_void, usize) {
        match self {
            Self::Pointers(values) => (
                values.as_ptr().cast(),
                values.len() * core::mem::size_of::<usize>(),
            ),
            Self::U32(values) => (values.as_ptr().cast(), values.len() * WORD_BYTES),
        }
    }
}

fn validate_slots(
    requirements: &ProgressiveLeafWorkspaceRequirements,
    slots: &ProgressiveLeafWorkspaceSlots,
) -> Result<(), PreparedProgressiveCommitError> {
    if requirements.batches.len() != slots.batches.len()
        || requirements.lde_scratch_words.is_some() != slots.lde_scratch.is_some()
        || requirements.state_pong_words.is_some() != slots.state_pong.is_some()
    {
        return Err(PreparedProgressiveCommitError::InvalidSlotShape);
    }
    Ok(())
}
fn slot_requirement(
    id: ArenaSlotId,
    len_words: usize,
    alignment_words: usize,
) -> CommitArenaSlotRequirement {
    CommitArenaSlotRequirement {
        id,
        len_words,
        alignment_words,
    }
}
fn pow2(log_size: u32) -> Result<usize, PreparedProgressiveCommitError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedProgressiveCommitError::SizeOverflow)
}
fn state_words(log_size: u32) -> Result<usize, PreparedProgressiveCommitError> {
    pow2(log_size)?
        .checked_mul(STATE_WORDS)
        .ok_or(PreparedProgressiveCommitError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use super::super::progressive_commit::ProgressiveCommitGroupGeometry;
    use super::*;

    #[test]
    fn mixed_log_requirements_seal_ping_pong_and_direct_outputs() {
        let requirements = progressive_leaf_workspace_requirements_for_mode(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 8,
                log_blowup_factor: 1,
                groups: vec![
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![4, 4],
                        retain_evaluations: false,
                    },
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![6],
                        retain_evaluations: true,
                    },
                ],
            },
        )
        .unwrap();
        assert_eq!(requirements.plan.lde_batches.len(), 2);
        assert_eq!(requirements.lde_scratch_words, Some(64));
        assert_eq!(requirements.state_ping_words, 256 * STATE_WORDS);
        assert_eq!(requirements.state_pong_words, Some(128 * STATE_WORDS));
        assert_eq!(requirements.leaf_hash_words, 256 * HASH_WORDS);
        assert_ne!(requirements.cache_key(), 0);
        assert_eq!(
            requirements.launch_sequence(),
            vec![
                ProgressiveLeafLaunchKind::Init { log_size: 5 },
                ProgressiveLeafLaunchKind::Lde {
                    batch_index: 0,
                    segment_offset: 0,
                    log_size: 5,
                    columns: 2
                },
                ProgressiveLeafLaunchKind::Absorb {
                    batch_index: 0,
                    segment_offset: 0,
                    log_size: 5,
                    columns: 2,
                    absorbed_columns_before: 0,
                },
                ProgressiveLeafLaunchKind::Expand {
                    from_log_size: 5,
                    to_log_size: 7
                },
                ProgressiveLeafLaunchKind::Lde {
                    batch_index: 1,
                    segment_offset: 0,
                    log_size: 7,
                    columns: 1
                },
                ProgressiveLeafLaunchKind::Absorb {
                    batch_index: 1,
                    segment_offset: 0,
                    log_size: 7,
                    columns: 1,
                    absorbed_columns_before: 2,
                },
                ProgressiveLeafLaunchKind::Expand {
                    from_log_size: 7,
                    to_log_size: 8
                },
                ProgressiveLeafLaunchKind::Finalize {
                    log_size: 8,
                    absorbed_columns: 3,
                },
            ]
        );
    }

    #[test]
    fn width_sixteen_chunks_bound_shared_lde_scratch_and_launches() {
        let requirements = progressive_leaf_workspace_requirements_for_mode(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 6,
                log_blowup_factor: 1,
                groups: vec![ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3; 65],
                    retain_evaluations: false,
                }],
            },
        )
        .unwrap();
        assert_eq!(
            requirements
                .plan
                .lde_batches
                .iter()
                .map(|batch| batch.columns.len())
                .collect::<Vec<_>>(),
            [16, 16, 16, 16, 1]
        );
        assert_eq!(requirements.lde_scratch_words, Some(16 * (1 << 4)));
        assert_eq!(
            requirements
                .launch_sequence()
                .iter()
                .filter(|launch| matches!(launch, ProgressiveLeafLaunchKind::Lde { .. }))
                .count(),
            5
        );
        assert_eq!(
            requirements
                .launch_sequence()
                .iter()
                .filter(|launch| matches!(launch, ProgressiveLeafLaunchKind::Absorb { .. }))
                .count(),
            5
        );
        validate_progressive_requirements(&requirements).unwrap();

        let mut undersized = requirements.clone();
        undersized.lde_scratch_words = Some(16 * (1 << 4) - 1);
        assert_eq!(
            validate_progressive_requirements(&undersized),
            Err(PreparedProgressiveCommitError::InvalidSlotShape)
        );
        let mut descriptor_drift = requirements.clone();
        descriptor_drift.batches[0].output_pointer_words -= POINTER_WORDS;
        assert_eq!(
            validate_progressive_requirements(&descriptor_drift),
            Err(PreparedProgressiveCommitError::InvalidSlotShape)
        );
    }

    #[test]
    fn full_lifting_mode_cannot_allocate_progressive_slots() {
        let result = progressive_leaf_workspace_requirements_for_mode(
            ProgressiveCommitMode::FullLifting,
            ProgressiveCommitGeometry {
                lifting_log_size: 5,
                log_blowup_factor: 1,
                groups: vec![],
            },
        );
        assert_eq!(
            result.unwrap_err(),
            PreparedProgressiveCommitError::Disabled
        );
    }

    #[test]
    fn combined_workspace_shares_exactly_the_leaf_layer_and_matches_legacy_merkle_shape() {
        let config = CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 8,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        };
        let geometry = ProgressiveCommitGeometry {
            lifting_log_size: 8,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![4, 4, 6],
                retain_evaluations: false,
            }],
        };
        let combined = progressive_commit_workspace_requirements_for_mode(
            ProgressiveCommitMode::DomainProgressive,
            config,
            geometry,
        )
        .unwrap();
        let legacy =
            super::super::prepared_commit::commit_workspace_requirements(config, &[vec![4, 4, 6]])
                .unwrap();
        let extracted = merkle_from_leaves_requirements(config).unwrap();
        assert_eq!(combined.merkle, extracted);
        assert_eq!(legacy.leaf_state_words, extracted.leaf_words);
        assert_eq!(legacy.merkle_scratch_words, extracted.merkle_scratch_words);
        assert_eq!(legacy.retained_layers, extracted.retained_layers);
        assert_eq!(legacy.tail_outputs, extracted.tail_outputs);
        assert_eq!(combined.leaves.leaf_hash_words, combined.merkle.leaf_words);

        let slots = ProgressiveCommitWorkspaceSlots {
            leaves: ProgressiveLeafWorkspaceSlots {
                lde_scratch: combined.leaves.lde_scratch_words.map(|_| ArenaSlotId(1)),
                state_ping: ArenaSlotId(2),
                state_pong: combined.leaves.state_pong_words.map(|_| ArenaSlotId(3)),
                leaf_hashes: ArenaSlotId(4),
                batches: combined
                    .leaves
                    .batches
                    .iter()
                    .enumerate()
                    .map(|(index, _)| {
                        let base = 10 + index as u32 * 3;
                        ProgressiveBatchSlots {
                            coefficient_ptrs: ArenaSlotId(base),
                            coefficient_sizes: ArenaSlotId(base + 1),
                            output_ptrs: ArenaSlotId(base + 2),
                        }
                    })
                    .collect(),
            },
            merkle: MerkleFromLeavesSlots {
                leaves: ArenaSlotId(4),
                merkle_scratch: combined
                    .merkle
                    .merkle_scratch_words
                    .map(|_| ArenaSlotId(30)),
                retained_layers: combined
                    .merkle
                    .retained_layers
                    .iter()
                    .enumerate()
                    .map(|(index, _)| ArenaSlotId(40 + index as u32))
                    .collect(),
                tail_level_ptrs: combined.merkle.tail_pointer_words.map(|_| ArenaSlotId(60)),
                tail_outputs: combined
                    .merkle
                    .tail_outputs
                    .iter()
                    .enumerate()
                    .map(|(index, _)| ArenaSlotId(70 + index as u32))
                    .collect(),
            },
        };
        let requested = combined.arena_slot_requirements(&slots).unwrap();
        assert_eq!(
            requested
                .iter()
                .filter(|entry| entry.id == ArenaSlotId(4))
                .count(),
            1
        );
        assert_eq!(
            requested
                .iter()
                .map(|entry| entry.id)
                .collect::<BTreeSet<_>>()
                .len(),
            requested.len()
        );
    }
}
