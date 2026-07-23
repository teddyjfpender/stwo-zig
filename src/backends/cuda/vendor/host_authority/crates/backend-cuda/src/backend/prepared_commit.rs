//! Prepared, arena-backed lifted Blake2s commitment.
//!
//! Setup validates the complete geometry and uploads every descriptor table on
//! the proof context's explicit stream. [`PreparedCommitGraph::launch`] then
//! contains only allocation-free kernel launches, so eager execution and CUDA
//! graph capture use exactly the same sequence.

use core::ffi::c_void;
use std::collections::BTreeSet;

use stwo::core::vcs::blake2_hash::Blake2sHash;

use super::commit_graph::{
    CommitGraphError, CommitGraphPlan, CommitHashFromTileTelemetry, CommitLaunchKind,
    CommitLdeBatch, CommitLeafGroup, CommitLeafUpdateMode, CommitTailPlan, RetainedLdeHashMode,
};
use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};

mod in_place;

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const HASH_WORDS: usize = core::mem::size_of::<Blake2sHash>() / WORD_BYTES;
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);
const MAX_FUSED_TAIL_LEVELS: u32 = 12;
pub const COMMIT_POINTER_ALIGNMENT_WORDS: usize = core::mem::align_of::<*mut u32>() / WORD_BYTES;
pub const COMMIT_HASH_ALIGNMENT_WORDS: usize = core::mem::align_of::<Blake2sHash>() / WORD_BYTES;

/// Protocol geometry shared by the pure requirement pass and device setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitWorkspaceConfig {
    pub log_blowup_factor: u32,
    pub lifting_log_size: u32,
    /// Bottom layers not retained for decommitment, counting the leaf layer.
    pub unretained_bottom_layers: u32,
    /// Requested top levels for the one-block fused tail (capped at 12).
    pub max_fused_tail_levels: u32,
}

/// One canonical coefficient source. The arena slot may be capacity-sized; only
/// the first `2^log_size` words are part of this polynomial.
#[derive(Clone, Copy, Debug)]
pub struct CommitCoefficientColumn {
    pub coefficients: ArenaSlice,
    pub log_size: u32,
}

/// One leaf-hash update/finalize group in canonical column order.
#[derive(Clone, Debug)]
pub struct CommitCoefficientGroup {
    pub columns: Vec<CommitCoefficientColumn>,
}

/// Optional persistent LDE destinations for one canonical commitment group.
/// When supplied, the commit writes and hashes these slices directly; they can
/// remain live through query sampling and serve as decommit sources without a
/// second full-domain LDE pass.
#[derive(Clone, Debug)]
pub struct CommitEvaluationGroup {
    pub columns: Vec<ArenaSlice>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitBatchRequirements {
    pub first_column: usize,
    pub column_count: usize,
    pub coefficient_log_size: u32,
    pub evaluation_log_size: u32,
    pub coefficient_pointer_words: usize,
    pub coefficient_size_words: usize,
    pub output_pointer_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitGroupRequirements {
    pub column_pointer_words: usize,
    pub column_log_size_words: usize,
    pub batches: Vec<CommitBatchRequirements>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitLayerRequirements {
    pub log_size: u32,
    pub words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InteriorStorage {
    LeafPing,
    ScratchPong,
    Retained(usize),
}

/// Exact arena shape for the qualified column-free Merkle suffix. `leaf_words`
/// is the zero-copy input layer produced by either legacy or progressive leaf
/// construction; every other field is unchanged from the historical commit
/// workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleFromLeavesRequirements {
    pub leaf_words: usize,
    pub merkle_scratch_words: Option<usize>,
    pub retained_layers: Vec<CommitLayerRequirements>,
    pub tail_pointer_words: Option<usize>,
    pub tail_outputs: Vec<CommitLayerRequirements>,
    interior: Vec<(CommitLayerRequirements, InteriorStorage)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleFromLeavesSlots {
    pub leaves: ArenaSlotId,
    pub merkle_scratch: Option<ArenaSlotId>,
    pub retained_layers: Vec<ArenaSlotId>,
    pub tail_level_ptrs: Option<ArenaSlotId>,
    pub tail_outputs: Vec<ArenaSlotId>,
}

impl MerkleFromLeavesRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &MerkleFromLeavesSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedCommitError> {
        validate_merkle_slot_shape(self, slots)?;
        let mut output = vec![CommitArenaSlotRequirement {
            id: slots.leaves,
            len_words: self.leaf_words,
            alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
        }];
        if let (Some(id), Some(words)) = (slots.merkle_scratch, self.merkle_scratch_words) {
            output.push(CommitArenaSlotRequirement {
                id,
                len_words: words,
                alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
            });
        }
        output.extend(slots.retained_layers.iter().zip(&self.retained_layers).map(
            |(&id, layer)| CommitArenaSlotRequirement {
                id,
                len_words: layer.words,
                alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
            },
        ));
        if let (Some(id), Some(words)) = (slots.tail_level_ptrs, self.tail_pointer_words) {
            output.push(CommitArenaSlotRequirement {
                id,
                len_words: words,
                alignment_words: COMMIT_POINTER_ALIGNMENT_WORDS,
            });
        }
        output.extend(
            slots
                .tail_outputs
                .iter()
                .zip(&self.tail_outputs)
                .map(|(&id, layer)| CommitArenaSlotRequirement {
                    id,
                    len_words: layer.words,
                    alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
                }),
        );
        ensure_distinct(&output.iter().map(|entry| entry.id).collect::<Vec<_>>())?;
        Ok(output)
    }
}

/// Exact arena capacity needed by one prepared commitment. Pointer tables use
/// [`COMMIT_POINTER_ALIGNMENT_WORDS`]; hash layers use
/// [`COMMIT_HASH_ALIGNMENT_WORDS`]; word buffers use one-word alignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitWorkspaceRequirements {
    pub twiddle_words: usize,
    pub lde_tile_words: usize,
    pub leaf_state_words: usize,
    pub merkle_scratch_words: Option<usize>,
    pub retained_layers: Vec<CommitLayerRequirements>,
    pub tail_pointer_words: Option<usize>,
    pub tail_outputs: Vec<CommitLayerRequirements>,
    pub groups: Vec<CommitGroupRequirements>,
    interior: Vec<(CommitLayerRequirements, InteriorStorage)>,
}

/// One named slot requirement for merging the commit workspace into a larger
/// proof-arena liveness/layout pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

impl CommitWorkspaceRequirements {
    /// Bind this pure shape to caller-chosen logical IDs. The returned entries
    /// have no offsets and can be placed alongside the rest of the proof arena.
    pub fn arena_slot_requirements(
        &self,
        slots: &CommitWorkspaceSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedCommitError> {
        validate_slot_shape(self, slots)?;
        let mut output = vec![
            CommitArenaSlotRequirement {
                id: slots.lde_tile,
                len_words: self.lde_tile_words,
                alignment_words: 1,
            },
            CommitArenaSlotRequirement {
                id: slots.leaf_state,
                len_words: self.leaf_state_words,
                alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
            },
        ];
        if let (Some(id), Some(len_words)) = (slots.merkle_scratch, self.merkle_scratch_words) {
            output.push(CommitArenaSlotRequirement {
                id,
                len_words,
                alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
            });
        }
        output.extend(slots.retained_layers.iter().zip(&self.retained_layers).map(
            |(&id, layer)| CommitArenaSlotRequirement {
                id,
                len_words: layer.words,
                alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
            },
        ));
        if let (Some(id), Some(len_words)) = (slots.tail_level_ptrs, self.tail_pointer_words) {
            output.push(CommitArenaSlotRequirement {
                id,
                len_words,
                alignment_words: COMMIT_POINTER_ALIGNMENT_WORDS,
            });
        }
        output.extend(
            slots
                .tail_outputs
                .iter()
                .zip(&self.tail_outputs)
                .map(|(&id, layer)| CommitArenaSlotRequirement {
                    id,
                    len_words: layer.words,
                    alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
                }),
        );
        for (group_slots, group) in slots.groups.iter().zip(&self.groups) {
            output.extend([
                CommitArenaSlotRequirement {
                    id: group_slots.column_ptrs,
                    len_words: group.column_pointer_words,
                    alignment_words: COMMIT_POINTER_ALIGNMENT_WORDS,
                },
                CommitArenaSlotRequirement {
                    id: group_slots.column_log_sizes,
                    len_words: group.column_log_size_words,
                    alignment_words: 1,
                },
            ]);
            for (batch_slots, batch) in group_slots.batches.iter().zip(&group.batches) {
                output.extend([
                    CommitArenaSlotRequirement {
                        id: batch_slots.coefficient_ptrs,
                        len_words: batch.coefficient_pointer_words,
                        alignment_words: COMMIT_POINTER_ALIGNMENT_WORDS,
                    },
                    CommitArenaSlotRequirement {
                        id: batch_slots.coefficient_sizes,
                        len_words: batch.coefficient_size_words,
                        alignment_words: 1,
                    },
                    CommitArenaSlotRequirement {
                        id: batch_slots.output_ptrs,
                        len_words: batch.output_pointer_words,
                        alignment_words: COMMIT_POINTER_ALIGNMENT_WORDS,
                    },
                ]);
            }
        }
        ensure_distinct(&output.iter().map(|entry| entry.id).collect::<Vec<_>>())?;
        Ok(output)
    }
}

/// Three descriptor slots for one same-log LDE batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitBatchSlots {
    pub coefficient_ptrs: ArenaSlotId,
    pub coefficient_sizes: ArenaSlotId,
    pub output_ptrs: ArenaSlotId,
}

/// Descriptor slots consumed by one leaf update/finalize group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitGroupSlots {
    pub column_ptrs: ArenaSlotId,
    pub column_log_sizes: ArenaSlotId,
    pub batches: Vec<CommitBatchSlots>,
}

/// Named logical slots in a caller-planned [`DeviceArena`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitWorkspaceSlots {
    pub lde_tile: ArenaSlotId,
    pub leaf_state: ArenaSlotId,
    pub merkle_scratch: Option<ArenaSlotId>,
    pub retained_layers: Vec<ArenaSlotId>,
    pub tail_level_ptrs: Option<ArenaSlotId>,
    pub tail_outputs: Vec<ArenaSlotId>,
    pub groups: Vec<CommitGroupSlots>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedCommitError {
    NoGroups,
    EmptyGroup(usize),
    InvalidUpdateWidth {
        group: usize,
        columns: usize,
    },
    InvalidFinalWidth(usize),
    InvalidBlowup(u32),
    InvalidLiftingLogSize(u32),
    InvalidUnretainedBottomLayers {
        lifting: u32,
        unretained: u32,
    },
    InvalidTailLevels(u32),
    InvalidColumnLogSize {
        group: usize,
        column: usize,
        log_size: u32,
    },
    EvaluationExceedsLifting {
        group: usize,
        column: usize,
        evaluation_log_size: u32,
        lifting_log_size: u32,
    },
    NonCanonicalColumnOrder {
        group: usize,
        column: usize,
        previous: u32,
        current: u32,
    },
    SizeOverflow,
    SlotShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    AliasedSourceSlot(ArenaSlotId),
    SourceAliasesWorkspace(ArenaSlotId),
    OutputAliasesSource(ArenaSlotId),
    OutputAliasesWorkspace(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedSlot {
        slot: ArenaSlotId,
        alignment_words: usize,
    },
    CoefficientTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    TwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    Arena(ArenaError),
    Graph(CommitGraphError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedCommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA commitment: {self:?}")
    }
}

impl std::error::Error for PreparedCommitError {}

impl From<ArenaError> for PreparedCommitError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CommitGraphError> for PreparedCommitError {
    fn from(value: CommitGraphError) -> Self {
        Self::Graph(value)
    }
}

impl From<CudaRuntimeError> for PreparedCommitError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

/// Pure sizing pass for the column-free suffix shared by both leaf producers.
pub fn merkle_from_leaves_requirements(
    config: CommitWorkspaceConfig,
) -> Result<MerkleFromLeavesRequirements, PreparedCommitError> {
    validate_config(config)?;
    let leaf_words = hash_words(config.lifting_log_size)?;
    let first_retained_log = config.lifting_log_size - config.unretained_bottom_layers;
    let tail_levels = config.max_fused_tail_levels.min(first_retained_log);
    let mut retained_layers = Vec::new();
    let mut interior = Vec::new();
    let mut scratch_words = None;
    let mut scratch_on_leaf = true;
    for log_size in (tail_levels..config.lifting_log_size).rev() {
        let layer = CommitLayerRequirements {
            log_size,
            words: hash_words(log_size)?,
        };
        let storage = if log_size > first_retained_log {
            if scratch_on_leaf {
                scratch_words.get_or_insert(layer.words);
                scratch_on_leaf = false;
                InteriorStorage::ScratchPong
            } else {
                scratch_on_leaf = true;
                InteriorStorage::LeafPing
            }
        } else {
            let index = retained_layers.len();
            retained_layers.push(layer);
            InteriorStorage::Retained(index)
        };
        interior.push((layer, storage));
    }
    let tail_outputs: Vec<_> = (0..tail_levels)
        .rev()
        .map(|log_size| {
            Ok(CommitLayerRequirements {
                log_size,
                words: hash_words(log_size)?,
            })
        })
        .collect::<Result<_, PreparedCommitError>>()?;
    Ok(MerkleFromLeavesRequirements {
        leaf_words,
        merkle_scratch_words: scratch_words,
        retained_layers,
        tail_pointer_words: (!tail_outputs.is_empty())
            .then(|| pointer_words(tail_outputs.len()))
            .transpose()?,
        tail_outputs,
        interior,
    })
}

/// Pure sizing/shape pass. `grouped_coefficient_log_sizes` must already be in
/// canonical global order and use the exact update/finalize grouping that will
/// be passed to [`PreparedCommitGraph::prepare`].
pub fn commit_workspace_requirements(
    config: CommitWorkspaceConfig,
    grouped_coefficient_log_sizes: &[Vec<u32>],
) -> Result<CommitWorkspaceRequirements, PreparedCommitError> {
    validate_config(config)?;
    if grouped_coefficient_log_sizes.is_empty() {
        return Err(PreparedCommitError::NoGroups);
    }

    let mut previous_log = None;
    let mut twiddle_words = 0usize;
    let mut lde_tile_words = 0usize;
    let mut groups = Vec::with_capacity(grouped_coefficient_log_sizes.len());
    for (group_index, logs) in grouped_coefficient_log_sizes.iter().enumerate() {
        if logs.is_empty() {
            return Err(PreparedCommitError::EmptyGroup(group_index));
        }
        let is_final = group_index + 1 == grouped_coefficient_log_sizes.len();
        if is_final {
            if logs.len() > 16 {
                return Err(PreparedCommitError::InvalidFinalWidth(logs.len()));
            }
        } else if logs.len() % 16 != 0 {
            return Err(PreparedCommitError::InvalidUpdateWidth {
                group: group_index,
                columns: logs.len(),
            });
        }

        let mut group_lde_words = 0usize;
        let mut evaluation_logs = Vec::with_capacity(logs.len());
        for (column_index, &log_size) in logs.iter().enumerate() {
            let evaluation_log_size = log_size
                .checked_add(config.log_blowup_factor)
                .ok_or(PreparedCommitError::SizeOverflow)?;
            if evaluation_log_size < 4 || evaluation_log_size > 30 {
                return Err(PreparedCommitError::InvalidColumnLogSize {
                    group: group_index,
                    column: column_index,
                    log_size,
                });
            }
            if evaluation_log_size > config.lifting_log_size {
                return Err(PreparedCommitError::EvaluationExceedsLifting {
                    group: group_index,
                    column: column_index,
                    evaluation_log_size,
                    lifting_log_size: config.lifting_log_size,
                });
            }
            if let Some(previous) = previous_log {
                if log_size < previous {
                    return Err(PreparedCommitError::NonCanonicalColumnOrder {
                        group: group_index,
                        column: column_index,
                        previous,
                        current: log_size,
                    });
                }
            }
            previous_log = Some(log_size);
            let evaluation_words = pow2_words(evaluation_log_size)?;
            group_lde_words = group_lde_words
                .checked_add(evaluation_words)
                .ok_or(PreparedCommitError::SizeOverflow)?;
            twiddle_words = twiddle_words.max(pow2_words(evaluation_log_size - 1)?);
            evaluation_logs.push(evaluation_log_size);
        }
        lde_tile_words = lde_tile_words.max(group_lde_words);

        let mut batches = Vec::new();
        let mut start = 0usize;
        while start < logs.len() {
            let mut end = start + 1;
            while end < logs.len() && logs[end] == logs[start] {
                end += 1;
            }
            let count = end - start;
            batches.push(CommitBatchRequirements {
                first_column: start,
                column_count: count,
                coefficient_log_size: logs[start],
                evaluation_log_size: evaluation_logs[start],
                coefficient_pointer_words: pointer_words(count)?,
                coefficient_size_words: count,
                output_pointer_words: pointer_words(count)?,
            });
            start = end;
        }
        groups.push(CommitGroupRequirements {
            column_pointer_words: pointer_words(logs.len())?,
            column_log_size_words: logs.len(),
            batches,
        });
    }

    let merkle = merkle_from_leaves_requirements(config)?;

    Ok(CommitWorkspaceRequirements {
        twiddle_words,
        lde_tile_words,
        leaf_state_words: merkle.leaf_words,
        merkle_scratch_words: merkle.merkle_scratch_words,
        retained_layers: merkle.retained_layers,
        tail_pointer_words: merkle.tail_pointer_words,
        tail_outputs: merkle.tail_outputs,
        groups,
        interior: merkle.interior,
    })
}

fn validate_config(config: CommitWorkspaceConfig) -> Result<(), PreparedCommitError> {
    if !(1..=16).contains(&config.log_blowup_factor) {
        return Err(PreparedCommitError::InvalidBlowup(config.log_blowup_factor));
    }
    if config.lifting_log_size >= 31 {
        return Err(PreparedCommitError::InvalidLiftingLogSize(
            config.lifting_log_size,
        ));
    }
    if config.unretained_bottom_layers > config.lifting_log_size {
        return Err(PreparedCommitError::InvalidUnretainedBottomLayers {
            lifting: config.lifting_log_size,
            unretained: config.unretained_bottom_layers,
        });
    }
    if config.max_fused_tail_levels > MAX_FUSED_TAIL_LEVELS {
        return Err(PreparedCommitError::InvalidTailLevels(
            config.max_fused_tail_levels,
        ));
    }
    Ok(())
}

fn pow2_words(log_size: u32) -> Result<usize, PreparedCommitError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedCommitError::SizeOverflow)
}

fn hash_words(log_size: u32) -> Result<usize, PreparedCommitError> {
    pow2_words(log_size)?
        .checked_mul(HASH_WORDS)
        .ok_or(PreparedCommitError::SizeOverflow)
}

fn pointer_words(count: usize) -> Result<usize, PreparedCommitError> {
    count
        .checked_mul(POINTER_WORDS)
        .ok_or(PreparedCommitError::SizeOverflow)
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

struct PendingUpload {
    destination: ArenaSlice,
    descriptor: HostDescriptor,
}

/// Fully prepared commitment. It borrows the arena so every captured address,
/// coefficient source, descriptor table, and output outlives the launch plan.
pub struct PreparedCommitGraph<'a> {
    arena: &'a DeviceArena,
    plan: CommitGraphPlan,
    retained_layers_bottom_up: Vec<ArenaSlice>,
    retained_evaluations: Vec<Option<Vec<ArenaSlice>>>,
}

/// Prepared qualified Merkle suffix over a caller-produced leaf layer.
pub struct PreparedMerkleFromLeaves<'a> {
    arena: &'a DeviceArena,
    plan: CommitGraphPlan,
    leaves: ArenaSlice,
    retained_layers_bottom_up: Vec<ArenaSlice>,
}

impl<'a> PreparedMerkleFromLeaves<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &MerkleFromLeavesRequirements,
        slots: &MerkleFromLeavesSlots,
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_with_interior_mode(
            arena,
            config,
            requirements,
            slots,
            super::blake2s::blake2s_interior_fused_enabled(),
        )
    }

    pub fn prepare_with_interior_mode(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &MerkleFromLeavesRequirements,
        slots: &MerkleFromLeavesSlots,
        interior_fused: bool,
    ) -> Result<Self, PreparedCommitError> {
        if merkle_from_leaves_requirements(config)? != *requirements {
            return Err(PreparedCommitError::SlotShapeMismatch {
                role: "merkle_requirements",
                expected: 1,
                actual: 0,
            });
        }
        requirements.arena_slot_requirements(slots)?;
        let leaves = bind_slot(
            arena,
            slots.leaves,
            requirements.leaf_words,
            COMMIT_HASH_ALIGNMENT_WORDS,
        )?;
        let scratch = match (requirements.merkle_scratch_words, slots.merkle_scratch) {
            (Some(words), Some(id)) => {
                Some(bind_slot(arena, id, words, COMMIT_HASH_ALIGNMENT_WORDS)?)
            }
            (None, None) => None,
            _ => unreachable!("slot shape validated"),
        };
        let retained: Vec<_> = slots
            .retained_layers
            .iter()
            .zip(&requirements.retained_layers)
            .map(|(&id, layer)| bind_slot(arena, id, layer.words, COMMIT_HASH_ALIGNMENT_WORDS))
            .collect::<Result<_, _>>()?;
        let tail_outputs: Vec<_> = slots
            .tail_outputs
            .iter()
            .zip(&requirements.tail_outputs)
            .map(|(&id, layer)| bind_slot(arena, id, layer.words, COMMIT_HASH_ALIGNMENT_WORDS))
            .collect::<Result<_, _>>()?;
        let interior_outputs = requirements
            .interior
            .iter()
            .map(|(_, storage)| match *storage {
                InteriorStorage::LeafPing => leaves,
                InteriorStorage::ScratchPong => scratch.expect("slot shape validated"),
                InteriorStorage::Retained(index) => retained[index],
            })
            .collect();
        let tail = if tail_outputs.is_empty() {
            None
        } else {
            let level_ptrs = bind_slot(
                arena,
                slots.tail_level_ptrs.expect("slot shape validated"),
                requirements
                    .tail_pointer_words
                    .expect("requirements have tail"),
                COMMIT_POINTER_ALIGNMENT_WORDS,
            )?;
            let pointers = tail_outputs
                .iter()
                .map(|slice| slice.as_u32_ptr() as usize)
                .collect::<Vec<_>>();
            unsafe {
                arena.context().memcpy_h2d_async(
                    level_ptrs.as_void_ptr(),
                    pointers.as_ptr().cast(),
                    core::mem::size_of_val(pointers.as_slice()),
                )?;
            }
            Some(CommitTailPlan {
                level_ptrs,
                level_outputs: tail_outputs.clone(),
            })
        };
        arena.context().sync()?;
        let plan = CommitGraphPlan::new_merkle_from_leaves_with_mode(
            config.lifting_log_size,
            config.unretained_bottom_layers,
            leaves,
            interior_outputs,
            tail,
            interior_fused,
        )?;
        let mut retained_layers_bottom_up = Vec::new();
        if config.unretained_bottom_layers == 0 {
            retained_layers_bottom_up.push(leaves);
        }
        retained_layers_bottom_up.extend(retained);
        retained_layers_bottom_up.extend(tail_outputs);
        Ok(Self {
            arena,
            plan,
            leaves,
            retained_layers_bottom_up,
        })
    }

    pub fn launch(&self) -> Result<(), PreparedCommitError> {
        self.plan.launch(self.arena.context())?;
        Ok(())
    }

    pub fn launch_sequence(&self) -> impl ExactSizeIterator<Item = CommitLaunchKind> + '_ {
        self.plan.launch_sequence()
    }

    pub fn leaves(&self) -> ArenaSlice {
        self.leaves
    }

    pub fn root_slice(&self) -> ArenaSlice {
        self.plan.root()
    }

    pub fn retained_layers_bottom_up(&self) -> &[ArenaSlice] {
        &self.retained_layers_bottom_up
    }
}

impl<'a> PreparedCommitGraph<'a> {
    /// Validate all inputs, bind arena slots, upload descriptors, then perform
    /// one setup synchronization before any graph capture starts.
    pub fn prepare(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        groups: &[CommitCoefficientGroup],
        twiddles: ArenaSlice,
        slots: &CommitWorkspaceSlots,
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_inner(
            arena,
            config,
            groups,
            twiddles,
            slots,
            None,
            super::blake2s::blake2s_interior_fused_enabled(),
            RetainedLdeHashMode::from_env(),
            CommitLeafUpdateMode::from_env(),
        )
    }

    /// Prepare a commitment with a deterministic per-group opening policy.
    /// `Some(group)` keeps that group's LDE columns resident through decommit;
    /// `None` uses the shared streaming tile and is recomputed if opened later.
    pub fn prepare_with_retained_evaluations(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        groups: &[CommitCoefficientGroup],
        twiddles: ArenaSlice,
        slots: &CommitWorkspaceSlots,
        output_groups: &[Option<CommitEvaluationGroup>],
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_inner(
            arena,
            config,
            groups,
            twiddles,
            slots,
            Some(output_groups),
            super::blake2s::blake2s_interior_fused_enabled(),
            RetainedLdeHashMode::from_env(),
            CommitLeafUpdateMode::from_env(),
        )
    }

    /// [`Self::prepare_with_retained_evaluations`] with the Step 3.1 retained
    /// LDE-write + leaf-absorb lane (`STWO_CUDA_NTT_LEAF_FUSED`) pinned
    /// explicitly, so the native byte-identity test can exercise BOTH
    /// retained commit topologies in one process (the env switch is a
    /// process-global `OnceLock`). Workspace requirements and slot budgets
    /// are identical in both modes; a fused-eligible retained group merely
    /// swaps its `Lde` + leaf-hash launch pair for one `RetainedNttHash`
    /// launch (see `CommitGraphPlan::new_pruned_with_modes`).
    pub fn prepare_with_retained_evaluations_and_mode(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        groups: &[CommitCoefficientGroup],
        twiddles: ArenaSlice,
        slots: &CommitWorkspaceSlots,
        output_groups: &[Option<CommitEvaluationGroup>],
        retained_lde_hash: RetainedLdeHashMode,
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_with_retained_evaluations_and_modes(
            arena,
            config,
            groups,
            twiddles,
            slots,
            output_groups,
            retained_lde_hash,
            CommitLeafUpdateMode::from_env(),
        )
    }

    /// Fully explicit commitment implementation selection used by native
    /// cross-mode gates. Both choices are sealed into the prepared topology.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_retained_evaluations_and_modes(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        groups: &[CommitCoefficientGroup],
        twiddles: ArenaSlice,
        slots: &CommitWorkspaceSlots,
        output_groups: &[Option<CommitEvaluationGroup>],
        retained_lde_hash: RetainedLdeHashMode,
        leaf_update_mode: CommitLeafUpdateMode,
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_inner(
            arena,
            config,
            groups,
            twiddles,
            slots,
            Some(output_groups),
            super::blake2s::blake2s_interior_fused_enabled(),
            retained_lde_hash,
            leaf_update_mode,
        )
    }

    /// [`Self::prepare`] with the Step 3.2 interior four-level fusion lane
    /// (`STWO_CUDA_BLAKE2S_INTERIOR_FUSED`) pinned explicitly, so the native
    /// byte-identity test can exercise BOTH interior launch topologies in one
    /// process (the env switch is a process-global `OnceLock`). Workspace
    /// requirements and slot budgets are identical in both modes; only the
    /// interior launch emission differs (see `CommitGraphPlan::new_pruned_impl`).
    pub fn prepare_with_interior_mode(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        groups: &[CommitCoefficientGroup],
        twiddles: ArenaSlice,
        slots: &CommitWorkspaceSlots,
        interior_fused: bool,
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_inner(
            arena,
            config,
            groups,
            twiddles,
            slots,
            None,
            interior_fused,
            RetainedLdeHashMode::from_env(),
            CommitLeafUpdateMode::from_env(),
        )
    }

    /// Prepare with an explicit materialized leaf-update implementation. This
    /// is the correctness/A-B entry point for the cooperative quad kernel;
    /// the selected mode is sealed into the launch topology before capture.
    pub fn prepare_with_leaf_update_mode(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        groups: &[CommitCoefficientGroup],
        twiddles: ArenaSlice,
        slots: &CommitWorkspaceSlots,
        leaf_update_mode: CommitLeafUpdateMode,
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_inner(
            arena,
            config,
            groups,
            twiddles,
            slots,
            None,
            super::blake2s::blake2s_interior_fused_enabled(),
            RetainedLdeHashMode::from_env(),
            leaf_update_mode,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_inner(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        groups: &[CommitCoefficientGroup],
        twiddles: ArenaSlice,
        slots: &CommitWorkspaceSlots,
        output_groups: Option<&[Option<CommitEvaluationGroup>]>,
        interior_fused: bool,
        retained_lde_hash: RetainedLdeHashMode,
        leaf_update_mode: CommitLeafUpdateMode,
    ) -> Result<Self, PreparedCommitError> {
        let grouped_logs: Vec<Vec<u32>> = groups
            .iter()
            .map(|group| group.columns.iter().map(|column| column.log_size).collect())
            .collect();
        let requirements = commit_workspace_requirements(config, &grouped_logs)?;
        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        let workspace_ids: Vec<_> = slot_requirements.iter().map(|entry| entry.id).collect();

        let context_token = arena.context().identity_token();
        if twiddles.context_token() != context_token {
            return Err(PreparedCommitError::ContextMismatch(twiddles.id()));
        }
        if twiddles.len_words() < requirements.twiddle_words {
            return Err(PreparedCommitError::TwiddlesTooSmall {
                required_words: requirements.twiddle_words,
                actual_words: twiddles.len_words(),
            });
        }
        let workspace_set: BTreeSet<_> = workspace_ids.iter().copied().collect();
        let mut source_ids = BTreeSet::from([twiddles.id()]);
        for group in groups {
            for column in &group.columns {
                if column.coefficients.context_token() != context_token {
                    return Err(PreparedCommitError::ContextMismatch(
                        column.coefficients.id(),
                    ));
                }
                let required_words = pow2_words(column.log_size)?;
                if column.coefficients.len_words() < required_words {
                    return Err(PreparedCommitError::CoefficientTooSmall {
                        slot: column.coefficients.id(),
                        required_words,
                        actual_words: column.coefficients.len_words(),
                    });
                }
                if !source_ids.insert(column.coefficients.id()) {
                    return Err(PreparedCommitError::AliasedSourceSlot(
                        column.coefficients.id(),
                    ));
                }
            }
        }
        if let Some(id) = source_ids.intersection(&workspace_set).next() {
            return Err(PreparedCommitError::SourceAliasesWorkspace(*id));
        }

        let retained_evaluations = match output_groups {
            None => vec![None; groups.len()],
            Some(outputs) => {
                check_count("evaluation output groups", groups.len(), outputs.len())?;
                let mut output_ids = BTreeSet::new();
                let mut retained = Vec::with_capacity(outputs.len());
                for (group_index, ((group, logs), output)) in
                    groups.iter().zip(&grouped_logs).zip(outputs).enumerate()
                {
                    let Some(output) = output else {
                        retained.push(None);
                        continue;
                    };
                    check_count(
                        "evaluation output columns",
                        group.columns.len(),
                        output.columns.len(),
                    )?;
                    let mut columns = Vec::with_capacity(output.columns.len());
                    for (column_index, (&slice, &log_size)) in
                        output.columns.iter().zip(logs).enumerate()
                    {
                        if slice.context_token() != context_token {
                            return Err(PreparedCommitError::ContextMismatch(slice.id()));
                        }
                        let required_words = pow2_words(
                            log_size
                                .checked_add(config.log_blowup_factor)
                                .ok_or(PreparedCommitError::SizeOverflow)?,
                        )?;
                        if slice.len_words() < required_words {
                            return Err(PreparedCommitError::SlotTooSmall {
                                slot: slice.id(),
                                required_words,
                                actual_words: slice.len_words(),
                            });
                        }
                        if !output_ids.insert(slice.id()) {
                            return Err(PreparedCommitError::DuplicateSlot(slice.id()));
                        }
                        if source_ids.contains(&slice.id()) {
                            return Err(PreparedCommitError::OutputAliasesSource(slice.id()));
                        }
                        if workspace_set.contains(&slice.id()) {
                            return Err(PreparedCommitError::OutputAliasesWorkspace(slice.id()));
                        }
                        debug_assert!(column_index < group.columns.len());
                        debug_assert!(group_index < groups.len());
                        columns.push(slice);
                    }
                    retained.push(Some(columns));
                }
                retained
            }
        };

        let lde_tile = bind_slot(arena, slots.lde_tile, requirements.lde_tile_words, 1)?;
        let leaf_state = bind_slot(
            arena,
            slots.leaf_state,
            requirements.leaf_state_words,
            COMMIT_HASH_ALIGNMENT_WORDS,
        )?;
        let scratch = match (requirements.merkle_scratch_words, slots.merkle_scratch) {
            (Some(words), Some(id)) => {
                Some(bind_slot(arena, id, words, COMMIT_HASH_ALIGNMENT_WORDS)?)
            }
            (None, None) => None,
            _ => unreachable!("slot shape validated"),
        };
        let retained: Vec<_> = slots
            .retained_layers
            .iter()
            .zip(&requirements.retained_layers)
            .map(|(&id, requirement)| {
                bind_slot(arena, id, requirement.words, COMMIT_HASH_ALIGNMENT_WORDS)
            })
            .collect::<Result<_, _>>()?;
        let tail_outputs: Vec<_> = slots
            .tail_outputs
            .iter()
            .zip(&requirements.tail_outputs)
            .map(|(&id, requirement)| {
                bind_slot(arena, id, requirement.words, COMMIT_HASH_ALIGNMENT_WORDS)
            })
            .collect::<Result<_, _>>()?;

        let mut uploads = Vec::new();
        let mut leaf_groups = Vec::with_capacity(groups.len());
        let mut first_column = 0u32;
        for ((((group, group_slots), group_requirement), logs), retained_group) in groups
            .iter()
            .zip(&slots.groups)
            .zip(&requirements.groups)
            .zip(&grouped_logs)
            .zip(&retained_evaluations)
        {
            let column_ptrs = bind_slot(
                arena,
                group_slots.column_ptrs,
                group_requirement.column_pointer_words,
                COMMIT_POINTER_ALIGNMENT_WORDS,
            )?;
            let column_log_sizes = bind_slot(
                arena,
                group_slots.column_log_sizes,
                group_requirement.column_log_size_words,
                1,
            )?;

            let output_pointers = match retained_group {
                Some(columns) => columns
                    .iter()
                    .map(|column| column.as_u32_ptr() as usize)
                    .collect(),
                None => {
                    let mut output_offset = 0usize;
                    let mut pointers = Vec::with_capacity(group.columns.len());
                    for &log_size in logs {
                        let evaluation_log_size = log_size + config.log_blowup_factor;
                        let pointer = unsafe { lde_tile.as_u32_ptr().add(output_offset) };
                        pointers.push(pointer as usize);
                        output_offset += pow2_words(evaluation_log_size)?;
                    }
                    pointers
                }
            };
            uploads.push(PendingUpload {
                destination: column_ptrs,
                descriptor: HostDescriptor::Pointers(output_pointers.clone()),
            });
            uploads.push(PendingUpload {
                destination: column_log_sizes,
                descriptor: HostDescriptor::U32(
                    logs.iter()
                        .map(|&log| log + config.log_blowup_factor)
                        .collect(),
                ),
            });

            let mut lde_batches = Vec::with_capacity(group_requirement.batches.len());
            for (batch, batch_slots) in group_requirement.batches.iter().zip(&group_slots.batches) {
                let range = batch.first_column..batch.first_column + batch.column_count;
                let coefficient_ptrs = bind_slot(
                    arena,
                    batch_slots.coefficient_ptrs,
                    batch.coefficient_pointer_words,
                    COMMIT_POINTER_ALIGNMENT_WORDS,
                )?;
                let coefficient_sizes = bind_slot(
                    arena,
                    batch_slots.coefficient_sizes,
                    batch.coefficient_size_words,
                    1,
                )?;
                let batch_output_ptrs = bind_slot(
                    arena,
                    batch_slots.output_ptrs,
                    batch.output_pointer_words,
                    COMMIT_POINTER_ALIGNMENT_WORDS,
                )?;
                uploads.push(PendingUpload {
                    destination: coefficient_ptrs,
                    descriptor: HostDescriptor::Pointers(
                        group.columns[range.clone()]
                            .iter()
                            .map(|column| column.coefficients.as_u32_ptr() as usize)
                            .collect(),
                    ),
                });
                uploads.push(PendingUpload {
                    destination: coefficient_sizes,
                    descriptor: HostDescriptor::U32(vec![
                        u32::try_from(pow2_words(
                            batch.coefficient_log_size
                        )?)
                        .map_err(|_| {
                            PreparedCommitError::SizeOverflow
                        })?;
                        batch.column_count
                    ]),
                });
                uploads.push(PendingUpload {
                    destination: batch_output_ptrs,
                    descriptor: HostDescriptor::Pointers(output_pointers[range].to_vec()),
                });
                let eval_domain_size = 1u32 << (batch.evaluation_log_size - 1);
                lde_batches.push(CommitLdeBatch {
                    coefficient_ptrs,
                    coefficient_sizes,
                    column_ptrs: batch_output_ptrs,
                    column_count: u32::try_from(batch.column_count)
                        .map_err(|_| PreparedCommitError::SizeOverflow)?,
                    log_n: batch.evaluation_log_size,
                    twiddles,
                    twiddles_size: u32::try_from(twiddles.len_words())
                        .map_err(|_| PreparedCommitError::SizeOverflow)?,
                    eval_domain_size,
                });
            }
            let column_count = u32::try_from(group.columns.len())
                .map_err(|_| PreparedCommitError::SizeOverflow)?;
            leaf_groups.push(CommitLeafGroup {
                first_column,
                column_count,
                column_ptrs,
                column_log_sizes,
                lde_batches,
                retain_evaluations: retained_group.is_some(),
            });
            first_column = first_column
                .checked_add(column_count)
                .ok_or(PreparedCommitError::SizeOverflow)?;
        }

        let interior_outputs: Vec<_> = requirements
            .interior
            .iter()
            .map(|(_, storage)| match *storage {
                InteriorStorage::LeafPing => leaf_state,
                InteriorStorage::ScratchPong => scratch.expect("slot shape validated"),
                InteriorStorage::Retained(index) => retained[index],
            })
            .collect();

        let tail = if tail_outputs.is_empty() {
            None
        } else {
            let level_ptrs = bind_slot(
                arena,
                slots.tail_level_ptrs.expect("slot shape validated"),
                requirements
                    .tail_pointer_words
                    .expect("requirements have tail"),
                COMMIT_POINTER_ALIGNMENT_WORDS,
            )?;
            uploads.push(PendingUpload {
                destination: level_ptrs,
                descriptor: HostDescriptor::Pointers(
                    tail_outputs
                        .iter()
                        .map(|slice| slice.as_u32_ptr() as usize)
                        .collect(),
                ),
            });
            Some(CommitTailPlan {
                level_ptrs,
                level_outputs: tail_outputs.clone(),
            })
        };

        let plan = CommitGraphPlan::new_pruned_with_modes(
            config.lifting_log_size,
            config.unretained_bottom_layers,
            leaf_state,
            leaf_groups,
            interior_outputs,
            tail,
            interior_fused,
            retained_lde_hash,
            leaf_update_mode,
        )?;

        // Dynamic shared-memory opt-in is a setup operation and therefore must
        // happen before capture. Unsupported devices fail closed here; replay
        // never performs runtime configuration.
        for &log_n in plan.producer_fused_log_sizes() {
            let code =
                unsafe { stwo_backend_cuda_kernels::raw::stwo_lde_n2b_hash16_configure(log_n) };
            check_cuda("commit_hash_from_tile_configure", code)?;
        }
        for &log_n in plan.retained_fused_log_sizes() {
            let code =
                unsafe { stwo_backend_cuda_kernels::raw::stwo_ntt_leaf_fused_configure(log_n) };
            check_cuda("commit_ntt_leaf_fused_configure", code)?;
        }

        // All host descriptor storage remains alive until this one setup drain.
        // No transfer or synchronization occurs in `launch` or during capture.
        let mut upload_result = Ok(());
        for upload in &uploads {
            let (source, bytes) = upload.descriptor.bytes();
            let result = unsafe {
                arena
                    .context()
                    .memcpy_h2d_async(upload.destination.as_void_ptr(), source, bytes)
            };
            if result.is_err() {
                upload_result = result;
                break;
            }
        }
        let sync_result = arena.context().sync();
        upload_result?;
        sync_result?;

        let mut retained_layers_bottom_up = Vec::new();
        if config.unretained_bottom_layers == 0 {
            retained_layers_bottom_up.push(leaf_state);
        }
        retained_layers_bottom_up.extend(retained.iter().copied());
        retained_layers_bottom_up.extend(tail_outputs.iter().copied());
        Ok(Self {
            arena,
            plan,
            retained_layers_bottom_up,
            retained_evaluations,
        })
    }

    /// Allocation/transfer/sync-free execution, shared by eager and capture.
    pub fn launch(&self) -> Result<(), PreparedCommitError> {
        self.plan.launch(self.arena.context())?;
        Ok(())
    }

    pub fn launch_sequence(&self) -> impl ExactSizeIterator<Item = CommitLaunchKind> + '_ {
        self.plan.launch_sequence()
    }

    pub fn hash_from_tile_telemetry(&self) -> CommitHashFromTileTelemetry {
        self.plan.hash_from_tile_telemetry()
    }

    pub fn root_slice(&self) -> ArenaSlice {
        self.plan.root()
    }

    /// Retained tree layers in bottom-up order. Unretained ping-pong layers are
    /// deliberately absent; callers reproduce their queried nodes from sources.
    pub fn retained_layers_bottom_up(&self) -> &[ArenaSlice] {
        &self.retained_layers_bottom_up
    }

    /// Per-group persistent LDE columns selected by the proof plan. Streaming
    /// groups are `None` and retain no evaluation storage after commitment.
    pub fn retained_evaluations(&self) -> &[Option<Vec<ArenaSlice>>] {
        &self.retained_evaluations
    }

    /// The sole commit-side D2H boundary: copy and synchronize the 32-byte root
    /// immediately before mixing it into the host Fiat-Shamir transcript.
    pub fn read_root_at_transcript_boundary(&self) -> Result<Blake2sHash, PreparedCommitError> {
        let mut root = Blake2sHash::default();
        unsafe {
            self.arena.context().memcpy_d2h_async(
                root.0.as_mut_ptr().cast(),
                self.plan.root().as_void_ptr().cast_const(),
                core::mem::size_of::<Blake2sHash>(),
            )?;
        }
        self.arena.context().sync()?;
        Ok(root)
    }
}

fn validate_slot_shape(
    requirements: &CommitWorkspaceRequirements,
    slots: &CommitWorkspaceSlots,
) -> Result<(), PreparedCommitError> {
    check_count("groups", requirements.groups.len(), slots.groups.len())?;
    check_count(
        "retained_layers",
        requirements.retained_layers.len(),
        slots.retained_layers.len(),
    )?;
    check_count(
        "tail_outputs",
        requirements.tail_outputs.len(),
        slots.tail_outputs.len(),
    )?;
    if requirements.merkle_scratch_words.is_some() != slots.merkle_scratch.is_some() {
        return Err(PreparedCommitError::SlotShapeMismatch {
            role: "merkle_scratch",
            expected: usize::from(requirements.merkle_scratch_words.is_some()),
            actual: usize::from(slots.merkle_scratch.is_some()),
        });
    }
    if requirements.tail_pointer_words.is_some() != slots.tail_level_ptrs.is_some() {
        return Err(PreparedCommitError::SlotShapeMismatch {
            role: "tail_level_ptrs",
            expected: usize::from(requirements.tail_pointer_words.is_some()),
            actual: usize::from(slots.tail_level_ptrs.is_some()),
        });
    }
    for (requirement, group_slots) in requirements.groups.iter().zip(&slots.groups) {
        check_count(
            "group_batches",
            requirement.batches.len(),
            group_slots.batches.len(),
        )?;
    }
    Ok(())
}

fn validate_merkle_slot_shape(
    requirements: &MerkleFromLeavesRequirements,
    slots: &MerkleFromLeavesSlots,
) -> Result<(), PreparedCommitError> {
    check_count(
        "retained_layers",
        requirements.retained_layers.len(),
        slots.retained_layers.len(),
    )?;
    check_count(
        "tail_outputs",
        requirements.tail_outputs.len(),
        slots.tail_outputs.len(),
    )?;
    if requirements.merkle_scratch_words.is_some() != slots.merkle_scratch.is_some() {
        return Err(PreparedCommitError::SlotShapeMismatch {
            role: "merkle_scratch",
            expected: usize::from(requirements.merkle_scratch_words.is_some()),
            actual: usize::from(slots.merkle_scratch.is_some()),
        });
    }
    if requirements.tail_pointer_words.is_some() != slots.tail_level_ptrs.is_some() {
        return Err(PreparedCommitError::SlotShapeMismatch {
            role: "tail_level_ptrs",
            expected: usize::from(requirements.tail_pointer_words.is_some()),
            actual: usize::from(slots.tail_level_ptrs.is_some()),
        });
    }
    Ok(())
}

fn check_count(
    role: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), PreparedCommitError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PreparedCommitError::SlotShapeMismatch {
            role,
            expected,
            actual,
        })
    }
}

fn ensure_distinct(ids: &[ArenaSlotId]) -> Result<(), PreparedCommitError> {
    let mut seen = BTreeSet::new();
    for &id in ids {
        if !seen.insert(id) {
            return Err(PreparedCommitError::DuplicateSlot(id));
        }
    }
    Ok(())
}

pub(crate) fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedCommitError> {
    truncate_bound_slot(arena.bind(id)?, required_words, alignment_words)
}

/// Validate one bound slot's capacity and alignment, then truncate it to the
/// logical requirement. Pooled slots may be larger than any single logical
/// buffer; END-relative twiddle bases and layer extents derive from
/// `len_words()` and must never observe the pooled surplus.
fn truncate_bound_slot(
    slice: ArenaSlice,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedCommitError> {
    if slice.len_words() < required_words {
        return Err(PreparedCommitError::SlotTooSmall {
            slot: slice.id(),
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedCommitError::MisalignedSlot {
            slot: slice.id(),
            alignment_words,
        });
    }
    Ok(slice.truncated(required_words))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; the binder must expose only the logical extent so
        // END-relative twiddle bases and layer extents never see the surplus.
        let oversized = ArenaSlice::dangling_for_test(1, 1024);
        let bound = truncate_bound_slot(oversized, 384, 1).unwrap();
        assert_eq!(bound.len_words(), 384);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(1, 128), 384, 1),
            Err(PreparedCommitError::SlotTooSmall { .. })
        ));
    }

    fn config(blowup: u32) -> CommitWorkspaceConfig {
        CommitWorkspaceConfig {
            log_blowup_factor: blowup,
            lifting_log_size: 10,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 4,
        }
    }

    #[test]
    fn requirements_plan_mixed_logs_pruned_ping_pong_and_tail() {
        let requirements =
            commit_workspace_requirements(config(1), &[vec![6; 16], vec![7; 16], vec![8, 8, 9]])
                .unwrap();

        assert_eq!(requirements.lde_tile_words, 16 << 8);
        assert_eq!(requirements.twiddle_words, 1 << 9);
        assert_eq!(requirements.leaf_state_words, 8 << 10);
        assert_eq!(requirements.merkle_scratch_words, Some(8 << 9));
        assert_eq!(
            requirements
                .retained_layers
                .iter()
                .map(|layer| layer.log_size)
                .collect::<Vec<_>>(),
            vec![6, 5, 4]
        );
        assert_eq!(
            requirements
                .tail_outputs
                .iter()
                .map(|layer| layer.log_size)
                .collect::<Vec<_>>(),
            vec![3, 2, 1, 0]
        );
        assert_eq!(requirements.groups[2].batches.len(), 2);
    }

    #[test]
    fn blowup_greater_than_one_sizes_exact_sources_and_zero_tail() {
        let requirements =
            commit_workspace_requirements(config(3), &[vec![5; 16], vec![6, 6]]).unwrap();
        let first = requirements.groups[0].batches[0];
        assert_eq!(first.coefficient_log_size, 5);
        assert_eq!(first.evaluation_log_size, 8);
        assert_eq!(first.coefficient_size_words, 16);
        assert_eq!(requirements.lde_tile_words, 16 << 8);
        assert_eq!(requirements.twiddle_words, 1 << 8);

        let mut too_small = config(3);
        too_small.lifting_log_size = 7;
        assert!(matches!(
            commit_workspace_requirements(too_small, &[vec![5]]),
            Err(PreparedCommitError::EvaluationExceedsLifting {
                evaluation_log_size: 8,
                lifting_log_size: 7,
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_blowup_and_noncanonical_or_oversized_groups() {
        assert_eq!(
            commit_workspace_requirements(config(0), &[vec![6]]).unwrap_err(),
            PreparedCommitError::InvalidBlowup(0)
        );
        assert!(matches!(
            commit_workspace_requirements(config(2), &[vec![8; 16], vec![7]]),
            Err(PreparedCommitError::NonCanonicalColumnOrder { .. })
        ));
        assert_eq!(
            commit_workspace_requirements(config(1), &[vec![6; 17]]).unwrap_err(),
            PreparedCommitError::InvalidFinalWidth(17)
        );
    }

    /// Native gate: setup/upload happens before capture, while eager and graph
    /// replay invoke the same allocation-free `launch` and produce one root.
    #[test]
    fn native_eager_and_capture_roots_match() {
        use super::super::exec_context::{ArenaLayout, ArenaSlotSpec, CudaExecContext};

        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return;
        }

        struct Slots {
            next_id: u32,
            next_word: usize,
            specs: Vec<ArenaSlotSpec>,
        }
        impl Slots {
            fn alloc(&mut self, words: usize, alignment_words: usize) -> ArenaSlotId {
                self.next_word = self.next_word.next_multiple_of(alignment_words);
                let id = ArenaSlotId(self.next_id);
                self.next_id += 1;
                self.specs.push(ArenaSlotSpec {
                    id,
                    offset_words: self.next_word,
                    len_words: words,
                    alignment_words,
                });
                self.next_word += words;
                id
            }
        }

        let config = CommitWorkspaceConfig {
            log_blowup_factor: 2,
            lifting_log_size: 6,
            unretained_bottom_layers: 2,
            max_fused_tail_levels: 4,
        };
        let logs = vec![vec![4, 4, 4]];
        let requirements = commit_workspace_requirements(config, &logs).unwrap();
        let mut allocator = Slots {
            next_id: 1,
            next_word: 0,
            specs: Vec::new(),
        };
        let coefficient_ids: Vec<_> = (0..3).map(|_| allocator.alloc(1 << 4, 1)).collect();
        let twiddle_id = allocator.alloc(requirements.twiddle_words, 1);
        let lde_tile = allocator.alloc(requirements.lde_tile_words, 1);
        let leaf_state =
            allocator.alloc(requirements.leaf_state_words, COMMIT_HASH_ALIGNMENT_WORDS);
        let merkle_scratch = requirements
            .merkle_scratch_words
            .map(|words| allocator.alloc(words, COMMIT_HASH_ALIGNMENT_WORDS));
        let retained_layers = requirements
            .retained_layers
            .iter()
            .map(|layer| allocator.alloc(layer.words, COMMIT_HASH_ALIGNMENT_WORDS))
            .collect();
        let tail_level_ptrs = requirements
            .tail_pointer_words
            .map(|words| allocator.alloc(words, COMMIT_POINTER_ALIGNMENT_WORDS));
        let tail_outputs = requirements
            .tail_outputs
            .iter()
            .map(|layer| allocator.alloc(layer.words, COMMIT_HASH_ALIGNMENT_WORDS))
            .collect();
        let groups = requirements
            .groups
            .iter()
            .map(|group| CommitGroupSlots {
                column_ptrs: allocator
                    .alloc(group.column_pointer_words, COMMIT_POINTER_ALIGNMENT_WORDS),
                column_log_sizes: allocator.alloc(group.column_log_size_words, 1),
                batches: group
                    .batches
                    .iter()
                    .map(|batch| CommitBatchSlots {
                        coefficient_ptrs: allocator.alloc(
                            batch.coefficient_pointer_words,
                            COMMIT_POINTER_ALIGNMENT_WORDS,
                        ),
                        coefficient_sizes: allocator.alloc(batch.coefficient_size_words, 1),
                        output_ptrs: allocator
                            .alloc(batch.output_pointer_words, COMMIT_POINTER_ALIGNMENT_WORDS),
                    })
                    .collect(),
            })
            .collect();
        let workspace_slots = CommitWorkspaceSlots {
            lde_tile,
            leaf_state,
            merkle_scratch,
            retained_layers,
            tail_level_ptrs,
            tail_outputs,
            groups,
        };
        let layout = ArenaLayout::new(
            allocator
                .next_word
                .next_multiple_of(COMMIT_HASH_ALIGNMENT_WORDS),
            &allocator.specs,
        )
        .unwrap();
        let arena = DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap();

        let coefficient_words: Vec<Vec<u32>> = (0..3)
            .map(|column| (0..(1 << 4)).map(|row| 1 + column * 17 + row).collect())
            .collect();
        for (&id, words) in coefficient_ids.iter().zip(&coefficient_words) {
            let destination = arena.bind(id).unwrap();
            unsafe {
                arena
                    .context()
                    .memcpy_h2d_async(
                        destination.as_void_ptr(),
                        words.as_ptr().cast(),
                        destination.len_bytes(),
                    )
                    .unwrap();
            }
        }
        let twiddle_words: Vec<u32> = (0..requirements.twiddle_words as u32)
            .map(|value| value.wrapping_mul(3).wrapping_add(1))
            .collect();
        let twiddles = arena.bind(twiddle_id).unwrap();
        unsafe {
            arena
                .context()
                .memcpy_h2d_async(
                    twiddles.as_void_ptr(),
                    twiddle_words.as_ptr().cast(),
                    twiddles.len_bytes(),
                )
                .unwrap();
        }
        arena.context().sync().unwrap();

        let columns = coefficient_ids
            .iter()
            .map(|&id| CommitCoefficientColumn {
                coefficients: arena.bind(id).unwrap(),
                log_size: 4,
            })
            .collect();
        let prepared = PreparedCommitGraph::prepare(
            &arena,
            config,
            &[CommitCoefficientGroup { columns }],
            twiddles,
            &workspace_slots,
        )
        .unwrap();

        prepared.launch().unwrap();
        let eager = prepared.read_root_at_transcript_boundary().unwrap();
        let capture = arena.context().capture().unwrap();
        prepared.launch().unwrap();
        let graph = capture.finish().unwrap();
        graph.launch(arena.context()).unwrap();
        let replay = prepared.read_root_at_transcript_boundary().unwrap();
        assert_eq!(eager, replay);
        drop(graph);
    }
}
