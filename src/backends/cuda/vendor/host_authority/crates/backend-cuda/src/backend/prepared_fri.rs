//! Prepared, arena-backed CUDA FRI fold and Merkle workspace.
//!
//! The transcript still owns every challenge and root boundary. This module
//! prepares the device-resident work between those boundaries: the original
//! circle-layer commitment, one exact fold round per transcript challenge, and
//! every fully retained FRI Merkle layer. Setup uploads the three stable QM31
//! coordinate pointer tables once. Launches contain only kernels on the proof's
//! explicit stream, so eager execution and graph capture call the same methods.

use core::ffi::c_void;
use std::collections::BTreeSet;

use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::vcs::blake2_hash::Blake2sHash;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};
use crate::columns::bindings::CudaSecureField;

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const SECURE_COORDINATES: usize = 4;
const HASH_WORDS: usize = core::mem::size_of::<Blake2sHash>() / WORD_BYTES;
const POINTER_WORDS: usize = core::mem::size_of::<*mut u32>().div_ceil(WORD_BYTES);
const LOG_PACKED_LEAF_SIZE: u32 = 2;

pub const FRI_POINTER_ALIGNMENT_WORDS: usize = core::mem::align_of::<*mut u32>() / WORD_BYTES;
pub const FRI_HASH_ALIGNMENT_WORDS: usize = core::mem::align_of::<Blake2sHash>() / WORD_BYTES;
pub const FRI_CHALLENGE_WORDS: usize = SECURE_COORDINATES;

/// Complete protocol/domain identity needed by the pure FRI workspace pass.
/// `twiddle_log_size` is the log2 word length of the inverse-twiddle buffer; it
/// may be larger than the FRI circle half-domain when a proof-wide tree is shared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriWorkspaceConfig {
    pub fri: FriConfig,
    pub circle_log_size: u32,
    pub twiddle_log_size: u32,
}

/// One retained hash layer, from leaves down to the root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriMerkleLayerRequirements {
    pub log_size: u32,
    pub words: usize,
}

/// Exact geometry of one committed FRI evaluation. `outgoing_fold_step` is
/// important: it is also the protocol rule deciding whether this tree packs four
/// adjacent QM31 rows into each leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriMerkleTreeRequirements {
    pub evaluation_log_size: u32,
    pub evaluation_words: usize,
    pub outgoing_fold_step: u32,
    pub log_rows_per_leaf: u32,
    pub layers_bottom_up: Vec<FriMerkleLayerRequirements>,
}

/// One challenge-bounded fold round. Round zero is circle-to-line followed by
/// `fold_step - 1` line folds; every later round contains line folds only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriRoundRequirements {
    pub input_log_size: u32,
    pub fold_step: u32,
    pub output_log_size: u32,
    /// Tree committed after this round, or `None` when the output is the last layer.
    pub output_tree: Option<usize>,
}

/// Exact arena capacity for one complete FRI commit sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriWorkspaceRequirements {
    pub config: FriWorkspaceConfig,
    pub last_layer_log_size: u32,
    pub twiddle_words: usize,
    pub evaluation_ping_words: usize,
    pub evaluation_pong_words: usize,
    pub coordinate_pointer_words: usize,
    pub trees: Vec<FriMerkleTreeRequirements>,
    pub rounds: Vec<FriRoundRequirements>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

/// Fully retained layers for one FRI tree, ordered leaves-to-root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriMerkleTreeSlots {
    pub layers_bottom_up: Vec<ArenaSlotId>,
}

/// Caller-selected logical slots. The input evaluation and inverse twiddles are
/// proof-wide sources supplied separately to [`PreparedFriGraph::prepare`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriWorkspaceSlots {
    pub evaluation_ping: ArenaSlotId,
    pub evaluation_pong: ArenaSlotId,
    pub input_coordinate_ptrs: ArenaSlotId,
    pub ping_coordinate_ptrs: ArenaSlotId,
    pub pong_coordinate_ptrs: ArenaSlotId,
    /// Compact snapshots for committed inner trees. Tree zero aliases the
    /// proof-wide quotient input and therefore has no snapshot slot.
    pub retained_tree_evaluations: Vec<ArenaSlotId>,
    pub retained_tree_coordinate_ptrs: Vec<ArenaSlotId>,
    /// One stable four-word SecureField slot per transcript-bounded fold round.
    pub folding_challenges: Vec<ArenaSlotId>,
    pub trees: Vec<FriMerkleTreeSlots>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedFriError {
    InvalidBlowup(u32),
    InvalidLastLayerDegreeBound(u32),
    InvalidCircleLogSize(u32),
    InvalidFoldStep(u32),
    InvalidLastLayerLogSize(u32),
    InvalidTwiddleLogSize(u32),
    FirstFoldPastLastLayer {
        circle_log_size: u32,
        fold_step: u32,
        last_layer_log_size: u32,
    },
    TwiddleDomainTooSmall {
        twiddle_log_size: u32,
        required_log_size: u32,
    },
    SizeOverflow,
    SlotShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    SourceAliasesWorkspace(ArenaSlotId),
    AliasedSourceSlot(ArenaSlotId),
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
    InputEvaluationTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    TwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    InvalidTreeIndex(usize),
    InvalidRoundIndex(usize),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedFriError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA FRI workspace: {self:?}")
    }
}

impl std::error::Error for PreparedFriError {}

impl From<ArenaError> for PreparedFriError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedFriError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl FriWorkspaceRequirements {
    /// Convert this pure geometry into named slots for a proof-wide liveness pass.
    pub fn arena_slot_requirements(
        &self,
        slots: &FriWorkspaceSlots,
    ) -> Result<Vec<FriArenaSlotRequirement>, PreparedFriError> {
        validate_slot_shape(self, slots)?;
        let mut output = vec![
            FriArenaSlotRequirement {
                id: slots.evaluation_ping,
                len_words: self.evaluation_ping_words,
                alignment_words: 1,
            },
            FriArenaSlotRequirement {
                id: slots.evaluation_pong,
                len_words: self.evaluation_pong_words,
                alignment_words: 1,
            },
            FriArenaSlotRequirement {
                id: slots.input_coordinate_ptrs,
                len_words: self.coordinate_pointer_words,
                alignment_words: FRI_POINTER_ALIGNMENT_WORDS,
            },
            FriArenaSlotRequirement {
                id: slots.ping_coordinate_ptrs,
                len_words: self.coordinate_pointer_words,
                alignment_words: FRI_POINTER_ALIGNMENT_WORDS,
            },
            FriArenaSlotRequirement {
                id: slots.pong_coordinate_ptrs,
                len_words: self.coordinate_pointer_words,
                alignment_words: FRI_POINTER_ALIGNMENT_WORDS,
            },
        ];
        output.extend(
            slots
                .retained_tree_evaluations
                .iter()
                .zip(self.trees.iter().skip(1))
                .map(|(&id, tree)| FriArenaSlotRequirement {
                    id,
                    len_words: tree.evaluation_words,
                    alignment_words: 1,
                }),
        );
        output.extend(slots.retained_tree_coordinate_ptrs.iter().map(|&id| {
            FriArenaSlotRequirement {
                id,
                len_words: self.coordinate_pointer_words,
                alignment_words: FRI_POINTER_ALIGNMENT_WORDS,
            }
        }));
        output.extend(
            slots
                .folding_challenges
                .iter()
                .map(|&id| FriArenaSlotRequirement {
                    id,
                    len_words: FRI_CHALLENGE_WORDS,
                    alignment_words: FRI_CHALLENGE_WORDS,
                }),
        );
        for (tree_slots, tree) in slots.trees.iter().zip(&self.trees) {
            output.extend(
                tree_slots
                    .layers_bottom_up
                    .iter()
                    .zip(&tree.layers_bottom_up)
                    .map(|(&id, layer)| FriArenaSlotRequirement {
                        id,
                        len_words: layer.words,
                        alignment_words: FRI_HASH_ALIGNMENT_WORDS,
                    }),
            );
        }
        ensure_distinct(output.iter().map(|entry| entry.id))?;
        Ok(output)
    }
}

/// Pure exact sizing pass. The generated tree and round order is the same order
/// consumed by `FriProver`: original circle tree, full-step inner trees, final
/// partial-step tree, and no tree for the final evaluation.
pub fn fri_workspace_requirements(
    config: FriWorkspaceConfig,
) -> Result<FriWorkspaceRequirements, PreparedFriError> {
    if !(1..=16).contains(&config.fri.log_blowup_factor) {
        return Err(PreparedFriError::InvalidBlowup(
            config.fri.log_blowup_factor,
        ));
    }
    if config.fri.log_last_layer_degree_bound > 10 {
        return Err(PreparedFriError::InvalidLastLayerDegreeBound(
            config.fri.log_last_layer_degree_bound,
        ));
    }
    if config.circle_log_size == 0 || config.circle_log_size >= 31 {
        return Err(PreparedFriError::InvalidCircleLogSize(
            config.circle_log_size,
        ));
    }
    if config.fri.fold_step == 0 || config.fri.fold_step >= 31 {
        return Err(PreparedFriError::InvalidFoldStep(config.fri.fold_step));
    }
    let last_layer_log_size = config
        .fri
        .log_last_layer_degree_bound
        .checked_add(config.fri.log_blowup_factor)
        .ok_or(PreparedFriError::SizeOverflow)?;
    if last_layer_log_size >= 31 {
        return Err(PreparedFriError::InvalidLastLayerLogSize(
            last_layer_log_size,
        ));
    }
    let required_twiddle_log = config.circle_log_size - 1;
    if config.twiddle_log_size >= 31 {
        return Err(PreparedFriError::InvalidTwiddleLogSize(
            config.twiddle_log_size,
        ));
    }
    if config.twiddle_log_size < required_twiddle_log {
        return Err(PreparedFriError::TwiddleDomainTooSmall {
            twiddle_log_size: config.twiddle_log_size,
            required_log_size: required_twiddle_log,
        });
    }
    if config.circle_log_size < last_layer_log_size + config.fri.fold_step {
        return Err(PreparedFriError::FirstFoldPastLastLayer {
            circle_log_size: config.circle_log_size,
            fold_step: config.fri.fold_step,
            last_layer_log_size,
        });
    }

    let mut trees = Vec::new();
    let mut rounds = Vec::new();
    let mut input_log_size = config.circle_log_size;
    loop {
        let fold_step = config
            .fri
            .fold_step
            .min(input_log_size - last_layer_log_size);
        let tree_index = trees.len();
        trees.push(tree_requirements(input_log_size, fold_step)?);
        let output_log_size = input_log_size - fold_step;
        rounds.push(FriRoundRequirements {
            input_log_size,
            fold_step,
            output_log_size,
            output_tree: (output_log_size > last_layer_log_size).then_some(tree_index + 1),
        });
        if output_log_size == last_layer_log_size {
            break;
        }
        input_log_size = output_log_size;
    }

    let max_line_words = secure_evaluation_words(config.circle_log_size - 1)?;
    Ok(FriWorkspaceRequirements {
        config,
        last_layer_log_size,
        twiddle_words: pow2_words(config.twiddle_log_size)?,
        evaluation_ping_words: max_line_words,
        evaluation_pong_words: max_line_words,
        coordinate_pointer_words: SECURE_COORDINATES
            .checked_mul(POINTER_WORDS)
            .ok_or(PreparedFriError::SizeOverflow)?,
        trees,
        rounds,
    })
}

fn tree_requirements(
    evaluation_log_size: u32,
    outgoing_fold_step: u32,
) -> Result<FriMerkleTreeRequirements, PreparedFriError> {
    let log_rows_per_leaf = if evaluation_log_size >= LOG_PACKED_LEAF_SIZE && outgoing_fold_step > 1
    {
        LOG_PACKED_LEAF_SIZE
    } else {
        0
    };
    let leaf_log_size = evaluation_log_size - log_rows_per_leaf;
    let layers_bottom_up = (0..=leaf_log_size)
        .rev()
        .map(|log_size| {
            Ok(FriMerkleLayerRequirements {
                log_size,
                words: hash_words(log_size)?,
            })
        })
        .collect::<Result<_, PreparedFriError>>()?;
    Ok(FriMerkleTreeRequirements {
        evaluation_log_size,
        evaluation_words: secure_evaluation_words(evaluation_log_size)?,
        outgoing_fold_step,
        log_rows_per_leaf,
        layers_bottom_up,
    })
}

fn pow2_words(log_size: u32) -> Result<usize, PreparedFriError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedFriError::SizeOverflow)
}

fn secure_evaluation_words(log_size: u32) -> Result<usize, PreparedFriError> {
    pow2_words(log_size)?
        .checked_mul(SECURE_COORDINATES)
        .ok_or(PreparedFriError::SizeOverflow)
}

fn hash_words(log_size: u32) -> Result<usize, PreparedFriError> {
    pow2_words(log_size)?
        .checked_mul(HASH_WORDS)
        .ok_or(PreparedFriError::SizeOverflow)
}

fn validate_slot_shape(
    requirements: &FriWorkspaceRequirements,
    slots: &FriWorkspaceSlots,
) -> Result<(), PreparedFriError> {
    if slots.folding_challenges.len() != requirements.rounds.len() {
        return Err(PreparedFriError::SlotShapeMismatch {
            role: "folding challenges",
            expected: requirements.rounds.len(),
            actual: slots.folding_challenges.len(),
        });
    }
    let retained_tree_count = requirements.trees.len().saturating_sub(1);
    if slots.retained_tree_evaluations.len() != retained_tree_count {
        return Err(PreparedFriError::SlotShapeMismatch {
            role: "retained tree evaluations",
            expected: retained_tree_count,
            actual: slots.retained_tree_evaluations.len(),
        });
    }
    if slots.retained_tree_coordinate_ptrs.len() != retained_tree_count {
        return Err(PreparedFriError::SlotShapeMismatch {
            role: "retained tree coordinate pointers",
            expected: retained_tree_count,
            actual: slots.retained_tree_coordinate_ptrs.len(),
        });
    }
    if slots.trees.len() != requirements.trees.len() {
        return Err(PreparedFriError::SlotShapeMismatch {
            role: "trees",
            expected: requirements.trees.len(),
            actual: slots.trees.len(),
        });
    }
    for (tree_slots, tree) in slots.trees.iter().zip(&requirements.trees) {
        if tree_slots.layers_bottom_up.len() != tree.layers_bottom_up.len() {
            return Err(PreparedFriError::SlotShapeMismatch {
                role: "tree layers",
                expected: tree.layers_bottom_up.len(),
                actual: tree_slots.layers_bottom_up.len(),
            });
        }
    }
    Ok(())
}

fn ensure_distinct(ids: impl IntoIterator<Item = ArenaSlotId>) -> Result<(), PreparedFriError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(PreparedFriError::DuplicateSlot(id));
        }
    }
    Ok(())
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedFriError> {
    truncate_bound_slot(arena.bind(id)?, required_words, alignment_words)
}

/// Validate one bound slot's capacity and alignment, then truncate it to the
/// logical requirement. Pooled slots may be larger than any single logical
/// buffer; fold extents and retained-layer sizes derive from `len_words()`
/// and must never observe the pooled surplus.
fn truncate_bound_slot(
    slice: ArenaSlice,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedFriError> {
    if slice.len_words() < required_words {
        return Err(PreparedFriError::SlotTooSmall {
            slot: slice.id(),
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedFriError::MisalignedSlot {
            slot: slice.id(),
            alignment_words,
        });
    }
    Ok(slice.truncated(required_words))
}

/// Selects which fold pipeline [`PreparedFriGraph::launch_round`] submits.
/// Both modes produce byte-identical folded evaluations, retained snapshots
/// and tree roots; `FusedTriple` is opt-in via `STWO_CUDA_FRI_FOLD_FUSED=1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FriFoldLaunchMode {
    /// One kernel per sub-fold plus the circle-fold destination memset
    /// (default; the proven fallback).
    PerFold,
    /// One 8-to-1 kernel per complete `fold_step == 3` round: each thread
    /// reads its eight source elements once and applies the three fold stages
    /// in registers. Ineligible rounds — the final partial round whose
    /// `fold_step < 3` — fail closed to the per-fold kernels.
    FusedTriple,
}

/// Pure `STWO_CUDA_FRI_FOLD_FUSED` parse, unit-testable without an
/// environment: only the literal `"1"` opts into the fused lane.
fn fri_fold_fused_flag_from(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// `STWO_CUDA_FRI_FOLD_FUSED=1` opts the default [`PreparedFriGraph::launch_round`]
/// into the fused triple-fold lane. Read once per process so eager runs,
/// capture and replay all observe one mode. Default OFF: the per-fold kernels
/// stay the proven fallback.
fn fri_fold_fused_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        fri_fold_fused_flag_from(std::env::var("STWO_CUDA_FRI_FOLD_FUSED").ok().as_deref())
    })
}

fn fri_fold_mode_from_env() -> FriFoldLaunchMode {
    if fri_fold_fused_enabled() {
        FriFoldLaunchMode::FusedTriple
    } else {
        FriFoldLaunchMode::PerFold
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvaluationBuffer {
    Input,
    Ping,
    Pong,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FoldKind {
    CircleToLine,
    Line,
}

/// Pure twiddle-offset math shared by the per-fold and fused launches: a line
/// fold over `n` elements reads the `n/2` twiddles at `twiddle_words - n`; the
/// circle fold reads its `n/2`-word tail directly at `twiddle_words - n/2`
/// (its `get_circle_twiddle` indexing consumes the packed half-domain).
fn fold_twiddle_offset(
    twiddle_words: usize,
    n: u32,
    kind: FoldKind,
) -> Result<u32, PreparedFriError> {
    let consumed_words = match kind {
        FoldKind::CircleToLine => (n >> 1) as usize,
        FoldKind::Line => n as usize,
    };
    twiddle_words
        .checked_sub(consumed_words)
        .and_then(|offset| u32::try_from(offset).ok())
        .ok_or(PreparedFriError::SizeOverflow)
}

#[derive(Clone, Copy, Debug)]
struct EvaluationBinding {
    values: ArenaSlice,
    coordinate_ptrs: ArenaSlice,
    coordinate_stride: usize,
}

#[derive(Clone, Copy, Debug)]
struct FoldLaunch {
    kind: FoldKind,
    n: u32,
    twiddle_offset: u32,
    input: EvaluationBinding,
    output: EvaluationBinding,
    alpha_squarings: u32,
}

#[derive(Debug)]
struct PreparedRound {
    folds: Vec<FoldLaunch>,
    folding_challenge: ArenaSlice,
    output: EvaluationBinding,
    output_log_size: u32,
    output_tree: Option<usize>,
}

#[derive(Debug)]
struct PreparedTree {
    evaluation: EvaluationBinding,
    evaluation_log_size: u32,
    log_rows_per_leaf: u32,
    layers_bottom_up: Vec<ArenaSlice>,
    layer_log_sizes_bottom_up: Vec<u32>,
}

/// Device view of one QM31 evaluation. Coordinate columns use a stable fixed
/// stride; only their first `2^log_size` words are live.
#[derive(Clone, Copy, Debug)]
pub struct PreparedFriEvaluation {
    pub values: ArenaSlice,
    pub coordinate_ptrs: ArenaSlice,
    pub coordinate_stride: usize,
    pub log_size: u32,
}

/// Prepared ordinary-Blake2s FRI launch graph. This deliberately has no legacy
/// fallback: invalid geometry, missing arena capacity, or a foreign context is an
/// error before any transcript-visible kernel executes.
pub struct PreparedFriGraph<'a> {
    arena: &'a DeviceArena,
    requirements: FriWorkspaceRequirements,
    twiddles: ArenaSlice,
    trees: Vec<PreparedTree>,
    rounds: Vec<PreparedRound>,
}

impl<'a> PreparedFriGraph<'a> {
    /// Bind every slot, upload stable coordinate tables on the explicit proof
    /// stream, then synchronize exactly once before capture is allowed.
    pub fn prepare(
        arena: &'a DeviceArena,
        config: FriWorkspaceConfig,
        input_evaluation: ArenaSlice,
        inverse_twiddles: ArenaSlice,
        slots: &FriWorkspaceSlots,
    ) -> Result<Self, PreparedFriError> {
        let requirements = fri_workspace_requirements(config)?;
        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        let workspace_ids: BTreeSet<_> = slot_requirements.iter().map(|entry| entry.id).collect();
        let context_token = arena.context().identity_token();
        for source in [input_evaluation, inverse_twiddles] {
            if source.context_token() != context_token {
                return Err(PreparedFriError::ContextMismatch(source.id()));
            }
            if workspace_ids.contains(&source.id()) {
                return Err(PreparedFriError::SourceAliasesWorkspace(source.id()));
            }
        }
        if input_evaluation.id() == inverse_twiddles.id() {
            return Err(PreparedFriError::AliasedSourceSlot(input_evaluation.id()));
        }

        let required_input_words = secure_evaluation_words(config.circle_log_size)?;
        if input_evaluation.len_words() < required_input_words {
            return Err(PreparedFriError::InputEvaluationTooSmall {
                required_words: required_input_words,
                actual_words: input_evaluation.len_words(),
            });
        }
        if inverse_twiddles.len_words() < requirements.twiddle_words {
            return Err(PreparedFriError::TwiddlesTooSmall {
                required_words: requirements.twiddle_words,
                actual_words: inverse_twiddles.len_words(),
            });
        }

        let ping = bind_slot(
            arena,
            slots.evaluation_ping,
            requirements.evaluation_ping_words,
            1,
        )?;
        let pong = bind_slot(
            arena,
            slots.evaluation_pong,
            requirements.evaluation_pong_words,
            1,
        )?;
        let input_ptrs = bind_slot(
            arena,
            slots.input_coordinate_ptrs,
            requirements.coordinate_pointer_words,
            FRI_POINTER_ALIGNMENT_WORDS,
        )?;
        let ping_ptrs = bind_slot(
            arena,
            slots.ping_coordinate_ptrs,
            requirements.coordinate_pointer_words,
            FRI_POINTER_ALIGNMENT_WORDS,
        )?;
        let pong_ptrs = bind_slot(
            arena,
            slots.pong_coordinate_ptrs,
            requirements.coordinate_pointer_words,
            FRI_POINTER_ALIGNMENT_WORDS,
        )?;
        let retained_values = slots
            .retained_tree_evaluations
            .iter()
            .zip(requirements.trees.iter().skip(1))
            .map(|(&id, tree)| bind_slot(arena, id, tree.evaluation_words, 1))
            .collect::<Result<Vec<_>, _>>()?;
        let retained_ptrs = slots
            .retained_tree_coordinate_ptrs
            .iter()
            .map(|&id| {
                bind_slot(
                    arena,
                    id,
                    requirements.coordinate_pointer_words,
                    FRI_POINTER_ALIGNMENT_WORDS,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let folding_challenges = slots
            .folding_challenges
            .iter()
            .map(|&id| bind_slot(arena, id, FRI_CHALLENGE_WORDS, FRI_CHALLENGE_WORDS))
            .collect::<Result<Vec<_>, _>>()?;

        let input = EvaluationBinding {
            values: input_evaluation,
            coordinate_ptrs: input_ptrs,
            coordinate_stride: pow2_words(config.circle_log_size)?,
        };
        let line_stride = pow2_words(config.circle_log_size - 1)?;
        let ping = EvaluationBinding {
            values: ping,
            coordinate_ptrs: ping_ptrs,
            coordinate_stride: line_stride,
        };
        let pong = EvaluationBinding {
            values: pong,
            coordinate_ptrs: pong_ptrs,
            coordinate_stride: line_stride,
        };
        let retained = retained_values
            .into_iter()
            .zip(retained_ptrs)
            .zip(requirements.trees.iter().skip(1))
            .map(|((values, coordinate_ptrs), tree)| {
                Ok(EvaluationBinding {
                    values,
                    coordinate_ptrs,
                    coordinate_stride: pow2_words(tree.evaluation_log_size)?,
                })
            })
            .collect::<Result<Vec<_>, PreparedFriError>>()?;

        for binding in [input, ping, pong]
            .into_iter()
            .chain(retained.iter().copied())
        {
            let pointers: Vec<usize> = (0..SECURE_COORDINATES)
                .map(|coordinate| unsafe {
                    binding
                        .values
                        .as_u32_ptr()
                        .add(coordinate * binding.coordinate_stride) as usize
                })
                .collect();
            unsafe {
                arena.context().memcpy_h2d_async(
                    binding.coordinate_ptrs.as_void_ptr(),
                    pointers.as_ptr().cast(),
                    pointers.len() * core::mem::size_of::<usize>(),
                )?;
            }
        }

        let mut tree_layers = Vec::with_capacity(requirements.trees.len());
        for (tree_slots, tree) in slots.trees.iter().zip(&requirements.trees) {
            tree_layers.push(
                tree_slots
                    .layers_bottom_up
                    .iter()
                    .zip(&tree.layers_bottom_up)
                    .map(|(&id, layer)| bind_slot(arena, id, layer.words, FRI_HASH_ALIGNMENT_WORDS))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        let binding = |which: EvaluationBuffer| match which {
            EvaluationBuffer::Input => input,
            EvaluationBuffer::Ping => ping,
            EvaluationBuffer::Pong => pong,
        };
        let mut current = EvaluationBuffer::Input;
        let mut trees = vec![PreparedTree {
            evaluation: input,
            evaluation_log_size: requirements.trees[0].evaluation_log_size,
            log_rows_per_leaf: requirements.trees[0].log_rows_per_leaf,
            layers_bottom_up: tree_layers[0].clone(),
            layer_log_sizes_bottom_up: requirements.trees[0]
                .layers_bottom_up
                .iter()
                .map(|layer| layer.log_size)
                .collect(),
        }];
        let mut retained = retained.into_iter();
        let mut rounds = Vec::with_capacity(requirements.rounds.len());
        for (round_index, round) in requirements.rounds.iter().enumerate() {
            let mut folds = Vec::with_capacity(round.fold_step as usize);
            let mut log_size = round.input_log_size;
            for fold_index in 0..round.fold_step {
                let next = match current {
                    EvaluationBuffer::Input | EvaluationBuffer::Pong => EvaluationBuffer::Ping,
                    EvaluationBuffer::Ping => EvaluationBuffer::Pong,
                };
                let n = u32::try_from(pow2_words(log_size)?)
                    .map_err(|_| PreparedFriError::SizeOverflow)?;
                let kind = if round_index == 0 && fold_index == 0 {
                    FoldKind::CircleToLine
                } else {
                    FoldKind::Line
                };
                folds.push(FoldLaunch {
                    kind,
                    n,
                    twiddle_offset: fold_twiddle_offset(requirements.twiddle_words, n, kind)?,
                    input: binding(current),
                    output: binding(next),
                    alpha_squarings: fold_index,
                });
                current = next;
                log_size -= 1;
            }
            let output = binding(current);
            if let Some(tree_index) = round.output_tree {
                let tree_requirement = &requirements.trees[tree_index];
                let evaluation = retained
                    .next()
                    .expect("slot validation covers every committed inner FRI tree");
                trees.push(PreparedTree {
                    evaluation,
                    evaluation_log_size: tree_requirement.evaluation_log_size,
                    log_rows_per_leaf: tree_requirement.log_rows_per_leaf,
                    layers_bottom_up: tree_layers[tree_index].clone(),
                    layer_log_sizes_bottom_up: tree_requirement
                        .layers_bottom_up
                        .iter()
                        .map(|layer| layer.log_size)
                        .collect(),
                });
            }
            rounds.push(PreparedRound {
                folds,
                folding_challenge: folding_challenges[round_index],
                output,
                output_log_size: round.output_log_size,
                output_tree: round.output_tree,
            });
        }
        debug_assert_eq!(trees.len(), requirements.trees.len());
        debug_assert!(retained.next().is_none());

        // Descriptor host storage may be released only after the explicit stream
        // has consumed every coordinate-table upload. No launch method synchronizes.
        arena.context().sync()?;

        Ok(Self {
            arena,
            requirements,
            twiddles: inverse_twiddles,
            trees,
            rounds,
        })
    }

    pub fn requirements(&self) -> &FriWorkspaceRequirements {
        &self.requirements
    }

    pub fn tree_count(&self) -> usize {
        self.trees.len()
    }

    pub fn round_count(&self) -> usize {
        self.rounds.len()
    }

    /// Fully retained hash layers for query decommitment, leaves first and root
    /// last. Their exact logical lengths are in `requirements().trees[index]`;
    /// arena slices may be capacity-sized by a proof-wide liveness allocator.
    pub fn tree_layers_bottom_up(
        &self,
        tree_index: usize,
    ) -> Result<&[ArenaSlice], PreparedFriError> {
        self.trees
            .get(tree_index)
            .map(|tree| tree.layers_bottom_up.as_slice())
            .ok_or(PreparedFriError::InvalidTreeIndex(tree_index))
    }

    /// Stable evaluation backing one committed FRI tree. Tree zero aliases the
    /// quotient input; inner trees use compact snapshots retained through
    /// decommitment instead of the subsequently overwritten ping/pong buffers.
    pub fn tree_evaluation(
        &self,
        tree_index: usize,
    ) -> Result<PreparedFriEvaluation, PreparedFriError> {
        let tree = self
            .trees
            .get(tree_index)
            .ok_or(PreparedFriError::InvalidTreeIndex(tree_index))?;
        Ok(PreparedFriEvaluation {
            values: tree.evaluation.values,
            coordinate_ptrs: tree.evaluation.coordinate_ptrs,
            coordinate_stride: tree.evaluation.coordinate_stride,
            log_size: tree.evaluation_log_size,
        })
    }

    /// Commit the original circle evaluation. Callers mix [`Self::read_tree_root`]
    /// into the transcript before drawing the first folding challenge.
    pub fn launch_first_tree(&self) -> Result<(), PreparedFriError> {
        self.launch_tree(0)
    }

    /// Execute exactly one challenge-bounded fold round from its stable device
    /// challenge slot and, unless it reached the final layer, commit its output
    /// tree. No host value is captured into the graph executable. The fold
    /// pipeline defaults to the proven per-fold kernels;
    /// `STWO_CUDA_FRI_FOLD_FUSED=1` (read once per process) opts into the fused
    /// triple-fold lane. Both lanes produce byte-identical outputs.
    pub fn launch_round(&self, round_index: usize) -> Result<Option<usize>, PreparedFriError> {
        self.launch_round_with_mode(round_index, fri_fold_mode_from_env())
    }

    /// Explicit-mode variant of [`Self::launch_round`] used by the parity
    /// tests to exercise both fold lanes in one process. The retained-snapshot
    /// d2d and the tree commitment are identical in both modes: the fused lane
    /// writes the round output to the same ping/pong destination the third
    /// per-fold launch writes, so `preserve_tree_evaluation` snapshots the same
    /// bytes — the value AFTER all three sub-folds of the round.
    pub fn launch_round_with_mode(
        &self,
        round_index: usize,
        mode: FriFoldLaunchMode,
    ) -> Result<Option<usize>, PreparedFriError> {
        self.launch_round_folds_only_with_mode(round_index, mode)?;
        let round = self
            .rounds
            .get(round_index)
            .ok_or(PreparedFriError::InvalidRoundIndex(round_index))?;
        if let Some(tree_index) = round.output_tree {
            self.preserve_tree_evaluation(tree_index, round.output)?;
            self.launch_tree(tree_index)?;
        }
        Ok(round.output_tree)
    }

    /// Run only the folds for a round. Production commitment uses
    /// [`Self::launch_round`] so committed inner outputs are retained for later
    /// decommitment; this lower-level entry remains useful for focused kernels.
    pub fn launch_round_folds_only(&self, round_index: usize) -> Result<(), PreparedFriError> {
        self.launch_round_folds_only_with_mode(round_index, fri_fold_mode_from_env())
    }

    /// Explicit-mode variant of [`Self::launch_round_folds_only`]. In
    /// [`FriFoldLaunchMode::FusedTriple`] a complete three-fold round runs as
    /// one 8-to-1 kernel; any other geometry (the final partial round with
    /// `fold_step < 3`) fails closed to the per-fold kernels.
    pub fn launch_round_folds_only_with_mode(
        &self,
        round_index: usize,
        mode: FriFoldLaunchMode,
    ) -> Result<(), PreparedFriError> {
        let round = self
            .rounds
            .get(round_index)
            .ok_or(PreparedFriError::InvalidRoundIndex(round_index))?;
        if mode == FriFoldLaunchMode::FusedTriple {
            if let [first, second, third] = round.folds.as_slice() {
                return self.launch_fused_triple(*first, *second, *third, round.folding_challenge);
            }
            // Fail closed: not a complete triple fold — run the exact
            // per-fold sequence below.
        }
        for launch in &round.folds {
            self.launch_fold(*launch, round.folding_challenge)?;
        }
        Ok(())
    }

    /// Stable destination for a device transcript's folding challenge output.
    pub fn round_challenge_slice(
        &self,
        round_index: usize,
    ) -> Result<ArenaSlice, PreparedFriError> {
        self.rounds
            .get(round_index)
            .map(|round| round.folding_challenge)
            .ok_or(PreparedFriError::InvalidRoundIndex(round_index))
    }

    /// Host-transcript migration boundary. Production device-transcript mode
    /// writes [`Self::round_challenge_slice`] directly and does not call this.
    pub fn upload_round_challenge_at_transcript_boundary(
        &self,
        round_index: usize,
        folding_alpha: SecureField,
    ) -> Result<(), PreparedFriError> {
        let destination = self.round_challenge_slice(round_index)?;
        let raw = CudaSecureField::from(folding_alpha).into_raw();
        unsafe {
            self.arena.context().memcpy_h2d_async(
                destination.as_void_ptr(),
                (&raw as *const stwo_backend_cuda_kernels::raw::CudaSecureField).cast(),
                core::mem::size_of_val(&raw),
            )?;
        }
        self.arena.context().sync()?;
        Ok(())
    }

    pub fn round_output(
        &self,
        round_index: usize,
    ) -> Result<PreparedFriEvaluation, PreparedFriError> {
        let round = self
            .rounds
            .get(round_index)
            .ok_or(PreparedFriError::InvalidRoundIndex(round_index))?;
        Ok(PreparedFriEvaluation {
            values: round.output.values,
            coordinate_ptrs: round.output.coordinate_ptrs,
            coordinate_stride: round.output.coordinate_stride,
            log_size: round.output_log_size,
        })
    }

    pub fn final_evaluation(&self) -> PreparedFriEvaluation {
        self.round_output(self.rounds.len() - 1)
            .expect("FRI requirements always contain a fold round")
    }

    pub fn tree_root(&self, tree_index: usize) -> Result<ArenaSlice, PreparedFriError> {
        Ok(*self
            .tree_layers_bottom_up(tree_index)?
            .last()
            .expect("pure sizing always includes a root layer"))
    }

    /// Transcript boundary: enqueue only the root D2H and synchronize the proof
    /// stream. No bulk evaluation or tree data crosses to the host here.
    pub fn read_tree_root(&self, tree_index: usize) -> Result<Blake2sHash, PreparedFriError> {
        let root = self.tree_root(tree_index)?;
        let mut host = Blake2sHash::default();
        unsafe {
            self.arena.context().memcpy_d2h_async(
                (&mut host as *mut Blake2sHash).cast::<c_void>(),
                root.as_void_ptr().cast_const(),
                core::mem::size_of::<Blake2sHash>(),
            )?;
        }
        self.arena.context().sync()?;
        Ok(host)
    }

    fn launch_fold(
        &self,
        launch: FoldLaunch,
        folding_challenge: ArenaSlice,
    ) -> Result<(), PreparedFriError> {
        let input_ptrs = launch.input.coordinate_ptrs.as_u32_ptr().cast::<*mut u32>();
        let output_ptrs = launch
            .output
            .coordinate_ptrs
            .as_u32_ptr()
            .cast::<*mut u32>();
        let alpha = folding_challenge
            .as_u32_ptr()
            .cast::<stwo_backend_cuda_kernels::raw::CudaSecureField>()
            .cast_const();
        let stream = self.arena.context().stream_raw().as_ptr();
        // The reference circle fold is an accumulator (`dst = dst*alpha^2 +
        // fold`). Its public caller supplies a zeroed destination. Preserve that
        // exact semantic without an allocation; the first line output occupies
        // the complete fixed-stride ping buffer.
        if launch.kind == FoldKind::CircleToLine {
            unsafe {
                self.arena.context().memset_async(
                    launch.output.values.as_void_ptr(),
                    0,
                    SECURE_COORDINATES * launch.output.coordinate_stride * WORD_BYTES,
                )?;
            }
        }
        let code = unsafe {
            match launch.kind {
                FoldKind::CircleToLine => {
                    stwo_backend_cuda_kernels::raw::stwo_fold_circle_into_line_on(
                        self.twiddles.as_u32_ptr(),
                        launch.twiddle_offset,
                        launch.n,
                        input_ptrs,
                        alpha,
                        launch.alpha_squarings,
                        output_ptrs,
                        stream,
                    )
                }
                FoldKind::Line => stwo_backend_cuda_kernels::raw::stwo_fold_line_on(
                    self.twiddles.as_u32_ptr(),
                    launch.twiddle_offset,
                    launch.n,
                    input_ptrs,
                    alpha,
                    launch.alpha_squarings,
                    output_ptrs,
                    stream,
                ),
            }
        };
        check_cuda("prepared_fri_fold", code)?;
        Ok(())
    }

    /// One 8-to-1 kernel replacing the three per-fold launches of a complete
    /// `fold_step == 3` round (`fri_fold_fused.cu`). Byte identity with the
    /// per-fold sequence is argued in the kernel file: per output element the
    /// exact same field-op sequence runs on the same operands (the twiddle
    /// offsets below are the three replaced launches' own values, and the
    /// per-stage alphas are the identical repeated-squaring chain), and exact
    /// modular arithmetic makes the regrouped evaluation bit-identical. The
    /// per-fold lane's circle-fold destination memset is skipped: its only
    /// effect is the zero accumulator input, which the kernel replicates in
    /// registers, and no consumer reads the skipped scratch bytes (every
    /// consumer reads exactly `2^log_size` live words per coordinate).
    fn launch_fused_triple(
        &self,
        first: FoldLaunch,
        second: FoldLaunch,
        third: FoldLaunch,
        folding_challenge: ArenaSlice,
    ) -> Result<(), PreparedFriError> {
        debug_assert_eq!(first.alpha_squarings, 0);
        debug_assert_eq!(second.alpha_squarings, 1);
        debug_assert_eq!(third.alpha_squarings, 2);
        debug_assert_eq!(second.kind, FoldKind::Line);
        debug_assert_eq!(third.kind, FoldKind::Line);
        debug_assert_eq!(second.n, first.n >> 1);
        debug_assert_eq!(third.n, first.n >> 2);
        let alpha = folding_challenge
            .as_u32_ptr()
            .cast::<stwo_backend_cuda_kernels::raw::CudaSecureField>()
            .cast_const();
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_fri_fold_fused3_on(
                self.twiddles.as_u32_ptr(),
                first.twiddle_offset,
                second.twiddle_offset,
                third.twiddle_offset,
                first.n,
                u32::from(first.kind == FoldKind::CircleToLine),
                first.input.coordinate_ptrs.as_u32_ptr().cast::<*mut u32>(),
                alpha,
                third.output.coordinate_ptrs.as_u32_ptr().cast::<*mut u32>(),
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("prepared_fri_fold_fused3", code)?;
        Ok(())
    }

    fn preserve_tree_evaluation(
        &self,
        tree_index: usize,
        source: EvaluationBinding,
    ) -> Result<(), PreparedFriError> {
        let tree = self
            .trees
            .get(tree_index)
            .ok_or(PreparedFriError::InvalidTreeIndex(tree_index))?;
        let coordinate_words = pow2_words(tree.evaluation_log_size)?;
        let coordinate_bytes = coordinate_words
            .checked_mul(WORD_BYTES)
            .ok_or(PreparedFriError::SizeOverflow)?;
        for coordinate in 0..SECURE_COORDINATES {
            unsafe {
                self.arena.context().memcpy_d2d_async(
                    tree.evaluation
                        .values
                        .as_u32_ptr()
                        .add(coordinate * tree.evaluation.coordinate_stride)
                        .cast(),
                    source
                        .values
                        .as_u32_ptr()
                        .add(coordinate * source.coordinate_stride)
                        .cast(),
                    coordinate_bytes,
                )?;
            }
        }
        Ok(())
    }

    fn launch_tree(&self, tree_index: usize) -> Result<(), PreparedFriError> {
        let tree = self
            .trees
            .get(tree_index)
            .ok_or(PreparedFriError::InvalidTreeIndex(tree_index))?;
        let evaluation_size = u32::try_from(pow2_words(tree.evaluation_log_size)?)
            .map_err(|_| PreparedFriError::SizeOverflow)?;
        let leaf = tree.layers_bottom_up[0];
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_blake2s_fri_leaf_on(
                evaluation_size,
                tree.evaluation
                    .coordinate_ptrs
                    .as_u32_ptr()
                    .cast::<*mut u32>(),
                tree.log_rows_per_leaf,
                leaf.as_u32_ptr()
                    .cast::<stwo_backend_cuda_kernels::raw::Blake2sHash>(),
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("prepared_fri_leaf", code)?;

        for (layer_index, layers) in tree.layers_bottom_up.windows(2).enumerate() {
            let input = layers[0];
            let output = layers[1];
            let output_hashes =
                u32::try_from(pow2_words(tree.layer_log_sizes_bottom_up[layer_index + 1])?)
                    .map_err(|_| PreparedFriError::SizeOverflow)?;
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_blake2s_layer_on(
                    input
                        .as_u32_ptr()
                        .cast::<stwo_backend_cuda_kernels::raw::Blake2sHash>(),
                    output_hashes,
                    output
                        .as_u32_ptr()
                        .cast::<stwo_backend_cuda_kernels::raw::Blake2sHash>(),
                    self.arena.context().stream_raw().as_ptr(),
                )
            };
            check_cuda("prepared_fri_merkle_layer", code)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_slots_truncate_pooled_surplus_to_the_logical_requirement() {
        // Pooled physical slots are sized to the LARGEST epoch-disjoint
        // sharer; the binder must expose only the logical extent so fold and
        // retained-layer extents never see the surplus.
        let oversized = ArenaSlice::dangling_for_test(6, 2048);
        let bound = truncate_bound_slot(oversized, 640, 1).unwrap();
        assert_eq!(bound.len_words(), 640);
        assert_eq!(bound.id(), oversized.id());
        assert_eq!(bound.as_u32_ptr(), oversized.as_u32_ptr());
        // Undersized slots still fail closed.
        assert!(matches!(
            truncate_bound_slot(ArenaSlice::dangling_for_test(6, 512), 640, 1),
            Err(PreparedFriError::SlotTooSmall { .. })
        ));
    }

    fn config(circle_log_size: u32, fold_step: u32, last_degree_log: u32) -> FriWorkspaceConfig {
        FriWorkspaceConfig {
            fri: FriConfig::new(last_degree_log, 1, 16, fold_step),
            circle_log_size,
            twiddle_log_size: circle_log_size - 1,
        }
    }

    fn slots(requirements: &FriWorkspaceRequirements) -> FriWorkspaceSlots {
        let mut next = 1u32;
        let mut id = || {
            let result = ArenaSlotId(next);
            next += 1;
            result
        };
        FriWorkspaceSlots {
            evaluation_ping: id(),
            evaluation_pong: id(),
            input_coordinate_ptrs: id(),
            ping_coordinate_ptrs: id(),
            pong_coordinate_ptrs: id(),
            retained_tree_evaluations: requirements.trees.iter().skip(1).map(|_| id()).collect(),
            retained_tree_coordinate_ptrs: requirements
                .trees
                .iter()
                .skip(1)
                .map(|_| id())
                .collect(),
            folding_challenges: requirements.rounds.iter().map(|_| id()).collect(),
            trees: requirements
                .trees
                .iter()
                .map(|tree| FriMerkleTreeSlots {
                    layers_bottom_up: tree.layers_bottom_up.iter().map(|_| id()).collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn fused_flag_parses_only_literal_one() {
        assert!(fri_fold_fused_flag_from(Some("1")));
        assert!(!fri_fold_fused_flag_from(Some("0")));
        assert!(!fri_fold_fused_flag_from(Some("true")));
        assert!(!fri_fold_fused_flag_from(Some("")));
        assert!(!fri_fold_fused_flag_from(None));
    }

    #[test]
    fn fold_twiddle_offsets_match_per_stage_consumption() {
        // Twiddle buffer of 2^8 words for a 2^9 circle domain. The circle fold
        // consumes the packed n/2-word tail; a line fold over n elements reads
        // its n/2 twiddles at `twiddle_words - n`.
        assert_eq!(
            fold_twiddle_offset(256, 512, FoldKind::CircleToLine).unwrap(),
            0
        );
        assert_eq!(fold_twiddle_offset(256, 256, FoldKind::Line).unwrap(), 0);
        assert_eq!(fold_twiddle_offset(256, 128, FoldKind::Line).unwrap(), 128);
        assert_eq!(fold_twiddle_offset(256, 64, FoldKind::Line).unwrap(), 192);
        // A domain larger than the twiddle buffer must fail closed instead of
        // wrapping the offset.
        assert_eq!(
            fold_twiddle_offset(64, 256, FoldKind::Line).unwrap_err(),
            PreparedFriError::SizeOverflow
        );
    }

    #[test]
    fn fused_eligibility_is_exactly_the_complete_triple_rounds() {
        // fold_step = 3: 9 -> 6 -> 3 -> 2. The two complete rounds carry three
        // sub-folds each (fused-eligible); the final partial round folds once
        // and must fail closed to the per-fold kernels.
        let requirements = fri_workspace_requirements(config(9, 3, 1)).unwrap();
        assert_eq!(
            requirements
                .rounds
                .iter()
                .map(|round| round.fold_step)
                .collect::<Vec<_>>(),
            vec![3, 3, 1]
        );
    }

    #[test]
    fn exact_rounds_include_last_partial_fold() {
        // Last domain log is 1 + 1 = 2. 11 -> 7 -> 3 -> 2, so the final
        // committed tree has outgoing step one and therefore does not pack.
        let requirements = fri_workspace_requirements(config(11, 4, 1)).unwrap();
        assert_eq!(requirements.last_layer_log_size, 2);
        assert_eq!(
            requirements.rounds,
            vec![
                FriRoundRequirements {
                    input_log_size: 11,
                    fold_step: 4,
                    output_log_size: 7,
                    output_tree: Some(1),
                },
                FriRoundRequirements {
                    input_log_size: 7,
                    fold_step: 4,
                    output_log_size: 3,
                    output_tree: Some(2),
                },
                FriRoundRequirements {
                    input_log_size: 3,
                    fold_step: 1,
                    output_log_size: 2,
                    output_tree: None,
                },
            ]
        );
        assert_eq!(
            requirements
                .trees
                .iter()
                .map(|tree| (tree.evaluation_log_size, tree.log_rows_per_leaf))
                .collect::<Vec<_>>(),
            vec![(11, 2), (7, 2), (3, 0)]
        );
    }

    #[test]
    fn exact_capacities_cover_ping_pong_descriptors_and_all_tree_layers() {
        let requirements = fri_workspace_requirements(config(8, 2, 1)).unwrap();
        assert_eq!(requirements.twiddle_words, 1 << 7);
        assert_eq!(requirements.evaluation_ping_words, 4 * (1 << 7));
        assert_eq!(requirements.evaluation_pong_words, 4 * (1 << 7));
        assert_eq!(
            requirements
                .trees
                .iter()
                .skip(1)
                .map(|tree| tree.evaluation_words)
                .collect::<Vec<_>>(),
            vec![4 * (1 << 6), 4 * (1 << 4)]
        );
        assert_eq!(
            requirements.coordinate_pointer_words,
            4 * core::mem::size_of::<usize>() / 4
        );
        for tree in &requirements.trees {
            assert_eq!(tree.layers_bottom_up.last().unwrap().log_size, 0);
            assert_eq!(tree.layers_bottom_up.last().unwrap().words, HASH_WORDS);
            for pair in tree.layers_bottom_up.windows(2) {
                assert_eq!(pair[0].log_size, pair[1].log_size + 1);
                assert_eq!(pair[0].words, pair[1].words * 2);
            }
        }

        let slots = slots(&requirements);
        let arena_slots = requirements.arena_slot_requirements(&slots).unwrap();
        let tree_layers = requirements
            .trees
            .iter()
            .map(|tree| tree.layers_bottom_up.len())
            .sum::<usize>();
        let retained_trees = requirements.trees.len() - 1;
        let expected = 5 + 2 * retained_trees + requirements.rounds.len() + tree_layers;
        assert_eq!(arena_slots.len(), expected);
        assert_eq!(
            arena_slots
                .iter()
                .filter(|entry| entry.alignment_words == FRI_HASH_ALIGNMENT_WORDS)
                .count(),
            tree_layers
        );
        for challenge in &slots.folding_challenges {
            let requirement = arena_slots
                .iter()
                .find(|entry| entry.id == *challenge)
                .unwrap();
            assert_eq!(requirement.len_words, FRI_CHALLENGE_WORDS);
            assert_eq!(requirement.alignment_words, FRI_CHALLENGE_WORDS);
        }
    }

    #[test]
    fn packed_leaf_geometry_is_exact_stwo_column_order() {
        use stwo::core::fields::m31::BaseField;
        use stwo::core::vcs::blake2_hash::Blake2sHasherGeneric;
        use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

        let coords: [Vec<u32>; 4] =
            std::array::from_fn(|coord| (0..16).map(|row| 1000 * coord as u32 + row).collect());
        for leaf in 0..4 {
            let mut direct = Vec::with_capacity(16);
            for offset in 0..4 {
                for coordinate in &coords {
                    direct.push(coordinate[4 * leaf + offset]);
                }
            }
            let materialized: Vec<_> = (0..16)
                .map(|column| {
                    let offset = column / 4;
                    let coord = column % 4;
                    coords[coord][4 * leaf + offset]
                })
                .collect();
            assert_eq!(direct, materialized);

            let direct_bytes: Vec<u8> = direct.iter().flat_map(|word| word.to_le_bytes()).collect();
            let direct_hash = Blake2sHasherGeneric::<false>::hash(&direct_bytes);
            let mut reference = Blake2sHasherGeneric::<false>::default();
            reference.update_leaf(
                &materialized
                    .iter()
                    .copied()
                    .map(BaseField::from_u32_unchecked)
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                direct_hash,
                <Blake2sHasherGeneric<false> as MerkleHasherLifted>::finalize(reference)
            );
        }
    }

    #[test]
    fn sizing_fails_closed_on_protocol_and_slot_mismatches() {
        let mut invalid_blowup = config(9, 2, 1);
        invalid_blowup.fri.log_blowup_factor = 0;
        assert_eq!(
            fri_workspace_requirements(invalid_blowup).unwrap_err(),
            PreparedFriError::InvalidBlowup(0)
        );
        assert!(matches!(
            fri_workspace_requirements(config(5, 4, 1)),
            Err(PreparedFriError::FirstFoldPastLastLayer { .. })
        ));
        let mut too_small_twiddles = config(9, 2, 1);
        too_small_twiddles.twiddle_log_size = 7;
        assert!(matches!(
            fri_workspace_requirements(too_small_twiddles),
            Err(PreparedFriError::TwiddleDomainTooSmall { .. })
        ));

        let requirements = fri_workspace_requirements(config(9, 2, 1)).unwrap();
        let mut missing_tree_slots = slots(&requirements);
        missing_tree_slots.trees.pop();
        assert!(matches!(
            requirements.arena_slot_requirements(&missing_tree_slots),
            Err(PreparedFriError::SlotShapeMismatch { role: "trees", .. })
        ));

        let mut missing_retained_evaluation = slots(&requirements);
        missing_retained_evaluation.retained_tree_evaluations.pop();
        assert!(matches!(
            requirements.arena_slot_requirements(&missing_retained_evaluation),
            Err(PreparedFriError::SlotShapeMismatch {
                role: "retained tree evaluations",
                ..
            })
        ));

        let mut aliased_slots = slots(&requirements);
        aliased_slots.pong_coordinate_ptrs = aliased_slots.ping_coordinate_ptrs;
        assert!(matches!(
            requirements.arena_slot_requirements(&aliased_slots),
            Err(PreparedFriError::DuplicateSlot(_))
        ));
    }
}
