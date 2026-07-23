//! Allocation-free, explicit-stream CUDA commit island.
//!
//! [`CommitGraphPlan::launch`] is the only execution path: callers invoke it
//! directly for eager execution or between [`CudaExecContext::capture`] and
//! `CudaGraphCapture::finish` for graph execution. That keeps kernel order and
//! parameters identical across both modes.

use core::ffi::c_void;
use core::ptr::NonNull;
use std::collections::BTreeSet;

use stwo_backend_cuda_kernels::raw::{self, Blake2sHash};

use super::exec_context::{check_cuda, ArenaSlice, ArenaSlotId, CudaExecContext, CudaRuntimeError};

const HASH_WORDS: usize = core::mem::size_of::<Blake2sHash>() / core::mem::size_of::<u32>();
const MAX_FUSED_TAIL_HASHES: u32 = 4096;

/// Selects how a `retain_evaluations` group meeting the NttHash shape
/// constraints (exactly 16 columns, one batch, `log_n == lifting_log_size`,
/// `log_n >= 13`) is committed. Both modes produce byte-identical retained
/// evaluations, leaf digests and roots; `Fused` is opt-in via
/// `STWO_CUDA_NTT_LEAF_FUSED=1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedLdeHashMode {
    /// The LDE writes the retained evaluations; a separate LeafUpdate pass
    /// re-reads every evaluation word for hashing (default).
    Separate,
    /// `ntt_leaf_fused.cu`: the final NTT stage writes the retained
    /// evaluations AND absorbs the same tile into the leaf states — one read
    /// of coefficients, one write of evaluations, zero re-read for hashing.
    Fused,
}

impl RetainedLdeHashMode {
    /// Process-wide default. Read once via `OnceLock` so plan construction,
    /// eager launches, capture and replay all observe one mode.
    pub fn from_env() -> Self {
        if ntt_leaf_fused_enabled() {
            Self::Fused
        } else {
            Self::Separate
        }
    }
}

/// Source-level implementation selected for a materialized streaming leaf
/// update. The mode is sealed into each launch node during preparation so an
/// eager launch and its captured replay cannot silently select different
/// kernels from ambient state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitLeafUpdateMode {
    Scalar,
    Ilp2,
    Quad,
    /// The input is stopped before its final N2B butterfly and is consumed by
    /// the producer-fused kernel. This is compiler-selected, never ambient.
    FromLde,
}

impl CommitLeafUpdateMode {
    pub fn from_env() -> Self {
        if std::env::var("STWO_CUDA_BLAKE2S_LEAF_QUAD").as_deref() == Ok("1") {
            Self::Quad
        } else if super::blake2s::blake2s_leaf_ilp2_enabled() {
            Self::Ilp2
        } else {
            Self::Scalar
        }
    }
}

/// `STWO_CUDA_NTT_LEAF_FUSED=1` opts retained full-lifting 16-column groups
/// into the LDE-write + leaf-absorb fused lane (Step 3.1). Default OFF until
/// the pod byte-identity and bandwidth gates pass.
fn ntt_leaf_fused_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("STWO_CUDA_NTT_LEAF_FUSED").as_deref() == Ok("1"))
}

/// One same-size LDE batch. Both pointer tables are DEVICE tables in the same
/// canonical order. `coefficient_sizes` gives each source's exact length;
/// outputs have `2 * eval_domain_size` words. One explicit-stream kernel stages
/// coefficients plus a zero tail before the in-place N2B transform.
#[derive(Clone, Copy, Debug)]
pub struct CommitLdeBatch {
    pub coefficient_ptrs: ArenaSlice,
    /// DEVICE table containing the exact source length of every coefficient
    /// column. Sources may be shorter than `eval_domain_size` when blowup > 1;
    /// the staging kernel zero-fills the remainder before the N2B transform.
    pub coefficient_sizes: ArenaSlice,
    pub column_ptrs: ArenaSlice,
    pub column_count: u32,
    pub log_n: u32,
    pub twiddles: ArenaSlice,
    pub twiddles_size: u32,
    pub eval_domain_size: u32,
}

/// Canonically ordered leaf-column group. `column_ptrs` and
/// `column_log_sizes` are DEVICE tables in the exact leaf byte order. Batches
/// may partition this group by log size, but their total column count must equal
/// `column_count` before the leaf kernel consumes the canonical group table.
#[derive(Clone, Debug)]
pub struct CommitLeafGroup {
    pub first_column: u32,
    pub column_count: u32,
    pub column_ptrs: ArenaSlice,
    pub column_log_sizes: ArenaSlice,
    pub lde_batches: Vec<CommitLdeBatch>,
    /// Persistent outputs must complete the circle transform in memory. The
    /// producer-fused/hash-from-pre-circle lanes are valid only for streamed
    /// scratch whose contents are dead after leaf hashing.
    pub retain_evaluations: bool,
}

/// Fused top-of-tree tail. `level_ptrs` is a DEVICE pointer table containing
/// `level_outputs` in the same order; output `i` holds half as many hashes as
/// output `i-1` (or the tail input for `i=0`).
#[derive(Clone, Debug)]
pub struct CommitTailPlan {
    pub level_ptrs: ArenaSlice,
    pub level_outputs: Vec<ArenaSlice>,
}

/// Observable launch topology, used by local plan tests and benchmark traces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitLaunchKind {
    LeafInit {
        hashes: u32,
    },
    Lde {
        group: u32,
        batch: u32,
        columns: u32,
        log_n: u32,
    },
    NttHash {
        group: u32,
        columns: u32,
        log_n: u32,
    },
    /// Retained twin of `NttHash` (Step 3.1 `ntt_leaf_fused.cu` lane, opt-in
    /// via `STWO_CUDA_NTT_LEAF_FUSED=1`): the final NTT stage WRITES the
    /// group's retained evaluations and absorbs the same tile into the leaf
    /// states, replacing the `Lde` + `LeafUpdate`/`LeafFinalize` pair.
    RetainedNttHash {
        group: u32,
        columns: u32,
        log_n: u32,
    },
    LeafUpdate {
        group: u32,
        first_column: u32,
        columns: u32,
        mode: CommitLeafUpdateMode,
    },
    LeafFinalize {
        group: u32,
        first_column: u32,
        columns: u32,
    },
    InteriorLayer {
        level: u32,
        output_hashes: u32,
    },
    /// One destructive column-free level in the explicit single-slab lane.
    /// The ABI saves the first child pair in the slab tail, then executes the
    /// proven low-to-high disjoint bands.
    InteriorLayerInPlace {
        level: u32,
        output_hashes: u32,
    },
    /// Four column-free interior levels in one launch (Step 3.2 fused interior
    /// lane, opt-in via `STWO_CUDA_BLAKE2S_INTERIOR_FUSED=1`). `first_level` is
    /// the first of the four fused levels; `output_hashes` counts the deepest
    /// (level `first_level + 3`) output. The three intermediate levels stay in
    /// shared memory and their planned buffers are never written.
    FusedInterior4 {
        first_level: u32,
        output_hashes: u32,
    },
    FusedTail {
        first_hashes: u32,
        levels: u32,
    },
}

/// Physical traffic removed by the native-final or producer-fused N2B→leaf
/// lanes. For `fused_groups` (unretained), `bytes_avoided` counts the
/// eliminated completed-LDE write plus its leaf-hash reread; for
/// `retained_fused_groups` (the RetainedNttHash lane) only the leaf-hash
/// reread is eliminated — the evaluation write must remain for decommitment.
/// `unfused_groups` exposes every legacy full-LDE group.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommitHashFromTileTelemetry {
    pub fused_groups: u64,
    pub fused_columns: u64,
    pub retained_fused_groups: u64,
    pub unfused_groups: u64,
    pub bytes_avoided: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitGraphError {
    InvalidLiftingLogSize(u32),
    NoLeafGroups,
    EmptyLeafGroup(u32),
    NonCanonicalGroupStart {
        group: u32,
        expected: u32,
        actual: u32,
    },
    InvalidUpdateWidth {
        group: u32,
        columns: u32,
    },
    InvalidFinalWidth {
        group: u32,
        columns: u32,
    },
    EmptyLdeBatches(u32),
    LdeColumnCountMismatch {
        group: u32,
        expected: u32,
        actual: u32,
    },
    InvalidLdeGeometry {
        group: u32,
        batch: u32,
    },
    BufferTooSmall {
        role: &'static str,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedPointerTable(&'static str),
    MisalignedHashBuffer(&'static str),
    AliasedArenaSlot(ArenaSlotId),
    InPlaceInteriorLayer(ArenaSlotId),
    InvalidInPlaceScratch,
    PrematureArenaSlotReuse(ArenaSlotId),
    InvalidUnretainedBottomLayers {
        lifting_log_size: u32,
        unretained: u32,
    },
    ContextMismatch,
    TooManyColumns,
    InteriorPastRoot(u32),
    EmptyTail,
    TailTooWide(u32),
    TooManyTailLevels(usize),
    IncompleteTree(u32),
    InconsistentGroupTwiddles {
        group: u32,
        batch: u32,
    },
    InvalidLeafUpdateMode,
    SizeOverflow,
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for CommitGraphError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid CUDA commit graph: {self:?}")
    }
}

impl std::error::Error for CommitGraphError {}

impl From<CudaRuntimeError> for CommitGraphError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

#[derive(Clone, Copy, Debug)]
enum CommitLaunch {
    LeafInit {
        size: u32,
        state: ArenaSlice,
    },
    Lde {
        group: u32,
        batch: u32,
        params: CommitLdeBatch,
        before_circle: bool,
    },
    NttHash {
        group: u32,
        first_column: u32,
        is_final: bool,
        params: CommitLdeBatch,
        state: ArenaSlice,
    },
    RetainedNttHash {
        group: u32,
        first_column: u32,
        is_final: bool,
        params: CommitLdeBatch,
        state: ArenaSlice,
    },
    LeafUpdate {
        group: u32,
        first_column: u32,
        columns: u32,
        mode: CommitLeafUpdateMode,
        column_ptrs: ArenaSlice,
        column_log_sizes: ArenaSlice,
        lifting_log_size: u32,
        twiddles: ArenaSlice,
        twiddle_words: u32,
        state: ArenaSlice,
    },
    LeafFinalize {
        group: u32,
        first_column: u32,
        columns: u32,
        column_ptrs: ArenaSlice,
        column_log_sizes: ArenaSlice,
        lifting_log_size: u32,
        twiddles: ArenaSlice,
        twiddle_words: u32,
        from_lde: bool,
        state: ArenaSlice,
    },
    InteriorLayer {
        level: u32,
        input: ArenaSlice,
        output: ArenaSlice,
        output_hashes: u32,
    },
    InteriorLayerInPlace {
        level: u32,
        hashes: ArenaSlice,
        scratch_pair: ArenaSlice,
        output_hashes: u32,
    },
    FusedInterior4 {
        first_level: u32,
        input: ArenaSlice,
        output: ArenaSlice,
        output_hashes: u32,
    },
    FusedTail {
        input: ArenaSlice,
        first_hashes: u32,
        level_ptrs: ArenaSlice,
        levels: u32,
    },
}

impl CommitLaunch {
    fn kind(self) -> CommitLaunchKind {
        match self {
            Self::LeafInit { size, .. } => CommitLaunchKind::LeafInit { hashes: size },
            Self::Lde {
                group,
                batch,
                params,
                ..
            } => CommitLaunchKind::Lde {
                group,
                batch,
                columns: params.column_count,
                log_n: params.log_n,
            },
            Self::NttHash { group, params, .. } => CommitLaunchKind::NttHash {
                group,
                columns: params.column_count,
                log_n: params.log_n,
            },
            Self::RetainedNttHash { group, params, .. } => CommitLaunchKind::RetainedNttHash {
                group,
                columns: params.column_count,
                log_n: params.log_n,
            },
            Self::LeafUpdate {
                group,
                first_column,
                columns,
                mode,
                ..
            } => CommitLaunchKind::LeafUpdate {
                group,
                first_column,
                columns,
                mode,
            },
            Self::LeafFinalize {
                group,
                first_column,
                columns,
                ..
            } => CommitLaunchKind::LeafFinalize {
                group,
                first_column,
                columns,
            },
            Self::InteriorLayer {
                level,
                output_hashes,
                ..
            } => CommitLaunchKind::InteriorLayer {
                level,
                output_hashes,
            },
            Self::InteriorLayerInPlace {
                level,
                output_hashes,
                ..
            } => CommitLaunchKind::InteriorLayerInPlace {
                level,
                output_hashes,
            },
            Self::FusedInterior4 {
                first_level,
                output_hashes,
                ..
            } => CommitLaunchKind::FusedInterior4 {
                first_level,
                output_hashes,
            },
            Self::FusedTail {
                first_hashes,
                levels,
                ..
            } => CommitLaunchKind::FusedTail {
                first_hashes,
                levels,
            },
        }
    }
}

/// Validated, allocation-free launch plan for one lifted Blake2s commitment.
#[derive(Debug)]
pub struct CommitGraphPlan {
    context_token: NonNull<c_void>,
    launches: Vec<CommitLaunch>,
    root: ArenaSlice,
    hash_from_tile: CommitHashFromTileTelemetry,
    producer_fused_log_sizes: Vec<u32>,
    retained_fused_log_sizes: Vec<u32>,
}

impl CommitGraphPlan {
    /// Build and fully validate the launch geometry before capture begins.
    ///
    /// Column pointer tables must already contain the canonical column order;
    /// this constructor never sorts or rewrites them. `interior_outputs` lists
    /// one output buffer per ordinary column-free Merkle level. If `tail` is
    /// present, its outputs finish the tree in one fused launch.
    pub fn new(
        lifting_log_size: u32,
        leaf_state: ArenaSlice,
        leaf_groups: Vec<CommitLeafGroup>,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
    ) -> Result<Self, CommitGraphError> {
        Self::new_pruned(
            lifting_log_size,
            0,
            leaf_state,
            leaf_groups,
            interior_outputs,
            tail,
        )
    }

    /// Build a plan whose bottom `unretained_bottom_layers` (counting the leaf
    /// layer) are scratch. Those bottom outputs may reuse two arena slots in
    /// strict producer/consumer order; every retained and fused-tail output stays
    /// uniquely addressable for later decommitment.
    ///
    /// Interior four-level fusion follows the process-wide
    /// `STWO_CUDA_BLAKE2S_INTERIOR_FUSED` flag (default OFF); see
    /// [`Self::new_pruned_impl`] for the explicit-mode variant the tests pin.
    pub fn new_pruned(
        lifting_log_size: u32,
        unretained_bottom_layers: u32,
        leaf_state: ArenaSlice,
        leaf_groups: Vec<CommitLeafGroup>,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
    ) -> Result<Self, CommitGraphError> {
        Self::new_pruned_impl(
            lifting_log_size,
            unretained_bottom_layers,
            leaf_state,
            leaf_groups,
            interior_outputs,
            tail,
            super::blake2s::blake2s_interior_fused_enabled(),
        )
    }

    /// [`Self::new_pruned`] with the Step 3.2 interior four-level fusion lane
    /// pinned explicitly, so plan-shape and native byte-identity tests can
    /// exercise BOTH launch topologies in one process regardless of the
    /// environment (the env switch is a process-global `OnceLock`).
    ///
    /// When `interior_fused` is on, aligned windows of four consecutive
    /// column-free interior levels collapse into one `FusedInterior4` launch
    /// **iff** all three intermediate levels are unretained
    /// ([`interior4_window_fusible`]) and the window's output buffer does not
    /// alias its input. Retained-layer policy (the simpler correct option per
    /// the plan): a window whose intermediates include a retained layer falls
    /// back to per-level launches, so retained layers are always written to
    /// their arena buffers by exactly the same kernel as today; the fused
    /// window's own OUTPUT level is always written to its planned buffer and
    /// may itself be retained. Validation, retention bookkeeping, and arena
    /// slot budgets are identical in both modes — unwritten intermediate
    /// ping-pong buffers stay allocated; only launch emission changes.
    pub(crate) fn new_pruned_impl(
        lifting_log_size: u32,
        unretained_bottom_layers: u32,
        leaf_state: ArenaSlice,
        leaf_groups: Vec<CommitLeafGroup>,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
        interior_fused: bool,
    ) -> Result<Self, CommitGraphError> {
        Self::new_pruned_with_modes(
            lifting_log_size,
            unretained_bottom_layers,
            leaf_state,
            leaf_groups,
            interior_outputs,
            tail,
            interior_fused,
            RetainedLdeHashMode::from_env(),
            CommitLeafUpdateMode::from_env(),
        )
    }

    /// [`Self::new_pruned_impl`] with the Step 3.1 retained LDE-write +
    /// leaf-absorb lane (`STWO_CUDA_NTT_LEAF_FUSED`) additionally pinned, so
    /// plan-shape and native byte-identity tests can exercise both retained
    /// commit topologies in one process. Under [`RetainedLdeHashMode::Fused`],
    /// a `retain_evaluations` group meeting the SAME shape constraints as the
    /// NttHash lane (exactly 16 columns, one batch,
    /// `log_n == lifting_log_size >= 13`) emits one `RetainedNttHash` launch
    /// instead of the `Lde` + `LeafUpdate`/`LeafFinalize` pair; every other
    /// group is planned exactly as before. Validation, retention bookkeeping,
    /// and arena slot budgets are identical in both modes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_pruned_with_modes(
        lifting_log_size: u32,
        unretained_bottom_layers: u32,
        leaf_state: ArenaSlice,
        leaf_groups: Vec<CommitLeafGroup>,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
        interior_fused: bool,
        retained_lde_hash: RetainedLdeHashMode,
        leaf_update_mode: CommitLeafUpdateMode,
    ) -> Result<Self, CommitGraphError> {
        if leaf_update_mode == CommitLeafUpdateMode::FromLde {
            return Err(CommitGraphError::InvalidLeafUpdateMode);
        }
        if lifting_log_size >= 31 {
            return Err(CommitGraphError::InvalidLiftingLogSize(lifting_log_size));
        }
        if unretained_bottom_layers > lifting_log_size {
            return Err(CommitGraphError::InvalidUnretainedBottomLayers {
                lifting_log_size,
                unretained: unretained_bottom_layers,
            });
        }
        if leaf_groups.is_empty() {
            return Err(CommitGraphError::NoLeafGroups);
        }
        let leaf_size = 1u32 << lifting_log_size;
        require_hash_capacity("leaf_state", leaf_state, leaf_size)?;
        let context_token = leaf_state.context_token();
        let mut input_slots = BTreeSet::new();

        let mut launches = Vec::new();
        let mut hash_from_tile = CommitHashFromTileTelemetry::default();
        let mut producer_fused_log_sizes = BTreeSet::new();
        let mut retained_fused_log_sizes = BTreeSet::new();
        launches.push(CommitLaunch::LeafInit {
            size: leaf_size,
            state: leaf_state,
        });

        let mut cols_done = 0u32;
        let last_group = leaf_groups.len() - 1;
        for (group_index, group) in leaf_groups.iter().enumerate() {
            let group_index = group_index as u32;
            require_same_context(context_token, group.column_ptrs)?;
            require_same_context(context_token, group.column_log_sizes)?;
            input_slots.insert(group.column_ptrs.id());
            input_slots.insert(group.column_log_sizes.id());
            if group.column_count == 0 {
                return Err(CommitGraphError::EmptyLeafGroup(group_index));
            }
            if group.first_column != cols_done {
                return Err(CommitGraphError::NonCanonicalGroupStart {
                    group: group_index,
                    expected: cols_done,
                    actual: group.first_column,
                });
            }
            require_pointer_table("leaf_column_ptrs", group.column_ptrs, group.column_count)?;
            require_words(
                "leaf_column_log_sizes",
                group.column_log_sizes,
                group.column_count as usize,
            )?;
            if group.lde_batches.is_empty() {
                return Err(CommitGraphError::EmptyLdeBatches(group_index));
            }

            let mut lde_columns = 0u32;
            let mut group_twiddles = None;
            for (batch_index, &batch) in group.lde_batches.iter().enumerate() {
                require_same_context(context_token, batch.coefficient_ptrs)?;
                require_same_context(context_token, batch.coefficient_sizes)?;
                require_same_context(context_token, batch.column_ptrs)?;
                require_same_context(context_token, batch.twiddles)?;
                validate_lde_batch(group_index, batch_index as u32, batch)?;
                let identity = (
                    batch.twiddles.id(),
                    batch.twiddles.as_u32_ptr(),
                    batch.twiddles_size,
                );
                if group_twiddles.is_some_and(|expected| expected != identity) {
                    return Err(CommitGraphError::InconsistentGroupTwiddles {
                        group: group_index,
                        batch: batch_index as u32,
                    });
                }
                group_twiddles = Some(identity);
                input_slots.insert(batch.coefficient_ptrs.id());
                input_slots.insert(batch.coefficient_sizes.id());
                input_slots.insert(batch.column_ptrs.id());
                input_slots.insert(batch.twiddles.id());
                lde_columns = lde_columns
                    .checked_add(batch.column_count)
                    .ok_or(CommitGraphError::TooManyColumns)?;
            }
            if lde_columns != group.column_count {
                return Err(CommitGraphError::LdeColumnCountMismatch {
                    group: group_index,
                    expected: group.column_count,
                    actual: lde_columns,
                });
            }

            let is_final = group_index as usize == last_group;
            let (_, _, twiddle_words) = group_twiddles.expect("non-empty LDE batches");
            let twiddles = group.lde_batches[0].twiddles;
            if is_final {
                if group.column_count > 16 {
                    return Err(CommitGraphError::InvalidFinalWidth {
                        group: group_index,
                        columns: group.column_count,
                    });
                }
            } else {
                if group.column_count % 16 != 0 {
                    return Err(CommitGraphError::InvalidUpdateWidth {
                        group: group_index,
                        columns: group.column_count,
                    });
                }
            }

            // The NttHash shape constraints, shared verbatim by the retained
            // lane: one full-lifting same-log 16-column batch. Under them the
            // leaf row index IS the evaluation index (the lifting ratio is 1),
            // so the fused kernels' absorb order coincides with the canonical
            // committed column order by construction.
            let hash16_shape = group.column_count == 16
                && group.lde_batches.len() == 1
                && group.lde_batches[0].log_n == lifting_log_size
                && group.lde_batches[0].log_n >= 13;
            let producer_fused = hash16_shape && !group.retain_evaluations;
            let retained_fused = hash16_shape
                && group.retain_evaluations
                && retained_lde_hash == RetainedLdeHashMode::Fused;
            let prefix_fused =
                !group.retain_evaluations && group.lde_batches.iter().all(|batch| batch.log_n < 13);
            if producer_fused || prefix_fused {
                hash_from_tile.fused_groups += 1;
                hash_from_tile.fused_columns += u64::from(group.column_count);
                for batch in &group.lde_batches {
                    let evaluation_words = (1u64 << batch.log_n)
                        .checked_mul(u64::from(batch.column_count))
                        .ok_or(CommitGraphError::SizeOverflow)?;
                    hash_from_tile.bytes_avoided = hash_from_tile
                        .bytes_avoided
                        .checked_add(
                            evaluation_words
                                .checked_mul(2 * core::mem::size_of::<u32>() as u64)
                                .ok_or(CommitGraphError::SizeOverflow)?,
                        )
                        .ok_or(CommitGraphError::SizeOverflow)?;
                }
            } else if retained_fused {
                // Only the leaf-hash reread disappears; the evaluation write
                // stays (the buffer is live through decommitment).
                hash_from_tile.retained_fused_groups += 1;
                let batch = group.lde_batches[0];
                let evaluation_words = (1u64 << batch.log_n)
                    .checked_mul(u64::from(batch.column_count))
                    .ok_or(CommitGraphError::SizeOverflow)?;
                hash_from_tile.bytes_avoided = hash_from_tile
                    .bytes_avoided
                    .checked_add(
                        evaluation_words
                            .checked_mul(core::mem::size_of::<u32>() as u64)
                            .ok_or(CommitGraphError::SizeOverflow)?,
                    )
                    .ok_or(CommitGraphError::SizeOverflow)?;
            } else {
                hash_from_tile.unfused_groups += 1;
            }

            if producer_fused {
                let params = group.lde_batches[0];
                producer_fused_log_sizes.insert(params.log_n);
                launches.push(CommitLaunch::NttHash {
                    group: group_index,
                    first_column: cols_done,
                    is_final,
                    params,
                    state: leaf_state,
                });
            } else if retained_fused {
                let params = group.lde_batches[0];
                retained_fused_log_sizes.insert(params.log_n);
                launches.push(CommitLaunch::RetainedNttHash {
                    group: group_index,
                    first_column: cols_done,
                    is_final,
                    params,
                    state: leaf_state,
                });
            } else {
                for (batch_index, &params) in group.lde_batches.iter().enumerate() {
                    launches.push(CommitLaunch::Lde {
                        group: group_index,
                        batch: batch_index as u32,
                        params,
                        before_circle: prefix_fused,
                    });
                }
                let launch = if is_final {
                    CommitLaunch::LeafFinalize {
                        group: group_index,
                        first_column: cols_done,
                        columns: group.column_count,
                        column_ptrs: group.column_ptrs,
                        column_log_sizes: group.column_log_sizes,
                        lifting_log_size,
                        twiddles,
                        twiddle_words,
                        from_lde: prefix_fused,
                        state: leaf_state,
                    }
                } else {
                    CommitLaunch::LeafUpdate {
                        group: group_index,
                        first_column: cols_done,
                        columns: group.column_count,
                        mode: if prefix_fused {
                            CommitLeafUpdateMode::FromLde
                        } else {
                            leaf_update_mode
                        },
                        column_ptrs: group.column_ptrs,
                        column_log_sizes: group.column_log_sizes,
                        lifting_log_size,
                        twiddles,
                        twiddle_words,
                        state: leaf_state,
                    }
                };
                launches.push(launch);
            }
            cols_done = cols_done
                .checked_add(group.column_count)
                .ok_or(CommitGraphError::TooManyColumns)?;
        }

        let suffix = build_merkle_from_leaves(
            lifting_log_size,
            unretained_bottom_layers,
            leaf_state,
            interior_outputs,
            tail,
            interior_fused,
            &input_slots,
            None,
        )?;
        launches.extend(suffix.launches);
        Ok(Self {
            context_token,
            launches,
            root: suffix.root,
            hash_from_tile,
            producer_fused_log_sizes: producer_fused_log_sizes.into_iter().collect(),
            retained_fused_log_sizes: retained_fused_log_sizes.into_iter().collect(),
        })
    }

    /// Build only the qualified column-free Merkle suffix from an already
    /// materialized Blake2s leaf layer. No leaf init, LDE, or leaf absorb
    /// launch is emitted. The interior and fused-tail launch sequence is the
    /// exact suffix used by every legacy constructor above.
    pub fn new_merkle_from_leaves(
        lifting_log_size: u32,
        unretained_bottom_layers: u32,
        leaf_hashes: ArenaSlice,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
    ) -> Result<Self, CommitGraphError> {
        Self::new_merkle_from_leaves_with_mode(
            lifting_log_size,
            unretained_bottom_layers,
            leaf_hashes,
            interior_outputs,
            tail,
            super::blake2s::blake2s_interior_fused_enabled(),
        )
    }

    /// Explicit interior-fusion twin used by A/B suffix tests.
    pub fn new_merkle_from_leaves_with_mode(
        lifting_log_size: u32,
        unretained_bottom_layers: u32,
        leaf_hashes: ArenaSlice,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
        interior_fused: bool,
    ) -> Result<Self, CommitGraphError> {
        let suffix = build_merkle_from_leaves(
            lifting_log_size,
            unretained_bottom_layers,
            leaf_hashes,
            interior_outputs,
            tail,
            interior_fused,
            &BTreeSet::new(),
            None,
        )?;
        Ok(Self {
            context_token: leaf_hashes.context_token(),
            launches: suffix.launches,
            root: suffix.root,
            hash_from_tile: CommitHashFromTileTelemetry::default(),
            producer_fused_log_sizes: Vec::new(),
            retained_fused_log_sizes: Vec::new(),
        })
    }

    /// Explicit single-slab Merkle suffix. Only bottom layers excluded from
    /// decommit retention may overwrite the leaf slab; legacy constructors
    /// continue to reject every in-place interior alias.
    pub fn new_merkle_from_leaves_in_place(
        lifting_log_size: u32,
        unretained_bottom_layers: u32,
        leaf_hashes: ArenaSlice,
        scratch_pair: ArenaSlice,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
    ) -> Result<Self, CommitGraphError> {
        Self::new_merkle_from_leaves_in_place_with_mode(
            lifting_log_size,
            unretained_bottom_layers,
            leaf_hashes,
            scratch_pair,
            interior_outputs,
            tail,
            false,
        )
    }

    /// Explicit-mode twin for the immutable one-slab program. A fused window
    /// may cross the destructive bottom bands only when its three intermediate
    /// levels are unretained and its level-four destination is distinct.
    pub(crate) fn new_merkle_from_leaves_in_place_with_mode(
        lifting_log_size: u32,
        unretained_bottom_layers: u32,
        leaf_hashes: ArenaSlice,
        scratch_pair: ArenaSlice,
        interior_outputs: Vec<ArenaSlice>,
        tail: Option<CommitTailPlan>,
        interior_fused: bool,
    ) -> Result<Self, CommitGraphError> {
        if unretained_bottom_layers == 0
            || scratch_pair.id() != leaf_hashes.id()
            || scratch_pair.len_words()
                < super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        {
            return Err(CommitGraphError::InvalidInPlaceScratch);
        }
        let leaf_start = leaf_hashes.as_u32_ptr() as usize;
        let leaf_end = leaf_start
            .checked_add(leaf_hashes.len_words() * core::mem::size_of::<u32>())
            .ok_or(CommitGraphError::InvalidInPlaceScratch)?;
        if (scratch_pair.as_u32_ptr() as usize) < leaf_end {
            return Err(CommitGraphError::InvalidInPlaceScratch);
        }
        let suffix = build_merkle_from_leaves(
            lifting_log_size,
            unretained_bottom_layers,
            leaf_hashes,
            interior_outputs,
            tail,
            interior_fused,
            &BTreeSet::new(),
            Some(scratch_pair),
        )?;
        Ok(Self {
            context_token: leaf_hashes.context_token(),
            launches: suffix.launches,
            root: suffix.root,
            hash_from_tile: CommitHashFromTileTelemetry::default(),
            producer_fused_log_sizes: Vec::new(),
            retained_fused_log_sizes: Vec::new(),
        })
    }

    /// Root hash slot produced by this plan.
    pub fn root(&self) -> ArenaSlice {
        self.root
    }

    /// Exact eager/capture launch topology, without allocating.
    pub fn launch_sequence(&self) -> impl ExactSizeIterator<Item = CommitLaunchKind> + '_ {
        self.launches.iter().copied().map(CommitLaunch::kind)
    }

    pub fn hash_from_tile_telemetry(&self) -> CommitHashFromTileTelemetry {
        self.hash_from_tile
    }

    pub fn producer_fused_log_sizes(&self) -> &[u32] {
        &self.producer_fused_log_sizes
    }

    /// Log sizes committed through the retained `RetainedNttHash` lane; each
    /// needs `stwo_ntt_leaf_fused_configure` before capture (mirrors
    /// [`Self::producer_fused_log_sizes`]).
    pub fn retained_fused_log_sizes(&self) -> &[u32] {
        &self.retained_fused_log_sizes
    }

    /// Enqueue the complete allocation-free commit sequence on `context`.
    /// Calling this inside capture and calling it eagerly execute identical code.
    pub fn launch(&self, context: &CudaExecContext) -> Result<(), CommitGraphError> {
        if context.identity_token() != self.context_token {
            return Err(CommitGraphError::ContextMismatch);
        }
        let stream = context.stream_raw().as_ptr();
        for &launch in &self.launches {
            let (operation, code) = unsafe {
                match launch {
                    CommitLaunch::LeafInit { size, state } => (
                        "commit_leaf_init",
                        raw::stwo_blake2s_leaf_init_on(size, state.as_u32_ptr().cast(), stream),
                    ),
                    CommitLaunch::Lde {
                        params,
                        before_circle,
                        ..
                    } => {
                        let code = if before_circle {
                            raw::stwo_lde_n2b_columns_before_circle_on(
                                params.coefficient_ptrs.as_u32_ptr().cast(),
                                params.coefficient_sizes.as_u32_ptr(),
                                params.column_ptrs.as_u32_ptr().cast(),
                                params.log_n,
                                params.column_count,
                                params.twiddles.as_u32_ptr(),
                                params.twiddles_size,
                                params.eval_domain_size,
                                stream,
                            )
                        } else {
                            raw::stwo_lde_n2b_columns_on(
                                params.coefficient_ptrs.as_u32_ptr().cast(),
                                params.coefficient_sizes.as_u32_ptr(),
                                params.column_ptrs.as_u32_ptr().cast(),
                                params.log_n,
                                params.column_count,
                                params.twiddles.as_u32_ptr(),
                                params.twiddles_size,
                                params.eval_domain_size,
                                stream,
                            )
                        };
                        ("commit_lde_n2b", code)
                    }
                    CommitLaunch::NttHash {
                        first_column,
                        is_final,
                        params,
                        state,
                        ..
                    } => (
                        "commit_lde_n2b_hash16",
                        raw::stwo_lde_n2b_hash16_on(
                            params.coefficient_ptrs.as_u32_ptr().cast(),
                            params.coefficient_sizes.as_u32_ptr(),
                            params.column_ptrs.as_u32_ptr().cast(),
                            params.log_n,
                            params.twiddles.as_u32_ptr(),
                            params.twiddles_size,
                            params.eval_domain_size,
                            first_column,
                            u32::from(is_final),
                            state.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    CommitLaunch::RetainedNttHash {
                        first_column,
                        is_final,
                        params,
                        state,
                        ..
                    } => (
                        "commit_ntt_leaf_fused",
                        raw::stwo_ntt_leaf_fused_on(
                            params.coefficient_ptrs.as_u32_ptr().cast(),
                            params.coefficient_sizes.as_u32_ptr(),
                            params.column_ptrs.as_u32_ptr().cast(),
                            params.log_n,
                            params.twiddles.as_u32_ptr(),
                            params.twiddles_size,
                            params.eval_domain_size,
                            first_column,
                            u32::from(is_final),
                            state.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    CommitLaunch::LeafUpdate {
                        columns,
                        column_ptrs,
                        column_log_sizes,
                        lifting_log_size,
                        twiddles,
                        twiddle_words,
                        mode,
                        first_column,
                        state,
                        ..
                    } => {
                        let (operation, code) = match mode {
                            CommitLeafUpdateMode::FromLde => (
                                "commit_leaf_update_from_lde",
                                raw::stwo_blake2s_leaf_group_from_lde_on(
                                    1u32 << lifting_log_size,
                                    columns,
                                    column_ptrs.as_u32_ptr().cast(),
                                    column_log_sizes.as_u32_ptr(),
                                    lifting_log_size,
                                    first_column,
                                    0,
                                    twiddles.as_u32_ptr(),
                                    twiddle_words,
                                    state.as_u32_ptr().cast(),
                                    stream,
                                ),
                            ),
                            CommitLeafUpdateMode::Ilp2 => (
                                "commit_leaf_update_ilp2",
                                raw::stwo_blake2s_leaf_update_ilp2_on(
                                    1u32 << lifting_log_size,
                                    columns,
                                    column_ptrs.as_u32_ptr().cast(),
                                    column_log_sizes.as_u32_ptr(),
                                    lifting_log_size,
                                    first_column,
                                    state.as_u32_ptr().cast(),
                                    stream,
                                ),
                            ),
                            CommitLeafUpdateMode::Quad => (
                                "commit_leaf_update_quad",
                                raw::stwo_blake2s_leaf_update_quad_on(
                                    1u32 << lifting_log_size,
                                    columns,
                                    column_ptrs.as_u32_ptr().cast(),
                                    column_log_sizes.as_u32_ptr(),
                                    lifting_log_size,
                                    first_column,
                                    state.as_u32_ptr().cast(),
                                    stream,
                                ),
                            ),
                            CommitLeafUpdateMode::Scalar => (
                                "commit_leaf_update",
                                raw::stwo_blake2s_leaf_update_on(
                                    1u32 << lifting_log_size,
                                    columns,
                                    column_ptrs.as_u32_ptr().cast(),
                                    column_log_sizes.as_u32_ptr(),
                                    lifting_log_size,
                                    first_column,
                                    state.as_u32_ptr().cast(),
                                    stream,
                                ),
                            ),
                        };
                        (operation, code)
                    }
                    CommitLaunch::LeafFinalize {
                        columns,
                        column_ptrs,
                        column_log_sizes,
                        lifting_log_size,
                        twiddles,
                        twiddle_words,
                        from_lde,
                        first_column,
                        state,
                        ..
                    } => {
                        let code = if from_lde {
                            raw::stwo_blake2s_leaf_group_from_lde_on(
                                1u32 << lifting_log_size,
                                columns,
                                column_ptrs.as_u32_ptr().cast(),
                                column_log_sizes.as_u32_ptr(),
                                lifting_log_size,
                                first_column,
                                1,
                                twiddles.as_u32_ptr(),
                                twiddle_words,
                                state.as_u32_ptr().cast(),
                                stream,
                            )
                        } else {
                            raw::stwo_blake2s_leaf_finalize_on(
                                1u32 << lifting_log_size,
                                columns,
                                column_ptrs.as_u32_ptr().cast(),
                                column_log_sizes.as_u32_ptr(),
                                lifting_log_size,
                                first_column,
                                state.as_u32_ptr().cast(),
                                stream,
                            )
                        };
                        ("commit_leaf_finalize", code)
                    }
                    CommitLaunch::InteriorLayer {
                        input,
                        output,
                        output_hashes,
                        ..
                    } => (
                        "commit_interior_layer",
                        raw::stwo_blake2s_layer_on(
                            input.as_u32_ptr().cast(),
                            output_hashes,
                            output.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    CommitLaunch::InteriorLayerInPlace {
                        hashes,
                        scratch_pair,
                        output_hashes,
                        ..
                    } => (
                        "commit_interior_layer_in_place",
                        raw::stwo_blake2s_layer_in_place_on(
                            output_hashes,
                            hashes.as_u32_ptr().cast(),
                            scratch_pair.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    CommitLaunch::FusedInterior4 {
                        input,
                        output,
                        output_hashes,
                        ..
                    } => (
                        "commit_interior_fused4",
                        raw::stwo_blake2s_interior4_on(
                            input.as_u32_ptr().cast(),
                            output_hashes,
                            output.as_u32_ptr().cast(),
                            stream,
                        ),
                    ),
                    CommitLaunch::FusedTail {
                        input,
                        first_hashes,
                        level_ptrs,
                        levels,
                    } => (
                        "commit_fused_tail",
                        raw::stwo_blake2s_tail_on(
                            input.as_u32_ptr().cast(),
                            first_hashes,
                            level_ptrs.as_u32_ptr().cast(),
                            levels,
                            stream,
                        ),
                    ),
                }
            };
            check_cuda(operation, code)?;
        }
        Ok(())
    }
}

struct MerkleFromLeavesBuild {
    launches: Vec<CommitLaunch>,
    root: ArenaSlice,
}

#[allow(clippy::too_many_arguments)]
fn build_merkle_from_leaves(
    lifting_log_size: u32,
    unretained_bottom_layers: u32,
    leaf_hashes: ArenaSlice,
    interior_outputs: Vec<ArenaSlice>,
    tail: Option<CommitTailPlan>,
    interior_fused: bool,
    forbidden_input_slots: &BTreeSet<ArenaSlotId>,
    in_place_scratch: Option<ArenaSlice>,
) -> Result<MerkleFromLeavesBuild, CommitGraphError> {
    if lifting_log_size >= 31 {
        return Err(CommitGraphError::InvalidLiftingLogSize(lifting_log_size));
    }
    if unretained_bottom_layers > lifting_log_size {
        return Err(CommitGraphError::InvalidUnretainedBottomLayers {
            lifting_log_size,
            unretained: unretained_bottom_layers,
        });
    }
    let leaf_size = 1u32 << lifting_log_size;
    require_hash_capacity("leaf_state", leaf_hashes, leaf_size)?;
    let context_token = leaf_hashes.context_token();
    let mut hash_slots = BTreeSet::from([leaf_hashes.id()]);
    let mut retained_slots = BTreeSet::new();
    if unretained_bottom_layers == 0 {
        retained_slots.insert(leaf_hashes.id());
    }
    let mut input_slots = forbidden_input_slots.clone();
    let mut launches = Vec::new();

    // Validate every interior level exactly as the per-level plan always has.
    let mut interior_levels = Vec::with_capacity(interior_outputs.len());
    let mut current = leaf_hashes;
    let mut current_hashes = leaf_size;
    for (level, &output) in interior_outputs.iter().enumerate() {
        require_same_context(context_token, output)?;
        if current_hashes < 2 {
            return Err(CommitGraphError::InteriorPastRoot(level as u32));
        }
        let aliases_input = output.id() == current.id();
        if aliases_input
            && (in_place_scratch.is_none() || (level as u32 + 1) >= unretained_bottom_layers)
        {
            return Err(CommitGraphError::InPlaceInteriorLayer(output.id()));
        }
        if retained_slots.contains(&output.id()) {
            return Err(CommitGraphError::PrematureArenaSlotReuse(output.id()));
        }
        hash_slots.insert(output.id());
        let output_hashes = current_hashes / 2;
        require_hash_capacity("interior_output", output, output_hashes)?;
        interior_levels.push(if aliases_input {
            CommitLaunch::InteriorLayerInPlace {
                level: level as u32,
                hashes: current,
                scratch_pair: in_place_scratch.expect("alias admission checked"),
                output_hashes,
            }
        } else {
            CommitLaunch::InteriorLayer {
                level: level as u32,
                input: current,
                output,
                output_hashes,
            }
        });
        current = output;
        current_hashes = output_hashes;
        if (level as u32 + 1) >= unretained_bottom_layers {
            retained_slots.insert(output.id());
        }
    }

    // Emission is byte-for-byte the legacy qualified suffix.
    let mut level = 0usize;
    while level < interior_levels.len() {
        let input = match interior_levels[level] {
            CommitLaunch::InteriorLayer { input, .. } => input,
            CommitLaunch::InteriorLayerInPlace { hashes, .. } => hashes,
            _ => unreachable!("interior_levels contains only interior records"),
        };
        if interior_fused
            && interior4_window_fusible(level, interior_levels.len(), unretained_bottom_layers)
        {
            if let CommitLaunch::InteriorLayer {
                output,
                output_hashes,
                ..
            } = interior_levels[level + 3]
            {
                if output.id() != input.id() {
                    launches.push(CommitLaunch::FusedInterior4 {
                        first_level: level as u32,
                        input,
                        output,
                        output_hashes,
                    });
                    level += 4;
                    continue;
                }
            }
        }
        launches.push(interior_levels[level]);
        level += 1;
    }

    if let Some(tail) = tail {
        if tail.level_outputs.is_empty() {
            return Err(CommitGraphError::EmptyTail);
        }
        if current_hashes > MAX_FUSED_TAIL_HASHES {
            return Err(CommitGraphError::TailTooWide(current_hashes));
        }
        if tail.level_outputs.len() >= 32 {
            return Err(CommitGraphError::TooManyTailLevels(
                tail.level_outputs.len(),
            ));
        }
        require_same_context(context_token, tail.level_ptrs)?;
        input_slots.insert(tail.level_ptrs.id());
        require_pointer_table(
            "tail_level_ptrs",
            tail.level_ptrs,
            tail.level_outputs.len() as u32,
        )?;
        let first_hashes = current_hashes;
        let tail_input = current;
        for &output in &tail.level_outputs {
            require_same_context(context_token, output)?;
            if current_hashes < 2 {
                return Err(CommitGraphError::InteriorPastRoot(launches.len() as u32));
            }
            if output.id() == current.id() {
                return Err(CommitGraphError::InPlaceInteriorLayer(output.id()));
            }
            if retained_slots.contains(&output.id()) {
                return Err(CommitGraphError::PrematureArenaSlotReuse(output.id()));
            }
            hash_slots.insert(output.id());
            retained_slots.insert(output.id());
            current_hashes /= 2;
            require_hash_capacity("tail_output", output, current_hashes)?;
            current = output;
        }
        launches.push(CommitLaunch::FusedTail {
            input: tail_input,
            first_hashes,
            level_ptrs: tail.level_ptrs,
            levels: tail.level_outputs.len() as u32,
        });
    }

    if let Some(id) = hash_slots.intersection(&input_slots).next() {
        return Err(CommitGraphError::AliasedArenaSlot(*id));
    }
    if current_hashes != 1 {
        return Err(CommitGraphError::IncompleteTree(current_hashes));
    }
    Ok(MerkleFromLeavesBuild {
        launches,
        root: current,
    })
}

/// Whether the four consecutive interior levels `[first_level, first_level+4)`
/// may fuse into one `FusedInterior4` launch. Pure planning math (unit-tested
/// below): the window must fit inside the ordinary interior levels (the fused
/// tail handles everything after them), and its three INTERMEDIATE levels —
/// `first_level..first_level+3`, whose distance above the leaves is
/// `level + 1` — must all be unretained (`level + 1 < unretained_bottom_layers`),
/// because the fused kernel keeps them in shared memory and never writes their
/// buffers. The tightest intermediate is level `first_level + 2`, giving
/// `first_level + 3 < unretained_bottom_layers`. The window's OUTPUT level
/// (`first_level + 3`) is always written and may be retained or not.
pub(crate) fn interior4_window_fusible(
    first_level: usize,
    n_interior_levels: usize,
    unretained_bottom_layers: u32,
) -> bool {
    first_level + 4 <= n_interior_levels
        && (first_level as u64) + 3 < u64::from(unretained_bottom_layers)
}

fn require_same_context(
    expected: NonNull<c_void>,
    slice: ArenaSlice,
) -> Result<(), CommitGraphError> {
    if slice.context_token() == expected {
        Ok(())
    } else {
        Err(CommitGraphError::ContextMismatch)
    }
}

fn require_words(
    role: &'static str,
    slice: ArenaSlice,
    required_words: usize,
) -> Result<(), CommitGraphError> {
    if slice.len_words() < required_words {
        Err(CommitGraphError::BufferTooSmall {
            role,
            required_words,
            actual_words: slice.len_words(),
        })
    } else {
        Ok(())
    }
}

fn require_hash_capacity(
    role: &'static str,
    slice: ArenaSlice,
    hashes: u32,
) -> Result<(), CommitGraphError> {
    if (slice.as_u32_ptr() as usize) % core::mem::align_of::<Blake2sHash>() != 0 {
        return Err(CommitGraphError::MisalignedHashBuffer(role));
    }
    let words = (hashes as usize)
        .checked_mul(HASH_WORDS)
        .ok_or(CommitGraphError::SizeOverflow)?;
    require_words(role, slice, words)
}

fn require_pointer_table(
    role: &'static str,
    slice: ArenaSlice,
    pointers: u32,
) -> Result<(), CommitGraphError> {
    if (slice.as_u32_ptr() as usize) % core::mem::align_of::<*mut u32>() != 0 {
        return Err(CommitGraphError::MisalignedPointerTable(role));
    }
    let bytes = (pointers as usize)
        .checked_mul(core::mem::size_of::<*mut u32>())
        .ok_or(CommitGraphError::SizeOverflow)?;
    let words = bytes
        .checked_add(core::mem::size_of::<u32>() - 1)
        .ok_or(CommitGraphError::SizeOverflow)?
        / core::mem::size_of::<u32>();
    require_words(role, slice, words)
}

fn validate_lde_batch(
    group: u32,
    batch: u32,
    params: CommitLdeBatch,
) -> Result<(), CommitGraphError> {
    if params.column_count == 0
        || !(4..=30).contains(&params.log_n)
        || params.eval_domain_size != (1u32 << (params.log_n - 1))
        || params.twiddles_size < params.eval_domain_size
    {
        return Err(CommitGraphError::InvalidLdeGeometry { group, batch });
    }
    require_pointer_table(
        "lde_coefficient_ptrs",
        params.coefficient_ptrs,
        params.column_count,
    )?;
    require_words(
        "lde_coefficient_sizes",
        params.coefficient_sizes,
        params.column_count as usize,
    )?;
    require_pointer_table("lde_column_ptrs", params.column_ptrs, params.column_count)?;
    require_words(
        "lde_twiddles",
        params.twiddles,
        params.twiddles_size as usize,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice(id: u32, words: usize) -> ArenaSlice {
        ArenaSlice::dangling_for_test(id, words)
    }

    fn batch(id: u32, columns: u32) -> CommitLdeBatch {
        CommitLdeBatch {
            coefficient_ptrs: slice(id, columns as usize * 2),
            coefficient_sizes: slice(id + 1, columns as usize),
            column_ptrs: slice(id + 2, columns as usize * 2),
            column_count: columns,
            log_n: 6,
            twiddles: slice(id + 3, 64),
            twiddles_size: 64,
            eval_domain_size: 32,
        }
    }

    fn groups() -> Vec<CommitLeafGroup> {
        vec![
            CommitLeafGroup {
                first_column: 0,
                column_count: 16,
                column_ptrs: slice(10, 32),
                column_log_sizes: slice(11, 16),
                lde_batches: vec![batch(20, 16)],
                retain_evaluations: false,
            },
            CommitLeafGroup {
                first_column: 16,
                column_count: 3,
                column_ptrs: slice(13, 6),
                column_log_sizes: slice(14, 3),
                lde_batches: vec![batch(30, 3)],
                retain_evaluations: false,
            },
        ]
    }

    #[test]
    fn extracted_merkle_suffix_is_launch_for_launch_identical_in_both_fusion_modes() {
        for interior_fused in [false, true] {
            let leaves = slice(1, 64 * HASH_WORDS);
            let interior = vec![
                slice(2, 32 * HASH_WORDS),
                leaves,
                slice(2, 8 * HASH_WORDS),
                slice(3, 4 * HASH_WORDS),
            ];
            let tail = CommitTailPlan {
                level_ptrs: slice(4, 4),
                level_outputs: vec![slice(5, 2 * HASH_WORDS), slice(6, HASH_WORDS)],
            };
            let legacy = CommitGraphPlan::new_pruned_with_modes(
                6,
                4,
                leaves,
                groups(),
                interior.clone(),
                Some(tail.clone()),
                interior_fused,
                RetainedLdeHashMode::Separate,
                CommitLeafUpdateMode::Scalar,
            )
            .unwrap();
            let suffix = CommitGraphPlan::new_merkle_from_leaves_with_mode(
                6,
                4,
                leaves,
                interior,
                Some(tail),
                interior_fused,
            )
            .unwrap();
            let legacy_suffix = legacy
                .launch_sequence()
                .filter(|kind| {
                    matches!(
                        kind,
                        CommitLaunchKind::InteriorLayer { .. }
                            | CommitLaunchKind::FusedInterior4 { .. }
                            | CommitLaunchKind::FusedTail { .. }
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(legacy_suffix, suffix.launch_sequence().collect::<Vec<_>>());
            assert_eq!(legacy.root().id(), suffix.root().id());
            if interior_fused {
                assert!(matches!(
                    legacy_suffix[0],
                    CommitLaunchKind::FusedInterior4 { .. }
                ));
            } else {
                assert_eq!(
                    legacy_suffix
                        .iter()
                        .filter(|kind| matches!(kind, CommitLaunchKind::InteriorLayer { .. }))
                        .count(),
                    4
                );
            }
        }
    }

    #[test]
    fn plan_preserves_canonical_launch_order_and_reaches_root() {
        let plan = CommitGraphPlan::new(
            6,
            slice(1, 64 * HASH_WORDS),
            groups(),
            vec![slice(2, 32 * HASH_WORDS), slice(3, 16 * HASH_WORDS)],
            Some(CommitTailPlan {
                level_ptrs: slice(4, 8),
                level_outputs: vec![
                    slice(5, 8 * HASH_WORDS),
                    slice(6, 4 * HASH_WORDS),
                    slice(7, 2 * HASH_WORDS),
                    slice(8, HASH_WORDS),
                ],
            }),
        )
        .unwrap();

        assert_eq!(plan.root().id().0, 8);
        assert_eq!(
            plan.hash_from_tile_telemetry(),
            CommitHashFromTileTelemetry {
                fused_groups: 2,
                fused_columns: 19,
                retained_fused_groups: 0,
                unfused_groups: 0,
                bytes_avoided: 64 * 19 * 8,
            }
        );
        assert_eq!(
            plan.launch_sequence().collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::LeafInit { hashes: 64 },
                CommitLaunchKind::Lde {
                    group: 0,
                    batch: 0,
                    columns: 16,
                    log_n: 6,
                },
                CommitLaunchKind::LeafUpdate {
                    group: 0,
                    first_column: 0,
                    columns: 16,
                    mode: CommitLeafUpdateMode::FromLde,
                },
                CommitLaunchKind::Lde {
                    group: 1,
                    batch: 0,
                    columns: 3,
                    log_n: 6,
                },
                CommitLaunchKind::LeafFinalize {
                    group: 1,
                    first_column: 16,
                    columns: 3,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 0,
                    output_hashes: 32,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 1,
                    output_hashes: 16,
                },
                CommitLaunchKind::FusedTail {
                    first_hashes: 16,
                    levels: 4,
                },
            ]
        );
    }

    #[test]
    fn materialized_leaf_mode_is_sealed_into_the_launch_topology() {
        for mode in [
            CommitLeafUpdateMode::Scalar,
            CommitLeafUpdateMode::Ilp2,
            CommitLeafUpdateMode::Quad,
        ] {
            let mut leaf_groups = groups();
            // Retention prevents the small-log producer-fused lane, exposing
            // the materialized update implementation selected by the caller.
            leaf_groups[0].retain_evaluations = true;
            let plan = CommitGraphPlan::new_pruned_with_modes(
                6,
                0,
                slice(1, 64 * HASH_WORDS),
                leaf_groups,
                (0..6)
                    .map(|level| slice(100 + level, (32usize >> level) * HASH_WORDS))
                    .collect(),
                None,
                false,
                RetainedLdeHashMode::Separate,
                mode,
            )
            .unwrap();
            assert!(plan.launch_sequence().any(|launch| {
                matches!(launch, CommitLaunchKind::LeafUpdate { mode: actual, .. } if actual == mode)
            }));
        }

        assert!(matches!(
            CommitGraphPlan::new_pruned_with_modes(
                6,
                0,
                slice(1, 64 * HASH_WORDS),
                groups(),
                Vec::new(),
                None,
                false,
                RetainedLdeHashMode::Separate,
                CommitLeafUpdateMode::FromLde,
            ),
            Err(CommitGraphError::InvalidLeafUpdateMode)
        ));
    }

    #[test]
    fn full_lifting_hash16_replaces_the_lde_write_and_leaf_reread() {
        let mut group = groups().remove(0);
        group.lde_batches[0].log_n = 13;
        group.lde_batches[0].eval_domain_size = 1 << 12;
        group.lde_batches[0].twiddles = slice(23, 1 << 12);
        group.lde_batches[0].twiddles_size = 1 << 12;
        let interior_outputs = (0..13)
            .map(|level| slice(100 + level, (1usize << (12 - level)) * HASH_WORDS))
            .collect();
        let plan = CommitGraphPlan::new(
            13,
            slice(1, (1 << 13) * HASH_WORDS),
            vec![group],
            interior_outputs,
            None,
        )
        .unwrap();

        assert_eq!(
            plan.launch_sequence().take(2).collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::LeafInit { hashes: 1 << 13 },
                CommitLaunchKind::NttHash {
                    group: 0,
                    columns: 16,
                    log_n: 13,
                },
            ]
        );
        assert_eq!(plan.producer_fused_log_sizes(), &[13]);
        assert_eq!(
            plan.hash_from_tile_telemetry(),
            CommitHashFromTileTelemetry {
                fused_groups: 1,
                fused_columns: 16,
                retained_fused_groups: 0,
                unfused_groups: 0,
                bytes_avoided: 16 * (1 << 13) * 8,
            }
        );
    }

    /// Both retained commit topologies in one process (the env switch is a
    /// process-global OnceLock, so the mode is pinned via
    /// `new_pruned_with_modes`): Separate keeps the Lde + leaf-hash pair and
    /// its full evaluation reread; Fused replaces that pair with one
    /// RetainedNttHash launch under exactly the NttHash shape constraints.
    /// This is the plan-level node-budget gate: one fewer launch per fused
    /// retained group.
    #[test]
    fn retained_full_lifting_group_fuses_only_in_fused_mode() {
        let retained_group = || {
            let mut group = groups().remove(0);
            group.retain_evaluations = true;
            group.lde_batches[0].log_n = 13;
            group.lde_batches[0].eval_domain_size = 1 << 12;
            group.lde_batches[0].twiddles = slice(23, 1 << 12);
            group.lde_batches[0].twiddles_size = 1 << 12;
            group
        };
        let interior_outputs = || {
            (0..13)
                .map(|level| slice(100 + level, (1usize << (12 - level)) * HASH_WORDS))
                .collect::<Vec<_>>()
        };
        let plan = |mode: RetainedLdeHashMode| {
            CommitGraphPlan::new_pruned_with_modes(
                13,
                0,
                slice(1, (1 << 13) * HASH_WORDS),
                vec![retained_group()],
                interior_outputs(),
                None,
                false,
                mode,
                CommitLeafUpdateMode::Scalar,
            )
            .unwrap()
        };

        let separate = plan(RetainedLdeHashMode::Separate);
        assert_eq!(
            separate.launch_sequence().take(3).collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::LeafInit { hashes: 1 << 13 },
                CommitLaunchKind::Lde {
                    group: 0,
                    batch: 0,
                    columns: 16,
                    log_n: 13,
                },
                CommitLaunchKind::LeafFinalize {
                    group: 0,
                    first_column: 0,
                    columns: 16,
                },
            ]
        );
        assert!(separate.retained_fused_log_sizes().is_empty());
        assert_eq!(
            separate.hash_from_tile_telemetry(),
            CommitHashFromTileTelemetry {
                unfused_groups: 1,
                ..Default::default()
            }
        );

        let fused = plan(RetainedLdeHashMode::Fused);
        assert_eq!(
            fused.launch_sequence().take(2).collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::LeafInit { hashes: 1 << 13 },
                CommitLaunchKind::RetainedNttHash {
                    group: 0,
                    columns: 16,
                    log_n: 13,
                },
            ]
        );
        assert_eq!(
            fused.launch_sequence().len() + 1,
            separate.launch_sequence().len()
        );
        assert!(fused.producer_fused_log_sizes().is_empty());
        assert_eq!(fused.retained_fused_log_sizes(), &[13]);
        assert_eq!(
            fused.hash_from_tile_telemetry(),
            CommitHashFromTileTelemetry {
                retained_fused_groups: 1,
                // Only the leaf-hash reread is avoided (the evaluation write
                // stays): 16 columns x 2^13 rows x 4 bytes.
                bytes_avoided: 16 * (1 << 13) * 4,
                ..Default::default()
            }
        );
        assert_eq!(separate.root().id(), fused.root().id());
    }

    /// Fused mode must not widen eligibility beyond the NttHash shape
    /// constraints (here: a lifted `log_n != lifting_log_size` retained
    /// group) and must not perturb the unretained producer-fused lane.
    #[test]
    fn retained_fusion_keeps_ineligible_and_unretained_groups_unchanged() {
        let mut lifted_retained = groups().remove(0);
        lifted_retained.retain_evaluations = true;
        lifted_retained.lde_batches[0].log_n = 12;
        lifted_retained.lde_batches[0].eval_domain_size = 1 << 11;
        lifted_retained.lde_batches[0].twiddles = slice(23, 1 << 11);
        lifted_retained.lde_batches[0].twiddles_size = 1 << 11;

        let mut producer = groups().remove(0);
        producer.first_column = 16;
        producer.column_ptrs = slice(40, 32);
        producer.column_log_sizes = slice(41, 16);
        producer.lde_batches = vec![batch(50, 16)];
        producer.lde_batches[0].log_n = 13;
        producer.lde_batches[0].eval_domain_size = 1 << 12;
        producer.lde_batches[0].twiddles = slice(53, 1 << 12);
        producer.lde_batches[0].twiddles_size = 1 << 12;

        let interior_outputs = (0..13)
            .map(|level| slice(100 + level, (1usize << (12 - level)) * HASH_WORDS))
            .collect::<Vec<_>>();
        let plan = CommitGraphPlan::new_pruned_with_modes(
            13,
            0,
            slice(1, (1 << 13) * HASH_WORDS),
            vec![lifted_retained, producer],
            interior_outputs,
            None,
            false,
            RetainedLdeHashMode::Fused,
            CommitLeafUpdateMode::Scalar,
        )
        .unwrap();

        assert_eq!(
            plan.launch_sequence().take(4).collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::LeafInit { hashes: 1 << 13 },
                CommitLaunchKind::Lde {
                    group: 0,
                    batch: 0,
                    columns: 16,
                    log_n: 12,
                },
                CommitLaunchKind::LeafUpdate {
                    group: 0,
                    first_column: 0,
                    columns: 16,
                    mode: CommitLeafUpdateMode::Scalar,
                },
                CommitLaunchKind::NttHash {
                    group: 1,
                    columns: 16,
                    log_n: 13,
                },
            ]
        );
        assert!(plan.retained_fused_log_sizes().is_empty());
        assert_eq!(plan.producer_fused_log_sizes(), &[13]);
        assert_eq!(
            plan.hash_from_tile_telemetry(),
            CommitHashFromTileTelemetry {
                fused_groups: 1,
                fused_columns: 16,
                retained_fused_groups: 0,
                unfused_groups: 1,
                bytes_avoided: 16 * (1 << 13) * 8,
            }
        );
    }

    #[test]
    fn plan_rejects_noncanonical_groups_and_incomplete_tree() {
        let mut bad_groups = groups();
        bad_groups[1].first_column = 17;
        assert!(matches!(
            CommitGraphPlan::new(6, slice(1, 64 * HASH_WORDS), bad_groups, vec![], None,),
            Err(CommitGraphError::NonCanonicalGroupStart { .. })
        ));

        assert_eq!(
            CommitGraphPlan::new(
                6,
                slice(1, 64 * HASH_WORDS),
                groups(),
                vec![slice(2, 32 * HASH_WORDS)],
                None,
            )
            .unwrap_err(),
            CommitGraphError::IncompleteTree(32)
        );
    }

    #[test]
    fn plan_rejects_lde_count_and_buffer_geometry_mismatches() {
        let mut bad_groups = groups();
        bad_groups[0].lde_batches[0].column_count = 15;
        assert!(matches!(
            CommitGraphPlan::new(6, slice(1, 64 * HASH_WORDS), bad_groups, vec![], None,),
            Err(CommitGraphError::LdeColumnCountMismatch { .. })
        ));

        let mut bad_groups = groups();
        bad_groups[0].column_log_sizes = slice(11, 15);
        assert!(matches!(
            CommitGraphPlan::new(6, slice(1, 64 * HASH_WORDS), bad_groups, vec![], None,),
            Err(CommitGraphError::BufferTooSmall {
                role: "leaf_column_log_sizes",
                ..
            })
        ));

        let mut bad_groups = groups();
        bad_groups[1].lde_batches = vec![batch(30, 1), batch(40, 2)];
        assert!(matches!(
            CommitGraphPlan::new(6, slice(1, 64 * HASH_WORDS), bad_groups, vec![], None,),
            Err(CommitGraphError::InconsistentGroupTwiddles { .. })
        ));
    }

    /// Both interior emission modes in one process (the env switch is a
    /// process-global OnceLock, so the mode is pinned via `new_pruned_impl`):
    /// per-level emits one InteriorLayer per level; the fused lane collapses
    /// the bottom window (whose three intermediates are unretained under
    /// prune depth 4) into one FusedInterior4 and keeps every retained level
    /// on the per-level kernel. This is the plan-level "node budget" gate:
    /// 8 interior nodes per-level vs 5 fused.
    #[test]
    fn pruned_plan_interior_fusion_replaces_the_unretained_bottom_window_only() {
        // lifting 8, prune depth 4: interior levels 0..8 (log 7..0), levels
        // 0,1,2 unretained ping-pong, levels 3..7 retained. No tail.
        let interior_outputs = vec![
            slice(2, 128 * HASH_WORDS), // level 0, scratch pong
            slice(1, 256 * HASH_WORDS), // level 1, leaf ping
            slice(2, 128 * HASH_WORDS), // level 2, scratch pong
            slice(4, 16 * HASH_WORDS),  // level 3, retained (window output)
            slice(5, 8 * HASH_WORDS),
            slice(6, 4 * HASH_WORDS),
            slice(7, 2 * HASH_WORDS),
            slice(8, HASH_WORDS),
        ];
        let plan = |fused: bool| {
            CommitGraphPlan::new_pruned_impl(
                8,
                4,
                slice(1, 256 * HASH_WORDS),
                groups(),
                interior_outputs.clone(),
                None,
                fused,
            )
            .unwrap()
        };

        let interior_kinds = |fused: bool| {
            plan(fused)
                .launch_sequence()
                .filter(|kind| {
                    matches!(
                        kind,
                        CommitLaunchKind::InteriorLayer { .. }
                            | CommitLaunchKind::FusedInterior4 { .. }
                    )
                })
                .collect::<Vec<_>>()
        };

        assert_eq!(
            interior_kinds(false),
            (0..8)
                .map(|level| CommitLaunchKind::InteriorLayer {
                    level,
                    output_hashes: 128 >> level,
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(
            interior_kinds(true),
            [CommitLaunchKind::FusedInterior4 {
                first_level: 0,
                output_hashes: 16,
            }]
            .into_iter()
            .chain((4..8).map(|level| CommitLaunchKind::InteriorLayer {
                level,
                output_hashes: 128 >> level,
            }))
            .collect::<Vec<_>>()
        );
        // Same root and identical validation outcome in both modes.
        assert_eq!(plan(false).root().id(), plan(true).root().id());
    }

    /// The fused kernel forbids in-place operation, so a window whose output
    /// slot ping-pongs back onto its input slot must fall back to per-level
    /// launches even with the lane enabled.
    #[test]
    fn interior_fusion_falls_back_per_level_when_window_output_aliases_input() {
        let interior_outputs = vec![
            slice(2, 128 * HASH_WORDS), // level 0
            slice(3, 64 * HASH_WORDS),  // level 1
            slice(2, 128 * HASH_WORDS), // level 2
            slice(1, 256 * HASH_WORDS), // level 3: output aliases the leaf input
            slice(5, 8 * HASH_WORDS),
            slice(6, 4 * HASH_WORDS),
            slice(7, 2 * HASH_WORDS),
            slice(8, HASH_WORDS),
        ];
        let plan = CommitGraphPlan::new_pruned_impl(
            8,
            4,
            slice(1, 256 * HASH_WORDS),
            groups(),
            interior_outputs,
            None,
            true,
        )
        .unwrap();
        assert_eq!(
            plan.launch_sequence()
                .filter(|kind| matches!(kind, CommitLaunchKind::FusedInterior4 { .. }))
                .count(),
            0
        );
        assert_eq!(
            plan.launch_sequence()
                .filter(|kind| matches!(kind, CommitLaunchKind::InteriorLayer { .. }))
                .count(),
            8
        );
    }

    #[test]
    fn interior4_window_fusibility_requires_unretained_intermediates_and_room() {
        // Prune depth 4: exactly the bottom window fuses.
        assert!(interior4_window_fusible(0, 10, 4));
        assert!(!interior4_window_fusible(1, 10, 4));
        assert!(!interior4_window_fusible(4, 10, 4));
        // The window must fit inside the ordinary interior levels.
        assert!(interior4_window_fusible(0, 4, 4));
        assert!(!interior4_window_fusible(0, 3, 4));
        assert!(!interior4_window_fusible(1, 4, 8));
        // Fully retained trees (no pruning) never fuse.
        assert!(!interior4_window_fusible(0, 10, 0));
        assert!(!interior4_window_fusible(0, 10, 3));
        // Deeper pruning fuses successive aligned windows.
        assert!(interior4_window_fusible(0, 10, 8));
        assert!(interior4_window_fusible(4, 10, 8));
        assert!(!interior4_window_fusible(5, 10, 8));
    }

    #[test]
    fn explicit_in_place_suffix_only_aliases_unretained_bottom_levels() {
        let leaf = slice(1, 16 * HASH_WORDS);
        let scratch = ArenaSlice::dangling_at_for_test(
            1,
            256,
            super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        );
        let outputs = vec![
            slice(1, 8 * HASH_WORDS),
            slice(2, 4 * HASH_WORDS),
            slice(3, 2 * HASH_WORDS),
            slice(4, HASH_WORDS),
        ];
        let plan = CommitGraphPlan::new_merkle_from_leaves_in_place(
            4,
            2,
            leaf,
            scratch,
            outputs.clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            plan.launch_sequence().collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::InteriorLayerInPlace {
                    level: 0,
                    output_hashes: 8,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 1,
                    output_hashes: 4,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 2,
                    output_hashes: 2,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 3,
                    output_hashes: 1,
                },
            ]
        );
        assert_eq!(plan.root().id(), ArenaSlotId(4));
        assert_eq!(
            CommitGraphPlan::new_merkle_from_leaves(4, 2, leaf, outputs, None).unwrap_err(),
            CommitGraphError::InPlaceInteriorLayer(ArenaSlotId(1))
        );
    }

    #[test]
    fn explicit_in_place_fusion_crosses_only_the_retained_boundary() {
        let leaf = slice(1, 64 * HASH_WORDS);
        let scratch = ArenaSlice::dangling_at_for_test(
            1,
            1024,
            super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        );
        let outputs = vec![
            slice(1, 32 * HASH_WORDS),
            slice(1, 16 * HASH_WORDS),
            slice(1, 8 * HASH_WORDS),
            slice(2, 4 * HASH_WORDS),
            slice(3, 2 * HASH_WORDS),
            slice(4, HASH_WORDS),
        ];
        let plan = CommitGraphPlan::new_merkle_from_leaves_in_place_with_mode(
            6, 4, leaf, scratch, outputs, None, true,
        )
        .unwrap();
        assert_eq!(
            plan.launch_sequence().collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::FusedInterior4 {
                    first_level: 0,
                    output_hashes: 4,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 4,
                    output_hashes: 2,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 5,
                    output_hashes: 1,
                },
            ]
        );

        let deeper = vec![
            slice(1, 32 * HASH_WORDS),
            slice(1, 16 * HASH_WORDS),
            slice(1, 8 * HASH_WORDS),
            slice(1, 4 * HASH_WORDS),
            slice(3, 2 * HASH_WORDS),
            slice(4, HASH_WORDS),
        ];
        let plan = CommitGraphPlan::new_merkle_from_leaves_in_place_with_mode(
            6, 5, leaf, scratch, deeper, None, true,
        )
        .unwrap();
        assert_eq!(
            plan.launch_sequence().collect::<Vec<_>>(),
            vec![
                CommitLaunchKind::InteriorLayerInPlace {
                    level: 0,
                    output_hashes: 32,
                },
                CommitLaunchKind::FusedInterior4 {
                    first_level: 1,
                    output_hashes: 2,
                },
                CommitLaunchKind::InteriorLayer {
                    level: 5,
                    output_hashes: 1,
                },
            ]
        );
    }

    #[test]
    fn in_place_suffix_rejects_retained_alias_and_invalid_scratch() {
        let leaf = slice(1, 16 * HASH_WORDS);
        let scratch = ArenaSlice::dangling_at_for_test(
            1,
            256,
            super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        );
        let retained_alias = vec![
            slice(1, 8 * HASH_WORDS),
            slice(1, 4 * HASH_WORDS),
            slice(3, 2 * HASH_WORDS),
            slice(4, HASH_WORDS),
        ];
        assert_eq!(
            CommitGraphPlan::new_merkle_from_leaves_in_place(
                4,
                2,
                leaf,
                scratch,
                retained_alias,
                None,
            )
            .unwrap_err(),
            CommitGraphError::InPlaceInteriorLayer(ArenaSlotId(1))
        );
        let outputs = vec![
            slice(1, 8 * HASH_WORDS),
            slice(2, 4 * HASH_WORDS),
            slice(3, 2 * HASH_WORDS),
            slice(4, HASH_WORDS),
        ];
        assert_eq!(
            CommitGraphPlan::new_merkle_from_leaves_in_place(
                4,
                0,
                leaf,
                scratch,
                outputs.clone(),
                None,
            )
            .unwrap_err(),
            CommitGraphError::InvalidInPlaceScratch
        );
        assert_eq!(
            CommitGraphPlan::new_merkle_from_leaves_in_place(
                4,
                2,
                leaf,
                ArenaSlice::dangling_at_for_test(
                    1,
                    32,
                    super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
                ),
                outputs,
                None,
            )
            .unwrap_err(),
            CommitGraphError::InvalidInPlaceScratch
        );
    }

    #[test]
    fn pruned_plan_allows_ordered_ping_pong_but_not_premature_reuse() {
        let plan = CommitGraphPlan::new_pruned(
            6,
            3,
            slice(1, 64 * HASH_WORDS),
            groups(),
            vec![
                slice(2, 32 * HASH_WORDS),
                slice(1, 64 * HASH_WORDS),
                slice(3, 8 * HASH_WORDS),
                slice(4, 4 * HASH_WORDS),
                slice(5, 2 * HASH_WORDS),
                slice(6, HASH_WORDS),
            ],
            None,
        )
        .unwrap();
        assert_eq!(plan.root().id(), ArenaSlotId(6));

        assert_eq!(
            CommitGraphPlan::new_pruned(
                6,
                1,
                slice(1, 64 * HASH_WORDS),
                groups(),
                vec![
                    slice(2, 32 * HASH_WORDS),
                    slice(3, 16 * HASH_WORDS),
                    // Slot 2 is a retained log-5 layer and is still needed by decommit.
                    slice(2, 32 * HASH_WORDS),
                ],
                None,
            )
            .unwrap_err(),
            CommitGraphError::PrematureArenaSlotReuse(ArenaSlotId(2))
        );
    }
}
