//! Device-query-driven PCS/FRI decommitment.
//!
//! The transcript writes raw queries into an arena slice. This module sorts and
//! deduplicates them on the proof stream, opens every trace/FRI tree without a
//! host row list, rebuilds pruned trace nodes from sparse resident LDE rows, and
//! emits one compact word buffer. Setup owns every descriptor upload; launch
//! methods allocate, transfer, synchronize, and touch the default stream zero
//! times. Production may bind the assembly directly into a larger proof bundle;
//! `read_assembly_once` remains the standalone diagnostic D2H boundary.
//!
//! The remaining host adapter is deliberately mechanical: attach roots,
//! sampled values, PoW/config, and the last-layer polynomial already produced
//! by their resident stages; then decode each metadata section into
//! `MerkleDecommitmentLifted`, `MerkleDecommitmentLiftedAux`, and
//! `FriLayerProof` in tree order. No hash, row lookup, fold, or transcript work
//! remains after this buffer is copied.

use core::ffi::c_void;
use std::collections::BTreeSet;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
const HASH_WORDS: usize = 8;
const POINTER_WORDS: usize = core::mem::size_of::<*const u32>().div_ceil(WORD_BYTES);
const HEADER_WORDS: usize = 8;
const TREE_META_WORDS: usize = 16;
const AUX_NODE_WORDS: usize = 10;
const MAGIC: u32 = 0x4457_5453;
const VERSION: u32 = 1;
const COUNT_UNIQUE: usize = 0;
const COUNT_MAPPED: usize = 1;
const COUNT_WALK: usize = 2;
const COUNT_EXPANDED: usize = 3;
const COUNT_SPARSE_BASE: usize = 4;

pub const DECOMMIT_POINTER_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<*const u32>() / WORD_BYTES;
pub const DECOMMIT_HASH_ALIGNMENT_WORDS: usize =
    core::mem::align_of::<stwo_backend_cuda_kernels::raw::Blake2sHash>() / WORD_BYTES;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum TraceTreeRole {
    Preprocessed = 0,
    Base = 1,
    Interaction = 2,
    Composition = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecommitSourceMode {
    ResidentEvaluations,
    RecomputeQueriedLde,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecommitColumnGeometry {
    /// Coefficient log size. Only read in `RecomputeQueriedLde` mode.
    pub coefficient_log_size: u32,
    /// Log size of the committed bit-reversed evaluation.
    pub evaluation_log_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceSourceGroupGeometry {
    pub mode: DecommitSourceMode,
    pub columns: Vec<DecommitColumnGeometry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceDecommitGeometry {
    pub role: TraceTreeRole,
    /// Domain on which this tree receives PCS queries. For the preprocessed
    /// tree this is its commitment log; other trace trees use `query_log_size`.
    pub tree_query_log_size: u32,
    pub leaf_log_size: u32,
    pub unretained_bottom_layers: u32,
    /// Canonical column order, partitioned exactly at Blake2s block boundaries.
    pub groups: Vec<TraceSourceGroupGeometry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriDecommitGeometry {
    /// Zero-based order among committed FRI trees.
    pub fri_tree_index: u32,
    pub evaluation_log_size: u32,
    /// Folds from the original quotient domain to this tree's evaluation.
    pub cumulative_fold: u32,
    pub outgoing_fold_step: u32,
    pub log_rows_per_leaf: u32,
}

impl FriDecommitGeometry {
    pub fn leaf_log_size(self) -> u32 {
        self.evaluation_log_size - self.log_rows_per_leaf
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecommitTreeGeometry {
    Trace(TraceDecommitGeometry),
    Fri(FriDecommitGeometry),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecommitWorkspaceConfig {
    pub query_log_size: u32,
    pub n_queries: u32,
    /// Trace trees first in canonical PCS order, then FRI trees in commit order.
    pub trees: Vec<DecommitTreeGeometry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecommitArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceGroupRequirements {
    pub column_count: usize,
    pub coefficient_pointer_words: Option<usize>,
    pub coefficient_size_words: Option<usize>,
    pub lde_tile_words: Option<usize>,
    /// Contiguous same-log ranges launched through `stwo_lde_n2b_columns_on`.
    pub lde_batches: Vec<(usize, usize, u32)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceTreeRequirements {
    pub column_count: usize,
    /// One canonical, tree-owned descriptor sequence. Group execution binds
    /// checked subranges instead of owning duplicate pointer/log tables.
    pub evaluation_pointer_words: usize,
    pub evaluation_log_words: usize,
    pub max_leaf_count: usize,
    pub sparse_level_capacities: Vec<usize>,
    pub sparse_level_offsets: Vec<u32>,
    pub retained_pointer_words: usize,
    pub groups: Vec<TraceGroupRequirements>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriTreeRequirements {
    pub max_expanded_positions: usize,
    pub retained_pointer_words: usize,
    pub coordinate_pointer_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecommitTreeRequirements {
    Trace(TraceTreeRequirements),
    Fri(FriTreeRequirements),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecommitWorkspaceRequirements {
    pub config: DecommitWorkspaceConfig,
    pub unique_query_words: usize,
    pub mapped_query_words: usize,
    pub walk_query_words: usize,
    pub expanded_position_words: usize,
    pub sparse_index_words: usize,
    pub sparse_hash_words: usize,
    pub count_words: usize,
    pub assembly_words: usize,
    pub trees: Vec<DecommitTreeRequirements>,
}

/// Capacity-model delta from writing queried values straight into the compact
/// proof bundle instead of round-tripping through a max-sized value slab.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecommitDirectPackModel {
    pub eliminated_arena_words: usize,
    /// Trace gathers become direct final-layout packs at equal launch count.
    pub direct_trace_pack_launches: usize,
    /// FRI gathers disappear because assembly reads retained coordinates.
    pub eliminated_gather_launches: usize,
    pub eliminated_staging_traffic_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceSourceGroupSlots {
    pub coefficient_ptrs: Option<ArenaSlotId>,
    pub coefficient_sizes: Option<ArenaSlotId>,
    pub lde_output_ptrs: Option<ArenaSlotId>,
    pub lde_tile: Option<ArenaSlotId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceDecommitSlots {
    pub evaluation_ptrs: ArenaSlotId,
    pub evaluation_log_sizes: ArenaSlotId,
    pub retained_layers_by_log: ArenaSlotId,
    pub sparse_level_offsets: ArenaSlotId,
    pub groups: Vec<TraceSourceGroupSlots>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriDecommitSlots {
    pub coordinate_ptrs: ArenaSlotId,
    pub retained_layers_by_log: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecommitTreeSlots {
    Trace(TraceDecommitSlots),
    Fri(FriDecommitSlots),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecommitWorkspaceSlots {
    pub unique_queries: ArenaSlotId,
    pub mapped_queries: ArenaSlotId,
    pub walk_queries: ArenaSlotId,
    pub walk_scratch: ArenaSlotId,
    pub expanded_positions: ArenaSlotId,
    pub sparse_indices: ArenaSlotId,
    pub sparse_hashes: ArenaSlotId,
    pub counts: ArenaSlotId,
    pub assembly: ArenaSlotId,
    pub trees: Vec<DecommitTreeSlots>,
}

#[derive(Clone, Copy, Debug)]
pub enum DecommitColumnSource {
    ResidentEvaluation(ArenaSlice),
    Coefficients(ArenaSlice),
}

#[derive(Clone, Debug)]
pub struct TraceSourceGroup {
    pub columns: Vec<DecommitColumnSource>,
}

#[derive(Clone, Debug)]
pub struct TraceDecommitSources {
    pub groups: Vec<TraceSourceGroup>,
    /// Bottom-up retained layers from `PreparedCommitGraph`.
    pub retained_layers_bottom_up: Vec<ArenaSlice>,
}

#[derive(Clone, Debug)]
pub struct FriDecommitOwnedSources {
    pub evaluation: ArenaSlice,
    pub coordinate_stride: usize,
    pub retained_layers_bottom_up: Vec<ArenaSlice>,
}

#[derive(Clone, Debug)]
pub enum DecommitTreeSources {
    Trace(TraceDecommitSources),
    Fri(FriDecommitOwnedSources),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedDecommitError {
    InvalidQueryLogSize(u32),
    InvalidQueryCount(u32),
    NoTrees,
    NonCanonicalTreeOrder(usize),
    InvalidTraceGeometry(usize),
    InvalidFriGeometry(usize),
    InvalidGroupWidth {
        tree: usize,
        group: usize,
        width: usize,
    },
    NonCanonicalColumnOrder {
        tree: usize,
        group: usize,
    },
    SizeOverflow,
    SlotShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    DuplicateSlot(ArenaSlotId),
    ContextMismatch(ArenaSlotId),
    AssemblySlotMismatch {
        expected: ArenaSlotId,
        actual: ArenaSlotId,
    },
    SourceAliasesWorkspace(ArenaSlotId),
    SourceModeMismatch {
        tree: usize,
        group: usize,
        column: usize,
    },
    SourceTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedSlot {
        slot: ArenaSlotId,
        alignment_words: usize,
    },
    MissingTwiddles,
    TwiddlesTooSmall {
        required_words: usize,
        actual_words: usize,
    },
    InvalidTreeIndex(usize),
    WrongTreeKind(usize),
    AssemblyCorrupt(&'static str),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedDecommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA decommitment: {self:?}")
    }
}

impl std::error::Error for PreparedDecommitError {}

impl From<ArenaError> for PreparedDecommitError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedDecommitError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

pub fn decommit_workspace_requirements(
    config: DecommitWorkspaceConfig,
) -> Result<DecommitWorkspaceRequirements, PreparedDecommitError> {
    if config.query_log_size == 0 || config.query_log_size >= 31 {
        return Err(PreparedDecommitError::InvalidQueryLogSize(
            config.query_log_size,
        ));
    }
    if config.n_queries == 0 {
        return Err(PreparedDecommitError::InvalidQueryCount(config.n_queries));
    }
    if config.trees.is_empty() {
        return Err(PreparedDecommitError::NoTrees);
    }

    let n_queries = config.n_queries as usize;
    let mut seen_fri = false;
    let mut previous_trace = None;
    let mut next_fri = 0u32;
    let mut max_walk = n_queries;
    let mut max_expanded = 1usize;
    let mut max_sparse_words = 1usize;
    let mut max_sparse_levels = 0usize;
    let mut assembly_words = HEADER_WORDS
        .checked_add(
            config
                .trees
                .len()
                .checked_mul(TREE_META_WORDS)
                .ok_or(PreparedDecommitError::SizeOverflow)?,
        )
        .and_then(|value| value.checked_add(2 * n_queries))
        .ok_or(PreparedDecommitError::SizeOverflow)?;
    let mut trees = Vec::with_capacity(config.trees.len());

    for (tree_index, tree) in config.trees.iter().enumerate() {
        match tree {
            DecommitTreeGeometry::Trace(trace) => {
                if seen_fri || previous_trace.is_some_and(|role| trace.role <= role) {
                    return Err(PreparedDecommitError::NonCanonicalTreeOrder(tree_index));
                }
                previous_trace = Some(trace.role);
                if trace.tree_query_log_size == 0
                    || trace.tree_query_log_size >= 31
                    || trace.leaf_log_size >= 31
                    || trace.unretained_bottom_layers > trace.leaf_log_size
                    || trace.groups.is_empty()
                {
                    return Err(PreparedDecommitError::InvalidTraceGeometry(tree_index));
                }
                let mut column_count = 0usize;
                let mut previous_log = None;
                let mut group_requirements = Vec::with_capacity(trace.groups.len());
                for (group_index, group) in trace.groups.iter().enumerate() {
                    let width = group.columns.len();
                    let final_group = group_index + 1 == trace.groups.len();
                    if width == 0
                        || (final_group && width > 16)
                        || (!final_group && width % 16 != 0)
                    {
                        return Err(PreparedDecommitError::InvalidGroupWidth {
                            tree: tree_index,
                            group: group_index,
                            width,
                        });
                    }
                    let mut tile_words = 0usize;
                    for column in &group.columns {
                        if column.evaluation_log_size == 0
                            || column.coefficient_log_size >= 31
                            || column.evaluation_log_size >= 31
                            || column.coefficient_log_size > column.evaluation_log_size
                            || column.evaluation_log_size > trace.leaf_log_size
                            || previous_log.is_some_and(|log| column.evaluation_log_size < log)
                        {
                            return Err(PreparedDecommitError::NonCanonicalColumnOrder {
                                tree: tree_index,
                                group: group_index,
                            });
                        }
                        previous_log = Some(column.evaluation_log_size);
                        tile_words = tile_words
                            .checked_add(pow2(column.evaluation_log_size)?)
                            .ok_or(PreparedDecommitError::SizeOverflow)?;
                    }
                    column_count = column_count
                        .checked_add(width)
                        .ok_or(PreparedDecommitError::SizeOverflow)?;
                    let mut batches = Vec::new();
                    if group.mode == DecommitSourceMode::RecomputeQueriedLde {
                        let mut start = 0;
                        while start < width {
                            let log = group.columns[start].evaluation_log_size;
                            let mut end = start + 1;
                            while end < width && group.columns[end].evaluation_log_size == log {
                                end += 1;
                            }
                            batches.push((start, end - start, log));
                            start = end;
                        }
                    }
                    group_requirements.push(TraceGroupRequirements {
                        column_count: width,
                        coefficient_pointer_words: (group.mode
                            == DecommitSourceMode::RecomputeQueriedLde)
                            .then_some(pointer_words(width)?),
                        coefficient_size_words: (group.mode
                            == DecommitSourceMode::RecomputeQueriedLde)
                            .then_some(width),
                        lde_tile_words: (group.mode == DecommitSourceMode::RecomputeQueriedLde)
                            .then_some(tile_words),
                        lde_batches: batches,
                    });
                }
                let max_leaf_count = n_queries
                    .checked_mul(pow2(trace.unretained_bottom_layers)?)
                    .ok_or(PreparedDecommitError::SizeOverflow)?;
                let sparse_level_capacities: Vec<_> = (0..trace.unretained_bottom_layers)
                    .map(|distance| max_leaf_count >> distance)
                    .collect();
                let mut running = 0usize;
                let sparse_level_offsets: Vec<u32> = sparse_level_capacities
                    .iter()
                    .map(|&capacity| {
                        let offset = u32::try_from(running)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?;
                        running = running
                            .checked_add(capacity)
                            .ok_or(PreparedDecommitError::SizeOverflow)?;
                        Ok::<u32, PreparedDecommitError>(offset)
                    })
                    .collect::<Result<_, _>>()?;
                max_sparse_words = max_sparse_words.max(running.max(1));
                max_sparse_levels = max_sparse_levels.max(sparse_level_capacities.len());
                assembly_words = assembly_words
                    .checked_add(n_queries)
                    .and_then(|v| v.checked_add(column_count.checked_mul(n_queries)?))
                    .and_then(|v| {
                        v.checked_add(
                            n_queries
                                .checked_mul(trace.leaf_log_size as usize)?
                                .checked_mul(HASH_WORDS)?,
                        )
                    })
                    .and_then(|v| {
                        v.checked_add(
                            n_queries
                                .checked_mul(trace.leaf_log_size as usize)?
                                .checked_mul(2 * AUX_NODE_WORDS)?,
                        )
                    })
                    .ok_or(PreparedDecommitError::SizeOverflow)?;
                trees.push(DecommitTreeRequirements::Trace(TraceTreeRequirements {
                    column_count,
                    evaluation_pointer_words: pointer_words(column_count)?,
                    evaluation_log_words: column_count,
                    max_leaf_count,
                    sparse_level_capacities,
                    sparse_level_offsets,
                    retained_pointer_words: pointer_words(trace.leaf_log_size as usize + 1)?,
                    groups: group_requirements,
                }));
            }
            DecommitTreeGeometry::Fri(fri) => {
                seen_fri = true;
                if fri.fri_tree_index != next_fri {
                    return Err(PreparedDecommitError::NonCanonicalTreeOrder(tree_index));
                }
                next_fri += 1;
                if fri.evaluation_log_size == 0
                    || fri.evaluation_log_size >= 31
                    || fri.log_rows_per_leaf > fri.evaluation_log_size
                    || !matches!(fri.log_rows_per_leaf, 0 | 2)
                    || fri.outgoing_fold_step == 0
                    || fri.outgoing_fold_step >= 31
                    || fri.cumulative_fold + fri.evaluation_log_size != config.query_log_size
                {
                    return Err(PreparedDecommitError::InvalidFriGeometry(tree_index));
                }
                let max_positions = n_queries
                    .checked_mul(pow2(fri.outgoing_fold_step)?)
                    .ok_or(PreparedDecommitError::SizeOverflow)?;
                max_expanded = max_expanded.max(max_positions);
                max_walk = max_walk.max(max_positions);
                let leaf_log = fri.leaf_log_size() as usize;
                assembly_words = assembly_words
                    .checked_add(n_queries)
                    .and_then(|v| v.checked_add(max_positions.checked_mul(4)?))
                    .and_then(|v| {
                        v.checked_add(
                            max_positions
                                .checked_mul(leaf_log)?
                                .checked_mul(HASH_WORDS)?,
                        )
                    })
                    .and_then(|v| {
                        v.checked_add(
                            max_positions
                                .checked_mul(leaf_log)?
                                .checked_mul(2 * AUX_NODE_WORDS)?,
                        )
                    })
                    .and_then(|v| v.checked_add(max_positions.checked_mul(5)?))
                    .ok_or(PreparedDecommitError::SizeOverflow)?;
                trees.push(DecommitTreeRequirements::Fri(FriTreeRequirements {
                    max_expanded_positions: max_positions,
                    retained_pointer_words: pointer_words(leaf_log + 1)?,
                    coordinate_pointer_words: pointer_words(4)?,
                }));
            }
        }
    }

    Ok(DecommitWorkspaceRequirements {
        config,
        unique_query_words: n_queries,
        mapped_query_words: n_queries,
        walk_query_words: max_walk,
        expanded_position_words: max_expanded,
        sparse_index_words: max_sparse_words,
        sparse_hash_words: max_sparse_words
            .checked_mul(HASH_WORDS)
            .ok_or(PreparedDecommitError::SizeOverflow)?,
        count_words: COUNT_SPARSE_BASE + max_sparse_levels.max(1),
        assembly_words,
        trees,
    })
}

fn pow2(log_size: u32) -> Result<usize, PreparedDecommitError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedDecommitError::SizeOverflow)
}

fn pointer_words(count: usize) -> Result<usize, PreparedDecommitError> {
    count
        .checked_mul(POINTER_WORDS)
        .ok_or(PreparedDecommitError::SizeOverflow)
}

impl DecommitWorkspaceRequirements {
    pub fn direct_pack_capacity_model(
        &self,
    ) -> Result<DecommitDirectPackModel, PreparedDecommitError> {
        let queries = self.config.n_queries as usize;
        let mut eliminated_arena_words = 1usize;
        let mut direct_trace_pack_launches = 0usize;
        let mut eliminated_gather_launches = 0usize;
        let mut staged_words = 0usize;
        for tree in &self.trees {
            let words = match tree {
                DecommitTreeRequirements::Trace(tree) => {
                    let all_resident = tree
                        .groups
                        .iter()
                        .all(|group| group.coefficient_pointer_words.is_none());
                    direct_trace_pack_launches = direct_trace_pack_launches
                        .checked_add(if all_resident { 1 } else { tree.groups.len() })
                        .ok_or(PreparedDecommitError::SizeOverflow)?;
                    tree.column_count
                        .checked_mul(queries)
                        .ok_or(PreparedDecommitError::SizeOverflow)?
                }
                DecommitTreeRequirements::Fri(tree) => {
                    eliminated_gather_launches = eliminated_gather_launches
                        .checked_add(1)
                        .ok_or(PreparedDecommitError::SizeOverflow)?;
                    tree.max_expanded_positions
                        .checked_mul(4)
                        .ok_or(PreparedDecommitError::SizeOverflow)?
                }
            };
            eliminated_arena_words = eliminated_arena_words.max(words);
            staged_words = staged_words
                .checked_add(words)
                .ok_or(PreparedDecommitError::SizeOverflow)?;
        }
        let eliminated_staging_traffic_bytes = u64::try_from(staged_words)
            .map_err(|_| PreparedDecommitError::SizeOverflow)?
            .checked_mul(2 * WORD_BYTES as u64)
            .ok_or(PreparedDecommitError::SizeOverflow)?;
        Ok(DecommitDirectPackModel {
            eliminated_arena_words,
            direct_trace_pack_launches,
            eliminated_gather_launches,
            eliminated_staging_traffic_bytes,
        })
    }

    pub fn arena_slot_requirements(
        &self,
        slots: &DecommitWorkspaceSlots,
    ) -> Result<Vec<DecommitArenaSlotRequirement>, PreparedDecommitError> {
        if slots.trees.len() != self.trees.len() {
            return Err(PreparedDecommitError::SlotShapeMismatch {
                role: "trees",
                expected: self.trees.len(),
                actual: slots.trees.len(),
            });
        }
        let mut output = vec![
            slot(slots.unique_queries, self.unique_query_words, 1),
            slot(slots.mapped_queries, self.mapped_query_words, 1),
            slot(slots.walk_queries, self.walk_query_words, 1),
            slot(slots.walk_scratch, self.walk_query_words, 1),
            slot(slots.expanded_positions, self.expanded_position_words, 1),
            slot(slots.sparse_indices, self.sparse_index_words, 1),
            slot(
                slots.sparse_hashes,
                self.sparse_hash_words,
                DECOMMIT_HASH_ALIGNMENT_WORDS,
            ),
            slot(slots.counts, self.count_words, 1),
            slot(slots.assembly, self.assembly_words, 1),
        ];
        for (tree_index, (requirements, tree_slots)) in
            self.trees.iter().zip(&slots.trees).enumerate()
        {
            match (requirements, tree_slots) {
                (DecommitTreeRequirements::Trace(tree), DecommitTreeSlots::Trace(tree_slots)) => {
                    if tree.groups.len() != tree_slots.groups.len() {
                        return Err(PreparedDecommitError::SlotShapeMismatch {
                            role: "trace groups",
                            expected: tree.groups.len(),
                            actual: tree_slots.groups.len(),
                        });
                    }
                    output.push(slot(
                        tree_slots.retained_layers_by_log,
                        tree.retained_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ));
                    output.push(slot(
                        tree_slots.sparse_level_offsets,
                        tree.sparse_level_offsets.len().max(1),
                        1,
                    ));
                    output.push(slot(
                        tree_slots.evaluation_ptrs,
                        tree.evaluation_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ));
                    output.push(slot(
                        tree_slots.evaluation_log_sizes,
                        tree.evaluation_log_words,
                        1,
                    ));
                    for (group, group_slots) in tree.groups.iter().zip(&tree_slots.groups) {
                        match (
                            group.coefficient_pointer_words,
                            group.coefficient_size_words,
                            group.lde_tile_words,
                            group_slots.coefficient_ptrs,
                            group_slots.coefficient_sizes,
                            group_slots.lde_output_ptrs,
                            group_slots.lde_tile,
                        ) {
                            (
                                Some(ptrs),
                                Some(sizes),
                                Some(tile),
                                Some(cp),
                                Some(cs),
                                Some(op),
                                Some(t),
                            ) => {
                                output.push(slot(cp, ptrs, DECOMMIT_POINTER_ALIGNMENT_WORDS));
                                output.push(slot(cs, sizes, 1));
                                output.push(slot(op, ptrs, DECOMMIT_POINTER_ALIGNMENT_WORDS));
                                output.push(slot(t, tile, 1));
                            }
                            (None, None, None, None, None, None, None) => {}
                            _ => {
                                return Err(PreparedDecommitError::SlotShapeMismatch {
                                    role: "trace recompute group",
                                    expected: usize::from(group.lde_tile_words.is_some()),
                                    actual: 1,
                                });
                            }
                        }
                    }
                }
                (DecommitTreeRequirements::Fri(tree), DecommitTreeSlots::Fri(tree_slots)) => {
                    output.push(slot(
                        tree_slots.coordinate_ptrs,
                        tree.coordinate_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ));
                    output.push(slot(
                        tree_slots.retained_layers_by_log,
                        tree.retained_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ));
                }
                _ => return Err(PreparedDecommitError::WrongTreeKind(tree_index)),
            }
        }
        // Recomputed LDE groups execute serially and may deliberately share
        // one max-sized tile. Every descriptor and all other scratch remains
        // exclusive; allowing any of those to alias would corrupt capture.
        let shared_lde_tiles = slots
            .trees
            .iter()
            .filter_map(|tree| match tree {
                DecommitTreeSlots::Trace(tree) => Some(
                    tree.groups
                        .iter()
                        .filter_map(|group| group.lde_tile)
                        .collect::<Vec<_>>(),
                ),
                DecommitTreeSlots::Fri(_) => None,
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        let mut exclusive = BTreeSet::new();
        for id in exclusive_decommit_slot_ids(slots) {
            if shared_lde_tiles.contains(&id) || !exclusive.insert(id) {
                return Err(PreparedDecommitError::DuplicateSlot(id));
            }
        }
        Ok(output)
    }
}

fn exclusive_decommit_slot_ids(slots: &DecommitWorkspaceSlots) -> Vec<ArenaSlotId> {
    let mut ids = vec![
        slots.unique_queries,
        slots.mapped_queries,
        slots.walk_queries,
        slots.walk_scratch,
        slots.expanded_positions,
        slots.sparse_indices,
        slots.sparse_hashes,
        slots.counts,
        slots.assembly,
    ];
    for tree in &slots.trees {
        match tree {
            DecommitTreeSlots::Trace(tree) => {
                ids.extend([
                    tree.evaluation_ptrs,
                    tree.evaluation_log_sizes,
                    tree.retained_layers_by_log,
                    tree.sparse_level_offsets,
                ]);
                for group in &tree.groups {
                    ids.extend(group.coefficient_ptrs);
                    ids.extend(group.coefficient_sizes);
                    ids.extend(group.lde_output_ptrs);
                }
            }
            DecommitTreeSlots::Fri(tree) => {
                ids.extend([tree.coordinate_ptrs, tree.retained_layers_by_log]);
            }
        }
    }
    ids
}

fn slot(id: ArenaSlotId, len_words: usize, alignment_words: usize) -> DecommitArenaSlotRequirement {
    DecommitArenaSlotRequirement {
        id,
        len_words: len_words.max(1),
        alignment_words,
    }
}

#[derive(Clone, Copy, Debug)]
struct LdeBatch {
    start: usize,
    count: usize,
    evaluation_log_size: u32,
}

#[derive(Debug)]
struct PreparedTraceGroup {
    coefficient_ptrs: Option<ArenaSlice>,
    coefficient_sizes: Option<ArenaSlice>,
    lde_output_ptrs: Option<ArenaSlice>,
    batches: Vec<LdeBatch>,
    first_column: usize,
    column_count: usize,
}

#[derive(Debug)]
struct PreparedTraceTree {
    role: TraceTreeRole,
    tree_query_log_size: u32,
    leaf_log_size: u32,
    unretained_bottom_layers: u32,
    column_count: usize,
    max_leaf_count: usize,
    sparse_level_capacities: Vec<usize>,
    sparse_level_offsets: Vec<u32>,
    sparse_level_offsets_device: ArenaSlice,
    evaluation_ptrs: ArenaSlice,
    evaluation_log_sizes: ArenaSlice,
    retained_layers_by_log: ArenaSlice,
    groups: Vec<PreparedTraceGroup>,
}

#[derive(Debug)]
struct PreparedFriTree {
    cumulative_fold: u32,
    outgoing_fold_step: u32,
    log_rows_per_leaf: u32,
    leaf_log_size: u32,
    coordinate_ptrs: ArenaSlice,
    retained_layers_by_log: ArenaSlice,
}

#[derive(Debug)]
enum PreparedTree {
    Trace(PreparedTraceTree),
    Fri(PreparedFriTree),
}

pub struct PreparedDecommitGraph<'a> {
    arena: &'a DeviceArena,
    requirements: DecommitWorkspaceRequirements,
    raw_queries: ArenaSlice,
    lde_twiddles: Option<ArenaSlice>,
    unique_queries: ArenaSlice,
    mapped_queries: ArenaSlice,
    walk_queries: ArenaSlice,
    walk_scratch: ArenaSlice,
    expanded_positions: ArenaSlice,
    sparse_indices: ArenaSlice,
    sparse_hashes: ArenaSlice,
    counts: ArenaSlice,
    assembly: ArenaSlice,
    trees: Vec<PreparedTree>,
}

impl<'a> PreparedDecommitGraph<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        arena: &'a DeviceArena,
        config: DecommitWorkspaceConfig,
        raw_queries: ArenaSlice,
        lde_twiddles: Option<ArenaSlice>,
        sources: &[DecommitTreeSources],
        slots: &DecommitWorkspaceSlots,
    ) -> Result<Self, PreparedDecommitError> {
        Self::prepare_with_destination(
            arena,
            config,
            raw_queries,
            lde_twiddles,
            sources,
            slots,
            None,
        )
    }

    /// Prepare against an exact caller-owned assembly view. The destination
    /// must retain `slots.assembly` as its arena identity; only its base pointer
    /// and logical extent may narrow to a proven subrange such as the final
    /// proof-bundle tail.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_into(
        arena: &'a DeviceArena,
        config: DecommitWorkspaceConfig,
        raw_queries: ArenaSlice,
        lde_twiddles: Option<ArenaSlice>,
        sources: &[DecommitTreeSources],
        slots: &DecommitWorkspaceSlots,
        assembly: ArenaSlice,
    ) -> Result<Self, PreparedDecommitError> {
        Self::prepare_with_destination(
            arena,
            config,
            raw_queries,
            lde_twiddles,
            sources,
            slots,
            Some(assembly),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_with_destination(
        arena: &'a DeviceArena,
        config: DecommitWorkspaceConfig,
        raw_queries: ArenaSlice,
        lde_twiddles: Option<ArenaSlice>,
        sources: &[DecommitTreeSources],
        slots: &DecommitWorkspaceSlots,
        assembly: Option<ArenaSlice>,
    ) -> Result<Self, PreparedDecommitError> {
        let requirements = decommit_workspace_requirements(config)?;
        let slot_requirements = requirements.arena_slot_requirements(slots)?;
        if sources.len() != requirements.trees.len() {
            return Err(PreparedDecommitError::SlotShapeMismatch {
                role: "tree sources",
                expected: requirements.trees.len(),
                actual: sources.len(),
            });
        }
        let workspace_ids: BTreeSet<_> = slot_requirements.iter().map(|entry| entry.id).collect();
        let context_token = arena.context().identity_token();
        if raw_queries.context_token() != context_token {
            return Err(PreparedDecommitError::ContextMismatch(raw_queries.id()));
        }
        if raw_queries.len_words() < requirements.config.n_queries as usize {
            return Err(PreparedDecommitError::SourceTooSmall {
                slot: raw_queries.id(),
                required_words: requirements.config.n_queries as usize,
                actual_words: raw_queries.len_words(),
            });
        }
        if workspace_ids.contains(&raw_queries.id()) {
            return Err(PreparedDecommitError::SourceAliasesWorkspace(
                raw_queries.id(),
            ));
        }
        if let Some(twiddles) = lde_twiddles {
            if twiddles.context_token() != context_token {
                return Err(PreparedDecommitError::ContextMismatch(twiddles.id()));
            }
            if workspace_ids.contains(&twiddles.id()) {
                return Err(PreparedDecommitError::SourceAliasesWorkspace(twiddles.id()));
            }
        }

        let bind = |id, words, alignment| bind_slot(arena, id, words, alignment);
        let unique_queries = bind(slots.unique_queries, requirements.unique_query_words, 1)?;
        let mapped_queries = bind(slots.mapped_queries, requirements.mapped_query_words, 1)?;
        let walk_queries = bind(slots.walk_queries, requirements.walk_query_words, 1)?;
        let walk_scratch = bind(slots.walk_scratch, requirements.walk_query_words, 1)?;
        let expanded_positions = bind(
            slots.expanded_positions,
            requirements.expanded_position_words,
            1,
        )?;
        let sparse_indices = bind(slots.sparse_indices, requirements.sparse_index_words, 1)?;
        let sparse_hashes = bind(
            slots.sparse_hashes,
            requirements.sparse_hash_words,
            DECOMMIT_HASH_ALIGNMENT_WORDS,
        )?;
        let counts = bind(slots.counts, requirements.count_words, 1)?;
        let assembly = match assembly {
            Some(destination) => validate_assembly_destination(
                destination,
                slots.assembly,
                context_token,
                requirements.assembly_words,
            )?,
            None => bind(slots.assembly, requirements.assembly_words, 1)?,
        };

        let mut uploads: Vec<(ArenaSlice, Vec<u8>)> = Vec::new();
        let mut trees = Vec::with_capacity(requirements.trees.len());
        let mut requires_twiddles = false;
        for (tree_index, (((geometry, requirement), source), tree_slots)) in requirements
            .config
            .trees
            .iter()
            .zip(&requirements.trees)
            .zip(sources)
            .zip(&slots.trees)
            .enumerate()
        {
            match (geometry, requirement, source, tree_slots) {
                (
                    DecommitTreeGeometry::Trace(geometry),
                    DecommitTreeRequirements::Trace(requirement),
                    DecommitTreeSources::Trace(source),
                    DecommitTreeSlots::Trace(tree_slots),
                ) => {
                    if source.groups.len() != requirement.groups.len() {
                        return Err(PreparedDecommitError::SlotShapeMismatch {
                            role: "trace source groups",
                            expected: requirement.groups.len(),
                            actual: source.groups.len(),
                        });
                    }
                    let first_retained = geometry.leaf_log_size - geometry.unretained_bottom_layers;
                    if source.retained_layers_bottom_up.len() != first_retained as usize + 1 {
                        return Err(PreparedDecommitError::SlotShapeMismatch {
                            role: "trace retained layers",
                            expected: first_retained as usize + 1,
                            actual: source.retained_layers_bottom_up.len(),
                        });
                    }
                    validate_sources(
                        &source.retained_layers_bottom_up,
                        context_token,
                        &workspace_ids,
                    )?;
                    for (index, &layer) in source.retained_layers_bottom_up.iter().enumerate() {
                        ensure_hash_layer(layer, first_retained - index as u32)?;
                    }
                    let retained = bind(
                        tree_slots.retained_layers_by_log,
                        requirement.retained_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    )?;
                    let mut retained_by_log = vec![0usize; geometry.leaf_log_size as usize + 1];
                    for (index, layer) in source.retained_layers_bottom_up.iter().enumerate() {
                        let log = first_retained as usize - index;
                        retained_by_log[log] = layer.as_u32_ptr() as usize;
                    }
                    uploads.push((retained, pointer_bytes(&retained_by_log)));
                    let sparse_offsets = bind(
                        tree_slots.sparse_level_offsets,
                        requirement.sparse_level_offsets.len().max(1),
                        1,
                    )?;
                    let offsets = if requirement.sparse_level_offsets.is_empty() {
                        vec![0u32]
                    } else {
                        requirement.sparse_level_offsets.clone()
                    };
                    uploads.push((sparse_offsets, u32_bytes(&offsets)));

                    let evaluation_ptrs = bind(
                        tree_slots.evaluation_ptrs,
                        requirement.evaluation_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    )?;
                    let evaluation_logs = bind(
                        tree_slots.evaluation_log_sizes,
                        requirement.evaluation_log_words,
                        1,
                    )?;
                    let mut canonical_evaluation_ptrs =
                        Vec::with_capacity(requirement.column_count);
                    let mut canonical_evaluation_logs =
                        Vec::with_capacity(requirement.column_count);

                    let mut groups = Vec::with_capacity(requirement.groups.len());
                    for (
                        group_index,
                        (((group_geometry, group_requirement), group_source), group_slots),
                    ) in geometry
                        .groups
                        .iter()
                        .zip(&requirement.groups)
                        .zip(&source.groups)
                        .zip(&tree_slots.groups)
                        .enumerate()
                    {
                        if group_source.columns.len() != group_requirement.column_count {
                            return Err(PreparedDecommitError::SlotShapeMismatch {
                                role: "trace group columns",
                                expected: group_requirement.column_count,
                                actual: group_source.columns.len(),
                            });
                        }
                        let first_column = canonical_evaluation_ptrs.len();
                        canonical_evaluation_logs.extend(
                            group_geometry
                                .columns
                                .iter()
                                .map(|column| column.evaluation_log_size),
                        );

                        let (coefficient_ptrs, coefficient_sizes, output_ptrs) =
                            match group_geometry.mode {
                                DecommitSourceMode::ResidentEvaluations => {
                                    let mut pointers =
                                        Vec::with_capacity(group_source.columns.len());
                                    for (column_index, (column, column_geometry)) in group_source
                                        .columns
                                        .iter()
                                        .zip(&group_geometry.columns)
                                        .enumerate()
                                    {
                                        let DecommitColumnSource::ResidentEvaluation(source) =
                                            column
                                        else {
                                            return Err(
                                                PreparedDecommitError::SourceModeMismatch {
                                                    tree: tree_index,
                                                    group: group_index,
                                                    column: column_index,
                                                },
                                            );
                                        };
                                        validate_source(*source, context_token, &workspace_ids)?;
                                        ensure_source_size(
                                            *source,
                                            pow2(column_geometry.evaluation_log_size)?,
                                        )?;
                                        pointers.push(source.as_u32_ptr() as usize);
                                    }
                                    canonical_evaluation_ptrs.extend(pointers);
                                    (None, None, None)
                                }
                                DecommitSourceMode::RecomputeQueriedLde => {
                                    requires_twiddles = true;
                                    let cp = bind(
                                        group_slots.coefficient_ptrs.expect("slot shape validated"),
                                        group_requirement.coefficient_pointer_words.unwrap(),
                                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                                    )?;
                                    let cs = bind(
                                        group_slots
                                            .coefficient_sizes
                                            .expect("slot shape validated"),
                                        group_requirement.coefficient_size_words.unwrap(),
                                        1,
                                    )?;
                                    let op = bind(
                                        group_slots.lde_output_ptrs.expect("slot shape validated"),
                                        group_requirement.coefficient_pointer_words.unwrap(),
                                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                                    )?;
                                    let tile = bind(
                                        group_slots.lde_tile.expect("slot shape validated"),
                                        group_requirement.lde_tile_words.unwrap(),
                                        1,
                                    )?;
                                    let mut source_pointers = Vec::new();
                                    let mut source_sizes = Vec::new();
                                    let mut output_pointers = Vec::new();
                                    let mut tile_offset = 0usize;
                                    for (column_index, (column, column_geometry)) in group_source
                                        .columns
                                        .iter()
                                        .zip(&group_geometry.columns)
                                        .enumerate()
                                    {
                                        let DecommitColumnSource::Coefficients(source) = column
                                        else {
                                            return Err(
                                                PreparedDecommitError::SourceModeMismatch {
                                                    tree: tree_index,
                                                    group: group_index,
                                                    column: column_index,
                                                },
                                            );
                                        };
                                        validate_source(*source, context_token, &workspace_ids)?;
                                        let coefficient_words =
                                            pow2(column_geometry.coefficient_log_size)?;
                                        ensure_source_size(*source, coefficient_words)?;
                                        source_pointers.push(source.as_u32_ptr() as usize);
                                        source_sizes
                                            .push(u32::try_from(coefficient_words).map_err(
                                                |_| PreparedDecommitError::SizeOverflow,
                                            )?);
                                        output_pointers.push(unsafe {
                                            tile.as_u32_ptr().add(tile_offset) as usize
                                        });
                                        tile_offset = tile_offset
                                            .checked_add(pow2(column_geometry.evaluation_log_size)?)
                                            .ok_or(PreparedDecommitError::SizeOverflow)?;
                                    }
                                    uploads.push((cp, pointer_bytes(&source_pointers)));
                                    uploads.push((cs, u32_bytes(&source_sizes)));
                                    uploads.push((op, pointer_bytes(&output_pointers)));
                                    canonical_evaluation_ptrs.extend(output_pointers);
                                    (Some(cp), Some(cs), Some(op))
                                }
                            };
                        groups.push(PreparedTraceGroup {
                            coefficient_ptrs,
                            coefficient_sizes,
                            lde_output_ptrs: output_ptrs,
                            batches: group_requirement
                                .lde_batches
                                .iter()
                                .map(|&(start, count, evaluation_log_size)| LdeBatch {
                                    start,
                                    count,
                                    evaluation_log_size,
                                })
                                .collect(),
                            first_column,
                            column_count: group_requirement.column_count,
                        });
                    }
                    if canonical_evaluation_ptrs.len() != requirement.column_count
                        || canonical_evaluation_logs.len() != requirement.column_count
                    {
                        return Err(PreparedDecommitError::SlotShapeMismatch {
                            role: "canonical trace descriptors",
                            expected: requirement.column_count,
                            actual: canonical_evaluation_ptrs
                                .len()
                                .min(canonical_evaluation_logs.len()),
                        });
                    }
                    uploads.push((evaluation_ptrs, pointer_bytes(&canonical_evaluation_ptrs)));
                    uploads.push((evaluation_logs, u32_bytes(&canonical_evaluation_logs)));
                    trees.push(PreparedTree::Trace(PreparedTraceTree {
                        role: geometry.role,
                        tree_query_log_size: geometry.tree_query_log_size,
                        leaf_log_size: geometry.leaf_log_size,
                        unretained_bottom_layers: geometry.unretained_bottom_layers,
                        column_count: requirement.column_count,
                        max_leaf_count: requirement.max_leaf_count,
                        sparse_level_capacities: requirement.sparse_level_capacities.clone(),
                        sparse_level_offsets: requirement.sparse_level_offsets.clone(),
                        sparse_level_offsets_device: sparse_offsets,
                        evaluation_ptrs,
                        evaluation_log_sizes: evaluation_logs,
                        retained_layers_by_log: retained,
                        groups,
                    }));
                }
                (
                    DecommitTreeGeometry::Fri(geometry),
                    DecommitTreeRequirements::Fri(requirement),
                    DecommitTreeSources::Fri(source),
                    DecommitTreeSlots::Fri(tree_slots),
                ) => {
                    validate_source(source.evaluation, context_token, &workspace_ids)?;
                    let evaluation_words = source
                        .coordinate_stride
                        .checked_mul(4)
                        .ok_or(PreparedDecommitError::SizeOverflow)?;
                    ensure_source_size(source.evaluation, evaluation_words)?;
                    if source.coordinate_stride < pow2(geometry.evaluation_log_size)? {
                        return Err(PreparedDecommitError::SourceTooSmall {
                            slot: source.evaluation.id(),
                            required_words: evaluation_words,
                            actual_words: source.evaluation.len_words(),
                        });
                    }
                    validate_sources(
                        &source.retained_layers_bottom_up,
                        context_token,
                        &workspace_ids,
                    )?;
                    let leaf_log = geometry.leaf_log_size();
                    if source.retained_layers_bottom_up.len() != leaf_log as usize + 1 {
                        return Err(PreparedDecommitError::SlotShapeMismatch {
                            role: "FRI retained layers",
                            expected: leaf_log as usize + 1,
                            actual: source.retained_layers_bottom_up.len(),
                        });
                    }
                    for (index, &layer) in source.retained_layers_bottom_up.iter().enumerate() {
                        ensure_hash_layer(layer, leaf_log - index as u32)?;
                    }
                    let coordinate_ptrs = bind(
                        tree_slots.coordinate_ptrs,
                        requirement.coordinate_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    )?;
                    let coordinates: Vec<_> = (0..4)
                        .map(|coordinate| unsafe {
                            source
                                .evaluation
                                .as_u32_ptr()
                                .add(coordinate * source.coordinate_stride)
                                as usize
                        })
                        .collect();
                    uploads.push((coordinate_ptrs, pointer_bytes(&coordinates)));
                    let retained = bind(
                        tree_slots.retained_layers_by_log,
                        requirement.retained_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    )?;
                    let mut retained_by_log = vec![0usize; leaf_log as usize + 1];
                    for (index, layer) in source.retained_layers_bottom_up.iter().enumerate() {
                        retained_by_log[leaf_log as usize - index] = layer.as_u32_ptr() as usize;
                    }
                    uploads.push((retained, pointer_bytes(&retained_by_log)));
                    trees.push(PreparedTree::Fri(PreparedFriTree {
                        cumulative_fold: geometry.cumulative_fold,
                        outgoing_fold_step: geometry.outgoing_fold_step,
                        log_rows_per_leaf: geometry.log_rows_per_leaf,
                        leaf_log_size: leaf_log,
                        coordinate_ptrs,
                        retained_layers_by_log: retained,
                    }));
                }
                _ => return Err(PreparedDecommitError::WrongTreeKind(tree_index)),
            }
        }
        if requires_twiddles && lde_twiddles.is_none() {
            return Err(PreparedDecommitError::MissingTwiddles);
        }
        if let Some(twiddles) = lde_twiddles {
            let required_words = requirements
                .config
                .trees
                .iter()
                .filter_map(|tree| match tree {
                    DecommitTreeGeometry::Trace(trace) => trace
                        .groups
                        .iter()
                        .flat_map(|group| &group.columns)
                        .map(|column| pow2(column.evaluation_log_size.saturating_sub(1)))
                        .collect::<Result<Vec<_>, _>>()
                        .ok()
                        .and_then(|values| values.into_iter().max()),
                    DecommitTreeGeometry::Fri(_) => None,
                })
                .max()
                .unwrap_or(0);
            if twiddles.len_words() < required_words {
                return Err(PreparedDecommitError::TwiddlesTooSmall {
                    required_words,
                    actual_words: twiddles.len_words(),
                });
            }
        }

        let mut upload_result = Ok(());
        for (destination, bytes) in &uploads {
            let result = unsafe {
                arena.context().memcpy_h2d_async(
                    destination.as_void_ptr(),
                    bytes.as_ptr().cast::<c_void>(),
                    bytes.len(),
                )
            };
            if result.is_err() {
                upload_result = result;
                break;
            }
        }
        let sync_result = arena.context().sync();
        upload_result?;
        sync_result?;

        Ok(Self {
            arena,
            requirements,
            raw_queries,
            lde_twiddles,
            unique_queries,
            mapped_queries,
            walk_queries,
            walk_scratch,
            expanded_positions,
            sparse_indices,
            sparse_hashes,
            counts,
            assembly,
            trees,
        })
    }

    pub fn requirements(&self) -> &DecommitWorkspaceRequirements {
        &self.requirements
    }

    /// First replay step, immediately after the device transcript drew raw queries.
    pub fn launch_query_normalization(&self) -> Result<(), PreparedDecommitError> {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_decommit_normalize_queries_on(
                self.raw_queries.as_u32_ptr(),
                self.requirements.config.n_queries,
                self.requirements.config.query_log_size,
                u32::try_from(self.trees.len()).map_err(|_| PreparedDecommitError::SizeOverflow)?,
                self.unique_queries.as_u32_ptr(),
                self.count_ptr(COUNT_UNIQUE),
                self.assembly.as_u32_ptr(),
                u32::try_from(self.requirements.assembly_words)
                    .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                self.stream(),
            )
        };
        check_cuda("decommit_normalize_queries", code)?;
        Ok(())
    }

    pub fn launch_trace_tree(&self, tree_index: usize) -> Result<(), PreparedDecommitError> {
        let Some(PreparedTree::Trace(tree)) = self.trees.get(tree_index) else {
            return Err(if tree_index >= self.trees.len() {
                PreparedDecommitError::InvalidTreeIndex(tree_index)
            } else {
                PreparedDecommitError::WrongTreeKind(tree_index)
            });
        };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_decommit_prepare_trace_queries_on(
                self.unique_queries.as_u32_ptr(),
                self.count_ptr(COUNT_UNIQUE),
                self.requirements.config.n_queries,
                self.requirements.config.query_log_size,
                tree.tree_query_log_size,
                tree.leaf_log_size,
                tree.unretained_bottom_layers,
                self.mapped_queries.as_u32_ptr(),
                self.count_ptr(COUNT_MAPPED),
                self.walk_queries.as_u32_ptr(),
                self.count_ptr(COUNT_WALK),
                self.sparse_indices.as_u32_ptr(),
                self.count_ptr(COUNT_SPARSE_BASE),
                self.stream(),
            )
        };
        check_cuda("decommit_prepare_trace_queries", code)?;

        // Resident groups are already flattened into one canonical pointer/log
        // table at preparation. Their planning boundaries carry no replay
        // dependency, unlike recompute groups whose shared LDE tile must be
        // consumed before the next group overwrites it.
        let aggregate_resident_pack = tree
            .groups
            .iter()
            .all(|group| group.coefficient_ptrs.is_none());
        let twiddles = self.lde_twiddles;
        for (group_index, group) in tree.groups.iter().enumerate() {
            if let (Some(coefficient_ptrs), Some(coefficient_sizes), Some(outputs)) = (
                group.coefficient_ptrs,
                group.coefficient_sizes,
                group.lde_output_ptrs,
            ) {
                let twiddles = twiddles.expect("prepare rejected missing twiddles");
                for batch in &group.batches {
                    let eval_domain_size = 1u32 << (batch.evaluation_log_size - 1);
                    let code = unsafe {
                        stwo_backend_cuda_kernels::raw::stwo_lde_n2b_columns_on(
                            coefficient_ptrs
                                .as_u32_ptr()
                                .cast::<*const u32>()
                                .add(batch.start),
                            coefficient_sizes.as_u32_ptr().add(batch.start),
                            outputs.as_u32_ptr().cast::<*mut u32>().add(batch.start),
                            batch.evaluation_log_size,
                            u32::try_from(batch.count)
                                .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                            twiddles.as_u32_ptr(),
                            u32::try_from(twiddles.len_words())
                                .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                            eval_domain_size,
                            self.stream(),
                        )
                    };
                    check_cuda("decommit_recompute_lde", code)?;
                }
            }

            // Consume this group before a later recompute group reuses the same LDE
            // tile. Each launch writes directly into its disjoint final bundle range.
            if !aggregate_resident_pack || group_index == 0 {
                let (first_column, column_count) = if aggregate_resident_pack {
                    (0, tree.column_count)
                } else {
                    (group.first_column, group.column_count)
                };
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_decommit_pack_trace_group_on(
                        u32::try_from(tree_index)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        u32::try_from(tree.column_count)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        u32::try_from(first_column)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        u32::try_from(column_count)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        tree.evaluation_ptrs
                            .as_u32_ptr()
                            .cast::<*const u32>()
                            .add(first_column),
                        tree.evaluation_log_sizes.as_u32_ptr().add(first_column),
                        tree.leaf_log_size,
                        self.mapped_queries.as_u32_ptr(),
                        self.count_ptr(COUNT_MAPPED),
                        self.requirements.config.n_queries,
                        self.assembly.as_u32_ptr(),
                        u32::try_from(self.requirements.assembly_words)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        self.stream(),
                    )
                };
                check_cuda("decommit_pack_trace_group", code)?;
            }

            if tree.unretained_bottom_layers != 0 {
                let final_group = group_index + 1 == tree.groups.len();
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_blake2s_sparse_leaf_group_on(
                        self.sparse_indices.as_u32_ptr(),
                        self.count_ptr(COUNT_SPARSE_BASE),
                        u32::try_from(tree.max_leaf_count)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        u32::try_from(group.column_count)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        tree.evaluation_ptrs
                            .as_u32_ptr()
                            .cast::<*mut u32>()
                            .add(group.first_column),
                        tree.evaluation_log_sizes
                            .as_u32_ptr()
                            .add(group.first_column),
                        tree.leaf_log_size,
                        u32::try_from(group.first_column)
                            .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                        u32::from(final_group),
                        self.sparse_hashes.as_u32_ptr().cast(),
                        self.stream(),
                    )
                };
                check_cuda("decommit_sparse_leaf_group", code)?;
            }
        }

        for distance in 1..tree.unretained_bottom_layers as usize {
            let child_offset = tree.sparse_level_offsets[distance - 1] as usize;
            let parent_offset = tree.sparse_level_offsets[distance] as usize;
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::stwo_decommit_sparse_parent_on(
                    self.sparse_indices.as_u32_ptr().add(child_offset),
                    self.sparse_hashes
                        .as_u32_ptr()
                        .cast::<stwo_backend_cuda_kernels::raw::Blake2sHash>()
                        .add(child_offset),
                    self.count_ptr(COUNT_SPARSE_BASE + distance - 1),
                    u32::try_from(tree.sparse_level_capacities[distance - 1])
                        .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                    self.sparse_indices.as_u32_ptr().add(parent_offset),
                    self.sparse_hashes
                        .as_u32_ptr()
                        .cast::<stwo_backend_cuda_kernels::raw::Blake2sHash>()
                        .add(parent_offset),
                    self.count_ptr(COUNT_SPARSE_BASE + distance),
                    self.stream(),
                )
            };
            check_cuda("decommit_sparse_parent", code)?;
        }

        let first_retained = tree.leaf_log_size - tree.unretained_bottom_layers;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_decommit_assemble_trace_on(
                u32::try_from(tree_index).map_err(|_| PreparedDecommitError::SizeOverflow)?,
                tree.role as u32,
                tree.leaf_log_size,
                first_retained,
                u32::try_from(tree.column_count)
                    .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                self.count_ptr(COUNT_MAPPED),
                self.requirements.config.n_queries,
                self.walk_queries.as_u32_ptr(),
                self.walk_scratch.as_u32_ptr(),
                self.count_ptr(COUNT_WALK),
                tree.retained_layers_by_log
                    .as_u32_ptr()
                    .cast::<*const stwo_backend_cuda_kernels::raw::Blake2sHash>(),
                self.sparse_indices.as_u32_ptr(),
                self.sparse_hashes.as_u32_ptr().cast(),
                tree.sparse_level_offsets_device.as_u32_ptr(),
                self.count_ptr(COUNT_SPARSE_BASE),
                tree.unretained_bottom_layers,
                self.assembly.as_u32_ptr(),
                u32::try_from(self.requirements.assembly_words)
                    .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                self.stream(),
            )
        };
        check_cuda("decommit_assemble_trace", code)?;
        Ok(())
    }

    /// Open one committed FRI tree from the stable evaluation snapshot retained
    /// by the prepared FRI graph until query positions are known.
    pub fn launch_fri_tree(&self, tree_index: usize) -> Result<(), PreparedDecommitError> {
        let Some(PreparedTree::Fri(tree)) = self.trees.get(tree_index) else {
            return Err(if tree_index >= self.trees.len() {
                PreparedDecommitError::InvalidTreeIndex(tree_index)
            } else {
                PreparedDecommitError::WrongTreeKind(tree_index)
            });
        };
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_decommit_prepare_fri_queries_on(
                self.unique_queries.as_u32_ptr(),
                self.count_ptr(COUNT_UNIQUE),
                self.requirements.config.n_queries,
                tree.cumulative_fold,
                tree.outgoing_fold_step,
                tree.log_rows_per_leaf,
                self.mapped_queries.as_u32_ptr(),
                self.count_ptr(COUNT_MAPPED),
                self.expanded_positions.as_u32_ptr(),
                self.count_ptr(COUNT_EXPANDED),
                self.walk_queries.as_u32_ptr(),
                self.count_ptr(COUNT_WALK),
                self.stream(),
            )
        };
        check_cuda("decommit_prepare_fri_queries", code)?;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_decommit_assemble_fri_on(
                u32::try_from(tree_index).map_err(|_| PreparedDecommitError::SizeOverflow)?,
                tree.leaf_log_size,
                self.mapped_queries.as_u32_ptr(),
                self.count_ptr(COUNT_MAPPED),
                self.expanded_positions.as_u32_ptr(),
                self.count_ptr(COUNT_EXPANDED),
                tree.coordinate_ptrs.as_u32_ptr().cast::<*const u32>(),
                self.walk_queries.as_u32_ptr(),
                self.walk_scratch.as_u32_ptr(),
                self.count_ptr(COUNT_WALK),
                tree.retained_layers_by_log
                    .as_u32_ptr()
                    .cast::<*const stwo_backend_cuda_kernels::raw::Blake2sHash>(),
                self.assembly.as_u32_ptr(),
                u32::try_from(self.requirements.assembly_words)
                    .map_err(|_| PreparedDecommitError::SizeOverflow)?,
                self.stream(),
            )
        };
        check_cuda("decommit_assemble_fri", code)?;
        Ok(())
    }

    pub fn assembly_slice(&self) -> ArenaSlice {
        self.assembly
    }

    /// Standalone diagnostic D2H boundary. Production callers may instead bind
    /// this view into a larger proof bundle and copy that bundle once. The
    /// allocation is capacity-sized; the decoded `used_words` prefix is compact.
    pub fn read_assembly_once(&self) -> Result<DecommitAssembly, PreparedDecommitError> {
        let mut words = vec![0u32; self.requirements.assembly_words];
        unsafe {
            self.arena.context().memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                self.assembly.as_void_ptr().cast_const(),
                words.len() * WORD_BYTES,
            )?;
        }
        self.arena.context().sync()?;
        DecommitAssembly::decode(words)
    }

    fn count_ptr(&self, index: usize) -> *mut u32 {
        debug_assert!(index < self.counts.len_words());
        unsafe { self.counts.as_u32_ptr().add(index) }
    }

    fn stream(&self) -> *mut c_void {
        self.arena.context().stream_raw().as_ptr()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecommitTreeMeta {
    pub kind: u32,
    pub role: u32,
    pub query_offset: usize,
    pub query_count: usize,
    pub values_offset: usize,
    pub values_count: usize,
    pub fri_witness_offset: usize,
    pub fri_witness_count: usize,
    pub hash_witness_offset: usize,
    pub hash_witness_count: usize,
    pub aux_offset: usize,
    pub aux_count: usize,
    pub all_values_offset: usize,
    pub all_values_count: usize,
    pub leaf_log_size: u32,
    pub used_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecommitAssembly {
    words: Vec<u32>,
    pub raw_query_offset: usize,
    pub raw_query_count: usize,
    pub unique_query_offset: usize,
    pub unique_query_count: usize,
    pub trees: Vec<DecommitTreeMeta>,
}

impl DecommitAssembly {
    pub fn decode(mut words: Vec<u32>) -> Result<Self, PreparedDecommitError> {
        if words.len() < HEADER_WORDS || words[0] != MAGIC || words[1] != VERSION {
            return Err(PreparedDecommitError::AssemblyCorrupt("header"));
        }
        let tree_count = words[2] as usize;
        let raw_query_count = words[3] as usize;
        let unique_query_count = words[4] as usize;
        let raw_query_offset = words[5] as usize;
        let unique_query_offset = words[6] as usize;
        let used = words[7] as usize;
        if used < HEADER_WORDS || used > words.len() {
            return Err(PreparedDecommitError::AssemblyCorrupt("used words"));
        }
        words.truncate(used);
        check_range(&words, raw_query_offset, raw_query_count)?;
        check_range(&words, unique_query_offset, unique_query_count)?;
        let metadata_end = HEADER_WORDS
            .checked_add(
                tree_count
                    .checked_mul(TREE_META_WORDS)
                    .ok_or(PreparedDecommitError::AssemblyCorrupt("tree count"))?,
            )
            .ok_or(PreparedDecommitError::AssemblyCorrupt("tree count"))?;
        if metadata_end > words.len() {
            return Err(PreparedDecommitError::AssemblyCorrupt("tree metadata"));
        }
        let mut trees = Vec::with_capacity(tree_count);
        for index in 0..tree_count {
            let meta = &words[HEADER_WORDS + index * TREE_META_WORDS..][..TREE_META_WORDS];
            let tree = DecommitTreeMeta {
                kind: meta[0],
                role: meta[1],
                query_offset: meta[2] as usize,
                query_count: meta[3] as usize,
                values_offset: meta[4] as usize,
                values_count: meta[5] as usize,
                fri_witness_offset: meta[6] as usize,
                fri_witness_count: meta[7] as usize,
                hash_witness_offset: meta[8] as usize,
                hash_witness_count: meta[9] as usize,
                aux_offset: meta[10] as usize,
                aux_count: meta[11] as usize,
                all_values_offset: meta[12] as usize,
                all_values_count: meta[13] as usize,
                leaf_log_size: meta[14],
                used_words: meta[15] as usize,
            };
            if tree.kind > 1 || tree.used_words == 0 {
                return Err(PreparedDecommitError::AssemblyCorrupt("tree not assembled"));
            }
            check_range(&words, tree.query_offset, tree.query_count)?;
            check_range(&words, tree.values_offset, tree.values_count)?;
            check_range(
                &words,
                tree.fri_witness_offset,
                tree.fri_witness_count
                    .checked_mul(4)
                    .ok_or(PreparedDecommitError::AssemblyCorrupt("FRI witness"))?,
            )?;
            check_range(
                &words,
                tree.hash_witness_offset,
                tree.hash_witness_count
                    .checked_mul(HASH_WORDS)
                    .ok_or(PreparedDecommitError::AssemblyCorrupt("hash witness"))?,
            )?;
            check_range(
                &words,
                tree.aux_offset,
                tree.aux_count
                    .checked_mul(AUX_NODE_WORDS)
                    .ok_or(PreparedDecommitError::AssemblyCorrupt("aux nodes"))?,
            )?;
            check_range(
                &words,
                tree.all_values_offset,
                tree.all_values_count
                    .checked_mul(5)
                    .ok_or(PreparedDecommitError::AssemblyCorrupt("all values"))?,
            )?;
            trees.push(tree);
        }
        Ok(Self {
            words,
            raw_query_offset,
            raw_query_count,
            unique_query_offset,
            unique_query_count,
            trees,
        })
    }

    pub fn words(&self) -> &[u32] {
        &self.words
    }

    pub fn raw_queries(&self) -> &[u32] {
        &self.words[self.raw_query_offset..self.raw_query_offset + self.raw_query_count]
    }

    pub fn unique_queries(&self) -> &[u32] {
        &self.words[self.unique_query_offset..self.unique_query_offset + self.unique_query_count]
    }
}

fn check_range(words: &[u32], offset: usize, count: usize) -> Result<(), PreparedDecommitError> {
    if count == 0 && offset == 0 {
        return Ok(());
    }
    if offset
        .checked_add(count)
        .is_some_and(|end| end <= words.len())
    {
        Ok(())
    } else {
        Err(PreparedDecommitError::AssemblyCorrupt("section range"))
    }
}

fn validate_sources(
    sources: &[ArenaSlice],
    context_token: core::ptr::NonNull<c_void>,
    workspace_ids: &BTreeSet<ArenaSlotId>,
) -> Result<(), PreparedDecommitError> {
    for &source in sources {
        validate_source(source, context_token, workspace_ids)?;
    }
    Ok(())
}

fn validate_source(
    source: ArenaSlice,
    context_token: core::ptr::NonNull<c_void>,
    workspace_ids: &BTreeSet<ArenaSlotId>,
) -> Result<(), PreparedDecommitError> {
    if source.context_token() != context_token {
        return Err(PreparedDecommitError::ContextMismatch(source.id()));
    }
    if workspace_ids.contains(&source.id()) {
        return Err(PreparedDecommitError::SourceAliasesWorkspace(source.id()));
    }
    Ok(())
}

fn ensure_source_size(
    source: ArenaSlice,
    required_words: usize,
) -> Result<(), PreparedDecommitError> {
    if source.len_words() < required_words {
        Err(PreparedDecommitError::SourceTooSmall {
            slot: source.id(),
            required_words,
            actual_words: source.len_words(),
        })
    } else {
        Ok(())
    }
}

fn ensure_hash_layer(source: ArenaSlice, log_size: u32) -> Result<(), PreparedDecommitError> {
    let required_words = pow2(log_size)?
        .checked_mul(HASH_WORDS)
        .ok_or(PreparedDecommitError::SizeOverflow)?;
    ensure_source_size(source, required_words)?;
    if source.as_u32_ptr() as usize % (DECOMMIT_HASH_ALIGNMENT_WORDS * WORD_BYTES) != 0 {
        return Err(PreparedDecommitError::MisalignedSlot {
            slot: source.id(),
            alignment_words: DECOMMIT_HASH_ALIGNMENT_WORDS,
        });
    }
    Ok(())
}

fn validate_assembly_destination(
    destination: ArenaSlice,
    expected_id: ArenaSlotId,
    context_token: core::ptr::NonNull<c_void>,
    required_words: usize,
) -> Result<ArenaSlice, PreparedDecommitError> {
    if destination.id() != expected_id {
        return Err(PreparedDecommitError::AssemblySlotMismatch {
            expected: expected_id,
            actual: destination.id(),
        });
    }
    if destination.context_token() != context_token {
        return Err(PreparedDecommitError::ContextMismatch(destination.id()));
    }
    if destination.len_words() < required_words {
        return Err(PreparedDecommitError::SlotTooSmall {
            slot: destination.id(),
            required_words,
            actual_words: destination.len_words(),
        });
    }
    Ok(destination.truncated(required_words))
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedDecommitError> {
    let slice = arena.bind(id)?;
    if slice.len_words() < required_words.max(1) {
        return Err(PreparedDecommitError::SlotTooSmall {
            slot: id,
            required_words: required_words.max(1),
            actual_words: slice.len_words(),
        });
    }
    if slice.as_u32_ptr() as usize % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedDecommitError::MisalignedSlot {
            slot: id,
            alignment_words,
        });
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(required_words.max(1)))
}

fn pointer_bytes(pointers: &[usize]) -> Vec<u8> {
    pointers
        .iter()
        .flat_map(|pointer| pointer.to_ne_bytes())
        .collect()
}

fn u32_bytes(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_ne_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct WalkLayout {
        hash_witness: Vec<(u32, u32)>,
        aux_nodes: Vec<(u32, u32)>,
        root: u32,
    }

    fn serial_walk_layout(mut current: Vec<u32>, leaf_log: u32) -> WalkLayout {
        let mut hash_witness = Vec::new();
        let mut aux_nodes = Vec::new();
        let mut next = Vec::with_capacity(current.len());
        for layer in (0..leaf_log).rev() {
            let previous_level = layer + 1;
            next.clear();
            let mut i = 0;
            while i < current.len() {
                let first = current[i];
                let pair = i + 1 < current.len() && current[i + 1] == (first ^ 1);
                if !pair {
                    hash_witness.push((previous_level, first ^ 1));
                }
                let parent = first >> 1;
                next.push(parent);
                aux_nodes.extend([
                    (previous_level, 2 * parent),
                    (previous_level, 2 * parent + 1),
                ]);
                i += if pair { 2 } else { 1 };
            }
            core::mem::swap(&mut current, &mut next);
        }
        assert_eq!(current.len(), 1);
        WalkLayout {
            hash_witness,
            aux_nodes,
            root: current[0],
        }
    }

    fn prefix_scatter_walk_layout(mut current: Vec<u32>, leaf_log: u32) -> WalkLayout {
        const CUDA_BLOCK: usize = 256;
        let mut hash_witness = Vec::new();
        let mut aux_nodes = Vec::new();
        let mut next = vec![0; current.len()];
        for layer in (0..leaf_log).rev() {
            let previous_level = layer + 1;
            let mut group_base = 0;
            for base in (0..current.len()).step_by(CUDA_BLOCK) {
                let end = (base + CUDA_BLOCK).min(current.len());
                let starts: Vec<_> = (base..end)
                    .filter(|&i| i == 0 || current[i - 1] != (current[i] ^ 1))
                    .collect();
                for (chunk_group, &i) in starts.iter().enumerate() {
                    let first = current[i];
                    let pair = i + 1 < current.len() && current[i + 1] == (first ^ 1);
                    if !pair {
                        hash_witness.push((previous_level, first ^ 1));
                    }
                    let parent = first >> 1;
                    next[group_base + chunk_group] = parent;
                    aux_nodes.extend([
                        (previous_level, 2 * parent),
                        (previous_level, 2 * parent + 1),
                    ]);
                }
                group_base += starts.len();
            }
            current.clear();
            current.extend_from_slice(&next[..group_base]);
        }
        assert_eq!(current.len(), 1);
        WalkLayout {
            hash_witness,
            aux_nodes,
            root: current[0],
        }
    }

    fn encoded_walk_layout(layout: &WalkLayout) -> Vec<u32> {
        let mut words = Vec::new();
        for &(level, index) in &layout.hash_witness {
            words.extend(
                (0..HASH_WORDS as u32)
                    .map(|word| level.rotate_left(word) ^ index.wrapping_mul(0x9e37_79b9) ^ word),
            );
        }
        for &(level, index) in &layout.aux_nodes {
            words.extend([level, index]);
            words.extend(
                (0..HASH_WORDS as u32)
                    .map(|word| level.rotate_left(word) ^ index.wrapping_mul(0x9e37_79b9) ^ word),
            );
        }
        words
    }

    fn trace(role: TraceTreeRole, tree_log: u32, columns: usize) -> DecommitTreeGeometry {
        DecommitTreeGeometry::Trace(TraceDecommitGeometry {
            role,
            tree_query_log_size: tree_log,
            leaf_log_size: tree_log,
            unretained_bottom_layers: 4,
            groups: vec![TraceSourceGroupGeometry {
                mode: DecommitSourceMode::RecomputeQueriedLde,
                columns: (0..columns)
                    .map(|_| DecommitColumnGeometry {
                        coefficient_log_size: tree_log - 2,
                        evaluation_log_size: tree_log,
                    })
                    .collect(),
            }],
        })
    }

    fn compositions(total: usize) -> Vec<Vec<usize>> {
        if total == 0 {
            return vec![Vec::new()];
        }
        let mut result = Vec::new();
        for first in 1..=total {
            for mut tail in compositions(total - first) {
                let mut parts = vec![first];
                parts.append(&mut tail);
                result.push(parts);
            }
        }
        result
    }

    #[test]
    fn canonical_tree_descriptors_cover_every_valid_group_topology() {
        for column_count in 1..=64usize {
            let final_width = (column_count - 1) % 16 + 1;
            let prefix_blocks = (column_count - final_width) / 16;
            for prefix in compositions(prefix_blocks) {
                let mut widths = prefix
                    .into_iter()
                    .map(|blocks| blocks * 16)
                    .collect::<Vec<_>>();
                widths.push(final_width);
                let groups = widths
                    .iter()
                    .map(|&width| TraceSourceGroupGeometry {
                        mode: DecommitSourceMode::ResidentEvaluations,
                        columns: vec![
                            DecommitColumnGeometry {
                                coefficient_log_size: 4,
                                evaluation_log_size: 6,
                            };
                            width
                        ],
                    })
                    .collect::<Vec<_>>();
                let requirements = decommit_workspace_requirements(DecommitWorkspaceConfig {
                    query_log_size: 6,
                    n_queries: 3,
                    trees: vec![DecommitTreeGeometry::Trace(TraceDecommitGeometry {
                        role: TraceTreeRole::Base,
                        tree_query_log_size: 6,
                        leaf_log_size: 6,
                        unretained_bottom_layers: 0,
                        groups,
                    })],
                })
                .unwrap();
                let DecommitTreeRequirements::Trace(tree) = &requirements.trees[0] else {
                    panic!("trace")
                };
                assert_eq!(tree.column_count, column_count);
                assert_eq!(tree.evaluation_pointer_words, column_count * POINTER_WORDS);
                assert_eq!(tree.evaluation_log_words, column_count);
                assert_eq!(tree.groups.len(), widths.len());
                assert_eq!(
                    requirements
                        .direct_pack_capacity_model()
                        .unwrap()
                        .direct_trace_pack_launches,
                    1
                );
            }
        }
    }

    #[test]
    fn direct_trace_pack_matches_independent_merkle_decommit_oracle() {
        use stwo::core::fields::m31::{BaseField, P};
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
        use stwo::prover::backend::CpuBackend;
        use stwo::prover::vcs_lifted::prover::MerkleProverLifted;

        for lifting_log in 2..=5u32 {
            let logs = (1..=lifting_log)
                .flat_map(|log| [log, log])
                .collect::<Vec<_>>();
            let columns = logs
                .iter()
                .enumerate()
                .map(|(column, &log)| {
                    (0..1usize << log)
                        .map(|row| {
                            let raw = if (column + row) % 7 == 0 {
                                P
                            } else {
                                (column * 257 + row * 17 + 1) as u32 % P
                            };
                            BaseField::from_u32_unchecked(raw)
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let tree = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
                columns.iter().collect(),
                lifting_log,
                0,
            );
            let domain = 1usize << lifting_log;
            let mut query_sets = Vec::new();
            if lifting_log <= 3 {
                query_sets.extend((1usize..1usize << domain).map(|mask| {
                    (0..domain)
                        .filter(|position| mask & (1usize << position) != 0)
                        .collect::<Vec<_>>()
                }));
            } else {
                query_sets.extend((0..domain).map(|position| vec![position]));
                query_sets.extend((0..domain - 1).map(|position| vec![position, position + 1]));
                query_sets.push((0..domain).collect());
            }

            for queries in query_sets {
                let (oracle, _) = tree.decommit(&queries, columns.iter().collect());
                let oracle = oracle.into_iter().flatten().collect::<Vec<_>>();
                let direct = columns
                    .iter()
                    .zip(&logs)
                    .flat_map(|(column, &column_log)| {
                        let shift = lifting_log - column_log;
                        queries.iter().map(move |&position| {
                            let row = ((position >> (shift + 1)) << 1) + (position & 1);
                            BaseField::reduce(column[row].0 as u64)
                        })
                    })
                    .collect::<Vec<_>>();
                assert_eq!(direct, oracle, "lifting={lifting_log} queries={queries:?}");
            }
        }
    }

    #[test]
    fn direct_trace_pack_consumes_each_reused_tile_before_overwrite() {
        use stwo::core::fields::m31::{BaseField, P};
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
        use stwo::prover::backend::CpuBackend;
        use stwo::prover::vcs_lifted::prover::MerkleProverLifted;

        const LIFTING_LOG: u32 = 5;
        let logs = (0..34)
            .map(|column| 2 + (column as u32 * 3 / 34))
            .collect::<Vec<_>>();
        let columns = logs
            .iter()
            .enumerate()
            .map(|(column, &log)| {
                (0..1usize << log)
                    .map(|row| {
                        let raw = if (column + row) % 11 == 0 {
                            P
                        } else {
                            (column * 1_009 + row * 37 + 1) as u32 % P
                        };
                        BaseField::from_u32_unchecked(raw)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let tree = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
            columns.iter().collect(),
            LIFTING_LOG,
            0,
        );
        let queries = [0usize, 1, 7, 16, 31];
        let (oracle, _) = tree.decommit(&queries, columns.iter().collect());
        let oracle = oracle.into_iter().flatten().collect::<Vec<_>>();

        let mut packed = vec![BaseField::from_u32_unchecked(0); oracle.len()];
        let mut first_column = 0;
        for width in [16usize, 16, 2] {
            // This clone models the one physical LDE tile being overwritten by
            // the next group. Only values copied into `packed` survive.
            let tile = columns[first_column..first_column + width].to_vec();
            for (local_column, (column, &log)) in tile.iter().zip(&logs[first_column..]).enumerate()
            {
                for (query_index, &position) in queries.iter().enumerate() {
                    let shift = LIFTING_LOG - log;
                    let row = ((position >> (shift + 1)) << 1) + (position & 1);
                    packed[(first_column + local_column) * queries.len() + query_index] =
                        BaseField::reduce(column[row].0 as u64);
                }
            }
            first_column += width;
        }
        assert_eq!(first_column, columns.len());
        assert_eq!(packed, oracle);
    }

    #[test]
    fn requirements_cover_trace_pruning_and_all_fri_sections() {
        let config = DecommitWorkspaceConfig {
            query_log_size: 12,
            n_queries: 16,
            trees: vec![
                trace(TraceTreeRole::Composition, 12, 8),
                DecommitTreeGeometry::Fri(FriDecommitGeometry {
                    fri_tree_index: 0,
                    evaluation_log_size: 12,
                    cumulative_fold: 0,
                    outgoing_fold_step: 3,
                    log_rows_per_leaf: 2,
                }),
                DecommitTreeGeometry::Fri(FriDecommitGeometry {
                    fri_tree_index: 1,
                    evaluation_log_size: 9,
                    cumulative_fold: 3,
                    outgoing_fold_step: 2,
                    log_rows_per_leaf: 2,
                }),
            ],
        };
        let requirements = decommit_workspace_requirements(config).unwrap();
        let DecommitTreeRequirements::Trace(trace) = &requirements.trees[0] else {
            panic!("trace")
        };
        assert_eq!(trace.max_leaf_count, 16 * 16);
        assert_eq!(trace.sparse_level_capacities, vec![256, 128, 64, 32]);
        assert_eq!(trace.sparse_level_offsets, vec![0, 256, 384, 448]);
        assert_eq!(trace.evaluation_pointer_words, 8 * POINTER_WORDS);
        assert_eq!(trace.evaluation_log_words, 8);
        let DecommitTreeRequirements::Fri(first) = &requirements.trees[1] else {
            panic!("fri")
        };
        assert_eq!(first.max_expanded_positions, 16 * 8);
        assert!(requirements.walk_query_words >= first.max_expanded_positions);
        assert!(requirements.assembly_words > HEADER_WORDS + 3 * TREE_META_WORDS);
        assert_eq!(
            requirements.direct_pack_capacity_model().unwrap(),
            DecommitDirectPackModel {
                eliminated_arena_words: 16 * 8 * 4,
                direct_trace_pack_launches: 1,
                eliminated_gather_launches: 2,
                eliminated_staging_traffic_bytes: (16 * 8 + 16 * 8 * 4 + 16 * 4 * 4) * 8,
            }
        );
    }

    #[test]
    fn recompute_topology_preserves_mixed_coefficient_and_evaluation_logs() {
        let requirements = decommit_workspace_requirements(DecommitWorkspaceConfig {
            query_log_size: 5,
            n_queries: 4,
            trees: vec![DecommitTreeGeometry::Trace(TraceDecommitGeometry {
                role: TraceTreeRole::Composition,
                tree_query_log_size: 5,
                leaf_log_size: 5,
                unretained_bottom_layers: 2,
                groups: vec![TraceSourceGroupGeometry {
                    mode: DecommitSourceMode::RecomputeQueriedLde,
                    columns: vec![
                        DecommitColumnGeometry {
                            coefficient_log_size: 2,
                            evaluation_log_size: 4,
                        },
                        DecommitColumnGeometry {
                            coefficient_log_size: 3,
                            evaluation_log_size: 4,
                        },
                        DecommitColumnGeometry {
                            coefficient_log_size: 4,
                            evaluation_log_size: 5,
                        },
                    ],
                }],
            })],
        })
        .unwrap();
        let DecommitTreeRequirements::Trace(tree) = &requirements.trees[0] else {
            panic!("trace")
        };
        let group = &tree.groups[0];
        let DecommitTreeGeometry::Trace(geometry) = &requirements.config.trees[0] else {
            panic!("trace geometry")
        };
        assert_eq!(
            geometry.groups[0]
                .columns
                .iter()
                .map(|column| (column.coefficient_log_size, column.evaluation_log_size))
                .collect::<Vec<_>>(),
            [(2, 4), (3, 4), (4, 5)]
        );
        assert_eq!(group.lde_batches, [(0, 2, 4), (2, 1, 5)]);
        assert_eq!(group.coefficient_size_words, Some(3));
        assert_eq!(group.lde_tile_words, Some(64));
    }

    #[test]
    fn canonical_order_and_hash_group_boundaries_fail_closed() {
        let mut bad_order = DecommitWorkspaceConfig {
            query_log_size: 10,
            n_queries: 8,
            trees: vec![
                trace(TraceTreeRole::Interaction, 10, 8),
                trace(TraceTreeRole::Base, 10, 8),
            ],
        };
        assert!(matches!(
            decommit_workspace_requirements(bad_order.clone()),
            Err(PreparedDecommitError::NonCanonicalTreeOrder(1))
        ));
        bad_order.trees = vec![trace(TraceTreeRole::Base, 10, 17)];
        assert!(matches!(
            decommit_workspace_requirements(bad_order),
            Err(PreparedDecommitError::InvalidGroupWidth { width: 17, .. })
        ));
    }

    #[test]
    fn trace_query_mapping_matches_stwo_preprocessed_rule() {
        let source_log = 12;
        let target_log = 9;
        let queries = vec![1usize, 2, 17, 511, 1023, 4095];
        let expected = stwo::core::pcs::utils::prepare_preprocessed_query_positions(
            &queries, source_log, target_log,
        );
        let mapped: Vec<_> = queries
            .iter()
            .map(|&position| {
                if source_log < target_log {
                    ((position >> 1) << (target_log - source_log + 1)) | (position & 1)
                } else {
                    ((position >> (source_log - target_log + 1)) << 1) | (position & 1)
                }
            })
            .collect();
        assert_eq!(mapped, expected);
    }

    #[test]
    fn fri_coset_layout_matches_reference_chunk_order() {
        let queries = [1u32, 2, 3, 9, 10, 15];
        let fold_step = 2;
        let mut expected = Vec::new();
        let mut previous = None;
        for query in queries {
            let coset = query >> fold_step;
            if previous == Some(coset) {
                continue;
            }
            previous = Some(coset);
            expected.extend((coset << fold_step)..((coset + 1) << fold_step));
        }
        assert_eq!(expected, vec![0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15]);
        let packed: Vec<_> = expected.iter().map(|position| position >> 2).collect();
        let packed: Vec<_> = BTreeSet::from_iter(packed).into_iter().collect();
        assert_eq!(packed, vec![0, 2, 3]);
    }

    #[test]
    fn packed_fri_fold_three_geometry_covers_duplicate_coset_boundaries() {
        let requirements = decommit_workspace_requirements(DecommitWorkspaceConfig {
            query_log_size: 12,
            n_queries: 5,
            trees: vec![DecommitTreeGeometry::Fri(FriDecommitGeometry {
                fri_tree_index: 0,
                evaluation_log_size: 12,
                cumulative_fold: 0,
                outgoing_fold_step: 3,
                log_rows_per_leaf: 2,
            })],
        })
        .unwrap();
        let DecommitTreeRequirements::Fri(tree) = &requirements.trees[0] else {
            panic!("fri")
        };
        assert_eq!(tree.max_expanded_positions, 5 * 8);
        assert_eq!(tree.coordinate_pointer_words, 8);

        let queries = [0u32, 7, 8, 8, 15];
        let cosets = queries
            .iter()
            .map(|query| query >> 3)
            .collect::<BTreeSet<_>>();
        assert_eq!(cosets, [0, 1].into_iter().collect());
        let packed_leaves = cosets
            .into_iter()
            .flat_map(|coset| (coset << 3)..((coset + 1) << 3))
            .map(|position| position >> 2)
            .collect::<BTreeSet<_>>();
        assert_eq!(packed_leaves, [0, 1, 2, 3].into_iter().collect());
    }

    #[test]
    fn sparse_leaf_blocks_match_canonical_pruned_merkle_walk() {
        use stwo::core::fields::m31::BaseField;
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
        use stwo::prover::backend::CpuBackend;
        use stwo::prover::vcs_lifted::prover::MerkleProverLifted;

        const LEAF_LOG: u32 = 8;
        const UNRETAINED: u32 = 4;
        let column: Vec<_> = (0..1 << LEAF_LOG)
            .map(|value| BaseField::from_u32_unchecked(value as u32))
            .collect();
        let tree = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit_pruned(
            vec![&column],
            LEAF_LOG,
        );
        let queries = [1usize, 2, 31, 32, 33, 201, 255];
        let canonical = tree.unretained_leaf_indices(&queries);
        let mut block_union = BTreeSet::new();
        for query in queries {
            let base = (query >> UNRETAINED) << UNRETAINED;
            block_union.extend(base..base + (1 << UNRETAINED));
        }
        assert_eq!(canonical, block_union.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn compact_assembly_decoder_rejects_ranges_and_preserves_query_order() {
        let tree_count = 1usize;
        let raw = [7, 3, 7, 1];
        let unique = [1, 3, 7];
        let raw_offset = HEADER_WORDS + tree_count * TREE_META_WORDS;
        let unique_offset = raw_offset + raw.len();
        let used = unique_offset + unique.len();
        let mut words = vec![0u32; used];
        words[..HEADER_WORDS].copy_from_slice(&[
            MAGIC,
            VERSION,
            tree_count as u32,
            raw.len() as u32,
            unique.len() as u32,
            raw_offset as u32,
            unique_offset as u32,
            used as u32,
        ]);
        words[HEADER_WORDS + 15] = 1;
        words[raw_offset..unique_offset].copy_from_slice(&raw);
        words[unique_offset..used].copy_from_slice(&unique);
        let decoded = DecommitAssembly::decode(words.clone()).unwrap();
        assert_eq!(decoded.raw_queries(), raw);
        assert_eq!(decoded.unique_queries(), unique);
        words[7] = (used + 1) as u32;
        assert!(matches!(
            DecommitAssembly::decode(words),
            Err(PreparedDecommitError::AssemblyCorrupt("used words"))
        ));
    }

    #[test]
    fn parallel_count_prefix_scatter_is_byte_identical_across_chunk_boundaries() {
        // Exhaust every non-empty query topology of a four-level tree. This
        // closes the sibling/singleton grouping proof independently of the
        // larger adversarial cases below.
        for mask in 1u32..(1 << 16) {
            let queries = (0..16)
                .filter(|index| mask & (1 << index) != 0)
                .collect::<Vec<_>>();
            assert_eq!(
                prefix_scatter_walk_layout(queries.clone(), 4),
                serial_walk_layout(queries, 4)
            );
        }

        let mut pseudo_random = (0..700)
            .map(|i| (i * 73 + 19) & ((1 << 12) - 1))
            .collect::<Vec<_>>();
        pseudo_random.sort_unstable();
        pseudo_random.dedup();
        let cases = [
            vec![0],
            vec![1, 2],
            (0..513).collect(),
            (0..1 << 12).filter(|index| index % 7 != 3).collect(),
            pseudo_random,
        ];
        for queries in cases {
            let serial = serial_walk_layout(queries.clone(), 12);
            let parallel = prefix_scatter_walk_layout(queries, 12);
            assert_eq!(parallel, serial);
            assert_eq!(encoded_walk_layout(&parallel), encoded_walk_layout(&serial));
            assert_eq!(parallel.root, 0);
        }
    }

    #[test]
    fn direct_assembly_destination_keeps_owner_identity_and_exact_extent() {
        let bundle = ArenaSlice::dangling_for_test(77, 96);
        let tail = bundle.checked_subslice(32, 64).unwrap();
        let destination =
            validate_assembly_destination(tail, bundle.id(), bundle.context_token(), 48).unwrap();
        assert_eq!(destination.id(), bundle.id());
        assert_eq!(destination.as_u32_ptr(), tail.as_u32_ptr());
        assert_eq!(destination.len_words(), 48);
        assert!(matches!(
            validate_assembly_destination(tail, ArenaSlotId(78), bundle.context_token(), 48,),
            Err(PreparedDecommitError::AssemblySlotMismatch {
                expected: ArenaSlotId(78),
                actual: ArenaSlotId(77),
            })
        ));
        assert!(matches!(
            validate_assembly_destination(
                tail.truncated(47),
                bundle.id(),
                bundle.context_token(),
                48,
            ),
            Err(PreparedDecommitError::SlotTooSmall {
                required_words: 48,
                actual_words: 47,
                ..
            })
        ));
    }

    #[test]
    fn compiled_decommit_tail_contract_uses_one_block_without_false_sm_occupancy() {
        let source = include_str!("../../../backend-cuda-kernels/cuda/decommit.cu");
        assert_eq!(source.matches("__launch_bounds__(BLOCK)").count(), 3);
        assert!(!source.contains("ASSEMBLY_MIN_BLOCKS_PER_SM"));
        assert!(source.contains("pack_trace_group_kernel<<<1, BLOCK"));
        assert!(source.contains("assemble_trace_kernel<<<1, BLOCK"));
        assert!(source.contains("assemble_fri_kernel<<<1, BLOCK"));
        assert!(!source.contains("assemble_trace_kernel<<<1, 1"));
        assert!(!source.contains("assemble_fri_kernel<<<1, 1"));
        assert!(!source.contains("gather_trace_values_kernel"));
        assert!(!source.contains("gather_fri_values_kernel"));
        assert!(source.contains("canonical_m31(columns[column][row])"));
        assert!(source.contains("canonical_m31(coordinates[c][expanded[i]])"));
    }
}
