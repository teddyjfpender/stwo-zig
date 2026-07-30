//! Address-free planning and CPU semantics for domain-progressive commit leaves.
//!
//! This module deliberately contains no CUDA ABI or launch code. It seals the
//! proposed architecture, proves its canonical byte stream against the current
//! full-lifting construction, and exposes exact accounting for review before a
//! device implementation is admitted.

use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasherGeneric};

const LEAF_BLOCK_COLUMNS: usize = 16;
/// Maximum number of scratch-backed same-domain columns materialized before
/// their canonical leaf bytes are absorbed and the shared LDE scratch is
/// reused. Retained destinations consume no shared scratch and therefore do
/// not count against this bound.
pub const PROGRESSIVE_LDE_BATCH_MAX_SCRATCH_COLUMNS: usize = LEAF_BLOCK_COLUMNS;
/// Conservative bound on one device pointer table and its `u32` column count.
const PROGRESSIVE_LDE_BATCH_MAX_TOTAL_COLUMNS: usize = 65_535;
const PROGRESSIVE_LDE_BATCH_POLICY: &[u8] = b"canonical-same-log-max-scratch-and-total-columns";
const FIELD_WORD_BYTES: usize = core::mem::size_of::<u32>();
pub const BLAKE2S_BLOCK_BYTES: usize = 64;
pub const PROGRESSIVE_BLAKE2S_H_OFFSET: usize = 0;
pub const PROGRESSIVE_BLAKE2S_PENDING_BLOCK_OFFSET: usize = 32;
/// Superseded state stride retained only for exact before/after accounting.
pub const LEGACY_PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES: usize = 128;
/// Device ABI stride for one clonable progressive BLAKE2s state. Every row in
/// one launch has absorbed the same canonical column prefix, so the counter,
/// pending length, and non-final flags are launch scalars. Only `h[8]` and the
/// lazy 64-byte final block are row-varying and survive in HBM.
pub const PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES: usize = 96;
const _: () = assert!(
    PROGRESSIVE_BLAKE2S_PENDING_BLOCK_OFFSET + BLAKE2S_BLOCK_BYTES
        == PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ProgressiveCommitMode {
    FullLifting = 0,
    DomainProgressive = 1,
}

impl ProgressiveCommitMode {
    /// Process-sealed and default-off until the CPU oracle and a later native
    /// differential are independently approved.
    pub fn from_env() -> Self {
        static MODE: std::sync::OnceLock<ProgressiveCommitMode> = std::sync::OnceLock::new();
        *MODE.get_or_init(|| {
            if std::env::var("STWO_CUDA_COMMIT_DOMAIN_PROGRESSIVE").as_deref() == Ok("1") {
                Self::DomainProgressive
            } else {
                Self::FullLifting
            }
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveCommitGroupGeometry {
    pub coefficient_log_sizes: Vec<u32>,
    pub retain_evaluations: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveCommitGeometry {
    pub lifting_log_size: u32,
    pub log_blowup_factor: u32,
    pub groups: Vec<ProgressiveCommitGroupGeometry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressiveColumn {
    pub canonical_index: usize,
    pub group_index: usize,
    pub column_in_group: usize,
    pub coefficient_log_size: u32,
    pub evaluation_log_size: u32,
    pub retained_evaluation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SameLogLdeBatch {
    pub evaluation_log_size: u32,
    /// Canonical commitment indices, possibly crossing historical group edges.
    pub columns: Vec<usize>,
    /// Exact retained destination association for every entry in `columns`.
    pub retained_columns: Vec<Option<(usize, usize)>>,
    pub output_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgressiveBlockSegment {
    pub evaluation_log_size: u32,
    pub first_column: usize,
    pub column_count: usize,
    pub byte_offset_in_block: usize,
    pub byte_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalLeafBlock {
    pub block_index: usize,
    pub first_column: usize,
    pub column_count: usize,
    pub byte_count: usize,
    pub segments: Vec<ProgressiveBlockSegment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateExpansion {
    pub from_log_size: u32,
    pub to_log_size: u32,
    pub states_before: usize,
    pub states_after: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sStateExpansion {
    pub domain: StateExpansion,
    /// Canonical boundary before which every column has been absorbed.
    pub absorbed_columns: usize,
    /// Total leaf-message bytes accepted by each source state.
    pub absorbed_bytes_per_state: usize,
    /// Exact BLAKE2s counter stored in the state: bytes already compressed.
    pub compressed_byte_counter: usize,
    /// Lazy-buffer prefix cloned with the state. A full pending final block is
    /// represented as 64, not zero.
    pub pending_block_prefix_bytes: usize,
    pub device_state_stride_bytes: usize,
    /// Exact algorithmic traffic for the sealed output-parallel expansion:
    /// every destination state reads one complete parent stride and writes one
    /// complete child stride. Cache effects are intentionally not claimed.
    pub read_traffic_bytes: usize,
    pub write_traffic_bytes: usize,
    pub total_traffic_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProgressiveCommitAccounting {
    pub leaf_nodes: usize,
    pub interior_nodes: usize,
    pub total_nodes: usize,
    pub canonical_leaf_bytes: usize,
    pub progressive_absorbed_bytes: usize,
    pub full_lifting_absorbed_bytes: usize,
    pub lde_output_words: usize,
    pub progressive_leaf_compressions: usize,
    pub full_lifting_leaf_compressions: usize,
    pub interior_compressions: usize,
    pub progressive_total_compressions: usize,
    pub full_lifting_total_compressions: usize,
    pub state_expansion_read_bytes: usize,
    pub state_expansion_write_bytes: usize,
    pub state_expansion_total_bytes: usize,
    pub state_init_write_bytes: usize,
    pub state_absorb_read_bytes: usize,
    pub state_absorb_write_bytes: usize,
    pub state_finalize_read_bytes: usize,
    pub state_total_traffic_bytes: usize,
    pub legacy_state_total_traffic_bytes: usize,
    pub state_traffic_saved_bytes: usize,
    pub peak_progressive_state_bytes: usize,
    pub legacy_peak_progressive_state_bytes: usize,
    pub peak_state_saved_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressiveCommitPlan {
    pub mode: ProgressiveCommitMode,
    pub geometry: ProgressiveCommitGeometry,
    pub columns: Vec<ProgressiveColumn>,
    pub lde_batches: Vec<SameLogLdeBatch>,
    pub leaf_blocks: Vec<CanonicalLeafBlock>,
    pub state_expansions: Vec<Blake2sStateExpansion>,
    pub accounting: ProgressiveCommitAccounting,
    pub cache_key: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgressiveCommitError {
    EmptyCommitment,
    EmptyGroup(usize),
    InvalidBlowup(u32),
    InvalidLiftingLogSize(u32),
    InvalidLogSize {
        group: usize,
        column: usize,
        log_size: u32,
    },
    EvaluationExceedsLifting {
        evaluation_log_size: u32,
        lifting_log_size: u32,
    },
    NonCanonicalOrder {
        previous: u32,
        current: u32,
    },
    InvalidLdeBatchPlan,
    SizeOverflow,
    OracleColumnCountMismatch,
    OracleColumnLengthMismatch {
        column: usize,
        expected: usize,
        actual: usize,
    },
    OracleTooLarge(u32),
}

pub fn plan_progressive_commit(
    mode: ProgressiveCommitMode,
    geometry: ProgressiveCommitGeometry,
) -> Result<ProgressiveCommitPlan, ProgressiveCommitError> {
    let plan = canonical_progressive_commit_plan(mode, geometry)?;
    validate_progressive_plan(&plan)?;
    Ok(plan)
}

/// Build the one canonical representation without calling admission. Keeping
/// derivation here lets public admission rebuild and compare the complete plan
/// without recursing through [`plan_progressive_commit`].
fn canonical_progressive_commit_plan(
    mode: ProgressiveCommitMode,
    geometry: ProgressiveCommitGeometry,
) -> Result<ProgressiveCommitPlan, ProgressiveCommitError> {
    if !(1..=16).contains(&geometry.log_blowup_factor) {
        return Err(ProgressiveCommitError::InvalidBlowup(
            geometry.log_blowup_factor,
        ));
    }
    if geometry.lifting_log_size >= 31 {
        return Err(ProgressiveCommitError::InvalidLiftingLogSize(
            geometry.lifting_log_size,
        ));
    }
    if geometry.groups.is_empty() {
        return Err(ProgressiveCommitError::EmptyCommitment);
    }
    let mut columns = Vec::new();
    let mut previous = None;
    for (group_index, group) in geometry.groups.iter().enumerate() {
        if group.coefficient_log_sizes.is_empty() {
            return Err(ProgressiveCommitError::EmptyGroup(group_index));
        }
        for (column_in_group, &coefficient_log_size) in
            group.coefficient_log_sizes.iter().enumerate()
        {
            let evaluation_log_size = coefficient_log_size
                .checked_add(geometry.log_blowup_factor)
                .ok_or(ProgressiveCommitError::SizeOverflow)?;
            if !(4..=30).contains(&evaluation_log_size) {
                return Err(ProgressiveCommitError::InvalidLogSize {
                    group: group_index,
                    column: column_in_group,
                    log_size: evaluation_log_size,
                });
            }
            if evaluation_log_size > geometry.lifting_log_size {
                return Err(ProgressiveCommitError::EvaluationExceedsLifting {
                    evaluation_log_size,
                    lifting_log_size: geometry.lifting_log_size,
                });
            }
            if previous.is_some_and(|previous| coefficient_log_size < previous) {
                return Err(ProgressiveCommitError::NonCanonicalOrder {
                    previous: previous.unwrap(),
                    current: coefficient_log_size,
                });
            }
            previous = Some(coefficient_log_size);
            columns.push(ProgressiveColumn {
                canonical_index: columns.len(),
                group_index,
                column_in_group,
                coefficient_log_size,
                evaluation_log_size,
                retained_evaluation: group.retain_evaluations,
            });
        }
    }
    u32::try_from(columns.len()).map_err(|_| ProgressiveCommitError::SizeOverflow)?;

    let mut lde_batches = Vec::new();
    let mut start = 0usize;
    while start < columns.len() {
        let log_size = columns[start].evaluation_log_size;
        let mut end = start + 1;
        let mut scratch_columns = usize::from(!columns[start].retained_evaluation);
        while end < columns.len()
            && end - start < PROGRESSIVE_LDE_BATCH_MAX_TOTAL_COLUMNS
            && columns[end].evaluation_log_size == log_size
        {
            if !columns[end].retained_evaluation
                && scratch_columns == PROGRESSIVE_LDE_BATCH_MAX_SCRATCH_COLUMNS
            {
                break;
            }
            scratch_columns += usize::from(!columns[end].retained_evaluation);
            end += 1;
        }
        let output_words = pow2(log_size)?
            .checked_mul(end - start)
            .ok_or(ProgressiveCommitError::SizeOverflow)?;
        lde_batches.push(SameLogLdeBatch {
            evaluation_log_size: log_size,
            columns: (start..end).collect(),
            retained_columns: columns[start..end]
                .iter()
                .map(|column| {
                    column
                        .retained_evaluation
                        .then_some((column.group_index, column.column_in_group))
                })
                .collect(),
            output_words,
        });
        start = end;
    }

    let leaf_blocks = columns
        .chunks(LEAF_BLOCK_COLUMNS)
        .enumerate()
        .map(|(block_index, block_columns)| {
            let first_column = block_columns[0].canonical_index;
            let mut segments = Vec::new();
            let mut local = 0usize;
            while local < block_columns.len() {
                let log_size = block_columns[local].evaluation_log_size;
                let mut end = local + 1;
                while end < block_columns.len()
                    && block_columns[end].evaluation_log_size == log_size
                {
                    end += 1;
                }
                let count = end - local;
                segments.push(ProgressiveBlockSegment {
                    evaluation_log_size: log_size,
                    first_column: first_column + local,
                    column_count: count,
                    byte_offset_in_block: local * FIELD_WORD_BYTES,
                    byte_count: count * FIELD_WORD_BYTES,
                });
                local = end;
            }
            CanonicalLeafBlock {
                block_index,
                first_column,
                column_count: block_columns.len(),
                byte_count: block_columns.len() * FIELD_WORD_BYTES,
                segments,
            }
        })
        .collect::<Vec<_>>();

    let mut state_expansions = Vec::new();
    let mut current_log = columns[0].evaluation_log_size;
    for batch in &lde_batches[1..] {
        if batch.evaluation_log_size > current_log {
            state_expansions.push(blake2s_expansion(
                current_log,
                batch.evaluation_log_size,
                batch.columns[0],
            )?);
            current_log = batch.evaluation_log_size;
        }
    }
    if current_log < geometry.lifting_log_size {
        state_expansions.push(blake2s_expansion(
            current_log,
            geometry.lifting_log_size,
            columns.len(),
        )?);
    }

    let leaf_nodes = pow2(geometry.lifting_log_size)?;
    let interior_nodes = leaf_nodes - 1;
    let canonical_leaf_bytes = leaf_nodes
        .checked_mul(columns.len())
        .and_then(|words| words.checked_mul(FIELD_WORD_BYTES))
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let progressive_absorbed_bytes = columns.iter().try_fold(0usize, |total, column| {
        let column_bytes = pow2(column.evaluation_log_size)?
            .checked_mul(FIELD_WORD_BYTES)
            .ok_or(ProgressiveCommitError::SizeOverflow)?;
        total
            .checked_add(column_bytes)
            .ok_or(ProgressiveCommitError::SizeOverflow)
    })?;
    let lde_output_words = columns.iter().try_fold(0usize, |total, column| {
        total
            .checked_add(pow2(column.evaluation_log_size)?)
            .ok_or(ProgressiveCommitError::SizeOverflow)
    })?;
    // BLAKE2s retains the last 64-byte leaf block for finalization. Every
    // non-final block is compressed when the next block's first word arrives,
    // after expansion to that word's domain. The final block is compressed
    // after the final expansion to the lifting domain.
    let mut progressive_leaf_compressions = 0usize;
    for block in &leaf_blocks[..leaf_blocks.len().saturating_sub(1)] {
        let next_column = block.first_column + block.column_count;
        progressive_leaf_compressions = progressive_leaf_compressions
            .checked_add(pow2(columns[next_column].evaluation_log_size)?)
            .ok_or(ProgressiveCommitError::SizeOverflow)?;
    }
    progressive_leaf_compressions = progressive_leaf_compressions
        .checked_add(leaf_nodes)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let full_lifting_leaf_compressions = leaf_nodes
        .checked_mul(leaf_blocks.len())
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let total_nodes = leaf_nodes
        .checked_add(interior_nodes)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let progressive_total_compressions = progressive_leaf_compressions
        .checked_add(interior_nodes)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let full_lifting_total_compressions = full_lifting_leaf_compressions
        .checked_add(interior_nodes)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let state_expansion_read_bytes =
        state_expansions
            .iter()
            .try_fold(0usize, |total, expansion| {
                total
                    .checked_add(expansion.read_traffic_bytes)
                    .ok_or(ProgressiveCommitError::SizeOverflow)
            })?;
    let state_expansion_write_bytes =
        state_expansions
            .iter()
            .try_fold(0usize, |total, expansion| {
                total
                    .checked_add(expansion.write_traffic_bytes)
                    .ok_or(ProgressiveCommitError::SizeOverflow)
            })?;
    let state_expansion_total_bytes = state_expansion_read_bytes
        .checked_add(state_expansion_write_bytes)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let initial_state_rows = pow2(columns[0].evaluation_log_size)?;
    let absorb_state_rows = lde_batches.iter().try_fold(0usize, |total, batch| {
        total
            .checked_add(pow2(batch.evaluation_log_size)?)
            .ok_or(ProgressiveCommitError::SizeOverflow)
    })?;
    let expansion_state_rows = state_expansions
        .iter()
        .try_fold(0usize, |total, expansion| {
            total
                .checked_add(expansion.domain.states_after)
                .ok_or(ProgressiveCommitError::SizeOverflow)
        })?;
    let state_init_write_bytes = initial_state_rows
        .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let state_absorb_read_bytes = absorb_state_rows
        .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let state_absorb_write_bytes = state_absorb_read_bytes;
    let state_finalize_read_bytes = leaf_nodes
        .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let state_total_traffic_bytes = state_init_write_bytes
        .checked_add(state_absorb_read_bytes)
        .and_then(|bytes| bytes.checked_add(state_absorb_write_bytes))
        .and_then(|bytes| bytes.checked_add(state_expansion_read_bytes))
        .and_then(|bytes| bytes.checked_add(state_expansion_write_bytes))
        .and_then(|bytes| bytes.checked_add(state_finalize_read_bytes))
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let legacy_state_total_traffic_bytes = initial_state_rows
        .checked_add(
            absorb_state_rows
                .checked_mul(2)
                .ok_or(ProgressiveCommitError::SizeOverflow)?,
        )
        .and_then(|rows| rows.checked_add(expansion_state_rows.checked_mul(2)?))
        .and_then(|rows| rows.checked_add(leaf_nodes))
        .ok_or(ProgressiveCommitError::SizeOverflow)?
        .checked_mul(LEGACY_PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let state_traffic_saved_bytes = legacy_state_total_traffic_bytes
        .checked_sub(state_total_traffic_bytes)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    // Expansion is explicitly non-aliasing: every parent must remain live
    // until all projected children have been written. No in-place traffic or
    // storage saving is claimed.
    let peak_for_stride = |stride: usize| {
        let initial_state_bytes = initial_state_rows
            .checked_mul(stride)
            .ok_or(ProgressiveCommitError::SizeOverflow)?;
        let final_state_bytes = leaf_nodes
            .checked_mul(stride)
            .ok_or(ProgressiveCommitError::SizeOverflow)?;
        state_expansions.iter().try_fold(
            initial_state_bytes.max(final_state_bytes),
            |peak, expansion| {
                let simultaneous_states = expansion
                    .domain
                    .states_before
                    .checked_add(expansion.domain.states_after)
                    .ok_or(ProgressiveCommitError::SizeOverflow)?;
                let live_bytes = simultaneous_states
                    .checked_mul(stride)
                    .ok_or(ProgressiveCommitError::SizeOverflow)?;
                Ok::<_, ProgressiveCommitError>(peak.max(live_bytes))
            },
        )
    };
    let peak_progressive_state_bytes = peak_for_stride(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)?;
    let legacy_peak_progressive_state_bytes =
        peak_for_stride(LEGACY_PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)?;
    let peak_state_saved_bytes = legacy_peak_progressive_state_bytes
        .checked_sub(peak_progressive_state_bytes)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let accounting = ProgressiveCommitAccounting {
        leaf_nodes,
        interior_nodes,
        total_nodes,
        canonical_leaf_bytes,
        progressive_absorbed_bytes,
        full_lifting_absorbed_bytes: canonical_leaf_bytes,
        lde_output_words,
        progressive_leaf_compressions,
        full_lifting_leaf_compressions,
        interior_compressions: interior_nodes,
        progressive_total_compressions,
        full_lifting_total_compressions,
        state_expansion_read_bytes,
        state_expansion_write_bytes,
        state_expansion_total_bytes,
        state_init_write_bytes,
        state_absorb_read_bytes,
        state_absorb_write_bytes,
        state_finalize_read_bytes,
        state_total_traffic_bytes,
        legacy_state_total_traffic_bytes,
        state_traffic_saved_bytes,
        peak_progressive_state_bytes,
        legacy_peak_progressive_state_bytes,
        peak_state_saved_bytes,
    };
    let cache_key = progressive_commit_cache_key(mode, &geometry);
    Ok(ProgressiveCommitPlan {
        mode,
        geometry,
        columns,
        lde_batches,
        leaf_blocks,
        state_expansions,
        accounting,
        cache_key,
    })
}

pub fn lifted_column_index(row: usize, source_log_size: u32, lifting_log_size: u32) -> usize {
    let ratio = lifting_log_size - source_log_size;
    (row >> (ratio + 1) << 1) + (row & 1)
}

pub fn progressive_leaf_oracle(
    plan: &ProgressiveCommitPlan,
    evaluations: &[Vec<u32>],
) -> Result<Vec<Blake2sHash>, ProgressiveCommitError> {
    validate_progressive_plan(plan)?;
    validate_oracle_columns(plan, evaluations)?;
    let first_log = plan.columns[0].evaluation_log_size;
    let mut states = vec![Blake2sHasherGeneric::<false>::default(); pow2(first_log)?];
    let mut current_log = first_log;
    for batch in &plan.lde_batches {
        if batch.evaluation_log_size > current_log {
            states = expand_states(states, current_log, batch.evaluation_log_size)?;
            current_log = batch.evaluation_log_size;
        }
        for &column_index in &batch.columns {
            for (state, &word) in states.iter_mut().zip(&evaluations[column_index]) {
                state.update(&word.to_le_bytes());
            }
        }
    }
    if current_log < plan.geometry.lifting_log_size {
        states = expand_states(states, current_log, plan.geometry.lifting_log_size)?;
    }
    Ok(states.into_iter().map(|state| state.finalize()).collect())
}

pub fn full_lifting_leaf_oracle(
    plan: &ProgressiveCommitPlan,
    evaluations: &[Vec<u32>],
) -> Result<Vec<Blake2sHash>, ProgressiveCommitError> {
    validate_progressive_plan(plan)?;
    validate_oracle_columns(plan, evaluations)?;
    let rows = pow2(plan.geometry.lifting_log_size)?;
    Ok((0..rows)
        .map(|row| {
            let mut state = Blake2sHasherGeneric::<false>::default();
            for (column, values) in plan.columns.iter().zip(evaluations) {
                state.update(
                    &values[lifted_column_index(
                        row,
                        column.evaluation_log_size,
                        plan.geometry.lifting_log_size,
                    )]
                    .to_le_bytes(),
                );
            }
            state.finalize()
        })
        .collect())
}

pub fn merkle_root(mut layer: Vec<Blake2sHash>) -> Blake2sHash {
    assert!(!layer.is_empty() && layer.len().is_power_of_two());
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|children| {
                Blake2sHasherGeneric::<false>::concat_and_hash(&children[0], &children[1])
            })
            .collect();
    }
    layer[0]
}

pub fn progressive_commit_cache_key(
    mode: ProgressiveCommitMode,
    geometry: &ProgressiveCommitGeometry,
) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    };
    feed(b"stwo-progressive-commit-plan-v4\0");
    feed(PROGRESSIVE_LDE_BATCH_POLICY);
    feed(&(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64).to_le_bytes());
    feed(&(PROGRESSIVE_LDE_BATCH_MAX_SCRATCH_COLUMNS as u64).to_le_bytes());
    feed(&(PROGRESSIVE_LDE_BATCH_MAX_TOTAL_COLUMNS as u64).to_le_bytes());
    feed(&[mode as u8]);
    feed(&geometry.lifting_log_size.to_le_bytes());
    feed(&geometry.log_blowup_factor.to_le_bytes());
    feed(&(geometry.groups.len() as u64).to_le_bytes());
    for group in &geometry.groups {
        feed(&[u8::from(group.retain_evaluations)]);
        feed(&(group.coefficient_log_sizes.len() as u64).to_le_bytes());
        for log_size in &group.coefficient_log_sizes {
            feed(&log_size.to_le_bytes());
        }
    }
    hash
}

/// Rebuild and compare the complete canonical plan before any public oracle or
/// address-bearing prepared graph trusts its geometry, sizes, or output map.
pub fn validate_progressive_plan(
    plan: &ProgressiveCommitPlan,
) -> Result<(), ProgressiveCommitError> {
    let canonical = canonical_progressive_commit_plan(plan.mode, plan.geometry.clone())?;
    if *plan != canonical {
        return Err(ProgressiveCommitError::InvalidLdeBatchPlan);
    }
    Ok(())
}

fn validate_oracle_columns(
    plan: &ProgressiveCommitPlan,
    evaluations: &[Vec<u32>],
) -> Result<(), ProgressiveCommitError> {
    if plan.geometry.lifting_log_size > 16 {
        return Err(ProgressiveCommitError::OracleTooLarge(
            plan.geometry.lifting_log_size,
        ));
    }
    if evaluations.len() != plan.columns.len() {
        return Err(ProgressiveCommitError::OracleColumnCountMismatch);
    }
    for (column, values) in plan.columns.iter().zip(evaluations) {
        let expected = pow2(column.evaluation_log_size)?;
        if values.len() != expected {
            return Err(ProgressiveCommitError::OracleColumnLengthMismatch {
                column: column.canonical_index,
                expected,
                actual: values.len(),
            });
        }
    }
    Ok(())
}

fn expand_states(
    states: Vec<Blake2sHasherGeneric<false>>,
    from_log: u32,
    to_log: u32,
) -> Result<Vec<Blake2sHasherGeneric<false>>, ProgressiveCommitError> {
    Ok((0..pow2(to_log)?)
        .map(|row| states[lifted_column_index(row, from_log, to_log)].clone())
        .collect())
}

fn blake2s_expansion(
    from_log_size: u32,
    to_log_size: u32,
    absorbed_columns: usize,
) -> Result<Blake2sStateExpansion, ProgressiveCommitError> {
    let domain = StateExpansion {
        from_log_size,
        to_log_size,
        states_before: pow2(from_log_size)?,
        states_after: pow2(to_log_size)?,
    };
    let (absorbed_bytes_per_state, compressed_byte_counter, pending_block_prefix_bytes) =
        blake2s_prefix_schedule(absorbed_columns)?;
    let read_traffic_bytes = domain
        .states_after
        .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let write_traffic_bytes = domain
        .states_after
        .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    Ok(Blake2sStateExpansion {
        domain,
        absorbed_columns,
        absorbed_bytes_per_state,
        compressed_byte_counter,
        pending_block_prefix_bytes,
        device_state_stride_bytes: PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
        read_traffic_bytes,
        write_traffic_bytes,
        total_traffic_bytes: read_traffic_bytes
            .checked_add(write_traffic_bytes)
            .ok_or(ProgressiveCommitError::SizeOverflow)?,
    })
}

fn blake2s_prefix_schedule(
    absorbed_columns: usize,
) -> Result<(usize, usize, usize), ProgressiveCommitError> {
    let absorbed_bytes = absorbed_columns
        .checked_mul(FIELD_WORD_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let pending_bytes = if absorbed_bytes == 0 {
        0
    } else {
        (absorbed_bytes - 1) % BLAKE2S_BLOCK_BYTES + 1
    };
    Ok((
        absorbed_bytes,
        absorbed_bytes - pending_bytes,
        pending_bytes,
    ))
}

fn pow2(log_size: u32) -> Result<usize, ProgressiveCommitError> {
    1usize
        .checked_shl(log_size)
        .ok_or(ProgressiveCommitError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry(logs: &[u32], lifting: u32) -> ProgressiveCommitGeometry {
        ProgressiveCommitGeometry {
            lifting_log_size: lifting,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: logs.to_vec(),
                retain_evaluations: false,
            }],
        }
    }

    fn evaluations(plan: &ProgressiveCommitPlan, salt: u32) -> Vec<Vec<u32>> {
        plan.columns
            .iter()
            .map(|column| {
                (0..1usize << column.evaluation_log_size)
                    .map(|row| {
                        salt.wrapping_add(104_729 * column.canonical_index as u32)
                            .wrapping_add(7_919 * row as u32)
                            % 0x7fff_ffff
                    })
                    .collect()
            })
            .collect()
    }

    fn compositions(
        length: usize,
        min: u32,
        max: u32,
        prefix: &mut Vec<u32>,
        output: &mut Vec<Vec<u32>>,
    ) {
        if prefix.len() == length {
            output.push(prefix.clone());
            return;
        }
        let start = prefix.last().copied().unwrap_or(min);
        for value in start..=max {
            prefix.push(value);
            compositions(length, min, max, prefix, output);
            prefix.pop();
        }
    }

    #[test]
    fn exhaustive_small_mixed_logs_match_full_lifting_leaves_and_roots() {
        for column_count in 1..=6 {
            let mut cases = Vec::new();
            compositions(column_count, 3, 5, &mut Vec::new(), &mut cases);
            for logs in cases {
                let plan = plan_progressive_commit(
                    ProgressiveCommitMode::DomainProgressive,
                    geometry(&logs, 6),
                )
                .unwrap();
                let values = evaluations(&plan, column_count as u32);
                let progressive = progressive_leaf_oracle(&plan, &values).unwrap();
                let full = full_lifting_leaf_oracle(&plan, &values).unwrap();
                assert_eq!(progressive, full, "logs={logs:?}");
                assert_eq!(merkle_root(progressive), merkle_root(full));
            }
        }
    }

    #[test]
    fn adversarial_words_and_log_rises_match_at_leaf_and_root() {
        let logs = (0..33)
            .map(|index| match index {
                0..=4 => 3,
                5..=15 => 4,
                _ => 5,
            })
            .collect::<Vec<_>>();
        let plan =
            plan_progressive_commit(ProgressiveCommitMode::DomainProgressive, geometry(&logs, 6))
                .unwrap();
        for pattern in 0..3 {
            let values = plan
                .columns
                .iter()
                .map(|column| {
                    (0..1usize << column.evaluation_log_size)
                        .map(|row| match pattern {
                            0 => 0,
                            1 => 0x7fff_fffe,
                            _ => {
                                if (row + column.canonical_index) & 1 == 0 {
                                    0
                                } else {
                                    0x7fff_fffe
                                }
                            }
                        })
                        .collect()
                })
                .collect::<Vec<_>>();
            let progressive = progressive_leaf_oracle(&plan, &values).unwrap();
            let full = full_lifting_leaf_oracle(&plan, &values).unwrap();
            assert_eq!(progressive, full);
            assert_eq!(merkle_root(progressive), merkle_root(full));
        }
    }

    #[test]
    fn retained_outputs_match_progressive_leaves_root_and_cpu_decommit() {
        use stwo::core::fields::m31::BaseField;
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
        use stwo::core::vcs_lifted::verifier::MerkleVerifierLifted;
        use stwo::prover::backend::CpuBackend;
        use stwo::prover::vcs_lifted::prover::MerkleProverLifted;

        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 6,
                log_blowup_factor: 1,
                groups: vec![
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![3, 4],
                        retain_evaluations: true,
                    },
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![5],
                        retain_evaluations: false,
                    },
                ],
            },
        )
        .unwrap();
        let retained = evaluations(&plan, 0x5a17);
        assert_eq!(
            plan.lde_batches
                .iter()
                .flat_map(|batch| batch.retained_columns.iter().copied())
                .collect::<Vec<_>>(),
            [Some((0, 0)), Some((0, 1)), None]
        );

        let progressive_leaves = progressive_leaf_oracle(&plan, &retained).unwrap();
        let full_lifting_leaves = full_lifting_leaf_oracle(&plan, &retained).unwrap();
        assert_eq!(progressive_leaves, full_lifting_leaves);

        let columns = retained
            .iter()
            .map(|column| {
                column
                    .iter()
                    .copied()
                    .map(BaseField::from_u32_unchecked)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let cpu = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
            columns.iter().collect(),
            plan.geometry.lifting_log_size,
            0,
        );
        assert_eq!(cpu.root(), merkle_root(progressive_leaves));

        let queries = [0usize, 5, 17, 63];
        let (queried_values, decommitment) = cpu.decommit(&queries, columns.iter().collect());
        let verifier = MerkleVerifierLifted::new(
            cpu.root(),
            plan.columns
                .iter()
                .map(|column| column.evaluation_log_size)
                .collect(),
            None,
        );
        verifier
            .verify(&queries, queried_values, decommitment.decommitment)
            .unwrap();
    }

    #[test]
    fn canonical_blocks_preserve_order_partial_bytes_and_mixed_log_segments() {
        let logs = (0..17)
            .map(|index| if index < 7 { 3 } else { 5 })
            .collect::<Vec<_>>();
        let plan =
            plan_progressive_commit(ProgressiveCommitMode::DomainProgressive, geometry(&logs, 6))
                .unwrap();
        assert_eq!(plan.leaf_blocks.len(), 2);
        assert_eq!(plan.leaf_blocks[0].first_column, 0);
        assert_eq!(plan.leaf_blocks[0].column_count, 16);
        assert_eq!(plan.leaf_blocks[0].byte_count, 64);
        assert_eq!(plan.leaf_blocks[0].segments.len(), 2);
        assert_eq!(plan.leaf_blocks[0].segments[0].column_count, 7);
        assert_eq!(plan.leaf_blocks[0].segments[1].byte_offset_in_block, 28);
        assert_eq!(plan.leaf_blocks[1].first_column, 16);
        assert_eq!(plan.leaf_blocks[1].column_count, 1);
        assert_eq!(plan.leaf_blocks[1].byte_count, 4);
        assert_eq!(
            plan.leaf_blocks
                .iter()
                .flat_map(|block| block.first_column..block.first_column + block.column_count)
                .collect::<Vec<_>>(),
            (0..17).collect::<Vec<_>>()
        );
    }

    #[test]
    fn same_log_batches_cross_groups_and_keep_retained_destinations() {
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 6,
                log_blowup_factor: 1,
                groups: vec![
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![3, 4],
                        retain_evaluations: false,
                    },
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![4, 4],
                        retain_evaluations: true,
                    },
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![5],
                        retain_evaluations: false,
                    },
                ],
            },
        )
        .unwrap();
        assert_eq!(plan.lde_batches[1].columns, vec![1, 2, 3]);
        assert_eq!(
            plan.lde_batches[1].retained_columns,
            vec![None, Some((1, 0)), Some((1, 1))]
        );
        assert_eq!(plan.lde_batches[1].output_words, 3 << 5);
    }

    #[test]
    fn same_log_scratch_chunks_are_canonical_bounded_and_oracle_identical() {
        for column_count in [1usize, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
            let plan = plan_progressive_commit(
                ProgressiveCommitMode::DomainProgressive,
                geometry(&vec![3; column_count], 6),
            )
            .unwrap();
            assert_eq!(
                plan.lde_batches
                    .iter()
                    .map(|batch| batch.columns.len())
                    .collect::<Vec<_>>(),
                (0..column_count)
                    .collect::<Vec<_>>()
                    .chunks(PROGRESSIVE_LDE_BATCH_MAX_SCRATCH_COLUMNS)
                    .map(<[usize]>::len)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                plan.lde_batches
                    .iter()
                    .flat_map(|batch| batch.columns.iter().copied())
                    .collect::<Vec<_>>(),
                (0..column_count).collect::<Vec<_>>()
            );
            assert!(plan.lde_batches.iter().all(|batch| {
                batch.evaluation_log_size == 4
                    && batch.output_words == batch.columns.len() * (1 << 4)
            }));
            validate_progressive_plan(&plan).unwrap();

            let values = evaluations(&plan, column_count as u32 ^ 0x6a09_e667);
            let progressive = progressive_leaf_oracle(&plan, &values).unwrap();
            let full = full_lifting_leaf_oracle(&plan, &values).unwrap();
            assert_eq!(progressive, full, "column_count={column_count}");
            assert_eq!(merkle_root(progressive), merkle_root(full));
        }
    }

    #[test]
    fn retained_columns_coalesce_without_raising_the_scratch_bound() {
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 6,
                log_blowup_factor: 1,
                groups: vec![
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![3; 8],
                        retain_evaluations: false,
                    },
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![3; 33],
                        retain_evaluations: true,
                    },
                    ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: vec![3; 8],
                        retain_evaluations: false,
                    },
                ],
            },
        )
        .unwrap();
        assert_eq!(plan.lde_batches.len(), 1);
        let batch = &plan.lde_batches[0];
        assert_eq!(batch.columns, (0..49).collect::<Vec<_>>());
        assert_eq!(
            batch
                .retained_columns
                .iter()
                .filter(|destination| destination.is_none())
                .count(),
            PROGRESSIVE_LDE_BATCH_MAX_SCRATCH_COLUMNS
        );
        assert_eq!(batch.output_words, 49 * (1 << 4));
        validate_progressive_plan(&plan).unwrap();

        let values = evaluations(&plan, 0x8bad_f00d);
        let progressive = progressive_leaf_oracle(&plan, &values).unwrap();
        let full = full_lifting_leaf_oracle(&plan, &values).unwrap();
        assert_eq!(progressive, full);
        assert_eq!(merkle_root(progressive), merkle_root(full));
    }

    #[test]
    fn retained_batches_respect_the_total_pointer_table_bound() {
        let column_count = PROGRESSIVE_LDE_BATCH_MAX_TOTAL_COLUMNS + 1;
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 4,
                log_blowup_factor: 1,
                groups: vec![ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3; column_count],
                    retain_evaluations: true,
                }],
            },
        )
        .unwrap();
        assert_eq!(
            plan.lde_batches
                .iter()
                .map(|batch| batch.columns.len())
                .collect::<Vec<_>>(),
            [PROGRESSIVE_LDE_BATCH_MAX_TOTAL_COLUMNS, 1]
        );
        assert!(plan
            .lde_batches
            .iter()
            .all(|batch| batch.retained_columns.iter().all(Option::is_some)));
        validate_progressive_plan(&plan).unwrap();
    }

    #[test]
    fn malformed_chunk_topologies_fail_closed() {
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[3; 17], 6),
        )
        .unwrap();
        assert_eq!(
            plan.lde_batches
                .iter()
                .map(|batch| batch.columns.len())
                .collect::<Vec<_>>(),
            [16, 1]
        );

        let rejects = |mutate: fn(&mut ProgressiveCommitPlan)| {
            let mut malformed = plan.clone();
            mutate(&mut malformed);
            assert_eq!(
                validate_progressive_plan(&malformed),
                Err(ProgressiveCommitError::InvalidLdeBatchPlan)
            );
        };
        rejects(|plan| plan.lde_batches[0].columns[0] = 1); // gap + duplicate.
        rejects(|plan| plan.lde_batches[0].columns.swap(0, 1));
        rejects(|plan| plan.lde_batches[0].evaluation_log_size += 1);
        rejects(|plan| plan.lde_batches[0].retained_columns[0] = Some((0, 0)));
        rejects(|plan| {
            let column = plan.lde_batches[0].columns.pop().unwrap();
            let retained = plan.lde_batches[0].retained_columns.pop().unwrap();
            plan.lde_batches[0].output_words -= 1 << 4;
            plan.lde_batches[1].columns.insert(0, column);
            plan.lde_batches[1].retained_columns.insert(0, retained);
            plan.lde_batches[1].output_words += 1 << 4;
        });
        rejects(|plan| {
            plan.lde_batches[0].columns.push(16);
            plan.lde_batches[0].retained_columns.push(None);
            plan.lde_batches[0].output_words += 1 << 4;
        });
        rejects(|plan| plan.cache_key ^= 1);
    }

    #[test]
    fn complete_admission_rejects_mutated_public_plans_before_oracle_indexing() {
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[3; 16].into_iter().chain([5]).collect::<Vec<_>>(), 6),
        )
        .unwrap();
        assert!(!plan.leaf_blocks.is_empty());
        assert!(!plan.state_expansions.is_empty());
        let values = evaluations(&plan, 0x51a7_1e55);

        let rejects = |mutate: fn(&mut ProgressiveCommitPlan)| {
            let mut malformed = plan.clone();
            mutate(&mut malformed);
            assert!(validate_progressive_plan(&malformed).is_err());
            assert!(progressive_leaf_oracle(&malformed, &values).is_err());
            assert!(full_lifting_leaf_oracle(&malformed, &values).is_err());
        };
        rejects(|plan| plan.leaf_blocks.clear());
        rejects(|plan| plan.state_expansions.clear());
        rejects(|plan| plan.accounting.total_nodes += 1);
        rejects(|plan| plan.geometry.log_blowup_factor = 0);
        rejects(|plan| plan.geometry.groups.clear());
        rejects(|plan| plan.columns.clear());
        rejects(|plan| plan.lde_batches[0].columns[0] = usize::MAX);
    }

    #[test]
    fn state_expansion_projection_and_accounting_are_exact() {
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[3; 16].into_iter().chain([5]).collect::<Vec<_>>(), 6),
        )
        .unwrap();
        assert_eq!(
            plan.state_expansions,
            vec![Blake2sStateExpansion {
                domain: StateExpansion {
                    from_log_size: 4,
                    to_log_size: 6,
                    states_before: 16,
                    states_after: 64,
                },
                absorbed_columns: 16,
                absorbed_bytes_per_state: 64,
                compressed_byte_counter: 0,
                pending_block_prefix_bytes: 64,
                device_state_stride_bytes: PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
                read_traffic_bytes: 64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
                write_traffic_bytes: 64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
                total_traffic_bytes: 128 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
            }]
        );
        for row in 0..64 {
            assert_eq!(lifted_column_index(row, 4, 6), (row >> 3 << 1) + (row & 1));
        }
        assert_eq!(plan.accounting.leaf_nodes, 64);
        assert_eq!(plan.accounting.interior_nodes, 63);
        assert_eq!(plan.accounting.total_nodes, 127);
        assert_eq!(plan.accounting.canonical_leaf_bytes, 64 * 17 * 4);
        assert_eq!(
            plan.accounting.progressive_absorbed_bytes,
            16 * 16 * 4 + 64 * 4
        );
        assert_eq!(plan.accounting.lde_output_words, 16 * 16 + 64);
        assert_eq!(plan.accounting.progressive_leaf_compressions, 64 + 64);
        assert_eq!(plan.accounting.full_lifting_leaf_compressions, 2 * 64);
        assert_eq!(plan.accounting.interior_compressions, 63);
        assert_eq!(plan.accounting.progressive_total_compressions, 191);
        assert_eq!(plan.accounting.full_lifting_total_compressions, 191);
        assert_eq!(
            plan.accounting.state_expansion_read_bytes,
            64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_ne!(
            plan.accounting.state_expansion_read_bytes,
            16 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
            "output-parallel expansion issues one parent load per destination"
        );
        assert_eq!(
            plan.accounting.state_expansion_write_bytes,
            64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.state_expansion_total_bytes,
            128 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.state_init_write_bytes,
            16 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.state_absorb_read_bytes,
            80 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.state_absorb_write_bytes,
            80 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.state_finalize_read_bytes,
            64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.state_total_traffic_bytes,
            368 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.legacy_state_total_traffic_bytes,
            368 * LEGACY_PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(plan.accounting.state_traffic_saved_bytes, 368 * 32);
        assert_eq!(
            plan.accounting.peak_progressive_state_bytes,
            80 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            plan.accounting.legacy_peak_progressive_state_bytes,
            80 * LEGACY_PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(plan.accounting.peak_state_saved_bytes, 80 * 32);
    }

    #[test]
    fn lazy_block_state_and_compressions_are_exact_at_16_and_32_columns() {
        let sixteen = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[3; 16], 6),
        )
        .unwrap();
        let expansion = sixteen.state_expansions[0];
        assert_eq!(expansion.absorbed_columns, 16);
        assert_eq!(expansion.absorbed_bytes_per_state, 64);
        assert_eq!(expansion.pending_block_prefix_bytes, 64);
        assert_eq!(expansion.compressed_byte_counter, 0);
        assert_eq!(sixteen.accounting.progressive_leaf_compressions, 64);
        assert_eq!(sixteen.accounting.full_lifting_leaf_compressions, 64);

        let thirty_two = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[3; 32], 6),
        )
        .unwrap();
        let expansion = thirty_two.state_expansions[0];
        assert_eq!(expansion.absorbed_columns, 32);
        assert_eq!(expansion.absorbed_bytes_per_state, 128);
        assert_eq!(expansion.pending_block_prefix_bytes, 64);
        assert_eq!(expansion.compressed_byte_counter, 64);
        assert_eq!(thirty_two.accounting.progressive_leaf_compressions, 16 + 64);
        assert_eq!(thirty_two.accounting.full_lifting_leaf_compressions, 2 * 64);
        assert_eq!(
            thirty_two.accounting.progressive_total_compressions,
            80 + 63
        );
        assert_eq!(
            thirty_two.accounting.full_lifting_total_compressions,
            128 + 63
        );
        assert_eq!(
            thirty_two.accounting.state_expansion_read_bytes,
            64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            thirty_two.accounting.state_expansion_write_bytes,
            64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
        assert_eq!(
            thirty_two.accounting.peak_progressive_state_bytes,
            80 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );

        let no_expansion = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[5; 3], 6),
        )
        .unwrap();
        assert!(no_expansion.state_expansions.is_empty());
        assert_eq!(
            no_expansion.accounting.peak_progressive_state_bytes,
            64 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES
        );
    }

    #[test]
    fn every_final_block_remainder_and_adjacent_log_rise_is_sealed() {
        for remainder in 1..=16 {
            let column_count = 16 + remainder;
            let plan = plan_progressive_commit(
                ProgressiveCommitMode::DomainProgressive,
                geometry(&vec![3; column_count], 6),
            )
            .unwrap();
            let final_block = plan.leaf_blocks.last().unwrap();
            assert_eq!(final_block.column_count, remainder);
            assert_eq!(final_block.byte_count, remainder * 4);
            let expansion = plan.state_expansions.last().unwrap();
            let expected_pending = if remainder == 16 { 64 } else { remainder * 4 };
            assert_eq!(expansion.pending_block_prefix_bytes, expected_pending);
            assert_eq!(
                expansion.compressed_byte_counter + expansion.pending_block_prefix_bytes,
                column_count * 4
            );
            let values = evaluations(&plan, remainder as u32 ^ 0xa5a5);
            let progressive = progressive_leaf_oracle(&plan, &values).unwrap();
            let full = full_lifting_leaf_oracle(&plan, &values).unwrap();
            assert_eq!(progressive, full, "final-block remainder {remainder}");
            assert_eq!(merkle_root(progressive), merkle_root(full));
        }

        let adjacent = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[3, 4], 6),
        )
        .unwrap();
        assert_eq!(adjacent.state_expansions.len(), 2);
        assert_eq!(adjacent.state_expansions[0].absorbed_columns, 1);
        assert_eq!(adjacent.state_expansions[0].pending_block_prefix_bytes, 4);
        assert_eq!(adjacent.state_expansions[1].absorbed_columns, 2);
        assert_eq!(adjacent.state_expansions[1].pending_block_prefix_bytes, 8);
    }

    #[test]
    fn launch_scalar_prefix_schedule_covers_empty_every_remainder_and_u32_max() {
        assert_eq!(blake2s_prefix_schedule(0).unwrap(), (0, 0, 0));
        for columns in 1usize..=64 {
            let (absorbed, compressed, pending) = blake2s_prefix_schedule(columns).unwrap();
            assert_eq!(absorbed, columns * FIELD_WORD_BYTES);
            assert_eq!(compressed + pending, absorbed);
            assert_eq!(pending, ((columns - 1) % 16 + 1) * FIELD_WORD_BYTES);
            assert_eq!(compressed % BLAKE2S_BLOCK_BYTES, 0);
        }
        let columns = u32::MAX as usize;
        let (absorbed, compressed, pending) = blake2s_prefix_schedule(columns).unwrap();
        assert_eq!(absorbed, columns * FIELD_WORD_BYTES);
        assert_eq!(pending, 15 * FIELD_WORD_BYTES);
        assert_eq!(compressed + pending, absorbed);
        assert_eq!(
            blake2s_prefix_schedule(usize::MAX),
            Err(ProgressiveCommitError::SizeOverflow)
        );
    }

    #[test]
    fn log_rises_around_lazy_block_boundaries_preserve_real_leaves_and_roots() {
        for absorbed_columns in [15usize, 16, 17, 31, 32, 33] {
            let logs = [vec![3; absorbed_columns], vec![4; 2]].concat();
            let plan = plan_progressive_commit(
                ProgressiveCommitMode::DomainProgressive,
                geometry(&logs, 6),
            )
            .unwrap();
            let rise = plan.state_expansions[0];
            let absorbed_bytes = absorbed_columns * FIELD_WORD_BYTES;
            let pending = (absorbed_bytes - 1) % BLAKE2S_BLOCK_BYTES + 1;
            assert_eq!(rise.absorbed_columns, absorbed_columns);
            assert_eq!(rise.absorbed_bytes_per_state, absorbed_bytes);
            assert_eq!(rise.pending_block_prefix_bytes, pending);
            assert_eq!(rise.compressed_byte_counter, absorbed_bytes - pending);

            let values = evaluations(&plan, absorbed_columns as u32 ^ 0x5a5a);
            let progressive = progressive_leaf_oracle(&plan, &values).unwrap();
            let full = full_lifting_leaf_oracle(&plan, &values).unwrap();
            assert_eq!(progressive, full, "rise after {absorbed_columns} columns");
            assert_eq!(merkle_root(progressive), merkle_root(full));
        }
    }

    #[test]
    fn cache_identity_covers_mode_geometry_and_retention() {
        let base = geometry(&[3, 4, 4], 6);
        let base_key = progressive_commit_cache_key(ProgressiveCommitMode::FullLifting, &base);
        assert_ne!(
            base_key,
            progressive_commit_cache_key(ProgressiveCommitMode::DomainProgressive, &base)
        );
        let mut changed = base.clone();
        changed.groups[0].coefficient_log_sizes[1] = 3;
        assert_ne!(
            base_key,
            progressive_commit_cache_key(ProgressiveCommitMode::FullLifting, &changed)
        );
        let mut retained = base.clone();
        retained.groups[0].retain_evaluations = true;
        assert_ne!(
            base_key,
            progressive_commit_cache_key(ProgressiveCommitMode::FullLifting, &retained)
        );
    }

    #[test]
    fn malformed_geometry_and_oracle_inputs_fail_closed() {
        assert!(matches!(
            plan_progressive_commit(
                ProgressiveCommitMode::DomainProgressive,
                geometry(&[4, 3], 6)
            ),
            Err(ProgressiveCommitError::NonCanonicalOrder { .. })
        ));
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            geometry(&[3, 4], 6),
        )
        .unwrap();
        assert_eq!(
            progressive_leaf_oracle(&plan, &[vec![0; 16]]),
            Err(ProgressiveCommitError::OracleColumnCountMismatch)
        );
        let mut wrong_length = evaluations(&plan, 9);
        wrong_length[1].pop();
        assert!(matches!(
            progressive_leaf_oracle(&plan, &wrong_length),
            Err(ProgressiveCommitError::OracleColumnLengthMismatch { column: 1, .. })
        ));

        let mut blowup_17 = geometry(&[3], 20);
        blowup_17.log_blowup_factor = 17;
        assert_eq!(
            plan_progressive_commit(ProgressiveCommitMode::DomainProgressive, blowup_17),
            Err(ProgressiveCommitError::InvalidBlowup(17))
        );
        assert_eq!(
            plan_progressive_commit(ProgressiveCommitMode::DomainProgressive, geometry(&[3], 31)),
            Err(ProgressiveCommitError::InvalidLiftingLogSize(31))
        );
        assert_eq!(
            plan_progressive_commit(
                ProgressiveCommitMode::DomainProgressive,
                ProgressiveCommitGeometry {
                    lifting_log_size: 6,
                    log_blowup_factor: 1,
                    groups: vec![ProgressiveCommitGroupGeometry {
                        coefficient_log_sizes: Vec::new(),
                        retain_evaluations: false,
                    }],
                }
            ),
            Err(ProgressiveCommitError::EmptyGroup(0))
        );
        assert_eq!(
            plan_progressive_commit(ProgressiveCommitMode::DomainProgressive, geometry(&[5], 5)),
            Err(ProgressiveCommitError::EvaluationExceedsLifting {
                evaluation_log_size: 6,
                lifting_log_size: 5,
            })
        );
    }
}
