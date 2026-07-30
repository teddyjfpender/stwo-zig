use std::collections::BTreeMap;

use hashbrown::HashMap;
use itertools::Itertools;
use tracing::{span, Level};

use super::ops::MerkleOpsLifted;
use crate::core::fields::m31::BaseField;
use crate::core::fields::qm31::SECURE_EXTENSION_DEGREE;
use crate::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use crate::core::vcs_lifted::verifier::{
    ExtendedMerkleDecommitmentLifted, MerkleDecommitmentLifted, MerkleDecommitmentLiftedAux,
};
use crate::core::ColumnVec;
use crate::prover::backend::{Col, Column};

/// Represents the prover side of a Merkle commitment scheme.
#[derive(Debug)]
pub struct MerkleProverLifted<B: MerkleOpsLifted<H>, H: MerkleHasherLifted> {
    /// Layers of the Merkle tree, sorted by increasing length.
    /// The first layer is a column of length 1, containing the root commitment.
    ///
    /// Trees built with [`Self::commit_pruned`] do not retain the bottom
    /// [`MerkleOpsLifted::merkle_prune_depth`] layers; those nodes are recomputed from the
    /// committed columns during decommit.
    pub layers: Vec<Col<B, H::Hash>>,
    /// Log size of the leaf layer (i.e. the height of the tree).
    leaf_log_size: u32,
}

impl<B: MerkleOpsLifted<H>, H: MerkleHasherLifted> MerkleProverLifted<B, H> {
    /// Returns the log size of the leaf layer of the tree.
    pub const fn log_size(&self) -> u32 {
        self.leaf_log_size
    }
    /// Commits to columns.
    /// Columns must be of power of 2 sizes, not necessarily sorted by length.
    ///
    /// # Arguments
    ///
    /// * `columns` - A vector of references to columns.
    ///
    /// # Returns
    ///
    /// A new instance of `MerkleProverLifted` with the committed layers.
    pub fn commit(
        columns: Vec<&Col<B, BaseField>>,
        lifting_log_size: u32,
        log_rows_per_leaf: u32,
    ) -> Self {
        Self::commit_inner(columns, lifting_log_size, log_rows_per_leaf, 0)
    }

    /// Same as [`Self::commit`], but does not retain the bottom
    /// [`MerkleOpsLifted::merkle_prune_depth`] layers of the tree. The unretained nodes are
    /// recomputed from the committed columns at decommit time, so callers must pass the same
    /// columns to [`Self::decommit`]. Backends choose the memory/recomputation tradeoff; the
    /// default omits four layers.
    ///
    /// Not supported for packed leaves (`log_rows_per_leaf > 0`), where decommit does not
    /// receive the packed columns.
    pub fn commit_pruned(columns: Vec<&Col<B, BaseField>>, lifting_log_size: u32) -> Self {
        let prune_depth = B::merkle_prune_depth();
        assert!(prune_depth > 0, "Merkle prune depth must be at least one.");
        Self::commit_inner(columns, lifting_log_size, 0, prune_depth)
    }

    fn commit_inner(
        columns: Vec<&Col<B, BaseField>>,
        lifting_log_size: u32,
        log_rows_per_leaf: u32,
        n_unretained_layers: u32,
    ) -> Self {
        // Pruned trees recompute leaf hashes from the committed columns at decommit time;
        // the packed-leaves path does not pass its (packed) columns to decommit, so the two
        // must not be combined.
        assert!(
            log_rows_per_leaf == 0 || n_unretained_layers == 0,
            "Layer pruning is not supported for packed leaves."
        );
        let _span = span!(Level::TRACE, "Merkle", class = "MerkleCommitment").entered();
        if columns.is_empty() {
            return Self {
                layers: vec![B::build_leaves(&[], lifting_log_size)],
                leaf_log_size: 0,
            };
        }

        // We enter this branch only during FRI commit phase, in which we commit 4 columns of the
        // same size. In particular, we don't need to sort the columns by size.
        let leaves = if log_rows_per_leaf > 0 {
            // TODO(Leo): add support for higher log_rows_per_leaf sizes.
            assert_eq!(
                log_rows_per_leaf, 2,
                "Leaf packing is only supported for log_rows_per_leaf = 2."
            );
            let columns: [&Col<B, BaseField>; SECURE_EXTENSION_DEGREE] =
                columns.try_into().unwrap();
            let packed_columns = B::pack_leaves_input(&columns);
            let max_log_size = packed_columns[0].len().ilog2();
            assert!(lifting_log_size >= max_log_size);
            B::build_leaves(&packed_columns.iter().collect_vec(), lifting_log_size)
        } else {
            let sorted_columns = columns.into_iter().sorted_by_key(|c| c.len()).collect_vec();
            let max_log_size = sorted_columns.last().unwrap().len().ilog2();
            assert!(lifting_log_size >= max_log_size);
            B::build_leaves(&sorted_columns, lifting_log_size)
        };

        Self::tree_from_leaves(leaves, lifting_log_size, n_unretained_layers)
    }

    /// Builds the interior tree above a pre-computed leaf layer (parent-of-leaves
    /// up to the root), pruning the bottom `n_unretained_layers`. Extracted from
    /// [`Self::commit_inner`] so the streamed-leaf commit path (which produces the
    /// leaf layer one column-group at a time to bound VRAM) can share the exact
    /// same interior construction — byte-identical tree either way.
    fn tree_from_leaves(
        leaves: Col<B, H::Hash>,
        lifting_log_size: u32,
        n_unretained_layers: u32,
    ) -> Self {
        // Build the layers from the leaves up, dropping unretained bottom layers eagerly to
        // also reduce the transient memory of the commitment itself.
        let min_retained_log_size = lifting_log_size.saturating_sub(n_unretained_layers);
        // Commit fusion: once every remaining level is retained AND the
        // subtree fits one block, hand the rest to the backend in one
        // `build_top_layers` call (default = the same per-level loop; the CUDA
        // override fuses ~TAIL_LEVELS launches into one). Scheduling only —
        // identical layer contents either way.
        const TAIL_LEVELS: u32 = 12;
        let mut layers_top_down: Vec<Col<B, H::Hash>> = Vec::new();
        let mut current = Some(leaves);
        for log_size in (0..lifting_log_size).rev() {
            let cur = current.take().unwrap();
            // `cur` has log size `log_size + 1`.
            let cur_log = log_size + 1;
            if cur_log <= TAIL_LEVELS && cur_log <= min_retained_log_size {
                let tail = B::build_top_layers(&cur, cur_log);
                layers_top_down.push(cur);
                layers_top_down.extend(tail);
                break;
            }
            let next = B::build_next_layer(&cur);
            if log_size < min_retained_log_size {
                layers_top_down.push(cur);
            }
            current = Some(next);
        }
        // The root (log size 0) is always retained; when the fused tail ran it
        // is already the last pushed layer.
        if let Some(cur) = current {
            layers_top_down.push(cur);
        }
        layers_top_down.reverse();

        Self {
            layers: layers_top_down,
            leaf_log_size: lifting_log_size,
        }
    }

    /// Streamed-leaf pruned commit (VRAM diet): identical to [`Self::commit_pruned`]
    /// but the caller supplies the already-computed lifted leaf layer (built one
    /// column-group at a time from coefficients, so all columns' LDE is never
    /// resident at once). The interior + pruning are byte-identical to
    /// `commit_pruned`; the leaf layer must equal what `build_leaves` would produce
    /// for the same (sorted) columns (gated by the backend's streaming tests +
    /// whole-proof byte-identity).
    pub fn commit_pruned_from_leaves(leaves: Col<B, H::Hash>, lifting_log_size: u32) -> Self {
        let prune_depth = B::merkle_prune_depth();
        assert!(prune_depth > 0, "Merkle prune depth must be at least one.");
        Self::tree_from_leaves(leaves, lifting_log_size, prune_depth)
    }

    /// Decommits to columns on the given queries.
    /// Queries are given as indices to the largest column.
    ///
    /// # Arguments
    ///
    /// * `queries_position` - Vector containing the positions of the queries, in increasing order.
    /// * `columns` - A vector of references to columns.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A vector of queried values. For each query position, the queried values are column values
    ///   corresponding to the query position, sorted increasingly by column length.
    /// * A `MerkleDecommitment` containing the hash witness.
    pub fn decommit(
        &self,
        query_positions: &[usize],
        columns: Vec<&Col<B, BaseField>>,
    ) -> (
        ColumnVec<Vec<BaseField>>,
        ExtendedMerkleDecommitmentLifted<H>,
    ) {
        // Materialize the sparse read set once, before the host Merkle walk. On
        // device backends this is one batched gather for the whole tree instead of
        // `queries x columns` scalar PCIe reads. Include every leaf needed to
        // reconstruct pruned bottom layers, so the sparse view is a complete drop-in
        // replacement for dense column access.
        let row_indices = self.decommit_column_rows(query_positions, &columns);
        let values = B::batch_gather_column_rows(&columns, &row_indices);
        let rows = row_indices
            .into_iter()
            .zip(values)
            .map(|(indices, values)| indices.into_iter().zip(values).collect())
            .collect();
        let gathered = GatheredColumns {
            log_sizes: columns.iter().map(|column| column.len().ilog2()).collect(),
            rows,
        };
        self.decommit_inner(query_positions, &gathered)
    }

    /// Same as [`Self::decommit`], but reads column values from a sparse, row-gathered view
    /// instead of the full columns. The view must contain every queried row and, for trees
    /// committed with [`Self::commit_pruned`], every row of the leaves returned by
    /// [`Self::unretained_leaf_indices`] (mapped per column).
    pub fn decommit_gathered(
        &self,
        query_positions: &[usize],
        gathered: &GatheredColumns,
    ) -> (
        ColumnVec<Vec<BaseField>>,
        ExtendedMerkleDecommitmentLifted<H>,
    ) {
        self.decommit_inner(query_positions, gathered)
    }

    fn decommit_inner(
        &self,
        query_positions: &[usize],
        columns: &impl ColumnAccess,
    ) -> (
        ColumnVec<Vec<BaseField>>,
        ExtendedMerkleDecommitmentLifted<H>,
    ) {
        // Prepare output buffers.
        let mut queried_values: ColumnVec<Vec<BaseField>> = vec![];
        let mut decommitment = MerkleDecommitmentLifted::<H>::default();
        let mut all_node_values: Vec<BTreeMap<usize, <H as MerkleHasherLifted>::Hash>> = vec![];

        // Compute the queried values.
        let max_log_size = self.leaf_log_size as usize;
        for col in 0..columns.n_columns() {
            let log_size = columns.column_log_size(col) as usize;
            let shift = max_log_size - log_size;
            let res: Vec<_> = query_positions
                .iter()
                .map(|pos| columns.value(col, (pos >> (shift + 1) << 1) + (pos & 1)))
                .collect();
            queried_values.push(res);
        }

        // Used to recompute nodes of unretained bottom layers (trees committed with
        // `commit_pruned`). Sorted by length exactly like in `commit_inner`. Skipped for
        // fully-retained trees (e.g. the FRI layer trees), where every node is read from a
        // stored layer.
        let is_pruned = self.layers.len() <= self.leaf_log_size as usize;
        let sorted_columns = if is_pruned {
            (0..columns.n_columns())
                .sorted_by_key(|&col| columns.column_log_size(col))
                .collect_vec()
        } else {
            vec![]
        };
        let mut node_memo = HashMap::<(usize, usize), H::Hash>::new();

        // Collect every retained-layer node the walk below will read (the mirror
        // is `retained_node_reads`, same idiom as `unretained_leaf_indices`) and
        // fetch it through the backend batch contract. This is no longer migration
        // flag scaffolding: the default implementation is exactly the old scalar
        // reads, while a resident backend turns the whole set into one gather and
        // one D2H transfer. Values remain exactly `layers[level].at(idx)`.
        let pairs = self.retained_node_reads(query_positions);
        let layer_refs: Vec<&Col<B, H::Hash>> = self.layers.iter().collect();
        let values = B::batch_layer_reads(&layer_refs, &pairs);
        let prefetch: HashMap<(usize, usize), H::Hash> = pairs
            .iter()
            .map(|&(l, i)| (l as usize, i as usize))
            .zip(values)
            .collect();

        let mut prev_layer_queries = query_positions.to_vec();
        prev_layer_queries.dedup();
        // We start iterating from the layer of log size `self.leaf_log_size - 1`, reading the
        // hashes of the previous (one larger) layer.
        for layer_log_size in (0..self.leaf_log_size as usize).rev() {
            let mut all_node_values_for_layer =
                BTreeMap::<usize, <H as MerkleHasherLifted>::Hash>::new();
            // Prepare write buffer for queries to the current layer. This will propagate to the
            // next layer.
            let mut curr_layer_queries: Vec<usize> = vec![];

            // Each layer node is a hash of column values as previous layer hashes.
            let prev_level = layer_log_size + 1;
            // All chunks have either length 1 (only one child is present) or 2 (both children are
            // present).
            for queries_chunk in prev_layer_queries.as_slice().chunk_by(|a, b| a ^ 1 == *b) {
                let first = queries_chunk[0];
                // If the brother of `first` was not queried before, add its hash to the witness.
                if queries_chunk.len() == 1 {
                    decommitment.hash_witness.push(self.node_hash(
                        columns,
                        &sorted_columns,
                        &mut node_memo,
                        &prefetch,
                        prev_level,
                        first ^ 1,
                    ))
                }
                let curr_index = first >> 1;
                curr_layer_queries.push(curr_index);

                // Add the previous layer hashes to all_node_values.
                all_node_values_for_layer.insert(
                    2 * curr_index,
                    self.node_hash(
                        columns,
                        &sorted_columns,
                        &mut node_memo,
                        &prefetch,
                        prev_level,
                        2 * curr_index,
                    ),
                );
                all_node_values_for_layer.insert(
                    2 * curr_index + 1,
                    self.node_hash(
                        columns,
                        &sorted_columns,
                        &mut node_memo,
                        &prefetch,
                        prev_level,
                        2 * curr_index + 1,
                    ),
                );
            }
            // Propagate queries to the next layer.
            prev_layer_queries = curr_layer_queries;

            all_node_values.push(all_node_values_for_layer);
        }
        (
            queried_values,
            ExtendedMerkleDecommitmentLifted {
                decommitment,
                aux: MerkleDecommitmentLiftedAux { all_node_values },
            },
        )
    }

    /// Returns the hash of the tree node at the layer of log size `level`, index `idx`.
    ///
    /// Retained layers are read directly; nodes of unretained bottom layers are recomputed from
    /// the committed columns (and memoized, as decommit paths of nearby queries share subtrees).
    #[allow(clippy::too_many_arguments)]
    fn node_hash(
        &self,
        columns: &impl ColumnAccess,
        sorted_columns: &[usize],
        memo: &mut HashMap<(usize, usize), H::Hash>,
        prefetch: &HashMap<(usize, usize), H::Hash>,
        level: usize,
        idx: usize,
    ) -> H::Hash {
        if let Some(layer) = self.layers.get(level) {
            if let Some(hash) = prefetch.get(&(level, idx)) {
                return *hash;
            }
            return layer.at(idx);
        }
        if let Some(hash) = memo.get(&(level, idx)) {
            return *hash;
        }
        let hash = if level == self.leaf_log_size as usize {
            leaf_hash::<H>(columns, sorted_columns, self.leaf_log_size, idx)
        } else {
            H::hash_children((
                self.node_hash(columns, sorted_columns, memo, prefetch, level + 1, 2 * idx),
                self.node_hash(
                    columns,
                    sorted_columns,
                    memo,
                    prefetch,
                    level + 1,
                    2 * idx + 1,
                ),
            ))
        };
        memo.insert((level, idx), hash);
        hash
    }

    /// The retained-layer read set of [`Self::decommit`]'s walk for these queries:
    /// every `(level, idx)` that `node_hash` will read DIRECTLY from a stored layer
    /// (witness reads `first ^ 1` plus the two aux reads per chunk, at levels the
    /// tree retains; recursion below unretained levels never touches stored layers
    /// — pruning is bottom-up, so everything under an unretained level is also
    /// unretained). MUST mirror the walk's index arithmetic exactly — same rule as
    /// [`Self::unretained_leaf_indices`]. A drifted mirror is safe (missed pairs
    /// fall back to per-element reads), just slower.
    fn retained_node_reads(&self, query_positions: &[usize]) -> Vec<(u32, u32)> {
        let mut pairs = Vec::new();
        let mut prev_layer_queries = query_positions.to_vec();
        prev_layer_queries.dedup();
        for layer_log_size in (0..self.leaf_log_size as usize).rev() {
            let prev_level = layer_log_size + 1;
            let retained = self.layers.get(prev_level).is_some();
            let mut curr_layer_queries: Vec<usize> = vec![];
            for queries_chunk in prev_layer_queries.as_slice().chunk_by(|a, b| a ^ 1 == *b) {
                let first = queries_chunk[0];
                let curr_index = first >> 1;
                curr_layer_queries.push(curr_index);
                if retained {
                    if queries_chunk.len() == 1 {
                        pairs.push((prev_level as u32, (first ^ 1) as u32));
                    }
                    pairs.push((prev_level as u32, (2 * curr_index) as u32));
                    pairs.push((prev_level as u32, (2 * curr_index + 1) as u32));
                }
            }
            prev_layer_queries = curr_layer_queries;
        }
        pairs
    }

    /// Returns the (sorted, deduplicated) leaf indices covered by tree nodes that
    /// [`Self::decommit`] will need to recompute for the given queries — i.e. the nodes it
    /// reads from unretained bottom layers. Empty for fully-retained trees.
    ///
    /// Mirrors the index arithmetic of the decommit walk.
    pub fn unretained_leaf_indices(&self, query_positions: &[usize]) -> Vec<usize> {
        let leaf_log_size = self.leaf_log_size as usize;
        let mut needed = std::collections::BTreeSet::new();

        let mut prev_layer_queries = query_positions.to_vec();
        prev_layer_queries.dedup();
        for layer_log_size in (0..leaf_log_size).rev() {
            let prev_level = layer_log_size + 1;
            let prev_level_unretained = self.layers.get(prev_level).is_none();
            // Log of the number of leaves under one node of `prev_level`.
            let span_log = leaf_log_size - prev_level;
            let mut curr_layer_queries: Vec<usize> = vec![];

            for queries_chunk in prev_layer_queries.as_slice().chunk_by(|a, b| a ^ 1 == *b) {
                let curr_index = queries_chunk[0] >> 1;
                curr_layer_queries.push(curr_index);
                if prev_level_unretained {
                    // The walk reads nodes `first ^ 1` (witness), `2 * curr_index` and
                    // `2 * curr_index + 1` (aux) — together exactly this pair of nodes.
                    for node in [2 * curr_index, 2 * curr_index + 1] {
                        needed.extend((node << span_log)..((node + 1) << span_log));
                    }
                }
            }
            prev_layer_queries = curr_layer_queries;
        }
        needed.into_iter().collect()
    }

    /// Exact per-column sparse read set required by [`Self::decommit`]. Query
    /// positions and unretained leaf positions live in the lifted leaf domain;
    /// map both through the same two-coset lifting rule used by `decommit_inner`
    /// and `leaf_hash`, then sort and deduplicate for deterministic descriptors.
    fn decommit_column_rows(
        &self,
        query_positions: &[usize],
        columns: &[&Col<B, BaseField>],
    ) -> Vec<Vec<usize>> {
        let leaf_rows = self.unretained_leaf_indices(query_positions);
        columns
            .iter()
            .map(|column| {
                let log_size = column.len().ilog2();
                let shift = self.leaf_log_size - log_size;
                let map_row = |position: &usize| (position >> (shift + 1) << 1) + (position & 1);
                let mut rows: Vec<_> = query_positions
                    .iter()
                    .chain(&leaf_rows)
                    .map(map_row)
                    .collect();
                rows.sort_unstable();
                rows.dedup();
                rows
            })
            .collect()
    }

    pub fn root(&self) -> H::Hash {
        self.layers.first().unwrap().at(0)
    }
}

/// Read access to the committed column values of a tree during decommit, in commit order.
trait ColumnAccess {
    fn n_columns(&self) -> usize;
    fn column_log_size(&self, col: usize) -> u32;
    /// The canonical field value at `row`; used for the queried values returned to the
    /// verifier.
    fn value(&self, col: usize, row: usize) -> BaseField;
    /// The raw stored representation at `row` (possibly the unreduced value `P`); used when
    /// recomputing leaf hashes, which must reproduce the exact bytes that
    /// [`MerkleOpsLifted::build_leaves`] committed.
    fn raw_value(&self, col: usize, row: usize) -> BaseField;
}

/// A sparse, row-gathered view of a tree's committed columns, sufficient for decommitting a
/// given set of queries. Used by the low-memory mode, which does not retain the full column
/// evaluations between commitment and decommitment.
pub struct GatheredColumns {
    /// Per column, in commit order: the column's log size.
    pub log_sizes: Vec<u32>,
    /// Per column, in commit order: the (row -> raw stored value) entries needed for the
    /// decommit. Values are gathered with [`Column::at_unreduced`].
    pub rows: Vec<HashMap<usize, BaseField>>,
}

impl ColumnAccess for GatheredColumns {
    fn n_columns(&self) -> usize {
        self.log_sizes.len()
    }
    fn column_log_size(&self, col: usize) -> u32 {
        self.log_sizes[col]
    }
    fn value(&self, col: usize, row: usize) -> BaseField {
        // The gathered entries hold raw representations; canonicalize like `Column::at` does.
        BaseField::reduce(self.rows[col][&row].0 as u64)
    }
    fn raw_value(&self, col: usize, row: usize) -> BaseField {
        self.rows[col][&row]
    }
}

/// Computes the hash of the single leaf at index `idx` from the committed columns.
///
/// Replicates the leaf stream of [`MerkleOpsLifted::build_leaves`]: columns are processed in
/// ascending size order, in chunks of 16 values per equal-size group, reading each column at
/// its lift-mapped index.
fn leaf_hash<H: MerkleHasherLifted>(
    columns: &impl ColumnAccess,
    sorted_columns: &[usize],
    lifting_log_size: u32,
    idx: usize,
) -> H::Hash {
    let mut hasher = H::default();
    for (log_size, group) in &sorted_columns
        .iter()
        .group_by(|&&col| columns.column_log_size(col))
    {
        let shift = lifting_log_size - log_size;
        let group_idx = (idx >> (shift + 1) << 1) + (idx & 1);
        let group = group.collect_vec();
        for chunk in group.chunks(16) {
            // Hash the raw stored representations: the leaf hash must reproduce the exact
            // bytes `build_leaves` committed, which are not canonicalized.
            hasher.update_leaf(
                &chunk
                    .iter()
                    .map(|&&col| columns.raw_value(col, group_idx))
                    .collect_vec(),
            );
        }
    }
    hasher.finalize()
}

#[cfg(test)]
mod test {
    use num_traits::Zero;

    use super::*;
    use crate::core::fields::m31::M31;
    use crate::core::poly::circle::CanonicCoset;
    use crate::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher};
    use crate::core::vcs::blake2_merkle::Blake2sMerkleHasher as Blake2sMerkleHasherCurrent;
    use crate::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
    use crate::core::vcs_lifted::test_utils::lift_poly;
    use crate::prover::backend::cpu::CpuCirclePoly;
    use crate::prover::backend::CpuBackend;
    use crate::prover::vcs::prover::MerkleProver;

    #[test]
    fn test_empty_cols() {
        // Check Merkle commitment on empty columns.
        let mixed_degree_merkle_prover =
            MerkleProver::<CpuBackend, Blake2sMerkleHasherCurrent>::commit(vec![]);
        let lifted_merkle_prover =
            MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(vec![], 0, 0);
        assert_eq!(
            mixed_degree_merkle_prover.layers,
            lifted_merkle_prover.layers
        );
    }

    fn prepare_merkle() -> (
        Vec<Vec<BaseField>>,
        MerkleProverLifted<CpuBackend, Blake2sHasher>,
    ) {
        let max_log_size = 4;
        let columns: Vec<Vec<BaseField>> = (2..=max_log_size)
            .map(|i| (0..1 << i).map(M31::from_u32_unchecked).collect())
            .collect();
        let merkle_prover = MerkleProverLifted::<CpuBackend, Blake2sHasher>::commit(
            columns.iter().collect(),
            max_log_size,
            0,
        );
        (columns, merkle_prover)
    }

    #[test]
    fn test_lifted_merkle_leaves() {
        let (_, merkle_prover) = prepare_merkle();
        let leaves = &merkle_prover.layers.last().unwrap();

        // Compute the expected first leaf.
        let mut hasher = Blake2sHasher::default();
        let data = [0u8; 12];
        hasher.update(&data);
        assert_eq!(hasher.finalize(), leaves[0]);

        // Compute the expected fifth leaf.
        let mut hasher = Blake2sHasher::default();
        let mut data = Vec::new();
        data.extend(0_u32.to_le_bytes());
        data.extend(2_u32.to_le_bytes());
        data.extend(4_u32.to_le_bytes());
        hasher.update(&data);
        assert_eq!(hasher.finalize(), leaves[4]);

        // Compute the expected last leaf.
        let mut hasher = Blake2sHasher::default();
        let mut data = Vec::new();
        data.extend(3_u32.to_le_bytes());
        data.extend(7_u32.to_le_bytes());
        data.extend(15_u32.to_le_bytes());
        hasher.update(&data);

        assert_eq!(hasher.finalize(), *leaves.last().unwrap());
    }

    #[test]
    fn test_lifted_decommitted_values() {
        let (cols, merkle_prover) = prepare_merkle();
        // Test decommits at position 0.
        let queried_values = merkle_prover.decommit(&[0], cols.iter().collect_vec()).0;

        let expected_values = vec![vec![BaseField::zero()]; 3];
        assert_eq!(expected_values, queried_values);

        // Test decommits at position 4.
        let queried_values = merkle_prover.decommit(&[4], cols.iter().collect_vec()).0;
        let expected_values = vec![
            vec![BaseField::from_u32_unchecked(0)],
            vec![BaseField::from_u32_unchecked(2)],
            vec![BaseField::from_u32_unchecked(4)],
        ];
        assert_eq!(expected_values, queried_values);

        // Test decommits at position 15.
        let queried_values = merkle_prover.decommit(&[15], cols.iter().collect_vec()).0;
        let expected_values = vec![
            vec![BaseField::from_u32_unchecked(3)],
            vec![BaseField::from_u32_unchecked(7)],
            vec![BaseField::from_u32_unchecked(15)],
        ];
        assert_eq!(expected_values, queried_values);
    }

    /// See the docs of `[crate::prover::backend::cpu::blake2s_lifted::build_leaves]`.
    #[test]
    fn test_bit_reverse_lifted_merkle_cpu() {
        const LOG_SIZE: u32 = 3;
        const LIFTED_LOG_SIZE: u32 = 9;
        let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
        let poly = CpuCirclePoly::new((0..1 << LOG_SIZE).map(BaseField::from).collect());
        let lifted_evaluation = lift_poly(&poly, LIFTED_LOG_SIZE);

        let last_column: Col<CpuBackend, BaseField> =
            (0..1 << LIFTED_LOG_SIZE).map(|_| M31::zero()).collect_vec();

        let mixed_degree_merkle_prover =
            MerkleProver::<CpuBackend, Blake2sMerkleHasherCurrent>::commit(vec![
                &lifted_evaluation.values,
                &last_column,
            ]);
        let lifted_merkle_prover_1 = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
            vec![&lifted_evaluation.values, &last_column],
            LIFTED_LOG_SIZE,
            0,
        );
        let lifted_merkle_prover_2 = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
            vec![&poly.evaluate(domain), &last_column],
            LIFTED_LOG_SIZE,
            0,
        );

        assert_eq!(lifted_merkle_prover_1.root(), lifted_merkle_prover_2.root());
        assert_eq!(
            mixed_degree_merkle_prover.root(),
            lifted_merkle_prover_1.root()
        );
    }

    /// A pruned tree must produce the exact same root, queried values, hash witness and aux
    /// node values as a fully-retained tree.
    #[test]
    fn test_pruned_commit_decommit_equivalence() {
        let max_log_size: u32 = 7;
        // Lift beyond the largest column to also exercise the trailing lift.
        let lifting_log_size = max_log_size + 1;
        let columns: Vec<Vec<BaseField>> = (2..=max_log_size)
            .map(|i| {
                (0..1u32 << i)
                    .map(|j| M31::from_u32_unchecked(j * i + 1))
                    .collect()
            })
            .collect();

        let full = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
            columns.iter().collect(),
            lifting_log_size,
            0,
        );
        let pruned = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit_pruned(
            columns.iter().collect(),
            lifting_log_size,
        );
        let depth_one = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit_inner(
            columns.iter().collect(),
            lifting_log_size,
            0,
            1,
        );

        assert_eq!(
            <CpuBackend as MerkleOpsLifted<Blake2sMerkleHasher>>::merkle_prune_depth(),
            4
        );
        assert_eq!(full.root(), pruned.root());
        assert_eq!(full.root(), depth_one.root());
        assert_eq!(full.log_size(), pruned.log_size());
        assert_eq!(full.layers.len() - pruned.layers.len(), 4);
        assert_eq!(full.layers.len() - depth_one.layers.len(), 1);

        let queries: Vec<usize> = vec![0, 5, 6, 7, 100, 201, 255];
        let (values_full, dec_full) = full.decommit(&queries, columns.iter().collect_vec());
        let (values_pruned, dec_pruned) = pruned.decommit(&queries, columns.iter().collect_vec());
        let (values_depth_one, dec_depth_one) =
            depth_one.decommit(&queries, columns.iter().collect_vec());

        assert_eq!(values_full, values_pruned);
        assert_eq!(values_full, values_depth_one);
        assert_eq!(
            dec_full.decommitment.hash_witness,
            dec_pruned.decommitment.hash_witness
        );
        assert_eq!(
            dec_full.decommitment.hash_witness,
            dec_depth_one.decommitment.hash_witness
        );
        assert_eq!(dec_full.aux.all_node_values, dec_pruned.aux.all_node_values);
        assert_eq!(
            dec_full.aux.all_node_values,
            dec_depth_one.aux.all_node_values
        );
    }

    /// Decommitting from a sparse row-gathered view (queried rows + the rows of unretained
    /// leaves) must produce exactly the same output as decommitting from the full columns.
    #[test]
    fn test_gathered_decommit_equivalence() {
        let max_log_size: u32 = 7;
        let lifting_log_size = max_log_size + 1;
        let columns: Vec<Vec<BaseField>> = (2..=max_log_size)
            .map(|i| {
                (0..1u32 << i)
                    .map(|j| M31::from_u32_unchecked(j * i + 3))
                    .collect()
            })
            .collect();

        let pruned = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit_pruned(
            columns.iter().collect(),
            lifting_log_size,
        );

        let queries: Vec<usize> = vec![1, 2, 3, 77, 140, 254];
        let (values_dense, dec_dense) = pruned.decommit(&queries, columns.iter().collect_vec());

        // Gather exactly the rows the decommit needs: the queried rows and the rows of the
        // unretained leaves, mapped per column.
        let leaf_indices = pruned.unretained_leaf_indices(&queries);
        let log_sizes = columns.iter().map(|c| c.len().ilog2()).collect_vec();
        let rows = columns
            .iter()
            .map(|col| {
                let shift = lifting_log_size - col.len().ilog2();
                let mut gathered = HashMap::new();
                for pos in queries.iter().chain(leaf_indices.iter()) {
                    let row = (pos >> (shift + 1) << 1) + (pos & 1);
                    gathered.insert(row, col[row]);
                }
                gathered
            })
            .collect_vec();
        let gathered = GatheredColumns { log_sizes, rows };

        let (values_gathered, dec_gathered) = pruned.decommit_gathered(&queries, &gathered);

        assert_eq!(values_dense, values_gathered);
        assert_eq!(
            dec_dense.decommitment.hash_witness,
            dec_gathered.decommitment.hash_witness
        );
        assert_eq!(
            dec_dense.aux.all_node_values,
            dec_gathered.aux.all_node_values
        );
    }

    #[test]
    fn test_decommitment_aux() {
        let (columns, merkle_prover) = prepare_merkle();
        let (
            _,
            ExtendedMerkleDecommitmentLifted {
                decommitment: _,
                aux,
            },
        ) = merkle_prover.decommit(&[1], columns.iter().collect_vec());

        let mut expected: Vec<BTreeMap<usize, Blake2sHash>> = vec![];
        merkle_prover
            .layers
            .iter()
            .skip(1)
            .rev()
            .for_each(|layer| expected.push(BTreeMap::from_iter([(0, layer[0]), (1, layer[1])])));
        assert_eq!(expected, aux.all_node_values);
    }
}
