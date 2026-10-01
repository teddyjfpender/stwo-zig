use std::collections::BTreeMap;

use stwo::core::fields::m31::M31;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher as VcsMerkleHasher;
use stwo::core::vcs::verifier::{MerkleDecommitment, MerkleVerificationError, MerkleVerifier};
use stwo::core::vcs::MerkleHasher;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher as LiftedMerkleHasher;
use stwo::core::vcs_lifted::verifier::{
    MerkleDecommitmentLifted, MerkleVerificationError as MerkleVerificationErrorLifted,
    MerkleVerifierLifted,
};
use stwo::core::vcs_lifted::MerkleHasherLifted;

use crate::common::*;
use crate::model::*;

#[derive(Clone)]
struct VcsBaseCase {
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    columns: Vec<Vec<M31>>,
    queries_per_log_size: BTreeMap<u32, Vec<usize>>,
    queried_values: Vec<M31>,
    decommitment: MerkleDecommitment<VcsMerkleHasher>,
}

#[derive(Clone)]
struct VcsLiftedBaseCase {
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    columns: Vec<Vec<M31>>,
    query_positions: Vec<usize>,
    queried_values: Vec<Vec<M31>>,
    decommitment: MerkleDecommitmentLifted<LiftedMerkleHasher>,
}

pub(crate) fn generate_vcs_verifier_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<VcsVerifierVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut cases = build_vcs_verifier_cases(state);
        if cases.is_empty() {
            continue;
        }
        let remaining = count - out.len();
        if cases.len() > remaining {
            cases.truncate(remaining);
        }
        out.extend(cases);
    }
    out
}

pub(crate) fn generate_vcs_prover_vectors(state: &mut u64, count: usize) -> Vec<VcsProverVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let Some(base) = build_vcs_base_case(state) else {
            continue;
        };
        out.push(VcsProverVector {
            root: encode_hash(base.root),
            column_log_sizes: base.column_log_sizes.clone(),
            columns: base
                .columns
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
            queries_per_log_size: base
                .queries_per_log_size
                .iter()
                .map(|(log_size, queries)| VcsLogSizeQueriesVector {
                    log_size: *log_size,
                    queries: queries.clone(),
                })
                .collect(),
            queried_values: base.queried_values.into_iter().map(encode_m31).collect(),
            hash_witness: base
                .decommitment
                .hash_witness
                .into_iter()
                .map(encode_hash)
                .collect(),
            column_witness: base
                .decommitment
                .column_witness
                .into_iter()
                .map(encode_m31)
                .collect(),
        });
    }
    out
}

pub(crate) fn generate_vcs_lifted_verifier_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<VcsLiftedVerifierVector> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let mut cases = build_vcs_lifted_verifier_cases(state);
        if cases.is_empty() {
            continue;
        }
        let remaining = count - out.len();
        if cases.len() > remaining {
            cases.truncate(remaining);
        }
        out.extend(cases);
    }
    out
}

fn build_vcs_lifted_verifier_cases(state: &mut u64) -> Vec<VcsLiftedVerifierVector> {
    let Some(base) = build_vcs_lifted_base_case(state) else {
        return vec![];
    };

    let root = base.root;
    let column_log_sizes = base.column_log_sizes.clone();
    let query_positions = base.query_positions.clone();
    let queried_values = base.queried_values.clone();
    let base_decommitment = base.decommitment.clone();

    let mut out = Vec::<VcsLiftedVerifierVector>::new();
    let mut push_case =
        |case: &str,
         case_root: Blake2sHash,
         case_queried_values: Vec<Vec<M31>>,
         case_decommitment: MerkleDecommitmentLifted<LiftedMerkleHasher>| {
            let expected = run_vcs_lifted_verifier(
                case_root,
                column_log_sizes.clone(),
                query_positions.clone(),
                case_queried_values.clone(),
                case_decommitment.clone(),
            );
            out.push(VcsLiftedVerifierVector {
                case: case.to_string(),
                root: encode_hash(case_root),
                column_log_sizes: column_log_sizes.clone(),
                query_positions: query_positions.clone(),
                queried_values: case_queried_values
                    .into_iter()
                    .map(|column| column.into_iter().map(encode_m31).collect())
                    .collect(),
                hash_witness: case_decommitment
                    .hash_witness
                    .into_iter()
                    .map(encode_hash)
                    .collect(),
                expected,
            });
        };

    push_case(
        "valid",
        root,
        queried_values.clone(),
        base_decommitment.clone(),
    );

    let mut bad_root = root;
    bad_root.0[0] ^= 1;
    push_case(
        "root_mismatch",
        bad_root,
        queried_values.clone(),
        base_decommitment.clone(),
    );

    if !base_decommitment.hash_witness.is_empty() {
        let mut short = base_decommitment.clone();
        short.hash_witness.pop();
        push_case("witness_too_short", root, queried_values.clone(), short);
    }

    let mut long = base_decommitment.clone();
    long.hash_witness.push(sample_hash(state));
    push_case("witness_too_long", root, queried_values.clone(), long);

    if !queried_values.is_empty() && !queried_values[0].is_empty() {
        let mut bad_values = queried_values.clone();
        bad_values[0][0] = sample_m31(state, false);
        push_case(
            "queried_values_mismatch",
            root,
            bad_values,
            base_decommitment,
        );
    }

    out
}

pub(crate) fn generate_vcs_lifted_prover_vectors(
    state: &mut u64,
    count: usize,
) -> Vec<VcsLiftedProverVector> {
    let mut bases = Vec::with_capacity(count);
    while bases.len() < count {
        if let Some(base) = build_vcs_lifted_base_case(state) {
            bases.push(base);
        }
    }
    // Unsorted / duplicate query KATs are appended after the random cases and
    // consume no RNG, so the primary stream (and every later section) is unchanged.
    let mut extra = fixed_unsorted_vcs_lifted_cases();
    extra.extend(
        bases
            .iter()
            .take(VCS_LIFTED_PROVER_UNSORTED_VARIANT_COUNT)
            .map(unsorted_duplicate_variant),
    );
    bases
        .into_iter()
        .chain(extra)
        .map(|base| VcsLiftedProverVector {
            root: encode_hash(base.root),
            column_log_sizes: base.column_log_sizes,
            columns: base
                .columns
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
            query_positions: base.query_positions,
            queried_values: base
                .queried_values
                .into_iter()
                .map(|column| column.into_iter().map(encode_m31).collect())
                .collect(),
            hash_witness: base
                .decommitment
                .hash_witness
                .into_iter()
                .map(encode_hash)
                .collect(),
        })
        .collect()
}

/// Number of random base cases re-emitted with reversed + duplicated queries.
const VCS_LIFTED_PROVER_UNSORTED_VARIANT_COUNT: usize = 4;

/// Fixed KATs (columns of log sizes 3, 2, 3 holding 1..=20) with unsorted and
/// duplicated query positions. Confirmed against upstream stwo 7b211ed
/// `MerkleProverLifted::decommit`, which normalises with `.sorted().dedup()`.
fn fixed_unsorted_vcs_lifted_cases() -> Vec<VcsLiftedBaseCase> {
    let columns: Vec<Vec<M31>> = vec![
        (1..=8).map(M31::from_u32_unchecked).collect(),
        (9..=12).map(M31::from_u32_unchecked).collect(),
        (13..=20).map(M31::from_u32_unchecked).collect(),
    ];
    [
        vec![7, 3, 1, 3],
        vec![5, 4, 4, 0],
        vec![7, 6, 5, 4, 3, 2, 1, 0, 7],
    ]
    .into_iter()
    .map(|query_positions| lifted_case(columns.clone(), vec![3, 2, 3], query_positions))
    .collect()
}

/// Re-emits `base` with its queries reversed and the first one duplicated.
/// The Merkle witness must not change: only the queried values follow the
/// caller's order.
fn unsorted_duplicate_variant(base: &VcsLiftedBaseCase) -> VcsLiftedBaseCase {
    let mut query_positions = base
        .query_positions
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    query_positions.push(base.query_positions[0]);
    let case = lifted_case(
        base.columns.clone(),
        base.column_log_sizes.clone(),
        query_positions,
    );
    assert_eq!(case.root, base.root);
    assert_eq!(
        case.decommitment.hash_witness,
        base.decommitment.hash_witness
    );
    case
}

fn lifted_case(
    columns: Vec<Vec<M31>>,
    column_log_sizes: Vec<u32>,
    query_positions: Vec<usize>,
) -> VcsLiftedBaseCase {
    let layers = commit_vcs_lifted_layers(&columns, &column_log_sizes);
    let root = layers[0][0];
    let queried_values = lifted_queried_values(&columns, layers.len() - 1, &query_positions);
    let hash_witness = lifted_hash_witness(&layers, &query_positions);
    VcsLiftedBaseCase {
        root,
        column_log_sizes,
        columns,
        query_positions,
        queried_values,
        decommitment: MerkleDecommitmentLifted::<LiftedMerkleHasher> { hash_witness },
    }
}

/// Commits `columns` (sorted by log size, stable) and returns every layer,
/// root first, mirroring upstream `MerkleProverLifted::commit`.
fn commit_vcs_lifted_layers(
    columns: &[Vec<M31>],
    column_log_sizes: &[u32],
) -> Vec<Vec<Blake2sHash>> {
    let mut sorted_indices = (0..columns.len()).collect::<Vec<_>>();
    sorted_indices.sort_by_key(|&i| (column_log_sizes[i], i));
    let sorted_columns = sorted_indices
        .iter()
        .map(|&i| &columns[i])
        .collect::<Vec<_>>();
    build_vcs_lifted_layers(build_vcs_lifted_leaves(&sorted_columns))
}

/// Builds all Merkle layers above `leaves`, root first.
pub(crate) fn build_vcs_lifted_layers(leaves: Vec<Blake2sHash>) -> Vec<Vec<Blake2sHash>> {
    let mut layers = vec![leaves];
    while layers.last().expect("at least one layer").len() > 1 {
        let prev = layers.last().expect("previous layer");
        layers.push(
            (0..(prev.len() >> 1))
                .map(|i| LiftedMerkleHasher::hash_children((prev[2 * i], prev[2 * i + 1])))
                .collect(),
        );
    }
    layers.reverse();
    layers
}

fn lifted_queried_values(
    columns: &[Vec<M31>],
    max_layer_log_size: usize,
    query_positions: &[usize],
) -> Vec<Vec<M31>> {
    columns
        .iter()
        .map(|col| {
            let log_size = col.len().ilog2() as usize;
            let shift = max_layer_log_size - log_size;
            query_positions
                .iter()
                .map(|pos| col[(pos >> (shift + 1) << 1) + (pos & 1)])
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Authentication-path witness of upstream `MerkleProverLifted::decommit`
/// (stwo 7b211ed): positions are sorted and deduplicated first, then each layer
/// is walked in sibling chunks (`chunk_by(|a, b| a ^ 1 == *b)`), emitting the
/// sibling hash of every singleton chunk. `layers` is root first.
pub(crate) fn lifted_hash_witness(
    layers: &[Vec<Blake2sHash>],
    query_positions: &[usize],
) -> Vec<Blake2sHash> {
    let mut prev_layer_queries = query_positions.to_vec();
    prev_layer_queries.sort_unstable();
    prev_layer_queries.dedup();
    let mut hash_witness = Vec::<Blake2sHash>::new();
    for layer_log_size in (0..layers.len() - 1).rev() {
        let prev_layer_hashes = &layers[layer_log_size + 1];
        let mut curr_layer_queries = Vec::<usize>::new();
        for chunk in prev_layer_queries.chunk_by(|a, b| a ^ 1 == *b) {
            let first = chunk[0];
            if chunk.len() == 1 {
                hash_witness.push(prev_layer_hashes[first ^ 1]);
            }
            curr_layer_queries.push(first >> 1);
        }
        prev_layer_queries = curr_layer_queries;
    }
    hash_witness
}

fn build_vcs_lifted_base_case(state: &mut u64) -> Option<VcsLiftedBaseCase> {
    let n_columns = 2 + (next_u64(state) as usize % 4);
    let mut column_log_sizes = Vec::with_capacity(n_columns);
    let mut columns = Vec::with_capacity(n_columns);
    for _ in 0..n_columns {
        let log_size = 1 + (next_u64(state) as u32 % 4);
        column_log_sizes.push(log_size);
        let col = (0..(1usize << log_size))
            .map(|_| sample_m31(state, false))
            .collect::<Vec<_>>();
        columns.push(col);
    }

    let max_log_size = *column_log_sizes.iter().max().expect("at least one column");
    let domain_size = 1usize << max_log_size;
    let mut query_positions = Vec::with_capacity(4);
    let n_queries = 1 + (next_u64(state) as usize % domain_size.min(4));
    while query_positions.len() < n_queries {
        let q = next_u64(state) as usize & (domain_size - 1);
        if !query_positions.contains(&q) {
            query_positions.push(q);
        }
    }
    query_positions.sort_unstable();

    let layers = commit_vcs_lifted_layers(&columns, &column_log_sizes);
    let root = layers[0][0];
    let queried_values = lifted_queried_values(&columns, layers.len() - 1, &query_positions);
    let hash_witness = lifted_hash_witness(&layers, &query_positions);

    let decommitment = MerkleDecommitmentLifted::<LiftedMerkleHasher> { hash_witness };
    let verifier = MerkleVerifierLifted::<LiftedMerkleHasher>::new(root, column_log_sizes.clone());
    if verifier
        .verify(
            &query_positions,
            queried_values.clone(),
            decommitment.clone(),
        )
        .is_err()
    {
        return None;
    }

    Some(VcsLiftedBaseCase {
        root,
        column_log_sizes,
        columns,
        query_positions,
        queried_values,
        decommitment,
    })
}

pub(crate) fn build_vcs_lifted_leaves(columns: &[&Vec<M31>]) -> Vec<Blake2sHash> {
    let hasher = LiftedMerkleHasher::default_with_initial_state();
    if columns.is_empty() {
        return vec![hasher.finalize()];
    }
    assert!(columns[0].len() >= 2, "A column must be of length >= 2.");

    let mut prev_layer: Vec<LiftedMerkleHasher> = vec![hasher; 2];
    let mut prev_layer_log_size: u32 = 1;

    let mut group_start: usize = 0;
    while group_start < columns.len() {
        let log_size = columns[group_start].len().ilog2();
        let mut group_end = group_start + 1;
        while group_end < columns.len() && columns[group_end].len().ilog2() == log_size {
            group_end += 1;
        }

        let log_ratio = log_size - prev_layer_log_size;
        prev_layer = (0..(1usize << log_size))
            .map(|idx| prev_layer[(idx >> (log_ratio + 1) << 1) + (idx & 1)].clone())
            .collect();

        for column in &columns[group_start..group_end] {
            for (i, hasher) in prev_layer.iter_mut().enumerate() {
                hasher.update_leaf(&[column[i]]);
            }
        }
        prev_layer_log_size = log_size;
        group_start = group_end;
    }

    prev_layer.into_iter().map(|h| h.finalize()).collect()
}

fn build_vcs_base_case(state: &mut u64) -> Option<VcsBaseCase> {
    let n_columns = 2 + (next_u64(state) as usize % 4);
    let mut column_log_sizes = Vec::with_capacity(n_columns);
    let mut columns = Vec::with_capacity(n_columns);
    for _ in 0..n_columns {
        let log_size = 1 + (next_u64(state) as u32 % 4);
        column_log_sizes.push(log_size);
        let col = (0..(1usize << log_size))
            .map(|_| sample_m31(state, false))
            .collect::<Vec<_>>();
        columns.push(col);
    }

    let max_log_size = *column_log_sizes.iter().max().expect("at least one column");
    let mut columns_by_layer = BTreeMap::<u32, Vec<Vec<M31>>>::new();
    for (log_size, column) in column_log_sizes
        .iter()
        .copied()
        .zip(columns.iter().cloned())
    {
        columns_by_layer.entry(log_size).or_default().push(column);
    }

    let mut queries_per_log_size = BTreeMap::<u32, Vec<usize>>::new();
    for log_size in 0..=max_log_size {
        if !columns_by_layer.contains_key(&log_size) {
            continue;
        }
        let layer_size = 1usize << log_size;
        let n_queries = 1 + (next_u64(state) as usize % layer_size.min(3));
        let mut queries = Vec::with_capacity(n_queries);
        while queries.len() < n_queries {
            let q = next_u64(state) as usize & ((1usize << log_size) - 1);
            if !queries.contains(&q) {
                queries.push(q);
            }
        }
        queries.sort_unstable();
        queries_per_log_size.insert(log_size, queries);
    }

    let mut layer_hashes = BTreeMap::<u32, Vec<Blake2sHash>>::new();
    for layer_log_size in (0..=max_log_size).rev() {
        let n_nodes = 1usize << layer_log_size;
        let layer_columns = columns_by_layer
            .get(&layer_log_size)
            .cloned()
            .unwrap_or_default();
        let prev_layer = if layer_log_size == max_log_size {
            None
        } else {
            Some(
                layer_hashes
                    .get(&(layer_log_size + 1))
                    .expect("previous layer should be available"),
            )
        };

        let mut hashes = Vec::with_capacity(n_nodes);
        for node_index in 0..n_nodes {
            let children = prev_layer.map(|p| (p[2 * node_index], p[2 * node_index + 1]));
            let node_values = layer_columns
                .iter()
                .map(|column| column[node_index])
                .collect::<Vec<_>>();
            hashes.push(VcsMerkleHasher::hash_node(children, &node_values));
        }
        layer_hashes.insert(layer_log_size, hashes);
    }
    let root = layer_hashes
        .get(&0)
        .expect("root layer")
        .first()
        .copied()
        .expect("non-empty root layer");

    let mut queried_values = Vec::<M31>::new();
    let mut hash_witness = Vec::<Blake2sHash>::new();
    let mut column_witness = Vec::<M31>::new();

    let mut last_layer_queries = Vec::<usize>::new();
    for layer_log_size in (0..=max_log_size).rev() {
        let layer_columns = columns_by_layer
            .get(&layer_log_size)
            .cloned()
            .unwrap_or_default();
        let previous_layer_hashes = if layer_log_size == max_log_size {
            None
        } else {
            Some(
                layer_hashes
                    .get(&(layer_log_size + 1))
                    .expect("previous layer hashes"),
            )
        };

        let mut layer_total_queries = Vec::<usize>::new();
        let mut prev_layer_queries = last_layer_queries.iter().copied().peekable();
        let mut layer_column_queries = queries_per_log_size
            .get(&layer_log_size)
            .map(|v| v.iter().copied())
            .into_iter()
            .flatten()
            .peekable();

        while let Some(node_index) =
            next_decommitment_node_for_prover(&mut prev_layer_queries, &mut layer_column_queries)
        {
            if let Some(prev_hashes) = previous_layer_hashes {
                if prev_layer_queries.next_if_eq(&(2 * node_index)).is_none() {
                    hash_witness.push(prev_hashes[2 * node_index]);
                }
                if prev_layer_queries
                    .next_if_eq(&(2 * node_index + 1))
                    .is_none()
                {
                    hash_witness.push(prev_hashes[2 * node_index + 1]);
                }
            }

            let node_values = layer_columns
                .iter()
                .map(|column| column[node_index])
                .collect::<Vec<_>>();
            if layer_column_queries.next_if_eq(&node_index).is_some() {
                queried_values.extend(node_values);
            } else {
                column_witness.extend(node_values);
            }
            layer_total_queries.push(node_index);
        }

        last_layer_queries = layer_total_queries;
    }

    let base_decommitment = MerkleDecommitment::<VcsMerkleHasher> {
        hash_witness,
        column_witness,
    };
    let base_expected = run_vcs_verifier(
        root,
        column_log_sizes.clone(),
        queries_per_log_size.clone(),
        queried_values.clone(),
        base_decommitment.clone(),
    );
    if base_expected != "ok" {
        return None;
    }

    Some(VcsBaseCase {
        root,
        column_log_sizes,
        columns,
        queries_per_log_size,
        queried_values,
        decommitment: base_decommitment,
    })
}

fn build_vcs_verifier_cases(state: &mut u64) -> Vec<VcsVerifierVector> {
    let Some(base) = build_vcs_base_case(state) else {
        return vec![];
    };

    let root = base.root;
    let column_log_sizes = base.column_log_sizes.clone();
    let queries_per_log_size = base.queries_per_log_size.clone();
    let queried_values = base.queried_values.clone();
    let base_decommitment = base.decommitment.clone();

    let mut out = Vec::<VcsVerifierVector>::new();
    let mut push_case =
        |case: &str,
         case_root: Blake2sHash,
         case_queried_values: Vec<M31>,
         case_decommitment: MerkleDecommitment<VcsMerkleHasher>| {
            let expected = run_vcs_verifier(
                case_root,
                column_log_sizes.clone(),
                queries_per_log_size.clone(),
                case_queried_values.clone(),
                case_decommitment.clone(),
            );
            out.push(VcsVerifierVector {
                case: case.to_string(),
                root: encode_hash(case_root),
                column_log_sizes: column_log_sizes.clone(),
                queries_per_log_size: queries_per_log_size
                    .iter()
                    .map(|(log_size, queries)| VcsLogSizeQueriesVector {
                        log_size: *log_size,
                        queries: queries.clone(),
                    })
                    .collect(),
                queried_values: case_queried_values.into_iter().map(encode_m31).collect(),
                hash_witness: case_decommitment
                    .hash_witness
                    .into_iter()
                    .map(encode_hash)
                    .collect(),
                column_witness: case_decommitment
                    .column_witness
                    .into_iter()
                    .map(encode_m31)
                    .collect(),
                expected,
            });
        };

    push_case(
        "valid",
        root,
        queried_values.clone(),
        base_decommitment.clone(),
    );

    let mut bad_root = root;
    bad_root.0[0] ^= 1;
    push_case(
        "root_mismatch",
        bad_root,
        queried_values.clone(),
        base_decommitment.clone(),
    );

    if !base_decommitment.hash_witness.is_empty() || !base_decommitment.column_witness.is_empty() {
        let mut short = base_decommitment.clone();
        if !short.hash_witness.is_empty() {
            short.hash_witness.pop();
        } else {
            short.column_witness.pop();
        }
        push_case("witness_too_short", root, queried_values.clone(), short);
    }

    let mut long = base_decommitment.clone();
    long.hash_witness.push(sample_hash(state));
    push_case("witness_too_long", root, queried_values.clone(), long);

    if !queried_values.is_empty() {
        let mut short_values = queried_values.clone();
        short_values.pop();
        push_case(
            "queried_values_too_short",
            root,
            short_values,
            base_decommitment.clone(),
        );
    }

    let mut long_values = queried_values.clone();
    long_values.push(sample_m31(state, false));
    push_case(
        "queried_values_too_long",
        root,
        long_values,
        base_decommitment,
    );

    out
}

fn next_decommitment_node_for_prover(
    prev_queries: &mut std::iter::Peekable<impl Iterator<Item = usize>>,
    layer_queries: &mut std::iter::Peekable<impl Iterator<Item = usize>>,
) -> Option<usize> {
    let prev = prev_queries.peek().map(|q| *q / 2);
    let layer = layer_queries.peek().copied();
    match (prev, layer) {
        (None, None) => None,
        (Some(v), None) | (None, Some(v)) => Some(v),
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

fn run_vcs_verifier(
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    queries_per_log_size: BTreeMap<u32, Vec<usize>>,
    queried_values: Vec<M31>,
    decommitment: MerkleDecommitment<VcsMerkleHasher>,
) -> String {
    let verifier = MerkleVerifier::<VcsMerkleHasher>::new(root, column_log_sizes);
    match verifier.verify(&queries_per_log_size, queried_values, decommitment) {
        Ok(()) => "ok".to_string(),
        Err(err) => merkle_error_name(err).to_string(),
    }
}

fn merkle_error_name(err: MerkleVerificationError) -> &'static str {
    match err {
        MerkleVerificationError::WitnessTooShort => "WitnessTooShort",
        MerkleVerificationError::WitnessTooLong => "WitnessTooLong",
        MerkleVerificationError::TooManyQueriedValues => "TooManyQueriedValues",
        MerkleVerificationError::TooFewQueriedValues => "TooFewQueriedValues",
        MerkleVerificationError::RootMismatch => "RootMismatch",
    }
}

fn run_vcs_lifted_verifier(
    root: Blake2sHash,
    column_log_sizes: Vec<u32>,
    query_positions: Vec<usize>,
    queried_values: Vec<Vec<M31>>,
    decommitment: MerkleDecommitmentLifted<LiftedMerkleHasher>,
) -> String {
    let verifier = MerkleVerifierLifted::<LiftedMerkleHasher>::new(root, column_log_sizes);
    match verifier.verify(&query_positions, queried_values, decommitment) {
        Ok(()) => "ok".to_string(),
        Err(err) => merkle_error_name_lifted(err).to_string(),
    }
}

fn merkle_error_name_lifted(err: MerkleVerificationErrorLifted) -> &'static str {
    match err {
        MerkleVerificationErrorLifted::WitnessTooShort => "WitnessTooShort",
        MerkleVerificationErrorLifted::WitnessTooLong => "WitnessTooLong",
        MerkleVerificationErrorLifted::RootMismatch => "RootMismatch",
    }
}
