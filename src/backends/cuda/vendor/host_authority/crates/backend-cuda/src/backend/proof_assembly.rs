//! Host-only adapter from the resident decommit ABI to STWO proof types.
//!
//! This is deliberately a decoder, not another prover stage. It consumes the
//! single compact D2H result plus transcript-visible roots/values already held
//! by the host, validates them against a sealed protocol shape, and constructs
//! the exact `ExtendedStarkProof<Blake2sMerkleHasher>`. It performs no channel,
//! hash, fold, query, or device operation.

use std::collections::{BTreeMap, BTreeSet};

use stwo::core::fields::m31::{BaseField, M31, P};
use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo::core::fri::{FriLayerProof, FriLayerProofAux, FriProof, FriProofAux};
use stwo::core::pcs::quotients::{CommitmentSchemeProof, CommitmentSchemeProofAux};
use stwo::core::pcs::{PcsConfig, TreeVec};
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::{ExtendedStarkProof, StarkProof};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::vcs_lifted::verifier::{
    MerkleDecommitmentLifted, MerkleDecommitmentLiftedAux, LOG_PACKED_LEAF_SIZE,
};

use super::prepared_decommit::{DecommitAssembly, DecommitTreeMeta, TraceTreeRole};

const HASH_WORDS: usize = 8;
const SECURE_WORDS: usize = SECURE_EXTENSION_DEGREE;
const AUX_NODE_WORDS: usize = 2 + HASH_WORDS;
const FRI_ALL_VALUE_WORDS: usize = 1 + SECURE_WORDS;

/// Sealed trace-tree topology from protocol discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blake2sTraceAssemblyShape {
    pub role: TraceTreeRole,
    pub leaf_log_size: u32,
    /// Domain to which global FRI queries are mapped for this tree.
    pub query_log_size: u32,
    /// Exact OODS sample count for each committed column, in original PCS tree order.
    pub oods_samples_per_column: Vec<usize>,
    /// For each stable log-sorted Merkle leaf column, the corresponding column
    /// in the original PCS tree order. STWO hashes columns in sorted order but
    /// exposes sampled and queried values in original order.
    pub commit_to_proof_column: Vec<usize>,
}

/// Sealed committed-FRI-tree topology from `FriWorkspaceRequirements`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sFriAssemblyShape {
    pub evaluation_log_size: u32,
    pub cumulative_fold: u32,
    pub outgoing_fold_step: u32,
    pub log_rows_per_leaf: u32,
}

impl Blake2sFriAssemblyShape {
    pub fn leaf_log_size(self) -> Option<u32> {
        self.evaluation_log_size.checked_sub(self.log_rows_per_leaf)
    }
}

/// Proof-wide immutable geometry. Production Starknet inputs contain four
/// trace trees; keeping the vector explicit also lets the adapter test smaller
/// canonical STWO fixtures without weakening boundary validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blake2sProofAssemblyShape {
    pub query_log_size: u32,
    pub n_queries: usize,
    pub trace_trees: Vec<Blake2sTraceAssemblyShape>,
    pub fri_trees: Vec<Blake2sFriAssemblyShape>,
}

pub struct Blake2sProofAssemblyInput {
    pub config: PcsConfig,
    pub shape: Blake2sProofAssemblyShape,
    /// Preprocessed/base/interaction/composition roots in trace-tree order.
    pub commitments: Vec<Blake2sHash>,
    /// Four-tree OODS values in exact tree/column/sample order.
    pub sampled_values: TreeVec<Vec<Vec<SecureField>>>,
    /// Transcript output before sorting and deduplication.
    pub raw_queries: Vec<u32>,
    pub proof_of_work: u64,
    /// Row-major SecureField words in `LinePoly` storage (bit-reversed) order.
    pub final_line_poly_words: Vec<u32>,
    /// First FRI tree root followed by every inner-tree root.
    pub fri_commitments: Vec<Blake2sHash>,
    pub decommitment: DecommitAssembly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Blake2sProofAssemblyError {
    InvalidQueryGeometry,
    InvalidTraceOrder(usize),
    InvalidTraceGeometry(usize),
    InvalidColumnPermutation(usize),
    InvalidFriGeometry(usize),
    CountMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    TreeKindMismatch {
        tree: usize,
        expected: u32,
        actual: u32,
    },
    TreeRoleMismatch {
        tree: usize,
        expected: u32,
        actual: u32,
    },
    TreeLeafLogMismatch {
        tree: usize,
        expected: u32,
        actual: u32,
    },
    QueryMismatch {
        tree: Option<usize>,
    },
    SectionShape {
        tree: usize,
        section: &'static str,
        expected: usize,
        actual: usize,
    },
    NonCanonicalM31 {
        section: &'static str,
        index: usize,
        word: u32,
    },
    NonCanonicalAux {
        tree: usize,
    },
    DuplicateAuxNode {
        tree: usize,
        level: u32,
        index: usize,
    },
    InvalidFinalLinePolynomial,
    InvalidTypedSample {
        tree: usize,
        column: usize,
        sample: usize,
    },
}

impl core::fmt::Display for Blake2sProofAssemblyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid resident Blake2s proof assembly: {self:?}")
    }
}

impl std::error::Error for Blake2sProofAssemblyError {}

/// Decode a complete resident Blake2s proof without protocol computation or
/// another transfer.
pub fn assemble_blake2s_stark_proof(
    input: Blake2sProofAssemblyInput,
) -> Result<ExtendedStarkProof<Blake2sMerkleHasher>, Blake2sProofAssemblyError> {
    const STARKNET_ROLES: [TraceTreeRole; 4] = [
        TraceTreeRole::Preprocessed,
        TraceTreeRole::Base,
        TraceTreeRole::Interaction,
        TraceTreeRole::Composition,
    ];
    check_count(
        "strict Starknet trace trees",
        STARKNET_ROLES.len(),
        input.shape.trace_trees.len(),
    )?;
    for (index, (tree, role)) in input
        .shape
        .trace_trees
        .iter()
        .zip(STARKNET_ROLES)
        .enumerate()
    {
        if tree.role != role {
            return Err(Blake2sProofAssemblyError::InvalidTraceOrder(index));
        }
    }
    assemble_blake2s_stark_proof_inner(input)
}

fn assemble_blake2s_stark_proof_inner(
    input: Blake2sProofAssemblyInput,
) -> Result<ExtendedStarkProof<Blake2sMerkleHasher>, Blake2sProofAssemblyError> {
    let Blake2sProofAssemblyInput {
        config,
        shape,
        commitments,
        sampled_values,
        raw_queries,
        proof_of_work,
        final_line_poly_words,
        fri_commitments,
        decommitment,
    } = input;
    validate_shape(config, &shape)?;
    check_count("commitments", shape.trace_trees.len(), commitments.len())?;
    check_count(
        "sampled value trees",
        shape.trace_trees.len(),
        sampled_values.len(),
    )?;
    check_count("raw queries", shape.n_queries, raw_queries.len())?;
    check_count(
        "FRI commitments",
        shape.fri_trees.len(),
        fri_commitments.len(),
    )?;
    check_count(
        "decommitment trees",
        shape.trace_trees.len() + shape.fri_trees.len(),
        decommitment.trees.len(),
    )?;

    validate_sampled_values(&shape.trace_trees, &sampled_values)?;
    validate_queries(&shape, &raw_queries, &decommitment)?;

    let words = decommitment.words();
    let unique_queries: Vec<u32> = decommitment.unique_queries().to_vec();
    let mut trace_decommitments = Vec::with_capacity(shape.trace_trees.len());
    let mut trace_aux = Vec::with_capacity(shape.trace_trees.len());
    let mut queried_values = Vec::with_capacity(shape.trace_trees.len());

    for (tree_index, trace_shape) in shape.trace_trees.iter().enumerate() {
        let meta = decommitment.trees[tree_index];
        validate_trace_meta(tree_index, trace_shape, meta)?;
        let expected_queries = map_trace_queries(
            &unique_queries,
            shape.query_log_size,
            trace_shape.query_log_size,
        );
        if section(words, meta.query_offset, meta.query_count) != expected_queries {
            return Err(Blake2sProofAssemblyError::QueryMismatch {
                tree: Some(tree_index),
            });
        }
        let column_count = trace_shape.oods_samples_per_column.len();
        let expected_values = column_count
            .checked_mul(expected_queries.len())
            .ok_or(Blake2sProofAssemblyError::InvalidTraceGeometry(tree_index))?;
        check_section_shape(
            tree_index,
            "queried values",
            expected_values,
            meta.values_count,
        )?;
        check_section_shape(tree_index, "FRI witness", 0, meta.fri_witness_count)?;
        check_section_shape(tree_index, "FRI all values", 0, meta.all_values_count)?;

        let flat_values = section(words, meta.values_offset, meta.values_count);
        let commit_values = if expected_queries.is_empty() {
            if column_count != 0 {
                return Err(Blake2sProofAssemblyError::InvalidTraceGeometry(tree_index));
            }
            Vec::new()
        } else {
            flat_values
                .chunks_exact(expected_queries.len())
                .map(|column| decode_base_values("trace queried values", column))
                .collect::<Result<Vec<_>, _>>()?
        };
        queried_values.push(restore_proof_column_order(
            tree_index,
            commit_values,
            &trace_shape.commit_to_proof_column,
        )?);
        let walk_queries: Vec<u32> = BTreeSet::from_iter(expected_queries.iter().copied())
            .into_iter()
            .collect();
        let topology = merkle_topology(&walk_queries, trace_shape.leaf_log_size);
        check_section_shape(
            tree_index,
            "hash witness",
            topology.witness_nodes.len(),
            meta.hash_witness_count,
        )?;
        trace_decommitments.push(MerkleDecommitmentLifted {
            hash_witness: decode_hashes(section(
                words,
                meta.hash_witness_offset,
                meta.hash_witness_count * HASH_WORDS,
            )),
        });
        trace_aux.push(decode_aux(tree_index, meta, words, &topology.aux_nodes)?);
    }

    let mut fri_proofs = Vec::with_capacity(shape.fri_trees.len());
    let mut fri_aux = Vec::with_capacity(shape.fri_trees.len());
    for (fri_index, fri_shape) in shape.fri_trees.iter().enumerate() {
        let tree_index = shape.trace_trees.len() + fri_index;
        let meta = decommitment.trees[tree_index];
        validate_fri_meta(tree_index, *fri_shape, meta)?;
        let tree_queries = folded_queries(&unique_queries, fri_shape.cumulative_fold);
        if section(words, meta.query_offset, meta.query_count) != tree_queries {
            return Err(Blake2sProofAssemblyError::QueryMismatch {
                tree: Some(tree_index),
            });
        }
        check_section_shape(tree_index, "trace queried values", 0, meta.values_count)?;
        let expanded = expanded_fri_positions(&tree_queries, fri_shape.outgoing_fold_step);
        let witness_count = expanded
            .len()
            .checked_sub(tree_queries.len())
            .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(fri_index))?;
        check_section_shape(
            tree_index,
            "FRI witness",
            witness_count,
            meta.fri_witness_count,
        )?;
        check_section_shape(
            tree_index,
            "FRI all values",
            expanded.len(),
            meta.all_values_count,
        )?;
        let fri_witness = decode_secure_values(
            "FRI witness",
            section(
                words,
                meta.fri_witness_offset,
                meta.fri_witness_count * SECURE_WORDS,
            ),
        )?;
        let all_values = decode_fri_all_values(tree_index, meta, words, &expanded)?;
        let tree_query_set: BTreeSet<_> =
            tree_queries.iter().map(|&query| query as usize).collect();
        let expected_witness: Vec<_> = all_values
            .iter()
            .filter(|(position, _)| !tree_query_set.contains(position))
            .map(|(_, &value)| value)
            .collect();
        if fri_witness != expected_witness {
            return Err(Blake2sProofAssemblyError::QueryMismatch {
                tree: Some(tree_index),
            });
        }
        let merkle_queries: Vec<u32> = BTreeSet::from_iter(
            expanded
                .iter()
                .map(|position| position >> fri_shape.log_rows_per_leaf),
        )
        .into_iter()
        .collect();
        let topology = merkle_topology(
            &merkle_queries,
            fri_shape
                .leaf_log_size()
                .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(fri_index))?,
        );
        check_section_shape(
            tree_index,
            "hash witness",
            topology.witness_nodes.len(),
            meta.hash_witness_count,
        )?;
        let decommitment = MerkleDecommitmentLifted {
            hash_witness: decode_hashes(section(
                words,
                meta.hash_witness_offset,
                meta.hash_witness_count * HASH_WORDS,
            )),
        };
        let decommitment_aux = decode_aux(tree_index, meta, words, &topology.aux_nodes)?;
        fri_proofs.push(FriLayerProof {
            fri_witness,
            decommitment,
            commitment: fri_commitments[fri_index],
        });
        fri_aux.push(FriLayerProofAux {
            all_values: vec![all_values],
            decommitment: decommitment_aux,
        });
    }

    let last_layer_poly = decode_line_poly(config, &final_line_poly_words)?;
    let mut fri_proofs = fri_proofs.into_iter();
    let first_layer = fri_proofs
        .next()
        .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(0))?;
    let mut fri_aux = fri_aux.into_iter();
    let first_layer_aux = fri_aux
        .next()
        .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(0))?;

    Ok(ExtendedStarkProof {
        proof: StarkProof(CommitmentSchemeProof {
            config,
            commitments: TreeVec(commitments),
            sampled_values,
            decommitments: TreeVec(trace_decommitments),
            queried_values: TreeVec(queried_values),
            proof_of_work,
            fri_proof: FriProof {
                first_layer,
                inner_layers: fri_proofs.collect(),
                last_layer_poly,
            },
        }),
        aux: CommitmentSchemeProofAux {
            unsorted_query_locations: raw_queries
                .into_iter()
                .map(|query| query as usize)
                .collect(),
            trace_decommitment: TreeVec(trace_aux),
            fri: FriProofAux {
                first_layer: first_layer_aux,
                inner_layers: fri_aux.collect(),
            },
        },
    })
}

fn validate_shape(
    config: PcsConfig,
    shape: &Blake2sProofAssemblyShape,
) -> Result<(), Blake2sProofAssemblyError> {
    if shape.query_log_size == 0
        || shape.query_log_size >= 31
        || shape.n_queries == 0
        || shape.n_queries != config.fri_config.n_queries
        || config
            .lifting_log_size
            .is_some_and(|lifting| lifting != shape.query_log_size)
        || shape.trace_trees.is_empty()
        || shape.fri_trees.is_empty()
    {
        return Err(Blake2sProofAssemblyError::InvalidQueryGeometry);
    }
    let mut previous_role = None;
    for (index, tree) in shape.trace_trees.iter().enumerate() {
        if previous_role.is_some_and(|role| tree.role <= role) {
            return Err(Blake2sProofAssemblyError::InvalidTraceOrder(index));
        }
        previous_role = Some(tree.role);
        if tree.leaf_log_size >= 31
            || tree.query_log_size >= 31
            || tree.query_log_size != tree.leaf_log_size
            || (tree.role != TraceTreeRole::Preprocessed
                && tree.query_log_size != shape.query_log_size)
        {
            return Err(Blake2sProofAssemblyError::InvalidTraceGeometry(index));
        }
        let mut permutation = tree.commit_to_proof_column.clone();
        permutation.sort_unstable();
        if permutation != (0..tree.oods_samples_per_column.len()).collect::<Vec<_>>() {
            return Err(Blake2sProofAssemblyError::InvalidColumnPermutation(index));
        }
    }

    let final_log_size = config
        .fri_config
        .log_last_layer_degree_bound
        .checked_add(config.fri_config.log_blowup_factor)
        .ok_or(Blake2sProofAssemblyError::InvalidQueryGeometry)?;
    let mut cumulative = 0u32;
    for (index, tree) in shape.fri_trees.iter().enumerate() {
        let expected_evaluation = shape
            .query_log_size
            .checked_sub(cumulative)
            .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(index))?;
        let expected_fold = config.fri_config.fold_step.min(
            expected_evaluation
                .checked_sub(final_log_size)
                .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(index))?,
        );
        let expected_packing = if expected_evaluation >= LOG_PACKED_LEAF_SIZE && expected_fold > 1 {
            LOG_PACKED_LEAF_SIZE
        } else {
            0
        };
        if tree.cumulative_fold != cumulative
            || tree.evaluation_log_size != expected_evaluation
            || tree.outgoing_fold_step != expected_fold
            || tree.log_rows_per_leaf != expected_packing
            || expected_fold == 0
        {
            return Err(Blake2sProofAssemblyError::InvalidFriGeometry(index));
        }
        cumulative = cumulative
            .checked_add(expected_fold)
            .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(index))?;
        let reached_final = expected_evaluation - expected_fold == final_log_size;
        if reached_final != (index + 1 == shape.fri_trees.len()) {
            return Err(Blake2sProofAssemblyError::InvalidFriGeometry(index));
        }
    }
    Ok(())
}

fn restore_proof_column_order<T>(
    tree: usize,
    commit_values: Vec<T>,
    commit_to_proof: &[usize],
) -> Result<Vec<T>, Blake2sProofAssemblyError> {
    if commit_values.len() != commit_to_proof.len() {
        return Err(Blake2sProofAssemblyError::InvalidColumnPermutation(tree));
    }
    let mut ordered = (0..commit_values.len()).map(|_| None).collect::<Vec<_>>();
    for (value, &proof_column) in commit_values.into_iter().zip(commit_to_proof) {
        let destination = ordered
            .get_mut(proof_column)
            .ok_or(Blake2sProofAssemblyError::InvalidColumnPermutation(tree))?;
        if destination.replace(value).is_some() {
            return Err(Blake2sProofAssemblyError::InvalidColumnPermutation(tree));
        }
    }
    ordered
        .into_iter()
        .map(|value| value.ok_or(Blake2sProofAssemblyError::InvalidColumnPermutation(tree)))
        .collect()
}

fn validate_sampled_values(
    trace_shapes: &[Blake2sTraceAssemblyShape],
    sampled_values: &TreeVec<Vec<Vec<SecureField>>>,
) -> Result<(), Blake2sProofAssemblyError> {
    for (tree_index, (shape, tree)) in trace_shapes.iter().zip(sampled_values.iter()).enumerate() {
        check_count(
            "sampled value columns",
            shape.oods_samples_per_column.len(),
            tree.len(),
        )?;
        for (column_index, (&expected, column)) in
            shape.oods_samples_per_column.iter().zip(tree).enumerate()
        {
            check_count("OODS samples", expected, column.len())?;
            for (sample_index, &sample) in column.iter().enumerate() {
                if sample
                    .to_m31_array()
                    .iter()
                    .any(|coordinate| coordinate.0 >= P)
                {
                    return Err(Blake2sProofAssemblyError::InvalidTypedSample {
                        tree: tree_index,
                        column: column_index,
                        sample: sample_index,
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_queries(
    shape: &Blake2sProofAssemblyShape,
    raw_queries: &[u32],
    decommitment: &DecommitAssembly,
) -> Result<(), Blake2sProofAssemblyError> {
    let bound = 1u32 << shape.query_log_size;
    if raw_queries.iter().any(|&query| query >= bound) || raw_queries != decommitment.raw_queries()
    {
        return Err(Blake2sProofAssemblyError::QueryMismatch { tree: None });
    }
    let unique: Vec<u32> = BTreeSet::from_iter(raw_queries.iter().copied())
        .into_iter()
        .collect();
    if unique != decommitment.unique_queries() {
        return Err(Blake2sProofAssemblyError::QueryMismatch { tree: None });
    }
    Ok(())
}

fn validate_trace_meta(
    tree_index: usize,
    shape: &Blake2sTraceAssemblyShape,
    meta: DecommitTreeMeta,
) -> Result<(), Blake2sProofAssemblyError> {
    validate_meta_kind(tree_index, 0, meta.kind)?;
    if meta.role != shape.role as u32 {
        return Err(Blake2sProofAssemblyError::TreeRoleMismatch {
            tree: tree_index,
            expected: shape.role as u32,
            actual: meta.role,
        });
    }
    validate_leaf_log(tree_index, shape.leaf_log_size, meta.leaf_log_size)
}

fn validate_fri_meta(
    tree_index: usize,
    shape: Blake2sFriAssemblyShape,
    meta: DecommitTreeMeta,
) -> Result<(), Blake2sProofAssemblyError> {
    validate_meta_kind(tree_index, 1, meta.kind)?;
    if meta.role != tree_index as u32 {
        return Err(Blake2sProofAssemblyError::TreeRoleMismatch {
            tree: tree_index,
            expected: tree_index as u32,
            actual: meta.role,
        });
    }
    let leaf_log = shape
        .leaf_log_size()
        .ok_or(Blake2sProofAssemblyError::InvalidFriGeometry(tree_index))?;
    validate_leaf_log(tree_index, leaf_log, meta.leaf_log_size)
}

fn validate_meta_kind(
    tree: usize,
    expected: u32,
    actual: u32,
) -> Result<(), Blake2sProofAssemblyError> {
    if expected == actual {
        Ok(())
    } else {
        Err(Blake2sProofAssemblyError::TreeKindMismatch {
            tree,
            expected,
            actual,
        })
    }
}

fn validate_leaf_log(
    tree: usize,
    expected: u32,
    actual: u32,
) -> Result<(), Blake2sProofAssemblyError> {
    if expected == actual {
        Ok(())
    } else {
        Err(Blake2sProofAssemblyError::TreeLeafLogMismatch {
            tree,
            expected,
            actual,
        })
    }
}

fn map_trace_queries(queries: &[u32], source_log: u32, target_log: u32) -> Vec<u32> {
    if target_log == 0 {
        return Vec::new();
    }
    queries
        .iter()
        .map(|&position| {
            if source_log < target_log {
                ((position >> 1) << (target_log - source_log + 1)) | (position & 1)
            } else {
                ((position >> (source_log - target_log + 1)) << 1) | (position & 1)
            }
        })
        .collect()
}

fn folded_queries(queries: &[u32], cumulative_fold: u32) -> Vec<u32> {
    queries
        .iter()
        .map(|query| query >> cumulative_fold)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn expanded_fri_positions(queries: &[u32], fold_step: u32) -> Vec<u32> {
    let mut expanded = Vec::new();
    let mut previous_coset = None;
    for &query in queries {
        let coset = query >> fold_step;
        if previous_coset == Some(coset) {
            continue;
        }
        previous_coset = Some(coset);
        expanded.extend((coset << fold_step)..((coset + 1) << fold_step));
    }
    expanded
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MerkleTopology {
    witness_nodes: Vec<(u32, u32)>,
    aux_nodes: Vec<(u32, u32)>,
}

fn merkle_topology(query_positions: &[u32], leaf_log_size: u32) -> MerkleTopology {
    let mut witness_nodes = Vec::new();
    let mut aux_nodes = Vec::new();
    let mut current = query_positions.to_vec();
    for layer_log_size in (0..leaf_log_size).rev() {
        let previous_level = layer_log_size + 1;
        let mut next = Vec::new();
        let mut index = 0usize;
        while index < current.len() {
            let first = current[index];
            let paired = index + 1 < current.len() && current[index + 1] == (first ^ 1);
            if !paired {
                witness_nodes.push((previous_level, first ^ 1));
            }
            let parent = first >> 1;
            next.push(parent);
            aux_nodes.push((previous_level, 2 * parent));
            aux_nodes.push((previous_level, 2 * parent + 1));
            index += if paired { 2 } else { 1 };
        }
        current = next;
    }
    MerkleTopology {
        witness_nodes,
        aux_nodes,
    }
}

fn decode_aux(
    tree_index: usize,
    meta: DecommitTreeMeta,
    words: &[u32],
    expected_nodes: &[(u32, u32)],
) -> Result<MerkleDecommitmentLiftedAux<Blake2sMerkleHasher>, Blake2sProofAssemblyError> {
    check_section_shape(
        tree_index,
        "aux nodes",
        expected_nodes.len(),
        meta.aux_count,
    )?;
    let leaf_log = meta.leaf_log_size as usize;
    let entries = section(words, meta.aux_offset, meta.aux_count * AUX_NODE_WORDS);
    let mut layers = vec![BTreeMap::new(); leaf_log];
    let mut previous = None;
    for (entry, &(expected_level, expected_index)) in
        entries.chunks_exact(AUX_NODE_WORDS).zip(expected_nodes)
    {
        let level = entry[0];
        let index = entry[1] as usize;
        if level != expected_level || index != expected_index as usize {
            return Err(Blake2sProofAssemblyError::NonCanonicalAux { tree: tree_index });
        }
        if level == 0 || level > meta.leaf_log_size {
            return Err(Blake2sProofAssemblyError::NonCanonicalAux { tree: tree_index });
        }
        if let Some((previous_level, previous_index)) = previous {
            if level > previous_level || (level == previous_level && index <= previous_index) {
                return Err(Blake2sProofAssemblyError::NonCanonicalAux { tree: tree_index });
            }
        }
        let layer_index = (meta.leaf_log_size - level) as usize;
        let hash = decode_hash(&entry[2..]);
        if layers[layer_index].insert(index, hash).is_some() {
            return Err(Blake2sProofAssemblyError::DuplicateAuxNode {
                tree: tree_index,
                level,
                index,
            });
        }
        previous = Some((level, index));
    }
    if meta.query_count != 0 && layers.iter().any(BTreeMap::is_empty) {
        return Err(Blake2sProofAssemblyError::NonCanonicalAux { tree: tree_index });
    }
    Ok(MerkleDecommitmentLiftedAux {
        all_node_values: layers,
    })
}

fn decode_fri_all_values(
    tree_index: usize,
    meta: DecommitTreeMeta,
    words: &[u32],
    expected_positions: &[u32],
) -> Result<BTreeMap<usize, SecureField>, Blake2sProofAssemblyError> {
    let entries = section(
        words,
        meta.all_values_offset,
        meta.all_values_count * FRI_ALL_VALUE_WORDS,
    );
    let mut values = BTreeMap::new();
    for (entry_index, entry) in entries.chunks_exact(FRI_ALL_VALUE_WORDS).enumerate() {
        if entry[0] != expected_positions[entry_index] {
            return Err(Blake2sProofAssemblyError::QueryMismatch {
                tree: Some(tree_index),
            });
        }
        let value = decode_secure_value("FRI all values", entry_index, &entry[1..])?;
        if values.insert(entry[0] as usize, value).is_some() {
            return Err(Blake2sProofAssemblyError::QueryMismatch {
                tree: Some(tree_index),
            });
        }
    }
    Ok(values)
}

fn decode_line_poly(
    config: PcsConfig,
    words: &[u32],
) -> Result<LinePoly, Blake2sProofAssemblyError> {
    let coefficients = 1usize
        .checked_shl(config.fri_config.log_last_layer_degree_bound)
        .ok_or(Blake2sProofAssemblyError::InvalidFinalLinePolynomial)?;
    if words.len() != coefficients * SECURE_WORDS {
        return Err(Blake2sProofAssemblyError::InvalidFinalLinePolynomial);
    }
    Ok(LinePoly::new(decode_secure_values(
        "final line polynomial",
        words,
    )?))
}

fn decode_base_values(
    section_name: &'static str,
    words: &[u32],
) -> Result<Vec<BaseField>, Blake2sProofAssemblyError> {
    words
        .iter()
        .enumerate()
        .map(|(index, &word)| decode_m31(section_name, index, word))
        .collect()
}

fn decode_secure_values(
    section_name: &'static str,
    words: &[u32],
) -> Result<Vec<SecureField>, Blake2sProofAssemblyError> {
    if words.len() % SECURE_WORDS != 0 {
        return Err(Blake2sProofAssemblyError::SectionShape {
            tree: usize::MAX,
            section: section_name,
            expected: words.len().next_multiple_of(SECURE_WORDS),
            actual: words.len(),
        });
    }
    words
        .chunks_exact(SECURE_WORDS)
        .enumerate()
        .map(|(index, words)| decode_secure_value(section_name, index, words))
        .collect()
}

fn decode_secure_value(
    section_name: &'static str,
    index: usize,
    words: &[u32],
) -> Result<SecureField, Blake2sProofAssemblyError> {
    let coordinates: [Result<M31, Blake2sProofAssemblyError>; SECURE_WORDS] =
        core::array::from_fn(|coordinate| {
            decode_m31(
                section_name,
                index * SECURE_WORDS + coordinate,
                words[coordinate],
            )
        });
    Ok(SecureField::from_m31_array(
        coordinates.into_iter().collect::<Result<Vec<_>, _>>()?[..]
            .try_into()
            .expect("exact secure coordinate count"),
    ))
}

fn decode_m31(
    section_name: &'static str,
    index: usize,
    word: u32,
) -> Result<M31, Blake2sProofAssemblyError> {
    if word >= P {
        Err(Blake2sProofAssemblyError::NonCanonicalM31 {
            section: section_name,
            index,
            word,
        })
    } else {
        Ok(M31::from_u32_unchecked(word))
    }
}

fn decode_hashes(words: &[u32]) -> Vec<Blake2sHash> {
    words.chunks_exact(HASH_WORDS).map(decode_hash).collect()
}

fn decode_hash(words: &[u32]) -> Blake2sHash {
    let mut bytes = [0u8; 32];
    for (word, destination) in words.iter().zip(bytes.chunks_exact_mut(4)) {
        destination.copy_from_slice(&word.to_le_bytes());
    }
    Blake2sHash(bytes)
}

fn section(words: &[u32], offset: usize, count: usize) -> &[u32] {
    if count == 0 && offset == 0 {
        &[]
    } else {
        &words[offset..offset + count]
    }
}

fn check_count(
    role: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), Blake2sProofAssemblyError> {
    if expected == actual {
        Ok(())
    } else {
        Err(Blake2sProofAssemblyError::CountMismatch {
            role,
            expected,
            actual,
        })
    }
}

fn check_section_shape(
    tree: usize,
    section: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), Blake2sProofAssemblyError> {
    if expected == actual {
        Ok(())
    } else {
        Err(Blake2sProofAssemblyError::SectionShape {
            tree,
            section,
            expected,
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use stwo::core::channel::Blake2sChannel;
    use stwo::core::fri::{FriLayerProof, FriLayerProofAux};
    use stwo::core::pcs::TreeVec;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::proof::ExtendedStarkProof;
    use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
    use stwo::prover::backend::{CpuBackend, FromSimdColumns};
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::{prove_ex, CommitmentSchemeProver};
    use stwo_backend_testkit::{generate_reference_trace, ReferenceEval};
    use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

    use super::*;

    const HEADER_WORDS: usize = 8;
    const META_WORDS: usize = 16;

    fn reference_proof() -> ExtendedStarkProof<Blake2sMerkleHasher> {
        let simd_trace = generate_reference_trace(6);
        let log_n_rows = simd_trace[0].domain.log_size();
        let config = PcsConfig::default();
        let twiddles = CpuBackend::precompute_twiddles(
            CanonicCoset::new(log_n_rows + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        let channel = &mut Blake2sChannel::default();
        let mut commitment_scheme =
            CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        let tree_builder = commitment_scheme.tree_builder();
        tree_builder.commit(channel);
        let trace = CpuBackend::from_simd_evals(simd_trace);
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(trace);
        tree_builder.commit(channel);

        let component = FrameworkComponent::new(
            &mut TraceLocationAllocator::default(),
            ReferenceEval { log_n_rows },
            SecureField::zero(),
        );
        prove_ex::<CpuBackend, Blake2sMerkleChannel>(
            &[&component],
            channel,
            commitment_scheme,
            false,
        )
        .unwrap()
    }

    fn shape_from_reference(
        proof: &ExtendedStarkProof<Blake2sMerkleHasher>,
    ) -> Blake2sProofAssemblyShape {
        let trace_count = proof.proof.commitments.len();
        let roles: Vec<_> = match trace_count {
            3 => vec![
                TraceTreeRole::Preprocessed,
                TraceTreeRole::Base,
                TraceTreeRole::Composition,
            ],
            4 => vec![
                TraceTreeRole::Preprocessed,
                TraceTreeRole::Base,
                TraceTreeRole::Interaction,
                TraceTreeRole::Composition,
            ],
            _ => panic!("unexpected reference trace-tree count {trace_count}"),
        };
        let fri_aux: Vec<_> = core::iter::once(&proof.aux.fri.first_layer)
            .chain(&proof.aux.fri.inner_layers)
            .collect();
        // The backend-testkit fixture uses fold_step=1, hence no leaf packing.
        let query_log_size = fri_aux[0].decommitment.all_node_values.len() as u32;
        let trace_trees = roles
            .into_iter()
            .enumerate()
            .map(|(index, role)| {
                let leaf_log_size =
                    proof.aux.trace_decommitment[index].all_node_values.len() as u32;
                Blake2sTraceAssemblyShape {
                    role,
                    leaf_log_size,
                    query_log_size: if role == TraceTreeRole::Preprocessed {
                        leaf_log_size
                    } else {
                        query_log_size
                    },
                    oods_samples_per_column: proof.proof.sampled_values[index]
                        .iter()
                        .map(Vec::len)
                        .collect(),
                    commit_to_proof_column: (0..proof.proof.sampled_values[index].len()).collect(),
                }
            })
            .collect();
        let fri_trees = fri_aux
            .iter()
            .enumerate()
            .map(|(_index, layer)| {
                let evaluation_log_size = layer.decommitment.all_node_values.len() as u32;
                Blake2sFriAssemblyShape {
                    evaluation_log_size,
                    cumulative_fold: query_log_size - evaluation_log_size,
                    outgoing_fold_step: proof.proof.config.fri_config.fold_step.min(
                        evaluation_log_size
                            - (proof.proof.config.fri_config.log_last_layer_degree_bound
                                + proof.proof.config.fri_config.log_blowup_factor),
                    ),
                    log_rows_per_leaf: 0,
                }
            })
            .collect();
        Blake2sProofAssemblyShape {
            query_log_size,
            n_queries: proof.proof.config.fri_config.n_queries,
            trace_trees,
            fri_trees,
        }
    }

    fn encode_reference_decommitment(
        proof: &ExtendedStarkProof<Blake2sMerkleHasher>,
        shape: &Blake2sProofAssemblyShape,
    ) -> DecommitAssembly {
        let raw: Vec<u32> = proof
            .aux
            .unsorted_query_locations
            .iter()
            .map(|&query| query as u32)
            .collect();
        let unique: Vec<u32> = BTreeSet::from_iter(raw.iter().copied())
            .into_iter()
            .collect();
        let tree_count = shape.trace_trees.len() + shape.fri_trees.len();
        let raw_offset = HEADER_WORDS + tree_count * META_WORDS;
        let unique_offset = raw_offset + raw.len();
        let mut words = vec![0u32; unique_offset + unique.len()];
        words[0] = 0x4457_5453;
        words[1] = 1;
        words[2] = tree_count as u32;
        words[3] = raw.len() as u32;
        words[4] = unique.len() as u32;
        words[5] = raw_offset as u32;
        words[6] = unique_offset as u32;
        words[raw_offset..unique_offset].copy_from_slice(&raw);
        words[unique_offset..unique_offset + unique.len()].copy_from_slice(&unique);

        for (tree_index, trace_shape) in shape.trace_trees.iter().enumerate() {
            let start = words.len();
            let queries =
                map_trace_queries(&unique, shape.query_log_size, trace_shape.query_log_size);
            let query_offset = append(&mut words, &queries);
            let values: Vec<_> = proof.proof.queried_values[tree_index]
                .iter()
                .flatten()
                .map(|value| value.0)
                .collect();
            let values_offset = append(&mut words, &values);
            let hashes = encode_hashes(&proof.proof.decommitments[tree_index].hash_witness);
            let hash_offset = append(&mut words, &hashes);
            let aux = encode_aux(
                &proof.aux.trace_decommitment[tree_index],
                trace_shape.leaf_log_size,
            );
            let aux_offset = append(&mut words, &aux);
            let used = (words.len() - start).max(1);
            let meta = &mut words[HEADER_WORDS + tree_index * META_WORDS..][..META_WORDS];
            meta[0] = 0;
            meta[1] = trace_shape.role as u32;
            meta[2] = query_offset as u32;
            meta[3] = queries.len() as u32;
            meta[4] = values_offset as u32;
            meta[5] = values.len() as u32;
            meta[8] = hash_offset as u32;
            meta[9] = proof.proof.decommitments[tree_index].hash_witness.len() as u32;
            meta[10] = aux_offset as u32;
            meta[11] = (aux.len() / AUX_NODE_WORDS) as u32;
            meta[14] = trace_shape.leaf_log_size;
            meta[15] = used as u32;
        }

        let fri_proofs: Vec<&FriLayerProof<Blake2sMerkleHasher>> =
            core::iter::once(&proof.proof.fri_proof.first_layer)
                .chain(&proof.proof.fri_proof.inner_layers)
                .collect();
        let fri_aux: Vec<&FriLayerProofAux<Blake2sMerkleHasher>> =
            core::iter::once(&proof.aux.fri.first_layer)
                .chain(&proof.aux.fri.inner_layers)
                .collect();
        for (fri_index, ((fri_shape, layer), layer_aux)) in shape
            .fri_trees
            .iter()
            .zip(fri_proofs)
            .zip(fri_aux)
            .enumerate()
        {
            let tree_index = shape.trace_trees.len() + fri_index;
            let start = words.len();
            let queries = folded_queries(&unique, fri_shape.cumulative_fold);
            let query_offset = append(&mut words, &queries);
            let witness = encode_secure_values(&layer.fri_witness);
            let witness_offset = append(&mut words, &witness);
            let hashes = encode_hashes(&layer.decommitment.hash_witness);
            let hash_offset = append(&mut words, &hashes);
            let aux = encode_aux(&layer_aux.decommitment, fri_shape.leaf_log_size().unwrap());
            let aux_offset = append(&mut words, &aux);
            let all_values = encode_all_values(&layer_aux.all_values[0]);
            let all_values_offset = append(&mut words, &all_values);
            let used = words.len() - start;
            let meta = &mut words[HEADER_WORDS + tree_index * META_WORDS..][..META_WORDS];
            meta[0] = 1;
            meta[1] = tree_index as u32;
            meta[2] = query_offset as u32;
            meta[3] = queries.len() as u32;
            meta[6] = witness_offset as u32;
            meta[7] = layer.fri_witness.len() as u32;
            meta[8] = hash_offset as u32;
            meta[9] = layer.decommitment.hash_witness.len() as u32;
            meta[10] = aux_offset as u32;
            meta[11] = (aux.len() / AUX_NODE_WORDS) as u32;
            meta[12] = all_values_offset as u32;
            meta[13] = layer_aux.all_values[0].len() as u32;
            meta[14] = fri_shape.leaf_log_size().unwrap();
            meta[15] = used as u32;
        }
        words[7] = words.len() as u32;
        DecommitAssembly::decode(words).unwrap()
    }

    fn append(destination: &mut Vec<u32>, values: &[u32]) -> usize {
        if values.is_empty() {
            return 0;
        }
        let offset = destination.len();
        destination.extend_from_slice(values);
        offset
    }

    fn encode_hashes(hashes: &[Blake2sHash]) -> Vec<u32> {
        hashes
            .iter()
            .flat_map(|hash| {
                hash.0
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn encode_secure_values(values: &[SecureField]) -> Vec<u32> {
        values
            .iter()
            .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
            .collect()
    }

    fn encode_aux(
        aux: &MerkleDecommitmentLiftedAux<Blake2sMerkleHasher>,
        leaf_log_size: u32,
    ) -> Vec<u32> {
        let mut words = Vec::new();
        for (layer_index, layer) in aux.all_node_values.iter().enumerate() {
            let level = leaf_log_size - layer_index as u32;
            for (&index, hash) in layer {
                words.push(level);
                words.push(index as u32);
                words.extend(encode_hashes(core::slice::from_ref(hash)));
            }
        }
        words
    }

    fn encode_all_values(values: &BTreeMap<usize, SecureField>) -> Vec<u32> {
        let mut words = Vec::new();
        for (&position, value) in values {
            words.push(position as u32);
            words.extend(encode_secure_values(core::slice::from_ref(value)));
        }
        words
    }

    fn final_line_words(proof: &ExtendedStarkProof<Blake2sMerkleHasher>) -> Vec<u32> {
        encode_secure_values(&proof.proof.fri_proof.last_layer_poly)
    }

    fn assert_structurally_equal(
        expected: &ExtendedStarkProof<Blake2sMerkleHasher>,
        actual: &ExtendedStarkProof<Blake2sMerkleHasher>,
    ) {
        assert_eq!(expected.proof.config, actual.proof.config);
        assert_eq!(expected.proof.commitments.0, actual.proof.commitments.0);
        assert_eq!(
            expected.proof.sampled_values.0,
            actual.proof.sampled_values.0
        );
        assert_eq!(
            expected.proof.decommitments.len(),
            actual.proof.decommitments.len()
        );
        for (expected, actual) in expected
            .proof
            .decommitments
            .iter()
            .zip(actual.proof.decommitments.iter())
        {
            assert_eq!(expected.hash_witness, actual.hash_witness);
        }
        assert_eq!(
            expected.proof.queried_values.0,
            actual.proof.queried_values.0
        );
        assert_eq!(expected.proof.proof_of_work, actual.proof.proof_of_work);
        assert_layer_equal(
            &expected.proof.fri_proof.first_layer,
            &actual.proof.fri_proof.first_layer,
        );
        assert_eq!(
            expected.proof.fri_proof.inner_layers.len(),
            actual.proof.fri_proof.inner_layers.len()
        );
        for (expected, actual) in expected
            .proof
            .fri_proof
            .inner_layers
            .iter()
            .zip(&actual.proof.fri_proof.inner_layers)
        {
            assert_layer_equal(expected, actual);
        }
        assert_eq!(
            expected.proof.fri_proof.last_layer_poly,
            actual.proof.fri_proof.last_layer_poly
        );
        assert_eq!(
            expected.aux.unsorted_query_locations,
            actual.aux.unsorted_query_locations
        );
        assert_eq!(
            expected.aux.trace_decommitment.len(),
            actual.aux.trace_decommitment.len()
        );
        for (expected, actual) in expected
            .aux
            .trace_decommitment
            .iter()
            .zip(actual.aux.trace_decommitment.iter())
        {
            assert_eq!(expected.all_node_values, actual.all_node_values);
        }
        assert_fri_aux_equal(&expected.aux.fri.first_layer, &actual.aux.fri.first_layer);
        assert_eq!(
            expected.aux.fri.inner_layers.len(),
            actual.aux.fri.inner_layers.len()
        );
        for (expected, actual) in expected
            .aux
            .fri
            .inner_layers
            .iter()
            .zip(&actual.aux.fri.inner_layers)
        {
            assert_fri_aux_equal(expected, actual);
        }
    }

    fn assert_layer_equal(
        expected: &FriLayerProof<Blake2sMerkleHasher>,
        actual: &FriLayerProof<Blake2sMerkleHasher>,
    ) {
        assert_eq!(expected.fri_witness, actual.fri_witness);
        assert_eq!(
            expected.decommitment.hash_witness,
            actual.decommitment.hash_witness
        );
        assert_eq!(expected.commitment, actual.commitment);
    }

    fn assert_fri_aux_equal(
        expected: &FriLayerProofAux<Blake2sMerkleHasher>,
        actual: &FriLayerProofAux<Blake2sMerkleHasher>,
    ) {
        assert_eq!(expected.all_values, actual.all_values);
        assert_eq!(
            expected.decommitment.all_node_values,
            actual.decommitment.all_node_values
        );
    }

    #[test]
    fn cpu_reference_proof_round_trips_through_compact_assembly() {
        let reference = reference_proof();
        let shape = shape_from_reference(&reference);
        let decommitment = encode_reference_decommitment(&reference, &shape);
        let fri_layers: Vec<_> = core::iter::once(&reference.proof.fri_proof.first_layer)
            .chain(&reference.proof.fri_proof.inner_layers)
            .collect();
        let input = Blake2sProofAssemblyInput {
            config: reference.proof.config,
            shape,
            commitments: reference.proof.commitments.0.clone(),
            sampled_values: TreeVec(reference.proof.sampled_values.0.clone()),
            raw_queries: reference
                .aux
                .unsorted_query_locations
                .iter()
                .map(|&query| query as u32)
                .collect(),
            proof_of_work: reference.proof.proof_of_work,
            final_line_poly_words: final_line_words(&reference),
            fri_commitments: fri_layers.iter().map(|layer| layer.commitment).collect(),
            decommitment,
        };
        let assembled = assemble_blake2s_stark_proof_inner(input).unwrap();
        assert_structurally_equal(&reference, &assembled);
    }

    #[test]
    fn rejects_noncanonical_final_field_word() {
        let reference = reference_proof();
        let shape = shape_from_reference(&reference);
        let decommitment = encode_reference_decommitment(&reference, &shape);
        let fri_layers: Vec<_> = core::iter::once(&reference.proof.fri_proof.first_layer)
            .chain(&reference.proof.fri_proof.inner_layers)
            .collect();
        let mut final_words = final_line_words(&reference);
        final_words[0] = P;
        let error = assemble_blake2s_stark_proof_inner(Blake2sProofAssemblyInput {
            config: reference.proof.config,
            shape,
            commitments: reference.proof.commitments.0.clone(),
            sampled_values: TreeVec(reference.proof.sampled_values.0.clone()),
            raw_queries: reference
                .aux
                .unsorted_query_locations
                .iter()
                .map(|&query| query as u32)
                .collect(),
            proof_of_work: reference.proof.proof_of_work,
            final_line_poly_words: final_words,
            fri_commitments: fri_layers.iter().map(|layer| layer.commitment).collect(),
            decommitment,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            Blake2sProofAssemblyError::NonCanonicalM31 {
                section: "final line polynomial",
                index: 0,
                word: P,
            }
        ));
    }

    #[test]
    fn public_adapter_requires_four_starknet_trace_trees() {
        let reference = reference_proof();
        let shape = shape_from_reference(&reference);
        let decommitment = encode_reference_decommitment(&reference, &shape);
        let fri_layers: Vec<_> = core::iter::once(&reference.proof.fri_proof.first_layer)
            .chain(&reference.proof.fri_proof.inner_layers)
            .collect();
        let error = assemble_blake2s_stark_proof(Blake2sProofAssemblyInput {
            config: reference.proof.config,
            shape,
            commitments: reference.proof.commitments.0.clone(),
            sampled_values: TreeVec(reference.proof.sampled_values.0.clone()),
            raw_queries: reference
                .aux
                .unsorted_query_locations
                .iter()
                .map(|&query| query as u32)
                .collect(),
            proof_of_work: reference.proof.proof_of_work,
            final_line_poly_words: final_line_words(&reference),
            fri_commitments: fri_layers.iter().map(|layer| layer.commitment).collect(),
            decommitment,
        })
        .unwrap_err();
        assert!(matches!(
            error,
            Blake2sProofAssemblyError::CountMismatch {
                role: "strict Starknet trace trees",
                expected: 4,
                actual: 3,
            }
        ));
    }

    #[test]
    fn queried_values_restore_original_pcs_column_order() {
        assert_eq!(
            restore_proof_column_order(0, vec!["small", "large", "middle"], &[1, 2, 0]).unwrap(),
            ["middle", "small", "large"]
        );
        assert!(matches!(
            restore_proof_column_order(3, vec![1, 2], &[0, 0]),
            Err(Blake2sProofAssemblyError::InvalidColumnPermutation(3))
        ));
    }

    #[test]
    fn preprocessed_projection_preserves_downmap_collisions_until_merkle_walk() {
        assert_eq!(map_trace_queries(&[0, 1, 2, 3], 9, 12), [0, 1, 16, 17]);

        let mapped = map_trace_queries(&[0, 1, 2, 3, 4], 12, 9);
        assert_eq!(mapped, [0, 1, 0, 1, 0]);
        let walk = BTreeSet::from_iter(mapped.iter().copied())
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(walk, [0, 1]);
        assert_eq!(merkle_topology(&walk, 9), merkle_topology(&[0, 1], 9));
    }

    #[test]
    fn packed_fri_fold_three_dedups_cosets_across_boundaries() {
        let queries = [0, 0, 7, 8, 8, 15, 16, 17];
        let expanded = expanded_fri_positions(&queries, 3);
        assert_eq!(expanded, (0..24).collect::<Vec<_>>());
        assert_eq!(
            BTreeSet::from_iter(expanded.iter().map(|position| position >> 2))
                .into_iter()
                .collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 5]
        );
    }
}
