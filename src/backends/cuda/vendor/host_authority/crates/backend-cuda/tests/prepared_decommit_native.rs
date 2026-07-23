#![cfg(stwo_cuda_link)]

use std::collections::BTreeSet;
use std::ffi::c_void;

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::prover::backend::CpuBackend;
use stwo::prover::vcs_lifted::prover::MerkleProverLifted;
use stwo_backend_cuda::{
    decommit_workspace_requirements, ArenaLayout, ArenaSlotId, ArenaSlotSpec, CudaExecContext,
    DecommitColumnGeometry, DecommitColumnSource, DecommitSourceMode, DecommitTreeGeometry,
    DecommitTreeRequirements, DecommitTreeSlots, DecommitTreeSources, DecommitWorkspaceConfig,
    DecommitWorkspaceRequirements, DecommitWorkspaceSlots, DeviceArena, FriDecommitGeometry,
    FriDecommitOwnedSources, FriDecommitSlots, PreparedDecommitGraph, TraceDecommitGeometry,
    TraceDecommitSlots, TraceDecommitSources, TraceSourceGroup, TraceSourceGroupGeometry,
    TraceSourceGroupSlots, TraceTreeRole, DECOMMIT_HASH_ALIGNMENT_WORDS,
    DECOMMIT_POINTER_ALIGNMENT_WORDS,
};

struct Slots {
    next_id: u32,
    next_word: usize,
    specs: Vec<ArenaSlotSpec>,
}

impl Slots {
    fn new() -> Self {
        Self {
            next_id: 1,
            next_word: 0,
            specs: Vec::new(),
        }
    }

    fn alloc(&mut self, words: usize, alignment: usize) -> ArenaSlotId {
        self.next_word = self.next_word.next_multiple_of(alignment);
        let id = ArenaSlotId(self.next_id);
        self.next_id += 1;
        self.specs.push(ArenaSlotSpec {
            id,
            offset_words: self.next_word,
            len_words: words.max(1),
            alignment_words: alignment,
        });
        self.next_word += words.max(1);
        id
    }
}

fn workspace_slots(
    requirements: &DecommitWorkspaceRequirements,
    allocator: &mut Slots,
    assembly_slot_words: usize,
) -> DecommitWorkspaceSlots {
    let mut trees = Vec::new();
    for tree in &requirements.trees {
        match tree {
            DecommitTreeRequirements::Trace(tree) => {
                trees.push(DecommitTreeSlots::Trace(TraceDecommitSlots {
                    evaluation_ptrs: allocator.alloc(
                        tree.evaluation_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ),
                    evaluation_log_sizes: allocator.alloc(tree.evaluation_log_words, 1),
                    retained_layers_by_log: allocator.alloc(
                        tree.retained_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ),
                    sparse_level_offsets: allocator
                        .alloc(tree.sparse_level_offsets.len().max(1), 1),
                    groups: tree
                        .groups
                        .iter()
                        .map(|group| TraceSourceGroupSlots {
                            coefficient_ptrs: group.coefficient_pointer_words.map(|words| {
                                allocator.alloc(words, DECOMMIT_POINTER_ALIGNMENT_WORDS)
                            }),
                            coefficient_sizes: group
                                .coefficient_size_words
                                .map(|words| allocator.alloc(words, 1)),
                            lde_output_ptrs: group.coefficient_pointer_words.map(|words| {
                                allocator.alloc(words, DECOMMIT_POINTER_ALIGNMENT_WORDS)
                            }),
                            lde_tile: group.lde_tile_words.map(|words| allocator.alloc(words, 1)),
                        })
                        .collect(),
                }));
            }
            DecommitTreeRequirements::Fri(tree) => {
                trees.push(DecommitTreeSlots::Fri(FriDecommitSlots {
                    coordinate_ptrs: allocator.alloc(
                        tree.coordinate_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ),
                    retained_layers_by_log: allocator.alloc(
                        tree.retained_pointer_words,
                        DECOMMIT_POINTER_ALIGNMENT_WORDS,
                    ),
                }));
            }
        }
    }
    DecommitWorkspaceSlots {
        unique_queries: allocator.alloc(requirements.unique_query_words, 1),
        mapped_queries: allocator.alloc(requirements.mapped_query_words, 1),
        walk_queries: allocator.alloc(requirements.walk_query_words, 1),
        walk_scratch: allocator.alloc(requirements.walk_query_words, 1),
        expanded_positions: allocator.alloc(requirements.expanded_position_words, 1),
        sparse_indices: allocator.alloc(requirements.sparse_index_words, 1),
        sparse_hashes: allocator.alloc(
            requirements.sparse_hash_words,
            DECOMMIT_HASH_ALIGNMENT_WORDS,
        ),
        counts: allocator.alloc(requirements.count_words, 1),
        assembly: allocator.alloc(assembly_slot_words, 1),
        trees,
    }
}

unsafe fn upload_words(arena: &DeviceArena, id: ArenaSlotId, words: &[u32]) {
    let destination = arena.bind(id).unwrap();
    arena
        .context()
        .memcpy_h2d_async(
            destination.as_void_ptr(),
            words.as_ptr().cast::<c_void>(),
            words.len() * core::mem::size_of::<u32>(),
        )
        .unwrap();
}

unsafe fn upload_hashes(arena: &DeviceArena, id: ArenaSlotId, hashes: &[Blake2sHash]) {
    let destination = arena.bind(id).unwrap();
    arena
        .context()
        .memcpy_h2d_async(
            destination.as_void_ptr(),
            hashes.as_ptr().cast::<c_void>(),
            core::mem::size_of_val(hashes),
        )
        .unwrap();
}

fn hash_words(hash: Blake2sHash) -> Vec<u32> {
    hash.0
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect()
}

fn witness_words(hashes: &[Blake2sHash]) -> Vec<u32> {
    hashes.iter().flat_map(|&hash| hash_words(hash)).collect()
}

fn aux_words(
    layers: &[std::collections::BTreeMap<usize, Blake2sHash>],
    leaf_log_size: u32,
) -> Vec<u32> {
    let mut words = Vec::new();
    for (layer_index, layer) in layers.iter().enumerate() {
        let level = leaf_log_size - layer_index as u32;
        for (&index, &hash) in layer {
            words.push(level);
            words.push(index as u32);
            words.extend(hash_words(hash));
        }
    }
    words
}

#[test]
fn eager_and_captured_trace_and_fri_decommit_match_cpu_layout() {
    const LOG_SIZE: u32 = 4;
    const TRACE_UNRETAINED: u32 = 2;
    const BUNDLE_PREFIX_WORDS: usize = 11;
    const BUNDLE_SUFFIX_WORDS: usize = 7;
    const BUNDLE_CANARY: u32 = 0xcafe_babe;
    let raw_queries = [7u32, 7, 3, 7, 3];
    let trace_column: Vec<_> = (0..1 << LOG_SIZE)
        .map(|value| BaseField::from_u32_unchecked(if value == 3 { P } else { value as u32 + 11 }))
        .collect();
    let trace_tree = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
        vec![&trace_column],
        LOG_SIZE,
        0,
    );
    let fri_columns: Vec<Vec<_>> = (0..4)
        .map(|coordinate| {
            (0..1 << LOG_SIZE)
                .map(|row| BaseField::from_u32_unchecked((100 * coordinate + row + 1) as u32))
                .collect()
        })
        .collect();
    let fri_tree = MerkleProverLifted::<CpuBackend, Blake2sMerkleHasher>::commit(
        fri_columns.iter().collect(),
        LOG_SIZE,
        0,
    );

    let config = DecommitWorkspaceConfig {
        query_log_size: LOG_SIZE,
        n_queries: raw_queries.len() as u32,
        trees: vec![
            DecommitTreeGeometry::Trace(TraceDecommitGeometry {
                role: TraceTreeRole::Base,
                tree_query_log_size: LOG_SIZE,
                leaf_log_size: LOG_SIZE,
                unretained_bottom_layers: TRACE_UNRETAINED,
                groups: vec![TraceSourceGroupGeometry {
                    mode: DecommitSourceMode::ResidentEvaluations,
                    columns: vec![DecommitColumnGeometry {
                        coefficient_log_size: LOG_SIZE - 1,
                        evaluation_log_size: LOG_SIZE,
                    }],
                }],
            }),
            DecommitTreeGeometry::Fri(FriDecommitGeometry {
                fri_tree_index: 0,
                evaluation_log_size: LOG_SIZE,
                cumulative_fold: 0,
                outgoing_fold_step: 3,
                log_rows_per_leaf: 0,
            }),
        ],
    };
    let requirements = decommit_workspace_requirements(config.clone()).unwrap();
    let mut allocator = Slots::new();
    let bundle_words = BUNDLE_PREFIX_WORDS + requirements.assembly_words + BUNDLE_SUFFIX_WORDS;
    let slots = workspace_slots(&requirements, &mut allocator, bundle_words);
    requirements.arena_slot_requirements(&slots).unwrap();

    let raw_slot = allocator.alloc(raw_queries.len(), 1);
    let trace_eval_slot = allocator.alloc(trace_column.len(), 1);
    let trace_layer_slots: Vec<_> = trace_tree
        .layers
        .iter()
        .map(|layer| allocator.alloc(layer.len() * 8, DECOMMIT_HASH_ALIGNMENT_WORDS))
        .collect();
    let fri_eval_slot = allocator.alloc(fri_columns.len() * fri_columns[0].len(), 1);
    let fri_layer_slots: Vec<_> = fri_tree
        .layers
        .iter()
        .map(|layer| allocator.alloc(layer.len() * 8, DECOMMIT_HASH_ALIGNMENT_WORDS))
        .collect();
    let layout = ArenaLayout::new(allocator.next_word, &allocator.specs).unwrap();
    let arena = DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap();

    unsafe {
        upload_words(&arena, raw_slot, &raw_queries);
        upload_words(
            &arena,
            trace_eval_slot,
            &trace_column.iter().map(|value| value.0).collect::<Vec<_>>(),
        );
        for (&slot, layer) in trace_layer_slots.iter().zip(&trace_tree.layers) {
            upload_hashes(&arena, slot, layer);
        }
        let fri_words: Vec<_> = fri_columns
            .iter()
            .flat_map(|column| column.iter().map(|value| value.0))
            .collect();
        upload_words(&arena, fri_eval_slot, &fri_words);
        for (&slot, layer) in fri_layer_slots.iter().zip(&fri_tree.layers) {
            upload_hashes(&arena, slot, layer);
        }
    }
    arena.context().sync().unwrap();

    let proof_bundle = arena.bind(slots.assembly).unwrap();
    let direct_tail = proof_bundle
        .checked_subslice(BUNDLE_PREFIX_WORDS, requirements.assembly_words)
        .unwrap();
    unsafe {
        arena
            .context()
            .fill_u32_async(
                proof_bundle.as_u32_ptr(),
                BUNDLE_CANARY,
                proof_bundle.len_words(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();

    let sources = vec![
        DecommitTreeSources::Trace(TraceDecommitSources {
            groups: vec![TraceSourceGroup {
                columns: vec![DecommitColumnSource::ResidentEvaluation(
                    arena.bind(trace_eval_slot).unwrap(),
                )],
            }],
            retained_layers_bottom_up: trace_layer_slots
                .iter()
                .take((LOG_SIZE - TRACE_UNRETAINED + 1) as usize)
                .rev()
                .map(|&slot| arena.bind(slot).unwrap())
                .collect(),
        }),
        DecommitTreeSources::Fri(FriDecommitOwnedSources {
            evaluation: arena.bind(fri_eval_slot).unwrap(),
            coordinate_stride: 1 << LOG_SIZE,
            retained_layers_bottom_up: fri_layer_slots
                .iter()
                .rev()
                .map(|&slot| arena.bind(slot).unwrap())
                .collect(),
        }),
    ];
    let prepared = PreparedDecommitGraph::prepare_into(
        &arena,
        config,
        arena.bind(raw_slot).unwrap(),
        None,
        &sources,
        &slots,
        direct_tail,
    )
    .unwrap();
    assert_eq!(prepared.assembly_slice().id(), proof_bundle.id());
    assert_eq!(
        prepared.assembly_slice().as_u32_ptr(),
        direct_tail.as_u32_ptr()
    );
    assert_eq!(
        prepared.assembly_slice().len_words(),
        requirements.assembly_words
    );

    prepared.launch_query_normalization().unwrap();
    prepared.launch_trace_tree(0).unwrap();
    prepared.launch_fri_tree(1).unwrap();
    let eager = prepared.read_assembly_once().unwrap();
    let read_bundle = || {
        let mut words = vec![0_u32; proof_bundle.len_words()];
        unsafe {
            arena
                .context()
                .memcpy_d2h_async(
                    words.as_mut_ptr().cast(),
                    proof_bundle.as_void_ptr().cast_const(),
                    proof_bundle.len_bytes(),
                )
                .unwrap();
        }
        arena.context().sync().unwrap();
        words
    };
    let eager_bundle = read_bundle();
    assert!(eager_bundle[..BUNDLE_PREFIX_WORDS]
        .iter()
        .all(|&word| word == BUNDLE_CANARY));
    assert_eq!(
        &eager_bundle[BUNDLE_PREFIX_WORDS..BUNDLE_PREFIX_WORDS + eager.words().len()],
        eager.words()
    );
    assert!(
        eager_bundle[BUNDLE_PREFIX_WORDS + requirements.assembly_words..]
            .iter()
            .all(|&word| word == BUNDLE_CANARY)
    );

    unsafe {
        arena
            .context()
            .fill_u32_async(
                proof_bundle.as_u32_ptr(),
                BUNDLE_CANARY,
                proof_bundle.len_words(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();

    let capture = arena.context().capture().unwrap();
    prepared.launch_query_normalization().unwrap();
    prepared.launch_trace_tree(0).unwrap();
    prepared.launch_fri_tree(1).unwrap();
    let graph = capture.finish().unwrap();
    graph.launch(arena.context()).unwrap();
    let captured = prepared.read_assembly_once().unwrap();
    assert_eq!(eager.words(), captured.words(), "captured layout drift");
    let captured_bundle = read_bundle();
    assert_eq!(captured_bundle, eager_bundle, "whole bundle drift");
    assert_eq!(eager.raw_queries(), raw_queries);
    assert_eq!(eager.unique_queries(), [3, 7]);

    let sorted_queries = [3usize, 7];
    let (trace_values, trace_decommitment) =
        trace_tree.decommit(&sorted_queries, vec![&trace_column]);
    let trace_meta = eager.trees[0];
    assert_eq!(
        &eager.words()
            [trace_meta.values_offset..trace_meta.values_offset + trace_meta.values_count],
        trace_values[0]
            .iter()
            .map(|value| value.0)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        &eager.words()[trace_meta.hash_witness_offset
            ..trace_meta.hash_witness_offset + trace_meta.hash_witness_count * 8],
        witness_words(&trace_decommitment.decommitment.hash_witness)
    );
    assert_eq!(
        &eager.words()[trace_meta.aux_offset..trace_meta.aux_offset + trace_meta.aux_count * 10],
        aux_words(&trace_decommitment.aux.all_node_values, LOG_SIZE)
    );

    let expanded = (0usize..8).collect::<Vec<_>>();
    let (_, fri_decommitment) = fri_tree.decommit(&expanded, Vec::new());
    let fri_meta = eager.trees[1];
    let query_set = BTreeSet::from(sorted_queries);
    let expected_fri_witness: Vec<_> = expanded
        .iter()
        .filter(|position| !query_set.contains(position))
        .flat_map(|&position| fri_columns.iter().map(move |column| column[position].0))
        .collect();
    assert_eq!(
        &eager.words()[fri_meta.fri_witness_offset
            ..fri_meta.fri_witness_offset + fri_meta.fri_witness_count * 4],
        expected_fri_witness
    );
    assert_eq!(
        &eager.words()[fri_meta.hash_witness_offset
            ..fri_meta.hash_witness_offset + fri_meta.hash_witness_count * 8],
        witness_words(&fri_decommitment.decommitment.hash_witness)
    );
    assert_eq!(
        &eager.words()[fri_meta.aux_offset..fri_meta.aux_offset + fri_meta.aux_count * 10],
        aux_words(&fri_decommitment.aux.all_node_values, LOG_SIZE)
    );
    let expected_all_values: Vec<_> = expanded
        .iter()
        .flat_map(|&position| {
            core::iter::once(position as u32)
                .chain(fri_columns.iter().map(move |column| column[position].0))
        })
        .collect();
    assert_eq!(
        &eager.words()[fri_meta.all_values_offset
            ..fri_meta.all_values_offset + fri_meta.all_values_count * 5],
        expected_all_values
    );
}
