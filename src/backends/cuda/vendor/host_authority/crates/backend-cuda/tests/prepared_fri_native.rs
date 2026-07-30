//! Native CUDA gate for the prepared FRI workspace. Keeping this as an
//! integration target avoids compiling the backend's legacy CUDA-only unit-test
//! modules when running the focused graph gate.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasherGeneric};
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo_backend_cuda::{
    fri_workspace_requirements, ArenaLayout, ArenaSlotId, ArenaSlotSpec, CudaExecContext,
    DeviceArena, FriArenaSlotRequirement, FriFoldLaunchMode, FriMerkleTreeSlots,
    FriWorkspaceConfig, FriWorkspaceRequirements, FriWorkspaceSlots, PreparedFriEvaluation,
    PreparedFriGraph,
};

const INPUT: ArenaSlotId = ArenaSlotId(50_000);
const TWIDDLES: ArenaSlotId = ArenaSlotId(50_001);
const SECURE_COORDINATES: usize = 4;
const M31_MODULUS: u32 = 0x7fff_ffff;

fn workspace_slots(requirements: &FriWorkspaceRequirements) -> FriWorkspaceSlots {
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
        retained_tree_coordinate_ptrs: requirements.trees.iter().skip(1).map(|_| id()).collect(),
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

fn read_evaluation(arena: &DeviceArena, evaluation: PreparedFriEvaluation) -> Vec<u32> {
    let coordinate_len = 1usize << evaluation.log_size;
    let mut host = vec![0u32; SECURE_COORDINATES * coordinate_len];
    for coordinate in 0..SECURE_COORDINATES {
        unsafe {
            arena
                .context()
                .memcpy_d2h_async(
                    host[coordinate * coordinate_len..].as_mut_ptr().cast(),
                    evaluation
                        .values
                        .as_u32_ptr()
                        .add(coordinate * evaluation.coordinate_stride)
                        .cast(),
                    coordinate_len * core::mem::size_of::<u32>(),
                )
                .unwrap();
        }
    }
    arena.context().sync().unwrap();
    host
}

/// Host reference Merkle root over one committed FRI evaluation. The leaf
/// geometry comes from the PLAN requirement `log_rows_per_leaf`, mirroring the
/// core verifier's `pack_leaves` rule (core/fri.rs): a tree whose outgoing
/// fold step exceeds one packs four adjacent QM31 rows per leaf, while the
/// final partial-fold tree (outgoing step one) hashes a single row per leaf.
fn reference_tree_root(input: &[u32], log_size: u32, log_rows_per_leaf: u32) -> Blake2sHash {
    let coordinate_stride = 1usize << log_size;
    let rows_per_leaf = 1usize << log_rows_per_leaf;
    let mut layer: Vec<Blake2sHash> = (0..coordinate_stride >> log_rows_per_leaf)
        .map(|leaf| {
            let mut hasher = Blake2sHasherGeneric::<false>::default();
            let words: Vec<BaseField> = (0..rows_per_leaf)
                .flat_map(|offset| {
                    (0..SECURE_COORDINATES).map(move |coordinate| {
                        BaseField::from_u32_unchecked(
                            input[coordinate * coordinate_stride + rows_per_leaf * leaf + offset],
                        )
                    })
                })
                .collect();
            hasher.update_leaf(&words);
            <Blake2sHasherGeneric<false> as MerkleHasherLifted>::finalize(hasher)
        })
        .collect();
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|children| {
                <Blake2sHasherGeneric<false> as MerkleHasherLifted>::hash_children((
                    children[0],
                    children[1],
                ))
            })
            .collect();
    }
    layer[0]
}

fn reference_fold_round(
    input: &[u32],
    input_log_size: u32,
    twiddles: &[u32],
    fold_step: u32,
    mut alpha: SecureField,
    first_fold_is_circle: bool,
) -> Vec<u32> {
    let input_stride = 1usize << input_log_size;
    let mut values: Vec<SecureField> = (0..input_stride)
        .map(|row| {
            SecureField::from_m31_array(std::array::from_fn(|coordinate| {
                BaseField::from_u32_unchecked(input[coordinate * input_stride + row])
            }))
        })
        .collect();
    let twiddle_words = twiddles.len();
    for fold_index in 0..fold_step {
        let circle_fold = first_fold_is_circle && fold_index == 0;
        let output_len = values.len() / 2;
        let twiddle_offset = if circle_fold {
            twiddle_words - output_len
        } else {
            twiddle_words - values.len()
        };
        let next = (0..output_len)
            .map(|index| {
                let x_inverse = if circle_fold {
                    let k = index >> 2;
                    match index & 3 {
                        0 => BaseField::from_u32_unchecked(twiddles[twiddle_offset + 2 * k + 1]),
                        1 => -BaseField::from_u32_unchecked(twiddles[twiddle_offset + 2 * k + 1]),
                        2 => -BaseField::from_u32_unchecked(twiddles[twiddle_offset + 2 * k]),
                        _ => BaseField::from_u32_unchecked(twiddles[twiddle_offset + 2 * k]),
                    }
                } else {
                    BaseField::from_u32_unchecked(twiddles[twiddle_offset + index])
                };
                let left = values[2 * index];
                let right = values[2 * index + 1];
                let f0 = left + right;
                let f1 = (left - right) * SecureField::from(x_inverse);
                f0 + alpha * f1
            })
            .collect();
        values = next;
        alpha *= alpha;
    }

    let mut coordinate_major = vec![0u32; SECURE_COORDINATES * values.len()];
    for (row, value) in values.into_iter().enumerate() {
        for (coordinate, felt) in value.to_m31_array().into_iter().enumerate() {
            coordinate_major[coordinate * (1usize << (input_log_size - fold_step)) + row] = felt.0;
        }
    }
    coordinate_major
}

/// Eager and captured execution use the exact same prepared methods and stable
/// addresses for both the packed first-layer tree and a multi-fold round.
#[test]
fn eager_and_capture_match() {
    let config = FriWorkspaceConfig {
        fri: FriConfig::new(1, 1, 16, 3),
        circle_log_size: 9,
        twiddle_log_size: 8,
    };
    let requirements = fri_workspace_requirements(config).unwrap();
    // Pin the protocol packing profile (core verifier `pack_leaves` rule):
    // trees 0 and 1 fold outward by three and pack four rows per leaf; tree 2
    // folds outward by one and commits UNPACKED, one QM31 row per leaf.
    assert_eq!(
        requirements
            .trees
            .iter()
            .map(|tree| (tree.outgoing_fold_step, tree.log_rows_per_leaf))
            .collect::<Vec<_>>(),
        vec![(3, 2), (3, 2), (1, 0)]
    );
    let slots = workspace_slots(&requirements);
    let mut requested = requirements.arena_slot_requirements(&slots).unwrap();
    requested.extend([
        FriArenaSlotRequirement {
            id: INPUT,
            len_words: SECURE_COORDINATES * (1usize << config.circle_log_size),
            alignment_words: 1,
        },
        FriArenaSlotRequirement {
            id: TWIDDLES,
            len_words: requirements.twiddle_words,
            alignment_words: 1,
        },
    ]);

    let mut offset = 0usize;
    let mut specs = Vec::with_capacity(requested.len());
    for requirement in requested {
        offset = offset.next_multiple_of(requirement.alignment_words);
        specs.push(ArenaSlotSpec {
            id: requirement.id,
            offset_words: offset,
            len_words: requirement.len_words,
            alignment_words: requirement.alignment_words,
        });
        offset += requirement.len_words;
    }
    let arena = DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap();
    let input = arena.bind(INPUT).unwrap();
    let twiddles = arena.bind(TWIDDLES).unwrap();
    let host_input: Vec<u32> = (0..input.len_words())
        .map(|index| (index as u32 * 17 + 3) % M31_MODULUS)
        .collect();
    let host_twiddles: Vec<u32> = (0..twiddles.len_words())
        .map(|index| (index as u32 * 29 + 1) % M31_MODULUS)
        .collect();
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                input.as_void_ptr(),
                host_input.as_ptr().cast(),
                input.len_bytes(),
            )
            .unwrap();
        arena
            .context()
            .memcpy_h2d_async(
                twiddles.as_void_ptr(),
                host_twiddles.as_ptr().cast(),
                twiddles.len_bytes(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();

    let prepared = PreparedFriGraph::prepare(&arena, config, input, twiddles, &slots).unwrap();

    prepared.launch_first_tree().unwrap();
    let eager_root = prepared.read_tree_root(0).unwrap();
    assert_eq!(
        eager_root,
        reference_tree_root(
            &host_input,
            config.circle_log_size,
            requirements.trees[0].log_rows_per_leaf
        )
    );
    let capture = arena.context().capture().unwrap();
    prepared.launch_first_tree().unwrap();
    let tree_graph = capture.finish().unwrap();
    tree_graph.launch(arena.context()).unwrap();
    let captured_root = prepared.read_tree_root(0).unwrap();
    assert_eq!(eager_root, captured_root);
    drop(tree_graph);

    let alpha = SecureField::from_u32_unchecked(1, 3, 5, 7);
    for round_index in 0..prepared.round_count() {
        prepared
            .upload_round_challenge_at_transcript_boundary(round_index, alpha)
            .unwrap();
    }

    // Host reference chain over every round: round 0 starts with the
    // circle-to-line fold, later rounds are line folds only, and the final
    // round is the partial `fold_step == 1` fold.
    let mut reference_rounds: Vec<Vec<u32>> = Vec::new();
    let mut reference_input = host_input.clone();
    let mut reference_log_size = config.circle_log_size;
    for (round_index, round) in requirements.rounds.iter().enumerate() {
        reference_input = reference_fold_round(
            &reference_input,
            reference_log_size,
            &host_twiddles,
            round.fold_step,
            alpha,
            round_index == 0,
        );
        reference_log_size = round.output_log_size;
        reference_rounds.push(reference_input.clone());
    }

    // Both fold lanes run in one invocation. `PerFold` is the proven baseline
    // (three fold kernels per complete round); `FusedTriple` must produce
    // byte-identical snapshots, roots and final evaluation with ONE 8-to-1
    // kernel per complete round. The final partial round (fold_step == 1)
    // exercises the fused lane's fail-closed fallback to the per-fold kernel.
    let mut per_mode_results = Vec::new();
    for (mode, fold_kernels_per_triple_round) in [
        (FriFoldLaunchMode::PerFold, 3u64),
        (FriFoldLaunchMode::FusedTriple, 1u64),
    ] {
        arena.context().reset_telemetry();
        prepared.launch_round_with_mode(0, mode).unwrap();
        arena.context().sync().unwrap();
        assert_eq!(
            arena.context().telemetry().d2d_bytes,
            (requirements.trees[1].evaluation_words * core::mem::size_of::<u32>()) as u64
        );
        let eager_inner = read_evaluation(&arena, prepared.tree_evaluation(1).unwrap());
        assert_eq!(eager_inner, reference_rounds[0], "mode {mode:?}");
        let eager_inner_root = prepared.read_tree_root(1).unwrap();
        assert_eq!(
            eager_inner_root,
            reference_tree_root(
                &eager_inner,
                requirements.trees[1].evaluation_log_size,
                requirements.trees[1].log_rows_per_leaf
            )
        );

        arena.context().reset_telemetry();
        let capture = arena.context().capture().unwrap();
        prepared.launch_round_with_mode(0, mode).unwrap();
        assert_eq!(
            arena.context().telemetry().d2d_bytes,
            (requirements.trees[1].evaluation_words * core::mem::size_of::<u32>()) as u64
        );
        let fold_graph = capture.finish().unwrap();
        arena.context().reset_telemetry();
        fold_graph.launch(arena.context()).unwrap();
        let captured_inner = read_evaluation(&arena, prepared.tree_evaluation(1).unwrap());
        assert_eq!(eager_inner, captured_inner, "mode {mode:?}");
        assert_eq!(eager_inner_root, prepared.read_tree_root(1).unwrap());
        let replay = arena.context().telemetry();
        assert_eq!(replay.graph_launches, 1);
        assert_eq!(
            replay.kernel_launches,
            fold_kernels_per_triple_round + requirements.trees[1].layers_bottom_up.len() as u64,
            "mode {mode:?}: retaining an inner codeword must add memcpy nodes, \
             not kernel nodes, and the fused lane must fold as ONE kernel"
        );
        drop(fold_graph);

        for round_index in 1..prepared.round_count() {
            prepared.launch_round_with_mode(round_index, mode).unwrap();
        }
        let second_inner = read_evaluation(&arena, prepared.tree_evaluation(2).unwrap());
        assert_eq!(second_inner, reference_rounds[1], "mode {mode:?}");
        let second_inner_root = prepared.read_tree_root(2).unwrap();
        assert_eq!(
            second_inner_root,
            reference_tree_root(
                &second_inner,
                requirements.trees[2].evaluation_log_size,
                requirements.trees[2].log_rows_per_leaf
            ),
            "mode {mode:?}: tree-2 root disagrees with the reference root of its OWN \
             (already equality-checked) evaluation"
        );
        let final_evaluation = read_evaluation(&arena, prepared.final_evaluation());
        assert_eq!(
            final_evaluation,
            *reference_rounds.last().unwrap(),
            "mode {mode:?}: the partial final round must match the reference"
        );
        assert_eq!(
            eager_inner,
            read_evaluation(&arena, prepared.tree_evaluation(1).unwrap()),
            "later ping/pong folds overwrote a committed FRI tree snapshot"
        );
        per_mode_results.push((
            eager_inner,
            eager_inner_root,
            second_inner,
            second_inner_root,
            final_evaluation,
        ));
    }
    assert_eq!(
        per_mode_results[0], per_mode_results[1],
        "fused triple folds must be byte-identical to the per-fold lane"
    );
}
