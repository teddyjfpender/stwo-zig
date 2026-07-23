//! Native A/B gate for the extracted column-free Merkle suffix.

#![cfg(stwo_cuda_link)]

use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher};
use stwo_backend_cuda::{
    merkle_from_leaves_requirements, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CommitLaunchKind, CommitWorkspaceConfig, CudaExecContext, DeviceArena,
    MerkleFromLeavesRequirements, MerkleFromLeavesSlots, PreparedMerkleFromLeaves,
};

fn slots(requirements: &MerkleFromLeavesRequirements) -> MerkleFromLeavesSlots {
    MerkleFromLeavesSlots {
        leaves: ArenaSlotId(1),
        merkle_scratch: requirements.merkle_scratch_words.map(|_| ArenaSlotId(2)),
        retained_layers: requirements
            .retained_layers
            .iter()
            .enumerate()
            .map(|(index, _)| ArenaSlotId(10 + index as u32))
            .collect(),
        tail_level_ptrs: requirements.tail_pointer_words.map(|_| ArenaSlotId(20)),
        tail_outputs: requirements
            .tail_outputs
            .iter()
            .enumerate()
            .map(|(index, _)| ArenaSlotId(30 + index as u32))
            .collect(),
    }
}

fn arena(
    requirements: &MerkleFromLeavesRequirements,
    slots: &MerkleFromLeavesSlots,
) -> DeviceArena {
    let requested = requirements.arena_slot_requirements(slots).unwrap();
    let mut offset = 0usize;
    let specs = requested
        .into_iter()
        .map(|requirement| {
            offset = offset.next_multiple_of(requirement.alignment_words);
            let spec = ArenaSlotSpec {
                id: requirement.id,
                offset_words: offset,
                len_words: requirement.len_words,
                alignment_words: requirement.alignment_words,
            };
            offset += requirement.len_words;
            spec
        })
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

fn upload_leaves(arena: &DeviceArena, slot: ArenaSlotId, leaves: &[Blake2sHash]) {
    let destination = arena.bind(slot).unwrap();
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                leaves.as_ptr().cast(),
                core::mem::size_of_val(leaves),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
}

fn read_hashes(arena: &DeviceArena, source: ArenaSlice) -> Vec<Blake2sHash> {
    let mut hashes = vec![Blake2sHash::default(); source.len_words() / 8];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                hashes.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                core::mem::size_of_val(hashes.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    hashes
}

fn cpu_layers(mut layer: Vec<Blake2sHash>) -> Vec<Vec<Blake2sHash>> {
    let mut layers = vec![layer.clone()];
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| Blake2sHasher::concat_and_hash(&pair[0], &pair[1]))
            .collect();
        layers.push(layer.clone());
    }
    layers
}

#[test]
fn extracted_suffix_per_level_and_fused_have_identical_bindings_layers_and_root() {
    let config = CommitWorkspaceConfig {
        log_blowup_factor: 1,
        lifting_log_size: 6,
        unretained_bottom_layers: 4,
        max_fused_tail_levels: 2,
    };
    let requirements = merkle_from_leaves_requirements(config).unwrap();
    let leaves = (0u32..64)
        .map(|row| Blake2sHasher::hash(&row.to_le_bytes()))
        .collect::<Vec<_>>();
    let expected = cpu_layers(leaves.clone());
    let mut roots = Vec::new();
    let mut retained_ids = Vec::new();
    for fused in [false, true] {
        let slots = slots(&requirements);
        let arena = arena(&requirements, &slots);
        upload_leaves(&arena, slots.leaves, &leaves);
        let prepared = PreparedMerkleFromLeaves::prepare_with_interior_mode(
            &arena,
            config,
            &requirements,
            &slots,
            fused,
        )
        .unwrap();
        assert_eq!(prepared.leaves().id(), slots.leaves);
        prepared.launch().unwrap();
        let actual_layers = prepared
            .retained_layers_bottom_up()
            .iter()
            .copied()
            .map(|slice| read_hashes(&arena, slice))
            .collect::<Vec<_>>();
        assert_eq!(
            actual_layers,
            vec![
                expected[4].clone(),
                expected[5].clone(),
                expected[6].clone()
            ]
        );
        roots.push(read_hashes(&arena, prepared.root_slice())[0]);
        retained_ids.push(
            prepared
                .retained_layers_bottom_up()
                .iter()
                .map(|slice| slice.id())
                .collect::<Vec<_>>(),
        );
        let kinds = prepared.launch_sequence().collect::<Vec<_>>();
        if fused {
            assert!(matches!(kinds[0], CommitLaunchKind::FusedInterior4 { .. }));
        } else {
            assert_eq!(
                kinds
                    .iter()
                    .filter(|kind| matches!(kind, CommitLaunchKind::InteriorLayer { .. }))
                    .count(),
                4
            );
        }
        assert!(matches!(
            kinds.last(),
            Some(CommitLaunchKind::FusedTail { .. })
        ));
    }
    assert_eq!(roots, vec![expected[6][0], expected[6][0]]);
    assert_eq!(retained_ids[0], retained_ids[1]);
}
