use std::collections::BTreeMap;

use stwo_backend_cuda::{
    compact_domain_arena_slot_requirements, ArenaLayout, ArenaSlotId, ArenaSlotSpec,
    CommitArenaSlotRequirement, CommitProgram, CommitWorkspaceConfig, CompactDomainProgram,
    CompositionSplitPointerSlots, CompositionSplitProgram, CudaExecContext, DeviceArena,
    DomainCooperativeProgram, MerkleFromLeavesSlots, ProgressiveBatchSlots,
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
    ProgressiveCommitWorkspaceRequirements, ProgressiveCommitWorkspaceSlots,
    ProgressiveLeafWorkspaceSlots, ProgressiveNttLeafFusionMode,
};

use super::{
    ids, BASELINE_COEFFICIENT_BASE, BASELINE_OUTPUT_BASE, BASELINE_SOURCE_BASE,
    BASELINE_SOURCE_POINTERS, CANDIDATE_OUTPUT_BASE, CANDIDATE_OUTPUT_POINTERS,
    CANDIDATE_SOURCE_BASE, CANDIDATE_SOURCE_POINTERS, COMPOSITION_RETAINED_COLUMNS,
    COMPOSITION_SOURCE_COORDINATES, FORWARD_TWIDDLES, GUARD_WORDS, INVERSE_TWIDDLES,
};

pub(super) fn programs(
    log_size: u32,
) -> (
    CommitProgram,
    DomainCooperativeProgram,
    CompactDomainProgram,
) {
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: log_size,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 12,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: log_size,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![log_size - 1; COMPOSITION_RETAINED_COLUMNS],
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    (base, domain, compact)
}

pub(super) fn workspace_slots(
    requirements: &ProgressiveCommitWorkspaceRequirements,
    first_id: u32,
) -> ProgressiveCommitWorkspaceSlots {
    let mut next = first_id;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    let slab = id();
    ProgressiveCommitWorkspaceSlots {
        leaves: ProgressiveLeafWorkspaceSlots {
            lde_scratch: requirements.leaves.lde_scratch_words.map(|_| id()),
            state_ping: slab,
            state_pong: requirements.leaves.state_pong_words.map(|_| slab),
            leaf_hashes: slab,
            batches: requirements
                .leaves
                .batches
                .iter()
                .map(|_| ProgressiveBatchSlots {
                    coefficient_ptrs: id(),
                    coefficient_sizes: id(),
                    output_ptrs: id(),
                })
                .collect(),
        },
        merkle: MerkleFromLeavesSlots {
            leaves: slab,
            merkle_scratch: requirements.merkle.merkle_scratch_words.map(|_| slab),
            retained_layers: requirements
                .merkle
                .retained_layers
                .iter()
                .map(|_| id())
                .collect(),
            tail_level_ptrs: requirements.merkle.tail_pointer_words.map(|_| id()),
            tail_outputs: requirements
                .merkle
                .tail_outputs
                .iter()
                .map(|_| id())
                .collect(),
        },
    }
}

fn insert_requirement(
    requirements: &mut BTreeMap<ArenaSlotId, (usize, usize)>,
    requirement: CommitArenaSlotRequirement,
) {
    requirements
        .entry(requirement.id)
        .and_modify(|current| {
            current.0 = current.0.max(requirement.len_words);
            current.1 = current.1.max(requirement.alignment_words);
        })
        .or_insert((requirement.len_words, requirement.alignment_words));
}

fn insert_data(
    requirements: &mut BTreeMap<ArenaSlotId, (usize, usize)>,
    id: ArenaSlotId,
    words: usize,
    alignment_words: usize,
) {
    assert!(requirements.insert(id, (words, alignment_words)).is_none());
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_arena(
    log_size: u32,
    base: &CommitProgram,
    domain: &DomainCooperativeProgram,
    compact: &CompactDomainProgram,
    split: CompositionSplitProgram,
    baseline_slots: &ProgressiveCommitWorkspaceSlots,
    candidate_slots: &ProgressiveCommitWorkspaceSlots,
) -> DeviceArena {
    let rows = 1usize << log_size;
    let half = rows / 2;
    let mut requirements = BTreeMap::new();
    for (id, words, alignment) in [
        (INVERSE_TWIDDLES, half, 1),
        (FORWARD_TWIDDLES, half, 1),
        (
            BASELINE_SOURCE_POINTERS,
            COMPOSITION_SOURCE_COORDINATES * core::mem::size_of::<usize>().div_ceil(4),
            core::mem::align_of::<usize>().div_ceil(4),
        ),
    ] {
        insert_data(&mut requirements, id, words, alignment);
    }
    for id in ids::<COMPOSITION_SOURCE_COORDINATES>(BASELINE_SOURCE_BASE)
        .into_iter()
        .chain(ids::<COMPOSITION_SOURCE_COORDINATES>(CANDIDATE_SOURCE_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(BASELINE_OUTPUT_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(CANDIDATE_OUTPUT_BASE))
    {
        insert_data(&mut requirements, id, rows + GUARD_WORDS, 2);
    }
    for id in ids::<COMPOSITION_RETAINED_COLUMNS>(BASELINE_COEFFICIENT_BASE) {
        insert_data(&mut requirements, id, half + GUARD_WORDS, 2);
    }
    for requirement in split
        .arena_slot_requirements(CompositionSplitPointerSlots {
            source_pointers: CANDIDATE_SOURCE_POINTERS,
            retained_pointers: CANDIDATE_OUTPUT_POINTERS,
        })
        .unwrap()
    {
        insert_requirement(&mut requirements, requirement);
    }
    for slots in [baseline_slots, candidate_slots] {
        for requirement in
            compact_domain_arena_slot_requirements(compact, base, domain, slots).unwrap()
        {
            insert_requirement(&mut requirements, requirement);
        }
    }
    let mut offset = 0usize;
    let specs = requirements
        .into_iter()
        .map(|(id, (len_words, alignment_words))| {
            offset = offset.next_multiple_of(alignment_words);
            let spec = ArenaSlotSpec {
                id,
                offset_words: offset,
                len_words,
                alignment_words,
            };
            offset += len_words;
            spec
        })
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}
