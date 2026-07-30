//! Native CUDA correctness/capture gates for prepared resident input edges.
//! A CPU/stub build compiles zero tests; GPU admission requires both passes.

#![cfg(stwo_cuda_link)]

use core::ffi::c_void;

use stwo_backend_cuda::{
    witness_input_compact_requirements, witness_input_gather_requirements, ArenaLayout, ArenaSlice,
    ArenaSlotId, ArenaSlotSpec, CudaExecContext, DeviceArena, PreparedWitnessInputCompactGraph,
    PreparedWitnessInputGatherGraph, WitnessInputCompactLayout, WitnessInputCompactRequirements,
    WitnessInputCompactSlots, WitnessInputGatherArenaSlotRequirement, WitnessInputGatherEdge,
    WitnessInputGatherRequirements, WitnessInputGatherSlots,
};

const SOURCE_WORDS: [usize; 2] = [8 * 16, 6 * 16];

fn edges() -> [WitnessInputGatherEdge; 2] {
    [
        WitnessInputGatherEdge {
            producer_rows: 16,
            word_base: 1,
            words_per_instance: 3,
            n_instances: 2,
        },
        WitnessInputGatherEdge {
            producer_rows: 16,
            word_base: 2,
            words_per_instance: 3,
            n_instances: 1,
        },
    ]
}

fn compact_edges() -> [WitnessInputGatherEdge; 1] {
    [WitnessInputGatherEdge {
        producer_rows: 16,
        word_base: 0,
        words_per_instance: 3,
        n_instances: 2,
    }]
}

fn compact_slots() -> WitnessInputCompactSlots {
    WitnessInputCompactSlots {
        source_pointers: ArenaSlotId(2),
        descriptors: ArenaSlotId(3),
        consumer_input_columns: (4..10).map(ArenaSlotId).collect(),
        output_pointers: ArenaSlotId(10),
        tuple_scratch: ArenaSlotId(11),
        sort_keys_a: ArenaSlotId(12),
        sort_keys_b: ArenaSlotId(13),
        sort_indices_a: ArenaSlotId(14),
        sort_indices_b: ArenaSlotId(15),
        run_heads: ArenaSlotId(16),
        run_positions: ArenaSlotId(17),
        n_unique: ArenaSlotId(18),
        sort_temp: ArenaSlotId(19),
        scan_temp: ArenaSlotId(20),
    }
}

fn compact_arena(
    requirements: &WitnessInputCompactRequirements,
    slots: &WitnessInputCompactSlots,
) -> DeviceArena {
    let mut requests = vec![WitnessInputGatherArenaSlotRequirement {
        id: ArenaSlotId(1),
        len_words: 6 * 16,
        alignment_words: 1,
    }];
    requests.extend(requirements.arena_slot_requirements(slots).unwrap());
    let mut offset = 0usize;
    let specs = requests
        .into_iter()
        .map(|request| {
            offset = offset.next_multiple_of(request.alignment_words);
            let result = ArenaSlotSpec {
                id: request.id,
                offset_words: offset,
                len_words: request.len_words,
                alignment_words: request.alignment_words,
            };
            offset += request.len_words;
            result
        })
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

fn compact_source(seed: u32) -> Vec<u32> {
    let mut source = vec![0u32; 6 * 16];
    for instance in 0..2 {
        for row in 0..16 {
            let group = (instance * 16 + row + seed as usize) % 10;
            for word in 0..3 {
                source[(instance * 3 + word) * 16 + row] = group as u32 + word as u32 * 100;
            }
        }
    }
    source
}

fn compact_host_reference(source: &[u32]) -> Vec<Vec<u32>> {
    let mut counts = std::collections::BTreeMap::<[u32; 3], u32>::new();
    for instance in 0..2 {
        for row in 0..16 {
            let tuple = std::array::from_fn(|word| source[(instance * 3 + word) * 16 + row]);
            *counts.entry(tuple).or_default() += 1;
        }
    }
    assert_eq!(counts.len(), 10);
    let first = *counts.first_key_value().unwrap().0;
    let mut columns = vec![vec![0u32; 16]; 6];
    for (row, (tuple, multiplicity)) in counts.into_iter().enumerate() {
        for word in 0..3 {
            columns[word][row] = tuple[word];
        }
        columns[3][row] = 1;
        columns[4][row] = row as u32;
        columns[5][row] = multiplicity;
    }
    for row in 10..16 {
        for word in 0..3 {
            columns[word][row] = first[word];
        }
        columns[4][row] = row as u32;
    }
    columns
}

fn slots() -> WitnessInputGatherSlots {
    WitnessInputGatherSlots {
        source_pointers: ArenaSlotId(3),
        descriptors: ArenaSlotId(4),
        consumer_input_columns: (5..10).map(ArenaSlotId).collect(),
        output_pointers: ArenaSlotId(10),
    }
}

fn arena(
    requirements: &WitnessInputGatherRequirements,
    slots: &WitnessInputGatherSlots,
) -> DeviceArena {
    let mut requests = vec![
        WitnessInputGatherArenaSlotRequirement {
            id: ArenaSlotId(1),
            len_words: SOURCE_WORDS[0],
            alignment_words: 1,
        },
        WitnessInputGatherArenaSlotRequirement {
            id: ArenaSlotId(2),
            len_words: SOURCE_WORDS[1],
            alignment_words: 1,
        },
    ];
    requests.extend(requirements.arena_slot_requirements(slots).unwrap());
    let mut offset = 0usize;
    let specs = requests
        .into_iter()
        .map(
            |WitnessInputGatherArenaSlotRequirement {
                 id,
                 len_words,
                 alignment_words,
             }| {
                offset = offset.next_multiple_of(alignment_words);
                let result = ArenaSlotSpec {
                    id,
                    offset_words: offset,
                    len_words,
                    alignment_words,
                };
                offset += len_words;
                result
            },
        )
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

fn source(producer: u32, source_words: usize, seed: u32) -> Vec<u32> {
    let rows = 16;
    (0..source_words)
        .map(|index| {
            let word = index / rows;
            let row = index % rows;
            seed + producer * 10_000 + word as u32 * 101 + row as u32
        })
        .collect()
}

fn upload(arena: &DeviceArena, destination: ArenaSlice, values: &[u32]) {
    assert_eq!(destination.len_words(), values.len());
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                values.as_ptr().cast::<c_void>(),
                core::mem::size_of_val(values),
            )
            .unwrap();
    }
}

fn read(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut result = vec![0u32; source.len_words()];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                result.as_mut_ptr().cast::<c_void>(),
                source.as_void_ptr().cast_const(),
                source.len_bytes(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    result
}

fn host_reference(
    requirements: &WitnessInputGatherRequirements,
    sources: &[Vec<u32>],
) -> Vec<Vec<u32>> {
    let mut columns = vec![vec![0u32; requirements.consumer_rows]; 5];
    for row in 0..requirements.consumer_rows {
        let source_global_row = if row < requirements.total_real_rows {
            row
        } else {
            row % 16
        };
        let (edge_index, plan) = requirements
            .edges
            .iter()
            .enumerate()
            .find(|(_, plan)| {
                source_global_row >= plan.destination_row_offset
                    && source_global_row < plan.destination_row_offset + plan.destination_rows
            })
            .unwrap();
        let local_row = source_global_row - plan.destination_row_offset;
        let instance = local_row / plan.edge.producer_rows;
        let producer_row = local_row % plan.edge.producer_rows;
        for word in 0..requirements.input_width {
            let source_word = plan.edge.word_base + instance * plan.edge.words_per_instance + word;
            columns[word][row] =
                sources[edge_index][source_word * plan.edge.producer_rows + producer_row];
        }
        columns[3][row] = u32::from(row < requirements.total_real_rows);
        columns[4][row] = row as u32;
    }
    columns
}

fn snapshot(arena: &DeviceArena, prepared: &PreparedWitnessInputGatherGraph<'_>) -> Vec<Vec<u32>> {
    prepared
        .consumer_input_columns()
        .iter()
        .copied()
        .map(|column| read(arena, column))
        .collect()
}

/// Multiple producers, canonical offsets, enabler/iota tails, packed padding,
/// graph capture, and mutated-source replay match the host resize semantics.
#[test]
fn prepared_witness_input_eager_capture_and_mutated_replay_match_host() {
    let edges = edges();
    let requirements = witness_input_gather_requirements(&edges, true, true).unwrap();
    assert_eq!(requirements.total_real_rows, 48);
    assert_eq!(requirements.consumer_rows, 64);
    let slots = slots();
    let arena = arena(&requirements, &slots);
    let source_slices = [
        arena.bind(ArenaSlotId(1)).unwrap(),
        arena.bind(ArenaSlotId(2)).unwrap(),
    ];
    let prepared = PreparedWitnessInputGatherGraph::prepare(
        &arena,
        &source_slices,
        &edges,
        true,
        true,
        &slots,
    )
    .unwrap();

    let initial = [source(1, SOURCE_WORDS[0], 7), source(2, SOURCE_WORDS[1], 7)];
    for (&destination, values) in source_slices.iter().zip(&initial) {
        upload(&arena, destination, values);
    }
    arena.context().sync().unwrap();
    arena.context().reset_telemetry();
    prepared.launch().unwrap();
    let eager = arena.context().telemetry();
    assert_eq!(eager.allocations, 0);
    assert_eq!(eager.h2d_bytes, 0);
    assert_eq!(eager.d2h_bytes, 0);
    assert_eq!(eager.d2d_bytes, 0);
    assert_eq!(eager.sync_calls, 0);
    assert_eq!(
        snapshot(&arena, &prepared),
        host_reference(&requirements, &initial)
    );

    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    arena.context().reset_telemetry();
    graph.launch(arena.context()).unwrap();
    let replay = arena.context().telemetry();
    assert_eq!(replay.graph_launches, 1);
    assert_eq!(replay.kernel_launches, 1);
    assert_eq!(replay.allocations, 0);
    assert_eq!(replay.h2d_bytes, 0);
    assert_eq!(replay.d2h_bytes, 0);
    assert_eq!(replay.d2d_bytes, 0);
    assert_eq!(replay.sync_calls, 0);
    assert_eq!(
        snapshot(&arena, &prepared),
        host_reference(&requirements, &initial)
    );

    let mutated = [
        source(1, SOURCE_WORDS[0], 1234),
        source(2, SOURCE_WORDS[1], 1234),
    ];
    for (&destination, values) in source_slices.iter().zip(&mutated) {
        upload(&arena, destination, values);
    }
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        snapshot(&arena, &prepared),
        host_reference(&requirements, &mutated)
    );
}

/// Resident tuple sorting, deterministic key validation, RLE multiplicities,
/// unique-row enabler, iota, padding, capture, and replay all match the host
/// DashMap claim-generator semantics without any hot-path transfer.
#[test]
fn prepared_witness_input_compact_eager_capture_and_replay_match_host() {
    let edges = compact_edges();
    let layout = WitnessInputCompactLayout {
        tuple_words: 3,
        key_words: 2,
        consumer_input_count: 6,
        enabler_slot: Some(3),
        iota_slot: Some(4),
        multiplicity_slot: 5,
    };
    let requirements = witness_input_compact_requirements(&edges, layout, 16).unwrap();
    assert_eq!(requirements.total_input_rows, 32);
    assert_eq!(requirements.sort_rows, 32);
    let slots = compact_slots();
    let arena = compact_arena(&requirements, &slots);
    let source_slice = arena.bind(ArenaSlotId(1)).unwrap();
    let prepared =
        PreparedWitnessInputCompactGraph::prepare(&arena, &[source_slice], &requirements, &slots)
            .unwrap();

    let initial = compact_source(0);
    upload(&arena, source_slice, &initial);
    arena.context().sync().unwrap();
    arena.context().reset_telemetry();
    prepared.launch().unwrap();
    let eager = arena.context().telemetry();
    assert_eq!(eager.allocations, 0);
    assert_eq!(eager.h2d_bytes, 0);
    assert_eq!(eager.d2h_bytes, 0);
    assert_eq!(eager.d2d_bytes, 0);
    assert_eq!(eager.sync_calls, 0);
    assert_eq!(
        snapshot_compact(&arena, &prepared),
        compact_host_reference(&initial)
    );
    assert_eq!(read(&arena, prepared.n_unique()), [10]);

    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    arena.context().reset_telemetry();
    graph.launch(arena.context()).unwrap();
    let replay = arena.context().telemetry();
    assert_eq!(replay.graph_launches, 1);
    assert_eq!(replay.allocations, 0);
    assert_eq!(replay.h2d_bytes, 0);
    assert_eq!(replay.d2h_bytes, 0);
    assert_eq!(replay.d2d_bytes, 0);
    assert_eq!(replay.sync_calls, 0);
    assert_eq!(
        snapshot_compact(&arena, &prepared),
        compact_host_reference(&initial)
    );

    let mutated = compact_source(3);
    upload(&arena, source_slice, &mutated);
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        snapshot_compact(&arena, &prepared),
        compact_host_reference(&mutated)
    );
    assert_eq!(read(&arena, prepared.n_unique()), [10]);
}

fn snapshot_compact(
    arena: &DeviceArena,
    prepared: &PreparedWitnessInputCompactGraph<'_>,
) -> Vec<Vec<u32>> {
    prepared
        .consumer_input_columns()
        .iter()
        .copied()
        .map(|column| read(arena, column))
        .collect()
}
