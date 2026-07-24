//! Native CUDA gate for arena-backed execution tables. CPU builds compile zero
//! tests; GPU admission requires this eager/capture/mutated-content test to pass.

#![cfg(stwo_cuda_link)]

use stwo_backend_cuda::{
    execution_tables_workspace_requirements, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CudaExecContext, DeviceArena, ExecutionTablesArenaSlotRequirement, ExecutionTablesHostData,
    ExecutionTablesWorkspaceRequirements, ExecutionTablesWorkspaceSlots, MemoryBaseTracePart,
    PreparedExecutionTablesError, PreparedExecutionTablesGraph, PreparedMemoryBaseTraceGraph,
    EXECUTION_TABLE_BIG_LIMBS, EXECUTION_TABLE_SMALL_LIMBS,
};

const N_ADDRS: usize = 7;
const N_BIG: usize = 3;
const N_SMALL: usize = 5;
const RC99_TABLE_SIZE: usize = 1 << 18;

fn slots() -> ExecutionTablesWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    ExecutionTablesWorkspaceSlots {
        raw_addr_to_id: id(),
        raw_f252_words: id(),
        raw_small_words: id(),
        big_limbs: (0..EXECUTION_TABLE_BIG_LIMBS).map(|_| id()).collect(),
        small_limbs: (0..EXECUTION_TABLE_SMALL_LIMBS).map(|_| id()).collect(),
        table_pointers: id(),
        table_strides: id(),
    }
}

fn arena(
    requirements: &ExecutionTablesWorkspaceRequirements,
    slots: &ExecutionTablesWorkspaceSlots,
) -> DeviceArena {
    let mut offset = 0usize;
    let specs = requirements
        .arena_slot_requirements(slots)
        .unwrap()
        .into_iter()
        .map(
            |ExecutionTablesArenaSlotRequirement {
                 id,
                 len_words,
                 alignment_words,
             }| {
                offset = offset.next_multiple_of(alignment_words);
                let spec = ArenaSlotSpec {
                    id,
                    offset_words: offset,
                    len_words,
                    alignment_words,
                };
                offset += len_words;
                spec
            },
        )
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

#[derive(Clone)]
struct OwnedTables {
    addr_to_id: Vec<u32>,
    f252_values: Vec<[u32; 8]>,
    small_values: Vec<u128>,
}

impl OwnedTables {
    fn view(&self) -> ExecutionTablesHostData<'_> {
        ExecutionTablesHostData {
            addr_to_id: &self.addr_to_id,
            f252_values: &self.f252_values,
            small_values: &self.small_values,
        }
    }
}

fn tables(seed: u32) -> OwnedTables {
    OwnedTables {
        addr_to_id: (0..N_ADDRS)
            .map(|index| seed.rotate_left(index as u32) ^ index as u32)
            .collect(),
        f252_values: (0..N_BIG)
            .map(|row| {
                std::array::from_fn(|word| {
                    seed.wrapping_mul(17 + row as u32)
                        .rotate_left((word * 3) as u32)
                        ^ (row * 41 + word) as u32
                })
            })
            .collect(),
        small_values: (0..N_SMALL)
            .map(|row| {
                let lo = u128::from(seed.wrapping_mul(101 + row as u32));
                let hi = u128::from(seed.rotate_left((row * 5) as u32));
                lo | (hi << 67) | (u128::from(row as u32) << 113)
            })
            .collect(),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    addr_to_id: Vec<u32>,
    big_limbs: Vec<Vec<u32>>,
    small_limbs: Vec<Vec<u32>>,
}

fn snapshot(arena: &DeviceArena, prepared: &PreparedExecutionTablesGraph<'_>) -> Snapshot {
    let mut addr_to_id = vec![0; prepared.raw_addr_to_id().len_words()];
    let mut big_limbs = prepared
        .big_limbs()
        .iter()
        .map(|column| vec![0; column.len_words()])
        .collect::<Vec<_>>();
    let mut small_limbs = prepared
        .small_limbs()
        .iter()
        .map(|column| vec![0; column.len_words()])
        .collect::<Vec<_>>();
    copy_to_host(arena, prepared.raw_addr_to_id(), &mut addr_to_id);
    for (&source, destination) in prepared.big_limbs().iter().zip(&mut big_limbs) {
        copy_to_host(arena, source, destination);
    }
    for (&source, destination) in prepared.small_limbs().iter().zip(&mut small_limbs) {
        copy_to_host(arena, source, destination);
    }
    arena.context().sync().unwrap();
    Snapshot {
        addr_to_id,
        big_limbs,
        small_limbs,
    }
}

fn copy_to_host(arena: &DeviceArena, source: ArenaSlice, destination: &mut [u32]) {
    assert_eq!(source.len_words(), destination.len());
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                destination.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                source.len_bytes(),
            )
            .unwrap();
    }
}

fn reference(
    requirements: &ExecutionTablesWorkspaceRequirements,
    tables: &OwnedTables,
) -> Snapshot {
    let big_rows = tables
        .f252_values
        .iter()
        .map(|words| split_9bit(words, EXECUTION_TABLE_BIG_LIMBS))
        .collect::<Vec<_>>();
    let small_rows = tables
        .small_values
        .iter()
        .map(|&value| {
            split_9bit(
                &[
                    value as u32,
                    (value >> 32) as u32,
                    (value >> 64) as u32,
                    (value >> 96) as u32,
                ],
                EXECUTION_TABLE_SMALL_LIMBS,
            )
        })
        .collect::<Vec<_>>();
    Snapshot {
        addr_to_id: tables.addr_to_id.clone(),
        big_limbs: (0..EXECUTION_TABLE_BIG_LIMBS)
            .map(|limb| {
                (0..requirements.big_column_words)
                    .map(|row| big_rows.get(row).map_or(0, |values| values[limb]))
                    .collect()
            })
            .collect(),
        small_limbs: (0..EXECUTION_TABLE_SMALL_LIMBS)
            .map(|limb| {
                (0..requirements.small_column_words)
                    .map(|row| small_rows.get(row).map_or(0, |values| values[limb]))
                    .collect()
            })
            .collect(),
    }
}

fn split_9bit(words: &[u32], n_limbs: usize) -> Vec<u32> {
    let mut result = Vec::with_capacity(n_limbs);
    let mut bits_left = 32u32;
    let mut word_index = 0usize;
    let mut word = words[0];
    for _ in 0..n_limbs {
        if bits_left > 9 {
            result.push(word & 0x1ff);
            word >>= 9;
            bits_left -= 9;
            continue;
        }
        let mut limb = word;
        word_index += 1;
        word = words.get(word_index).copied().unwrap_or(0);
        if bits_left < 9 {
            limb |= (word << bits_left) & 0x1ff;
            word >>= 9 - bits_left;
        }
        result.push(limb);
        bits_left += 32 - 9;
    }
    result
}

/// Eager launch, captured replay, and replay after same-geometry compact-table
/// mutation are byte-identical to the scalar split. The hot call itself reports
/// no allocation, transfer, or synchronization.
#[test]
fn prepared_execution_tables_eager_capture_and_mutation_match_cpu() {
    let requirements = execution_tables_workspace_requirements(N_ADDRS, N_BIG, N_SMALL).unwrap();
    let slots = slots();
    let arena = arena(&requirements, &slots);
    let prepared = PreparedExecutionTablesGraph::prepare(&arena, &requirements, &slots).unwrap();
    assert_eq!(
        prepared.launch().unwrap_err(),
        PreparedExecutionTablesError::NotIngested
    );
    assert!(matches!(
        prepared.view(),
        Err(PreparedExecutionTablesError::NotIngested)
    ));

    let first = tables(0x1234_5678);
    let ingest = prepared.ingest(first.view()).unwrap();
    assert_eq!(ingest.sync_calls, 1);
    assert_eq!(
        ingest.compact_h2d_bytes,
        ((N_ADDRS + N_BIG * 8 + N_SMALL * 4) * 4) as u64
    );
    assert!(ingest.descriptor_h2d_bytes > 0);
    assert_eq!(prepared.view().unwrap().shape(), (N_ADDRS, N_BIG, N_SMALL));

    arena.context().reset_telemetry();
    let launch = prepared.launch().unwrap();
    assert_eq!(launch.kernel_launches, 2);
    assert_eq!(launch.allocations, 0);
    assert_eq!(launch.h2d_bytes, 0);
    assert_eq!(launch.d2h_bytes, 0);
    assert_eq!(launch.d2d_bytes, 0);
    assert_eq!(launch.sync_calls, 0);
    let hot = arena.context().telemetry();
    assert_eq!(hot.allocations, 0);
    assert_eq!(hot.h2d_bytes, 0);
    assert_eq!(hot.d2h_bytes, 0);
    assert_eq!(hot.d2d_bytes, 0);
    assert_eq!(hot.sync_calls, 0);
    assert_eq!(
        snapshot(&arena, &prepared),
        reference(&requirements, &first)
    );

    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    arena.context().reset_telemetry();
    graph.launch(arena.context()).unwrap();
    let replay = arena.context().telemetry();
    assert_eq!(replay.graph_launches, 1);
    assert_eq!(replay.kernel_launches, 2);
    assert_eq!(replay.allocations, 0);
    assert_eq!(replay.h2d_bytes, 0);
    assert_eq!(replay.d2h_bytes, 0);
    assert_eq!(replay.sync_calls, 0);
    assert_eq!(
        snapshot(&arena, &prepared),
        reference(&requirements, &first)
    );

    let second = tables(0xdead_beef);
    let mutated_ingest = prepared.ingest(second.view()).unwrap();
    assert_eq!(mutated_ingest.sync_calls, 1);
    assert_eq!(mutated_ingest.descriptor_h2d_bytes, 0);
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        snapshot(&arena, &prepared),
        reference(&requirements, &second)
    );
}

#[derive(Clone)]
struct MemoryTraceSlots {
    address_counts: ArenaSlotId,
    big_counts: ArenaSlotId,
    small_counts: ArenaSlotId,
    address_outputs: Vec<ArenaSlotId>,
    big_outputs: Vec<Vec<ArenaSlotId>>,
    small_outputs: Vec<ArenaSlotId>,
    rc99_lut: ArenaSlotId,
    rc99_counts: ArenaSlotId,
}

fn memory_trace_slots() -> MemoryTraceSlots {
    let mut next = 100u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    MemoryTraceSlots {
        address_counts: id(),
        big_counts: id(),
        small_counts: id(),
        address_outputs: (0..32).map(|_| id()).collect(),
        big_outputs: (0..3).map(|_| (0..29).map(|_| id()).collect()).collect(),
        small_outputs: (0..9).map(|_| id()).collect(),
        rc99_lut: id(),
        rc99_counts: id(),
    }
}

fn arena_with_memory(
    requirements: &ExecutionTablesWorkspaceRequirements,
    execution_slots: &ExecutionTablesWorkspaceSlots,
    memory: &MemoryTraceSlots,
) -> DeviceArena {
    let mut requests = requirements
        .arena_slot_requirements(execution_slots)
        .unwrap()
        .into_iter()
        .map(|request| (request.id, request.len_words, request.alignment_words))
        .collect::<Vec<_>>();
    requests.extend([
        (memory.address_counts, 16 * 16, 1),
        (memory.big_counts, 3 * 16, 1),
        (memory.small_counts, 16, 1),
    ]);
    requests.extend(memory.address_outputs.iter().map(|&id| (id, 16, 1)));
    requests.extend(memory.big_outputs.iter().flatten().map(|&id| (id, 16, 1)));
    requests.extend(memory.small_outputs.iter().map(|&id| (id, 16, 1)));
    requests.extend([
        (memory.rc99_lut, RC99_TABLE_SIZE, 1),
        (memory.rc99_counts, 8 * RC99_TABLE_SIZE, 1),
    ]);
    let mut offset = 0usize;
    let specs = requests
        .into_iter()
        .map(|(id, len_words, alignment_words)| {
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

fn upload_words(arena: &DeviceArena, slot: ArenaSlotId, words: &[u32]) {
    let destination = arena.bind(slot).unwrap();
    assert_eq!(destination.len_words(), words.len());
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                words.as_ptr().cast(),
                core::mem::size_of_val(words),
            )
            .unwrap();
    }
}

fn read_slot(arena: &DeviceArena, slot: ArenaSlotId) -> Vec<u32> {
    let source = arena.bind(slot).unwrap();
    let mut words = vec![0; source.len_words()];
    copy_to_host(arena, source, &mut words);
    arena.context().sync().unwrap();
    words
}

fn assert_memory_trace(
    arena: &DeviceArena,
    slots: &MemoryTraceSlots,
    requirements: &ExecutionTablesWorkspaceRequirements,
    tables: &OwnedTables,
    address_counts: &[u32],
    big_counts: &[u32],
    small_counts: &[u32],
) {
    let split = reference(requirements, tables);
    for chunk in 0..16 {
        let ids = read_slot(arena, slots.address_outputs[2 * chunk]);
        let mults = read_slot(arena, slots.address_outputs[2 * chunk + 1]);
        for row in 0..16 {
            let index = chunk * 16 + row;
            assert_eq!(
                ids[row],
                tables.addr_to_id.get(index + 1).copied().unwrap_or(0)
            );
            assert_eq!(mults[row], address_counts[index]);
        }
    }
    for (part, source_offset) in [0usize, 16, 32].into_iter().enumerate() {
        for limb in 0..EXECUTION_TABLE_BIG_LIMBS {
            let actual = read_slot(arena, slots.big_outputs[part][limb]);
            let expected = (0..16)
                .map(|row| {
                    split.big_limbs[limb]
                        .get(source_offset + row)
                        .copied()
                        .unwrap_or(0)
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
        let actual = read_slot(arena, slots.big_outputs[part][28]);
        let expected = (0..16)
            .map(|row| big_counts.get(source_offset + row).copied().unwrap_or(0))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
    for limb in 0..EXECUTION_TABLE_SMALL_LIMBS {
        assert_eq!(
            read_slot(arena, slots.small_outputs[limb]),
            split.small_limbs[limb]
        );
    }
    assert_eq!(read_slot(arena, slots.small_outputs[8]), small_counts);
}

fn expected_rc99_counts(
    requirements: &ExecutionTablesWorkspaceRequirements,
    tables: &OwnedTables,
    big_rows: usize,
) -> Vec<u32> {
    let split = reference(requirements, tables);
    let mut counts = vec![0u32; 8 * RC99_TABLE_SIZE];
    for row in 0..big_rows {
        for pair in 0..EXECUTION_TABLE_BIG_LIMBS / 2 {
            let lo = split.big_limbs[2 * pair].get(row).copied().unwrap_or(0);
            let hi = split.big_limbs[2 * pair + 1].get(row).copied().unwrap_or(0);
            let key = (lo << 9) | hi;
            counts[(pair % 8) * RC99_TABLE_SIZE + rc99_lut_value(key) as usize] += 1;
        }
    }
    for row in 0..requirements.small_column_words {
        for pair in 0..EXECUTION_TABLE_SMALL_LIMBS / 2 {
            let key =
                (split.small_limbs[2 * pair][row] << 9) | split.small_limbs[2 * pair + 1][row];
            counts[pair * RC99_TABLE_SIZE + rc99_lut_value(key) as usize] += 1;
        }
    }
    let relation_totals = counts
        .chunks_exact(RC99_TABLE_SIZE)
        .map(|relation| relation.iter().sum::<u32>())
        .collect::<Vec<_>>();
    assert_eq!(
        relation_totals,
        [
            (2 * big_rows + requirements.small_column_words) as u32,
            (2 * big_rows + requirements.small_column_words) as u32,
            (2 * big_rows + requirements.small_column_words) as u32,
            (2 * big_rows + requirements.small_column_words) as u32,
            (2 * big_rows) as u32,
            (2 * big_rows) as u32,
            big_rows as u32,
            big_rows as u32,
        ]
    );
    counts
}

fn rc99_lut_value(key: u32) -> u32 {
    (key + 17) & (RC99_TABLE_SIZE as u32 - 1)
}

/// The final real big segment may be partial and followed by an explicit zero
/// padding component. Padded id/source offsets remain stable across capture and
/// replay, and every base column is byte-identical to the host layout.
#[test]
fn prepared_memory_base_trace_handles_partial_final_and_padding_part() {
    let requirements = execution_tables_workspace_requirements(N_ADDRS, 19, N_SMALL).unwrap();
    let execution_slots = slots();
    let memory_slots = memory_trace_slots();
    let arena = arena_with_memory(&requirements, &execution_slots, &memory_slots);
    let execution =
        PreparedExecutionTablesGraph::prepare(&arena, &requirements, &execution_slots).unwrap();
    let first = OwnedTables {
        addr_to_id: tables(0x1234_5678).addr_to_id,
        f252_values: (0..19)
            .map(|row| std::array::from_fn(|word| (row * 37 + word * 11 + 5) as u32))
            .collect(),
        small_values: tables(0x1234_5678).small_values,
    };
    execution.ingest(first.view()).unwrap();
    let address_counts = (0..16 * 16)
        .map(|word| (word < N_ADDRS - 1).then_some(word as u32 + 7).unwrap_or(0))
        .collect::<Vec<_>>();
    let big_counts = (0..3 * 16)
        .map(|word| (word < 19).then_some(word as u32 + 101).unwrap_or(0))
        .collect::<Vec<_>>();
    let small_counts = (0..16)
        .map(|word| (word < N_SMALL).then_some(word as u32 + 211).unwrap_or(0))
        .collect::<Vec<_>>();
    upload_words(&arena, memory_slots.address_counts, &address_counts);
    upload_words(&arena, memory_slots.big_counts, &big_counts);
    upload_words(&arena, memory_slots.small_counts, &small_counts);
    upload_words(
        &arena,
        memory_slots.rc99_counts,
        &vec![0; 8 * RC99_TABLE_SIZE],
    );
    arena.context().sync().unwrap();

    let address_outputs = memory_slots
        .address_outputs
        .iter()
        .map(|&slot| arena.bind(slot).unwrap())
        .collect::<Vec<_>>();
    let big_output_slices = memory_slots
        .big_outputs
        .iter()
        .map(|outputs| {
            outputs
                .iter()
                .map(|&slot| arena.bind(slot).unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let big_parts = [0usize, 16, 32]
        .into_iter()
        .zip(&big_output_slices)
        .map(|(source_offset, outputs)| MemoryBaseTracePart {
            source_offset,
            row_count: 16,
            outputs,
        })
        .collect::<Vec<_>>();
    let small_outputs = memory_slots
        .small_outputs
        .iter()
        .map(|&slot| arena.bind(slot).unwrap())
        .collect::<Vec<_>>();
    let prepared = PreparedMemoryBaseTraceGraph::prepare(
        &arena,
        &execution,
        arena.bind(memory_slots.address_counts).unwrap(),
        address_counts.len(),
        16,
        &address_outputs,
        arena.bind(memory_slots.big_counts).unwrap(),
        big_counts.len(),
        &big_parts,
        arena.bind(memory_slots.small_counts).unwrap(),
        small_counts.len(),
        MemoryBaseTracePart {
            source_offset: 0,
            row_count: 16,
            outputs: &small_outputs,
        },
        arena.bind(memory_slots.rc99_lut).unwrap(),
        RC99_TABLE_SIZE,
        arena.bind(memory_slots.rc99_counts).unwrap(),
    )
    .unwrap();
    prepared
        .upload_rc99_lut(
            &(0..RC99_TABLE_SIZE as u32)
                .map(rc99_lut_value)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert_eq!(prepared.kernel_launches(), 9);

    execution.launch().unwrap();
    prepared.launch().unwrap();
    assert_memory_trace(
        &arena,
        &memory_slots,
        &requirements,
        &first,
        &address_counts,
        &big_counts,
        &small_counts,
    );
    assert_eq!(
        read_slot(&arena, memory_slots.rc99_counts),
        expected_rc99_counts(&requirements, &first, big_counts.len())
    );

    upload_words(
        &arena,
        memory_slots.rc99_counts,
        &vec![0; 8 * RC99_TABLE_SIZE],
    );
    arena.context().sync().unwrap();
    let capture = arena.context().capture().unwrap();
    execution.launch().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    graph.launch(arena.context()).unwrap();
    assert_memory_trace(
        &arena,
        &memory_slots,
        &requirements,
        &first,
        &address_counts,
        &big_counts,
        &small_counts,
    );
    assert_eq!(
        read_slot(&arena, memory_slots.rc99_counts),
        expected_rc99_counts(&requirements, &first, big_counts.len())
    );
}
