//! Native CUDA correctness/capture gate for fixed-table materialization.
//! A CPU/stub build compiles zero tests; GPU admission requires exactly one pass.

#![cfg(stwo_cuda_link)]

use core::ffi::c_void;

use stwo_backend_cuda::{
    fixed_table_workspace_requirements, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CudaExecContext, DeviceArena, FixedTableArenaSlotRequirement,
    FixedTableContiguousWorkspaceSlots, FixedTableLookupSource, FixedTableMaterializationConfig,
    FixedTableSourceColumn, FixedTableWorkspaceRequirements, PreparedFixedTableGraph,
};

const ROWS: usize = 16;

fn config() -> FixedTableMaterializationConfig {
    let mut lookup_sources = vec![
        FixedTableLookupSource::Constant(123),
        FixedTableLookupSource::SourceColumn(0),
        FixedTableLookupSource::MultiplicityColumn(3),
    ];
    for multiplicity_column in 0..4 {
        lookup_sources.extend([
            FixedTableLookupSource::Constant(99),
            FixedTableLookupSource::ExpandedXorA {
                multiplicity_column,
                limb_bits: 2,
                expand_bits: 1,
            },
            FixedTableLookupSource::ExpandedXorB {
                multiplicity_column,
                limb_bits: 2,
                expand_bits: 1,
            },
            FixedTableLookupSource::ExpandedXor {
                multiplicity_column,
                limb_bits: 2,
                expand_bits: 1,
            },
        ]);
    }
    lookup_sources.extend((0..4).map(FixedTableLookupSource::MultiplicityColumn));
    FixedTableMaterializationConfig {
        row_count: ROWS,
        source_column_count: 1,
        trace_multiplicity_columns: vec![2, 0],
        multiplicity_column_count: 4,
        lookup_sources,
    }
}

fn slots() -> FixedTableContiguousWorkspaceSlots {
    FixedTableContiguousWorkspaceSlots {
        source_pointers: Some(ArenaSlotId(3)),
        multiplicity_pointers: ArenaSlotId(4),
        trace_multiplicity_columns: ArenaSlotId(5),
        trace_outputs: vec![ArenaSlotId(6), ArenaSlotId(7)],
        trace_output_pointers: ArenaSlotId(8),
        lookup_descriptors: ArenaSlotId(9),
        lookup_output: ArenaSlotId(10),
        lookup_output_pointers: ArenaSlotId(11),
    }
}

fn arena(
    requirements: &FixedTableWorkspaceRequirements,
    slots: &FixedTableContiguousWorkspaceSlots,
) -> DeviceArena {
    let mut requests = [
        FixedTableArenaSlotRequirement {
            id: ArenaSlotId(1),
            len_words: ROWS,
            alignment_words: 1,
        },
        FixedTableArenaSlotRequirement {
            id: ArenaSlotId(2),
            len_words: 4 * ROWS,
            alignment_words: 1,
        },
    ]
    .into_iter()
    .collect::<Vec<_>>();
    requests.extend(
        requirements
            .arena_slot_requirements_contiguous(slots)
            .unwrap(),
    );
    let mut offset = 0usize;
    let specs = requests
        .into_iter()
        .map(
            |FixedTableArenaSlotRequirement {
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

fn inputs(seed: u32) -> (Vec<u32>, Vec<Vec<u32>>) {
    let source = (0..ROWS as u32).map(|row| 700 + row).collect();
    let multiplicities = (0..4u32)
        .map(|column| {
            (0..ROWS as u32)
                .map(|row| seed + 100 * column + row)
                .collect()
        })
        .collect();
    (source, multiplicities)
}

fn value(
    source: FixedTableLookupSource,
    row: usize,
    sources: &[Vec<u32>],
    multiplicities: &[Vec<u32>],
) -> u32 {
    match source {
        FixedTableLookupSource::Constant(value) => value,
        FixedTableLookupSource::SourceColumn(column) => sources[column as usize][row],
        FixedTableLookupSource::MultiplicityColumn(column) => multiplicities[column as usize][row],
        FixedTableLookupSource::ExpandedXorA {
            multiplicity_column,
            limb_bits,
            expand_bits,
        }
        | FixedTableLookupSource::ExpandedXorB {
            multiplicity_column,
            limb_bits,
            expand_bits,
        }
        | FixedTableLookupSource::ExpandedXor {
            multiplicity_column,
            limb_bits,
            expand_bits,
        } => {
            let expand_mask = (1 << expand_bits) - 1;
            let limb_mask = (1 << limb_bits) - 1;
            let a = (multiplicity_column >> expand_bits) * (1 << limb_bits)
                + ((row as u32) >> limb_bits);
            let b =
                (multiplicity_column & expand_mask) * (1 << limb_bits) + ((row as u32) & limb_mask);
            match source {
                FixedTableLookupSource::ExpandedXorA { .. } => a,
                FixedTableLookupSource::ExpandedXorB { .. } => b,
                FixedTableLookupSource::ExpandedXor { .. } => a ^ b,
                _ => unreachable!(),
            }
        }
    }
}

fn host_reference(
    config: &FixedTableMaterializationConfig,
    source: &[u32],
    multiplicities: &[Vec<u32>],
) -> (Vec<Vec<u32>>, Vec<Vec<u32>>) {
    let trace = config
        .trace_multiplicity_columns
        .iter()
        .map(|&column| multiplicities[column as usize].clone())
        .collect();
    let sources = [source.to_vec()];
    let lookup = config
        .lookup_sources
        .iter()
        .map(|&descriptor| {
            (0..ROWS)
                .map(|row| value(descriptor, row, &sources, multiplicities))
                .collect()
        })
        .collect();
    (trace, lookup)
}

fn snapshot(
    arena: &DeviceArena,
    prepared: &PreparedFixedTableGraph<'_>,
) -> (Vec<Vec<u32>>, Vec<Vec<u32>>) {
    let lookup = read(arena, prepared.lookup_output_slab().unwrap());
    (
        prepared
            .trace_outputs()
            .iter()
            .map(|&output| read(arena, output))
            .collect(),
        lookup.chunks_exact(ROWS).map(<[u32]>::to_vec).collect(),
    )
}

/// Constant/preprocessed/multiplicity descriptors and the expanded-XOR formula
/// agree with the host reference in eager, captured, and mutated replay modes.
#[test]
fn prepared_fixed_table_eager_capture_and_mutated_multiplicity_match_host() {
    let config = config();
    let requirements = fixed_table_workspace_requirements(&config).unwrap();
    let slots = slots();
    let arena = arena(&requirements, &slots);
    let source_slices = [arena.bind(ArenaSlotId(1)).unwrap()];
    let multiplicity_slab = arena.bind(ArenaSlotId(2)).unwrap();
    let prepared = PreparedFixedTableGraph::prepare_contiguous(
        &arena,
        &config,
        &source_slices.map(FixedTableSourceColumn::from),
        multiplicity_slab,
        &slots,
    )
    .unwrap();

    let (source, initial) = inputs(11);
    upload(&arena, source_slices[0], &source);
    let initial_flat = initial.iter().flatten().copied().collect::<Vec<_>>();
    upload(&arena, multiplicity_slab, &initial_flat);
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
        host_reference(&config, &source, &initial)
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
        host_reference(&config, &source, &initial)
    );

    let (_, mutated) = inputs(9000);
    let mutated_flat = mutated.iter().flatten().copied().collect::<Vec<_>>();
    upload(&arena, multiplicity_slab, &mutated_flat);
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        snapshot(&arena, &prepared),
        host_reference(&config, &source, &mutated)
    );
}
