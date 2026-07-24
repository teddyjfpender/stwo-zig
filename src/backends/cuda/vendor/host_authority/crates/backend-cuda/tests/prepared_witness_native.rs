//! Native CUDA correctness/capture gate for the prepared recorded-witness ABI.
//! A CPU/stub build compiles zero tests; GPU admission requires exactly one pass.

#![cfg(stwo_cuda_link)]

use stwo_backend_cuda::exec_tables::DeviceExecutionTables;
use stwo_backend_cuda::jit_witness::interp::{interpret_rows, RowOutputs};
use stwo_backend_cuda::jit_witness::isa::WitnessProgram;
use stwo_backend_cuda::jit_witness::recording::WitnessRecorder;
use stwo_backend_cuda::{
    aot, witness_workspace_requirements, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CudaExecContext, DeviceArena, PreparedWitnessError, PreparedWitnessGraph, PreparedWitnessMode,
    WitnessArenaSlotRequirement, WitnessWorkspaceRequirements, WitnessWorkspaceSlots,
};

const ROWS: usize = 32;
const MULTIPLICITY_WORDS: usize = 8;
const M31_MODULUS: u32 = 0x7fff_ffff;

fn program() -> WitnessProgram {
    let mut recorder = WitnessRecorder::new("prepared_witness_native_gate");
    let address = recorder.input(0);
    let addend = recorder.input(1);
    let id = recorder.table_limb(0, address, 0);
    let value = recorder.table_limb(1, id, 0);
    let sum = recorder.m31_add(value, addend);
    recorder.col_write(0, sum);
    recorder.col_write(1, value);
    recorder.mult_push(0, address);
    recorder.lookup_word(0, sum);
    recorder.sub_word(0, value);
    recorder.finish()
}

fn workspace_slots(requirements: &WitnessWorkspaceRequirements) -> WitnessWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    WitnessWorkspaceSlots {
        input_columns: requirements
            .input_column_words
            .iter()
            .map(|_| id())
            .collect(),
        input_pointers: id(),
        execution_table_pointers: id(),
        execution_table_strides: id(),
        output_columns: requirements
            .output_column_words
            .iter()
            .map(|_| id())
            .collect(),
        output_pointers: id(),
        multiplicity_columns: requirements
            .multiplicity_column_words
            .iter()
            .map(|_| id())
            .collect(),
        multiplicity_pointers: id(),
        multiplicity_dummy: requirements.multiplicity_dummy_words.map(|_| id()),
        lookup_words: id(),
        sub_words: id(),
    }
}

fn arena(
    requirements: &WitnessWorkspaceRequirements,
    slots: &WitnessWorkspaceSlots,
) -> DeviceArena {
    let mut offset = 0usize;
    let specs = requirements
        .arena_slot_requirements(slots)
        .unwrap()
        .into_iter()
        .map(
            |WitnessArenaSlotRequirement {
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
                values.as_ptr().cast(),
                core::mem::size_of_val(values),
            )
            .unwrap();
    }
}

fn read(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut values = vec![0u32; source.len_words()];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                values.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                source.len_bytes(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    values
}

#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    columns: Vec<Vec<u32>>,
    lookup: Vec<u32>,
    sub: Vec<u32>,
    multiplicity: Vec<u32>,
}

fn snapshot(arena: &DeviceArena, prepared: &PreparedWitnessGraph<'_>) -> Snapshot {
    Snapshot {
        columns: prepared
            .output_columns()
            .iter()
            .copied()
            .map(|slice| read(arena, slice))
            .collect(),
        lookup: read(arena, prepared.lookup_words()),
        sub: read(arena, prepared.sub_words()),
        multiplicity: read(arena, prepared.multiplicity_columns()[0]),
    }
}

fn reference(
    program: &WitnessProgram,
    addresses: &[u32],
    addends: &[u32],
    small_values: &[u128],
) -> Snapshot {
    let rows = addresses
        .iter()
        .zip(addends)
        .map(|(&address, &addend)| vec![address, addend])
        .collect::<Vec<_>>();
    let oracle = |table: u32, key: u32, limb: u32| match table {
        0 => key,
        1 if limb == 0 => (small_values[key as usize] as u32) & 0x1ff,
        1 => 0,
        _ => panic!("unexpected table {table}"),
    };
    let interpreted = interpret_rows(program, &rows, &oracle);

    // Independent scalar reference for the complete toy writer contract.
    let cpu_rows = addresses
        .iter()
        .zip(addends)
        .map(|(&address, &addend)| {
            let value = (small_values[address as usize] as u32) & 0x1ff;
            let raw_sum = value + addend;
            let sum = if raw_sum >= M31_MODULUS {
                raw_sum - M31_MODULUS
            } else {
                raw_sum
            };
            RowOutputs {
                columns: vec![sum, value],
                mults: vec![(0, address)],
                lookup_words: vec![sum],
                sub_words: vec![value],
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        interpreted, cpu_rows,
        "recording interpreter drifted from CPU"
    );

    let mut multiplicity = vec![0u32; MULTIPLICITY_WORDS];
    for &address in addresses {
        multiplicity[address as usize] += 1;
    }
    Snapshot {
        columns: (0..program.n_cols as usize)
            .map(|column| interpreted.iter().map(|row| row.columns[column]).collect())
            .collect(),
        lookup: interpreted
            .iter()
            .flat_map(|row| row.lookup_words.iter().copied())
            .collect(),
        sub: interpreted
            .iter()
            .flat_map(|row| row.sub_words.iter().copied())
            .collect(),
        multiplicity,
    }
}

/// Eager, captured, and input-mutated graph replay are byte-identical to both
/// the recording interpreter and an independent scalar CPU implementation.
#[test]
fn prepared_witness_eager_capture_and_mutated_replay_match_cpu() {
    let program = program();
    let requirements =
        witness_workspace_requirements(&program, ROWS, &[MULTIPLICITY_WORDS]).unwrap();
    let slots = workspace_slots(&requirements);
    let arena = arena(&requirements, &slots);

    // Address `a` maps to small-value id `a`; the recorded writer reads its low
    // 9-bit limb through both execution-table descriptor layers.
    let addr_to_id = (0..MULTIPLICITY_WORDS as u32).collect::<Vec<_>>();
    let f252_values = vec![[0u32; 8]];
    let small_values = (0..MULTIPLICITY_WORDS)
        .map(|index| (17 + 37 * index) as u128)
        .collect::<Vec<_>>();
    let tables = DeviceExecutionTables::upload(&addr_to_id, &f252_values, &small_values);
    let prepared = PreparedWitnessGraph::prepare(
        &arena,
        &program,
        ROWS,
        &[MULTIPLICITY_WORDS],
        &tables,
        &slots,
        PreparedWitnessMode::PreResolved,
    )
    .unwrap();
    assert!(prepared.installed_aot_receipt().is_none());
    assert_eq!(prepared.row_count(), ROWS);
    assert_eq!(
        prepared.kernel_identity().semantic_hash,
        program.semantic_hash()
    );
    assert_ne!(prepared.kernel_identity().cache_key, 0);
    assert_eq!(prepared.descriptor_slices().len(), 5);

    let addresses = (0..ROWS)
        .map(|row| (row % MULTIPLICITY_WORDS) as u32)
        .collect::<Vec<_>>();
    let addends = (0..ROWS)
        .map(|row| (M31_MODULUS - 20 + row as u32) % M31_MODULUS)
        .collect::<Vec<_>>();
    upload(&arena, prepared.input_columns()[0], &addresses);
    upload(&arena, prepared.input_columns()[1], &addends);
    arena.context().sync().unwrap();

    aot::reset_runtime_stats();
    arena.context().reset_telemetry();
    let clear = prepared.clear_multiplicities().unwrap();
    let launch = prepared.launch().unwrap();
    assert_eq!(clear.memset_bytes, (MULTIPLICITY_WORDS * 4) as u64);
    assert_eq!(launch.kernel_launches, 1);
    let hot = arena.context().telemetry();
    assert_eq!(hot.allocations, 0);
    assert_eq!(hot.h2d_bytes, 0);
    assert_eq!(hot.d2h_bytes, 0);
    assert_eq!(hot.d2d_bytes, 0);
    assert_eq!(hot.sync_calls, 0);
    assert_eq!(hot.memset_bytes, clear.memset_bytes);
    let kernel_stats = aot::runtime_stats();
    assert_eq!(kernel_stats.aot_loads, 0, "launch loaded a new AOT module");
    assert_eq!(
        kernel_stats.runtime_loads, 0,
        "launch invoked runtime compilation"
    );
    assert_eq!(
        snapshot(&arena, &prepared),
        reference(&program, &addresses, &addends, &small_values)
    );

    let capture = arena.context().capture().unwrap();
    prepared.clear_multiplicities().unwrap();
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
    assert_eq!(replay.sync_calls, 0);
    assert_eq!(
        snapshot(&arena, &prepared),
        reference(&program, &addresses, &addends, &small_values)
    );

    let mutated_addresses = addresses
        .iter()
        .map(|address| (address + 3) % MULTIPLICITY_WORDS as u32)
        .collect::<Vec<_>>();
    let mutated_addends = addends
        .iter()
        .map(|value| (value + 1_234_567) % M31_MODULUS)
        .collect::<Vec<_>>();
    upload(&arena, prepared.input_columns()[0], &mutated_addresses);
    upload(&arena, prepared.input_columns()[1], &mutated_addends);
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        snapshot(&arena, &prepared),
        reference(
            &program,
            &mutated_addresses,
            &mutated_addends,
            &small_values,
        )
    );

    // This test kernel is intentionally absent from the generated pack. Once the
    // strict monotonic switch is enabled, its already-runtime-resolved cache entry
    // must be rejected rather than reused inside a nominally AOT graph.
    let strict = PreparedWitnessGraph::prepare(
        &arena,
        &program,
        ROWS,
        &[MULTIPLICITY_WORDS],
        &tables,
        &slots,
        PreparedWitnessMode::RequireEmbeddedAot,
    );
    assert!(matches!(
        strict,
        Err(PreparedWitnessError::StrictAotUnavailable(_) | PreparedWitnessError::EmptyAotManifest)
    ));
}

/// Hardware-only authority gate for the checked-in add_opcode AOT artifact.
///
/// Run this test alone: strict AOT admission is process-wide and monotonic.
#[test]
#[ignore = "requires a CUDA device and an embedded AOT pack for its exact SM"]
fn strict_prepared_witness_retains_the_exact_installed_aot_receipt() {
    let program = stwo_backend_cuda::jit_witness::recorded_program("add_opcode").unwrap();
    let row_count = 257;
    let requirements = witness_workspace_requirements(program, row_count, &[]).unwrap();
    let slots = workspace_slots(&requirements);
    let arena = arena(&requirements, &slots);
    let tables = DeviceExecutionTables::upload(&[0], &[[0; 8]], &[0]);

    let prepared = PreparedWitnessGraph::prepare(
        &arena,
        program,
        row_count,
        &[],
        &tables,
        &slots,
        PreparedWitnessMode::RequireEmbeddedAot,
    )
    .unwrap();
    let receipt = prepared
        .installed_aot_receipt()
        .expect("strict graph retains its installed AOT authority");
    assert_eq!(receipt.manifest_identity(), aot::loaded_manifest_identity());
    assert_eq!(
        receipt.kernel_symbol(),
        prepared.kernel_identity().kernel_name.as_str()
    );
    assert_eq!(
        receipt.semantic_hash(),
        prepared.kernel_identity().semantic_hash
    );
    assert_eq!(receipt.cache_key(), prepared.kernel_identity().cache_key);
    assert_eq!(receipt.program_identity(), program.semantic_identity());
    assert_eq!(receipt.launch().grid(), [2, 1, 1]);
    assert_eq!(receipt.launch().block(), [256, 1, 1]);
    assert_eq!(receipt.launch().dynamic_shared_bytes(), 0);
}
