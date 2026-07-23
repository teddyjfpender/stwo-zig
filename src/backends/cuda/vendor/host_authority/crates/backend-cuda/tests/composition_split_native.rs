//! Exact-shape native CUDA differential for Composition coefficient splitting.
//!
//! At log 24 and 25 this compares the terminal fallback and fused paths over
//! every retained and source word in eager execution, one captured replay, a
//! mutated replay, and the red zones. Run on a CUDA device with:
//!
//! ```text
//! /usr/bin/time -v cargo test -p stwo-backend-cuda \
//!   --test composition_split_native --release -- --ignored --nocapture
//! ```

#![cfg(stwo_cuda_link)]

use std::time::Instant;

use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo_backend_cuda::{
    gpu_memory_info, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec, CompositionSplitColumns,
    CompositionSplitError, CompositionSplitLaunchMode, CompositionSplitPointerSlots,
    CompositionSplitProgram, CudaExecContext, DeviceArena, PreparedCompositionSplitGraph,
    COMPOSITION_RETAINED_COLUMNS, COMPOSITION_SOURCE_COORDINATES,
};

const MODULUS: u32 = 0x7fff_ffff;
const GUARD_WORD: u32 = 0xdead_beef;
const GUARD_WORDS: usize = 64;
const HOST_CHUNK_WORDS: usize = 1 << 20;

const INVERSE_TWIDDLES: ArenaSlotId = ArenaSlotId(1);
const FORWARD_TWIDDLES: ArenaSlotId = ArenaSlotId(2);
const FALLBACK_SOURCE_POINTERS: ArenaSlotId = ArenaSlotId(3);
const FALLBACK_OUTPUT_POINTERS: ArenaSlotId = ArenaSlotId(4);
const FUSED_SOURCE_POINTERS: ArenaSlotId = ArenaSlotId(5);
const FUSED_OUTPUT_POINTERS: ArenaSlotId = ArenaSlotId(6);
const FALLBACK_SOURCE_BASE: u32 = 100;
const FUSED_SOURCE_BASE: u32 = 200;
const FALLBACK_OUTPUT_BASE: u32 = 300;
const FUSED_OUTPUT_BASE: u32 = 400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WordDigest {
    sum: u64,
    mixed: u64,
}

impl WordDigest {
    fn absorb(&mut self, word: u32, index: usize) {
        let keyed = u64::from(word) ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.sum = self.sum.wrapping_add(keyed);
        self.mixed = self
            .mixed
            .rotate_left(9)
            .wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ keyed;
    }
}

#[derive(Debug)]
struct CaseReceipt {
    log_size: u32,
    arena_bytes: usize,
    pool_used_bytes: usize,
    pool_reserved_bytes: usize,
    graph_kernel_nodes: u64,
    eager_digest: WordDigest,
    capture_digest: WordDigest,
    mutation_digest: WordDigest,
    elapsed_ms: u128,
}

fn ids<const N: usize>(base: u32) -> [ArenaSlotId; N] {
    std::array::from_fn(|index| ArenaSlotId(base + index as u32))
}

fn add_slot(
    specs: &mut Vec<ArenaSlotSpec>,
    offset: &mut usize,
    id: ArenaSlotId,
    len_words: usize,
    alignment_words: usize,
) {
    *offset = offset.next_multiple_of(alignment_words);
    specs.push(ArenaSlotSpec {
        id,
        offset_words: *offset,
        len_words,
        alignment_words,
    });
    *offset += len_words;
}

fn build_arena(log_size: u32, program: CompositionSplitProgram) -> DeviceArena {
    let rows = 1usize << log_size;
    let twiddle_words = rows / 2;
    let mut specs = Vec::new();
    let mut offset = 0usize;
    add_slot(&mut specs, &mut offset, INVERSE_TWIDDLES, twiddle_words, 1);
    add_slot(&mut specs, &mut offset, FORWARD_TWIDDLES, twiddle_words, 1);
    for slot in ids::<COMPOSITION_SOURCE_COORDINATES>(FALLBACK_SOURCE_BASE)
        .into_iter()
        .chain(ids::<COMPOSITION_SOURCE_COORDINATES>(FUSED_SOURCE_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(FALLBACK_OUTPUT_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(FUSED_OUTPUT_BASE))
    {
        // The final N2B kernels use aligned uint64 stores.
        add_slot(&mut specs, &mut offset, slot, rows + GUARD_WORDS, 2);
    }
    for slots in [
        CompositionSplitPointerSlots {
            source_pointers: FALLBACK_SOURCE_POINTERS,
            retained_pointers: FALLBACK_OUTPUT_POINTERS,
        },
        CompositionSplitPointerSlots {
            source_pointers: FUSED_SOURCE_POINTERS,
            retained_pointers: FUSED_OUTPUT_POINTERS,
        },
    ] {
        for requirement in program.arena_slot_requirements(slots).unwrap() {
            add_slot(
                &mut specs,
                &mut offset,
                requirement.id,
                requirement.len_words,
                requirement.alignment_words,
            );
        }
    }
    let layout = ArenaLayout::new(offset, &specs).unwrap();
    DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap()
}

fn upload(arena: &DeviceArena, destination: ArenaSlice, words: &[u32]) {
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
    arena.context().sync().unwrap();
}

fn upload_twiddles(arena: &DeviceArena, log_size: u32) {
    let tree =
        CpuBackend::precompute_twiddles(CanonicCoset::new(log_size).circle_domain().half_coset);
    let inverse = tree
        .itwiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    upload(arena, arena.bind(INVERSE_TWIDDLES).unwrap(), &inverse);
    drop(inverse);
    let forward = tree
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    upload(arena, arena.bind(FORWARD_TWIDDLES).unwrap(), &forward);
}

fn pattern_word(seed: u64, coordinate: usize, row: usize) -> u32 {
    let mut value = seed
        ^ (coordinate as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (row as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    ((value ^ (value >> 31)) % u64::from(MODULUS)) as u32
}

fn fill_guard(arena: &DeviceArena, slot: ArenaSlotId, rows: usize) {
    let guard = arena
        .bind(slot)
        .unwrap()
        .checked_subslice(rows, GUARD_WORDS)
        .unwrap();
    unsafe {
        arena
            .context()
            .fill_u32_async(guard.as_u32_ptr(), GUARD_WORD, GUARD_WORDS)
            .unwrap();
    }
}

fn reset_inputs(arena: &DeviceArena, log_size: u32, seed: u64) {
    let rows = 1usize << log_size;
    let fallback_sources = ids::<COMPOSITION_SOURCE_COORDINATES>(FALLBACK_SOURCE_BASE);
    let fused_sources = ids::<COMPOSITION_SOURCE_COORDINATES>(FUSED_SOURCE_BASE);
    let outputs = ids::<COMPOSITION_RETAINED_COLUMNS>(FALLBACK_OUTPUT_BASE)
        .into_iter()
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(FUSED_OUTPUT_BASE));
    for slot in fallback_sources
        .into_iter()
        .chain(fused_sources)
        .chain(outputs.clone())
    {
        fill_guard(arena, slot, rows);
    }
    for slot in outputs {
        let output = arena.bind(slot).unwrap().checked_subslice(0, rows).unwrap();
        unsafe {
            arena
                .context()
                .fill_u32_async(output.as_u32_ptr(), GUARD_WORD, rows)
                .unwrap();
        }
    }
    arena.context().sync().unwrap();

    let mut host = vec![0u32; HOST_CHUNK_WORDS.min(rows)];
    for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
        let fallback = arena.bind(fallback_sources[coordinate]).unwrap();
        let fused = arena.bind(fused_sources[coordinate]).unwrap();
        for first in (0..rows).step_by(HOST_CHUNK_WORDS) {
            let count = HOST_CHUNK_WORDS.min(rows - first);
            for (local, word) in host[..count].iter_mut().enumerate() {
                *word = pattern_word(seed, coordinate, first + local);
            }
            for destination in [fallback, fused] {
                let destination = destination.checked_subslice(first, count).unwrap();
                unsafe {
                    arena
                        .context()
                        .memcpy_h2d_async(
                            destination.as_void_ptr(),
                            host.as_ptr().cast(),
                            count * core::mem::size_of::<u32>(),
                        )
                        .unwrap();
                }
            }
            // The pageable host chunk is reused only after both copies finish.
            arena.context().sync().unwrap();
        }
    }
}

fn read_words(arena: &DeviceArena, source: ArenaSlice, output: &mut [u32]) {
    assert_eq!(source.len_words(), output.len());
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                output.as_mut_ptr().cast(),
                source.as_void_ptr(),
                core::mem::size_of_val(output),
            )
            .unwrap();
    }
}

fn compare_pair(
    arena: &DeviceArena,
    left: ArenaSlice,
    right: ArenaSlice,
    words: usize,
    label: &str,
    digest: &mut WordDigest,
) {
    let chunk_words = HOST_CHUNK_WORDS.min(words);
    let mut left_host = vec![0u32; chunk_words];
    let mut right_host = vec![0u32; chunk_words];
    for first in (0..words).step_by(HOST_CHUNK_WORDS) {
        let count = HOST_CHUNK_WORDS.min(words - first);
        read_words(
            arena,
            left.checked_subslice(first, count).unwrap(),
            &mut left_host[..count],
        );
        read_words(
            arena,
            right.checked_subslice(first, count).unwrap(),
            &mut right_host[..count],
        );
        arena.context().sync().unwrap();
        for local in 0..count {
            let row = first + local;
            let left_word = left_host[local];
            let right_word = right_host[local];
            assert_eq!(left_word, right_word, "{label} mismatch at row {row}");
            assert!(left_word < MODULUS, "{label} non-canonical at row {row}");
            digest.absorb(left_word, row);
        }
    }
}

fn assert_guards(arena: &DeviceArena, log_size: u32) {
    let rows = 1usize << log_size;
    let mut words = [0u32; GUARD_WORDS];
    for slot in ids::<COMPOSITION_SOURCE_COORDINATES>(FALLBACK_SOURCE_BASE)
        .into_iter()
        .chain(ids::<COMPOSITION_SOURCE_COORDINATES>(FUSED_SOURCE_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(FALLBACK_OUTPUT_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(FUSED_OUTPUT_BASE))
    {
        let guard = arena
            .bind(slot)
            .unwrap()
            .checked_subslice(rows, GUARD_WORDS)
            .unwrap();
        read_words(arena, guard, &mut words);
        arena.context().sync().unwrap();
        assert!(
            words.iter().all(|&word| word == GUARD_WORD),
            "guard {slot:?}"
        );
    }
}

fn verify(arena: &DeviceArena, log_size: u32) -> WordDigest {
    let rows = 1usize << log_size;
    let mut output_digest = WordDigest { sum: 0, mixed: 0 };
    for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
        let left = arena
            .bind(ArenaSlotId(FALLBACK_SOURCE_BASE + coordinate as u32))
            .unwrap();
        let right = arena
            .bind(ArenaSlotId(FUSED_SOURCE_BASE + coordinate as u32))
            .unwrap();
        let mut ignored = WordDigest { sum: 0, mixed: 0 };
        compare_pair(
            arena,
            left,
            right,
            rows,
            &format!("source coordinate {coordinate}"),
            &mut ignored,
        );
    }
    for column in 0..COMPOSITION_RETAINED_COLUMNS {
        let left = arena
            .bind(ArenaSlotId(FALLBACK_OUTPUT_BASE + column as u32))
            .unwrap();
        let right = arena
            .bind(ArenaSlotId(FUSED_OUTPUT_BASE + column as u32))
            .unwrap();
        compare_pair(
            arena,
            left,
            right,
            rows,
            &format!("retained column {column}"),
            &mut output_digest,
        );
    }
    assert_guards(arena, log_size);
    output_digest
}

fn columns(arena: &DeviceArena, source_base: u32, output_base: u32) -> CompositionSplitColumns {
    CompositionSplitColumns {
        source_evaluations: ids::<COMPOSITION_SOURCE_COORDINATES>(source_base)
            .map(|slot| arena.bind(slot).unwrap()),
        retained_evaluations: ids::<COMPOSITION_RETAINED_COLUMNS>(output_base)
            .map(|slot| arena.bind(slot).unwrap()),
    }
}

fn run_case(log_size: u32) -> CaseReceipt {
    assert!(matches!(log_size, 24 | 25));
    let started = Instant::now();
    let program = CompositionSplitProgram::compile(log_size).unwrap();
    let arena = build_arena(log_size, program);
    let arena_bytes = arena.layout().total_words() * core::mem::size_of::<u32>();
    upload_twiddles(&arena, log_size);
    let inverse = arena.bind(INVERSE_TWIDDLES).unwrap();
    let forward = arena.bind(FORWARD_TWIDDLES).unwrap();
    let fallback = PreparedCompositionSplitGraph::prepare(
        &arena,
        program,
        CompositionSplitLaunchMode::TerminalFallback,
        CompositionSplitPointerSlots {
            source_pointers: FALLBACK_SOURCE_POINTERS,
            retained_pointers: FALLBACK_OUTPUT_POINTERS,
        },
        columns(&arena, FALLBACK_SOURCE_BASE, FALLBACK_OUTPUT_BASE),
        inverse,
        forward,
    )
    .unwrap();
    let fused = PreparedCompositionSplitGraph::prepare(
        &arena,
        program,
        CompositionSplitLaunchMode::FusedFirstForward,
        CompositionSplitPointerSlots {
            source_pointers: FUSED_SOURCE_POINTERS,
            retained_pointers: FUSED_OUTPUT_POINTERS,
        },
        columns(&arena, FUSED_SOURCE_BASE, FUSED_OUTPUT_BASE),
        inverse,
        forward,
    )
    .unwrap();

    reset_inputs(&arena, log_size, 0x0123_4567_89ab_cdef);
    fallback.launch().unwrap();
    fused.launch().unwrap();
    arena.context().sync().unwrap();
    let eager_digest = verify(&arena, log_size);

    reset_inputs(&arena, log_size, 0x89ab_cdef_0123_4567);
    let capture = arena.context().capture().unwrap();
    fallback.launch().unwrap();
    fused.launch().unwrap();
    let graph = capture.finish().unwrap();
    let expected_nodes = u64::from(
        program.traffic().terminal_fallback_kernel_launches
            + program.traffic().fused_kernel_launches,
    );
    assert_eq!(graph.kernel_nodes(), expected_nodes);
    graph.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    let capture_digest = verify(&arena, log_size);

    reset_inputs(&arena, log_size, 0xfedc_ba98_7654_3210);
    graph.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    let mutation_digest = verify(&arena, log_size);
    assert_ne!(eager_digest, capture_digest);
    assert_ne!(capture_digest, mutation_digest);

    let pool = arena.context().pool_memory().unwrap();
    CaseReceipt {
        log_size,
        arena_bytes,
        pool_used_bytes: pool.used_bytes,
        pool_reserved_bytes: pool.reserved_bytes,
        graph_kernel_nodes: graph.kernel_nodes(),
        eager_digest,
        capture_digest,
        mutation_digest,
        elapsed_ms: started.elapsed().as_millis(),
    }
}

fn requested_logs() -> Vec<u32> {
    let mut logs = std::env::var("STWO_COMPOSITION_SPLIT_LOGS")
        .unwrap_or_else(|_| "24,25".to_owned())
        .split(',')
        .map(|value| value.trim().parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    logs.sort_unstable();
    logs.dedup();
    assert!(!logs.is_empty());
    assert!(logs.iter().all(|log| matches!(log, 24 | 25)));
    logs
}

#[test]
#[ignore = "requires exact log24/log25 native CUDA execution"]
fn composition_split_exact_shape_fallback_matches_fused_eager_and_graph() {
    assert!(matches!(
        CompositionSplitProgram::compile(23),
        Err(CompositionSplitError::UnsupportedProductionLog(23))
    ));
    assert!(matches!(
        CompositionSplitProgram::compile(26),
        Err(CompositionSplitError::UnsupportedProductionLog(26))
    ));
    assert!(stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT);
    let requested_logs = requested_logs();
    let memory_before = gpu_memory_info();
    let receipts = requested_logs.into_iter().map(run_case).collect::<Vec<_>>();
    let memory_after = gpu_memory_info();
    let cases = receipts
        .iter()
        .map(|receipt| {
            serde_json::json!({
                "log_size": receipt.log_size,
                "arena_bytes": receipt.arena_bytes,
                "pool_used_bytes": receipt.pool_used_bytes,
                "pool_reserved_bytes": receipt.pool_reserved_bytes,
                "graph_kernel_nodes": receipt.graph_kernel_nodes,
                "eager_digest": [receipt.eager_digest.sum, receipt.eager_digest.mixed],
                "capture_digest": [receipt.capture_digest.sum, receipt.capture_digest.mixed],
                "mutation_digest": [receipt.mutation_digest.sum, receipt.mutation_digest.mixed],
                "elapsed_ms": receipt.elapsed_ms,
            })
        })
        .collect::<Vec<_>>();
    eprintln!(
        "STWO_COMPOSITION_SPLIT_NATIVE_RECEIPT_JSON={}",
        serde_json::json!({
            "schema": "stwo.composition-split-native.v1",
            "passed": true,
            "log24_fused_launch_threads": 256,
            "all_retained_bytes_equal": true,
            "source_clobber_bytes_equal": true,
            "guards_preserved": true,
            "eager": true,
            "capture_replay": true,
            "mutated_replay": true,
            "host_chunk_bytes": HOST_CHUNK_WORDS * core::mem::size_of::<u32>(),
            "memory_before": memory_before,
            "memory_after": memory_after,
            "cases": cases,
        })
    );
}
