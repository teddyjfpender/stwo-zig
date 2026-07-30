//! Native differential and captured-manifest lifetime gate for run sums.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{
    ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, CudaGraphExec,
    DeviceArena,
};
use stwo_backend_cuda_kernels::raw::{CudaQuotientNativeRunEntry, CudaQuotientNativeRunManifest};

const GROUP_LOG: u32 = 9;
const ROWS: usize = 1 << GROUP_LOG;
const COORDINATES: usize = 4;
const MODULUS_MINUS_ONE: u32 = 2_147_483_646;
const MODULUS_MINUS_TWO: u32 = 2_147_483_645;
const POINTER_WORDS: usize = core::mem::size_of::<usize>() / 4;
const SCRATCH_WORDS: usize = 64 + 128;
const TERM_DESCRIPTORS: ArenaSlotId = ArenaSlotId(1);
const SOURCE_POINTERS: ArenaSlotId = ArenaSlotId(2);
const LINE_COEFFICIENTS: ArenaSlotId = ArenaSlotId(3);
const GROUP_B: ArenaSlotId = ArenaSlotId(4);
const SOURCE_BASE: u32 = 100;
const SCRATCH_BASE: u32 = 1_000;
const DIRECT_OUTPUT_BASE: u32 = 2_000;
const RUN_SUM_OUTPUT_BASE: u32 = 3_000;

#[derive(Clone)]
struct Term {
    source_log: u32,
    b: SecureField,
    c: SecureField,
}

fn source_id(index: usize) -> ArenaSlotId {
    ArenaSlotId(SOURCE_BASE + index as u32)
}

fn coordinate_id(base: u32, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(base + coordinate as u32)
}

fn fixture_terms() -> Vec<Term> {
    let sf = SecureField::from_u32_unchecked;
    [6, 6, 7, 7, 9, 9]
        .into_iter()
        .enumerate()
        .map(|(index, source_log)| {
            let value = index as u32 * 32 + 1;
            Term {
                source_log,
                b: if index == 0 {
                    sf(MODULUS_MINUS_ONE, MODULUS_MINUS_TWO, value + 4, value + 6)
                } else {
                    sf(value, value + 2, value + 4, value + 6)
                },
                c: if index == 1 {
                    sf(MODULUS_MINUS_TWO, MODULUS_MINUS_ONE, value + 12, value + 14)
                } else {
                    sf(value + 8, value + 10, value + 12, value + 14)
                },
            }
        })
        .collect()
}

fn fixture_sources(terms: &[Term]) -> Vec<Vec<u32>> {
    terms
        .iter()
        .enumerate()
        .map(|(source, term)| {
            let mut values = (0..1usize << term.source_log)
                .map(|row| {
                    let value = (source as u64 + 1) * 1_000_003 + row as u64 * 104_729;
                    (value % 2_147_483_646 + 1) as u32
                })
                .collect::<Vec<_>>();
            values[0] = MODULUS_MINUS_ONE;
            values[1] = MODULUS_MINUS_TWO;
            values
        })
        .collect()
}

fn manifest() -> CudaQuotientNativeRunManifest {
    let mut manifest = CudaQuotientNativeRunManifest {
        run_count: 2,
        direct_term_begin: 4,
        direct_term_end: 6,
        target_log_size: GROUP_LOG,
        ..Default::default()
    };
    manifest.runs[0] = CudaQuotientNativeRunEntry {
        term_begin: 0,
        term_end: 2,
        source_log_size: 6,
        scratch_offset_words: 0,
    };
    manifest.runs[1] = CudaQuotientNativeRunEntry {
        term_begin: 2,
        term_end: 4,
        source_log_size: 7,
        scratch_offset_words: 64,
    };
    manifest
}

fn build_arena(terms: &[Term], sources: &[Vec<u32>]) -> DeviceArena {
    let mut specs = Vec::new();
    let mut cursor = 0usize;
    let mut add = |id, len_words, alignment_words: usize| {
        cursor = cursor.next_multiple_of(alignment_words);
        specs.push(ArenaSlotSpec {
            id,
            offset_words: cursor,
            len_words,
            alignment_words,
        });
        cursor += len_words;
    };
    add(TERM_DESCRIPTORS, terms.len() * 3, 1);
    add(SOURCE_POINTERS, terms.len() * POINTER_WORDS, POINTER_WORDS);
    add(LINE_COEFFICIENTS, terms.len() * 3 * COORDINATES, 1);
    add(GROUP_B, COORDINATES, 1);
    for (index, source) in sources.iter().enumerate() {
        add(source_id(index), source.len(), 1);
    }
    for coordinate in 0..COORDINATES {
        add(coordinate_id(SCRATCH_BASE, coordinate), SCRATCH_WORDS, 1);
    }
    for base in [DIRECT_OUTPUT_BASE, RUN_SUM_OUTPUT_BASE] {
        for coordinate in 0..COORDINATES {
            add(coordinate_id(base, coordinate), ROWS, 1);
        }
    }
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(cursor, &specs).unwrap(),
    )
    .unwrap()
}

fn upload<T>(arena: &DeviceArena, id: ArenaSlotId, values: &[T]) {
    let destination = arena.bind(id).unwrap();
    assert!(core::mem::size_of_val(values) <= destination.len_bytes());
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
    arena.context().sync().unwrap();
}

fn read(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut words = vec![0; source.len_words()];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                source.as_void_ptr(),
                source.len_bytes(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    words
}

fn secure_words(values: impl IntoIterator<Item = SecureField>) -> Vec<u32> {
    values
        .into_iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn coefficient_words(terms: &[Term]) -> Vec<u32> {
    let zero = SecureField::from(0u32);
    secure_words(terms.iter().flat_map(|term| [zero, term.b, term.c]))
}

fn source_row(row: usize, source_log: u32) -> usize {
    let distance = GROUP_LOG - source_log;
    (row >> (distance + 1) << 1) + (row & 1)
}

fn expected(terms: &[Term], sources: &[Vec<u32>]) -> Vec<Vec<u32>> {
    let mut output = vec![vec![0; ROWS]; COORDINATES];
    for row in 0..ROWS {
        let mut numerator = SecureField::from(0u32);
        for (source, term) in terms.iter().enumerate() {
            numerator +=
                BaseField::from_u32_unchecked(sources[source][source_row(row, term.source_log)])
                    * term.c
                    - term.b;
        }
        for (coordinate, value) in numerator.to_m31_array().into_iter().enumerate() {
            output[coordinate][row] = value.0;
        }
    }
    output
}

fn coordinate_ptr(arena: &DeviceArena, base: u32, coordinate: usize) -> *mut u32 {
    arena
        .bind(coordinate_id(base, coordinate))
        .unwrap()
        .as_u32_ptr()
}

fn poison_outputs(arena: &DeviceArena) {
    for base in [DIRECT_OUTPUT_BASE, RUN_SUM_OUTPUT_BASE] {
        for coordinate in 0..COORDINATES {
            unsafe {
                arena
                    .context()
                    .fill_u32_async(coordinate_ptr(arena, base, coordinate), 0xdead_beef, ROWS)
                    .unwrap();
            }
        }
    }
    arena.context().sync().unwrap();
}

fn snapshot(arena: &DeviceArena, base: u32) -> Vec<Vec<u32>> {
    (0..COORDINATES)
        .map(|coordinate| read(arena, arena.bind(coordinate_id(base, coordinate)).unwrap()))
        .collect()
}

fn launch_precompute(arena: &DeviceArena, manifest: &CudaQuotientNativeRunManifest) {
    let descriptors = arena.bind(TERM_DESCRIPTORS).unwrap();
    let sources = arena.bind(SOURCE_POINTERS).unwrap();
    let coefficients = arena.bind(LINE_COEFFICIENTS).unwrap();
    let stream = arena.context().stream_raw().as_ptr();
    for run in &manifest.runs[..manifest.run_count as usize] {
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_precompute_quotient_numerator_native_run_on(
                descriptors.as_u32_ptr(),
                run.term_begin,
                run.term_end,
                run.source_log_size,
                sources.as_u32_ptr().cast(),
                coefficients.as_u32_ptr().cast(),
                coordinate_ptr(arena, SCRATCH_BASE, 0),
                coordinate_ptr(arena, SCRATCH_BASE, 1),
                coordinate_ptr(arena, SCRATCH_BASE, 2),
                coordinate_ptr(arena, SCRATCH_BASE, 3),
                run.scratch_offset_words,
                stream,
            )
        };
        assert_eq!(code, 0);
    }
}

fn launch_direct(arena: &DeviceArena) {
    let descriptors = arena.bind(TERM_DESCRIPTORS).unwrap();
    let sources = arena.bind(SOURCE_POINTERS).unwrap();
    let coefficients = arena.bind(LINE_COEFFICIENTS).unwrap();
    let group_b = arena.bind(GROUP_B).unwrap();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_on(
            descriptors.as_u32_ptr(),
            0,
            6,
            GROUP_LOG,
            sources.as_u32_ptr().cast(),
            coefficients.as_u32_ptr().cast(),
            group_b.as_u32_ptr().cast(),
            coordinate_ptr(arena, DIRECT_OUTPUT_BASE, 0),
            coordinate_ptr(arena, DIRECT_OUTPUT_BASE, 1),
            coordinate_ptr(arena, DIRECT_OUTPUT_BASE, 2),
            coordinate_ptr(arena, DIRECT_OUTPUT_BASE, 3),
            arena.context().stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);
}

fn launch_expand(arena: &DeviceArena, manifest: &CudaQuotientNativeRunManifest) {
    let descriptors = arena.bind(TERM_DESCRIPTORS).unwrap();
    let sources = arena.bind(SOURCE_POINTERS).unwrap();
    let coefficients = arena.bind(LINE_COEFFICIENTS).unwrap();
    let group_b = arena.bind(GROUP_B).unwrap();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_expand_quotient_numerator_native_run_sums_on(
            manifest,
            descriptors.as_u32_ptr(),
            sources.as_u32_ptr().cast(),
            coefficients.as_u32_ptr().cast(),
            group_b.as_u32_ptr().cast(),
            coordinate_ptr(arena, SCRATCH_BASE, 0),
            coordinate_ptr(arena, SCRATCH_BASE, 1),
            coordinate_ptr(arena, SCRATCH_BASE, 2),
            coordinate_ptr(arena, SCRATCH_BASE, 3),
            coordinate_ptr(arena, RUN_SUM_OUTPUT_BASE, 0),
            coordinate_ptr(arena, RUN_SUM_OUTPUT_BASE, 1),
            coordinate_ptr(arena, RUN_SUM_OUTPUT_BASE, 2),
            coordinate_ptr(arena, RUN_SUM_OUTPUT_BASE, 3),
            arena.context().stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0);
}

fn capture_candidate_from_stack(arena: &DeviceArena) -> CudaGraphExec {
    let stack_manifest = manifest();
    let capture = arena.context().capture().unwrap();
    launch_precompute(arena, &stack_manifest);
    launch_expand(arena, &stack_manifest);
    let graph = capture.finish().unwrap();
    assert_eq!(
        graph.kernel_nodes(),
        u64::from(stack_manifest.run_count) + 1
    );
    graph
}

#[test]
fn eager_and_captured_stack_manifest_match_direct_after_mutation_and_restore() {
    let mut terms = fixture_terms();
    let original_terms = terms.clone();
    let original_sources = fixture_sources(&terms);
    let mut sources = original_sources.clone();
    let arena = build_arena(&terms, &sources);
    let descriptors = terms
        .iter()
        .enumerate()
        .flat_map(|(source, term)| [source as u32, source as u32, term.source_log])
        .collect::<Vec<_>>();
    let group_b = terms
        .iter()
        .fold(SecureField::from(0u32), |sum, term| sum + term.b);
    upload(&arena, TERM_DESCRIPTORS, &descriptors);
    upload(&arena, LINE_COEFFICIENTS, &coefficient_words(&terms));
    upload(&arena, GROUP_B, &secure_words([group_b]));
    for (source, values) in sources.iter().enumerate() {
        upload(&arena, source_id(source), values);
    }
    let pointers = (0..sources.len())
        .map(|source| arena.bind(source_id(source)).unwrap().as_u32_ptr() as usize)
        .collect::<Vec<_>>();
    upload(&arena, SOURCE_POINTERS, &pointers);

    let run_manifest = manifest();
    poison_outputs(&arena);
    launch_precompute(&arena, &run_manifest);
    launch_direct(&arena);
    launch_expand(&arena, &run_manifest);
    arena.context().sync().unwrap();
    let eager = expected(&terms, &sources);
    assert_eq!(snapshot(&arena, DIRECT_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, RUN_SUM_OUTPUT_BASE), eager);

    let captured_candidate = capture_candidate_from_stack(&arena);
    sources[0].fill(0x6bad_c0de);
    terms[1].c = SecureField::from_u32_unchecked(MODULUS_MINUS_ONE, 17, MODULUS_MINUS_TWO, 19);
    upload(&arena, source_id(0), &sources[0]);
    upload(&arena, LINE_COEFFICIENTS, &coefficient_words(&terms));
    poison_outputs(&arena);
    launch_direct(&arena);
    captured_candidate.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    let mutated = expected(&terms, &sources);
    assert_ne!(mutated, eager);
    assert_eq!(snapshot(&arena, DIRECT_OUTPUT_BASE), mutated);
    assert_eq!(snapshot(&arena, RUN_SUM_OUTPUT_BASE), mutated);

    upload(&arena, source_id(0), &original_sources[0]);
    terms[1].c = original_terms[1].c;
    upload(&arena, LINE_COEFFICIENTS, &coefficient_words(&terms));
    poison_outputs(&arena);
    launch_direct(&arena);
    captured_candidate.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    assert_eq!(snapshot(&arena, DIRECT_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, RUN_SUM_OUTPUT_BASE), eager);
}
