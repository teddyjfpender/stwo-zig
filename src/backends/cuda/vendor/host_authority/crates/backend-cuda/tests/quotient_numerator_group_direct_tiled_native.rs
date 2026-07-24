//! Exact native differential for the dormant 512-row tiled numerator owner.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{
    ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, CudaGraphExec,
    DeviceArena,
};

const GROUP_LOG: u32 = 9;
const ROWS: usize = 1 << GROUP_LOG;
const COORDINATES: usize = 4;
const POINTER_WORDS: usize = core::mem::size_of::<usize>() / 4;
const TERM_DESCRIPTORS: ArenaSlotId = ArenaSlotId(1);
const SOURCE_POINTERS: ArenaSlotId = ArenaSlotId(2);
const LINE_COEFFICIENTS: ArenaSlotId = ArenaSlotId(3);
const GROUP_B: ArenaSlotId = ArenaSlotId(4);
const SOURCE_BASE: u32 = 100;
const DIRECT_OUTPUT_BASE: u32 = 1_000;
const TILED_4K_OUTPUT_BASE: u32 = 2_000;
const TILED_16K_OUTPUT_BASE: u32 = 3_000;
const CONTRIBUTION_TILED_16K_OUTPUT_BASE: u32 = 4_000;

#[derive(Clone, Copy)]
enum LaunchVariant {
    Direct,
    RawTiled(u32),
    ContributionTiled,
}

#[derive(Clone)]
struct Term {
    source_log: u32,
    b: SecureField,
    c: SecureField,
}

fn source_id(index: usize) -> ArenaSlotId {
    ArenaSlotId(SOURCE_BASE + index as u32)
}

fn output_id(base: u32, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(base + coordinate as u32)
}

fn fixture_terms() -> Vec<Term> {
    let sf = SecureField::from_u32_unchecked;
    let mut logs = vec![6; 17];
    logs.extend([7, 9]);
    logs.into_iter()
        .enumerate()
        .map(|(index, source_log)| {
            let value = index as u32 * 32 + 1;
            Term {
                source_log,
                b: sf(value, value + 2, value + 4, value + 6),
                c: sf(value + 8, value + 10, value + 12, value + 14),
            }
        })
        .collect()
}

fn fixture_sources(terms: &[Term]) -> Vec<Vec<u32>> {
    terms
        .iter()
        .enumerate()
        .map(|(source, term)| {
            (0..1usize << term.source_log)
                .map(|row| {
                    let value = (source as u64 + 1) * 1_000_003 + row as u64 * 104_729;
                    (value % 2_147_483_646 + 1) as u32
                })
                .collect()
        })
        .collect()
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
    for base in [
        DIRECT_OUTPUT_BASE,
        TILED_4K_OUTPUT_BASE,
        TILED_16K_OUTPUT_BASE,
        CONTRIBUTION_TILED_16K_OUTPUT_BASE,
    ] {
        for coordinate in 0..COORDINATES {
            add(output_id(base, coordinate), ROWS, 1);
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

fn poison_outputs(arena: &DeviceArena) {
    for base in [
        DIRECT_OUTPUT_BASE,
        TILED_4K_OUTPUT_BASE,
        TILED_16K_OUTPUT_BASE,
        CONTRIBUTION_TILED_16K_OUTPUT_BASE,
    ] {
        for coordinate in 0..COORDINATES {
            let output = arena.bind(output_id(base, coordinate)).unwrap();
            unsafe {
                arena
                    .context()
                    .fill_u32_async(output.as_u32_ptr(), 0xdead_beef, ROWS)
                    .unwrap();
            }
        }
    }
    arena.context().sync().unwrap();
}

fn snapshot(arena: &DeviceArena, base: u32) -> Vec<Vec<u32>> {
    (0..COORDINATES)
        .map(|coordinate| read(arena, arena.bind(output_id(base, coordinate)).unwrap()))
        .collect()
}

fn launch(arena: &DeviceArena, output_base: u32, variant: LaunchVariant) {
    let output = |coordinate| {
        arena
            .bind(output_id(output_base, coordinate))
            .unwrap()
            .as_u32_ptr()
    };
    let descriptors = arena.bind(TERM_DESCRIPTORS).unwrap();
    let sources = arena.bind(SOURCE_POINTERS).unwrap();
    let coefficients = arena.bind(LINE_COEFFICIENTS).unwrap();
    let group_b = arena.bind(GROUP_B).unwrap();
    let stream = arena.context().stream_raw().as_ptr();
    let term_count = u32::try_from(descriptors.len_words() / 3).unwrap();
    let code = unsafe {
        match variant {
            LaunchVariant::Direct => {
                stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_on(
                    descriptors.as_u32_ptr(),
                    0,
                    term_count,
                    GROUP_LOG,
                    sources.as_u32_ptr().cast(),
                    coefficients.as_u32_ptr().cast(),
                    group_b.as_u32_ptr().cast(),
                    output(0),
                    output(1),
                    output(2),
                    output(3),
                    stream,
                )
            }
            LaunchVariant::RawTiled(tile_words) => {
                stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_tiled_on(
                    descriptors.as_u32_ptr(),
                    0,
                    term_count,
                    GROUP_LOG,
                    sources.as_u32_ptr().cast(),
                    coefficients.as_u32_ptr().cast(),
                    group_b.as_u32_ptr().cast(),
                    output(0),
                    output(1),
                    output(2),
                    output(3),
                    tile_words,
                    stream,
                )
            }
            LaunchVariant::ContributionTiled => {
                stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_contribution_tiled_on(
                descriptors.as_u32_ptr(),
                0,
                term_count,
                GROUP_LOG,
                sources.as_u32_ptr().cast(),
                coefficients.as_u32_ptr().cast(),
                group_b.as_u32_ptr().cast(),
                output(0),
                output(1),
                output(2),
                output(3),
                stream,
            )
            }
        }
    };
    assert_eq!(code, 0);
}

fn capture(arena: &DeviceArena, output_base: u32, variant: LaunchVariant) -> CudaGraphExec {
    let capture = arena.context().capture().unwrap();
    launch(arena, output_base, variant);
    let graph = capture.finish().unwrap();
    assert_eq!(graph.kernel_nodes(), 1);
    graph
}

#[test]
fn eager_capture_mutation_and_restoration_match_host_and_direct() {
    let terms = fixture_terms();
    let original_sources = fixture_sources(&terms);
    let mut sources = original_sources.clone();
    let arena = build_arena(&terms, &sources);
    let descriptors = terms
        .iter()
        .enumerate()
        .flat_map(|(source, term)| [source as u32, source as u32, term.source_log])
        .collect::<Vec<_>>();
    let zero = SecureField::from(0u32);
    let coefficients = terms
        .iter()
        .flat_map(|term| [zero, term.b, term.c])
        .collect::<Vec<_>>();
    let group_b = terms
        .iter()
        .fold(SecureField::from(0u32), |sum, term| sum + term.b);
    upload(&arena, TERM_DESCRIPTORS, &descriptors);
    upload(&arena, LINE_COEFFICIENTS, &secure_words(coefficients));
    upload(&arena, GROUP_B, &secure_words([group_b]));
    for (source, values) in sources.iter().enumerate() {
        upload(&arena, source_id(source), values);
    }
    let pointers = (0..sources.len())
        .map(|source| arena.bind(source_id(source)).unwrap().as_u32_ptr() as usize)
        .collect::<Vec<_>>();
    upload(&arena, SOURCE_POINTERS, &pointers);

    poison_outputs(&arena);
    launch(&arena, DIRECT_OUTPUT_BASE, LaunchVariant::Direct);
    launch(&arena, TILED_4K_OUTPUT_BASE, LaunchVariant::RawTiled(1024));
    launch(&arena, TILED_16K_OUTPUT_BASE, LaunchVariant::RawTiled(4096));
    launch(
        &arena,
        CONTRIBUTION_TILED_16K_OUTPUT_BASE,
        LaunchVariant::ContributionTiled,
    );
    arena.context().sync().unwrap();
    let eager = expected(&terms, &sources);
    assert_eq!(snapshot(&arena, DIRECT_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, TILED_4K_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, TILED_16K_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, CONTRIBUTION_TILED_16K_OUTPUT_BASE), eager);

    let direct = capture(&arena, DIRECT_OUTPUT_BASE, LaunchVariant::Direct);
    let tiled_4k = capture(&arena, TILED_4K_OUTPUT_BASE, LaunchVariant::RawTiled(1024));
    let tiled_16k = capture(&arena, TILED_16K_OUTPUT_BASE, LaunchVariant::RawTiled(4096));
    let contribution_tiled_16k = capture(
        &arena,
        CONTRIBUTION_TILED_16K_OUTPUT_BASE,
        LaunchVariant::ContributionTiled,
    );
    sources[0].fill(0x6bad_c0de);
    upload(&arena, source_id(0), &sources[0]);
    poison_outputs(&arena);
    direct.launch(arena.context()).unwrap();
    tiled_4k.launch(arena.context()).unwrap();
    tiled_16k.launch(arena.context()).unwrap();
    contribution_tiled_16k.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    let mutated = expected(&terms, &sources);
    assert_ne!(mutated, eager);
    assert_eq!(snapshot(&arena, DIRECT_OUTPUT_BASE), mutated);
    assert_eq!(snapshot(&arena, TILED_4K_OUTPUT_BASE), mutated);
    assert_eq!(snapshot(&arena, TILED_16K_OUTPUT_BASE), mutated);
    assert_eq!(
        snapshot(&arena, CONTRIBUTION_TILED_16K_OUTPUT_BASE),
        mutated
    );

    upload(&arena, source_id(0), &original_sources[0]);
    poison_outputs(&arena);
    direct.launch(arena.context()).unwrap();
    tiled_4k.launch(arena.context()).unwrap();
    tiled_16k.launch(arena.context()).unwrap();
    contribution_tiled_16k.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    assert_eq!(snapshot(&arena, DIRECT_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, TILED_4K_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, TILED_16K_OUTPUT_BASE), eager);
    assert_eq!(snapshot(&arena, CONTRIBUTION_TILED_16K_OUTPUT_BASE), eager);
}
