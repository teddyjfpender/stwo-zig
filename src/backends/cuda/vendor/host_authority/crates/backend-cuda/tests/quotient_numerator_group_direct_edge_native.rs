//! Native CUDA edge differential for direct quotient-numerator ownership.
//!
//! This target calls the production raw entry points. It covers the log-0
//! scalar fallback and the log-1 two-row owner against both the legacy device
//! formula and an independent host evaluation, including captured mutation.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{
    ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, DeviceArena,
};

const TERM_DESCRIPTORS: ArenaSlotId = ArenaSlotId(1);
const SOURCE_POINTERS: ArenaSlotId = ArenaSlotId(2);
const LINE_COEFFICIENTS: ArenaSlotId = ArenaSlotId(3);
const GROUP_B: ArenaSlotId = ArenaSlotId(4);
const GROUP_OFFSETS: ArenaSlotId = ArenaSlotId(5);
const GROUP_LOGS: ArenaSlotId = ArenaSlotId(6);
const LEGACY_OUTPUT_POINTERS: ArenaSlotId = ArenaSlotId(7);
const SOURCE_BASE: u32 = 100;
const DIRECT_OUTPUT_BASE: u32 = 200;
const LEGACY_OUTPUT_BASE: u32 = 300;
const GROUPS: usize = 2;
const COORDINATES: usize = 4;
const POINTER_WORDS: usize = core::mem::size_of::<usize>() / core::mem::size_of::<u32>();

#[derive(Clone, Copy)]
struct Term {
    source: u32,
    source_log: u32,
    b: SecureField,
    c: SecureField,
}

fn source_id(source: usize) -> ArenaSlotId {
    ArenaSlotId(SOURCE_BASE + source as u32)
}

fn output_id(base: u32, group: usize, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(base + (group * COORDINATES + coordinate) as u32)
}

fn build_arena(source_lengths: &[usize]) -> DeviceArena {
    let mut specs = Vec::new();
    let mut offset = 0usize;
    let mut add = |id, len_words, alignment_words: usize| {
        offset = offset.next_multiple_of(alignment_words);
        specs.push(ArenaSlotSpec {
            id,
            offset_words: offset,
            len_words,
            alignment_words,
        });
        offset += len_words;
    };

    add(TERM_DESCRIPTORS, 4 * 3, 1);
    add(
        SOURCE_POINTERS,
        source_lengths.len() * POINTER_WORDS,
        POINTER_WORDS,
    );
    add(LINE_COEFFICIENTS, 4 * 3 * COORDINATES, 1);
    add(GROUP_B, GROUPS * COORDINATES, 1);
    add(GROUP_OFFSETS, GROUPS + 1, 1);
    add(GROUP_LOGS, GROUPS, 1);
    add(
        LEGACY_OUTPUT_POINTERS,
        GROUPS * COORDINATES * POINTER_WORDS,
        POINTER_WORDS,
    );
    for (source, &len_words) in source_lengths.iter().enumerate() {
        add(source_id(source), len_words, 1);
    }
    for base in [DIRECT_OUTPUT_BASE, LEGACY_OUTPUT_BASE] {
        for group in 0..GROUPS {
            let rows = 1usize << group;
            for coordinate in 0..COORDINATES {
                add(output_id(base, group, coordinate), rows, 1);
            }
        }
    }

    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

fn upload<T>(arena: &DeviceArena, id: ArenaSlotId, values: &[T]) {
    let destination = arena.bind(id).unwrap();
    let bytes = core::mem::size_of_val(values);
    assert!(bytes <= destination.len_bytes());
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(destination.as_void_ptr(), values.as_ptr().cast(), bytes)
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

fn secure_words(values: &[SecureField]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn expected(
    terms: &[Term],
    sources: &[Vec<u32>],
    range: core::ops::Range<usize>,
    group_log: u32,
) -> Vec<Vec<u32>> {
    let rows = 1usize << group_log;
    let mut coordinates = vec![vec![0; rows]; COORDINATES];
    for row in 0..rows {
        let mut numerator = SecureField::from(0u32);
        for term in &terms[range.clone()] {
            let log_ratio = group_log - term.source_log;
            let source_row = (row >> (log_ratio + 1) << 1) + (row & 1);
            numerator += BaseField::from_u32_unchecked(sources[term.source as usize][source_row])
                * term.c
                - term.b;
        }
        for (coordinate, value) in numerator.to_m31_array().into_iter().enumerate() {
            coordinates[coordinate][row] = value.0;
        }
    }
    coordinates
}

fn snapshot(arena: &DeviceArena, base: u32) -> Vec<Vec<u32>> {
    (0..GROUPS)
        .flat_map(|group| {
            (0..COORDINATES).map(move |coordinate| {
                read(
                    arena,
                    arena.bind(output_id(base, group, coordinate)).unwrap(),
                )
            })
        })
        .collect()
}

fn poison_outputs(arena: &DeviceArena) {
    for base in [DIRECT_OUTPUT_BASE, LEGACY_OUTPUT_BASE] {
        for group in 0..GROUPS {
            for coordinate in 0..COORDINATES {
                let output = arena.bind(output_id(base, group, coordinate)).unwrap();
                unsafe {
                    arena
                        .context()
                        .fill_u32_async(output.as_u32_ptr(), 0xdead_beef, output.len_words())
                        .unwrap();
                }
            }
        }
    }
    arena.context().sync().unwrap();
}

fn launch_legacy(arena: &DeviceArena) {
    let output_pointers = arena.bind(LEGACY_OUTPUT_POINTERS).unwrap();
    let table = output_pointers.as_u32_ptr().cast::<*mut u32>();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_single_write_on(
            arena.bind(GROUP_OFFSETS).unwrap().as_u32_ptr(),
            arena.bind(TERM_DESCRIPTORS).unwrap().as_u32_ptr(),
            GROUPS as u32,
            2,
            arena.bind(SOURCE_POINTERS).unwrap().as_u32_ptr().cast(),
            arena.bind(LINE_COEFFICIENTS).unwrap().as_u32_ptr().cast(),
            arena.bind(GROUP_LOGS).unwrap().as_u32_ptr(),
            table,
            table.add(GROUPS),
            table.add(2 * GROUPS),
            table.add(3 * GROUPS),
            arena.context().stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0, "legacy quotient-numerator launch failed");
}

fn launch_direct(arena: &DeviceArena) {
    for group in 0..GROUPS {
        let term_begin = (group * 2) as u32;
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_accumulate_quotient_numerator_group_direct_on(
                arena.bind(TERM_DESCRIPTORS).unwrap().as_u32_ptr(),
                term_begin,
                term_begin + 2,
                group as u32,
                arena.bind(SOURCE_POINTERS).unwrap().as_u32_ptr().cast(),
                arena.bind(LINE_COEFFICIENTS).unwrap().as_u32_ptr().cast(),
                arena
                    .bind(GROUP_B)
                    .unwrap()
                    .as_u32_ptr()
                    .add(group * COORDINATES)
                    .cast(),
                arena
                    .bind(output_id(DIRECT_OUTPUT_BASE, group, 0))
                    .unwrap()
                    .as_u32_ptr(),
                arena
                    .bind(output_id(DIRECT_OUTPUT_BASE, group, 1))
                    .unwrap()
                    .as_u32_ptr(),
                arena
                    .bind(output_id(DIRECT_OUTPUT_BASE, group, 2))
                    .unwrap()
                    .as_u32_ptr(),
                arena
                    .bind(output_id(DIRECT_OUTPUT_BASE, group, 3))
                    .unwrap()
                    .as_u32_ptr(),
                arena.context().stream_raw().as_ptr(),
            )
        };
        assert_eq!(
            code, 0,
            "group-direct quotient-numerator launch {group} failed"
        );
    }
}

fn expected_snapshot(terms: &[Term], sources: &[Vec<u32>]) -> Vec<Vec<u32>> {
    [
        expected(terms, sources, 0..2, 0),
        expected(terms, sources, 2..4, 1),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[test]
fn scalar_and_paired_eager_capture_mutation_match_legacy_and_host() {
    let sf = SecureField::from_u32_unchecked;
    let terms = [
        Term {
            source: 0,
            source_log: 0,
            b: sf(0x7fff_ffed, 13, 17, 19),
            c: sf(23, 0x7fff_ffe7, 31, 37),
        },
        Term {
            source: 1,
            source_log: 0,
            b: sf(41, 43, 0x7fff_ffd9, 53),
            c: sf(59, 61, 67, 0x7fff_ffcf),
        },
        Term {
            source: 2,
            source_log: 1,
            b: sf(71, 73, 79, 83),
            c: sf(0x7fff_ffc5, 97, 101, 103),
        },
        Term {
            source: 3,
            source_log: 1,
            b: sf(107, 0x7fff_ffb9, 113, 127),
            c: sf(131, 137, 0x7fff_ffad, 149),
        },
    ];
    let mut sources = vec![
        vec![0x7fff_fffd],
        vec![123_456_789],
        vec![0x7fff_fffb, 17],
        vec![29, 0x7fff_fff9],
    ];
    let arena = build_arena(&sources.iter().map(Vec::len).collect::<Vec<_>>());
    let descriptors = terms
        .iter()
        .enumerate()
        .flat_map(|(term, descriptor)| [descriptor.source, term as u32, descriptor.source_log])
        .collect::<Vec<_>>();
    let zero = SecureField::from(0u32);
    let coefficients = terms
        .iter()
        .flat_map(|term| [zero, term.b, term.c])
        .collect::<Vec<_>>();
    let group_b = [terms[0].b + terms[1].b, terms[2].b + terms[3].b];
    upload(&arena, TERM_DESCRIPTORS, &descriptors);
    upload(&arena, LINE_COEFFICIENTS, &secure_words(&coefficients));
    upload(&arena, GROUP_B, &secure_words(&group_b));
    upload(&arena, GROUP_OFFSETS, &[0u32, 2, 4]);
    upload(&arena, GROUP_LOGS, &[0u32, 1]);
    for (source, values) in sources.iter().enumerate() {
        upload(&arena, source_id(source), values);
    }
    let source_pointers = (0..sources.len())
        .map(|source| arena.bind(source_id(source)).unwrap().as_u32_ptr() as usize)
        .collect::<Vec<_>>();
    upload(&arena, SOURCE_POINTERS, &source_pointers);
    let arena_ref = &arena;
    let legacy_output_pointers = (0..COORDINATES)
        .flat_map(|coordinate| {
            (0..GROUPS).map(move |group| {
                arena_ref
                    .bind(output_id(LEGACY_OUTPUT_BASE, group, coordinate))
                    .unwrap()
                    .as_u32_ptr() as usize
            })
        })
        .collect::<Vec<_>>();
    upload(&arena, LEGACY_OUTPUT_POINTERS, &legacy_output_pointers);

    poison_outputs(&arena);
    launch_legacy(&arena);
    launch_direct(&arena);
    arena.context().sync().unwrap();
    let eager_expected = expected_snapshot(&terms, &sources);
    let eager_legacy = snapshot(&arena, LEGACY_OUTPUT_BASE);
    let eager_direct = snapshot(&arena, DIRECT_OUTPUT_BASE);
    assert_eq!(
        eager_legacy, eager_expected,
        "legacy device formula drifted from host"
    );
    assert_eq!(
        eager_direct, eager_expected,
        "group-direct eager output mismatch"
    );

    let capture = arena.context().capture().unwrap();
    launch_direct(&arena);
    let graph = capture.finish().unwrap();
    assert_eq!(
        graph.kernel_nodes(),
        2,
        "scalar and paired launches must both be captured"
    );

    sources[0][0] = 181;
    sources[1][0] = 0x7fff_ffa3;
    sources[2].copy_from_slice(&[191, 193]);
    sources[3].copy_from_slice(&[0x7fff_ff91, 211]);
    for (source, values) in sources.iter().enumerate() {
        upload(&arena, source_id(source), values);
    }
    poison_outputs(&arena);
    launch_legacy(&arena);
    graph.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    let replay_expected = expected_snapshot(&terms, &sources);
    let replay_legacy = snapshot(&arena, LEGACY_OUTPUT_BASE);
    let replay_direct = snapshot(&arena, DIRECT_OUTPUT_BASE);
    assert_eq!(
        replay_legacy, replay_expected,
        "mutated legacy device formula drifted"
    );
    assert_eq!(
        replay_direct, replay_expected,
        "captured group-direct mutation mismatch"
    );
    assert_ne!(replay_direct[..COORDINATES], eager_direct[..COORDINATES]);
    assert_ne!(replay_direct[COORDINATES..], eager_direct[COORDINATES..]);
    for (source, expected) in sources.iter().enumerate() {
        assert_eq!(
            read(&arena, arena.bind(source_id(source)).unwrap()),
            *expected
        );
    }
}
