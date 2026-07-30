//! Native CUDA differential for the two hand-written arena witness producers.
//!
//! Hardware admission should require exactly two passed tests from this target;
//! a CPU/stub build compiles zero tests and is not soundness evidence.

#![cfg(stwo_cuda_link)]

use std::collections::BTreeMap;

use stwo::core::fields::m31::BaseField;
use stwo_backend_cuda::{blake_witness, memory_witness, BaseFieldVec, CudaExecContext};

fn upload(words: impl IntoIterator<Item = u32>) -> BaseFieldVec {
    BaseFieldVec::from_vec(
        words
            .into_iter()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    )
}

fn download(column: &BaseFieldVec) -> Vec<u32> {
    column.to_vec().into_iter().map(|value| value.0).collect()
}

#[test]
fn blake_g_arena_outputs_match_legacy_trace_and_generated_flat_abis() {
    const ROWS: usize = 16;
    const LOOKUP_TUPLE_COLS: [[usize; 3]; 16] = [
        [53, 55, 18],
        [14, 16, 19],
        [54, 56, 20],
        [15, 17, 21],
        [57, 59, 28],
        [24, 26, 29],
        [58, 60, 30],
        [25, 27, 31],
        [61, 63, 38],
        [34, 36, 39],
        [62, 64, 40],
        [35, 37, 41],
        [65, 67, 48],
        [44, 46, 49],
        [66, 68, 50],
        [45, 47, 51],
    ];
    // SubComponentInputs is flattened by relation field, then instance.  It
    // contains the same tuples as LookupData in a different generated ABI
    // order; sharing TUPLE_COLS here masked the old CUDA fallback permutation
    // bug and makes this native differential reject any future re-conflation.
    const SUB_TUPLE_COLS: [[usize; 3]; 16] = [
        [53, 55, 18],
        [14, 16, 19],
        [61, 63, 38],
        [34, 36, 39],
        [54, 56, 20],
        [15, 17, 21],
        [62, 64, 40],
        [35, 37, 41],
        [57, 59, 28],
        [58, 60, 30],
        [24, 26, 29],
        [25, 27, 31],
        [65, 67, 48],
        [66, 68, 50],
        [44, 46, 49],
        [45, 47, 51],
    ];
    const RELATIONS: [u32; 16] = [
        112558620, 112558620, 521092554, 521092554, 648362599, 45448144, 648362599, 45448144,
        112558620, 112558620, 521092554, 521092554, 62225763, 95781001, 62225763, 95781001,
    ];
    const FINAL_COLS: [usize; 20] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 32, 33, 69, 70, 42, 43, 71, 72,
    ];

    let input_words = (0..ROWS * 6)
        .map(|index| {
            (0x9e37_79b9u32.wrapping_mul(index as u32 + 1)).rotate_left((index % 31) as u32)
        })
        .collect::<Vec<_>>();
    let inputs = upload(input_words.iter().copied());
    let legacy = blake_witness::write_trace(&inputs, 13, ROWS);
    let legacy_host = legacy.iter().map(download).collect::<Vec<_>>();

    let context = CudaExecContext::new().unwrap();
    let trace = (0..blake_witness::BG_N_TRACE)
        .map(|_| BaseFieldVec::new_uninitialized(ROWS))
        .collect::<Vec<_>>();
    let lookup = BaseFieldVec::new_uninitialized(87 * ROWS);
    let sub = BaseFieldVec::new_uninitialized(48 * ROWS);
    blake_witness::write_trace_into_on(
        &inputs,
        13,
        ROWS,
        &trace,
        &lookup,
        &sub,
        context.launch_context(),
    )
    .unwrap();
    context.sync().unwrap();

    for (actual, expected) in trace.iter().zip(&legacy_host) {
        assert_eq!(&download(actual), expected);
    }
    let lookup = download(&lookup);
    let sub = download(&sub);
    for row in 0..ROWS {
        for (tuple, columns) in LOOKUP_TUPLE_COLS.iter().enumerate() {
            assert_eq!(lookup[(4 * tuple) * ROWS + row], RELATIONS[tuple]);
            for (word, &column) in columns.iter().enumerate() {
                let expected = legacy_host[column][row];
                assert_eq!(lookup[(4 * tuple + 1 + word) * ROWS + row], expected);
            }
        }
        for (tuple, columns) in SUB_TUPLE_COLS.iter().enumerate() {
            for (word, &column) in columns.iter().enumerate() {
                assert_eq!(
                    sub[(3 * tuple + word) * ROWS + row],
                    legacy_host[column][row]
                );
            }
        }
        assert_eq!(lookup[64 * ROWS + row], 1139985212);
        for (word, &column) in FINAL_COLS.iter().enumerate() {
            assert_eq!(lookup[(65 + word) * ROWS + row], legacy_host[column][row]);
        }
        assert_eq!(lookup[85 * ROWS + row], 1);
        assert_eq!(lookup[86 * ROWS + row], legacy_host[52][row]);
    }

    // Exercise the production fused symbol, not only the compatibility writer.
    // The four identity LUTs keep exact count indexes transparent. Per-slab
    // totals plus the expected sparse cells prove that every one of the sixteen
    // descriptor edges was emitted for every row while trace/lookup stay exact.
    let fused_inputs: [BaseFieldVec; 6] =
        std::array::from_fn(|word| upload((0..ROWS).map(|row| input_words[row * 6 + word])));
    let fused_trace = (0..blake_witness::BG_N_TRACE)
        .map(|_| BaseFieldVec::new_uninitialized(ROWS))
        .collect::<Vec<_>>();
    let fused_lookup = BaseFieldVec::new_uninitialized(87 * ROWS);
    let luts = [8u32, 4, 7, 9].map(|bits| upload(0..1u32 << (2 * bits)));
    let count_words = [2 << 16, 16 << 20, 1 << 8, 1 << 14, 1 << 18];
    let counts = count_words.map(BaseFieldVec::new_zeroes);
    let input_ptrs = fused_inputs.each_ref().map(|column| column.device_ptr);
    let trace_ptrs = fused_trace
        .iter()
        .map(|column| column.device_ptr.cast_mut())
        .collect::<Vec<_>>();
    let lut_ptrs = luts.each_ref().map(|lut| lut.device_ptr);
    let count_ptrs = counts.each_ref().map(|count| count.device_ptr.cast_mut());
    let status = unsafe {
        stwo_backend_cuda_kernels::raw::blake_g_write_trace_fused_into_on(
            input_ptrs.as_ptr(),
            13,
            ROWS as u32,
            trace_ptrs.as_ptr(),
            fused_lookup.device_ptr.cast_mut(),
            lut_ptrs.as_ptr(),
            count_ptrs.as_ptr(),
            context.launch_context().stream_raw().as_ptr(),
        )
    };
    assert_eq!(status, 0);
    context.sync().unwrap();
    for (actual, expected) in fused_trace.iter().zip(&legacy_host) {
        assert_eq!(&download(actual), expected);
    }
    assert_eq!(download(&fused_lookup), lookup);
    let mut expected_counts: [BTreeMap<usize, u32>; 5] = std::array::from_fn(|_| BTreeMap::new());
    for row in 0..ROWS {
        for (edge, columns) in SUB_TUPLE_COLS.iter().enumerate() {
            let a = legacy_host[columns[0]][row] as usize;
            let b = legacy_host[columns[1]][row] as usize;
            let (destination, index) = match edge {
                0..=3 => (0, (a << 8) | b),
                4..=7 => (0, (1 << 16) | (a << 8) | b),
                8..=9 => (
                    1,
                    (((a >> 10) << 2) | (b >> 10)) * (1 << 20) + ((a & 0x3ff) << 10) + (b & 0x3ff),
                ),
                10..=11 => (2, (a << 4) | b),
                12..=13 => (3, (a << 7) | b),
                14..=15 => (4, (a << 9) | b),
                _ => unreachable!(),
            };
            *expected_counts[destination].entry(index).or_default() += 1;
        }
    }
    for (destination, (actual, expected)) in counts.iter().zip(expected_counts).enumerate() {
        let actual = download(actual);
        assert_eq!(
            actual.iter().copied().map(u64::from).sum::<u64>(),
            expected.values().copied().map(u64::from).sum::<u64>(),
            "count slab {destination} total"
        );
        for (index, expected) in expected {
            assert_eq!(actual[index], expected, "count slab {destination}[{index}]");
        }
    }

    // The live SN2 path reads blake_round's word-major sub buffer directly.
    let producer_sub = upload((0..6).flat_map(|word| {
        let input_words = &input_words;
        (0..ROWS).map(move |row| input_words[row * 6 + word])
    }));
    let edge_expected = blake_witness::write_trace(&inputs, ROWS, ROWS);
    let edge_trace = (0..blake_witness::BG_N_TRACE)
        .map(|_| BaseFieldVec::new_uninitialized(ROWS))
        .collect::<Vec<_>>();
    let edge_lookup = BaseFieldVec::new_uninitialized(87 * ROWS);
    let edge_sub = BaseFieldVec::new_uninitialized(48 * ROWS);
    blake_witness::write_trace_from_sub_into_on(
        &producer_sub,
        ROWS,
        0,
        1,
        ROWS,
        ROWS,
        &edge_trace,
        &edge_lookup,
        &edge_sub,
        context.launch_context(),
    )
    .unwrap();
    context.sync().unwrap();
    for (actual, expected) in edge_trace.iter().zip(&edge_expected) {
        assert_eq!(download(actual), download(expected));
    }
}

#[test]
fn memory_big_and_small_arena_outputs_match_legacy_columns() {
    const ROWS: usize = 16;
    let context = CudaExecContext::new().unwrap();

    let big_values = upload((0..ROWS * 8).map(|index| {
        0x85eb_ca6bu32
            .wrapping_mul(index as u32 + 7)
            .rotate_right((index % 29) as u32)
    }));
    let big_legacy = memory_witness::limb_split_big(&big_values, 11, ROWS);
    let big_mults = (0..ROWS)
        .map(|row| if row < 11 { row as u32 * 17 + 3 } else { 0 })
        .collect::<Vec<_>>();
    let big_trace = (0..29)
        .map(|_| BaseFieldVec::new_uninitialized(ROWS))
        .collect::<Vec<_>>();
    memory_witness::limb_split_big_into_on(
        &big_values,
        11,
        ROWS,
        &big_mults,
        &big_trace,
        context.launch_context(),
    )
    .unwrap();

    let small_values =
        upload((0..ROWS * 4).map(|index| 0xc2b2_ae35u32.wrapping_mul(index as u32 + 13)));
    let small_legacy = memory_witness::limb_split_small(&small_values, 9, ROWS);
    let small_mults = (0..ROWS)
        .map(|row| if row < 9 { row as u32 * 23 + 5 } else { 0 })
        .collect::<Vec<_>>();
    let small_trace = (0..9)
        .map(|_| BaseFieldVec::new_uninitialized(ROWS))
        .collect::<Vec<_>>();
    memory_witness::limb_split_small_into_on(
        &small_values,
        9,
        ROWS,
        &small_mults,
        &small_trace,
        context.launch_context(),
    )
    .unwrap();
    context.sync().unwrap();

    for (actual, expected) in big_trace.iter().zip(&big_legacy) {
        assert_eq!(download(actual), download(expected));
    }
    assert_eq!(download(&big_trace[28]), big_mults);
    for (actual, expected) in small_trace.iter().zip(&small_legacy) {
        assert_eq!(download(actual), download(expected));
    }
    assert_eq!(download(&small_trace[8]), small_mults);
}
