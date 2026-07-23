//! Native admission for the six-input Blake-G witness and relation bodies.

use core::ffi::c_void;

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;

use super::super::{BG_N_DATA_INPUTS, BG_N_TRACE};
use super::tests::{chain, direct_denominators, direct_fractions, evaluate_six_inputs};
use crate::{ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, DeviceArena};

// Run four full 256-thread blocks plus a one-row tail.  The real/padded
// boundary sits one row into block three, and repeated block-head vectors
// create cross-block multiplicity contention.
const ROWS: usize = 1025;
const N_REAL: usize = 769;
const LAUNCH_BLOCK_ROWS: usize = 256;
const RELATION_COLUMNS: usize = 9;
const RELATION_COORDINATES: usize = 4 * RELATION_COLUMNS;
const LUT_WORDS: [usize; 4] = [1 << 16, 1 << 8, 1 << 14, 1 << 18];
const COUNT_WORDS: [usize; 5] = [2 << 16, 16 << 20, 1 << 8, 1 << 14, 1 << 18];
const POINTER_WORDS: usize = core::mem::size_of::<usize>() / core::mem::size_of::<u32>();
const ALPHA_WORDS: usize = 21 * 4;
const TOTAL_WORDS: usize = BG_N_DATA_INPUTS * ROWS
    + BG_N_TRACE * ROWS
    + RELATION_COORDINATES * ROWS
    + (1 << 16)
    + (1 << 8)
    + (1 << 14)
    + (1 << 18)
    + (2 << 16)
    + (16 << 20)
    + (1 << 8)
    + (1 << 14)
    + (1 << 18)
    + ALPHA_WORDS
    + 4
    + (BG_N_DATA_INPUTS + RELATION_COORDINATES) * POINTER_WORDS;

fn upload(context: &CudaExecContext, destination: ArenaSlice, words: &[u32]) {
    assert_eq!(destination.len_words(), words.len());
    unsafe {
        context
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                words.as_ptr().cast::<c_void>(),
                destination.len_bytes(),
            )
            .unwrap();
    }
}

fn upload_pointers(context: &CudaExecContext, destination: ArenaSlice, pointers: &[usize]) {
    assert_eq!(destination.len_bytes(), core::mem::size_of_val(pointers));
    unsafe {
        context
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                pointers.as_ptr().cast::<c_void>(),
                destination.len_bytes(),
            )
            .unwrap();
    }
}

fn launch(
    context: &CudaExecContext,
    inputs: &[*const u32; BG_N_DATA_INPUTS],
    trace: &[*mut u32; BG_N_TRACE],
    luts: &[*const u32; 4],
    counts: &[*mut u32; 5],
    source_pointers: ArenaSlice,
    output_pointers: ArenaSlice,
    alphas: ArenaSlice,
    z: ArenaSlice,
) {
    let stream = context.stream_raw().as_ptr();
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::blake_g_write_trace_fused_direct_into_on(
            inputs.as_ptr(),
            N_REAL as u32,
            ROWS as u32,
            trace.as_ptr(),
            luts.as_ptr(),
            counts.as_ptr(),
            stream,
        )
    };
    assert_eq!(code, 0, "direct Blake-G witness launch failed");
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_relation_blake_g_inputs_on(
            source_pointers.as_u32_ptr().cast(),
            BG_N_DATA_INPUTS as u32,
            ROWS as u32,
            N_REAL as u32,
            alphas.as_u32_ptr().cast_const(),
            21,
            z.as_u32_ptr().cast_const(),
            output_pointers.as_u32_ptr().cast(),
            RELATION_COORDINATES as u32,
            stream,
        )
    };
    assert_eq!(code, 0, "direct Blake-G relation launch failed");
}

struct Expected {
    trace: Vec<u32>,
    interactions: Vec<u32>,
    counts: [Vec<u32>; 5],
    claimed_sum: SecureField,
}

fn count_lut(
    counts: &mut [Vec<u32>; 5],
    destination: usize,
    relation: usize,
    bits: u32,
    tuple: [u32; 4],
) {
    let key = ((tuple[1] << bits) | tuple[2]) as usize;
    let table_size = 1usize << (2 * bits);
    counts[destination][relation * table_size + key] += 1;
}

fn expected(
    input_rows: &[[u32; BG_N_DATA_INPUTS]],
    alphas: &[SecureField; 21],
    z: SecureField,
) -> Expected {
    let oracle_rows = input_rows
        .iter()
        .enumerate()
        .map(|(row, &inputs)| evaluate_six_inputs(inputs, row, N_REAL))
        .collect::<Vec<_>>();
    for (row, oracle) in oracle_rows.iter().enumerate() {
        assert!(
            direct_denominators(oracle, alphas, z)
                .into_iter()
                .all(|denominator| !denominator.is_zero()),
            "zero direct Blake-G denominator at row {row}"
        );
    }
    let chains = oracle_rows
        .iter()
        .map(|row| chain(direct_fractions(row, alphas, z)))
        .collect::<Vec<_>>();
    let trace = (0..BG_N_TRACE)
        .flat_map(|column| oracle_rows.iter().map(move |row| row.trace[column]))
        .collect::<Vec<_>>();
    let mut interactions = Vec::with_capacity(RELATION_COORDINATES * ROWS);
    for column in 0..RELATION_COLUMNS {
        for coordinate in 0..4 {
            interactions.extend(
                chains
                    .iter()
                    .map(|chain| chain[column].to_m31_array()[coordinate].0),
            );
        }
    }
    let mut counts: [Vec<u32>; 5] = std::array::from_fn(|index| vec![0; COUNT_WORDS[index]]);
    for row in &oracle_rows {
        for &tuple in &[0, 1, 8, 9] {
            count_lut(&mut counts, 0, 0, 8, row.tuples[tuple]);
        }
        for &tuple in &[2, 3, 10, 11] {
            count_lut(&mut counts, 0, 1, 8, row.tuples[tuple]);
        }
        for &tuple in &[5, 7] {
            count_lut(&mut counts, 2, 0, 4, row.tuples[tuple]);
        }
        for &tuple in &[12, 14] {
            count_lut(&mut counts, 3, 0, 7, row.tuples[tuple]);
        }
        for &tuple in &[13, 15] {
            count_lut(&mut counts, 4, 0, 9, row.tuples[tuple]);
        }
        for &tuple in &[4, 6] {
            let [_, a, b, _] = row.tuples[tuple];
            let column = ((a >> 10) << 2) | (b >> 10);
            let table_row = ((a & 0x3ff) << 10) | (b & 0x3ff);
            counts[1][((column << 20) | table_row) as usize] += 1;
        }
    }
    Expected {
        trace,
        interactions,
        counts,
        claimed_sum: chains
            .iter()
            .fold(SecureField::zero(), |sum, chain| sum + chain[8]),
    }
}

fn download(
    context: &CudaExecContext,
    trace: ArenaSlice,
    interactions: ArenaSlice,
    counts: &[ArenaSlice; 5],
) -> (Vec<u32>, Vec<u32>, [Vec<u32>; 5]) {
    let mut trace_words = vec![0u32; trace.len_words()];
    let mut interaction_words = vec![0u32; interactions.len_words()];
    let mut count_words: [Vec<u32>; 5] =
        std::array::from_fn(|index| vec![0u32; counts[index].len_words()]);
    unsafe {
        context
            .memcpy_d2h_async(
                trace_words.as_mut_ptr().cast::<c_void>(),
                trace.as_void_ptr().cast_const(),
                trace.len_bytes(),
            )
            .unwrap();
        context
            .memcpy_d2h_async(
                interaction_words.as_mut_ptr().cast::<c_void>(),
                interactions.as_void_ptr().cast_const(),
                interactions.len_bytes(),
            )
            .unwrap();
        for (destination, source) in count_words.iter_mut().zip(counts) {
            context
                .memcpy_d2h_async(
                    destination.as_mut_ptr().cast::<c_void>(),
                    source.as_void_ptr().cast_const(),
                    source.len_bytes(),
                )
                .unwrap();
        }
    }
    context.sync().unwrap();
    (trace_words, interaction_words, count_words)
}

fn assert_words(label: &str, actual: &[u32], expected: &[u32]) {
    assert_eq!(actual.len(), expected.len(), "{label} length");
    if let Some(index) = actual
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected)
    {
        panic!(
            "{label} mismatch at word {index}: device={} oracle={}",
            actual[index], expected[index]
        );
    }
}

fn assert_output(
    label: &str,
    context: &CudaExecContext,
    trace: ArenaSlice,
    interactions: ArenaSlice,
    counts: &[ArenaSlice; 5],
    expected: &Expected,
) {
    let (trace_words, interaction_words, count_words) =
        download(context, trace, interactions, counts);
    assert_words(&format!("{label} trace"), &trace_words, &expected.trace);
    assert_words(
        &format!("{label} interactions"),
        &interaction_words,
        &expected.interactions,
    );
    for index in 0..count_words.len() {
        assert_words(
            &format!("{label} count[{index}]"),
            &count_words[index],
            &expected.counts[index],
        );
    }
    let claimed_sum = (0..ROWS).fold(SecureField::zero(), |sum, row| {
        sum + SecureField::from_u32_unchecked(
            interaction_words[32 * ROWS + row],
            interaction_words[33 * ROWS + row],
            interaction_words[34 * ROWS + row],
            interaction_words[35 * ROWS + row],
        )
    });
    assert_eq!(claimed_sum, expected.claimed_sum, "{label} claimed sum");
}

fn assert_all_extension_coordinates_observable(expected: &Expected) {
    for coordinate in 0..4 {
        assert!(
            (0..RELATION_COLUMNS).any(|column| {
                let start = (4 * column + coordinate) * ROWS;
                expected.interactions[start..start + ROWS]
                    .iter()
                    .any(|&word| word != 0)
            }),
            "QM31 coordinate {coordinate} is not observable"
        );
    }
}

fn fixture_inputs() -> Vec<[u32; BG_N_DATA_INPUTS]> {
    let boundaries = [
        [0; BG_N_DATA_INPUTS],
        [u32::MAX; BG_N_DATA_INPUTS],
        [u32::MAX, 1, u32::MAX, 1, u32::MAX, 1],
        [0, u32::MAX, 1, u32::MAX - 1, 0x8000_0000, 0x7fff_ffff],
    ];
    let mut state = 0xd1b5_4a32u32;
    (0..ROWS)
        .map(|row| {
            let block_row = row % LAUNCH_BLOCK_ROWS;
            if block_row < boundaries.len() {
                boundaries[block_row]
            } else {
                std::array::from_fn(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    state
                })
            }
        })
        .collect()
}

fn challenge_powers(alpha: SecureField) -> [SecureField; 21] {
    let mut power = SecureField::from(1u32);
    std::array::from_fn(|_| {
        let result = power;
        power *= alpha;
        result
    })
}

fn eager_challenges() -> ([SecureField; 21], SecureField) {
    // Match LookupElements::from_z_alpha with a full-QM31 transcript pair.
    (
        challenge_powers(SecureField::from_u32_unchecked(3, 5, 7, 11)),
        SecureField::from_u32_unchecked(13, 17, 19, 23),
    )
}

fn replay_challenges() -> ([SecureField; 21], SecureField) {
    (
        challenge_powers(SecureField::from_u32_unchecked(29, 31, 37, 41)),
        SecureField::from_u32_unchecked(43, 47, 53, 59),
    )
}

#[test]
fn direct_blake_g_native_fixture_is_adversarial() {
    assert_eq!(ROWS / LAUNCH_BLOCK_ROWS, 4);
    assert_eq!(ROWS % LAUNCH_BLOCK_ROWS, 1);
    assert_eq!(N_REAL / LAUNCH_BLOCK_ROWS, 3);
    assert_eq!(N_REAL % LAUNCH_BLOCK_ROWS, 1);

    let inputs = fixture_inputs();
    let (eager_alphas, eager_z) = eager_challenges();
    let eager = expected(&inputs, &eager_alphas, eager_z);
    assert_all_extension_coordinates_observable(&eager);
    assert!(!eager.claimed_sum.is_zero());
    assert_eq!(
        eager
            .counts
            .map(|counts| counts.into_iter().map(u64::from).sum::<u64>()),
        [8, 2, 2, 2, 2].map(|per_row| per_row * ROWS as u64)
    );
    let (replay_alphas, replay_z) = replay_challenges();
    let replay = expected(&inputs, &replay_alphas, replay_z);
    assert_all_extension_coordinates_observable(&replay);
    assert!(!replay.claimed_sum.is_zero());
    let last_real = evaluate_six_inputs(inputs[N_REAL - 1], N_REAL - 1, N_REAL);
    let first_padding = evaluate_six_inputs(inputs[N_REAL], N_REAL, N_REAL);
    assert_eq!((last_real.trace[52], first_padding.trace[52]), (1, 0));
}

fn upload_inputs(
    context: &CudaExecContext,
    destinations: &[ArenaSlice; BG_N_DATA_INPUTS],
    rows: &[[u32; BG_N_DATA_INPUTS]],
) -> [Vec<u32>; BG_N_DATA_INPUTS] {
    let columns: [Vec<u32>; BG_N_DATA_INPUTS] =
        std::array::from_fn(|column| rows.iter().map(|row| row[column]).collect());
    for (destination, words) in destinations.iter().zip(&columns) {
        upload(context, *destination, words);
    }
    columns
}

fn clear_counts(context: &CudaExecContext, counts: &[ArenaSlice; 5]) {
    for destination in counts {
        unsafe {
            context
                .memset_async(destination.as_void_ptr(), 0, destination.len_bytes())
                .unwrap();
        }
    }
}

#[test]
#[cfg_attr(not(stwo_cuda_link), ignore = "requires a native CUDA-linked backend")]
fn direct_blake_g_native_matches_host_oracle_eager_and_replay() {
    assert!(
        stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT,
        "native Blake-G admission cannot run against CUDA stubs"
    );
    let aot_entries = stwo_backend_cuda_kernels::aot_pack::aot_pack_entries();
    println!("direct_blake_g_native_aot_entries={aot_entries}");
    #[cfg(feature = "test-only-empty-aot-pack")]
    assert_eq!(
        aot_entries, 0,
        "the cheap direct oracle must not pay for unrelated generated AOT cubins"
    );

    let mut input_rows = fixture_inputs();
    let (alphas, z) = eager_challenges();
    let eager_expected = expected(&input_rows, &alphas, z);
    assert_all_extension_coordinates_observable(&eager_expected);

    let layout = ArenaLayout::new(
        TOTAL_WORDS,
        &[ArenaSlotSpec {
            id: ArenaSlotId(1),
            offset_words: 0,
            len_words: TOTAL_WORDS,
            alignment_words: 1,
        }],
    )
    .unwrap();
    let arena = DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap();
    let slab = arena.bind(ArenaSlotId(1)).unwrap();
    let mut offset = 0usize;
    let mut take = |words: usize| {
        let result = slab.checked_subslice(offset, words).unwrap();
        offset += words;
        result
    };
    let input_slab = take(BG_N_DATA_INPUTS * ROWS);
    let input_slices: [ArenaSlice; BG_N_DATA_INPUTS] =
        std::array::from_fn(|column| input_slab.checked_subslice(column * ROWS, ROWS).unwrap());
    let trace_slab = take(BG_N_TRACE * ROWS);
    let trace_slices: [ArenaSlice; BG_N_TRACE] =
        std::array::from_fn(|column| trace_slab.checked_subslice(column * ROWS, ROWS).unwrap());
    let interaction_slab = take(RELATION_COORDINATES * ROWS);
    let interaction_slices: [ArenaSlice; RELATION_COORDINATES] = std::array::from_fn(|column| {
        interaction_slab
            .checked_subslice(column * ROWS, ROWS)
            .unwrap()
    });
    let lut_slices = LUT_WORDS.map(&mut take);
    let count_slices = COUNT_WORDS.map(&mut take);
    let alpha_slice = take(ALPHA_WORDS);
    let z_slice = take(4);
    let source_pointer_slice = take(BG_N_DATA_INPUTS * POINTER_WORDS);
    let output_pointer_slice = take(RELATION_COORDINATES * POINTER_WORDS);
    assert_eq!(offset, TOTAL_WORDS);

    let eager_input_columns = upload_inputs(arena.context(), &input_slices, &input_rows);
    // A dense identity permutation makes every key-to-row and relation offset
    // independently observable without importing Cairo's preprocessed trace.
    let lut_words = LUT_WORDS.map(|words| (0..words as u32).collect::<Vec<_>>());
    for (destination, words) in lut_slices.iter().zip(&lut_words) {
        upload(arena.context(), *destination, words);
    }
    clear_counts(arena.context(), &count_slices);
    let alpha_words = alphas
        .iter()
        .flat_map(|alpha| alpha.to_m31_array().map(|coordinate| coordinate.0))
        .collect::<Vec<_>>();
    let z_words = z.to_m31_array().map(|coordinate| coordinate.0);
    let source_pointer_words = input_slices.map(|source| source.as_u32_ptr() as usize);
    let output_pointer_words = interaction_slices.map(|output| output.as_u32_ptr() as usize);
    upload(arena.context(), alpha_slice, &alpha_words);
    upload(arena.context(), z_slice, &z_words);
    upload_pointers(arena.context(), source_pointer_slice, &source_pointer_words);
    upload_pointers(arena.context(), output_pointer_slice, &output_pointer_words);

    let input_pointers = input_slices.map(|slice| slice.as_u32_ptr().cast_const());
    let trace_pointers = trace_slices.map(ArenaSlice::as_u32_ptr);
    let lut_pointers = lut_slices.map(|slice| slice.as_u32_ptr().cast_const());
    let count_pointers = count_slices.map(ArenaSlice::as_u32_ptr);
    launch(
        arena.context(),
        &input_pointers,
        &trace_pointers,
        &lut_pointers,
        &count_pointers,
        source_pointer_slice,
        output_pointer_slice,
        alpha_slice,
        z_slice,
    );
    assert_output(
        "eager",
        arena.context(),
        trace_slab,
        interaction_slab,
        &count_slices,
        &eager_expected,
    );
    drop(eager_input_columns);
    drop(eager_expected);

    let capture = arena.context().capture().unwrap();
    launch(
        arena.context(),
        &input_pointers,
        &trace_pointers,
        &lut_pointers,
        &count_pointers,
        source_pointer_slice,
        output_pointer_slice,
        alpha_slice,
        z_slice,
    );
    let graph = capture.finish().unwrap();
    assert_eq!(graph.kernel_nodes(), 2);
    input_rows[0][0] ^= 0x1357_9bdf;
    input_rows[N_REAL - 1][5] = input_rows[N_REAL - 1][5].wrapping_add(1);
    input_rows[N_REAL][2] ^= u32::MAX;
    input_rows[ROWS - 1][3] ^= 0xa5a5_5a5a;
    let replay_input_columns = upload_inputs(arena.context(), &input_slices, &input_rows);
    let (replay_alphas, replay_z) = replay_challenges();
    let replay_alpha_words = replay_alphas
        .iter()
        .flat_map(|alpha| alpha.to_m31_array().map(|coordinate| coordinate.0))
        .collect::<Vec<_>>();
    let replay_z_words = replay_z.to_m31_array().map(|coordinate| coordinate.0);
    upload(arena.context(), alpha_slice, &replay_alpha_words);
    upload(arena.context(), z_slice, &replay_z_words);
    let replay_expected = expected(&input_rows, &replay_alphas, replay_z);
    assert_all_extension_coordinates_observable(&replay_expected);
    clear_counts(arena.context(), &count_slices);
    unsafe {
        arena
            .context()
            .fill_u32_async(trace_slab.as_u32_ptr(), u32::MAX, trace_slab.len_words())
            .unwrap();
        arena
            .context()
            .fill_u32_async(
                interaction_slab.as_u32_ptr(),
                u32::MAX,
                interaction_slab.len_words(),
            )
            .unwrap();
    }
    graph.launch(arena.context()).unwrap();
    assert_output(
        "replay",
        arena.context(),
        trace_slab,
        interaction_slab,
        &count_slices,
        &replay_expected,
    );
    drop(replay_input_columns);
}
