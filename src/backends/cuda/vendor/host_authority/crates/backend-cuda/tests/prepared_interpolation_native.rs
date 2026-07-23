//! Native CUDA differential for resident interpolation with exact aliases on
//! the supported log-size range 3 through 30.
//!
//! Hardware admission must require exactly one passed test from this target. A
//! stub build compiles zero tests, so a host-only pass is not CUDA evidence.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::cpu::CpuCircleEvaluation;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::twiddles::TwiddleTree;
use stwo::prover::poly::BitReversedOrder;
use stwo_backend_cuda::{
    b2n_stage_intervals, gpu_memory_info, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CudaBackend, CudaExecContext, DeviceArena, InterpolationBatch, InterpolationColumn,
    InterpolationLaunchMode, PreparedInterpolationError, PreparedInterpolationGraph,
    INTERPOLATION_POINTER_ALIGNMENT_WORDS,
};

const MAX_LOG_SIZE: u32 = 30;
const CPU_ORACLE_MAX_LOG_SIZE: u32 = 18;
const PATTERN_TILE_WORDS: usize = 1 << 22;
const COMPARE_CHUNK_WORDS: usize = 1 << 22;
const MIN_FREE_DEVICE_BYTES: usize = 20 << 30;

const INVERSE_TWIDDLES: ArenaSlotId = ArenaSlotId(1);
const ALIASED_VALUES: ArenaSlotId = ArenaSlotId(2);
const DISTINCT_EVALUATIONS: ArenaSlotId = ArenaSlotId(3);
const DISTINCT_COEFFICIENTS: ArenaSlotId = ArenaSlotId(4);
const INPUT_POINTERS: ArenaSlotId = ArenaSlotId(5);
const OUTPUT_POINTERS: ArenaSlotId = ArenaSlotId(6);

const RANDOM_SEED_0: u64 = 0x243f_6a88_85a3_08d3;
const RANDOM_SEED_1: u64 = 0x1319_8a2e_0370_7344;
const RANDOM_SEED_2: u64 = 0xa409_3822_299f_31d0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputPattern {
    Zero,
    One,
    ImpulseFirst,
    ImpulseLast,
    ImpulseBitReversed,
    Alternating,
    Ramp,
    CarryHeavy,
    Random(u64),
}

const CORE_PATTERNS: [InputPattern; 3] = [
    InputPattern::Zero,
    InputPattern::CarryHeavy,
    InputPattern::Random(RANDOM_SEED_0),
];

const STAGEWISE_PATTERNS: [InputPattern; 2] = [
    InputPattern::Random(RANDOM_SEED_0),
    InputPattern::CarryHeavy,
];

const EXHAUSTIVE_PATTERNS: [InputPattern; 11] = [
    InputPattern::Zero,
    InputPattern::One,
    InputPattern::ImpulseFirst,
    InputPattern::ImpulseLast,
    InputPattern::ImpulseBitReversed,
    InputPattern::Alternating,
    InputPattern::Ramp,
    InputPattern::CarryHeavy,
    InputPattern::Random(RANDOM_SEED_0),
    InputPattern::Random(RANDOM_SEED_1),
    InputPattern::Random(RANDOM_SEED_2),
];

impl InputPattern {
    fn name(self) -> &'static str {
        match self {
            Self::Zero => "all-zero",
            Self::One => "all-one",
            Self::ImpulseFirst => "impulse-first",
            Self::ImpulseLast => "impulse-last",
            Self::ImpulseBitReversed => "impulse-bit-reversed",
            Self::Alternating => "alternating-zero-p-minus-one",
            Self::Ramp => "ramp",
            Self::CarryHeavy => "carry-heavy",
            Self::Random(RANDOM_SEED_0) => "random-seed-0",
            Self::Random(RANDOM_SEED_1) => "random-seed-1",
            Self::Random(RANDOM_SEED_2) => "random-seed-2",
            Self::Random(_) => "random",
        }
    }

    fn word(self, index: usize, log_size: u32) -> u32 {
        let words = 1usize << log_size;
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::ImpulseFirst => u32::from(index == 0) * (P - 1),
            Self::ImpulseLast => u32::from(index == words - 1) * (P - 1),
            Self::ImpulseBitReversed => {
                u32::from(index == bit_reverse_index(1, log_size)) * (P - 1)
            }
            Self::Alternating => {
                if index & 1 == 0 {
                    0
                } else {
                    P - 1
                }
            }
            Self::Ramp => (index as u64 % u64::from(P)) as u32,
            Self::CarryHeavy => match index & 7 {
                0 => P - 1,
                1 => P - 2,
                2 => P - 3,
                3 => P - 4,
                4 => 1,
                5 => 2,
                6 => P / 2,
                _ => P / 2 + 1,
            },
            Self::Random(seed) => splitmix64(seed ^ index as u64) as u32 % P,
        }
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn patterns_for_log(log_size: u32) -> &'static [InputPattern] {
    if log_size <= CPU_ORACLE_MAX_LOG_SIZE {
        &EXHAUSTIVE_PATTERNS
    } else {
        &CORE_PATTERNS
    }
}

fn arena(max_log_size: u32) -> DeviceArena {
    let max_value_words = 1usize << max_log_size;
    let max_twiddle_words = max_value_words / 2;
    let pointer_words = 2 * core::mem::size_of::<*mut u32>().div_ceil(4);
    let requests = [
        (INVERSE_TWIDDLES, max_twiddle_words, 1),
        (ALIASED_VALUES, max_value_words, 1),
        (DISTINCT_EVALUATIONS, max_value_words, 1),
        (DISTINCT_COEFFICIENTS, max_value_words, 1),
        (
            INPUT_POINTERS,
            pointer_words,
            INTERPOLATION_POINTER_ALIGNMENT_WORDS,
        ),
        (
            OUTPUT_POINTERS,
            pointer_words,
            INTERPOLATION_POINTER_ALIGNMENT_WORDS,
        ),
    ];
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

fn upload_inverse_twiddles(arena: &DeviceArena, log_size: u32) {
    let words = 1usize << (log_size - 1);
    let twiddles =
        CudaBackend::precompute_twiddles(CanonicCoset::new(log_size).circle_domain().half_coset);
    unsafe { stwo_backend_cuda_kernels::raw::stwo_legacy_stream_sync() };
    unsafe {
        arena
            .context()
            .memcpy_d2d_async(
                arena.bind(INVERSE_TWIDDLES).unwrap().as_void_ptr(),
                twiddles.itwiddles.device_ptr.cast(),
                words * core::mem::size_of::<u32>(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
}

fn pattern_words(pattern: InputPattern, log_size: u32, count: usize) -> Vec<u32> {
    (0..count)
        .map(|index| pattern.word(index, log_size))
        .collect()
}

fn upload_equal_inputs(
    arena: &DeviceArena,
    aliased: ArenaSlice,
    distinct: ArenaSlice,
    log_size: u32,
    pattern: InputPattern,
) {
    assert_eq!(aliased.len_words(), distinct.len_words());
    let words = aliased.len_words();
    if matches!(pattern, InputPattern::Zero | InputPattern::One) {
        unsafe {
            arena
                .context()
                .fill_u32_async(
                    aliased.as_u32_ptr(),
                    u32::from(pattern == InputPattern::One),
                    words,
                )
                .unwrap();
        }
    } else {
        let tile = pattern_words(pattern, log_size, PATTERN_TILE_WORDS.min(words));
        // The position-dependent impulse cases only run under the exhaustive
        // cutoff, so they are represented exactly rather than tiled.
        assert!(
            !matches!(
                pattern,
                InputPattern::ImpulseFirst
                    | InputPattern::ImpulseLast
                    | InputPattern::ImpulseBitReversed
            ) || tile.len() == words
        );
        for offset in (0..words).step_by(tile.len()) {
            let count = tile.len().min(words - offset);
            unsafe {
                arena
                    .context()
                    .memcpy_h2d_async(
                        aliased.as_u32_ptr().add(offset).cast(),
                        tile.as_ptr().cast(),
                        count * core::mem::size_of::<u32>(),
                    )
                    .unwrap();
            }
        }
    }
    unsafe {
        arena
            .context()
            .memcpy_d2d_async(
                distinct.as_void_ptr(),
                aliased.as_void_ptr().cast_const(),
                aliased.len_bytes(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
}

fn cpu_ifft(pattern: InputPattern, log_size: u32, twiddles: &TwiddleTree<CpuBackend>) -> Vec<u32> {
    let values = pattern_words(pattern, log_size, 1usize << log_size)
        .into_iter()
        .map(BaseField::from_u32_unchecked)
        .collect();
    CpuCircleEvaluation::<BaseField, BitReversedOrder>::new(
        CanonicCoset::new(log_size).circle_domain(),
        values,
    )
    .interpolate_with_twiddles(twiddles)
    .coeffs
    .into_iter()
    .map(|value| value.0)
    .collect()
}

fn assert_exact_word_parity(
    arena: &DeviceArena,
    aliased: ArenaSlice,
    distinct: ArenaSlice,
    log_size: u32,
    phase: &str,
    expected_cpu: Option<&[u32]>,
) {
    assert_eq!(aliased.len_words(), distinct.len_words());
    if let Some(expected) = expected_cpu {
        assert_eq!(expected.len(), aliased.len_words());
    }
    let mut alias_words = vec![0u32; COMPARE_CHUNK_WORDS.min(aliased.len_words())];
    let mut distinct_words = vec![0u32; alias_words.len()];
    for offset in (0..aliased.len_words()).step_by(COMPARE_CHUNK_WORDS) {
        let count = COMPARE_CHUNK_WORDS.min(aliased.len_words() - offset);
        unsafe {
            arena
                .context()
                .memcpy_d2h_async(
                    alias_words.as_mut_ptr().cast(),
                    aliased.as_u32_ptr().add(offset).cast_const().cast(),
                    count * core::mem::size_of::<u32>(),
                )
                .unwrap();
            arena
                .context()
                .memcpy_d2h_async(
                    distinct_words.as_mut_ptr().cast(),
                    distinct.as_u32_ptr().add(offset).cast_const().cast(),
                    count * core::mem::size_of::<u32>(),
                )
                .unwrap();
        }
        arena.context().sync().unwrap();
        if let Some(index) = alias_words[..count]
            .iter()
            .zip(&distinct_words[..count])
            .position(|(alias, distinct)| alias != distinct)
        {
            panic!(
                "exact-alias mismatch at log {log_size}, {phase}, word {}: alias={} distinct={}",
                offset + index,
                alias_words[index],
                distinct_words[index],
            );
        }
        if let Some(expected) = expected_cpu {
            if let Some(index) = alias_words[..count]
                .iter()
                .zip(&expected[offset..offset + count])
                .position(|(actual, expected)| actual != expected)
            {
                panic!(
                    "CUDA/CPU IFFT mismatch at log {log_size}, {phase}, word {}: CUDA={} CPU={}",
                    offset + index,
                    alias_words[index],
                    expected[offset + index],
                );
            }
        }
    }
}

fn interpolation_batch_for_log(
    arena: &DeviceArena,
    log_size: u32,
) -> (InterpolationBatch, ArenaSlice, ArenaSlice, ArenaSlice) {
    let words = 1usize << log_size;
    let aliased = arena.bind(ALIASED_VALUES).unwrap().truncated(words);
    let distinct_evaluations = arena.bind(DISTINCT_EVALUATIONS).unwrap().truncated(words);
    let distinct_coefficients = arena.bind(DISTINCT_COEFFICIENTS).unwrap().truncated(words);
    let batch = InterpolationBatch {
        columns: vec![
            InterpolationColumn {
                evaluations: aliased,
                coefficients: aliased,
                log_size,
            },
            InterpolationColumn {
                evaluations: distinct_evaluations,
                coefficients: distinct_coefficients,
                log_size,
            },
        ],
        input_pointers: INPUT_POINTERS,
        output_pointers: OUTPUT_POINTERS,
    };
    (batch, aliased, distinct_evaluations, distinct_coefficients)
}

fn interpolation_for_log(
    arena: &DeviceArena,
    log_size: u32,
    mode: InterpolationLaunchMode,
) -> (
    PreparedInterpolationGraph<'_>,
    ArenaSlice,
    ArenaSlice,
    ArenaSlice,
) {
    let (batch, aliased, distinct_evaluations, distinct_coefficients) =
        interpolation_batch_for_log(arena, log_size);
    let prepared = PreparedInterpolationGraph::prepare(
        arena,
        &[batch],
        arena.bind(INVERSE_TWIDDLES).unwrap(),
        mode,
    )
    .unwrap();
    assert_eq!(prepared.batch_count(), 1);
    assert_eq!(prepared.column_count(), 2);
    (
        prepared,
        aliased,
        distinct_evaluations,
        distinct_coefficients,
    )
}

fn exercise_supported_logs(
    arena: &DeviceArena,
    cpu_twiddles: &TwiddleTree<CpuBackend>,
    mode: InterpolationLaunchMode,
) {
    for log_size in 3..=MAX_LOG_SIZE {
        let (prepared, aliased, distinct_evaluations, distinct_coefficients) =
            interpolation_for_log(arena, log_size, mode);
        let patterns = match mode {
            InterpolationLaunchMode::StageWiseCopyThenInPlace => &STAGEWISE_PATTERNS,
            InterpolationLaunchMode::StageFusedOutOfPlace => patterns_for_log(log_size),
        };

        let eager = patterns[0];
        upload_equal_inputs(arena, aliased, distinct_evaluations, log_size, eager);
        prepared.launch().unwrap();
        let expected =
            (log_size <= CPU_ORACLE_MAX_LOG_SIZE).then(|| cpu_ifft(eager, log_size, cpu_twiddles));
        assert_exact_word_parity(
            arena,
            aliased,
            distinct_coefficients,
            log_size,
            eager.name(),
            expected.as_deref(),
        );

        let capture = arena.context().capture().unwrap();
        prepared.launch().unwrap();
        let graph = capture.finish().unwrap();
        let expected_nodes = match mode {
            InterpolationLaunchMode::StageWiseCopyThenInPlace => u64::from(log_size),
            InterpolationLaunchMode::StageFusedOutOfPlace => {
                b2n_stage_intervals(log_size).unwrap().len() as u64
            }
        };
        assert_eq!(
            graph.kernel_nodes(),
            expected_nodes,
            "unexpected {mode:?} topology at log {log_size}",
        );

        for &pattern in &patterns[1..] {
            upload_equal_inputs(arena, aliased, distinct_evaluations, log_size, pattern);
            graph.launch(arena.context()).unwrap();
            let expected = (log_size <= CPU_ORACLE_MAX_LOG_SIZE)
                .then(|| cpu_ifft(pattern, log_size, cpu_twiddles));
            assert_exact_word_parity(
                arena,
                aliased,
                distinct_coefficients,
                log_size,
                pattern.name(),
                expected.as_deref(),
            );
        }

        if matches!(log_size, 17 | 18 | 30) {
            eprintln!(
                "{mode:?} interpolation boundary log {log_size}: {} patterns passed exact alias parity; CPU oracle={}",
                patterns.len(),
                log_size <= CPU_ORACLE_MAX_LOG_SIZE,
            );
        }
    }
}

#[test]
fn exact_alias_matches_distinct_for_supported_logs_3_through_30() {
    assert_eq!(b2n_stage_intervals(1), None);
    assert_eq!(b2n_stage_intervals(2), None);
    assert_eq!(b2n_stage_intervals(17), Some(vec![9, 8]));
    assert_eq!(b2n_stage_intervals(18), Some(vec![10, 8]));
    assert_eq!(b2n_stage_intervals(30), Some(vec![1; 30]));

    let (free_bytes, total_bytes) = gpu_memory_info();
    assert!(
        free_bytes >= MIN_FREE_DEVICE_BYTES,
        "fused log-30 interpolation gate requires at least {} GiB free device memory; free={:.2} GiB total={:.2} GiB",
        MIN_FREE_DEVICE_BYTES >> 30,
        free_bytes as f64 / (1u64 << 30) as f64,
        total_bytes as f64 / (1u64 << 30) as f64,
    );

    // Generate the real inverse-twiddle tower once on-device. The legacy
    // producer is fenced before its result crosses onto the proof-owned stream.
    // One maximum-size arena and twiddle upload are reused serially by both
    // launch modes. This keeps the explicit log-30 boundary below 20 GiB while
    // every prepared graph still sees its exact logical extent.
    let arena = arena(MAX_LOG_SIZE);

    for mode in [
        InterpolationLaunchMode::StageWiseCopyThenInPlace,
        InterpolationLaunchMode::StageFusedOutOfPlace,
    ] {
        for log_size in [1, 2] {
            let (batch, ..) = interpolation_batch_for_log(&arena, log_size);
            assert_eq!(
                PreparedInterpolationGraph::prepare(
                    &arena,
                    &[batch],
                    arena.bind(INVERSE_TWIDDLES).unwrap(),
                    mode,
                )
                .err(),
                Some(PreparedInterpolationError::InvalidLogSize { batch: 0, log_size }),
            );
        }
    }

    upload_inverse_twiddles(&arena, MAX_LOG_SIZE);

    // Exhaustive host-oracle coverage stops at log 18: it includes both the
    // log-17 and log-18 block-init boundaries while keeping the CPU IFFT and
    // host vectors below 2^18 words. Logs 19..=30 retain full-word aliased vs
    // distinct CUDA parity for zero, carry-heavy, and deterministic-random
    // inputs. This makes log 30 execute three times without a multi-gigabyte
    // host oracle.
    let cpu_twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(CPU_ORACLE_MAX_LOG_SIZE)
            .circle_domain()
            .half_coset,
    );

    exercise_supported_logs(
        &arena,
        &cpu_twiddles,
        InterpolationLaunchMode::StageWiseCopyThenInPlace,
    );
    exercise_supported_logs(
        &arena,
        &cpu_twiddles,
        InterpolationLaunchMode::StageFusedOutOfPlace,
    );
    assert_eq!(patterns_for_log(MAX_LOG_SIZE), CORE_PATTERNS);
}
