use stwo::core::fields::m31::{BaseField, P};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};

use super::*;

const RANDOM_SEEDS: [u64; 3] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
];

#[test]
fn production_schedules_are_exact_and_fail_closed() {
    let log24 = CompositionSplitProgram::compile(24).unwrap();
    assert_eq!(
        log24.schedule(),
        CompositionSplitSchedule {
            evaluation_log_size: 24,
            inverse_intervals: 3,
            final_inverse_first_stage: 19,
            final_inverse_stages: 6,
            first_forward_first_stage: 2,
            first_forward_stages: 5,
            remaining_forward_intervals: 2,
            shared_min_stride_log: 18,
        }
    );
    assert_eq!(log24.schedule().first_unfused_forward_stage(), 7);

    let log25 = CompositionSplitProgram::compile(25).unwrap();
    assert_eq!(log25.schedule().first_unfused_forward_stage(), 7);
    for unsupported in [0, 3, 23, 26, 30, 31] {
        assert_eq!(
            CompositionSplitProgram::compile(unsupported),
            Err(CompositionSplitError::UnsupportedProductionLog(unsupported))
        );
    }

    for malformed in [
        CompositionSplitSchedule {
            final_inverse_stages: 0,
            ..log24.schedule()
        },
        CompositionSplitSchedule {
            final_inverse_first_stage: u32::MAX,
            ..log24.schedule()
        },
        CompositionSplitSchedule {
            first_forward_stages: 0,
            ..log24.schedule()
        },
        CompositionSplitSchedule {
            first_forward_first_stage: u32::MAX,
            ..log24.schedule()
        },
    ] {
        assert!(!malformed.is_exact());
    }
}

#[test]
fn production_launch_mode_admission_is_exact() {
    let log24 = CompositionSplitProgram::compile(24).unwrap();
    assert!(log24.admits_launch_mode(CompositionSplitLaunchMode::TerminalFallback));
    assert!(log24.admits_launch_mode(CompositionSplitLaunchMode::FusedFirstForward));

    let log25 = CompositionSplitProgram::compile(25).unwrap();
    assert!(log25.admits_launch_mode(CompositionSplitLaunchMode::TerminalFallback));
    assert!(log25.admits_launch_mode(CompositionSplitLaunchMode::FusedFirstForward));
}

#[test]
fn traffic_and_launch_receipts_are_exact() {
    let log24 = CompositionSplitProgram::compile(24).unwrap().traffic();
    assert_eq!(log24.source_image_bytes, 268_435_456);
    assert_eq!(log24.retained_image_bytes, 536_870_912);
    assert_eq!(log24.current_logical_bytes, 6_174_015_488);
    assert_eq!(log24.terminal_fallback_logical_bytes, 5_100_273_664);
    assert_eq!(log24.fused_logical_bytes, 4_026_531_840);
    assert_eq!(
        (log24.current_kernel_launches, log24.fused_kernel_launches),
        (7, 5)
    );
    assert_eq!((log24.current_d2d_nodes, log24.fused_d2d_nodes), (8, 0));

    let log25 = CompositionSplitProgram::compile(25).unwrap().traffic();
    assert_eq!(log25.source_image_bytes, 536_870_912);
    assert_eq!(log25.retained_image_bytes, 1_073_741_824);
    assert_eq!(log25.current_logical_bytes, 13_421_772_800);
    assert_eq!(log25.terminal_fallback_logical_bytes, 11_274_289_152);
    assert_eq!(log25.fused_logical_bytes, 9_126_805_504);
    assert_eq!(
        (log25.current_kernel_launches, log25.fused_kernel_launches),
        (8, 6)
    );
    assert_eq!((log25.current_d2d_nodes, log25.fused_d2d_nodes), (8, 0));
}

#[test]
fn oracle_matches_split_identity_and_canonical_output_order() {
    for log_size in 3..=8 {
        let rows = 1usize << log_size;
        let domain = CanonicCoset::new(log_size).circle_domain();
        for seed in RANDOM_SEEDS {
            let sources = (0..COMPOSITION_SOURCE_COORDINATES)
                .map(|coordinate| {
                    (0..rows)
                        .map(|row| random_word(seed ^ coordinate as u64, row))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let oracle = CompositionSplitProgram::oracle(log_size, &sources).unwrap();
            for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
                let left = &oracle.retained_evaluations[coordinate];
                let right =
                    &oracle.retained_evaluations[COMPOSITION_SOURCE_COORDINATES + coordinate];
                assert_eq!((left.len(), right.len()), (rows, rows));
                for stored_row in 0..rows {
                    let point = domain.at(bit_reverse_index(stored_row, log_size));
                    let top_factor = point.repeated_double(log_size - 2).x;
                    let reconstructed = BaseField::from_u32_unchecked(left[stored_row])
                        + top_factor * BaseField::from_u32_unchecked(right[stored_row]);
                    assert_eq!(
                        reconstructed.0, sources[coordinate][stored_row],
                        "log={log_size} seed={seed:#x} coord={coordinate} row={stored_row}"
                    );
                }
            }
        }
    }
}

#[test]
fn oracle_separates_left_and_right_coordinate_halves() {
    for log_size in 3..=8 {
        let half_words = 1usize << (log_size - 1);
        let domain = CanonicCoset::new(log_size).circle_domain();
        let twiddles = CpuBackend::precompute_twiddles(domain.half_coset);
        for right_only in [false, true] {
            let mut sources = Vec::with_capacity(COMPOSITION_SOURCE_COORDINATES);
            let mut expected_halves = Vec::with_capacity(COMPOSITION_SOURCE_COORDINATES);
            for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
                let half = (0..half_words)
                    .map(|row| random_word(RANDOM_SEEDS[coordinate % 3], row))
                    .map(BaseField::from_u32_unchecked)
                    .collect::<Vec<_>>();
                let zeros = vec![BaseField::from_u32_unchecked(0); half_words];
                let coefficients = if right_only {
                    [zeros.as_slice(), half.as_slice()].concat()
                } else {
                    [half.as_slice(), zeros.as_slice()].concat()
                };
                let source = CircleCoefficients::<CpuBackend>::new(coefficients)
                    .evaluate_with_twiddles(domain, &twiddles)
                    .values
                    .into_iter()
                    .map(|value| value.0)
                    .collect::<Vec<_>>();
                sources.push(source);
                expected_halves.push(half);
            }
            let oracle = CompositionSplitProgram::oracle(log_size, &sources).unwrap();
            for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
                let zero_index = if right_only {
                    coordinate
                } else {
                    COMPOSITION_SOURCE_COORDINATES + coordinate
                };
                assert!(oracle.retained_evaluations[zero_index]
                    .iter()
                    .all(|&word| word == 0));
                let live_index = if right_only {
                    COMPOSITION_SOURCE_COORDINATES + coordinate
                } else {
                    coordinate
                };
                let expected =
                    CircleCoefficients::<CpuBackend>::new(expected_halves[coordinate].clone())
                        .evaluate_with_twiddles(domain, &twiddles)
                        .values
                        .into_iter()
                        .map(|value| value.0)
                        .collect::<Vec<_>>();
                assert_eq!(oracle.retained_evaluations[live_index], expected);
            }
        }
    }
}

#[test]
fn oracle_rejects_shape_length_and_noncanonical_words() {
    assert!(matches!(
        CompositionSplitProgram::oracle(3, &[vec![0; 8]]),
        Err(CompositionSplitError::SourceColumnCount { .. })
    ));
    let mut sources = vec![vec![0; 8]; COMPOSITION_SOURCE_COORDINATES];
    sources[2].pop();
    assert_eq!(
        CompositionSplitProgram::oracle(3, &sources),
        Err(CompositionSplitError::SourceLength {
            coordinate: 2,
            expected: 8,
            actual: 7,
        })
    );
    let mut sources = vec![vec![0; 8]; COMPOSITION_SOURCE_COORDINATES];
    sources[3][5] = P;
    assert_eq!(
        CompositionSplitProgram::oracle(3, &sources),
        Err(CompositionSplitError::NonCanonicalWord {
            coordinate: 3,
            row: 5,
            word: P,
        })
    );
}

#[test]
fn disjoint_subslices_of_one_arena_slot_are_valid_but_overlap_is_not() {
    let slot = ArenaSlotId(7);
    assert_eq!(
        validate_address_ranges(&[(slot, (0x1000, 0x1800)), (slot, (0x1800, 0x2000))]),
        Ok(())
    );
    assert_eq!(
        validate_address_ranges(&[(slot, (0x1000, 0x1801)), (slot, (0x1800, 0x2000))]),
        Err(CompositionSplitError::InvalidAlias {
            first: slot,
            second: slot,
        })
    );
}

fn random_word(seed: u64, row: usize) -> u32 {
    (splitmix64(seed ^ row as u64) % u64::from(P)) as u32
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
