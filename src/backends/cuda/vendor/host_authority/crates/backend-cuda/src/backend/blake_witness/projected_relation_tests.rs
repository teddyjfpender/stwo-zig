use std::collections::BTreeSet;

use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use super::super::{BG_FUSED_SEMANTIC_HASH, BG_N_AUX, BG_N_COLS, BG_N_TRACE};
use super::*;

const USES: [(usize, usize, usize, u32); 17] = [
    (0, 0, 4, 112_558_620),
    (4, 3, 4, 112_558_620),
    (8, 6, 4, 521_092_554),
    (12, 9, 4, 521_092_554),
    (16, 12, 4, 648_362_599),
    (20, 15, 4, 45_448_144),
    (24, 18, 4, 648_362_599),
    (28, 21, 4, 45_448_144),
    (32, 24, 4, 112_558_620),
    (36, 27, 4, 112_558_620),
    (40, 30, 4, 521_092_554),
    (44, 33, 4, 521_092_554),
    (48, 36, 4, 62_225_763),
    (52, 39, 4, 95_781_001),
    (56, 42, 4, 62_225_763),
    (60, 45, 4, 95_781_001),
    (64, 48, 21, BG_FINAL_RELATION),
];

use BlakeGRelationColumnSource::{Auxiliary as A, BaseTrace as B};

const EXPECTED_COLUMNS: [BlakeGRelationColumnSource; BG_N_PROJECTED_RELATION_COLUMNS] = [
    A(0),
    A(2),
    B(18),
    B(14),
    B(16),
    B(19),
    A(1),
    A(3),
    B(20),
    B(15),
    B(17),
    B(21),
    A(4),
    A(6),
    B(28),
    B(24),
    B(26),
    B(29),
    A(5),
    A(7),
    B(30),
    B(25),
    B(27),
    B(31),
    A(8),
    A(10),
    B(38),
    B(34),
    B(36),
    B(39),
    A(9),
    A(11),
    B(40),
    B(35),
    B(37),
    B(41),
    A(12),
    A(14),
    B(48),
    B(44),
    B(46),
    B(49),
    A(13),
    A(15),
    B(50),
    B(45),
    B(47),
    B(51),
    B(0),
    B(1),
    B(2),
    B(3),
    B(4),
    B(5),
    B(6),
    B(7),
    B(8),
    B(9),
    B(10),
    B(11),
    B(32),
    B(33),
    A(16),
    A(17),
    B(42),
    B(43),
    A(18),
    A(19),
];

fn legacy_words(columns: &[u32; BG_N_COLS]) -> [u32; BG_N_LOOKUP_WORDS] {
    let mut words = [0u32; BG_N_LOOKUP_WORDS];
    for tuple in 0..BG_TUPLE_RELATIONS.len() {
        words[4 * tuple] = BG_TUPLE_RELATIONS[tuple];
        for word in 0..3 {
            words[4 * tuple + 1 + word] =
                columns[BG_LOOKUP_TUPLE_COLUMNS[3 * tuple + word] as usize];
        }
    }
    words[64] = BG_FINAL_RELATION;
    for (word, &column) in BG_FINAL_COLUMNS.iter().enumerate() {
        words[65 + word] = columns[column as usize];
    }
    words[85] = 1;
    words[86] = columns[52];
    words
}

fn projected_columns(
    trace: &[u32; BG_N_TRACE],
    auxiliary: &[u32; BG_N_AUX],
) -> [u32; BG_N_PROJECTED_RELATION_COLUMNS] {
    BG_PROJECTED_RELATION_COLUMNS.map(|source| match source {
        BlakeGRelationColumnSource::BaseTrace(column) => trace[column as usize],
        BlakeGRelationColumnSource::Auxiliary(column) => auxiliary[column as usize],
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SixInputRow {
    pub(super) trace: [u32; BG_N_TRACE],
    auxiliary: [u32; BG_N_AUX],
    pub(super) tuples: [[u32; 4]; 16],
    final_tuple: [u32; 21],
    enabler: u32,
}

impl SixInputRow {
    fn lookup_words(&self) -> [u32; BG_N_LOOKUP_WORDS] {
        let mut words = [0u32; BG_N_LOOKUP_WORDS];
        for (tuple, values) in self.tuples.iter().enumerate() {
            words[4 * tuple..4 * tuple + 4].copy_from_slice(values);
        }
        words[64..85].copy_from_slice(&self.final_tuple);
        words[85] = 1;
        words[86] = self.enabler;
        words
    }

    fn columns(&self) -> [u32; BG_N_COLS] {
        let mut columns = [0u32; BG_N_COLS];
        columns[..BG_N_TRACE].copy_from_slice(&self.trace);
        columns[BG_N_TRACE..].copy_from_slice(&self.auxiliary);
        columns
    }
}

/// Host oracle for the exact six-input device evaluator. Every triple sum is
/// explicitly wrapping: the CUDA body uses `uint32_t`, not field addition.
pub(super) fn evaluate_six_inputs(inputs: [u32; 6], row: usize, n_real: usize) -> SixInputRow {
    let [in0, in1, in2, in3, in4, in5] = inputs;
    let lo16 = |value: u32| value & 0xffff;
    let hi16 = |value: u32| value >> 16;
    let mut trace = [0u32; BG_N_TRACE];
    let mut auxiliary = [0u32; BG_N_AUX];

    trace[..12].copy_from_slice(&[
        lo16(in0),
        hi16(in0),
        lo16(in1),
        hi16(in1),
        lo16(in2),
        hi16(in2),
        lo16(in3),
        hi16(in3),
        lo16(in4),
        hi16(in4),
        lo16(in5),
        hi16(in5),
    ]);

    let ts0 = in0.wrapping_add(in1).wrapping_add(in4);
    let (ts0_lo, ts0_hi) = (lo16(ts0), hi16(ts0));
    trace[12..14].copy_from_slice(&[ts0_lo, ts0_hi]);
    let (ts0_lo_ls8, ts0_lo_ms8) = (ts0_lo & 0xff, ts0_lo >> 8);
    let (ts0_hi_ls8, ts0_hi_ms8) = (ts0_hi & 0xff, ts0_hi >> 8);
    let (in3_lo_ls8, in3_lo_ms8) = (lo16(in3) & 0xff, lo16(in3) >> 8);
    let (in3_hi_ls8, in3_hi_ms8) = (hi16(in3) & 0xff, hi16(in3) >> 8);
    let xor16 = [
        ts0_lo_ls8 ^ in3_lo_ls8,
        ts0_lo_ms8 ^ in3_lo_ms8,
        ts0_hi_ls8 ^ in3_hi_ls8,
        ts0_hi_ms8 ^ in3_hi_ms8,
    ];
    auxiliary[..4].copy_from_slice(&[ts0_lo_ls8, ts0_hi_ls8, in3_lo_ls8, in3_hi_ls8]);
    trace[14..22].copy_from_slice(&[
        ts0_lo_ms8, ts0_hi_ms8, in3_lo_ms8, in3_hi_ms8, xor16[0], xor16[1], xor16[2], xor16[3],
    ]);
    let xr16_lo = xor16[2] + xor16[3] * 256;
    let xr16_hi = xor16[0] + xor16[1] * 256;
    let xr16 = xr16_lo + (xr16_hi << 16);

    let ts22 = in2.wrapping_add(xr16);
    let (ts22_lo, ts22_hi) = (lo16(ts22), hi16(ts22));
    trace[22..24].copy_from_slice(&[ts22_lo, ts22_hi]);
    let (in1_lo_ls12, in1_lo_ms4) = (lo16(in1) & 0xfff, lo16(in1) >> 12);
    let (in1_hi_ls12, in1_hi_ms4) = (hi16(in1) & 0xfff, hi16(in1) >> 12);
    let (ts22_lo_ls12, ts22_lo_ms4) = (ts22_lo & 0xfff, ts22_lo >> 12);
    let (ts22_hi_ls12, ts22_hi_ms4) = (ts22_hi & 0xfff, ts22_hi >> 12);
    let xor12 = [
        in1_lo_ls12 ^ ts22_lo_ls12,
        in1_lo_ms4 ^ ts22_lo_ms4,
        in1_hi_ls12 ^ ts22_hi_ls12,
        in1_hi_ms4 ^ ts22_hi_ms4,
    ];
    auxiliary[4..8].copy_from_slice(&[in1_lo_ls12, in1_hi_ls12, ts22_lo_ls12, ts22_hi_ls12]);
    trace[24..32].copy_from_slice(&[
        in1_lo_ms4,
        in1_hi_ms4,
        ts22_lo_ms4,
        ts22_hi_ms4,
        xor12[0],
        xor12[1],
        xor12[2],
        xor12[3],
    ]);
    let xr12_lo = xor12[1] + xor12[2] * 16;
    let xr12_hi = xor12[3] + xor12[0] * 16;
    let xr12 = xr12_lo + (xr12_hi << 16);

    let ts44 = ts0.wrapping_add(xr12).wrapping_add(in5);
    let (ts44_lo, ts44_hi) = (lo16(ts44), hi16(ts44));
    trace[32..34].copy_from_slice(&[ts44_lo, ts44_hi]);
    let (ts44_lo_ls8, ts44_lo_ms8) = (ts44_lo & 0xff, ts44_lo >> 8);
    let (ts44_hi_ls8, ts44_hi_ms8) = (ts44_hi & 0xff, ts44_hi >> 8);
    let (xr16_lo_ls8, xr16_lo_ms8) = (xr16_lo & 0xff, xr16_lo >> 8);
    let (xr16_hi_ls8, xr16_hi_ms8) = (xr16_hi & 0xff, xr16_hi >> 8);
    let xor8 = [
        ts44_lo_ls8 ^ xr16_lo_ls8,
        ts44_lo_ms8 ^ xr16_lo_ms8,
        ts44_hi_ls8 ^ xr16_hi_ls8,
        ts44_hi_ms8 ^ xr16_hi_ms8,
    ];
    auxiliary[8..12].copy_from_slice(&[ts44_lo_ls8, ts44_hi_ls8, xr16_lo_ls8, xr16_hi_ls8]);
    trace[34..42].copy_from_slice(&[
        ts44_lo_ms8,
        ts44_hi_ms8,
        xr16_lo_ms8,
        xr16_hi_ms8,
        xor8[0],
        xor8[1],
        xor8[2],
        xor8[3],
    ]);
    let xr8_lo = xor8[1] + xor8[2] * 256;
    let xr8_hi = xor8[3] + xor8[0] * 256;
    let xr8 = xr8_lo + (xr8_hi << 16);

    let ts66 = ts22.wrapping_add(xr8);
    let (ts66_lo, ts66_hi) = (lo16(ts66), hi16(ts66));
    trace[42..44].copy_from_slice(&[ts66_lo, ts66_hi]);
    let (xr12_lo_ls7, xr12_lo_ms9) = (xr12_lo & 0x7f, xr12_lo >> 7);
    let (xr12_hi_ls7, xr12_hi_ms9) = (xr12_hi & 0x7f, xr12_hi >> 7);
    let (ts66_lo_ls7, ts66_lo_ms9) = (ts66_lo & 0x7f, ts66_lo >> 7);
    let (ts66_hi_ls7, ts66_hi_ms9) = (ts66_hi & 0x7f, ts66_hi >> 7);
    let xor7 = [
        xr12_lo_ls7 ^ ts66_lo_ls7,
        xr12_lo_ms9 ^ ts66_lo_ms9,
        xr12_hi_ls7 ^ ts66_hi_ls7,
        xr12_hi_ms9 ^ ts66_hi_ms9,
    ];
    auxiliary[12..20].copy_from_slice(&[
        xr12_lo_ls7,
        xr12_hi_ls7,
        ts66_lo_ls7,
        ts66_hi_ls7,
        xor7[1] + xor7[2] * 512,
        xor7[3] + xor7[0] * 512,
        xr8_lo,
        xr8_hi,
    ]);
    trace[44..52].copy_from_slice(&[
        xr12_lo_ms9,
        xr12_hi_ms9,
        ts66_lo_ms9,
        ts66_hi_ms9,
        xor7[0],
        xor7[1],
        xor7[2],
        xor7[3],
    ]);
    let enabler = u32::from(row < n_real);
    trace[52] = enabler;

    let tuples = [
        [112_558_620, ts0_lo_ls8, in3_lo_ls8, xor16[0]],
        [112_558_620, ts0_lo_ms8, in3_lo_ms8, xor16[1]],
        [521_092_554, ts0_hi_ls8, in3_hi_ls8, xor16[2]],
        [521_092_554, ts0_hi_ms8, in3_hi_ms8, xor16[3]],
        [648_362_599, in1_lo_ls12, ts22_lo_ls12, xor12[0]],
        [45_448_144, in1_lo_ms4, ts22_lo_ms4, xor12[1]],
        [648_362_599, in1_hi_ls12, ts22_hi_ls12, xor12[2]],
        [45_448_144, in1_hi_ms4, ts22_hi_ms4, xor12[3]],
        [112_558_620, ts44_lo_ls8, xr16_lo_ls8, xor8[0]],
        [112_558_620, ts44_lo_ms8, xr16_lo_ms8, xor8[1]],
        [521_092_554, ts44_hi_ls8, xr16_hi_ls8, xor8[2]],
        [521_092_554, ts44_hi_ms8, xr16_hi_ms8, xor8[3]],
        [62_225_763, xr12_lo_ls7, ts66_lo_ls7, xor7[0]],
        [95_781_001, xr12_lo_ms9, ts66_lo_ms9, xor7[1]],
        [62_225_763, xr12_hi_ls7, ts66_hi_ls7, xor7[2]],
        [95_781_001, xr12_hi_ms9, ts66_hi_ms9, xor7[3]],
    ];
    let final_tuple = [
        BG_FINAL_RELATION,
        lo16(in0),
        hi16(in0),
        lo16(in1),
        hi16(in1),
        lo16(in2),
        hi16(in2),
        lo16(in3),
        hi16(in3),
        lo16(in4),
        hi16(in4),
        lo16(in5),
        hi16(in5),
        ts44_lo,
        ts44_hi,
        auxiliary[16],
        auxiliary[17],
        ts66_lo,
        ts66_hi,
        xr8_lo,
        xr8_hi,
    ];
    SixInputRow {
        trace,
        auxiliary,
        tuples,
        final_tuple,
        enabler,
    }
}

fn combine(words: &[u32], alphas: &[SecureField; 21], z: SecureField) -> SecureField {
    words.iter().enumerate().fold(-z, |acc, (index, &word)| {
        acc + SecureField::from(BaseField::from_u32_unchecked(word)) * alphas[index]
    })
}

pub(super) fn direct_denominators(
    row: &SixInputRow,
    alphas: &[SecureField; 21],
    z: SecureField,
) -> [SecureField; 17] {
    std::array::from_fn(|index| {
        if index < row.tuples.len() {
            combine(&row.tuples[index], alphas, z)
        } else {
            combine(&row.final_tuple, alphas, z)
        }
    })
}

pub(super) fn direct_fractions(
    row: &SixInputRow,
    alphas: &[SecureField; 21],
    z: SecureField,
) -> [SecureField; 9] {
    let denominators = direct_denominators(row, alphas, z);
    std::array::from_fn(|column| {
        if column < 8 {
            let left = denominators[2 * column];
            let right = denominators[2 * column + 1];
            (left + right) / (left * right)
        } else {
            -SecureField::from(BaseField::from_u32_unchecked(row.enabler)) / denominators[16]
        }
    })
}

fn legacy_fractions(
    words: &[u32; BG_N_LOOKUP_WORDS],
    alphas: &[SecureField; 21],
    z: SecureField,
) -> [SecureField; 9] {
    std::array::from_fn(|column| {
        if column < 8 {
            let (left_offset, _, left_width, _) = USES[2 * column];
            let (right_offset, _, right_width, _) = USES[2 * column + 1];
            let left = combine(&words[left_offset..left_offset + left_width], alphas, z);
            let right = combine(&words[right_offset..right_offset + right_width], alphas, z);
            (left + right) / (left * right)
        } else {
            let (offset, _, width, _) = USES[16];
            -SecureField::from(BaseField::from_u32_unchecked(words[86]))
                / combine(&words[offset..offset + width], alphas, z)
        }
    })
}

pub(super) fn chain(fractions: [SecureField; 9]) -> [SecureField; 9] {
    let mut sum = SecureField::zero();
    fractions.map(|fraction| {
        sum += fraction;
        sum
    })
}

#[test]
fn projected_map_is_exhaustive_pinned_and_minimal() {
    assert_eq!(BG_PROJECTED_RELATION_COLUMNS, EXPECTED_COLUMNS);
    assert_eq!(BG_PROJECTED_RELATION_MAP_HASH, 0x4898_bf01_628f_45b7);
    let mut base_entries = 0;
    let mut auxiliary_entries = 0;
    let mut base_columns = BTreeSet::new();
    let mut auxiliary_columns = BTreeSet::new();
    for source in BG_PROJECTED_RELATION_COLUMNS {
        match source {
            BlakeGRelationColumnSource::BaseTrace(column) => {
                base_entries += 1;
                base_columns.insert(column);
            }
            BlakeGRelationColumnSource::Auxiliary(column) => {
                auxiliary_entries += 1;
                auxiliary_columns.insert(column);
            }
        }
    }
    assert_eq!((base_entries, auxiliary_entries), (48, 20));
    assert_eq!(base_columns.len(), 48);
    assert_eq!(auxiliary_columns, (0..20).collect());
    let unused = (0..BG_N_TRACE as u8)
        .filter(|column| !base_columns.contains(column))
        .collect::<Vec<_>>();
    assert_eq!(unused, BG_PROJECTED_UNUSED_TRACE_COLUMNS);
    assert_eq!(
        USES.len() + BG_N_PROJECTED_RELATION_COLUMNS + 2,
        BG_N_LOOKUP_WORDS
    );
    assert!(blake_g_projected_relation_identity_is_exact(
        "blake_g",
        BG_FUSED_SEMANTIC_HASH,
        BG_N_LOOKUP_WORDS,
        BG_N_PROJECTED_RELATION_COLUMNS,
        BG_PROJECTED_RELATION_MAP_HASH,
    ));
    for mutation in [
        (
            "blake_g_mutated",
            BG_FUSED_SEMANTIC_HASH,
            BG_N_LOOKUP_WORDS,
            BG_N_PROJECTED_RELATION_COLUMNS,
            BG_PROJECTED_RELATION_MAP_HASH,
        ),
        (
            "blake_g",
            BG_FUSED_SEMANTIC_HASH ^ 1,
            BG_N_LOOKUP_WORDS,
            BG_N_PROJECTED_RELATION_COLUMNS,
            BG_PROJECTED_RELATION_MAP_HASH,
        ),
        (
            "blake_g",
            BG_FUSED_SEMANTIC_HASH,
            BG_N_LOOKUP_WORDS - 1,
            BG_N_PROJECTED_RELATION_COLUMNS,
            BG_PROJECTED_RELATION_MAP_HASH,
        ),
        (
            "blake_g",
            BG_FUSED_SEMANTIC_HASH,
            BG_N_LOOKUP_WORDS,
            BG_N_PROJECTED_RELATION_COLUMNS - 1,
            BG_PROJECTED_RELATION_MAP_HASH,
        ),
        (
            "blake_g",
            BG_FUSED_SEMANTIC_HASH,
            BG_N_LOOKUP_WORDS,
            BG_N_PROJECTED_RELATION_COLUMNS,
            BG_PROJECTED_RELATION_MAP_HASH ^ 1,
        ),
    ] {
        assert!(!blake_g_projected_relation_identity_is_exact(
            mutation.0, mutation.1, mutation.2, mutation.3, mutation.4
        ));
    }
}

#[test]
fn projected_tuples_match_legacy_for_boundary_random_and_padding_rows() {
    let mut state = 0x9e37_79b9u32;
    for case in 0..1_024usize {
        let rows = 1usize << (case % 9 + 1);
        let n_real = [1, rows / 2, rows.saturating_sub(1), rows][case % 4].max(1);
        let row = [0, n_real.saturating_sub(1), n_real.min(rows - 1), rows - 1][case % 4];
        let mut columns = [0u32; BG_N_COLS];
        for value in &mut columns {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *value = state % 0x7fff_ffff;
        }
        columns[52] = u32::from(row < n_real);
        let trace = std::array::from_fn(|column| columns[column]);
        let auxiliary = std::array::from_fn(|column| columns[BG_N_TRACE + column]);
        let legacy = legacy_words(&columns);
        let projected = projected_columns(&trace, &auxiliary);
        for (use_index, &(legacy_offset, projected_offset, width, relation)) in
            USES.iter().enumerate()
        {
            assert_eq!(legacy[legacy_offset], relation);
            assert_eq!(
                projected[projected_offset..projected_offset + width - 1],
                legacy[legacy_offset + 1..legacy_offset + width],
                "case={case} use={use_index} row={row} n_real={n_real}",
            );
        }
        assert_eq!(legacy[85], 1, "One stays one on padding");
        assert_eq!(legacy[86], u32::from(row < n_real));
    }
}

#[test]
fn six_input_oracle_matches_all_words_fractions_chains_and_claimed_sum() {
    // Base-field-only alpha powers plus a non-base z make every denominator
    // provably non-zero, so this test has no probabilistic divide-by-zero gap.
    let alphas = std::array::from_fn(|index| {
        SecureField::from(BaseField::from_u32_unchecked((index + 1) as u32))
    });
    let z = SecureField::from_u32_unchecked(0, 1, 0, 0);
    let boundaries = [
        [0; 6],
        [u32::MAX; 6],
        [u32::MAX, 1, u32::MAX, 1, u32::MAX, 1],
        [0, u32::MAX, 1, u32::MAX - 1, 0x8000_0000, 0x7fff_ffff],
    ];
    let mut state = 0xd1b5_4a32u32;

    for case in 0..64usize {
        let rows = 1usize << (case % 7 + 1);
        let n_real = [1, rows / 2, rows.saturating_sub(1), rows][case % 4].max(1);
        let mut direct_claimed_sum = SecureField::zero();
        let mut legacy_claimed_sum = SecureField::zero();
        for row_index in 0..rows {
            let inputs = if case < boundaries.len() && row_index == 0 {
                boundaries[case]
            } else {
                std::array::from_fn(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    state
                })
            };
            let direct = evaluate_six_inputs(inputs, row_index, n_real);
            let direct_words = direct.lookup_words();
            let legacy_words = legacy_words(&direct.columns());
            assert_eq!(
                direct_words, legacy_words,
                "all 87 words: case={case} row={row_index} n_real={n_real}"
            );

            let direct_fractions = direct_fractions(&direct, &alphas, z);
            let legacy_fractions = legacy_fractions(&legacy_words, &alphas, z);
            assert_eq!(
                direct_fractions, legacy_fractions,
                "eight pair fractions plus final fraction: case={case} row={row_index}"
            );
            let direct_chain = chain(direct_fractions);
            let legacy_chain = chain(legacy_fractions);
            assert_eq!(
                direct_chain, legacy_chain,
                "all 36 interaction coordinates: case={case} row={row_index}"
            );
            direct_claimed_sum += direct_chain[8];
            legacy_claimed_sum += legacy_chain[8];
            assert_eq!(direct.enabler, u32::from(row_index < n_real));
            if row_index >= n_real {
                assert_eq!(
                    direct_fractions[8],
                    SecureField::zero(),
                    "only the final Blake use is disabled on padding"
                );
            }
        }
        assert_eq!(
            direct_claimed_sum, legacy_claimed_sum,
            "claimed sum: case={case} rows={rows} n_real={n_real}"
        );
    }
}
