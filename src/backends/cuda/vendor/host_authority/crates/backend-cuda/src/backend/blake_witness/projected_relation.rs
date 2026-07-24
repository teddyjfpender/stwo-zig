//! Descriptor-native Blake-G relation projection.
//!
//! This module pins the complete legacy 87-word meaning while materializing
//! only the 68 row-varying operands. It is an ABI/capacity bridge, not a
//! production speed claim: retaining committed operands may add copy traffic.

use super::{BG_FUSED_SEMANTIC_HASH, BG_N_TRACE};

/// Canonical source of one descriptor-native Blake-G relation operand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlakeGRelationColumnSource {
    BaseTrace(u8),
    Auxiliary(u8),
}

pub(super) const BG_LOOKUP_TUPLE_COLUMNS: [u8; 48] = [
    53, 55, 18, 14, 16, 19, 54, 56, 20, 15, 17, 21, 57, 59, 28, 24, 26, 29, 58, 60, 30, 25, 27, 31,
    61, 63, 38, 34, 36, 39, 62, 64, 40, 35, 37, 41, 65, 67, 48, 44, 46, 49, 66, 68, 50, 45, 47, 51,
];
pub(super) const BG_TUPLE_RELATIONS: [u32; 16] = [
    112_558_620,
    112_558_620,
    521_092_554,
    521_092_554,
    648_362_599,
    45_448_144,
    648_362_599,
    45_448_144,
    112_558_620,
    112_558_620,
    521_092_554,
    521_092_554,
    62_225_763,
    95_781_001,
    62_225_763,
    95_781_001,
];
pub(super) const BG_FINAL_COLUMNS: [u8; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 32, 33, 69, 70, 42, 43, 71, 72,
];
pub(super) const BG_FINAL_RELATION: u32 = 1_139_985_212;

const fn column_source(column: u8) -> BlakeGRelationColumnSource {
    if column < BG_N_TRACE as u8 {
        BlakeGRelationColumnSource::BaseTrace(column)
    } else {
        BlakeGRelationColumnSource::Auxiliary(column - BG_N_TRACE as u8)
    }
}

pub const BG_N_PROJECTED_RELATION_COLUMNS: usize = 68;

const fn build_columns() -> [BlakeGRelationColumnSource; BG_N_PROJECTED_RELATION_COLUMNS] {
    let mut sources = [BlakeGRelationColumnSource::BaseTrace(0); BG_N_PROJECTED_RELATION_COLUMNS];
    let mut column = 0;
    while column < BG_LOOKUP_TUPLE_COLUMNS.len() {
        sources[column] = column_source(BG_LOOKUP_TUPLE_COLUMNS[column]);
        column += 1;
    }
    let mut final_column = 0;
    while final_column < BG_FINAL_COLUMNS.len() {
        sources[BG_LOOKUP_TUPLE_COLUMNS.len() + final_column] =
            column_source(BG_FINAL_COLUMNS[final_column]);
        final_column += 1;
    }
    sources
}

pub const BG_N_LOOKUP_WORDS: usize = 87;
pub const BG_PROJECTED_RELATION_COLUMNS: [BlakeGRelationColumnSource;
    BG_N_PROJECTED_RELATION_COLUMNS] = build_columns();

/// Trace columns deliberately not retained through Interaction by this ABI.
pub const BG_PROJECTED_UNUSED_TRACE_COLUMNS: [u8; 5] = [12, 13, 22, 23, 52];

const fn hash_entry(mut hash: u64, tag: u8, value: u32) -> u64 {
    hash = (hash ^ tag as u64).wrapping_mul(0x100_0000_01b3);
    let bytes = value.to_le_bytes();
    let mut byte = 0;
    while byte < bytes.len() {
        hash = (hash ^ bytes[byte] as u64).wrapping_mul(0x100_0000_01b3);
        byte += 1;
    }
    hash
}

const fn map_hash() -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut tuple = 0;
    while tuple < BG_TUPLE_RELATIONS.len() {
        hash = hash_entry(hash, 2, BG_TUPLE_RELATIONS[tuple]);
        let mut operand = 0;
        while operand < 3 {
            let (tag, ordinal) = match BG_PROJECTED_RELATION_COLUMNS[3 * tuple + operand] {
                BlakeGRelationColumnSource::BaseTrace(ordinal) => (0, ordinal),
                BlakeGRelationColumnSource::Auxiliary(ordinal) => (1, ordinal),
            };
            hash = hash_entry(hash, tag, ordinal as u32);
            operand += 1;
        }
        tuple += 1;
    }
    hash = hash_entry(hash, 2, BG_FINAL_RELATION);
    let mut operand = BG_LOOKUP_TUPLE_COLUMNS.len();
    while operand < BG_PROJECTED_RELATION_COLUMNS.len() {
        let (tag, ordinal) = match BG_PROJECTED_RELATION_COLUMNS[operand] {
            BlakeGRelationColumnSource::BaseTrace(ordinal) => (0, ordinal),
            BlakeGRelationColumnSource::Auxiliary(ordinal) => (1, ordinal),
        };
        hash = hash_entry(hash, tag, ordinal as u32);
        operand += 1;
    }
    hash = hash_entry(hash, 3, 1); // Multiplicity::One.
    hash_entry(hash, 4, 0) // Multiplicity::Enabler.
}

pub const BG_PROJECTED_RELATION_MAP_HASH: u64 = map_hash();

pub fn blake_g_projected_relation_identity_is_exact(
    component: &str,
    semantic_hash: u64,
    logical_words: usize,
    projected_columns: usize,
    map_hash: u64,
) -> bool {
    component == "blake_g"
        && semantic_hash == BG_FUSED_SEMANTIC_HASH
        && logical_words == BG_N_LOOKUP_WORDS
        && projected_columns == BG_N_PROJECTED_RELATION_COLUMNS
        && map_hash == BG_PROJECTED_RELATION_MAP_HASH
}

#[cfg(test)]
#[path = "projected_relation_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "projected_relation_native_tests.rs"]
mod native_tests;
