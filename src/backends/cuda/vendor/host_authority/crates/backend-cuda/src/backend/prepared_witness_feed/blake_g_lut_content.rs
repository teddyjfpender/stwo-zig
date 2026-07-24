//! Collision-resistant identity for the four immutable direct Blake-G LUTs.
//!
//! The identity is derived from the complete host words. Callers cannot supply
//! a digest, and the fixed role order and extents are part of both hash layers.

use super::super::prepared_witness::{
    BlakeGDirectLut, BLAKE_G_DIRECT_LUT_ORDER, BLAKE_G_DIRECT_LUT_WORDS,
};

const LUT_DOMAIN: &[u8] = b"stwo-cuda-blake-g-direct-lut-content-v1\0";
const ORDERED_DOMAIN: &[u8] = b"stwo-cuda-blake-g-direct-ordered-lut-content-v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlakeGDirectLutContentError {
    LengthMismatch {
        role: BlakeGDirectLut,
        expected: usize,
        actual: usize,
    },
    RowOutOfRange {
        role: BlakeGDirectLut,
        index: usize,
        row: u32,
        row_count: usize,
    },
}

impl core::fmt::Display for BlakeGDirectLutContentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid direct Blake-G LUT content: {self:?}")
    }
}

impl std::error::Error for BlakeGDirectLutContentError {}

/// Exact content identity for the four LUT roles consumed by direct Blake-G.
///
/// Construction validates every extent and row before hashing all words in
/// host order. Equality is therefore the authority boundary: geometry alone
/// never proves that a prepared LUT is the canonical preprocessed permutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlakeGDirectLutContentIdentity {
    ordered_lut_identities: [[u8; 32]; 4],
    identity: [u8; 32],
}

impl BlakeGDirectLutContentIdentity {
    /// Derive the only accepted identity form from complete host LUT words.
    ///
    /// The array order is [`BLAKE_G_DIRECT_LUT_ORDER`]. There is deliberately
    /// no constructor from digest bytes.
    pub fn from_host_words(luts: [&[u32]; 4]) -> Result<Self, BlakeGDirectLutContentError> {
        let mut ordered_lut_identities = [[0; 32]; 4];
        for (index, ((words, role), expected)) in luts
            .into_iter()
            .zip(BLAKE_G_DIRECT_LUT_ORDER)
            .zip(BLAKE_G_DIRECT_LUT_WORDS)
            .enumerate()
        {
            validate_lut(role, expected, words)?;
            ordered_lut_identities[index] = lut_identity(role, expected, words);
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(ORDERED_DOMAIN);
        hash_len(&mut hasher, ordered_lut_identities.len());
        for ((role, words), lut_identity) in BLAKE_G_DIRECT_LUT_ORDER
            .into_iter()
            .zip(BLAKE_G_DIRECT_LUT_WORDS)
            .zip(ordered_lut_identities)
        {
            hasher.update(&[role as u8]);
            hash_len(&mut hasher, words);
            hasher.update(&lut_identity);
        }
        let identity = *hasher.finalize().as_bytes();
        Ok(Self {
            ordered_lut_identities,
            identity,
        })
    }

    pub const fn identity(&self) -> [u8; 32] {
        self.identity
    }

    pub const fn ordered_lut_identities(&self) -> [[u8; 32]; 4] {
        self.ordered_lut_identities
    }

    pub const fn lut_order(&self) -> [BlakeGDirectLut; 4] {
        BLAKE_G_DIRECT_LUT_ORDER
    }

    pub const fn lut_words(&self) -> [usize; 4] {
        BLAKE_G_DIRECT_LUT_WORDS
    }
}

fn validate_lut(
    role: BlakeGDirectLut,
    expected: usize,
    words: &[u32],
) -> Result<(), BlakeGDirectLutContentError> {
    if words.len() != expected {
        return Err(BlakeGDirectLutContentError::LengthMismatch {
            role,
            expected,
            actual: words.len(),
        });
    }
    if let Some((index, &row)) = words
        .iter()
        .enumerate()
        .find(|(_, row)| **row as usize >= expected)
    {
        return Err(BlakeGDirectLutContentError::RowOutOfRange {
            role,
            index,
            row,
            row_count: expected,
        });
    }
    Ok(())
}

fn lut_identity(role: BlakeGDirectLut, expected: usize, words: &[u32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LUT_DOMAIN);
    hasher.update(&[role as u8]);
    hash_len(&mut hasher, expected);
    hash_len(&mut hasher, words.len());
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn hash_len(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(
        &u64::try_from(value)
            .expect("direct Blake-G LUT extent fits u64")
            .to_le_bytes(),
    );
}

#[cfg(test)]
mod tests;
