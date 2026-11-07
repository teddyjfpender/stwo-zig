//! Bounded, optional advice indexed by pairing-call ordinal. Advice can only
//! establish a mathematically checked positive result; it cannot supply a bit.
use super::{miller, residue};
#[cfg(feature = "host")]
use alloc::vec::Vec;
#[cfg(feature = "host")]
use ark_bn254::Bn254;
#[cfg(feature = "host")]
use ark_ec::pairing::{MillerLoopOutput, Pairing};
#[cfg(feature = "host")]
use ark_ff::One;

const MAGIC: &[u8; 8] = b"STWBNH01";
const HEADER: usize = 12;
const RECORD: usize = 4 + residue::BYTES;
const MAX_HINTS: usize = 4096;

pub(super) struct Stream {
    rows: &'static [u8],
    calls: u64,
    #[cfg(feature = "host")]
    pub(super) collect: Option<Vec<u8>>,
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().expect("checked hint width"))
}

impl Stream {
    pub(super) const fn new() -> Self {
        Self {
            rows: &[],
            calls: 0,
            #[cfg(feature = "host")]
            collect: None,
        }
    }

    pub(super) fn install(&mut self, input: &'static [u8]) -> Option<&'static [u8]> {
        if input.len() < crate::witness::HEADER {
            return None;
        }
        let base = word(&input[16..]) as usize;
        if base < crate::witness::HEADER || base > input.len() {
            return None;
        }
        let (base, trailer) = input.split_at(base);
        if !trailer.is_empty() {
            if trailer.len() < HEADER || &trailer[..8] != MAGIC {
                return None;
            }
            let count = word(&trailer[8..]) as usize;
            if count > MAX_HINTS || trailer.len() != HEADER + count * RECORD {
                return None;
            }
            let rows = &trailer[HEADER..];
            let mut previous = 0;
            for row in rows.chunks_exact(RECORD) {
                let ordinal = word(row);
                if ordinal <= previous {
                    return None;
                }
                previous = ordinal;
            }
            self.rows = rows;
        }
        Some(base)
    }

    pub(super) fn next(&mut self) -> Option<&'static [u8]> {
        self.calls += 1;
        if self.rows.is_empty() || u64::from(word(self.rows)) != self.calls {
            return None;
        }
        let (row, rest) = self.rows.split_at(RECORD);
        self.rows = rest;
        Some(&row[4..])
    }

    pub(super) fn check(&mut self, groups: &[miller::Group], hint: Option<&[u8]>) -> bool {
        if let Some(hint) = hint.and_then(residue::Hint::decode) {
            if hint.valid_seed()
                && hint.check_tail(miller::run(groups, Some((&hint.seed, &hint.inverse))))
            {
                return true;
            }
        }
        #[cfg(feature = "host")]
        if let Some(rows) = &mut self.collect {
            let value = miller::run(groups, None);
            let result =
                Bn254::final_exponentiation(MillerLoopOutput(value)).is_some_and(|o| o.0.is_one());
            if result && rows.len() / RECORD < MAX_HINTS {
                if let (Ok(ordinal), Some(hint)) = (
                    u32::try_from(self.calls),
                    residue::Hint::from_positive_miller(value),
                ) {
                    rows.extend_from_slice(&ordinal.to_le_bytes());
                    rows.extend_from_slice(&hint.encode());
                }
            }
            return result;
        }
        miller::check(groups)
    }

    #[cfg(feature = "host")]
    pub(super) fn finish(&mut self, mut input: Vec<u8>) -> Option<Vec<u8>> {
        let rows = self.collect.take()?;
        if input.len().checked_add(HEADER + rows.len())? > crate::witness::MAX_INPUT {
            return None;
        }
        input.extend_from_slice(MAGIC);
        input.extend_from_slice(&((rows.len() / RECORD) as u32).to_le_bytes());
        input.extend(rows);
        Some(input)
    }
}
