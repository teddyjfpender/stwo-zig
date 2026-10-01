//! Proof-of-work grind vectors for both Blake2s channel variants.
//!
//! Upstream `SimdBackend::grind` returns the smallest nonce `(hi << 32) | lo` with
//! `lo < 2^GRIND_LOW_BITS` (20) whose `verify_pow_nonce` succeeds, scanning `hi` upwards. A nonce
//! with `hi > 0` therefore appears whenever no `lo < 2^20` succeeds for `hi = 0`. The vectors
//! include such cases at 20 and 26 bits, and for `pow_bits <= 20` the oracle proves minimality
//! by rejecting every smaller candidate of the same `(hi, lo < 2^20)` form.

use anyhow::{Result, ensure};
use serde::Serialize;
use stwo::core::channel::{Blake2sChannelGeneric, Channel};
use stwo::core::proof_of_work::GrindOps;
use stwo::prover::backend::simd::SimdBackend;

use crate::checkpoint::{U64Record, hex32};
use crate::primitives::channel::{BLAKE2S_LANE, BLAKE2S_M31_LANE};

/// Upstream `GRIND_LOW_BITS` (`crates/stwo/src/prover/backend/simd/grind.rs`).
pub const GRIND_LOW_BITS: u32 = 20;
/// The largest `pow_bits` for which the oracle exhaustively proves minimality.
const EXHAUSTIVE_MINIMALITY_MAX_BITS: u32 = 20;

#[derive(Serialize)]
pub struct GrindRecord {
    pub lane: &'static str,
    /// The channel is `Channel::default()` followed by `mix_u64(seed)`.
    pub seed: u64,
    pub digest: String,
    pub pow_bits: u32,
    pub nonce: U64Record,
    /// `true` when every smaller `(hi, lo < 2^20)` candidate was checked and rejected.
    pub minimality_proven: bool,
}

#[derive(Serialize)]
pub struct GrindSection {
    pub grind_low_bits: u32,
    pub cases: Vec<GrindRecord>,
}

fn seeded_channel<const M: bool>(seed: u64) -> Blake2sChannelGeneric<M> {
    let mut channel = Blake2sChannelGeneric::<M>::default();
    channel.mix_u64(seed);
    channel
}

fn prove_minimal<const M: bool>(
    channel: &Blake2sChannelGeneric<M>,
    pow_bits: u32,
    nonce: u64,
) -> Result<()> {
    let (hi, lo) = ((nonce >> 32) as u32, nonce as u32);
    ensure!(
        lo < 1 << GRIND_LOW_BITS,
        "grind low word {lo} is outside the scanned window"
    );
    for candidate_hi in 0..=hi {
        let end = if candidate_hi == hi {
            lo
        } else {
            1 << GRIND_LOW_BITS
        };
        for candidate_lo in 0..end {
            let candidate = ((candidate_hi as u64) << 32) | candidate_lo as u64;
            ensure!(
                !channel.verify_pow_nonce(pow_bits, candidate),
                "grind nonce {nonce} is not minimal: {candidate} also verifies"
            );
        }
    }
    Ok(())
}

fn grind_case<const M: bool>(lane: &'static str, seed: u64, pow_bits: u32) -> Result<GrindRecord>
where
    SimdBackend: GrindOps<Blake2sChannelGeneric<M>>,
{
    let channel = seeded_channel::<M>(seed);
    let nonce = SimdBackend::grind(&channel, pow_bits);
    ensure!(
        channel.verify_pow_nonce(pow_bits, nonce),
        "grind returned a failing nonce"
    );
    let minimality_proven = pow_bits <= EXHAUSTIVE_MINIMALITY_MAX_BITS;
    if minimality_proven {
        prove_minimal(&channel, pow_bits, nonce)?;
    }
    Ok(GrindRecord {
        lane,
        seed,
        digest: hex32(channel.digest().0),
        pow_bits,
        nonce: nonce.into(),
        minimality_proven,
    })
}

/// Seeds for `pow_bits = 20`: the first two whose nonce has `hi == 0` and the first two whose
/// nonce has `hi > 0`, scanning seeds upwards.
fn split_cases_at_20<const M: bool>(lane: &'static str) -> Result<Vec<GrindRecord>>
where
    SimdBackend: GrindOps<Blake2sChannelGeneric<M>>,
{
    const PER_CLASS: usize = 2;
    let (mut low, mut high) = (Vec::new(), Vec::new());
    for seed in 0u64.. {
        if low.len() == PER_CLASS && high.len() == PER_CLASS {
            break;
        }
        ensure!(seed < 64, "no hi>0 grind within 64 seeds at 20 bits");
        let record = grind_case::<M>(lane, seed, 20)?;
        let class = if record.nonce.hi == 0 {
            &mut low
        } else {
            &mut high
        };
        if class.len() < PER_CLASS {
            class.push(record);
        }
    }
    low.extend(high);
    Ok(low)
}

fn lane_cases<const M: bool>(lane: &'static str) -> Result<Vec<GrindRecord>>
where
    SimdBackend: GrindOps<Blake2sChannelGeneric<M>>,
{
    let mut cases = Vec::new();
    for seed in 0..2 {
        cases.push(grind_case::<M>(lane, seed, 16)?);
    }
    cases.extend(split_cases_at_20::<M>(lane)?);
    for seed in 0..2 {
        cases.push(grind_case::<M>(lane, seed, 24)?);
    }
    for seed in 0..3 {
        cases.push(grind_case::<M>(lane, seed, 26)?);
    }
    ensure!(
        cases
            .iter()
            .any(|case| case.pow_bits == 26 && case.nonce.hi > 0),
        "{lane}: no hi>0 grind among the 26-bit seeds"
    );
    Ok(cases)
}

pub fn grind_section() -> Result<GrindSection> {
    let mut cases = lane_cases::<false>(BLAKE2S_LANE)?;
    cases.extend(lane_cases::<true>(BLAKE2S_M31_LANE)?);
    Ok(GrindSection {
        grind_low_bits: GRIND_LOW_BITS,
        cases,
    })
}
