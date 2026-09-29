//! Rung R0: primitive vectors that need no circuit.
//!
//! - `channel`: Blake2s / Blake2s-M31 channel transcripts, `mix_hash`, `FriConfig::mix_into`;
//! - `grind`: minimum-nonce proof-of-work vectors at 16, 20, 24 and 26 bits;
//! - `fields`: M31 reduction and QM31 (including pointwise) operations;
//! - `hashing`: `Hasher` vectors, `reduce_to_m31`, host and in-circuit circuit hashes;
//! - `fri`: FRI folding with `fold_step = 4` down to a last layer of degree bound 0;
//! - `formats`: ChaCha20Rng KAT, felt252 word encoding, leaf wire JSON, base64.

mod channel;
mod fields;
mod formats;
mod fri;
mod grind;
mod hashing;

use anyhow::Result;
use serde::Serialize;

use crate::checkpoint::Envelope;

/// An upstream in-tree expectation (an `expect!` snapshot, golden constant or registry value)
/// that the oracle re-derived and asserted before emitting the checkpoint.
#[derive(Serialize)]
pub struct UpstreamExpectation {
    pub source: &'static str,
    pub name: &'static str,
    pub value: String,
}

#[derive(Serialize)]
pub struct PrimitivesBody {
    pub upstream_expectations: Vec<UpstreamExpectation>,
    pub channels: Vec<channel::ScriptRecord>,
    pub grind: grind::GrindSection,
    pub fields: fields::FieldsSection,
    pub hashing: hashing::HashingSection,
    pub formats: formats::FormatsSection,
    pub fri: fri::FriFoldSection,
}

pub fn run() -> Result<Envelope<PrimitivesBody>> {
    let mut upstream_expectations = Vec::new();
    let hashing = hashing::hashing_section(&mut upstream_expectations)?;
    let body = PrimitivesBody {
        channels: channel::channel_scripts(),
        grind: grind::grind_section()?,
        fields: fields::fields_section(),
        hashing,
        formats: formats::formats_section()?,
        fri: fri::fri_fold_section()?,
        upstream_expectations,
    };
    Ok(Envelope::new("r0", "primitives", Vec::new(), body))
}
