//! Strict codecs and typed reconstruction for the compact Metal proof boundary.
//!
//! Authenticated protocol, statement, and proof bytes are validated before a
//! pinned `StarkProof` and Cairo verifier input are constructed.

use cairo_air::air::{
    MemorySmallValue, PublicData, PublicMemory, PublicSegmentRanges, SegmentRange,
};
use cairo_air::cairo_components::CairoComponents;
use cairo_air::claims::{CairoClaim, CairoInteractionClaim};
use cairo_air::relations::CommonLookupElements;
use cairo_air::CairoProofForRustVerifier;
use serde_json::{Map, Value};
use std::fmt;
use stwo::core::air::Components;
use stwo::core::channel::Blake2sChannel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::{FriConfig, FriLayerProof, FriProof};
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::pcs::{PcsConfig, TreeVec};
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_common::prover_types::cpu::CasmState;

mod proof_codec;
mod protocol;
mod reconstruction;
mod statement;

pub(super) use proof_codec::*;
pub use protocol::*;
pub use reconstruction::*;
pub use statement::*;

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub fn protocol_bytes_for_lib_tests() -> Vec<u8> {
        CompactProtocolV1::sn2(0, 2, 4, 4000, protocol::EXPECTED_TRACE_COLUMNS)
            .encode()
            .unwrap()
    }
}

#[cfg(test)]
mod tests;
