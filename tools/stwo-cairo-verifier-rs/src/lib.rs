//! Strict framing and canonical Cairo verification for `STWZCVE/1`.
//!
//! The first implemented proof codec accepts the complete serde JSON emitted by
//! `gpu_bench`, or its `CairoProofForRustVerifier` projection. Compact resident
//! proof reconstruction is authenticated and reconstructed by `compact_codec`.

pub mod compact_codec;
mod framing;
mod interaction_claim_guard;
mod support;
mod verification;

pub use framing::*;
pub use support::*;
pub use verification::*;

#[cfg(test)]
mod tests;
