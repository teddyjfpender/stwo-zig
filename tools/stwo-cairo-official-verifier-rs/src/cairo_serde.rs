//! Pinned official Cairo-verifier serialization for Rust-verifier proofs.

use std::ops::Deref;
use std::path::Path;

use anyhow::{Context, Result};
use cairo_air::CairoProofForRustVerifier;
use cairo_air::utils::{deserialize_proof_from_file, sort_and_transpose_queried_values};
use starknet_ff::FieldElement;
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo_cairo_serialize::CairoSerialize;

use crate::ProofFormat;

/// Serializes the exact values consumed by the Cairo verifier.
///
/// The official `CairoSerialize` implementation is defined for the prover's
/// extended proof, even though it does not serialize the auxiliary fields.
/// This adapter applies the same upstream field order directly to the
/// Rust-verifier proof so transport parity can be checked independently.
pub fn serialize_blake2s_proof(path: &Path, format: ProofFormat) -> Result<Vec<String>> {
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(path, format.upstream())
            .context("failed to deserialize Blake2s Cairo proof")?;
    let mut serialized = Vec::<FieldElement>::new();

    let trace_log_sizes = proof.claim.log_sizes();
    let CommitmentSchemeProof {
        config,
        commitments,
        sampled_values,
        decommitments,
        queried_values,
        proof_of_work,
        fri_proof,
    } = &proof.stark_proof.0;
    let sorted_queried_values = sort_and_transpose_queried_values(
        queried_values,
        trace_log_sizes
            .iter()
            .map(|columns| columns.as_slice())
            .collect(),
    );

    proof.claim.serialize(&mut serialized);
    proof.interaction_pow.serialize(&mut serialized);
    proof
        .interaction_claim
        .flatten_interaction_claim()
        .serialize(&mut serialized);
    config.serialize(&mut serialized);
    commitments.deref().serialize(&mut serialized);
    sampled_values.deref().serialize(&mut serialized);
    decommitments.deref().serialize(&mut serialized);
    sorted_queried_values.deref().serialize(&mut serialized);
    proof_of_work.serialize(&mut serialized);
    fri_proof.serialize(&mut serialized);
    proof.channel_salt.serialize(&mut serialized);

    Ok(serialized
        .into_iter()
        .map(|felt| format!("0x{felt:x}"))
        .collect())
}
