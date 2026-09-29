//! `verify-circuit`: upstream `circuit_verifier::verify::verify_circuit` on a circuit proof given as
//! CircuitSerialize bytes, for accepting proofs made by another prover (design §8.2, R7/R11).
//!
//! The request names everything the verifier takes besides the proof: the proof's `PcsConfig`, the
//! verified circuit's preprocessed column log sizes (commitment order), its preprocessed root and
//! the output digest it claims. The proof is decoded with `deserialize_proof_with_config` under
//! `circuit_verifier_proof_config` of those, and verified by building and checking the verification
//! circuit. The checkpoint records the proof's digest and whether it was accepted; a rejection is a
//! result, not an error.

use std::path::Path;

use anyhow::{Context as _, Result};
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::statement::circuit_verifier_proof_config;
use circuit_verifier::verify::{CircuitConfig, CircuitPublicData, verify_circuit};
use circuits::blake::HashValue;
use circuits_stark_verifier::order_hash_map::OrderedHashMap;
use serde::{Deserialize, Serialize};
use stwo::core::pcs::PcsConfig;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::checkpoint::{Envelope, sha256_hex};

#[derive(Deserialize, Serialize)]
pub struct VerifyRequest {
    pub pcs_config: PcsConfig,
    pub preprocessed_column_log_sizes: Vec<(String, u32)>,
    pub preprocessed_root: [u32; 8],
    pub output_digest: [u32; 8],
}

#[derive(Serialize)]
pub struct VerifyBody {
    pub request: VerifyRequest,
    pub proof_bytes: usize,
    pub proof_sha256: String,
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<String>,
}

pub fn run(proof_path: &Path, request_path: &Path) -> Result<Envelope<VerifyBody>> {
    let proof_bytes = std::fs::read(proof_path)
        .with_context(|| format!("failed to read {}", proof_path.display()))?;
    let request: VerifyRequest = serde_json::from_slice(
        &std::fs::read(request_path)
            .with_context(|| format!("failed to read {}", request_path.display()))?,
    )
    .context("invalid verify request")?;
    let layout: OrderedHashMap<PreProcessedColumnId, u32> = request
        .preprocessed_column_log_sizes
        .iter()
        .map(|(id, log_size)| (PreProcessedColumnId { id: id.clone() }, *log_size))
        .collect();
    let proof_config = circuit_verifier_proof_config(&layout, &request.pcs_config);

    let outcome = match deserialize_proof_with_config(&mut proof_bytes.as_slice(), &proof_config) {
        Err(error) => Err(format!("deserialize: {error:?}")),
        // Upstream asserts on some malformed proofs; a panic is a rejection too.
        Ok(proof) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_circuit(
                CircuitConfig {
                    config: request.pcs_config,
                    preprocessed_column_log_sizes: layout,
                },
                HashValue::from(request.preprocessed_root),
                proof,
                CircuitPublicData {
                    output_digest: HashValue::from(request.output_digest),
                },
            )
            .map(|_| ())
        }))
        .unwrap_or_else(|panic| {
            Err(panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "verifier panicked".to_owned()))
        }),
    };
    Ok(Envelope::new(
        "r7",
        "verify-circuit",
        Vec::new(),
        VerifyBody {
            request,
            proof_bytes: proof_bytes.len(),
            proof_sha256: sha256_hex(&proof_bytes),
            accepted: outcome.is_ok(),
            rejection: outcome.err(),
        },
    ))
}
