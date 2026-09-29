//! `prove-cairo`: the leaf-lane Cairo proof (R10c).
//!
//! Runs `stwo_cairo_prover::prover::prove_cairo::<Blake2sM31MerkleChannel>` on an adapted
//! `ProverInput` under a `ProverParameters` document, exactly as `leaf-prover`'s step 3
//! (`crates/leaf_prover/src/prove_leaf.rs`) does with the registry's `cairo_prover_params`: the
//! leaf lane always proves on `Blake2sM31MerkleChannel`, so `channel_hash` is ignored, as in Rust.
//! The proof is verified with `verify_cairo_ex` before anything is emitted.
//!
//! Output, a checkpoint that pins the proof bytes and summarises each transcript stage:
//!
//! - `binary`: SHA-256 and length of `bincode(CairoProofForRustVerifier)` (the `Binary` proof
//!   format without its bzip2 wrapper). Every byte in it is fixed by the protocol.
//! - `extended_binary`: SHA-256 and length of `bincode(CairoProof)` (the `ExtendedBinary` format
//!   without bzip2) with every auxiliary hash map written in ascending key order. Upstream
//!   serializes `hashbrown::HashMap`s whose iteration order depends on a per-process random seed,
//!   so its own `ExtendedBinary` bytes are not reproducible run to run; the canonical order is the
//!   one encoding both implementations can agree on. Map lengths and entries are unchanged.
//! - `stages`: the per-stage values a divergence is localised with (config, the four roots, the
//!   two PoW nonces, digests of each proof field).
//!
//! `--proof-output` additionally writes the canonical `ExtendedBinary` payload for local diffing.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use cairo_air::CairoProof;
use cairo_air::air::CairoProofForRustVerifier;
use cairo_air::verifier::verify_cairo_ex;
use serde::Serialize;
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleHasher};
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLiftedAux;
use stwo::core::vcs_lifted::hasher::Hasher;
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_prover::prover::{ProverParameters, prove_cairo};

use crate::checkpoint::{Envelope, InputRecord, U64Record, hex32, sha256_hex};
use crate::upstream::ProvingRoot;

type H = Blake2sMerkleHasher;
type Hash = <H as Hasher>::Hash;

#[derive(Serialize)]
struct ByteRecord {
    bytes: u64,
    sha256: String,
}

impl ByteRecord {
    fn of(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.len() as u64,
            sha256: sha256_hex(bytes),
        }
    }
}

#[derive(Serialize)]
struct PcsConfigRecord {
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u64,
    fold_step: u32,
    trace_lifting_log_size: u32,
    preprocessed_lifting_log_size: u32,
}

impl From<PcsConfig> for PcsConfigRecord {
    fn from(config: PcsConfig) -> Self {
        let fri = config.fri_config;
        Self {
            pow_bits: fri.pow_bits,
            log_blowup_factor: fri.log_blowup_factor,
            log_last_layer_degree_bound: fri.log_last_layer_degree_bound,
            n_queries: fri.n_queries as u64,
            fold_step: fri.fold_step,
            trace_lifting_log_size: config.trace_lifting_log_size,
            preprocessed_lifting_log_size: config.preprocessed_lifting_log_size,
        }
    }
}

/// Per-stage summaries. Each `*_sha256` is SHA-256 of that field's bincode encoding.
#[derive(Serialize)]
struct Stages {
    config: PcsConfigRecord,
    claim_sha256: String,
    interaction_pow: U64Record,
    interaction_claim_sha256: String,
    commitments: Vec<String>,
    sampled_values_sha256: String,
    decommitments_sha256: String,
    queried_values_sha256: String,
    proof_of_work: U64Record,
    fri_proof_sha256: String,
    fri_inner_layer_roots: Vec<String>,
    fri_last_layer_poly: Vec<[u32; 4]>,
    unsorted_query_locations_sha256: String,
    trace_aux_sha256: String,
    fri_aux_sha256: String,
    channel_salt: u32,
}

#[derive(Serialize)]
struct Body {
    params: serde_json::Value,
    binary: ByteRecord,
    extended_binary: ByteRecord,
    stages: Stages,
}

pub struct Output {
    pub checkpoint: Vec<u8>,
    pub extended_binary: Vec<u8>,
}

fn bincode_of(value: &impl Serialize) -> Result<Vec<u8>> {
    bincode::serialize(value).context("bincode serialization failed")
}

/// `MerkleDecommitmentLiftedAux` with every layer map in ascending key order.
#[derive(Serialize)]
struct CanonicalMerkleAux {
    all_node_values: Vec<BTreeMap<usize, Hash>>,
}

impl From<&MerkleDecommitmentLiftedAux<H>> for CanonicalMerkleAux {
    fn from(aux: &MerkleDecommitmentLiftedAux<H>) -> Self {
        Self {
            all_node_values: aux
                .all_node_values
                .iter()
                .map(|layer| layer.iter().map(|(k, v)| (*k, *v)).collect())
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct CanonicalFriLayerAux {
    all_values: Vec<BTreeMap<usize, QM31>>,
    decommitment: CanonicalMerkleAux,
}

#[derive(Serialize)]
struct CanonicalFriAux {
    first_layer: CanonicalFriLayerAux,
    inner_layers: Vec<CanonicalFriLayerAux>,
}

fn canonical_fri_layer(layer: &stwo::core::fri::FriLayerProofAux<H>) -> CanonicalFriLayerAux {
    CanonicalFriLayerAux {
        all_values: layer
            .all_values
            .iter()
            .map(|map| map.iter().map(|(k, v)| (*k, *v)).collect())
            .collect(),
        decommitment: (&layer.decommitment).into(),
    }
}

#[derive(Serialize)]
struct CanonicalAux {
    unsorted_query_locations: Vec<usize>,
    trace_decommitment: Vec<CanonicalMerkleAux>,
    fri: CanonicalFriAux,
}

/// Field order and types of `cairo_air::CairoProof`, with the canonical aux.
#[derive(Serialize)]
struct CanonicalCairoProof<'a> {
    claim: &'a cairo_air::claims::CairoClaim,
    interaction_pow: u64,
    interaction_claim: &'a cairo_air::claims::CairoInteractionClaim,
    stark_proof: &'a stwo::core::proof::StarkProof<H>,
    aux: CanonicalAux,
    channel_salt: u32,
    preprocessed_trace_variant: &'a stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant,
}

fn canonical_extended_binary(proof: &CairoProof<H>) -> Result<Vec<u8>> {
    let aux = &proof.extended_stark_proof.aux;
    let canonical = CanonicalCairoProof {
        claim: &proof.claim,
        interaction_pow: proof.interaction_pow,
        interaction_claim: &proof.interaction_claim,
        stark_proof: &proof.extended_stark_proof.proof,
        aux: CanonicalAux {
            unsorted_query_locations: aux.unsorted_query_locations.clone(),
            trace_decommitment: aux.trace_decommitment.iter().map(Into::into).collect(),
            fri: CanonicalFriAux {
                first_layer: canonical_fri_layer(&aux.fri.first_layer),
                inner_layers: aux.fri.inner_layers.iter().map(canonical_fri_layer).collect(),
            },
        },
        channel_salt: proof.channel_salt,
        preprocessed_trace_variant: &proof.preprocessed_trace_variant,
    };
    bincode_of(&canonical)
}

fn hash_hex(hash: &Hash) -> String {
    hex32(hash.as_ref())
}

/// `params` is a `ProverParameters` document or a circuit registry, whose
/// `cairo_prover_params` member is then used. With `proving_root` it is a path inside that
/// `proving` checkout (recorded relative to it); otherwise a local path.
pub fn run(prover_input: &Path, params: &Path, proving_root: Option<&Path>) -> Result<Output> {
    let input_bytes = std::fs::read(prover_input)
        .with_context(|| format!("failed to read {}", prover_input.display()))?;
    let mut inputs = vec![InputRecord {
        path: prover_input.display().to_string(),
        bytes: input_bytes.len() as u64,
        sha256: sha256_hex(&input_bytes),
    }];
    let params_bytes = match proving_root {
        Some(root) => {
            let mut checkout = ProvingRoot::open(root)?;
            let bytes = checkout.read(&params.display().to_string())?;
            inputs.extend(checkout.into_records());
            bytes
        }
        None => {
            let bytes = std::fs::read(params)
                .with_context(|| format!("failed to read {}", params.display()))?;
            inputs.push(InputRecord {
                path: params.display().to_string(),
                bytes: bytes.len() as u64,
                sha256: sha256_hex(&bytes),
            });
            bytes
        }
    };
    let input: ProverInput =
        serde_json::from_slice(&input_bytes).context("invalid ProverInput JSON")?;
    let document: serde_json::Value = serde_json::from_slice(&params_bytes)?;
    let params_json = document.get("cairo_prover_params").cloned().unwrap_or(document);
    let prover_params: ProverParameters = serde_json::from_value(params_json.clone())
        .context("invalid ProverParameters JSON")?;

    let proof = prove_cairo::<Blake2sM31MerkleChannel>(input, prover_params)
        .map_err(|error| anyhow::anyhow!("prove_cairo failed: {error:?}"))?;
    verify_cairo_ex::<Blake2sM31MerkleChannel>(
        proof.clone().into(),
        prover_params.include_all_preprocessed_columns,
    )
    .map_err(|error| anyhow::anyhow!("verify_cairo_ex rejected the proof: {error:?}"))?;

    let binary = bincode_of(&CairoProofForRustVerifier::from(proof.clone()))?;
    let extended_binary = canonical_extended_binary(&proof)?;
    // `CairoProof` and `CanonicalCairoProof` share their field order and the upstream derive
    // writes a map as `len, (key, value)*`, so the canonical payload has the upstream length.
    ensure!(
        bincode_of(&proof)?.len() == extended_binary.len(),
        "canonical ExtendedBinary length differs from upstream's"
    );

    let stark = &proof.extended_stark_proof.proof.0;
    let aux = &proof.extended_stark_proof.aux;
    let stages = Stages {
        config: stark.config.into(),
        claim_sha256: sha256_hex(bincode_of(&proof.claim)?),
        interaction_pow: proof.interaction_pow.into(),
        interaction_claim_sha256: sha256_hex(bincode_of(&proof.interaction_claim)?),
        commitments: stark.commitments.iter().map(hash_hex).collect(),
        sampled_values_sha256: sha256_hex(bincode_of(&stark.sampled_values)?),
        decommitments_sha256: sha256_hex(bincode_of(&stark.decommitments)?),
        queried_values_sha256: sha256_hex(bincode_of(&stark.queried_values)?),
        proof_of_work: stark.proof_of_work.into(),
        fri_proof_sha256: sha256_hex(bincode_of(&stark.fri_proof)?),
        fri_inner_layer_roots: stark
            .fri_proof
            .inner_layers
            .iter()
            .map(|layer| hash_hex(&layer.commitment))
            .collect(),
        fri_last_layer_poly: stark
            .fri_proof
            .last_layer_poly
            .clone()
            .into_ordered_coefficients()
            .into_iter()
            .map(crate::checkpoint::qm31)
            .collect(),
        unsorted_query_locations_sha256: sha256_hex(bincode_of(&aux.unsorted_query_locations)?),
        trace_aux_sha256: sha256_hex(bincode_of(
            &aux.trace_decommitment
                .iter()
                .map(CanonicalMerkleAux::from)
                .collect::<Vec<_>>(),
        )?),
        fri_aux_sha256: sha256_hex(bincode_of(&CanonicalFriAux {
            first_layer: canonical_fri_layer(&aux.fri.first_layer),
            inner_layers: aux.fri.inner_layers.iter().map(canonical_fri_layer).collect(),
        })?),
        channel_salt: proof.channel_salt,
    };

    let body = Body {
        params: params_json,
        binary: ByteRecord::of(&binary),
        extended_binary: ByteRecord::of(&extended_binary),
        stages,
    };
    Ok(Output {
        checkpoint: crate::output::json(&Envelope::new("r10c", "prove-cairo", inputs, body))?,
        extended_binary,
    })
}

const _: fn() = || {
    fn is_lifted<T: MerkleHasherLifted>() {}
    is_lifted::<H>();
};
