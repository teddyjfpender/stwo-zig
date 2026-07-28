use crate::compact_codec::{
    reconstruct_cairo_proof_v1, CompactProtocolV1, CompactStatementV1, PROTOCOL_MAGIC,
};
use crate::framing::{Envelope, SectionKind};
use crate::interaction_claim_guard::validate_memory_id_to_big_aggregate;
use crate::support::{
    hex_digest, COMPACT_PROOF_PROVENANCE_SOURCE, COMPACT_PROOF_SERIALIZATION,
    EMBEDDED_STATEMENT_ENCODING, EXTENDED_JSON_PROOF_ENCODING, JSON_BRIDGE_PROVENANCE_SOURCE,
    JSON_PROOF_PROTOCOL_SCHEMA_VERSION, RUST_VERIFIER_JSON_PROOF_ENCODING, STWO_CAIRO_REVISION,
    STWO_REVISION,
};
use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, CairoProofForRustVerifier};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;

/// Exact protocol payload for the bounded JSON-proof bridge.
///
/// These fields are checked both against the accepted SN PIE protocol and
/// against the deserialized proof before canonical verification is attempted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonProofProtocol {
    pub schema_version: u32,
    pub proof_encoding: String,
    pub channel: String,
    pub preprocessed_trace_variant: String,
    pub channel_salt: u32,
    pub pow_bits: u32,
    pub log_blowup_factor: u32,
    pub n_queries: u32,
    pub log_last_layer_degree_bound: u32,
    pub fold_step: u32,
    pub lifting_log_size: Option<u32>,
    pub interaction_pow_bits: u32,
    pub stwo_cairo_revision: String,
    pub stwo_revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedStatementBinding {
    pub schema_version: u32,
    pub encoding: String,
    pub proof_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JsonBridgeProvenance {
    pub schema_version: u32,
    pub source: String,
    pub protocol_sha256: String,
    pub statement_sha256: String,
    pub proof_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompactProofProvenance {
    pub schema_version: u32,
    pub source: String,
    pub proof_serialization: String,
    pub protocol_sha256: String,
    pub statement_sha256: String,
    pub proof_sha256: String,
    pub adapted_input_sha256: String,
    pub artifact_manifest_sha256: String,
    pub runner_executable_sha256: String,
    pub backend_executable_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalVerificationFailure {
    pub code: &'static str,
    pub message: String,
}

impl CanonicalVerificationFailure {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CanonicalVerificationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CanonicalVerificationFailure {}

/// Verifies a complete Cairo proof JSON carried by an authenticated envelope.
///
/// This is deliberately not a compact-proof decoder. The proof section must be
/// a complete Rust serde object containing its typed claim and public data.
pub fn verify_json_proof_envelope(
    envelope: &Envelope<'_>,
) -> Result<(), CanonicalVerificationFailure> {
    let protocol_section = envelope.section(SectionKind::Protocol);
    let statement_section = envelope.section(SectionKind::Statement);
    let proof_section = envelope.section(SectionKind::Proof);
    let provenance_section = envelope.section(SectionKind::Provenance);

    let protocol: JsonProofProtocol =
        serde_json::from_slice(protocol_section.payload).map_err(|error| {
            CanonicalVerificationFailure::new(
                "invalid_protocol",
                format!("invalid JSON proof protocol payload: {error}"),
            )
        })?;
    validate_json_proof_protocol(&protocol)?;

    let statement: EmbeddedStatementBinding = serde_json::from_slice(statement_section.payload)
        .map_err(|error| {
            CanonicalVerificationFailure::new(
                "invalid_statement_binding",
                format!("invalid embedded-statement binding: {error}"),
            )
        })?;
    if statement.schema_version != JSON_PROOF_PROTOCOL_SCHEMA_VERSION
        || statement.encoding != EMBEDDED_STATEMENT_ENCODING
        || statement.proof_sha256 != hex_digest(proof_section.sha256)
    {
        return Err(CanonicalVerificationFailure::new(
            "invalid_statement_binding",
            "statement section does not canonically bind the proof JSON",
        ));
    }

    let provenance: JsonBridgeProvenance = serde_json::from_slice(provenance_section.payload)
        .map_err(|error| {
            CanonicalVerificationFailure::new(
                "invalid_provenance_binding",
                format!("invalid JSON bridge provenance: {error}"),
            )
        })?;
    if provenance.schema_version != JSON_PROOF_PROTOCOL_SCHEMA_VERSION
        || provenance.source != JSON_BRIDGE_PROVENANCE_SOURCE
        || provenance.protocol_sha256 != hex_digest(protocol_section.sha256)
        || provenance.statement_sha256 != hex_digest(statement_section.sha256)
        || provenance.proof_sha256 != hex_digest(proof_section.sha256)
    {
        return Err(CanonicalVerificationFailure::new(
            "invalid_provenance_binding",
            "provenance section does not bind all JSON bridge inputs",
        ));
    }

    let proof = decode_json_proof(&protocol, proof_section.payload)?;
    validate_protocol_against_proof(&protocol, &proof)?;
    verify_pinned_cairo_proof(proof)
}

pub fn verification_mode(envelope: &Envelope<'_>) -> &'static str {
    if envelope
        .section(SectionKind::Protocol)
        .payload
        .starts_with(&PROTOCOL_MAGIC)
    {
        "compact_metal_proof_v1"
    } else {
        "complete_cairo_proof_json_v1"
    }
}

pub fn verify_authenticated_envelope(
    envelope: &Envelope<'_>,
) -> Result<(), CanonicalVerificationFailure> {
    if verification_mode(envelope) == "compact_metal_proof_v1" {
        verify_compact_proof_envelope(envelope)
    } else {
        verify_json_proof_envelope(envelope)
    }
}

pub fn verify_compact_proof_envelope(
    envelope: &Envelope<'_>,
) -> Result<(), CanonicalVerificationFailure> {
    let protocol_section = envelope.section(SectionKind::Protocol);
    let statement_section = envelope.section(SectionKind::Statement);
    let proof_section = envelope.section(SectionKind::Proof);
    let provenance_section = envelope.section(SectionKind::Provenance);

    let provenance: CompactProofProvenance = serde_json::from_slice(provenance_section.payload)
        .map_err(|error| {
            CanonicalVerificationFailure::new(
                "invalid_provenance_binding",
                format!("invalid compact-proof provenance: {error}"),
            )
        })?;
    let identities = [
        &provenance.adapted_input_sha256,
        &provenance.artifact_manifest_sha256,
        &provenance.runner_executable_sha256,
        &provenance.backend_executable_sha256,
    ];
    if provenance.schema_version != 1
        || provenance.source != COMPACT_PROOF_PROVENANCE_SOURCE
        || provenance.proof_serialization != COMPACT_PROOF_SERIALIZATION
        || provenance.protocol_sha256 != hex_digest(protocol_section.sha256)
        || provenance.statement_sha256 != hex_digest(statement_section.sha256)
        || provenance.proof_sha256 != hex_digest(proof_section.sha256)
        || identities
            .into_iter()
            .any(|digest| !is_lower_sha256(digest))
    {
        return Err(CanonicalVerificationFailure::new(
            "invalid_provenance_binding",
            "compact provenance does not canonically bind all proof inputs and identities",
        ));
    }

    let protocol = CompactProtocolV1::decode(protocol_section.payload)
        .map_err(|error| CanonicalVerificationFailure::new(error.code, error.message))?;
    let statement = CompactStatementV1::decode(statement_section.payload)
        .map_err(|error| CanonicalVerificationFailure::new(error.code, error.message))?;
    let proof = reconstruct_cairo_proof_v1(proof_section.payload, &protocol, &statement)
        .map_err(|error| CanonicalVerificationFailure::new(error.code, error.message))?;
    verify_pinned_cairo_proof(proof)
}

fn verify_pinned_cairo_proof(
    proof: CairoProofForRustVerifier<Blake2sMerkleHasher>,
) -> Result<(), CanonicalVerificationFailure> {
    validate_memory_id_to_big_aggregate(&proof)?;
    match catch_unwind(AssertUnwindSafe(|| {
        verify_cairo::<Blake2sMerkleChannel>(proof)
    })) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(CanonicalVerificationFailure::new(
            "canonical_verification_rejected",
            error.to_string(),
        )),
        Err(payload) => Err(CanonicalVerificationFailure::new(
            "canonical_verification_panicked",
            panic_message(payload),
        )),
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_json_proof_protocol(
    protocol: &JsonProofProtocol,
) -> Result<(), CanonicalVerificationFailure> {
    let encoding_supported = matches!(
        protocol.proof_encoding.as_str(),
        EXTENDED_JSON_PROOF_ENCODING | RUST_VERIFIER_JSON_PROOF_ENCODING
    );
    let variant_supported = matches!(
        protocol.preprocessed_trace_variant.as_str(),
        "canonical" | "canonical_without_pedersen" | "canonical_small"
    );
    if protocol.schema_version != JSON_PROOF_PROTOCOL_SCHEMA_VERSION
        || !encoding_supported
        || protocol.channel != "blake2s"
        || !variant_supported
        || protocol.pow_bits != 26
        || protocol.log_blowup_factor != 1
        || protocol.n_queries != 70
        || protocol.log_last_layer_degree_bound != 0
        || protocol.fold_step != 3
        || protocol.lifting_log_size.is_some()
        || protocol.interaction_pow_bits != 24
        || protocol.stwo_cairo_revision != STWO_CAIRO_REVISION
        || protocol.stwo_revision != STWO_REVISION
    {
        return Err(CanonicalVerificationFailure::new(
            "invalid_protocol",
            "JSON proof protocol is not the pinned SN PIE Blake2s/fold-3 configuration",
        ));
    }
    Ok(())
}

fn decode_json_proof(
    protocol: &JsonProofProtocol,
    payload: &[u8],
) -> Result<CairoProofForRustVerifier<Blake2sMerkleHasher>, CanonicalVerificationFailure> {
    match protocol.proof_encoding.as_str() {
        EXTENDED_JSON_PROOF_ENCODING => {
            serde_json::from_slice::<CairoProof<Blake2sMerkleHasher>>(payload)
                .map(Into::into)
                .map_err(|error| {
                    CanonicalVerificationFailure::new(
                        "invalid_proof_json",
                        format!("invalid extended Cairo proof JSON: {error}"),
                    )
                })
        }
        RUST_VERIFIER_JSON_PROOF_ENCODING => serde_json::from_slice(payload).map_err(|error| {
            CanonicalVerificationFailure::new(
                "invalid_proof_json",
                format!("invalid Rust-verifier Cairo proof JSON: {error}"),
            )
        }),
        _ => Err(CanonicalVerificationFailure::new(
            "invalid_protocol",
            "unsupported proof encoding",
        )),
    }
}

fn validate_protocol_against_proof(
    protocol: &JsonProofProtocol,
    proof: &CairoProofForRustVerifier<Blake2sMerkleHasher>,
) -> Result<(), CanonicalVerificationFailure> {
    let proof_variant = match proof.preprocessed_trace_variant {
        PreProcessedTraceVariant::Canonical => "canonical",
        PreProcessedTraceVariant::CanonicalWithoutPedersen => "canonical_without_pedersen",
        PreProcessedTraceVariant::CanonicalSmall => "canonical_small",
    };
    let PcsConfig {
        pow_bits,
        fri_config,
        lifting_log_size,
    } = proof.stark_proof.0.config;
    if proof.channel_salt != protocol.channel_salt
        || proof_variant != protocol.preprocessed_trace_variant
        || pow_bits != protocol.pow_bits
        || fri_config.log_blowup_factor != protocol.log_blowup_factor
        || fri_config.n_queries != protocol.n_queries as usize
        || fri_config.log_last_layer_degree_bound != protocol.log_last_layer_degree_bound
        || fri_config.fold_step != protocol.fold_step
        || lifting_log_size != protocol.lifting_log_size
    {
        return Err(CanonicalVerificationFailure::new(
            "proof_protocol_mismatch",
            "deserialized proof parameters do not match the authenticated protocol",
        ));
    }
    Ok(())
}

fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "canonical verifier panicked with a non-string payload".to_owned()
    }
}
