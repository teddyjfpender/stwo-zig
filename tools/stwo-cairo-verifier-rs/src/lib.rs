//! Strict framing and canonical Cairo verification for `STWZCVE/1`.
//!
//! The first implemented proof codec accepts the complete serde JSON emitted by
//! `gpu_bench`, or its `CairoProofForRustVerifier` projection. Compact resident
//! proof reconstruction remains a separate, explicitly unsupported codec.

pub mod compact_codec;
mod interaction_claim_guard;

use crate::compact_codec::{
    reconstruct_cairo_proof_v1, CompactProtocolV1, CompactStatementV1, PROTOCOL_MAGIC,
};
use crate::interaction_claim_guard::validate_memory_id_to_big_aggregate;
use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, CairoProofForRustVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;

pub const ENVELOPE_ABI: &str = "STWZCVE/1";
pub const MAGIC: [u8; 8] = *b"STWZCVE\0";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: u16 = 32;
pub const SECTION_HEADER_LEN: usize = 48;
pub const REQUIRED_SECTION_COUNT: u32 = 4;
pub const SECTION_FLAG_MANDATORY: u16 = 1;
pub const MAX_ENVELOPE_LEN: u64 = 1 << 30;
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const MAX_RESULT_LEN: u64 = 1 << 20;
pub const MAX_ADDRESS_SPACE_LEN: u64 = 4 << 30;

pub const STWO_CAIRO_REPOSITORY: &str = "https://github.com/teddyjfpender/stwo-cairo";
pub const STWO_CAIRO_REVISION: &str = "dcd5834565b7a26a27a614e353c9c60109ebc1d9";
pub const STWO_REPOSITORY: &str = "https://github.com/teddyjfpender/stwo";
pub const STWO_REVISION: &str = "9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2";
pub const JSON_PROOF_PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const EXTENDED_JSON_PROOF_ENCODING: &str = "cairo_proof_extended_json_v1";
pub const RUST_VERIFIER_JSON_PROOF_ENCODING: &str = "cairo_proof_rust_verifier_json_v1";
pub const EMBEDDED_STATEMENT_ENCODING: &str = "embedded_in_cairo_proof_json_v1";
pub const JSON_BRIDGE_PROVENANCE_SOURCE: &str = "gpu_bench_json_bridge_v1";
pub const COMPACT_PROOF_PROVENANCE_SOURCE: &str = "metal_prover_service_v1";
pub const COMPACT_PROOF_SERIALIZATION: &str = "resident_sn2_bundle_v1";

const CARGO_LOCK: &[u8] = include_bytes!("../Cargo.lock");

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum SectionKind {
    Protocol = 1,
    Statement = 2,
    Proof = 3,
    Provenance = 4,
}

impl SectionKind {
    pub const ALL: [Self; 4] = [
        Self::Protocol,
        Self::Statement,
        Self::Proof,
        Self::Provenance,
    ];

    fn from_u16(value: u16) -> Result<Self, EnvelopeError> {
        match value {
            1 => Ok(Self::Protocol),
            2 => Ok(Self::Statement),
            3 => Ok(Self::Proof),
            4 => Ok(Self::Provenance),
            _ => Err(EnvelopeError::UnknownSection(value)),
        }
    }

    pub fn max_payload_len(self) -> u64 {
        match self {
            Self::Protocol => 4 << 20,
            Self::Statement => 256 << 20,
            Self::Proof => 512 << 20,
            Self::Provenance => 16 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Section<'a> {
    pub kind: SectionKind,
    pub payload: &'a [u8],
    pub sha256: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub struct Envelope<'a> {
    sections: [Section<'a>; 4],
}

impl<'a> Envelope<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > usize::try_from(MAX_ENVELOPE_LEN).unwrap_or(usize::MAX) {
            return Err(EnvelopeError::EnvelopeTooLarge(bytes.len() as u64));
        }
        if bytes.len() < usize::from(HEADER_LEN) {
            return Err(EnvelopeError::TruncatedHeader);
        }
        if bytes[..MAGIC.len()] != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }

        let version = read_u16(bytes, 8)?;
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let header_len = read_u16(bytes, 10)?;
        if header_len != HEADER_LEN {
            return Err(EnvelopeError::NoncanonicalHeaderLength(header_len));
        }
        let flags = read_u32(bytes, 12)?;
        if flags != 0 {
            return Err(EnvelopeError::UnknownHeaderFlags(flags));
        }
        let section_count = read_u32(bytes, 16)?;
        if section_count != REQUIRED_SECTION_COUNT {
            return Err(EnvelopeError::InvalidSectionCount(section_count));
        }
        let reserved = read_u32(bytes, 20)?;
        if reserved != 0 {
            return Err(EnvelopeError::NonzeroHeaderReserved(reserved));
        }
        let declared_len = read_u64(bytes, 24)?;
        if declared_len > MAX_ENVELOPE_LEN {
            return Err(EnvelopeError::EnvelopeTooLarge(declared_len));
        }
        let actual_len = u64::try_from(bytes.len()).map_err(|_| EnvelopeError::LengthOverflow)?;
        if declared_len != actual_len {
            return Err(EnvelopeError::EnvelopeLengthMismatch {
                declared: declared_len,
                actual: actual_len,
            });
        }

        let mut cursor = usize::from(HEADER_LEN);
        let mut parsed: [Option<Section<'a>>; 4] = [None; 4];
        for expected_kind in SectionKind::ALL {
            let header_end = cursor
                .checked_add(SECTION_HEADER_LEN)
                .ok_or(EnvelopeError::LengthOverflow)?;
            if header_end > bytes.len() {
                return Err(EnvelopeError::TruncatedSectionHeader(expected_kind));
            }

            let kind = SectionKind::from_u16(read_u16(bytes, cursor)?)?;
            if kind != expected_kind {
                if parsed[kind as usize - 1].is_some() {
                    return Err(EnvelopeError::DuplicateSection(kind));
                }
                return Err(EnvelopeError::NoncanonicalSectionOrder {
                    expected: expected_kind,
                    actual: kind,
                });
            }
            let section_flags = read_u16(bytes, cursor + 2)?;
            if section_flags != SECTION_FLAG_MANDATORY {
                return Err(EnvelopeError::UnknownSectionFlags {
                    kind,
                    flags: section_flags,
                });
            }
            let section_reserved = read_u32(bytes, cursor + 4)?;
            if section_reserved != 0 {
                return Err(EnvelopeError::NonzeroSectionReserved {
                    kind,
                    value: section_reserved,
                });
            }
            let payload_len = read_u64(bytes, cursor + 8)?;
            if payload_len == 0 {
                return Err(EnvelopeError::EmptySection(kind));
            }
            if payload_len > kind.max_payload_len() {
                return Err(EnvelopeError::SectionTooLarge {
                    kind,
                    length: payload_len,
                    maximum: kind.max_payload_len(),
                });
            }
            let mut expected_digest = [0_u8; 32];
            expected_digest.copy_from_slice(&bytes[cursor + 16..cursor + 48]);

            let payload_start = header_end;
            let payload_len =
                usize::try_from(payload_len).map_err(|_| EnvelopeError::LengthOverflow)?;
            let payload_end = payload_start
                .checked_add(payload_len)
                .ok_or(EnvelopeError::LengthOverflow)?;
            if payload_end > bytes.len() {
                return Err(EnvelopeError::TruncatedSectionPayload(kind));
            }
            let payload = &bytes[payload_start..payload_end];
            let actual_digest = sha256(payload);
            if actual_digest != expected_digest {
                return Err(EnvelopeError::DigestMismatch(kind));
            }

            parsed[kind as usize - 1] = Some(Section {
                kind,
                payload,
                sha256: actual_digest,
            });
            cursor = payload_end;
        }

        if cursor != bytes.len() {
            return Err(EnvelopeError::TrailingBytes(bytes.len() - cursor));
        }

        Ok(Self {
            sections: parsed
                .map(|section| section.expect("all four canonical sections were parsed in order")),
        })
    }

    pub fn section(&self, kind: SectionKind) -> Section<'a> {
        self.sections[kind as usize - 1]
    }

    pub fn sections(&self) -> &[Section<'a>; 4] {
        &self.sections
    }
}

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
    fn new(code: &'static str, message: impl Into<String>) -> Self {
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

#[derive(Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    BadMagic,
    DigestMismatch(SectionKind),
    DuplicateSection(SectionKind),
    EmptySection(SectionKind),
    EnvelopeLengthMismatch {
        declared: u64,
        actual: u64,
    },
    EnvelopeTooLarge(u64),
    InvalidSectionCount(u32),
    LengthOverflow,
    NoncanonicalHeaderLength(u16),
    NoncanonicalSectionOrder {
        expected: SectionKind,
        actual: SectionKind,
    },
    NonzeroHeaderReserved(u32),
    NonzeroSectionReserved {
        kind: SectionKind,
        value: u32,
    },
    SectionTooLarge {
        kind: SectionKind,
        length: u64,
        maximum: u64,
    },
    TrailingBytes(usize),
    TruncatedHeader,
    TruncatedSectionHeader(SectionKind),
    TruncatedSectionPayload(SectionKind),
    UnknownHeaderFlags(u32),
    UnknownSection(u16),
    UnknownSectionFlags {
        kind: SectionKind,
        flags: u16,
    },
    UnsupportedVersion(u16),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EnvelopeError::*;
        match self {
            BadMagic => write!(formatter, "invalid STWZCVE magic"),
            DigestMismatch(kind) => write!(formatter, "{:?} section SHA-256 mismatch", kind),
            DuplicateSection(kind) => write!(formatter, "duplicate {:?} section", kind),
            EmptySection(kind) => write!(formatter, "empty {:?} section", kind),
            EnvelopeLengthMismatch { declared, actual } => write!(
                formatter,
                "envelope length mismatch: header declares {declared}, file has {actual}"
            ),
            EnvelopeTooLarge(length) => write!(
                formatter,
                "envelope length {length} exceeds {MAX_ENVELOPE_LEN}-byte limit"
            ),
            InvalidSectionCount(count) => {
                write!(formatter, "section count {count} is not exactly four")
            }
            LengthOverflow => write!(formatter, "integer overflow while decoding envelope length"),
            NoncanonicalHeaderLength(length) => {
                write!(formatter, "noncanonical header length {length}")
            }
            NoncanonicalSectionOrder { expected, actual } => write!(
                formatter,
                "noncanonical section order: expected {:?}, found {:?}",
                expected, actual
            ),
            NonzeroHeaderReserved(value) => {
                write!(formatter, "header reserved field is nonzero ({value})")
            }
            NonzeroSectionReserved { kind, value } => write!(
                formatter,
                "{:?} section reserved field is nonzero ({value})",
                kind
            ),
            SectionTooLarge {
                kind,
                length,
                maximum,
            } => write!(
                formatter,
                "{:?} section length {length} exceeds {maximum}-byte limit",
                kind
            ),
            TrailingBytes(count) => write!(formatter, "{count} trailing envelope bytes"),
            TruncatedHeader => write!(formatter, "truncated STWZCVE header"),
            TruncatedSectionHeader(kind) => {
                write!(formatter, "truncated {:?} section header", kind)
            }
            TruncatedSectionPayload(kind) => {
                write!(formatter, "truncated {:?} section payload", kind)
            }
            UnknownHeaderFlags(flags) => write!(formatter, "unknown header flags 0x{flags:08x}"),
            UnknownSection(kind) => write!(formatter, "unknown mandatory section type {kind}"),
            UnknownSectionFlags { kind, flags } => {
                write!(formatter, "unknown {:?} section flags 0x{flags:04x}", kind)
            }
            UnsupportedVersion(version) => {
                write!(formatter, "unsupported STWZCVE version {version}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[derive(Debug, Serialize)]
pub struct SourcePin {
    pub repository: &'static str,
    pub revision: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AdapterIdentity {
    pub schema_version: u32,
    pub adapter_version: &'static str,
    pub envelope_abi: &'static str,
    pub cargo_lock_sha256: String,
    pub executable_sha256: Option<String>,
    pub stwo_cairo: SourcePin,
    pub stwo: SourcePin,
    pub proof_reconstruction_implemented: bool,
    pub canonical_verification_implemented: bool,
    pub json_proof_verification_implemented: bool,
    pub compact_claim_reconstruction_implemented: bool,
    pub compact_stark_proof_reconstruction_implemented: bool,
    pub compact_proof_reconstruction_implemented: bool,
    pub compact_proof_verification_implemented: bool,
}

#[derive(Debug, Serialize)]
pub struct SectionLimits {
    pub protocol_bytes: u64,
    pub statement_bytes: u64,
    pub proof_bytes: u64,
    pub provenance_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct VerifierConfig {
    pub schema_version: u32,
    pub adapter_version: &'static str,
    pub envelope_abi: &'static str,
    pub result_schema_version: u32,
    pub argv_template: [&'static str; 5],
    pub timeout_ms: u64,
    pub max_envelope_bytes: u64,
    pub max_result_bytes: u64,
    pub max_address_space_bytes: u64,
    pub section_limits: SectionLimits,
    pub stwo_cairo: SourcePin,
    pub stwo: SourcePin,
}

pub fn adapter_identity(executable: Option<&Path>) -> io::Result<AdapterIdentity> {
    Ok(AdapterIdentity {
        schema_version: 1,
        adapter_version: env!("CARGO_PKG_VERSION"),
        envelope_abi: ENVELOPE_ABI,
        cargo_lock_sha256: hex_digest(sha256(CARGO_LOCK)),
        executable_sha256: executable.map(sha256_file).transpose()?.map(hex_digest),
        stwo_cairo: SourcePin {
            repository: STWO_CAIRO_REPOSITORY,
            revision: STWO_CAIRO_REVISION,
        },
        stwo: SourcePin {
            repository: STWO_REPOSITORY,
            revision: STWO_REVISION,
        },
        proof_reconstruction_implemented: true,
        canonical_verification_implemented: true,
        json_proof_verification_implemented: true,
        compact_claim_reconstruction_implemented: true,
        compact_stark_proof_reconstruction_implemented: true,
        compact_proof_reconstruction_implemented: true,
        compact_proof_verification_implemented: true,
    })
}

pub fn verifier_config() -> VerifierConfig {
    VerifierConfig {
        schema_version: 1,
        adapter_version: env!("CARGO_PKG_VERSION"),
        envelope_abi: ENVELOPE_ABI,
        result_schema_version: 1,
        argv_template: [
            "verify",
            "--envelope",
            "{exclusive_envelope_path}",
            "--result",
            "{exclusive_result_path}",
        ],
        timeout_ms: DEFAULT_TIMEOUT_MS,
        max_envelope_bytes: MAX_ENVELOPE_LEN,
        max_result_bytes: MAX_RESULT_LEN,
        max_address_space_bytes: MAX_ADDRESS_SPACE_LEN,
        section_limits: SectionLimits {
            protocol_bytes: SectionKind::Protocol.max_payload_len(),
            statement_bytes: SectionKind::Statement.max_payload_len(),
            proof_bytes: SectionKind::Proof.max_payload_len(),
            provenance_bytes: SectionKind::Provenance.max_payload_len(),
        },
        stwo_cairo: SourcePin {
            repository: STWO_CAIRO_REPOSITORY,
            revision: STWO_CAIRO_REVISION,
        },
        stwo: SourcePin {
            repository: STWO_REPOSITORY,
            revision: STWO_REVISION,
        },
    }
}

pub fn read_envelope_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "envelope path is not a regular file",
        ));
    }
    if metadata.len() > MAX_ENVELOPE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "envelope length {} exceeds {MAX_ENVELOPE_LEN}-byte limit",
                metadata.len()
            ),
        ));
    }

    let capacity = usize::try_from(metadata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "envelope length overflow"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::take(&mut file, MAX_ENVELOPE_LEN + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ENVELOPE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "envelope grew beyond the allocation limit while reading",
        ));
    }
    Ok(bytes)
}

pub fn write_json_atomically<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "result path has no file name")
    })?;
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "result path already exists",
        ));
    }

    let encoded = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "result length overflow"))?;
    if encoded_len.saturating_add(1) > MAX_RESULT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encoded result length {} exceeds {MAX_RESULT_LEN}-byte limit",
                encoded_len.saturating_add(1)
            ),
        ));
    }

    let mut reserved = None;
    for attempt in 0..32_u32 {
        let name = format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            attempt
        );
        let candidate = parent.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                reserved = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temporary, mut file) = reserved.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve an atomic result temporary file",
        )
    })?;

    let write_result = (|| {
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    let publish = fs::hard_link(&temporary, path);
    let cleanup = fs::remove_file(&temporary);
    publish?;
    cleanup?;
    if let Ok(directory) = File::open(parent) {
        directory.sync_all()?;
    }
    Ok(())
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

pub fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EnvelopeError> {
    let raw = bytes
        .get(offset..offset.checked_add(2).ok_or(EnvelopeError::LengthOverflow)?)
        .ok_or(EnvelopeError::LengthOverflow)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EnvelopeError> {
    let raw = bytes
        .get(offset..offset.checked_add(4).ok_or(EnvelopeError::LengthOverflow)?)
        .ok_or(EnvelopeError::LengthOverflow)?;
    Ok(u32::from_le_bytes(
        raw.try_into().expect("four-byte subslice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EnvelopeError> {
    let raw = bytes
        .get(offset..offset.checked_add(8).ok_or(EnvelopeError::LengthOverflow)?)
        .ok_or(EnvelopeError::LengthOverflow)?;
    Ok(u64::from_le_bytes(
        raw.try_into().expect("eight-byte subslice"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(sections: &[(SectionKind, u16, u32, &[u8])]) -> Vec<u8> {
        let total_len = usize::from(HEADER_LEN)
            + sections
                .iter()
                .map(|(_, _, _, payload)| SECTION_HEADER_LEN + payload.len())
                .sum::<usize>();
        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&HEADER_LEN.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(sections.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(total_len as u64).to_le_bytes());
        for (kind, flags, reserved, payload) in sections {
            bytes.extend_from_slice(&(*kind as u16).to_le_bytes());
            bytes.extend_from_slice(&flags.to_le_bytes());
            bytes.extend_from_slice(&reserved.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&sha256(payload));
            bytes.extend_from_slice(payload);
        }
        bytes
    }

    fn canonical() -> Vec<u8> {
        encode(&[
            (
                SectionKind::Protocol,
                SECTION_FLAG_MANDATORY,
                0,
                b"protocol",
            ),
            (
                SectionKind::Statement,
                SECTION_FLAG_MANDATORY,
                0,
                b"statement",
            ),
            (SectionKind::Proof, SECTION_FLAG_MANDATORY, 0, b"proof"),
            (
                SectionKind::Provenance,
                SECTION_FLAG_MANDATORY,
                0,
                b"provenance",
            ),
        ])
    }

    fn json_bridge(proof: &[u8], n_queries: u32, statement_proof_digest: [u8; 32]) -> Vec<u8> {
        let protocol = serde_json::to_vec(&JsonProofProtocol {
            schema_version: JSON_PROOF_PROTOCOL_SCHEMA_VERSION,
            proof_encoding: RUST_VERIFIER_JSON_PROOF_ENCODING.to_owned(),
            channel: "blake2s".to_owned(),
            preprocessed_trace_variant: "canonical".to_owned(),
            channel_salt: 0,
            pow_bits: 26,
            log_blowup_factor: 1,
            n_queries,
            log_last_layer_degree_bound: 0,
            fold_step: 3,
            lifting_log_size: None,
            interaction_pow_bits: 24,
            stwo_cairo_revision: STWO_CAIRO_REVISION.to_owned(),
            stwo_revision: STWO_REVISION.to_owned(),
        })
        .unwrap();
        let statement = serde_json::to_vec(&EmbeddedStatementBinding {
            schema_version: JSON_PROOF_PROTOCOL_SCHEMA_VERSION,
            encoding: EMBEDDED_STATEMENT_ENCODING.to_owned(),
            proof_sha256: hex_digest(statement_proof_digest),
        })
        .unwrap();
        let provenance = serde_json::to_vec(&JsonBridgeProvenance {
            schema_version: JSON_PROOF_PROTOCOL_SCHEMA_VERSION,
            source: JSON_BRIDGE_PROVENANCE_SOURCE.to_owned(),
            protocol_sha256: hex_digest(sha256(&protocol)),
            statement_sha256: hex_digest(sha256(&statement)),
            proof_sha256: hex_digest(sha256(proof)),
        })
        .unwrap();
        encode(&[
            (SectionKind::Protocol, SECTION_FLAG_MANDATORY, 0, &protocol),
            (
                SectionKind::Statement,
                SECTION_FLAG_MANDATORY,
                0,
                &statement,
            ),
            (SectionKind::Proof, SECTION_FLAG_MANDATORY, 0, proof),
            (
                SectionKind::Provenance,
                SECTION_FLAG_MANDATORY,
                0,
                &provenance,
            ),
        ])
    }

    #[test]
    fn parses_and_authenticates_canonical_envelope() {
        let bytes = canonical();
        let envelope = Envelope::parse(&bytes).unwrap();
        assert_eq!(envelope.section(SectionKind::Proof).payload, b"proof");
        assert_eq!(envelope.sections().len(), 4);
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        let mut bytes = canonical();
        bytes[0] ^= 1;
        assert_eq!(Envelope::parse(&bytes), Err(EnvelopeError::BadMagic));

        let mut bytes = canonical();
        bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn rejects_noncanonical_header_and_reserved_fields() {
        let mut bytes = canonical();
        bytes[10..12].copy_from_slice(&31_u16.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::NoncanonicalHeaderLength(31))
        );

        let mut bytes = canonical();
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::NonzeroHeaderReserved(1))
        );
    }

    #[test]
    fn rejects_unknown_header_flags() {
        let mut bytes = canonical();
        bytes[12..16].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::UnknownHeaderFlags(1))
        );
    }

    #[test]
    fn rejects_wrong_section_count() {
        let mut bytes = canonical();
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::InvalidSectionCount(3))
        );
    }

    #[test]
    fn rejects_declared_length_mismatch_and_trailing_bytes() {
        let mut bytes = canonical();
        let short = bytes.len() as u64 - 1;
        bytes[24..32].copy_from_slice(&short.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::EnvelopeLengthMismatch {
                declared: short,
                actual: bytes.len() as u64,
            })
        );

        let mut bytes = canonical();
        bytes.push(0);
        let new_len = bytes.len() as u64;
        bytes[24..32].copy_from_slice(&new_len.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::TrailingBytes(1))
        );
    }

    #[test]
    fn rejects_noncanonical_section_order() {
        let bytes = encode(&[
            (
                SectionKind::Statement,
                SECTION_FLAG_MANDATORY,
                0,
                b"statement",
            ),
            (
                SectionKind::Protocol,
                SECTION_FLAG_MANDATORY,
                0,
                b"protocol",
            ),
            (SectionKind::Proof, SECTION_FLAG_MANDATORY, 0, b"proof"),
            (
                SectionKind::Provenance,
                SECTION_FLAG_MANDATORY,
                0,
                b"provenance",
            ),
        ]);
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::NoncanonicalSectionOrder {
                expected: SectionKind::Protocol,
                actual: SectionKind::Statement,
            })
        );
    }

    #[test]
    fn rejects_duplicate_section() {
        let bytes = encode(&[
            (
                SectionKind::Protocol,
                SECTION_FLAG_MANDATORY,
                0,
                b"protocol",
            ),
            (
                SectionKind::Protocol,
                SECTION_FLAG_MANDATORY,
                0,
                b"duplicate",
            ),
            (SectionKind::Proof, SECTION_FLAG_MANDATORY, 0, b"proof"),
            (
                SectionKind::Provenance,
                SECTION_FLAG_MANDATORY,
                0,
                b"provenance",
            ),
        ]);
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::DuplicateSection(SectionKind::Protocol))
        );
    }

    #[test]
    fn rejects_unknown_section_and_flags() {
        let mut bytes = canonical();
        bytes[32..34].copy_from_slice(&5_u16.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::UnknownSection(5))
        );

        let mut bytes = canonical();
        bytes[34..36].copy_from_slice(&3_u16.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::UnknownSectionFlags {
                kind: SectionKind::Protocol,
                flags: 3,
            })
        );
    }

    #[test]
    fn rejects_nonzero_section_reserved_field() {
        let mut bytes = canonical();
        bytes[36..40].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::NonzeroSectionReserved {
                kind: SectionKind::Protocol,
                value: 7,
            })
        );
    }

    #[test]
    fn rejects_empty_and_oversized_sections_before_payload_access() {
        let bytes = encode(&[
            (SectionKind::Protocol, SECTION_FLAG_MANDATORY, 0, b""),
            (
                SectionKind::Statement,
                SECTION_FLAG_MANDATORY,
                0,
                b"statement",
            ),
            (SectionKind::Proof, SECTION_FLAG_MANDATORY, 0, b"proof"),
            (
                SectionKind::Provenance,
                SECTION_FLAG_MANDATORY,
                0,
                b"provenance",
            ),
        ]);
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::EmptySection(SectionKind::Protocol))
        );

        let mut bytes = canonical();
        let claimed = SectionKind::Protocol.max_payload_len() + 1;
        bytes[40..48].copy_from_slice(&claimed.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::SectionTooLarge {
                kind: SectionKind::Protocol,
                length: claimed,
                maximum: SectionKind::Protocol.max_payload_len(),
            })
        );
    }

    #[test]
    fn rejects_truncated_section_header_and_payload() {
        let mut bytes = canonical();
        bytes.truncate(40);
        let len = bytes.len() as u64;
        bytes[24..32].copy_from_slice(&len.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::TruncatedSectionHeader(SectionKind::Protocol))
        );

        let mut bytes = canonical();
        bytes.truncate(82);
        let len = bytes.len() as u64;
        bytes[24..32].copy_from_slice(&len.to_le_bytes());
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::TruncatedSectionPayload(
                SectionKind::Protocol
            ))
        );
    }

    #[test]
    fn rejects_payload_digest_mismatch() {
        let mut bytes = canonical();
        bytes[usize::from(HEADER_LEN) + SECTION_HEADER_LEN] ^= 1;
        assert_eq!(
            Envelope::parse(&bytes),
            Err(EnvelopeError::DigestMismatch(SectionKind::Protocol))
        );
    }

    #[test]
    fn identity_reports_json_and_compact_verification_capabilities() {
        let identity = adapter_identity(None).unwrap();
        assert_eq!(identity.envelope_abi, "STWZCVE/1");
        assert_eq!(identity.stwo_cairo.revision, STWO_CAIRO_REVISION);
        assert_eq!(identity.stwo.revision, STWO_REVISION);
        assert_eq!(identity.cargo_lock_sha256.len(), 64);
        assert!(identity.proof_reconstruction_implemented);
        assert!(identity.canonical_verification_implemented);
        assert!(identity.json_proof_verification_implemented);
        assert!(identity.compact_claim_reconstruction_implemented);
        assert!(identity.compact_stark_proof_reconstruction_implemented);
        assert!(identity.compact_proof_reconstruction_implemented);
        assert!(identity.compact_proof_verification_implemented);
    }

    #[test]
    fn compact_provenance_rejects_unbound_external_identities_before_decoding() {
        let protocol = crate::compact_codec::CompactProtocolV1::decode(
            &crate::compact_codec::tests_support::protocol_bytes_for_lib_tests(),
        );
        assert!(protocol.is_ok());
        let protocol = crate::compact_codec::tests_support::protocol_bytes_for_lib_tests();
        let statement = b"statement";
        let proof = b"proof";
        let provenance = serde_json::to_vec(&CompactProofProvenance {
            schema_version: 1,
            source: COMPACT_PROOF_PROVENANCE_SOURCE.to_owned(),
            proof_serialization: COMPACT_PROOF_SERIALIZATION.to_owned(),
            protocol_sha256: hex_digest(sha256(&protocol)),
            statement_sha256: hex_digest(sha256(statement)),
            proof_sha256: hex_digest(sha256(proof)),
            adapted_input_sha256: "A".repeat(64),
            artifact_manifest_sha256: "0".repeat(64),
            runner_executable_sha256: "0".repeat(64),
            backend_executable_sha256: "0".repeat(64),
        })
        .unwrap();
        let bytes = encode(&[
            (SectionKind::Protocol, SECTION_FLAG_MANDATORY, 0, &protocol),
            (SectionKind::Statement, SECTION_FLAG_MANDATORY, 0, statement),
            (SectionKind::Proof, SECTION_FLAG_MANDATORY, 0, proof),
            (
                SectionKind::Provenance,
                SECTION_FLAG_MANDATORY,
                0,
                &provenance,
            ),
        ]);
        let envelope = Envelope::parse(&bytes).unwrap();
        assert_eq!(verification_mode(&envelope), "compact_metal_proof_v1");
        let failure = verify_compact_proof_envelope(&envelope).unwrap_err();
        assert_eq!(failure.code, "invalid_provenance_binding");
    }

    #[test]
    fn json_bridge_authenticates_metadata_before_decoding_proof() {
        let proof = b"{}";
        let bytes = json_bridge(proof, 70, sha256(proof));
        let envelope = Envelope::parse(&bytes).unwrap();
        let failure = verify_json_proof_envelope(&envelope).unwrap_err();
        assert_eq!(failure.code, "invalid_proof_json");
    }

    #[test]
    fn json_bridge_rejects_protocol_and_statement_drift() {
        let proof = b"{}";
        let bytes = json_bridge(proof, 69, sha256(proof));
        let envelope = Envelope::parse(&bytes).unwrap();
        let failure = verify_json_proof_envelope(&envelope).unwrap_err();
        assert_eq!(failure.code, "invalid_protocol");

        let bytes = json_bridge(proof, 70, sha256(b"different proof"));
        let envelope = Envelope::parse(&bytes).unwrap();
        let failure = verify_json_proof_envelope(&envelope).unwrap_err();
        assert_eq!(failure.code, "invalid_statement_binding");
    }

    #[test]
    fn verifier_configuration_is_bounded_and_uses_direct_argv() {
        let config = verifier_config();
        assert_eq!(config.envelope_abi, "STWZCVE/1");
        assert_eq!(config.argv_template[0], "verify");
        assert_eq!(config.argv_template.len(), 5);
        assert_eq!(config.max_envelope_bytes, MAX_ENVELOPE_LEN);
        assert_eq!(
            config.section_limits.proof_bytes,
            SectionKind::Proof.max_payload_len()
        );
        assert!(config.max_result_bytes < config.max_envelope_bytes);
        assert_eq!(config.stwo_cairo.revision, STWO_CAIRO_REVISION);
        assert_eq!(config.stwo.revision, STWO_REVISION);
    }

    #[test]
    fn atomic_json_publication_refuses_replacement() {
        let directory = std::env::temp_dir().join(format!(
            "stwo-cairo-verifier-adapter-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let result = directory.join("result.json");
        write_json_atomically(&result, &serde_json::json!({"ok": false})).unwrap();
        assert_eq!(fs::read_to_string(&result).unwrap(), "{\"ok\":false}\n");
        assert_eq!(
            write_json_atomically(&result, &serde_json::json!({"ok": true}))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_json_publication_enforces_result_limit_without_creating_output() {
        let directory = std::env::temp_dir().join(format!(
            "stwo-cairo-verifier-adapter-limit-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let result = directory.join("result.json");
        let oversized = "x".repeat(MAX_RESULT_LEN as usize);

        assert_eq!(
            write_json_atomically(&result, &oversized)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!result.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);

        fs::remove_dir_all(directory).unwrap();
    }
}
