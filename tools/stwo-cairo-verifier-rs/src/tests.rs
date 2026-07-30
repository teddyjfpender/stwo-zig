use super::*;
use std::fs;
use std::io;

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
