use super::protocol::PREPROCESSED_CANONICAL_WITHOUT_PEDERSEN;
use super::*;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn protocol(active: u32, sampled: u32, decommit: u32) -> Vec<u8> {
    let mut bytes = vec![0_u8; PROTOCOL_HEADER_LEN as usize];
    bytes[..8].copy_from_slice(&PROTOCOL_MAGIC);
    put_u16(&mut bytes, 8, CODEC_VERSION);
    put_u16(&mut bytes, 10, PROTOCOL_HEADER_LEN);
    for (offset, value) in [
        (16, 1),
        (20, 1),
        (24, 1),
        (32, 26),
        (36, 1),
        (40, 70),
        (48, 3),
        (52, u32::MAX),
        (56, 24),
        (60, 4),
        (64, 4),
        (68, 8),
        (72, 1),
        (76, 12),
        (80, active),
        (84, sampled),
        (88, decommit),
        (92, 161),
        (96, 3449),
        (100, 2268),
        (104, 8),
    ] {
        put_u32(&mut bytes, offset, value);
    }
    bytes
}

fn real_fib_tag_two_protocol() -> Vec<u8> {
    let mut bytes = protocol(30, 3564, 2_077_800);
    put_u32(&mut bytes, 24, PREPROCESSED_CANONICAL_WITHOUT_PEDERSEN);
    put_u32(&mut bytes, 68, 7);
    put_u32(&mut bytes, 76, 11);
    for (offset, columns) in [(92, 105), (96, 396), (100, 324), (104, 8)] {
        put_u32(&mut bytes, offset, columns);
    }
    put_u32(&mut bytes, 108, 20);
    bytes
}

fn statement(active: usize) -> Vec<u8> {
    let len = STATEMENT_HEADER_LEN as usize
        + PUBLIC_SEGMENT_COUNT * 5 * 4
        + COMPONENT_ENABLE_COUNT * 4
        + active * 4;
    let mut bytes = vec![0_u8; len];
    bytes[..8].copy_from_slice(&STATEMENT_MAGIC);
    put_u16(&mut bytes, 8, CODEC_VERSION);
    put_u16(&mut bytes, 10, STATEMENT_HEADER_LEN);
    put_u32(&mut bytes, 56, COMPONENT_ENABLE_COUNT as u32);
    put_u32(&mut bytes, 60, active as u32);
    put_u32(&mut bytes, 64, PUBLIC_SEGMENT_COUNT as u32);
    put_u32(&mut bytes, 68, MEMORY_ENTRY_WORDS as u32);
    let segments = STATEMENT_HEADER_LEN as usize;
    put_u32(&mut bytes, segments, 1);
    let enable = segments + PUBLIC_SEGMENT_COUNT * 5 * 4;
    for index in 0..active {
        put_u32(&mut bytes, enable + index * 4, 1);
    }
    let logs = enable + COMPONENT_ENABLE_COUNT * 4;
    for index in 0..active {
        put_u32(&mut bytes, logs + index * 4, 4);
    }
    bytes
}

fn proof(protocol: &CompactProtocolV1) -> Vec<u8> {
    let words = protocol.proof_word_count().unwrap();
    let mut bytes = vec![0_u8; words * 4];
    let decommit = words - protocol.decommitment_capacity_words as usize;
    let set = |bytes: &mut [u8], index: usize, value: u32| put_u32(bytes, index * 4, value);
    set(&mut bytes, decommit, DECOMMIT_MAGIC);
    set(&mut bytes, decommit + 1, DECOMMIT_VERSION);
    set(&mut bytes, decommit + 2, protocol.decommitment_record_count);
    set(&mut bytes, decommit + 3, protocol.query_count);
    set(&mut bytes, decommit + 4, protocol.query_count);
    set(&mut bytes, decommit + 5, 200);
    set(&mut bytes, decommit + 6, 200 + protocol.query_count);
    set(
        &mut bytes,
        decommit + 7,
        protocol.decommitment_capacity_words,
    );
    for index in 0..protocol.decommitment_record_count as usize {
        let base = decommit + 8 + index * 16;
        set(
            &mut bytes,
            base,
            u32::from(index >= protocol.commitment_count as usize),
        );
        set(&mut bytes, base + 1, index as u32);
        set(&mut bytes, base + 2, 200);
        set(&mut bytes, base + 3, 1);
        if index < protocol.commitment_count as usize {
            set(
                &mut bytes,
                base + 5,
                protocol.trace_tree_column_counts[index],
            );
        }
        set(
            &mut bytes,
            base + 14,
            protocol.decommitment_record_count - index as u32,
        );
        set(&mut bytes, base + 15, 1);
    }
    bytes
}

fn structurally_decodable_proof(protocol: &CompactProtocolV1) -> Vec<u8> {
    let mut bytes = proof(protocol);
    let offsets = compact_proof_offsets(protocol);
    let decommit = offsets.decommitment_start;
    let set = |bytes: &mut [u8], index: usize, value: u32| put_u32(bytes, index * 4, value);
    for index in 0..protocol.decommitment_capacity_words as usize {
        set(&mut bytes, decommit + index, 0);
    }
    set(&mut bytes, decommit, DECOMMIT_MAGIC);
    set(&mut bytes, decommit + 1, DECOMMIT_VERSION);
    set(&mut bytes, decommit + 2, protocol.decommitment_record_count);
    set(&mut bytes, decommit + 3, protocol.query_count);
    set(&mut bytes, decommit + 4, 1);
    set(&mut bytes, decommit + 5, 200);
    set(&mut bytes, decommit + 6, 201);
    set(&mut bytes, decommit + 200, 7);
    set(&mut bytes, decommit + 201, 7);
    let mut cursor = 202_usize;
    for index in 0..protocol.decommitment_record_count as usize {
        let base = decommit + DECOMMIT_HEADER_WORDS + index * DECOMMIT_TREE_META_WORDS;
        let tree_start = cursor;
        set(
            &mut bytes,
            base,
            u32::from(index >= protocol.commitment_count as usize),
        );
        set(&mut bytes, base + 1, index as u32);
        set(&mut bytes, base + 2, 201);
        set(&mut bytes, base + 3, 1);
        if index < protocol.commitment_count as usize {
            let count = protocol.trace_tree_column_counts[index] as usize;
            set(&mut bytes, base + 4, cursor as u32);
            set(&mut bytes, base + 5, count as u32);
            cursor += count;
        }
        set(
            &mut bytes,
            base + 14,
            protocol.decommitment_record_count - index as u32,
        );
        set(&mut bytes, base + 15, (cursor - tree_start).max(1) as u32);
    }
    let used = cursor.max(200 + protocol.query_count as usize);
    set(&mut bytes, decommit + 7, used as u32);
    set(&mut bytes, offsets.query_pow_start, 0x7654_3210);
    set(&mut bytes, offsets.query_pow_start + 1, 0xfedc_ba98);
    bytes
}

fn composition_only_sample_shape(protocol: &CompactProtocolV1) -> Vec<Vec<usize>> {
    vec![
        vec![0; protocol.trace_tree_column_counts[0] as usize],
        vec![0; protocol.trace_tree_column_counts[1] as usize],
        vec![0; protocol.trace_tree_column_counts[2] as usize],
        vec![1; protocol.trace_tree_column_counts[3] as usize],
    ]
}

fn fib_like_protocol() -> CompactProtocolV1 {
    let mut protocol = CompactProtocolV1::sn2_for_preprocessed_trace(
        PreProcessedTraceVariant::CanonicalWithoutPedersen,
        9,
        2,
        32,
        400,
        [105, 7, 3, 8],
    );
    protocol.max_log_degree_bound = 20;
    protocol.fri_tree_count = 7;
    protocol.decommitment_record_count = 11;
    protocol.validate_geometry().unwrap();
    protocol
}

#[test]
fn decodes_typed_statement_and_validates_compact_proof_geometry() {
    let protocol_bytes = protocol(2, 4, 4000);
    let statement_bytes = statement(2);
    let protocol = CompactProtocolV1::decode(&protocol_bytes).unwrap();
    let validated =
        validate_compact_sections_v1(&protocol_bytes, &statement_bytes, &proof(&protocol)).unwrap();
    assert_eq!(validated.statement.component_log_sizes, [4, 4]);
    assert_eq!(
        validated.statement.public_data.initial_state,
        CasmState::default()
    );
    assert_eq!(validated.proof_geometry.interaction_claim_words, 8);
    assert_eq!(validated.proof_geometry.decommitment_used_words, 4000);
    assert_eq!(validated.proof_geometry.raw_query_count, 70);
    assert_eq!(
        validated.protocol.preprocessed_trace_variant,
        PreProcessedTraceVariant::Canonical
    );
    assert_eq!(validated.protocol.encode().unwrap(), protocol_bytes);
    assert_eq!(validated.statement.encode().unwrap(), statement_bytes);
}

#[test]
fn preprocessed_trace_variants_have_stable_tags_and_exact_tree_widths() {
    for (variant, wire_tag, preprocessed_columns) in [
        (PreProcessedTraceVariant::Canonical, 1, 161),
        (PreProcessedTraceVariant::CanonicalWithoutPedersen, 2, 105),
        (PreProcessedTraceVariant::CanonicalSmall, 3, 156),
    ] {
        let protocol = CompactProtocolV1::sn2_for_preprocessed_trace(
            variant,
            9,
            2,
            4,
            4000,
            [preprocessed_columns, 3449, 2268, 8],
        );
        let encoded = protocol.encode().unwrap();
        assert_eq!(
            read_u32(&encoded, 24, "preprocessed variant").unwrap(),
            wire_tag
        );
        assert_eq!(
            read_u32(&encoded, 92, "trace-tree-0 columns").unwrap(),
            preprocessed_columns
        );
        assert_eq!(CompactProtocolV1::decode(&encoded).unwrap(), protocol);
    }
}

#[test]
fn decodes_real_fib_tag_two_protocol_geometry() {
    use sha2::{Digest, Sha256};

    let bytes = real_fib_tag_two_protocol();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "52921cfab4fde413abc484a6c39d363b88dd729c19acef620670af60c6da9286"
    );
    let protocol = CompactProtocolV1::decode(&bytes).unwrap();
    assert_eq!(
        protocol.preprocessed_trace_variant,
        PreProcessedTraceVariant::CanonicalWithoutPedersen
    );
    assert_eq!(protocol.trace_tree_column_counts, [105, 396, 324, 8]);
    assert_eq!(protocol.interaction_sum_count, 30);
    assert_eq!(protocol.sampled_value_words, 3564);
    assert_eq!(protocol.decommitment_capacity_words, 2_077_800);
    assert_eq!(protocol.max_log_degree_bound, 20);
    assert_eq!(protocol.encode().unwrap(), bytes);
}

#[test]
fn preprocessed_trace_variants_reject_unknown_and_mismatched_geometry() {
    let canonical = protocol(2, 4, 4000);
    for unknown_tag in [0, 4, u32::MAX] {
        let mut bytes = canonical.clone();
        put_u32(&mut bytes, 24, unknown_tag);
        let error = CompactProtocolV1::decode(&bytes).unwrap_err();
        assert_eq!(error.code, "invalid_compact_protocol");
        assert!(error
            .message
            .contains("unknown preprocessed trace variant tag"));
    }

    for (wire_tag, wrong_columns) in [(1, 105), (2, 156), (3, 161)] {
        let mut bytes = canonical.clone();
        put_u32(&mut bytes, 24, wire_tag);
        put_u32(&mut bytes, 92, wrong_columns);
        let error = CompactProtocolV1::decode(&bytes).unwrap_err();
        assert_eq!(error.code, "invalid_compact_protocol");
        assert!(error.message.contains("trace-tree-0 columns"));
    }

    let mismatched = CompactProtocolV1::sn2_for_preprocessed_trace(
        PreProcessedTraceVariant::CanonicalSmall,
        9,
        2,
        4,
        4000,
        EXPECTED_TRACE_COLUMNS,
    );
    assert!(mismatched.encode().is_err());
}

#[test]
fn reconstructs_pinned_cairo_claim_types_from_compact_words() {
    let protocol = CompactProtocolV1::decode(&protocol(2, 4, 4000)).unwrap();
    let statement = CompactStatementV1::decode(&statement(2)).unwrap();
    let mut proof = proof(&protocol);
    let interaction_start = 4 * HASH_WORDS;
    for (index, value) in (1_u32..=8).enumerate() {
        put_u32(&mut proof, (interaction_start + index) * 4, value);
    }
    put_u32(&mut proof, (interaction_start + 8) * 4, 0x89ab_cdef);
    put_u32(&mut proof, (interaction_start + 9) * 4, 0x0123_4567);

    let reconstructed = reconstruct_claims_v1(&proof, &protocol, &statement).unwrap();
    let flat_claim = reconstructed.cairo_claim.flatten_claim();
    assert_eq!(
        flat_claim.component_enable_bits,
        statement.component_enable_bits
    );
    assert_eq!(
        flat_claim.component_log_sizes,
        statement.component_log_sizes
    );
    assert_eq!(
        reconstructed.interaction_claim.flatten_interaction_claim(),
        [
            QM31::from_u32_unchecked(1, 2, 3, 4),
            QM31::from_u32_unchecked(5, 6, 7, 8),
        ]
    );
    assert_eq!(reconstructed.interaction_pow, 0x0123_4567_89ab_cdef);
}

#[test]
fn reconstructs_memory_big_prefix_and_aggregate_claim() {
    let mut statement_bytes = statement(1);
    let enable = STATEMENT_HEADER_LEN as usize + PUBLIC_SEGMENT_COUNT * 5 * 4;
    put_u32(&mut statement_bytes, enable, 0);
    put_u32(&mut statement_bytes, enable + MEMORY_BIG_START * 4, 1);
    let protocol = CompactProtocolV1::decode(&protocol(1, 4, 4000)).unwrap();
    let statement = CompactStatementV1::decode(&statement_bytes).unwrap();
    let mut proof = proof(&protocol);
    for (index, value) in [9_u32, 10, 11, 12].into_iter().enumerate() {
        put_u32(&mut proof, (4 * HASH_WORDS + index) * 4, value);
    }

    let reconstructed = reconstruct_claims_v1(&proof, &protocol, &statement).unwrap();
    let flat_claim = reconstructed.cairo_claim.flatten_claim();
    assert_eq!(
        flat_claim.component_enable_bits,
        statement.component_enable_bits
    );
    assert_eq!(
        flat_claim.component_log_sizes,
        statement.component_log_sizes
    );
    let sum = QM31::from_u32_unchecked(9, 10, 11, 12);
    assert_eq!(
        reconstructed.interaction_claim.flatten_interaction_claim(),
        [sum]
    );
    assert_eq!(
        reconstructed
            .interaction_claim
            .memory_id_to_big
            .unwrap()
            .claimed_sum,
        sum
    );
}

#[test]
fn reconstructs_all_83_flattened_component_slots() {
    let mut statement_bytes = statement(COMPONENT_ENABLE_COUNT);
    let enable = STATEMENT_HEADER_LEN as usize + PUBLIC_SEGMENT_COUNT * 5 * 4;
    let logs = enable + COMPONENT_ENABLE_COUNT * 4;
    for field_index in 0..CLAIM_FIELD_NAMES.len() {
        if let Some(log_size) = fixed_log_size(field_index) {
            put_u32(
                &mut statement_bytes,
                logs + claim_field_first_slot(field_index) * 4,
                log_size,
            );
        }
    }
    let protocol =
        CompactProtocolV1::decode(&protocol(COMPONENT_ENABLE_COUNT as u32, 4, 4000)).unwrap();
    let statement = CompactStatementV1::decode(&statement_bytes).unwrap();
    let proof = proof(&protocol);
    let reconstructed = reconstruct_claims_v1(&proof, &protocol, &statement).unwrap();

    let flat_claim = reconstructed.cairo_claim.flatten_claim();
    assert_eq!(
        flat_claim.component_enable_bits,
        statement.component_enable_bits
    );
    assert_eq!(
        flat_claim.component_log_sizes,
        statement.component_log_sizes
    );
    assert_eq!(
        reconstructed
            .interaction_claim
            .flatten_interaction_claim()
            .len(),
        COMPONENT_ENABLE_COUNT
    );
    assert_eq!(
        reconstructed
            .interaction_claim
            .memory_id_to_big
            .unwrap()
            .big_claimed_sums
            .len(),
        MEMORY_BIG_COUNT
    );
}

#[test]
fn reconstructs_pinned_stark_proof_structure() {
    let protocol = CompactProtocolV1::decode(&protocol(2, 32, 8000)).unwrap();
    let statement = CompactStatementV1::decode(&statement(2)).unwrap();
    let proof = structurally_decodable_proof(&protocol);
    let stark = reconstruct_stark_proof_v1(
        &proof,
        &protocol,
        &statement,
        &composition_only_sample_shape(&protocol),
    )
    .unwrap();

    assert_eq!(stark.0.commitments.len(), 4);
    assert_eq!(stark.0.sampled_values.len(), 4);
    assert_eq!(stark.0.sampled_values[3].len(), 8);
    assert!(stark.0.sampled_values[3]
        .iter()
        .all(|column| column.len() == 1));
    assert_eq!(stark.0.decommitments.len(), 4);
    assert_eq!(stark.0.queried_values[0].len(), 161);
    assert_eq!(stark.0.queried_values[1].len(), 3449);
    assert_eq!(stark.0.queried_values[2].len(), 2268);
    assert_eq!(stark.0.queried_values[3].len(), 8);
    assert_eq!(stark.0.fri_proof.inner_layers.len(), 7);
    assert_eq!(stark.0.fri_proof.last_layer_poly.len(), 1);
    assert_eq!(stark.0.proof_of_work, 0xfedc_ba98_7654_3210);
}

#[test]
fn reconstructs_fib_like_four_plus_seven_geometry() {
    use sha2::{Digest, Sha256};

    let protocol = fib_like_protocol();
    let encoded = protocol.encode().unwrap();
    let encoded_hex = encoded
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        encoded_hex,
        "5354575a43503100010070000000000001000000010000000200000009000000\
             1a00000001000000460000000000000003000000ffffffff1800000004000000\
             0400000007000000010000000b00000002000000200000009001000069000000\
             07000000030000000800000014000000"
            .replace(' ', "")
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(&encoded)),
        "4dae06a01beaa037e0c051ad6d83eff2f2c28fa259e44fef8cdecdc5101cc334"
    );
    assert_eq!(read_u32(&encoded, 68, "FRI trees").unwrap(), 7);
    assert_eq!(read_u32(&encoded, 76, "decommit records").unwrap(), 11);
    assert_eq!(read_u32(&encoded, 108, "maximum degree").unwrap(), 20);
    let decoded = CompactProtocolV1::decode(&encoded).unwrap();
    assert_eq!(decoded, protocol);

    let statement = CompactStatementV1::decode(&statement(2)).unwrap();
    let proof = structurally_decodable_proof(&decoded);
    validate_compact_proof_v1(&proof, &decoded, &statement).unwrap();
    let stark = reconstruct_stark_proof_v1(
        &proof,
        &decoded,
        &statement,
        &composition_only_sample_shape(&decoded),
    )
    .unwrap();
    assert_eq!(stark.0.commitments.len(), 4);
    assert_eq!(stark.0.fri_proof.inner_layers.len(), 6);
    assert_eq!(stark.0.queried_values[0].len(), 105);
    assert_eq!(stark.0.queried_values[1].len(), 7);
    assert_eq!(stark.0.queried_values[2].len(), 3);
    assert_eq!(stark.0.queried_values[3].len(), 8);
}

#[test]
fn stark_reconstruction_rejects_shape_and_decommitment_field_drift() {
    let protocol = CompactProtocolV1::decode(&protocol(2, 32, 8000)).unwrap();
    let statement = CompactStatementV1::decode(&statement(2)).unwrap();
    let mut proof = structurally_decodable_proof(&protocol);
    let mut shape = composition_only_sample_shape(&protocol);
    shape[3][0] = 0;
    assert!(reconstruct_stark_proof_v1(&proof, &protocol, &statement, &shape).is_err());

    let decommit = compact_proof_offsets(&protocol).decommitment_start;
    put_u32(&mut proof, (decommit + 202) * 4, M31_PRIME);
    assert!(reconstruct_stark_proof_v1(
        &proof,
        &protocol,
        &statement,
        &composition_only_sample_shape(&protocol)
    )
    .is_err());
}

#[test]
fn claim_reconstruction_rejects_fixed_log_size_drift() {
    let mut statement_bytes = statement(1);
    let enable = STATEMENT_HEADER_LEN as usize + PUBLIC_SEGMENT_COUNT * 5 * 4;
    put_u32(&mut statement_bytes, enable, 0);
    put_u32(&mut statement_bytes, enable + 23 * 4, 1);
    let protocol = CompactProtocolV1::decode(&protocol(1, 4, 4000)).unwrap();
    let statement = CompactStatementV1::decode(&statement_bytes).unwrap();
    let proof = proof(&protocol);
    assert!(reconstruct_claims_v1(&proof, &protocol, &statement).is_ok());

    let logs = enable + COMPONENT_ENABLE_COUNT * 4;
    put_u32(&mut statement_bytes, logs, 5);
    let statement = CompactStatementV1::decode(&statement_bytes).unwrap();
    assert!(reconstruct_claims_v1(&proof, &protocol, &statement).is_err());
}

#[test]
fn decodes_nonempty_program_output_and_segment_data() {
    let mut bytes = statement(1);
    put_u32(&mut bytes, 16, 1);
    put_u32(&mut bytes, 20, 2);
    put_u32(&mut bytes, 24, 3);
    put_u32(&mut bytes, 40, 5);
    put_u32(&mut bytes, 44, 6);
    put_u32(&mut bytes, 48, 1);
    put_u32(&mut bytes, 52, 1);
    let memory_start = STATEMENT_HEADER_LEN as usize + PUBLIC_SEGMENT_COUNT * 5 * 4;
    bytes.splice(
        memory_start..memory_start,
        [0_u8; 2 * MEMORY_ENTRY_WORDS * 4],
    );
    put_u32(&mut bytes, memory_start, 7);
    put_u32(&mut bytes, memory_start + 4, 0xfeed_beef);
    let output_start = memory_start + MEMORY_ENTRY_WORDS * 4;
    put_u32(&mut bytes, output_start, 8);
    put_u32(&mut bytes, output_start + 4, 0xdead_beef);

    let decoded = CompactStatementV1::decode(&bytes).unwrap();
    assert_eq!(decoded.public_data.initial_state.pc.0, 1);
    assert_eq!(decoded.public_data.public_memory.safe_call_ids, [5, 6]);
    assert_eq!(decoded.public_data.public_memory.program[0].0, 7);
    assert_eq!(
        decoded.public_data.public_memory.program[0].1[0],
        0xfeed_beef
    );
    assert_eq!(decoded.public_data.public_memory.output[0].0, 8);
    assert_eq!(
        decoded.public_data.public_memory.output[0].1[0],
        0xdead_beef
    );
}

#[test]
fn protocol_mutations_fail_closed() {
    for (offset, value) in [
        (0, 1),
        (8, 2),
        (12, 1),
        (40, 0),
        (68, 7),
        (76, 11),
        (92, 0),
        (108, 1),
    ] {
        let mut bytes = protocol(2, 4, 4000);
        put_u32(&mut bytes, offset, value);
        assert!(
            CompactProtocolV1::decode(&bytes).is_err(),
            "offset {offset}"
        );
    }
    let mut bytes = protocol(2, 3, 4000);
    assert!(CompactProtocolV1::decode(&bytes).is_err());
    bytes.pop();
    assert!(CompactProtocolV1::decode(&bytes).is_err());
}

#[test]
fn recorded_sn_pie_layout_counts_reconcile_exactly() {
    let sn2 = CompactProtocolV1::decode(&protocol(58, 24_440, 2_077_800)).unwrap();
    assert_eq!(sn2.proof_word_count().unwrap(), 2_102_576);
    assert_eq!(
        sn2.proof_word_count().unwrap() - sn2.decommitment_capacity_words as usize,
        24_776
    );

    let sn134 = CompactProtocolV1::decode(&protocol(58, 24_436, 2_077_800)).unwrap();
    assert_eq!(sn134.proof_word_count().unwrap(), 2_102_572);
    assert_eq!(
        sn134.proof_word_count().unwrap() - sn134.decommitment_capacity_words as usize,
        24_772
    );
}

#[test]
fn statement_mutations_fail_closed() {
    let mut bytes = statement(2);
    bytes[0] ^= 1;
    let error = match CompactStatementV1::decode(&bytes) {
        Ok(_) => panic!("mutated statement unexpectedly decoded"),
        Err(error) => error,
    };
    assert_eq!(error.code, "invalid_compact_statement");

    let mut bytes = statement(2);
    let enable = STATEMENT_HEADER_LEN as usize + PUBLIC_SEGMENT_COUNT * 5 * 4;
    put_u32(&mut bytes, enable + 4, 2);
    assert!(CompactStatementV1::decode(&bytes).is_err());

    let mut bytes = statement(2);
    put_u32(&mut bytes, 16, M31_PRIME);
    assert!(CompactStatementV1::decode(&bytes).is_err());

    let mut bytes = statement(2);
    bytes.push(0);
    assert!(CompactStatementV1::decode(&bytes).is_err());
}

#[test]
fn rejects_noncontiguous_memory_big_enable_prefix() {
    let mut bytes = statement(2);
    let enable = STATEMENT_HEADER_LEN as usize + PUBLIC_SEGMENT_COUNT * 5 * 4;
    put_u32(&mut bytes, enable, 0);
    put_u32(&mut bytes, enable + MEMORY_BIG_START * 4, 1);
    put_u32(&mut bytes, enable + (MEMORY_BIG_START + 2) * 4, 1);
    assert!(CompactStatementV1::decode(&bytes).is_err());
}

#[test]
fn proof_mutations_fail_closed() {
    let protocol = CompactProtocolV1::decode(&protocol(2, 4, 4000)).unwrap();
    let statement = CompactStatementV1::decode(&statement(2)).unwrap();
    let original = proof(&protocol);
    let decommit = protocol.proof_word_count().unwrap() - 4000;
    for (word, value) in [
        (decommit, 0),
        (decommit + 2, 11),
        (decommit + 3, 69),
        (decommit + 7, 4001),
        (decommit + 8, 1),
        (decommit + 9, 3),
        (decommit + 8 + 16 * 4 + 5, 1),
        (decommit + 8 + 5, 160),
    ] {
        let mut bytes = original.clone();
        put_u32(&mut bytes, word * 4, value);
        assert!(
            validate_compact_proof_v1(&bytes, &protocol, &statement).is_err(),
            "word {word}"
        );
    }
    let mut bytes = original;
    put_u32(&mut bytes, 4 * HASH_WORDS * 4, M31_PRIME);
    assert!(validate_compact_proof_v1(&bytes, &protocol, &statement).is_err());
}
