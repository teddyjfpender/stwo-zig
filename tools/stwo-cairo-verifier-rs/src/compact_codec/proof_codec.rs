use super::reconstruction::{CompactProofOffsetsV1, DecommitTreeMetaV1};
use super::*;

pub(super) fn compact_proof_offsets(protocol: &CompactProtocolV1) -> CompactProofOffsetsV1 {
    let interaction_start = protocol.commitment_count as usize * HASH_WORDS;
    let interaction_pow_start = interaction_start + protocol.interaction_sum_count as usize * 4;
    let sampled_start = interaction_pow_start + NONCE_WORDS;
    let fri_commitments_start = sampled_start + protocol.sampled_value_words as usize;
    let final_line_start = fri_commitments_start + protocol.fri_tree_count as usize * HASH_WORDS;
    let query_pow_start = final_line_start + protocol.final_line_coefficient_count as usize * 4;
    CompactProofOffsetsV1 {
        interaction_start,
        interaction_pow_start,
        sampled_start,
        fri_commitments_start,
        final_line_start,
        query_pow_start,
        decommitment_start: query_pow_start + NONCE_WORDS,
    }
}

pub(super) fn read_decommit_meta(
    bytes: &[u8],
    decommitment_start: usize,
    tree_index: usize,
) -> Result<DecommitTreeMetaV1, CompactCodecError> {
    let base = decommitment_start + DECOMMIT_HEADER_WORDS + tree_index * DECOMMIT_TREE_META_WORDS;
    Ok(DecommitTreeMetaV1 {
        query_count: read_proof_word(bytes, base + 3)? as usize,
        values_offset: read_proof_word(bytes, base + 4)? as usize,
        values_count: read_proof_word(bytes, base + 5)? as usize,
        fri_witness_offset: read_proof_word(bytes, base + 6)? as usize,
        fri_witness_count: read_proof_word(bytes, base + 7)? as usize,
        hash_witness_offset: read_proof_word(bytes, base + 8)? as usize,
        hash_witness_count: read_proof_word(bytes, base + 9)? as usize,
    })
}

pub(super) fn read_hash(bytes: &[u8], word_index: usize) -> Result<Blake2sHash, CompactCodecError> {
    let mut hash = [0_u8; 32];
    for index in 0..HASH_WORDS {
        hash[index * 4..index * 4 + 4]
            .copy_from_slice(&read_proof_word(bytes, word_index + index)?.to_le_bytes());
    }
    Ok(Blake2sHash(hash))
}

pub(super) fn read_decommit_hashes(
    bytes: &[u8],
    decommitment_start: usize,
    offset: usize,
    count: usize,
) -> Result<Vec<Blake2sHash>, CompactCodecError> {
    (0..count)
        .map(|index| read_hash(bytes, decommitment_start + offset + index * HASH_WORDS))
        .collect()
}

pub(super) fn read_decommit_m31(
    bytes: &[u8],
    decommitment_start: usize,
    offset: usize,
) -> Result<M31, CompactCodecError> {
    let value = read_proof_word(bytes, decommitment_start + offset)?;
    if value >= M31_PRIME {
        return Err(invalid_proof(format!(
            "decommitment M31 word is not canonical ({value})"
        )));
    }
    Ok(M31::from_u32_unchecked(value))
}

pub(super) fn read_decommit_qm31(
    bytes: &[u8],
    decommitment_start: usize,
    offset: usize,
) -> Result<QM31, CompactCodecError> {
    Ok(QM31::from_m31(
        read_decommit_m31(bytes, decommitment_start, offset)?,
        read_decommit_m31(bytes, decommitment_start, offset + 1)?,
        read_decommit_m31(bytes, decommitment_start, offset + 2)?,
        read_decommit_m31(bytes, decommitment_start, offset + 3)?,
    ))
}

pub(super) fn claim_field_first_slot(field_index: usize) -> usize {
    if field_index <= 49 {
        field_index
    } else {
        field_index + MEMORY_BIG_COUNT - 1
    }
}

pub(super) fn fixed_log_size(field_index: usize) -> Option<u32> {
    match field_index {
        23 => Some(4),
        25 => Some(20),
        38 => Some(23),
        41 => Some(15),
        46 => Some(6),
        51 => Some(6),
        52 => Some(8),
        53 => Some(11),
        54 => Some(12),
        55 => Some(18),
        56 => Some(20),
        57 => Some(7),
        58 => Some(8),
        59 => Some(18),
        60 => Some(14),
        61 => Some(18),
        62 => Some(16),
        63 => Some(15),
        64 => Some(8),
        65 => Some(14),
        66 => Some(16),
        67 => Some(18),
        _ => None,
    }
}

pub(super) fn object_with(name: &str, value: Value) -> Value {
    let mut object = Map::new();
    object.insert(name.to_owned(), value);
    Value::Object(object)
}

pub(super) fn read_qm31(bytes: &[u8], word_index: usize) -> Result<QM31, CompactCodecError> {
    Ok(QM31::from_u32_unchecked(
        read_proof_word(bytes, word_index)?,
        read_proof_word(bytes, word_index + 1)?,
        read_proof_word(bytes, word_index + 2)?,
        read_proof_word(bytes, word_index + 3)?,
    ))
}

/// Validates compact resident bundle words against authenticated geometry.
pub fn validate_compact_proof_v1(
    bytes: &[u8],
    protocol: &CompactProtocolV1,
    statement: &CompactStatementV1,
) -> Result<CompactProofGeometryV1, CompactCodecError> {
    if protocol.interaction_sum_count as usize != statement.component_log_sizes.len() {
        return Err(invalid_proof(
            "interaction sum count does not match the statement active-component count",
        ));
    }
    let expected_words = protocol.proof_word_count()?;
    let expected_bytes = expected_words.checked_mul(4).ok_or_else(length_overflow)?;
    require_exact_len(bytes, expected_bytes, "proof")
        .map_err(|error| CompactCodecError::invalid("invalid_compact_proof", error.message))?;

    let offsets = compact_proof_offsets(protocol);
    let interaction_start = offsets.interaction_start;
    let interaction_words = protocol.interaction_sum_count as usize * 4;
    let sampled_start = interaction_start + interaction_words + NONCE_WORDS;
    let sampled_words = protocol.sampled_value_words as usize;
    let final_line_start = offsets.final_line_start;
    let final_line_words = protocol.final_line_coefficient_count as usize * 4;
    let decommitment_offset = offsets.decommitment_start;
    validate_canonical_m31(
        bytes,
        interaction_start,
        interaction_words,
        "interaction claim",
    )?;
    validate_canonical_m31(bytes, sampled_start, sampled_words, "sampled values")?;
    validate_canonical_m31(
        bytes,
        final_line_start,
        final_line_words,
        "final line polynomial",
    )?;

    let capacity = protocol.decommitment_capacity_words as usize;
    let word = |index: usize| read_proof_word(bytes, decommitment_offset + index);
    if word(0)? != DECOMMIT_MAGIC || word(1)? != DECOMMIT_VERSION {
        return Err(invalid_proof("invalid versioned decommitment header"));
    }
    if word(2)? != protocol.decommitment_record_count {
        return Err(invalid_proof(format!(
            "decommitment tree count {} does not match authenticated count {}",
            word(2)?,
            protocol.decommitment_record_count
        )));
    }
    let raw_query_count = word(3)?;
    let unique_query_count = word(4)?;
    if raw_query_count != protocol.query_count
        || unique_query_count == 0
        || unique_query_count > raw_query_count
    {
        return Err(invalid_proof(
            "decommitment query counts do not match the authenticated query geometry",
        ));
    }
    let used = word(7)? as usize;
    let record_count = protocol.decommitment_record_count as usize;
    let metadata_end = DECOMMIT_HEADER_WORDS
        .checked_add(
            record_count
                .checked_mul(DECOMMIT_TREE_META_WORDS)
                .ok_or_else(length_overflow)?,
        )
        .ok_or_else(length_overflow)?;
    if used < metadata_end || used > capacity {
        return Err(invalid_proof(
            "decommitment used-word count is outside its authenticated capacity",
        ));
    }
    checked_word_range(
        word(5)? as usize,
        raw_query_count as usize,
        used,
        "raw queries",
    )?;
    checked_word_range(
        word(6)? as usize,
        unique_query_count as usize,
        used,
        "unique queries",
    )?;

    for index in 0..record_count {
        let base = DECOMMIT_HEADER_WORDS + index * DECOMMIT_TREE_META_WORDS;
        let kind = word(base)?;
        let role = word(base + 1)?;
        let expected_kind = u32::from(index >= protocol.commitment_count as usize);
        if kind != expected_kind || role != index as u32 {
            return Err(invalid_proof(format!(
                "decommitment record {index} has kind/role {kind}/{role}, expected {expected_kind}/{index}"
            )));
        }
        let query_count = word(base + 3)? as usize;
        let leaf_log_size = word(base + 14)?;
        let tree_used_words = word(base + 15)?;
        if query_count == 0
            || query_count > unique_query_count as usize
            || leaf_log_size == 0
            || leaf_log_size > 30
            || tree_used_words == 0
        {
            return Err(invalid_proof(format!(
                "decommitment record {index} has invalid query/log/used geometry"
            )));
        }
        if index >= protocol.commitment_count as usize && word(base + 5)? != 0 {
            return Err(invalid_proof(format!(
                "FRI decommitment record {index} unexpectedly contains trace values"
            )));
        }
        if index < protocol.commitment_count as usize {
            if word(base + 7)? != 0 {
                return Err(invalid_proof(format!(
                    "trace decommitment record {index} unexpectedly contains FRI witnesses"
                )));
            }
            let expected_values = query_count
                .checked_mul(protocol.trace_tree_column_counts[index] as usize)
                .ok_or_else(length_overflow)?;
            if word(base + 5)? as usize != expected_values {
                return Err(invalid_proof(format!(
                    "trace decommitment record {index} has {} values, expected {expected_values}",
                    word(base + 5)?
                )));
            }
        }
        checked_meta_range(&word, base + 2, base + 3, 1, used, "queries")?;
        checked_meta_range(&word, base + 4, base + 5, 1, used, "values")?;
        checked_meta_range(&word, base + 6, base + 7, 4, used, "FRI witnesses")?;
        checked_meta_range(
            &word,
            base + 8,
            base + 9,
            HASH_WORDS,
            used,
            "hash witnesses",
        )?;
        checked_meta_range(
            &word,
            base + 10,
            base + 11,
            DECOMMIT_AUX_NODE_WORDS,
            used,
            "auxiliary nodes",
        )?;
        checked_meta_range(&word, base + 12, base + 13, 5, used, "all-values rows")?;
    }

    Ok(CompactProofGeometryV1 {
        total_words: expected_words,
        interaction_claim_words: interaction_words,
        sampled_value_words: sampled_words,
        decommitment_offset_words: decommitment_offset,
        decommitment_used_words: used,
        raw_query_count,
        unique_query_count,
    })
}

pub(super) fn decode_state(
    bytes: &[u8],
    offset: usize,
    label: &str,
) -> Result<CasmState, CompactCodecError> {
    Ok(CasmState {
        pc: M31::from_u32_unchecked(read_m31_word(bytes, offset, label)?),
        ap: M31::from_u32_unchecked(read_m31_word(bytes, offset + 4, label)?),
        fp: M31::from_u32_unchecked(read_m31_word(bytes, offset + 8, label)?),
    })
}

pub(super) fn decode_segment(
    bytes: &[u8],
    offset: usize,
    index: usize,
) -> Result<Option<SegmentRange>, CompactCodecError> {
    let present = read_statement_u32(bytes, offset, "segment presence")?;
    let fields = [
        read_statement_u32(bytes, offset + 4, "segment start id")?,
        read_statement_u32(bytes, offset + 8, "segment start value")?,
        read_statement_u32(bytes, offset + 12, "segment stop id")?,
        read_statement_u32(bytes, offset + 16, "segment stop value")?,
    ];
    match present {
        0 if fields == [0; 4] && index != 0 => Ok(None),
        0 => Err(invalid_statement(format!(
            "absent segment {index} is not canonically zero"
        ))),
        1 => {
            for value in fields {
                require_m31(value, "segment pointer")?;
            }
            Ok(Some(SegmentRange {
                start_ptr: MemorySmallValue {
                    id: fields[0],
                    value: fields[1],
                },
                stop_ptr: MemorySmallValue {
                    id: fields[2],
                    value: fields[3],
                },
            }))
        }
        value => Err(invalid_statement(format!(
            "segment {index} has invalid presence value {value}"
        ))),
    }
}

pub(super) fn decode_memory_section(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    label: &str,
) -> Result<Vec<(u32, [u32; 8])>, CompactCodecError> {
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let id = read_statement_u32(bytes, *cursor, "public memory id")?;
        require_m31(id, "public memory id")?;
        let mut value = [0_u32; 8];
        for (limb_index, limb) in value.iter_mut().enumerate() {
            *limb = read_statement_u32(bytes, *cursor + 4 + limb_index * 4, "felt limb")?;
        }
        result.push((id, value));
        *cursor += MEMORY_ENTRY_WORDS * 4;
        let _ = (label, index);
    }
    Ok(result)
}

pub(super) fn validate_canonical_m31(
    bytes: &[u8],
    start_word: usize,
    count: usize,
    label: &str,
) -> Result<(), CompactCodecError> {
    for index in 0..count {
        let value = read_proof_word(bytes, start_word + index)?;
        if value >= M31_PRIME {
            return Err(invalid_proof(format!(
                "{label} word {index} is not canonical M31 ({value})"
            )));
        }
    }
    Ok(())
}

pub(super) fn checked_meta_range<F>(
    word: &F,
    offset_index: usize,
    count_index: usize,
    stride: usize,
    used: usize,
    label: &str,
) -> Result<(), CompactCodecError>
where
    F: Fn(usize) -> Result<u32, CompactCodecError>,
{
    let offset = word(offset_index)? as usize;
    let count = (word(count_index)? as usize)
        .checked_mul(stride)
        .ok_or_else(length_overflow)?;
    checked_word_range(offset, count, used, label)
}

pub(super) fn checked_word_range(
    offset: usize,
    count: usize,
    used: usize,
    label: &str,
) -> Result<(), CompactCodecError> {
    if count == 0 && offset == 0 {
        return Ok(());
    }
    let end = offset.checked_add(count).ok_or_else(length_overflow)?;
    if end > used {
        return Err(invalid_proof(format!(
            "{label} range {offset}..{end} exceeds decommitment used words {used}"
        )));
    }
    Ok(())
}

pub(super) fn read_proof_word(bytes: &[u8], word_index: usize) -> Result<u32, CompactCodecError> {
    read_u32(
        bytes,
        word_index.checked_mul(4).ok_or_else(length_overflow)?,
        "proof word",
    )
    .map_err(|error| CompactCodecError::invalid("invalid_compact_proof", error.message))
}

pub(super) fn read_m31_word(
    bytes: &[u8],
    offset: usize,
    label: &str,
) -> Result<u32, CompactCodecError> {
    let value = read_statement_u32(bytes, offset, label)?;
    require_m31(value, label)?;
    Ok(value)
}

pub(super) fn require_m31(value: u32, label: &str) -> Result<(), CompactCodecError> {
    if value >= M31_PRIME {
        return Err(invalid_statement(format!(
            "{label} is not canonical M31 ({value})"
        )));
    }
    Ok(())
}

pub(super) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn expect_u16(
    bytes: &[u8],
    offset: usize,
    expected: u16,
    label: &str,
) -> Result<(), CompactCodecError> {
    let actual = read_u16(bytes, offset, label)?;
    if actual != expected {
        return Err(invalid_protocol(format!(
            "{label} is {actual}, expected {expected}"
        )));
    }
    Ok(())
}

pub(super) fn expect_u32(
    bytes: &[u8],
    offset: usize,
    expected: u32,
    label: &str,
) -> Result<(), CompactCodecError> {
    let actual = read_u32(bytes, offset, label)?;
    if actual != expected {
        return Err(invalid_protocol(format!(
            "{label} is {actual}, expected {expected}"
        )));
    }
    Ok(())
}

pub(super) fn expect_statement_u16(
    bytes: &[u8],
    offset: usize,
    expected: u16,
    label: &str,
) -> Result<(), CompactCodecError> {
    let actual = read_u16(bytes, offset, label).map_err(as_statement_error)?;
    if actual != expected {
        return Err(invalid_statement(format!(
            "{label} is {actual}, expected {expected}"
        )));
    }
    Ok(())
}

pub(super) fn expect_statement_u32(
    bytes: &[u8],
    offset: usize,
    expected: u32,
    label: &str,
) -> Result<(), CompactCodecError> {
    let actual = read_statement_u32(bytes, offset, label)?;
    if actual != expected {
        return Err(invalid_statement(format!(
            "{label} is {actual}, expected {expected}"
        )));
    }
    Ok(())
}

pub(super) fn read_statement_u32(
    bytes: &[u8],
    offset: usize,
    label: &str,
) -> Result<u32, CompactCodecError> {
    read_u32(bytes, offset, label).map_err(as_statement_error)
}

pub(super) fn read_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16, CompactCodecError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_protocol(format!("truncated {label}")))?;
    Ok(u16::from_le_bytes(raw.try_into().expect("two-byte slice")))
}

pub(super) fn read_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, CompactCodecError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_protocol(format!("truncated {label}")))?;
    Ok(u32::from_le_bytes(raw.try_into().expect("four-byte slice")))
}

pub(super) fn require_exact_len(
    bytes: &[u8],
    expected: usize,
    label: &str,
) -> Result<(), CompactCodecError> {
    if bytes.len() != expected {
        return Err(CompactCodecError::invalid(
            match label {
                "statement" => "invalid_compact_statement",
                "proof" => "invalid_compact_proof",
                _ => "invalid_compact_protocol",
            },
            format!("{label} length is {}, expected {expected}", bytes.len()),
        ));
    }
    Ok(())
}

pub(super) fn usize_from_u32(value: u32, label: &str) -> Result<usize, CompactCodecError> {
    usize::try_from(value).map_err(|_| {
        CompactCodecError::invalid(
            "compact_length_overflow",
            format!("{label} does not fit usize"),
        )
    })
}

pub(super) fn invalid_protocol(message: impl Into<String>) -> CompactCodecError {
    CompactCodecError::invalid("invalid_compact_protocol", message)
}

pub(super) fn invalid_statement(message: impl Into<String>) -> CompactCodecError {
    CompactCodecError::invalid("invalid_compact_statement", message)
}

pub(super) fn invalid_proof(message: impl Into<String>) -> CompactCodecError {
    CompactCodecError::invalid("invalid_compact_proof", message)
}

pub(super) fn as_statement_error(error: CompactCodecError) -> CompactCodecError {
    invalid_statement(error.message)
}

pub(super) fn length_overflow() -> CompactCodecError {
    CompactCodecError::invalid(
        "compact_length_overflow",
        "compact codec length arithmetic overflow",
    )
}
