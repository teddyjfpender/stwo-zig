use super::*;

pub const PROTOCOL_MAGIC: [u8; 8] = *b"STWZCP1\0";
pub const STATEMENT_MAGIC: [u8; 8] = *b"STWZCS1\0";
pub const CODEC_VERSION: u16 = 1;
pub const PROTOCOL_HEADER_LEN: u16 = 112;
pub const STATEMENT_HEADER_LEN: u16 = 80;
pub const COMPONENT_ENABLE_COUNT: usize = 83;
pub const MEMORY_BIG_START: usize = 49;
pub const MEMORY_BIG_COUNT: usize = 16;
pub const PUBLIC_SEGMENT_COUNT: usize = 11;
pub const MEMORY_ENTRY_WORDS: usize = 9;
pub const HASH_WORDS: usize = 8;
pub const NONCE_WORDS: usize = 2;
pub const M31_PRIME: u32 = 0x7fff_ffff;
pub const DECOMMIT_MAGIC: u32 = 0x4457_5453;
pub const DECOMMIT_VERSION: u32 = 1;
pub const DECOMMIT_HEADER_WORDS: usize = 8;
pub const DECOMMIT_TREE_META_WORDS: usize = 16;
pub const DECOMMIT_AUX_NODE_WORDS: usize = 10;

const BLAKE2S_CHANNEL: u32 = 1;
const RESIDENT_SN2_BUNDLE_V1: u32 = 1;
const PREPROCESSED_CANONICAL: u32 = 1;
pub(super) const PREPROCESSED_CANONICAL_WITHOUT_PEDERSEN: u32 = 2;
const PREPROCESSED_CANONICAL_SMALL: u32 = 3;
#[cfg(test)]
pub(super) const EXPECTED_TRACE_COLUMNS: [u32; 4] = [161, 3449, 2268, 8];
const TRACE_TREE_COUNT: u32 = 4;
const LEGACY_MAX_LOG_DEGREE_BOUND: u32 = 24;
const MAX_RUNTIME_LOG_DEGREE_BOUND: u32 = 31;
const MAX_QUERY_COUNT: u32 = 1 << 20;

// Pinned to cairo-air's CairoClaim field order at STWO_CAIRO_REVISION. The
// compact statement stores the flattened 83-slot representation, so this is
// the inverse mapping back to the canonical typed claim.
pub(super) const CLAIM_FIELD_NAMES: [&str; 68] = [
    "add_opcode",
    "add_opcode_small",
    "add_ap_opcode",
    "assert_eq_opcode",
    "assert_eq_opcode_imm",
    "assert_eq_opcode_double_deref",
    "blake_compress_opcode",
    "call_opcode_abs",
    "call_opcode_rel_imm",
    "generic_opcode",
    "jnz_opcode_non_taken",
    "jnz_opcode_taken",
    "jump_opcode_abs",
    "jump_opcode_double_deref",
    "jump_opcode_rel",
    "jump_opcode_rel_imm",
    "mul_opcode",
    "mul_opcode_small",
    "qm_31_add_mul_opcode",
    "ret_opcode",
    "verify_instruction",
    "blake_round",
    "blake_g",
    "blake_round_sigma",
    "triple_xor_32",
    "verify_bitwise_xor_12",
    "add_mod_builtin",
    "bitwise_builtin",
    "mul_mod_builtin",
    "pedersen_builtin",
    "pedersen_builtin_narrow_windows",
    "poseidon_builtin",
    "range_check96_builtin",
    "range_check_builtin",
    "ec_op_builtin",
    "partial_ec_mul_generic",
    "pedersen_aggregator_window_bits_18",
    "partial_ec_mul_window_bits_18",
    "pedersen_points_table_window_bits_18",
    "pedersen_aggregator_window_bits_9",
    "partial_ec_mul_window_bits_9",
    "pedersen_points_table_window_bits_9",
    "poseidon_aggregator",
    "poseidon_3_partial_rounds_chain",
    "poseidon_full_round_chain",
    "cube_252",
    "poseidon_round_keys",
    "range_check_252_width_27",
    "memory_address_to_id",
    "memory_id_to_big",
    "memory_id_to_small",
    "range_check_6",
    "range_check_8",
    "range_check_11",
    "range_check_12",
    "range_check_18",
    "range_check_20",
    "range_check_4_3",
    "range_check_4_4",
    "range_check_9_9",
    "range_check_7_2_5",
    "range_check_3_6_6_3",
    "range_check_4_4_4_4",
    "range_check_3_3_3_3_3",
    "verify_bitwise_xor_4",
    "verify_bitwise_xor_7",
    "verify_bitwise_xor_8",
    "verify_bitwise_xor_9",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactCodecError {
    pub code: &'static str,
    pub message: String,
}

impl CompactCodecError {
    pub(super) fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for CompactCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CompactCodecError {}

/// Authenticated protocol and compact-layout geometry for version 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactProtocolV1 {
    pub preprocessed_trace_variant: PreProcessedTraceVariant,
    pub channel_salt: u32,
    pub query_pow_bits: u32,
    pub log_blowup_factor: u32,
    pub query_count: u32,
    pub log_last_layer_degree_bound: u32,
    pub fri_fold_step: u32,
    pub fri_lifting_log_size: Option<u32>,
    pub interaction_pow_bits: u32,
    pub commitment_count: u32,
    pub sampled_tree_count: u32,
    pub fri_tree_count: u32,
    pub final_line_coefficient_count: u32,
    pub decommitment_record_count: u32,
    pub max_log_degree_bound: u32,
    pub interaction_sum_count: u32,
    pub sampled_value_words: u32,
    pub decommitment_capacity_words: u32,
    pub trace_tree_column_counts: [u32; 4],
}

impl CompactProtocolV1 {
    pub fn sn2(
        channel_salt: u32,
        interaction_sum_count: u32,
        sampled_value_words: u32,
        decommitment_capacity_words: u32,
        trace_tree_column_counts: [u32; 4],
    ) -> Self {
        Self::sn2_for_preprocessed_trace(
            PreProcessedTraceVariant::Canonical,
            channel_salt,
            interaction_sum_count,
            sampled_value_words,
            decommitment_capacity_words,
            trace_tree_column_counts,
        )
    }

    pub fn sn2_for_preprocessed_trace(
        preprocessed_trace_variant: PreProcessedTraceVariant,
        channel_salt: u32,
        interaction_sum_count: u32,
        sampled_value_words: u32,
        decommitment_capacity_words: u32,
        trace_tree_column_counts: [u32; 4],
    ) -> Self {
        Self {
            preprocessed_trace_variant,
            channel_salt,
            query_pow_bits: 26,
            log_blowup_factor: 1,
            query_count: 70,
            log_last_layer_degree_bound: 0,
            fri_fold_step: 3,
            fri_lifting_log_size: None,
            interaction_pow_bits: 24,
            commitment_count: TRACE_TREE_COUNT,
            sampled_tree_count: TRACE_TREE_COUNT,
            fri_tree_count: 8,
            final_line_coefficient_count: 1,
            decommitment_record_count: 12,
            max_log_degree_bound: LEGACY_MAX_LOG_DEGREE_BOUND,
            interaction_sum_count,
            sampled_value_words,
            decommitment_capacity_words,
            trace_tree_column_counts,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CompactCodecError> {
        require_exact_len(bytes, usize::from(PROTOCOL_HEADER_LEN), "protocol")?;
        if bytes[..8] != PROTOCOL_MAGIC {
            return Err(invalid_protocol("invalid compact protocol magic"));
        }
        expect_u16(bytes, 8, CODEC_VERSION, "protocol version")?;
        expect_u16(bytes, 10, PROTOCOL_HEADER_LEN, "protocol header length")?;
        expect_u32(bytes, 12, 0, "protocol flags")?;
        expect_u32(bytes, 16, BLAKE2S_CHANNEL, "channel")?;
        expect_u32(bytes, 20, RESIDENT_SN2_BUNDLE_V1, "proof serialization")?;
        let preprocessed_trace_variant =
            decode_preprocessed_trace_variant(read_u32(bytes, 24, "preprocessed variant")?)?;
        let lifting_word = read_u32(bytes, 52, "FRI lifting log size")?;
        let max_log_word = read_u32(bytes, 108, "maximum log degree bound")?;

        let interaction_sum_count = read_u32(bytes, 80, "interaction sum count")?;
        if interaction_sum_count == 0 || interaction_sum_count > COMPONENT_ENABLE_COUNT as u32 {
            return Err(invalid_protocol(format!(
                "interaction sum count {interaction_sum_count} is outside 1..={COMPONENT_ENABLE_COUNT}"
            )));
        }
        let sampled_value_words = read_u32(bytes, 84, "sampled value words")?;
        if sampled_value_words == 0 || sampled_value_words % 4 != 0 {
            return Err(invalid_protocol(
                "sampled value word count must be a nonzero QM31 multiple",
            ));
        }
        let decommitment_capacity_words = read_u32(bytes, 88, "decommitment words")?;
        let mut trace_tree_column_counts = [0_u32; 4];
        for (index, value) in trace_tree_column_counts.iter_mut().enumerate() {
            *value = read_u32(bytes, 92 + index * 4, "trace tree column count")?;
        }
        let protocol = Self {
            preprocessed_trace_variant,
            channel_salt: read_u32(bytes, 28, "channel salt")?,
            query_pow_bits: read_u32(bytes, 32, "query PoW bits")?,
            log_blowup_factor: read_u32(bytes, 36, "log blowup factor")?,
            query_count: read_u32(bytes, 40, "query count")?,
            log_last_layer_degree_bound: read_u32(bytes, 44, "last-layer degree bound")?,
            fri_fold_step: read_u32(bytes, 48, "FRI fold step")?,
            fri_lifting_log_size: if lifting_word == u32::MAX {
                None
            } else {
                Some(lifting_word)
            },
            interaction_pow_bits: read_u32(bytes, 56, "interaction PoW bits")?,
            commitment_count: read_u32(bytes, 60, "commitment count")?,
            sampled_tree_count: read_u32(bytes, 64, "sampled tree count")?,
            fri_tree_count: read_u32(bytes, 68, "FRI tree count")?,
            final_line_coefficient_count: read_u32(bytes, 72, "final line coefficient count")?,
            decommitment_record_count: read_u32(bytes, 76, "decommitment record count")?,
            max_log_degree_bound: if max_log_word == 0 {
                LEGACY_MAX_LOG_DEGREE_BOUND
            } else {
                max_log_word
            },
            interaction_sum_count,
            sampled_value_words,
            decommitment_capacity_words,
            trace_tree_column_counts,
        };
        protocol.validate_geometry()?;
        Ok(protocol)
    }

    pub fn validate_geometry(&self) -> Result<(), CompactCodecError> {
        let expected_preprocessed_columns =
            preprocessed_trace_column_count(self.preprocessed_trace_variant);
        if self.trace_tree_column_counts[0] != expected_preprocessed_columns {
            return Err(invalid_protocol(
                format!(
                    "preprocessed trace variant requires {expected_preprocessed_columns} trace-tree-0 columns, found {}",
                    self.trace_tree_column_counts[0]
                ),
            ));
        }
        if self.query_pow_bits > 64 || self.interaction_pow_bits > 64 {
            return Err(invalid_protocol(
                "proof-of-work bits exceed the nonce width",
            ));
        }
        if !(1..=16).contains(&self.log_blowup_factor)
            || self.query_count == 0
            || self.query_count > MAX_QUERY_COUNT
            || self.log_last_layer_degree_bound > 10
            || self.max_log_degree_bound > MAX_RUNTIME_LOG_DEGREE_BOUND
            || self.max_log_degree_bound <= self.log_last_layer_degree_bound
        {
            return Err(invalid_protocol(
                "PCS runtime geometry is outside supported bounds",
            ));
        }
        if let Some(log_size) = self.fri_lifting_log_size {
            if log_size == 0 || log_size > MAX_RUNTIME_LOG_DEGREE_BOUND {
                return Err(invalid_protocol("FRI lifting log size is outside 1..=31"));
            }
        }
        let expected_fri_layers = fri_layer_count(
            self.max_log_degree_bound,
            self.log_last_layer_degree_bound,
            self.fri_fold_step,
        )?;
        if self.commitment_count != TRACE_TREE_COUNT
            || self.sampled_tree_count != TRACE_TREE_COUNT
            || self.fri_tree_count != expected_fri_layers
            || self.decommitment_record_count
                != self
                    .commitment_count
                    .checked_add(self.fri_tree_count)
                    .ok_or_else(length_overflow)?
        {
            return Err(invalid_protocol(
                "commitment, sampled, FRI, and decommitment counts are inconsistent",
            ));
        }
        let maximum_coefficients = 1_u32 << self.log_last_layer_degree_bound;
        if self.final_line_coefficient_count == 0
            || self.final_line_coefficient_count > maximum_coefficients
        {
            return Err(invalid_protocol(
                "final-line coefficient count exceeds its authenticated degree bound",
            ));
        }
        if self
            .trace_tree_column_counts
            .iter()
            .any(|&count| count == 0)
        {
            return Err(invalid_protocol("trace tree column counts must be nonzero"));
        }
        let minimum_decommit_words = DECOMMIT_HEADER_WORDS
            .checked_add(
                usize::try_from(self.decommitment_record_count)
                    .map_err(|_| length_overflow())?
                    .checked_mul(DECOMMIT_TREE_META_WORDS)
                    .ok_or_else(length_overflow)?,
            )
            .and_then(|value| {
                value.checked_add(usize::try_from(self.query_count).ok()?.checked_mul(2)?)
            })
            .ok_or_else(length_overflow)?;
        if usize::try_from(self.decommitment_capacity_words).map_err(|_| length_overflow())?
            < minimum_decommit_words
        {
            return Err(invalid_protocol(format!(
                "decommitment capacity is smaller than the authenticated minimum {minimum_decommit_words}"
            )));
        }
        Ok(())
    }

    pub fn validate_max_log_degree_bound(&self, derived: u32) -> Result<(), CompactCodecError> {
        self.validate_geometry()?;
        if derived != self.max_log_degree_bound {
            return Err(invalid_protocol(format!(
                "AIR maximum log degree bound {derived} does not match authenticated value {}",
                self.max_log_degree_bound
            )));
        }
        Ok(())
    }

    pub fn proof_word_count(&self) -> Result<usize, CompactCodecError> {
        self.validate_geometry()?;
        let terms = [
            usize_from_u32(self.commitment_count, "commitment count")?
                .checked_mul(HASH_WORDS)
                .ok_or_else(length_overflow)?,
            usize_from_u32(self.interaction_sum_count, "interaction sum count")?
                .checked_mul(4)
                .ok_or_else(length_overflow)?,
            NONCE_WORDS,
            usize_from_u32(self.sampled_value_words, "sampled value words")?,
            usize_from_u32(self.fri_tree_count, "FRI tree count")?
                .checked_mul(HASH_WORDS)
                .ok_or_else(length_overflow)?,
            usize_from_u32(
                self.final_line_coefficient_count,
                "final line coefficient count",
            )?
            .checked_mul(4)
            .ok_or_else(length_overflow)?,
            NONCE_WORDS,
            usize_from_u32(
                self.decommitment_capacity_words,
                "decommitment capacity words",
            )?,
        ];
        terms.into_iter().try_fold(0_usize, |total, term| {
            total.checked_add(term).ok_or_else(length_overflow)
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CompactCodecError> {
        self.validate_geometry()?;
        let mut bytes = vec![0_u8; usize::from(PROTOCOL_HEADER_LEN)];
        bytes[..8].copy_from_slice(&PROTOCOL_MAGIC);
        write_u16(&mut bytes, 8, CODEC_VERSION);
        write_u16(&mut bytes, 10, PROTOCOL_HEADER_LEN);
        for (offset, value) in [
            (16, BLAKE2S_CHANNEL),
            (20, RESIDENT_SN2_BUNDLE_V1),
            (
                24,
                encode_preprocessed_trace_variant(self.preprocessed_trace_variant),
            ),
            (28, self.channel_salt),
            (32, self.query_pow_bits),
            (36, self.log_blowup_factor),
            (40, self.query_count),
            (44, self.log_last_layer_degree_bound),
            (48, self.fri_fold_step),
            (52, self.fri_lifting_log_size.unwrap_or(u32::MAX)),
            (56, self.interaction_pow_bits),
            (60, self.commitment_count),
            (64, self.sampled_tree_count),
            (68, self.fri_tree_count),
            (72, self.final_line_coefficient_count),
            (76, self.decommitment_record_count),
            (80, self.interaction_sum_count),
            (84, self.sampled_value_words),
            (88, self.decommitment_capacity_words),
            (92, self.trace_tree_column_counts[0]),
            (96, self.trace_tree_column_counts[1]),
            (100, self.trace_tree_column_counts[2]),
            (104, self.trace_tree_column_counts[3]),
            (
                108,
                if self.max_log_degree_bound == LEGACY_MAX_LOG_DEGREE_BOUND {
                    0
                } else {
                    self.max_log_degree_bound
                },
            ),
        ] {
            write_u32(&mut bytes, offset, value);
        }
        Self::decode(&bytes)?;
        Ok(bytes)
    }
}

fn decode_preprocessed_trace_variant(
    tag: u32,
) -> Result<PreProcessedTraceVariant, CompactCodecError> {
    match tag {
        PREPROCESSED_CANONICAL => Ok(PreProcessedTraceVariant::Canonical),
        PREPROCESSED_CANONICAL_WITHOUT_PEDERSEN => {
            Ok(PreProcessedTraceVariant::CanonicalWithoutPedersen)
        }
        PREPROCESSED_CANONICAL_SMALL => Ok(PreProcessedTraceVariant::CanonicalSmall),
        _ => Err(invalid_protocol(format!(
            "unknown preprocessed trace variant tag {tag}"
        ))),
    }
}

fn encode_preprocessed_trace_variant(variant: PreProcessedTraceVariant) -> u32 {
    match variant {
        PreProcessedTraceVariant::Canonical => PREPROCESSED_CANONICAL,
        PreProcessedTraceVariant::CanonicalWithoutPedersen => {
            PREPROCESSED_CANONICAL_WITHOUT_PEDERSEN
        }
        PreProcessedTraceVariant::CanonicalSmall => PREPROCESSED_CANONICAL_SMALL,
    }
}

fn preprocessed_trace_column_count(variant: PreProcessedTraceVariant) -> u32 {
    match variant {
        PreProcessedTraceVariant::Canonical => 161,
        PreProcessedTraceVariant::CanonicalWithoutPedersen => 105,
        PreProcessedTraceVariant::CanonicalSmall => 156,
    }
}

fn fri_layer_count(
    max_log_degree_bound: u32,
    final_log: u32,
    fold_step: u32,
) -> Result<u32, CompactCodecError> {
    let folds = max_log_degree_bound
        .checked_sub(final_log)
        .filter(|&value| value > 0)
        .ok_or_else(|| invalid_protocol("FRI degree bound does not exceed the final layer"))?;
    if fold_step == 0 || fold_step > folds {
        return Err(invalid_protocol(
            "FRI fold step is outside the folding range",
        ));
    }
    Ok(1 + (folds - 1) / fold_step)
}
