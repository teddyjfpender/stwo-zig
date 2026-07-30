use super::*;

/// Statement geometry plus the actual pinned Rust verifier `PublicData` type.
pub struct CompactStatementV1 {
    pub public_data: PublicData,
    pub component_enable_bits: [bool; COMPONENT_ENABLE_COUNT],
    pub component_log_sizes: Vec<u32>,
}

impl CompactStatementV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, CompactCodecError> {
        if bytes.len() < usize::from(STATEMENT_HEADER_LEN) {
            return Err(invalid_statement("truncated compact statement header"));
        }
        if bytes[..8] != STATEMENT_MAGIC {
            return Err(invalid_statement("invalid compact statement magic"));
        }
        expect_statement_u16(bytes, 8, CODEC_VERSION, "statement version")?;
        expect_statement_u16(bytes, 10, STATEMENT_HEADER_LEN, "statement header length")?;
        expect_statement_u32(bytes, 12, 0, "statement flags")?;
        expect_statement_u32(
            bytes,
            56,
            COMPONENT_ENABLE_COUNT as u32,
            "component enable count",
        )?;
        expect_statement_u32(
            bytes,
            64,
            PUBLIC_SEGMENT_COUNT as u32,
            "public segment count",
        )?;
        expect_statement_u32(bytes, 68, MEMORY_ENTRY_WORDS as u32, "memory entry words")?;
        expect_statement_u32(bytes, 72, 0, "statement reserved field 0")?;
        expect_statement_u32(bytes, 76, 0, "statement reserved field 1")?;

        let program_count = usize_from_u32(
            read_statement_u32(bytes, 48, "program count")?,
            "program count",
        )?;
        let output_count = usize_from_u32(
            read_statement_u32(bytes, 52, "output count")?,
            "output count",
        )?;
        let active_count = usize_from_u32(
            read_statement_u32(bytes, 60, "active component count")?,
            "active component count",
        )?;
        if active_count == 0 || active_count > COMPONENT_ENABLE_COUNT {
            return Err(invalid_statement(format!(
                "active component count {active_count} is outside 1..={COMPONENT_ENABLE_COUNT}"
            )));
        }

        let segments_bytes = PUBLIC_SEGMENT_COUNT
            .checked_mul(5 * 4)
            .ok_or_else(length_overflow)?;
        let memory_count = program_count
            .checked_add(output_count)
            .ok_or_else(length_overflow)?;
        let memory_bytes = memory_count
            .checked_mul(MEMORY_ENTRY_WORDS * 4)
            .ok_or_else(length_overflow)?;
        let expected_len = usize::from(STATEMENT_HEADER_LEN)
            .checked_add(segments_bytes)
            .and_then(|value| value.checked_add(memory_bytes))
            .and_then(|value| value.checked_add(COMPONENT_ENABLE_COUNT * 4))
            .and_then(|value| value.checked_add(active_count * 4))
            .ok_or_else(length_overflow)?;
        require_exact_len(bytes, expected_len, "statement")?;

        let initial_state = decode_state(bytes, 16, "initial state")?;
        let final_state = decode_state(bytes, 28, "final state")?;
        let safe_call_ids = [
            read_m31_word(bytes, 40, "safe call id 0")?,
            read_m31_word(bytes, 44, "safe call id 1")?,
        ];

        let mut cursor = usize::from(STATEMENT_HEADER_LEN);
        let mut segments = Vec::with_capacity(PUBLIC_SEGMENT_COUNT);
        for index in 0..PUBLIC_SEGMENT_COUNT {
            segments.push(decode_segment(bytes, cursor, index)?);
            cursor += 5 * 4;
        }
        if segments[0].is_none() {
            return Err(invalid_statement("the output segment is mandatory"));
        }

        let program = decode_memory_section(bytes, &mut cursor, program_count, "program")?;
        let output = decode_memory_section(bytes, &mut cursor, output_count, "output")?;

        let mut component_enable_bits = [false; COMPONENT_ENABLE_COUNT];
        for (index, enabled) in component_enable_bits.iter_mut().enumerate() {
            *enabled = match read_statement_u32(bytes, cursor, "component enable bit")? {
                0 => false,
                1 => true,
                value => {
                    return Err(invalid_statement(format!(
                        "component enable bit {index} has non-binary value {value}"
                    )))
                }
            };
            cursor += 4;
        }
        let enabled_count = component_enable_bits.iter().filter(|&&value| value).count();
        if enabled_count != active_count {
            return Err(invalid_statement(format!(
                "{enabled_count} enabled components do not match active count {active_count}"
            )));
        }
        let memory_big =
            &component_enable_bits[MEMORY_BIG_START..MEMORY_BIG_START + MEMORY_BIG_COUNT];
        if memory_big.windows(2).any(|pair| !pair[0] && pair[1]) {
            return Err(invalid_statement(
                "memory_id_to_big enable bits are not a contiguous active prefix",
            ));
        }

        let mut component_log_sizes = Vec::with_capacity(active_count);
        for index in 0..active_count {
            let log_size = read_statement_u32(bytes, cursor, "component log size")?;
            if !(1..=30).contains(&log_size) {
                return Err(invalid_statement(format!(
                    "component log size {index} is outside 1..=30 ({log_size})"
                )));
            }
            component_log_sizes.push(log_size);
            cursor += 4;
        }
        debug_assert_eq!(cursor, bytes.len());

        let take = |index: usize| segments[index];
        let public_segments = PublicSegmentRanges {
            output: take(0).expect("mandatory output segment checked above"),
            pedersen: take(1),
            range_check_128: take(2),
            ecdsa: take(3),
            bitwise: take(4),
            ec_op: take(5),
            keccak: take(6),
            poseidon: take(7),
            range_check_96: take(8),
            add_mod: take(9),
            mul_mod: take(10),
        };
        Ok(Self {
            public_data: PublicData {
                public_memory: PublicMemory {
                    program,
                    public_segments,
                    output,
                    safe_call_ids,
                },
                initial_state,
                final_state,
            },
            component_enable_bits,
            component_log_sizes,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CompactCodecError> {
        let active_count = self
            .component_enable_bits
            .iter()
            .filter(|&&bit| bit)
            .count();
        if active_count != self.component_log_sizes.len() {
            return Err(invalid_statement(
                "enabled components do not match the provided log sizes",
            ));
        }
        let program_count: u32 = self
            .public_data
            .public_memory
            .program
            .len()
            .try_into()
            .map_err(|_| length_overflow())?;
        let output_count: u32 = self
            .public_data
            .public_memory
            .output
            .len()
            .try_into()
            .map_err(|_| length_overflow())?;
        let mut bytes = vec![0_u8; usize::from(STATEMENT_HEADER_LEN)];
        bytes[..8].copy_from_slice(&STATEMENT_MAGIC);
        write_u16(&mut bytes, 8, CODEC_VERSION);
        write_u16(&mut bytes, 10, STATEMENT_HEADER_LEN);
        let initial = self.public_data.initial_state;
        let final_state = self.public_data.final_state;
        for (offset, value) in [
            (16, initial.pc.0),
            (20, initial.ap.0),
            (24, initial.fp.0),
            (28, final_state.pc.0),
            (32, final_state.ap.0),
            (36, final_state.fp.0),
            (40, self.public_data.public_memory.safe_call_ids[0]),
            (44, self.public_data.public_memory.safe_call_ids[1]),
            (48, program_count),
            (52, output_count),
            (56, COMPONENT_ENABLE_COUNT as u32),
            (60, active_count as u32),
            (64, PUBLIC_SEGMENT_COUNT as u32),
            (68, MEMORY_ENTRY_WORDS as u32),
        ] {
            write_u32(&mut bytes, offset, value);
        }

        let segments = &self.public_data.public_memory.public_segments;
        for segment in [
            Some(segments.output),
            segments.pedersen,
            segments.range_check_128,
            segments.ecdsa,
            segments.bitwise,
            segments.ec_op,
            segments.keccak,
            segments.poseidon,
            segments.range_check_96,
            segments.add_mod,
            segments.mul_mod,
        ] {
            match segment {
                Some(range) => {
                    push_u32(&mut bytes, 1);
                    push_u32(&mut bytes, range.start_ptr.id);
                    push_u32(&mut bytes, range.start_ptr.value);
                    push_u32(&mut bytes, range.stop_ptr.id);
                    push_u32(&mut bytes, range.stop_ptr.value);
                }
                None => bytes.extend_from_slice(&[0_u8; 20]),
            }
        }
        for (id, value) in self
            .public_data
            .public_memory
            .program
            .iter()
            .chain(&self.public_data.public_memory.output)
        {
            push_u32(&mut bytes, *id);
            for limb in value {
                push_u32(&mut bytes, *limb);
            }
        }
        for enabled in self.component_enable_bits {
            push_u32(&mut bytes, u32::from(enabled));
        }
        for &log_size in &self.component_log_sizes {
            push_u32(&mut bytes, log_size);
        }
        Self::decode(&bytes)?;
        Ok(bytes)
    }
}
