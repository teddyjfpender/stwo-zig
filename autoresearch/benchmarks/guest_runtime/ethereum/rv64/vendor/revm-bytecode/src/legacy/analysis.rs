use super::JumpTable;
use crate::opcode;
use bitvec::{bitvec, order::Lsb0, vec::BitVec};
use primitives::Bytes;
use std::vec::Vec;

/// Analyzes the bytecode to produce a jump table and potentially padded bytecode.
///
/// Prefer using [`Bytecode::new_legacy`](crate::Bytecode::new_legacy) instead.
pub(crate) fn analyze_legacy(bytecode: Bytes) -> (JumpTable, Bytes) {
    // stwo: the scan runs over the padded copy with the padding temporarily
    // set to JUMPDEST, so the loop needs no end-of-code test: whichever way
    // a final PUSH overshoots (at most 32 bytes), it lands on a sentinel and
    // only the rare JUMPDEST path checks the bound. Five instructions per
    // opcode instead of seven. The padding is then always MAX_PADDING zero
    // bytes, an upper bound of the exact amount (a PUSH32 immediate running
    // 32 bytes past the end plus the final STOP; a trailing DUPN/SWAPN/
    // EXCHANGE needs at most 2). Padding is never observable: consumers
    // read `original_len` bytes.
    let len = bytecode.len();
    let mut jumps: BitVec<u8> = bitvec![u8, Lsb0; 0; len];
    let mut padded = Vec::with_capacity(len + MAX_PADDING);
    padded.extend_from_slice(&bytecode);
    padded.resize(len + MAX_PADDING, opcode::JUMPDEST);
    let start = padded.as_ptr();
    let end = start.wrapping_add(len);
    let mut p = start;
    loop {
        // SAFETY: p <= start + len + 32 < start + padded.len(): every step
        // from a position < len advances by at most 33 and positions >= len
        // are sentinels.
        let op = unsafe { *p };
        let advance = ADVANCE[op as usize];
        if advance == 0 {
            if p >= end {
                break;
            }
            // SAFETY: p < end
            unsafe { jumps.set_unchecked(p.offset_from_unsigned(start), true) }
            p = p.wrapping_add(1);
        } else {
            p = p.wrapping_add(advance as usize);
        }
    }
    padded[len..].fill(0);
    (JumpTable::new(jumps), Bytes::from(padded))
}

/// Upper bound of the padding the exact analysis computes.
const MAX_PADDING: usize = 33;

/// The original exact-padding analysis, kept for the tests that pin it.
#[cfg(test)]
pub(crate) fn analyze_legacy_eager(bytecode: Bytes) -> (JumpTable, Bytes) {
    let mut jumps: BitVec<u8> = bitvec![u8, Lsb0; 0; bytecode.len()];
    let range = bytecode.as_ptr_range();
    let start = range.start;
    let mut iterator = start;
    let end = range.end;
    let mut prev_byte: u8 = 0;
    let mut last_byte: u8 = 0;
    while iterator < end {
        prev_byte = last_byte;
        last_byte = unsafe { *iterator };
        let advance = ADVANCE[last_byte as usize];
        if advance == 0 {
            unsafe { jumps.set_unchecked(iterator.offset_from_unsigned(start), true) }
            iterator = unsafe { iterator.add(1) };
        } else {
            iterator = iterator.wrapping_add(advance as usize);
        }
    }
    let push_overflow = (iterator as usize) - (end as usize);
    let mut padding = push_overflow;
    if last_byte == opcode::STOP {
        padding += is_dupn_swapn_exchange(prev_byte) as usize;
    } else {
        padding += 1 + is_dupn_swapn_exchange(last_byte) as usize;
    }
    assert!(padding <= MAX_PADDING);
    let bytecode = if padding > 0 {
        let mut padded = Vec::with_capacity(bytecode.len() + padding);
        padded.extend_from_slice(&bytecode);
        padded.resize(padded.len() + padding, 0);
        Bytes::from(padded)
    } else {
        bytecode
    };
    (JumpTable::new(jumps), bytecode)
}

/// Byte advance per opcode for the jump-table scan: 0 marks JUMPDEST.
const ADVANCE: [u8; 256] = {
    let mut table = [1u8; 256];
    let mut i = 0;
    while i < 32 {
        table[opcode::PUSH1 as usize + i] = i as u8 + 2;
        i += 1;
    }
    table[opcode::JUMPDEST as usize] = 0;
    table
};

/// Returns true if the opcode is DUPN, SWAPN, or EXCHANGE.
#[cfg(test)]
const fn is_dupn_swapn_exchange(opcode: u8) -> bool {
    opcode.wrapping_sub(opcode::DUPN) < 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_scan_matches_exact_analysis() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for case in 0..600usize {
            let len = 1 + (case * 37) % 700;
            let mut code: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    match seed % 5 {
                        0 => opcode::JUMPDEST,
                        1 => opcode::PUSH1 + (seed >> 8) as u8 % 32,
                        _ => (seed >> 16) as u8,
                    }
                })
                .collect();
            if case % 3 == 0 {
                // end inside a long PUSH immediate
                let at = len.saturating_sub(1 + case % 32);
                code[at] = opcode::PUSH32;
            }
            let (eager, _) = analyze_legacy_eager(code.clone().into());
            let (fast, padded) = analyze_legacy(code.clone().into());
            assert_eq!(padded.len(), len + MAX_PADDING);
            assert_eq!(&padded[..len], &code[..]);
            assert!(padded[len..].iter().all(|&b| b == 0));
            assert_eq!(fast, eager, "case {case}");
        }
    }

    #[test]
    fn test_bytecode_ends_with_stop_no_padding_needed() {
        let bytecode = vec![
            opcode::PUSH1,
            0x01,
            opcode::PUSH1,
            0x02,
            opcode::ADD,
            opcode::STOP,
        ];
        let (_, padded_bytecode) = analyze_legacy_eager(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len());
    }

    #[test]
    fn test_bytecode_ends_without_stop_requires_padding() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::PUSH1, 0x02, opcode::ADD];
        let (_, padded_bytecode) = analyze_legacy_eager(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 1);
    }

    #[test]
    fn test_bytecode_ends_with_push16_requires_17_bytes_padding() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::PUSH16];
        let (_, padded_bytecode) = analyze_legacy_eager(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 17);
    }

    #[test]
    fn test_bytecode_ends_with_push2_requires_2_bytes_padding() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::PUSH2, 0x02];
        let (_, padded_bytecode) = analyze_legacy_eager(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 2);
    }

    #[test]
    fn test_bytecode_with_jumpdest_at_start() {
        let bytecode = vec![opcode::JUMPDEST, opcode::PUSH1, 0x01, opcode::STOP];
        let (jump_table, _) = analyze_legacy_eager(bytecode.into());
        assert!(jump_table.is_valid(0)); // First byte should be a valid jumpdest
    }

    #[test]
    fn test_bytecode_with_jumpdest_after_push() {
        let bytecode = vec![opcode::PUSH1, 0x01, opcode::JUMPDEST, opcode::STOP];
        let (jump_table, _) = analyze_legacy_eager(bytecode.into());
        assert!(jump_table.is_valid(2)); // JUMPDEST should be at position 2
    }

    #[test]
    fn test_bytecode_with_multiple_jumpdests() {
        let bytecode = vec![
            opcode::JUMPDEST,
            opcode::PUSH1,
            0x01,
            opcode::JUMPDEST,
            opcode::STOP,
        ];
        let (jump_table, _) = analyze_legacy_eager(bytecode.into());
        assert!(jump_table.is_valid(0)); // First JUMPDEST
        assert!(jump_table.is_valid(3)); // Second JUMPDEST
    }

    #[test]
    fn test_bytecode_with_max_push32() {
        let bytecode = vec![opcode::PUSH32];
        let (_, padded_bytecode) = analyze_legacy_eager(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len() + 33); // PUSH32 + 32 bytes + STOP
    }

    #[test]
    fn test_truncated_pushes_are_padded_without_inbounds_pointer_advance() {
        for push in opcode::PUSH1..=opcode::PUSH32 {
            let bytecode = vec![push];
            let (_, padded_bytecode) = analyze_legacy_eager(bytecode.clone().into());
            let push_immediate_len = (push - opcode::PUSH1 + 1) as usize;
            assert_eq!(
                padded_bytecode.len(),
                bytecode.len() + push_immediate_len + 1
            );
        }
    }

    #[test]
    fn test_bytecode_with_invalid_opcode() {
        let bytecode = vec![0xFF, opcode::STOP]; // 0xFF is an invalid opcode
        let (jump_table, _) = analyze_legacy_eager(bytecode.into());
        assert!(!jump_table.is_valid(0)); // Invalid opcode should not be a jumpdest
    }

    #[test]
    fn test_bytecode_with_sequential_pushes() {
        let bytecode = vec![
            opcode::PUSH1,
            0x01,
            opcode::PUSH2,
            0x02,
            0x03,
            opcode::PUSH4,
            0x04,
            0x05,
            0x06,
            0x07,
            opcode::STOP,
        ];
        let (jump_table, padded_bytecode) = analyze_legacy_eager(bytecode.clone().into());
        assert_eq!(padded_bytecode.len(), bytecode.len());
        assert!(!jump_table.is_valid(0)); // PUSH1
        assert!(!jump_table.is_valid(2)); // PUSH2
        assert!(!jump_table.is_valid(5)); // PUSH4
    }

    #[test]
    fn test_bytecode_with_jumpdest_in_push_data() {
        let bytecode = vec![
            opcode::PUSH2,
            opcode::JUMPDEST, // This should not be treated as a JUMPDEST
            0x02,
            opcode::STOP,
        ];
        let (jump_table, _) = analyze_legacy_eager(bytecode.into());
        assert!(!jump_table.is_valid(1)); // JUMPDEST in push data should not be valid
    }

    #[test]
    fn test_bytecode_ends_with_immediate_opcode_and_stop_requires_padding() {
        // For SWAPN/DUPN/EXCHANGE, the STOP (0x00) is consumed as the immediate operand,
        // not as an actual STOP instruction, so padding is needed.
        // [OPCODE]       -> [OPCODE, STOP, STOP] (3 bytes)
        // [OPCODE, STOP] -> [OPCODE, STOP, STOP] (3 bytes)
        for op in [opcode::SWAPN, opcode::DUPN, opcode::EXCHANGE] {
            for bytecode in [vec![op], vec![op, opcode::STOP]] {
                let (_, padded_bytecode) = analyze_legacy_eager(bytecode.into());
                assert_eq!(padded_bytecode.len(), 3);
                assert_eq!(padded_bytecode[0], op);
                assert_eq!(padded_bytecode[1], opcode::STOP);
                assert_eq!(padded_bytecode[2], opcode::STOP);
            }
        }
    }
}
