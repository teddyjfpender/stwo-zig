//! Streaming compact transport for the pinned official ProverInput.
//! This is transport only: adaptation and AIR semantics remain upstream-owned.

use std::io::Write;
use stwo_cairo_adapter::ProverInput;

pub fn write(writer: &mut impl Write, input: &ProverInput) -> std::io::Result<()> {
    macro_rules! word {
        ($value:expr) => {
            writer.write_all(&$value.to_le_bytes())?
        };
    }
    macro_rules! state {
        ($state:expr) => {{
            word!($state.pc.0);
            word!($state.ap.0);
            word!($state.fp.0);
        }};
    }
    writer.write_all(b"STWZCPI\0")?;
    word!(1_u32);
    word!(0_u32);
    state!(input.state_transitions.initial_state);
    state!(input.state_transitions.final_state);
    word!(input.pc_count as u64);
    let mask = input
        .public_segment_context
        .iter()
        .enumerate()
        .fold(0_u16, |mask, (bit, present)| {
            mask | (u16::from(*present) << bit)
        });
    word!(mask);
    word!(0_u16);
    word!(0_u32);
    let states = &input.state_transitions.casm_states_by_opcode;
    // The order is the frozen wire order, not a lexical component ordering.
    let groups = [
        &states.generic_opcode,
        &states.add_ap_opcode,
        &states.add_opcode,
        &states.add_opcode_small,
        &states.assert_eq_opcode,
        &states.assert_eq_opcode_double_deref,
        &states.assert_eq_opcode_imm,
        &states.call_opcode_abs,
        &states.call_opcode_rel_imm,
        &states.jnz_opcode_non_taken,
        &states.jnz_opcode_taken,
        &states.jump_opcode_rel_imm,
        &states.jump_opcode_rel,
        &states.jump_opcode_double_deref,
        &states.jump_opcode_abs,
        &states.mul_opcode_small,
        &states.mul_opcode,
        &states.ret_opcode,
        &states.blake_compress_opcode,
        &states.qm_31_add_mul_opcode,
    ];
    word!(groups.len() as u32);
    word!(0_u32);
    for group in groups {
        word!(group.len() as u64);
        for entry in group {
            state!(entry);
        }
    }
    let memory = &input.memory;
    word!(memory.config.small_max);
    word!(memory.config.log_small_value_capacity);
    word!(0_u32);
    word!(memory.address_to_id.len() as u64);
    word!(memory.f252_values.len() as u64);
    word!(memory.small_values.len() as u64);
    for id in &memory.address_to_id {
        word!(id.0);
    }
    for value in &memory.f252_values {
        for limb in value {
            word!(*limb);
        }
    }
    for value in &memory.small_values {
        word!(*value);
    }
    word!(input.public_memory_addresses.len() as u64);
    for address in &input.public_memory_addresses {
        word!(*address);
    }
    let segments = &input.builtin_segments;
    for segment in [
        segments.add_mod_builtin,
        segments.bitwise_builtin,
        segments.output,
        segments.mul_mod_builtin,
        segments.pedersen_builtin,
        segments.poseidon_builtin,
        segments.range_check96_builtin,
        segments.range_check_builtin,
        segments.ec_op_builtin,
    ] {
        writer.write_all(&[u8::from(segment.is_some())])?;
        writer.write_all(&[0; 7])?;
        word!(segment.map_or(0, |segment| segment.begin_addr) as u64);
        word!(segment.map_or(0, |segment| segment.stop_ptr) as u64);
    }
    Ok(())
}
