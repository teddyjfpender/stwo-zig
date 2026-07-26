use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use super::components::{
    add_ap_opcode, add_opcode, add_opcode_small, assert_eq_opcode, assert_eq_opcode_double_deref,
    assert_eq_opcode_imm, bitwise_builtin, blake_g, blake_round, blake_round_sigma,
    call_opcode_abs, call_opcode_rel_imm, cube_252, ec_op_builtin, generic_opcode,
    jnz_opcode_non_taken, jnz_opcode_taken, jump_opcode_abs, jump_opcode_double_deref,
    jump_opcode_rel, jump_opcode_rel_imm, mul_opcode, mul_opcode_small, partial_ec_mul_generic,
    partial_ec_mul_window_bits_18, partial_ec_mul_window_bits_9,
    pedersen_aggregator_window_bits_18, pedersen_aggregator_window_bits_9, pedersen_builtin,
    pedersen_builtin_narrow_windows, pedersen_points_table_window_bits_18,
    pedersen_points_table_window_bits_9, poseidon_3_partial_rounds_chain, poseidon_aggregator,
    poseidon_builtin, poseidon_full_round_chain, poseidon_round_keys, qm_31_add_mul_opcode,
    range_check96_builtin, range_check_11, range_check_12, range_check_18, range_check_20,
    range_check_252_width_27, range_check_3_3_3_3_3, range_check_3_6_6_3, range_check_4_3,
    range_check_4_4, range_check_4_4_4_4, range_check_6, range_check_7_2_5, range_check_8,
    range_check_9_9, range_check_builtin, ret_opcode, triple_xor_32, verify_bitwise_xor_4,
    verify_bitwise_xor_7, verify_bitwise_xor_8, verify_bitwise_xor_9, verify_instruction,
};
use super::witness_eval::bytecode::isa::{WitnessInst, WitnessProgram};
use super::witness_eval::recording::RecordingOutput;

const MAGIC: &[u8; 8] = b"STWZWIT\0";
const VERSION: u32 = 1;

fn recordings() -> Vec<(&'static str, RecordingOutput)> {
    vec![
        ("add_opcode", add_opcode::record_add_opcode()),
        (
            "add_opcode_small",
            add_opcode_small::record_add_opcode_small(),
        ),
        ("add_ap_opcode", add_ap_opcode::record_add_ap_opcode()),
        (
            "assert_eq_opcode",
            assert_eq_opcode::record_assert_eq_opcode(),
        ),
        (
            "assert_eq_opcode_imm",
            assert_eq_opcode_imm::record_assert_eq_opcode_imm(),
        ),
        (
            "assert_eq_opcode_double_deref",
            assert_eq_opcode_double_deref::record_assert_eq_opcode_double_deref(),
        ),
        ("call_opcode_abs", call_opcode_abs::record_call_opcode_abs()),
        (
            "call_opcode_rel_imm",
            call_opcode_rel_imm::record_call_opcode_rel_imm(),
        ),
        ("generic_opcode", generic_opcode::record_generic_opcode()),
        (
            "jnz_opcode_non_taken",
            jnz_opcode_non_taken::record_jnz_opcode_non_taken(),
        ),
        (
            "jnz_opcode_taken",
            jnz_opcode_taken::record_jnz_opcode_taken(),
        ),
        ("jump_opcode_abs", jump_opcode_abs::record_jump_opcode_abs()),
        (
            "jump_opcode_double_deref",
            jump_opcode_double_deref::record_jump_opcode_double_deref(),
        ),
        ("jump_opcode_rel", jump_opcode_rel::record_jump_opcode_rel()),
        (
            "jump_opcode_rel_imm",
            jump_opcode_rel_imm::record_jump_opcode_rel_imm(),
        ),
        ("mul_opcode", mul_opcode::record_mul_opcode()),
        (
            "mul_opcode_small",
            mul_opcode_small::record_mul_opcode_small(),
        ),
        (
            "qm_31_add_mul_opcode",
            qm_31_add_mul_opcode::record_qm_31_add_mul_opcode(),
        ),
        ("ret_opcode", ret_opcode::record_ret_opcode()),
        (
            "verify_instruction",
            verify_instruction::record_verify_instruction(),
        ),
        ("blake_g", blake_g::record_blake_g()),
        ("blake_round", blake_round::record_blake_round()),
        ("triple_xor_32", triple_xor_32::record_triple_xor_32()),
        (
            "partial_ec_mul_generic",
            partial_ec_mul_generic::record_partial_ec_mul_generic(),
        ),
        (
            "pedersen_aggregator_window_bits_18",
            pedersen_aggregator_window_bits_18::record_pedersen_aggregator_window_bits_18(),
        ),
        (
            "partial_ec_mul_window_bits_18",
            partial_ec_mul_window_bits_18::record_partial_ec_mul_window_bits_18(),
        ),
        (
            "pedersen_aggregator_window_bits_9",
            pedersen_aggregator_window_bits_9::record_pedersen_aggregator_window_bits_9(),
        ),
        (
            "partial_ec_mul_window_bits_9",
            partial_ec_mul_window_bits_9::record_partial_ec_mul_window_bits_9(),
        ),
        ("cube_252", cube_252::record_cube_252()),
        (
            "range_check_252_width_27",
            range_check_252_width_27::record_range_check_252_width_27(),
        ),
        (
            "blake_round_sigma",
            blake_round_sigma::record_blake_round_sigma(),
        ),
        (
            "pedersen_points_table_window_bits_18",
            pedersen_points_table_window_bits_18::record_pedersen_points_table_window_bits_18(),
        ),
        (
            "pedersen_points_table_window_bits_9",
            pedersen_points_table_window_bits_9::record_pedersen_points_table_window_bits_9(),
        ),
        (
            "poseidon_round_keys",
            poseidon_round_keys::record_poseidon_round_keys(),
        ),
        ("range_check_11", range_check_11::record_range_check_11()),
        ("range_check_12", range_check_12::record_range_check_12()),
        ("range_check_18", range_check_18::record_range_check_18()),
        ("range_check_20", range_check_20::record_range_check_20()),
        (
            "range_check_3_3_3_3_3",
            range_check_3_3_3_3_3::record_range_check_3_3_3_3_3(),
        ),
        (
            "range_check_3_6_6_3",
            range_check_3_6_6_3::record_range_check_3_6_6_3(),
        ),
        ("range_check_4_3", range_check_4_3::record_range_check_4_3()),
        ("range_check_4_4", range_check_4_4::record_range_check_4_4()),
        (
            "range_check_4_4_4_4",
            range_check_4_4_4_4::record_range_check_4_4_4_4(),
        ),
        ("range_check_6", range_check_6::record_range_check_6()),
        (
            "range_check_7_2_5",
            range_check_7_2_5::record_range_check_7_2_5(),
        ),
        ("range_check_8", range_check_8::record_range_check_8()),
        ("range_check_9_9", range_check_9_9::record_range_check_9_9()),
        (
            "verify_bitwise_xor_4",
            verify_bitwise_xor_4::record_verify_bitwise_xor_4(),
        ),
        (
            "verify_bitwise_xor_7",
            verify_bitwise_xor_7::record_verify_bitwise_xor_7(),
        ),
        (
            "verify_bitwise_xor_8",
            verify_bitwise_xor_8::record_verify_bitwise_xor_8(),
        ),
        (
            "verify_bitwise_xor_9",
            verify_bitwise_xor_9::record_verify_bitwise_xor_9(),
        ),
        ("bitwise_builtin", bitwise_builtin::record_bitwise_builtin()),
        (
            "pedersen_builtin",
            pedersen_builtin::record_pedersen_builtin(),
        ),
        (
            "pedersen_builtin_narrow_windows",
            pedersen_builtin_narrow_windows::record_pedersen_builtin_narrow_windows(),
        ),
        (
            "poseidon_3_partial_rounds_chain",
            poseidon_3_partial_rounds_chain::record_poseidon_3_partial_rounds_chain(),
        ),
        (
            "poseidon_aggregator",
            poseidon_aggregator::record_poseidon_aggregator(),
        ),
        (
            "poseidon_builtin",
            poseidon_builtin::record_poseidon_builtin(),
        ),
        (
            "poseidon_full_round_chain",
            poseidon_full_round_chain::record_poseidon_full_round_chain(),
        ),
        (
            "range_check96_builtin",
            range_check96_builtin::record_range_check96_builtin(),
        ),
        (
            "range_check_builtin",
            range_check_builtin::record_range_check_builtin(),
        ),
        ("ec_op_builtin", ec_op_builtin::record_ec_op_builtin()),
    ]
}

pub fn write_bundle(path: &Path) -> io::Result<()> {
    let entries = recordings();
    for (label, output) in &entries {
        if !output.poison_ops.is_empty()
            || !output.poisoned_cols.is_empty()
            || !output.poisoned_lookup_words.is_empty()
            || !output.poisoned_sub_words.is_empty()
        {
            return Err(io::Error::other(format!(
                "{label} has incomplete recording: ops={:?}, columns={:?}, lookup={:?}, sub={:?}",
                output.poison_ops,
                output.poisoned_cols,
                output.poisoned_lookup_words,
                output.poisoned_sub_words,
            )));
        }
    }

    let mut writer = BufWriter::new(File::create(path)?);
    writer.write_all(MAGIC)?;
    writer.write_all(&VERSION.to_le_bytes())?;
    writer.write_all(&(entries.len() as u32).to_le_bytes())?;
    for (label, output) in entries {
        write_entry(&mut writer, label, &output.program)?;
    }
    writer.flush()
}

fn write_entry(writer: &mut impl Write, label: &str, program: &WitnessProgram) -> io::Result<()> {
    let label_len = u16::try_from(label.len()).map_err(io::Error::other)?;
    let inst_count = u32::try_from(program.insts.len()).map_err(io::Error::other)?;
    writer.write_all(&label_len.to_le_bytes())?;
    writer.write_all(&0_u16.to_le_bytes())?;
    for count in [
        program.n_regs,
        program.n_inputs,
        program.n_cols,
        program.n_mult_tables,
        program.n_lookup_words,
        program.n_sub_words,
        inst_count,
    ] {
        writer.write_all(&count.to_le_bytes())?;
    }
    writer.write_all(&program.semantic_hash().to_le_bytes())?;
    writer.write_all(label.as_bytes())?;
    for instruction in &program.insts {
        write_instruction(writer, instruction)?;
    }
    Ok(())
}

fn write_instruction(writer: &mut impl Write, instruction: &WitnessInst) -> io::Result<()> {
    writer.write_all(&[instruction.op, instruction.pad])?;
    writer.write_all(&instruction.dst.to_le_bytes())?;
    writer.write_all(&instruction.a.to_le_bytes())?;
    writer.write_all(&instruction.b.to_le_bytes())?;
    writer.write_all(&instruction.imm.to_le_bytes())
}
