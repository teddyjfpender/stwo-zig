use anyhow::{Result, ensure};

use crate::program::{
    MetalEvaluationProgramBaseInstV1, MetalEvaluationProgramExtInstV1,
    MetalEvaluationProgramHeaderV1, MetalEvaluationProgramSectionDescV1,
    OwnedMetalEvaluationProgramV1,
};

pub fn program(program: &OwnedMetalEvaluationProgramV1) -> Result<Vec<u8>> {
    let header = program.header();
    let mut bytes = Vec::with_capacity(
        96 + program.sections().len() * 24 + usize::try_from(program.payload_len_bytes())?,
    );
    encode_header(&mut bytes, header);
    ensure!(
        bytes.len() == 96,
        "evaluation-program header encoding drifted"
    );
    for section in program.sections() {
        encode_section(&mut bytes, *section);
    }
    for value in program.base_consts() {
        push_u32(&mut bytes, *value);
    }
    for value in program.ext_consts() {
        for coordinate in value {
            push_u32(&mut bytes, *coordinate);
        }
    }
    for instruction in program.base_insts() {
        encode_base_instruction(&mut bytes, instruction);
    }
    for instruction in program.ext_insts() {
        encode_extension_instruction(&mut bytes, instruction);
    }
    for root in program.constraint_roots() {
        push_u32(&mut bytes, *root);
    }
    Ok(bytes)
}

fn encode_header(bytes: &mut Vec<u8>, header: MetalEvaluationProgramHeaderV1) {
    push_u32(bytes, header.magic);
    push_u16(bytes, header.abi_major);
    push_u16(bytes, header.abi_minor);
    push_u32(bytes, header.n_sections);
    push_u32(bytes, header.flags);
    push_u64(bytes, header.semantic_hash);
    push_u64(bytes, header.capability_bits);
    push_u32(bytes, header.n_interactions);
    push_u32(bytes, header.n_base_params);
    push_u32(bytes, header.n_ext_params);
    push_u32(bytes, header.n_constraints);
    push_u32(bytes, header.max_base_regs);
    push_u32(bytes, header.max_ext_regs);
    push_u32(bytes, header.secure_ext_degree);
    for value in header.reserved {
        push_u32(bytes, value);
    }
    push_u32(bytes, 0);
}

fn encode_section(bytes: &mut Vec<u8>, section: MetalEvaluationProgramSectionDescV1) {
    push_u32(bytes, section.kind);
    push_u32(bytes, section.elem_size);
    push_u64(bytes, section.offset_bytes);
    push_u64(bytes, section.count);
}

fn encode_base_instruction(bytes: &mut Vec<u8>, instruction: &MetalEvaluationProgramBaseInstV1) {
    bytes.push(instruction.op);
    bytes.push(instruction.interaction);
    push_u16(bytes, instruction.dst);
    push_u32(bytes, instruction.a);
    push_u32(bytes, instruction.b);
    bytes.extend_from_slice(&instruction.imm.to_le_bytes());
}

fn encode_extension_instruction(
    bytes: &mut Vec<u8>,
    instruction: &MetalEvaluationProgramExtInstV1,
) {
    bytes.push(instruction.op);
    bytes.push(instruction.reserved0);
    push_u16(bytes, instruction.dst);
    push_u32(bytes, instruction.a);
    push_u32(bytes, instruction.b);
    push_u32(bytes, instruction.c);
    push_u32(bytes, instruction.d);
}

pub fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
