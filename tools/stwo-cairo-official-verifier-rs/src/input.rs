//! Semantic inspection of the pinned official adapter input.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo_cairo_adapter::builtins::{
    BuiltinSegments as UpstreamBuiltinSegments, MemorySegmentAddresses,
};
use stwo_cairo_adapter::{ExecutionResources, ProverInput};
use stwo_cairo_common::prover_types::cpu::CasmState;

use crate::sha256_file;

pub const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct StateSet {
    count: usize,
    sha256_le: String,
}

#[derive(Debug, Serialize)]
pub struct OpcodeStates {
    generic_opcode: StateSet,
    add_ap_opcode: StateSet,
    add_opcode: StateSet,
    add_opcode_small: StateSet,
    assert_eq_opcode: StateSet,
    assert_eq_opcode_double_deref: StateSet,
    assert_eq_opcode_imm: StateSet,
    call_opcode_abs: StateSet,
    call_opcode_rel_imm: StateSet,
    jnz_opcode_non_taken: StateSet,
    jnz_opcode_taken: StateSet,
    jump_opcode_rel_imm: StateSet,
    jump_opcode_rel: StateSet,
    jump_opcode_double_deref: StateSet,
    jump_opcode_abs: StateSet,
    mul_opcode_small: StateSet,
    mul_opcode: StateSet,
    ret_opcode: StateSet,
    blake_compress_opcode: StateSet,
    qm_31_add_mul_opcode: StateSet,
}

#[derive(Debug, Serialize)]
pub struct TableDigest {
    count: usize,
    sha256_le: String,
}

#[derive(Debug, Serialize)]
pub struct MemorySummary {
    small_max: u128,
    log_small_value_capacity: u32,
    address_to_id: TableDigest,
    f252_values: TableDigest,
    small_values: TableDigest,
}

#[derive(Debug, Serialize)]
pub struct Segment {
    begin_addr: usize,
    stop_ptr: usize,
}

#[derive(Debug, Serialize)]
pub struct BuiltinSegments {
    add_mod_builtin: Option<Segment>,
    bitwise_builtin: Option<Segment>,
    output: Option<Segment>,
    mul_mod_builtin: Option<Segment>,
    pedersen_builtin: Option<Segment>,
    poseidon_builtin: Option<Segment>,
    range_check96_builtin: Option<Segment>,
    range_check_builtin: Option<Segment>,
    ec_op_builtin: Option<Segment>,
}

#[derive(Debug, Serialize)]
pub struct ResourceMemory {
    memory_address_to_id: usize,
    memory_id_to_big: usize,
    memory_id_to_small: usize,
}

#[derive(Debug, Serialize)]
pub struct ResourceSummary {
    opcodes_instance_counter: BTreeMap<String, usize>,
    builtin_instance_counter: BTreeMap<String, usize>,
    memory_tables_sizes: ResourceMemory,
    verify_instruction: usize,
}

#[derive(Debug, Serialize)]
pub struct InputSummary {
    schema: &'static str,
    input_sha256: String,
    initial_state: [u32; 3],
    final_state: [u32; 3],
    opcode_states: OpcodeStates,
    memory: MemorySummary,
    pc_count: usize,
    public_memory_addresses: TableDigest,
    builtin_segments: BuiltinSegments,
    public_segment_context: [bool; 11],
    execution_resources: ResourceSummary,
}

pub fn inspect_input(path: &Path) -> Result<InputSummary> {
    let metadata = path
        .metadata()
        .with_context(|| format!("failed to stat {}", path.display()))?;
    ensure!(metadata.is_file(), "prover input is not a regular file");
    ensure!(metadata.len() > 0, "prover input is empty");
    ensure!(
        metadata.len() <= MAX_INPUT_BYTES,
        "prover input exceeds the {MAX_INPUT_BYTES}-byte limit"
    );
    let input: ProverInput = serde_json::from_reader(BufReader::new(
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
    ))
    .context("failed to decode official ProverInput JSON")?;
    Ok(summarize(input, sha256_file(path)?))
}

fn summarize(input: ProverInput, input_sha256: String) -> InputSummary {
    let states = &input.state_transitions.casm_states_by_opcode;
    let resources = ExecutionResources::from_prover_input(&input);
    InputSummary {
        schema: "stwo_cairo_official_input_summary_v1",
        input_sha256,
        initial_state: state(input.state_transitions.initial_state),
        final_state: state(input.state_transitions.final_state),
        opcode_states: OpcodeStates {
            generic_opcode: state_set(&states.generic_opcode),
            add_ap_opcode: state_set(&states.add_ap_opcode),
            add_opcode: state_set(&states.add_opcode),
            add_opcode_small: state_set(&states.add_opcode_small),
            assert_eq_opcode: state_set(&states.assert_eq_opcode),
            assert_eq_opcode_double_deref: state_set(&states.assert_eq_opcode_double_deref),
            assert_eq_opcode_imm: state_set(&states.assert_eq_opcode_imm),
            call_opcode_abs: state_set(&states.call_opcode_abs),
            call_opcode_rel_imm: state_set(&states.call_opcode_rel_imm),
            jnz_opcode_non_taken: state_set(&states.jnz_opcode_non_taken),
            jnz_opcode_taken: state_set(&states.jnz_opcode_taken),
            jump_opcode_rel_imm: state_set(&states.jump_opcode_rel_imm),
            jump_opcode_rel: state_set(&states.jump_opcode_rel),
            jump_opcode_double_deref: state_set(&states.jump_opcode_double_deref),
            jump_opcode_abs: state_set(&states.jump_opcode_abs),
            mul_opcode_small: state_set(&states.mul_opcode_small),
            mul_opcode: state_set(&states.mul_opcode),
            ret_opcode: state_set(&states.ret_opcode),
            blake_compress_opcode: state_set(&states.blake_compress_opcode),
            qm_31_add_mul_opcode: state_set(&states.qm_31_add_mul_opcode),
        },
        memory: MemorySummary {
            small_max: input.memory.config.small_max,
            log_small_value_capacity: input.memory.config.log_small_value_capacity,
            address_to_id: u32_table(input.memory.address_to_id.iter().map(|value| value.0)),
            f252_values: f252_table(&input.memory.f252_values),
            small_values: u128_table(&input.memory.small_values),
        },
        pc_count: input.pc_count,
        public_memory_addresses: u32_table(input.public_memory_addresses.iter().copied()),
        builtin_segments: segments(&input.builtin_segments),
        public_segment_context: *input.public_segment_context,
        execution_resources: ResourceSummary {
            opcodes_instance_counter: resources.opcodes_instance_counter.into_iter().collect(),
            builtin_instance_counter: resources.builtin_instance_counter.into_iter().collect(),
            memory_tables_sizes: ResourceMemory {
                memory_address_to_id: resources.memory_tables_sizes.memory_address_to_id,
                memory_id_to_big: resources.memory_tables_sizes.memory_id_to_big,
                memory_id_to_small: resources.memory_tables_sizes.memory_id_to_small,
            },
            verify_instruction: resources.verify_instruction,
        },
    }
}

fn state(value: CasmState) -> [u32; 3] {
    [value.pc.0, value.ap.0, value.fp.0]
}

fn state_set(states: &[CasmState]) -> StateSet {
    let mut hasher = Sha256::new();
    for state in states {
        for value in [state.pc.0, state.ap.0, state.fp.0] {
            hasher.update(value.to_le_bytes());
        }
    }
    StateSet {
        count: states.len(),
        sha256_le: format!("{:x}", hasher.finalize()),
    }
}

fn u32_table(values: impl IntoIterator<Item = u32>) -> TableDigest {
    let mut count = 0;
    let mut hasher = Sha256::new();
    for value in values {
        count += 1;
        hasher.update(value.to_le_bytes());
    }
    TableDigest {
        count,
        sha256_le: format!("{:x}", hasher.finalize()),
    }
}

fn u128_table(values: &[u128]) -> TableDigest {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update(value.to_le_bytes());
    }
    TableDigest {
        count: values.len(),
        sha256_le: format!("{:x}", hasher.finalize()),
    }
}

fn f252_table(values: &[[u32; 8]]) -> TableDigest {
    let mut hasher = Sha256::new();
    for value in values {
        for word in value {
            hasher.update(word.to_le_bytes());
        }
    }
    TableDigest {
        count: values.len(),
        sha256_le: format!("{:x}", hasher.finalize()),
    }
}

fn segments(value: &UpstreamBuiltinSegments) -> BuiltinSegments {
    BuiltinSegments {
        add_mod_builtin: segment(value.add_mod_builtin),
        bitwise_builtin: segment(value.bitwise_builtin),
        output: segment(value.output),
        mul_mod_builtin: segment(value.mul_mod_builtin),
        pedersen_builtin: segment(value.pedersen_builtin),
        poseidon_builtin: segment(value.poseidon_builtin),
        range_check96_builtin: segment(value.range_check96_builtin),
        range_check_builtin: segment(value.range_check_builtin),
        ec_op_builtin: segment(value.ec_op_builtin),
    }
}

fn segment(value: Option<MemorySegmentAddresses>) -> Option<Segment> {
    value.map(|value| Segment {
        begin_addr: value.begin_addr,
        stop_ptr: value.stop_ptr,
    })
}
