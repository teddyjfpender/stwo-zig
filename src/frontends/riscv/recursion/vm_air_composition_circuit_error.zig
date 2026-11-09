//! Internal shard of vm_air_composition_circuit.zig; use the public facade.

pub const std = @import("std");

pub const graph_build = @import("vm_air_composition_circuit_graph_build.zig");

pub const vm_air_composition_circuit = @This();

pub const stwo_core = @import("stwo_core");

pub const circle = stwo_core.circle;

pub const M31 = stwo_core.fields.m31.M31;

pub const m31 = stwo_core.fields.m31;

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const qm31 = stwo_core.fields.qm31;

pub const canonic = stwo_core.poly.circle.canonic;

pub const verifier_types = stwo_core.verifier_types;

pub const clock_component = @import("stwo_riscv_rv32").air_clock_update_component;

pub const clock_interaction = @import("stwo_riscv_rv32").air_clock_update_interaction;

pub const component_order = @import("stwo_riscv_rv32").air_component_order;

pub const logup = @import("stwo_riscv_air_lang").shared_air_logup;

pub const memory_interaction = @import("stwo_riscv_memory").air_interaction;

pub const merkle_node = @import("stwo_riscv_memory").air_merkle_node;

pub const poseidon2_air = @import("stwo_riscv_memory").air_poseidon2_air;

pub const opcode_entries = @import("stwo_riscv_rv32").air_lookups_opcode_entries;

pub const opcode_interaction = @import("stwo_riscv_rv32").air_lookups_opcode_interaction;

pub const table_interaction = @import("stwo_riscv_rv32").air_lookups_tables_interaction;

pub const table_schema = @import("stwo_riscv_air_lang").shared_air_lookups_tables_schema;

pub const program_commitment = @import("stwo_riscv_rv32").air_program_commitment;

pub const program_interaction = @import("stwo_riscv_rv32").air_program_interaction;

pub const semantic_eval = @import("stwo_riscv_rv32").air_semantic_eval;

pub const statement_mod = @import("stwo_riscv_rv32").air_statement;

pub const trace_mod = @import("stwo_riscv_rv32").runner_trace;

pub const graph_mod = @import("stwo_riscv_rv32").recursion_air_composition_circuit;

pub const row18_witness = @import("stwo_riscv_rv32").recursion_air_vm_air_composition_input_witness;

pub const vm_leaf_context = @import("stwo_riscv_rv32").recursion_vm_leaf_context;

pub const transcript_claims = @import("stwo_riscv_rv32").air_transcript_claims;

pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;

pub const CIRCUIT_DOMAIN = "stwo-zig/riscv/recursion/vm-air-composition-circuit/v1\x00";

pub const CIRCUIT_ID: u32 = 1;

pub const TREE_COUNT: usize = 4;

pub const Error = std.mem.Allocator.Error || graph_mod.Error ||
    row18_witness.Error || vm_leaf_context.Error || QM31.Error || error{
    ArithmeticOverflow,
    BindingCountMismatch,
    CircuitIdentityMismatch,
    CircuitTooLarge,
    GraphConstructionFailed,
    IncompatibleCommittedTrace,
    InputIsNotBaseField,
    InvalidCaptureShape,
    InvalidComponentOrder,
    InvalidInteractionShape,
    InvalidMainTraceShape,
    InvalidRelationArity,
    InvalidSampleGeometry,
    InvalidTraceShape,
    UnsatisfiedCircuit,
};
