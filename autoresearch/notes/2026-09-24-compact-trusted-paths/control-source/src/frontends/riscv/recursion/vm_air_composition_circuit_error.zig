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

pub const clock_component = @import("../air/clock_update_component.zig");

pub const clock_interaction = @import("../air/clock_update_interaction.zig");

pub const component_order = @import("../air/component_order.zig");

pub const logup = @import("../air/logup.zig");

pub const memory_interaction = @import("../air/memory_commitment/interaction.zig");

pub const merkle_node = @import("../air/memory_commitment/merkle_node.zig");

pub const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");

pub const opcode_entries = @import("../air/lookups/opcode_entries.zig");

pub const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");

pub const table_interaction = @import("../air/lookups/tables/interaction.zig");

pub const table_schema = @import("../air/lookups/tables/schema.zig");

pub const program_commitment = @import("../air/program/commitment.zig");

pub const program_interaction = @import("../air/program/interaction.zig");

pub const semantic_eval = @import("../air/semantic_eval.zig");

pub const statement_mod = @import("../air/statement.zig");

pub const trace_mod = @import("../runner/trace.zig");

pub const graph_mod = @import("air/composition_circuit.zig");

pub const row18_witness = @import("air/vm_air_composition_input_witness.zig");

pub const vm_leaf_context = @import("vm_leaf_context.zig");

pub const transcript_claims = @import("../air/transcript/claims.zig");

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
