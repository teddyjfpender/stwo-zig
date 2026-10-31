//! Bounded RV64 AIR and verifier-owned state relation, separate from execution.
pub const statement = @import("statement.zig");
pub const layout = @import("layout.zig");
pub const rows = @import("rows.zig");
pub const witness = @import("witness.zig");
pub const trace = @import("trace.zig");
pub const evaluation = @import("evaluation.zig");
pub const relations = @import("relations.zig");
pub const component = @import("component.zig");
pub const protocol = @import("protocol.zig");
pub const projection = @import("projection.zig");
pub const operations = @import("operations.zig");
pub const control_policy = @import("control_policy.zig");
pub const encoding = @import("encoding.zig");
pub const full = struct {
    pub const packed_frame = @import("full/packed_frame.zig");
    pub const packed_control_constraints = @import("full/packed_control_constraints.zig");
    pub const parallel = @import("full/parallel.zig");
    pub const frame = @import("full/frame.zig");
    pub const component = @import("full/component.zig");
};
pub const program = struct {
    pub const packed_control = @import("program/packed_control.zig");
    pub const opcode_policy = @import("program/opcode_policy.zig");
    pub const setup = @import("program/setup.zig");
    pub const provider = @import("program/provider.zig");
    pub const component = @import("program/component.zig");
    pub const compact = @import("program/compact.zig");
    pub const service = @import("program/service.zig");
};
pub const range = struct {
    pub const provider = @import("range/provider.zig");
    pub const cpu = @import("range/cpu.zig");
    pub const table_cpu = @import("range/table_cpu.zig");
};
pub const providers = struct {
    pub const byte = @import("providers/byte.zig");
    pub const tables = @import("providers/tables.zig");
    pub const table_component = @import("providers/table_component.zig");
};

pub const arithmetic = struct {
    pub const multiplication = @import("arithmetic/multiplication/mod.zig");
    pub const division = @import("arithmetic/division/mod.zig");
};

pub const crypto = struct {
    pub const main_storage = @import("crypto/main_storage.zig");
    pub const secp256k1 = @import("crypto/secp256k1/mod.zig");
    pub const keccak = @import("crypto/keccak/mod.zig");
};

pub const memory = struct {
    pub const terminal_air = @import("memory/terminal_air.zig");
    pub const terminal_component = @import("memory/terminal_component.zig");
    pub const ownership = @import("memory/ownership.zig");
    pub const openings = @import("memory/openings.zig");
    pub const private_interaction = @import("memory/private_interaction.zig");
    pub const provider_interaction = @import("memory/provider_interaction.zig");
    pub const private_trace = @import("memory/private_trace.zig");
    pub const policy_provider = @import("memory/policy_provider.zig");
    pub const policy_component = @import("memory/policy_component.zig");
    pub const batch = @import("memory/batch.zig");
    pub const native_frontier = @import("memory/native_frontier.zig");
    pub const native_frontier_wire = @import("memory/native_frontier_wire.zig");
    pub const permit_air = @import("memory/permit_air.zig");
    pub const permit_component = @import("memory/permit_component.zig");
    pub const node_component = @import("memory/node_component.zig");
    pub const cell_component = @import("memory/cell_component.zig");
    pub const leaf_air = @import("memory/leaf_air.zig");
    pub const leaf_component = @import("memory/leaf_component.zig");
    pub const side_air = @import("memory/side_air.zig");
    pub const side_component = @import("memory/side_component.zig");
    pub const cell_air = @import("memory/cell_air.zig");
    pub const node_air = @import("memory/node_air.zig");
    pub const chunk_component = @import("memory/chunk_component.zig");
    pub const message_air = @import("memory/message_air.zig");
    pub const message_component = @import("memory/message_component.zig");
    pub const chunk_air = @import("memory/chunk_air.zig");
    pub const internal_relations = @import("memory/internal_relations.zig");
    pub const values = @import("memory/values.zig");
    pub const policy_air = @import("memory/policy_air.zig");
    pub const policy = @import("memory/policy.zig");
    pub const commitment = @import("memory/commitment.zig");
    pub const image = @import("memory/image.zig");
    pub const transition = @import("memory/transition.zig");
};

pub const state_policy = @import("state_policy.zig");
pub const state_cyclic = @import("state_cyclic.zig");

/// Inactive Word16 request vocabulary; no production profile selects it.
pub const word16_v1 = struct {
    pub const operations = @import("word16_v1/operations.zig");
    pub const function_bus = @import("word16_v1/function_bus.zig");
    pub const binary = @import("word16_v1/binary.zig");
    pub const binary_lookup = @import("word16_v1/binary_lookup.zig");
    pub const binary_component = @import("word16_v1/binary_component.zig");
    pub const binary_source = @import("word16_v1/binary_source.zig");
};
