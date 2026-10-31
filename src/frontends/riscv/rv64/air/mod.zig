//! Bounded RV64 AIR and verifier-owned state relation, separate from execution.
pub const statement = @import("statement.zig");
pub const layout = @import("layout.zig");
pub const rows = @import("rows.zig");
pub const witness = @import("witness.zig");
pub const trace = @import("trace.zig");
pub const evaluation = @import("evaluation.zig");
pub const lane = @import("lane.zig");
pub const geometry = @import("geometry.zig");
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
    pub const load_store_v1 = @import("memory/load_store_v1/mod.zig");
    pub const load_store_v2 = @import("memory/load_store_v2/mod.zig");
    pub const closed_ram = @import("memory/closed_ram/mod.zig");
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
    pub const prefix = @import("memory/prefix.zig");
    pub const permutation_point = @import("memory/permutation_point.zig");
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
    pub const word_add = @import("word16_v1/word_add.zig");
    pub const operations = @import("word16_v1/operations.zig");
    pub const function_bus = @import("word16_v1/function_bus.zig");
    pub const binary = @import("word16_v1/binary.zig");
    pub const binary_lookup = @import("word16_v1/binary_lookup.zig");
    pub const binary_component = @import("word16_v1/binary_component.zig");
    pub const binary_source = @import("word16_v1/binary_source.zig");
    /// Inactive byte-interface SHIFT prototype; no CPU profile selects it.
    pub const shift_experiment = struct {
        pub const equations = @import("word16_v1/shift_byte.zig");
        pub const lookup = @import("word16_v1/shift_byte_lookup.zig");
        pub const component = @import("word16_v1/shift_byte_component.zig");
        pub const table_component = @import("word16_v1/shift_byte_table_component.zig");
    };
    /// Separate inactive Word16 candidate, sharing only pure chunk arithmetic.
    pub const shift_word_experiment = struct {
        pub const equations = @import("word16_v1/shift_word.zig");
        pub const lookup = @import("word16_v1/shift_word_lookup.zig");
        pub const table = @import("word16_v1/shift_word_table.zig");
        pub const component = @import("word16_v1/shift_word_component.zig");
        pub const table_component = @import("word16_v1/shift_word_table_component.zig");
    };
    /// Same Word16 truth schema, separate immutable packed-table shape.
    pub const shift_word_packed_experiment = struct {
        pub const equations = @import("word16_v1/shift_word.zig");
        pub const lookup = @import("word16_v1/shift_word_lookup.zig");
        pub const table = @import("word16_v1/shift_word_packed_table.zig");
        pub const component = @import("word16_v1/shift_word_component.zig");
        pub const source = @import("word16_v1/shift_word_source.zig");
        pub const table_component = @import("word16_v1/shift_word_packed_table_component.zig");
    };
    /// Qualified ALU diagnostic; not the production full-ISA protocol.
    pub const alu_experiment = struct {
        pub const equations = @import("word16_v1/alu.zig");
        pub const lookup = @import("word16_v1/alu_lookup.zig");
        pub const component = @import("word16_v1/alu_component.zig");
        pub const source = @import("word16_v1/alu_source.zig");
        pub const range_source = @import("word16_v1/u16_source.zig");
        pub const range_component = @import("word16_v1/u16_component.zig");
    };
};

/// Concrete register-only BINARY CPU; legacy profiles retain their encoding.
pub const word16_cpu = struct {
    pub const native_projection = @import("word16_cpu/native_projection.zig");
    pub const interaction = @import("word16_cpu/interaction.zig");
    pub const profile = @import("word16_cpu/profile.zig");
    pub const layout = @import("word16_cpu/layout.zig");
    pub const public = @import("word16_cpu/public.zig");
    pub const lookup = @import("word16_cpu/lookup.zig");
    pub const equations = @import("word16_cpu/equations.zig");
    pub const rom = @import("word16_cpu/rom.zig");
    pub const boundary = @import("word16_cpu/boundary.zig");
    pub const fixed = @import("word16_cpu/fixed.zig");
    pub const table = @import("word16_cpu/table.zig");
    pub const trace = @import("word16_cpu/trace.zig");
    pub const component = @import("word16_cpu/component.zig");
    pub const table_trace = @import("word16_cpu/table_trace.zig");
    pub const boundary_trace = @import("word16_cpu/boundary_trace.zig");
};

/// Concrete indexed-address ALU/binary diagnostic, not a runtime profile flag.
pub const word16_index_control = struct {
    pub const authority = @import("word16_index_control/authority.zig");
    pub const equations = @import("word16_index_control/equations.zig");
    pub const trace = @import("word16_index_control/trace.zig");
    pub const rom_trace = @import("word16_index_control/rom_trace.zig");
    pub const component = @import("word16_index_control/component.zig");
};
pub const word16_execution = @import("word16_execution/mod.zig");
