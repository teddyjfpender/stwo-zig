//! One explicit native/recursive choice for the Ethereum fixed-program AIR.
//! The profile selects constraints and column layouts; callers must separately
//! admit the exact ELF-derived fixed table and independently derive Tree0.
const execution = @import("../isa/execution_profile.zig");
const program = @import("../air/program/interaction.zig");

pub const CircuitProfileV1 = enum(u16) {
    legacy_v4 = 0,
    fixed_program_narrow_v1 = 1,

    pub fn requireExecution(self: @This(), selected: execution.ExecutionProfile) !void {
        if (self != .legacy_v4 and selected != .rv32im_zkvm_ethereum_v1) return error.EthereumCircuitProfileRequired;
    }
    pub fn programPolicy(self: @This()) program.Policy {
        return switch (self) {
            .legacy_v4 => .sparse_merkle_v1,
            .fixed_program_narrow_v1 => .fixed_decoded_table_v1,
        };
    }
    /// Execution-only singleton Keccak residency ceiling. The exact call count
    /// and canonical row geometry remain authenticated by the native profile.
    pub fn keccakMaximumLogSize(self: @This()) u32 {
        return switch (self) {
            .legacy_v4 => 16,
            .fixed_program_narrow_v1 => 18,
        };
    }

    pub fn poseidonLayout(self: @This()) PoseidonLayoutV1 {
        return switch (self) {
            .legacy_v4 => .legacy_v1,
            .fixed_program_narrow_v1 => .narrow_degree3_v1,
        };
    }
};
pub const PoseidonLayoutV1 = enum(u8) { legacy_v1 = 0, narrow_degree3_v1 = 1 };
