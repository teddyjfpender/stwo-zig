//! One explicit native/recursive choice for the Ethereum fixed-program AIR.
//! The profile selects constraints and column layouts; callers must separately
//! admit the exact ELF-derived fixed table and independently derive Tree0.
const execution = @import("../isa/execution_profile.zig");
const program = @import("../air/program/interaction.zig");

pub const CircuitProfileV1 = enum(u16) {
    legacy_v4 = 0,
    fixed_program_narrow_v1 = 1,
    ethereum_v5 = 2,
    ethereum_local_zero_v1 = 3,

    pub fn requireExecution(self: @This(), selected: execution.ExecutionProfile) !void {
        if ((self == .ethereum_v5 or self == .ethereum_local_zero_v1) or (self != .legacy_v4 and selected != .rv32im_zkvm_ethereum_v1)) return error.EthereumCircuitProfileRequired;
    }
    /// Family11's explicit policy cannot activate the old native profile.
    pub fn requireCallerExecution(self: @This(), selected: execution.ExecutionProfile) !void {
        if ((self != .ethereum_v5 and self != .ethereum_local_zero_v1) or (selected != .rv32im_zkvm_ethereum_v1 and selected != .rv32im_zkvm_ethereum_sha_v1)) return error.EthereumCircuitProfileRequired;
    }

    pub fn localZeroCustody(self: @This()) bool {
        return self == .ethereum_local_zero_v1;
    }
    pub fn programPolicy(self: @This()) program.Policy {
        return switch (self) {
            .legacy_v4 => .sparse_merkle_v1,
            .fixed_program_narrow_v1, .ethereum_v5, .ethereum_local_zero_v1 => .fixed_decoded_table_v1,
        };
    }
    /// Execution-only singleton Keccak residency ceiling. The exact call count
    /// and canonical row geometry remain authenticated by the native profile.
    pub fn keccakMaximumLogSize(self: @This()) u32 {
        return switch (self) {
            .legacy_v4 => 16,
            .fixed_program_narrow_v1, .ethereum_v5, .ethereum_local_zero_v1 => 18,
        };
    }

    pub fn poseidonLayout(self: @This()) PoseidonLayoutV1 {
        return switch (self) {
            .legacy_v4 => .legacy_v1,
            .fixed_program_narrow_v1, .ethereum_v5, .ethereum_local_zero_v1 => .narrow_degree3_v1,
        };
    }
};
pub const PoseidonLayoutV1 = enum(u8) { legacy_v1 = 0, narrow_degree3_v1 = 1 };
