//! One explicit native/recursive choice for the Ethereum fixed-program AIR.
//! The profile selects constraints and column layouts; callers must separately
//! admit the exact ELF-derived fixed table and independently derive Tree0.
const execution = @import("stwo_riscv_isa").execution_profile;
const layout_mod = @import("circuit_layout.zig");

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
    pub fn layout(self: @This()) layout_mod.CircuitLayout {
        return switch (self) {
            .legacy_v4 => .ordinary_sparse,
            .fixed_program_narrow_v1, .ethereum_v5, .ethereum_local_zero_v1 => .fixed_decoded_narrow,
        };
    }
    pub fn programPolicy(self: @This()) @import("circuit_layout.zig").ProgramPolicy {
        return self.layout().programPolicy();
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
        return self.layout().poseidonLayout();
    }
};
pub const PoseidonLayoutV1 = layout_mod.PoseidonLayoutV1;

test "product circuit profile: original tags retain layout, Keccak and custody selection" {
    const std = @import("std");
    const profiles = [_]CircuitProfileV1{ .legacy_v4, .fixed_program_narrow_v1, .ethereum_v5, .ethereum_local_zero_v1 };
    for (profiles, 0..) |profile, tag| {
        try std.testing.expectEqual(@as(u16, @intCast(tag)), @intFromEnum(profile));
        try std.testing.expectEqual(if (tag == 0) layout_mod.CircuitLayout.ordinary_sparse else layout_mod.CircuitLayout.fixed_decoded_narrow, profile.layout());
        try std.testing.expectEqual(@as(u32, if (tag == 0) 16 else 18), profile.keccakMaximumLogSize());
        try std.testing.expectEqual(tag == 3, profile.localZeroCustody());
    }
    try std.testing.expect(PoseidonLayoutV1 == layout_mod.PoseidonLayoutV1);
}
