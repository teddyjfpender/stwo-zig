//! Profile-local extension storage for one execution segment.

const std = @import("std");
const execution_profile = @import("../../isa/execution_profile.zig");
const call_buffer = @import("call_buffer.zig");
const keccakf_call_buffer = @import("keccakf_call_buffer.zig");
const keccakf_v1 = @import("keccakf_v1.zig");
const poseidon2_v1 = @import("poseidon2_v1.zig");
const secp256k1_recover_call_buffer = @import("secp256k1_recover_call_buffer.zig");
const secp256k1_recover_v1 = @import("secp256k1_recover_v1.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;

pub const ExternalCounts = struct {
    calls: usize,
    rows: usize,
};

pub const Poseidon2 = struct {
    calls: call_buffer.Builder,
    rows: poseidon2_v1.ExecutionRowsBuilder,
    external_step_origin: usize,

    pub fn init(allocator: std.mem.Allocator, budget: usize, origin: usize) !Poseidon2 {
        const limit = @min(budget, call_buffer.max_calls);
        return .{
            .calls = try .init(allocator, limit),
            .rows = try .init(allocator, limit),
            .external_step_origin = origin,
        };
    }

    pub fn deinit(self: *Poseidon2) void {
        self.calls.deinit();
        self.rows.deinit();
        self.* = undefined;
    }

    pub fn externalCounts(self: *const Poseidon2) !ExternalCounts {
        return .{ .calls = self.calls.len(), .rows = self.rows.len() };
    }

    pub fn validateExternalCount(self: *const Poseidon2, expected: usize) bool {
        const counts = self.externalCounts() catch return false;
        return counts.calls == expected and counts.rows == expected;
    }
};

pub const Keccakf = struct {
    calls: keccakf_call_buffer.Builder,
    rows: keccakf_v1.ExecutionRowsBuilder,
    external_step_origin: usize,

    pub fn init(allocator: std.mem.Allocator, budget: usize, origin: usize) !Keccakf {
        const limit = @min(budget, keccakf_call_buffer.max_calls);
        return .{
            .calls = try .init(allocator, limit),
            .rows = try .init(allocator, limit),
            .external_step_origin = origin,
        };
    }

    pub fn deinit(self: *Keccakf) void {
        self.calls.deinit();
        self.rows.deinit();
        self.* = undefined;
    }

    pub fn externalCounts(self: *const Keccakf) !ExternalCounts {
        return .{ .calls = self.calls.len(), .rows = self.rows.len() };
    }

    pub fn validateExternalCount(self: *const Keccakf, expected: usize) bool {
        const counts = self.externalCounts() catch return false;
        return counts.calls == expected and counts.rows == expected;
    }
};

pub const Ethereum = struct {
    keccakf_calls: keccakf_call_buffer.Builder,
    keccakf_rows: keccakf_v1.ExecutionRowsBuilder,
    signer_recovery_calls: secp256k1_recover_call_buffer.Builder,
    signer_recovery_rows: secp256k1_recover_v1.ExecutionRowsBuilder,
    external_step_origin: usize,

    pub fn init(allocator: std.mem.Allocator, budget: usize, origin: usize) !Ethereum {
        const keccakf_limit = @min(budget, keccakf_call_buffer.max_calls);
        const signer_limit = @min(budget, secp256k1_recover_call_buffer.max_calls);
        var keccakf_calls = try keccakf_call_buffer.Builder.init(allocator, keccakf_limit);
        errdefer keccakf_calls.deinit();
        var keccakf_rows = try keccakf_v1.ExecutionRowsBuilder.init(allocator, keccakf_limit);
        errdefer keccakf_rows.deinit();
        var signer_calls = try secp256k1_recover_call_buffer.Builder.init(
            allocator,
            signer_limit,
        );
        errdefer signer_calls.deinit();
        return .{
            .keccakf_calls = keccakf_calls,
            .keccakf_rows = keccakf_rows,
            .signer_recovery_calls = signer_calls,
            .signer_recovery_rows = try secp256k1_recover_v1.ExecutionRowsBuilder.init(
                allocator,
                signer_limit,
            ),
            .external_step_origin = origin,
        };
    }

    pub fn deinit(self: *Ethereum) void {
        self.keccakf_calls.deinit();
        self.keccakf_rows.deinit();
        self.signer_recovery_calls.deinit();
        self.signer_recovery_rows.deinit();
        self.* = undefined;
    }

    pub fn externalCounts(self: *const Ethereum) !ExternalCounts {
        return .{
            .calls = try std.math.add(
                usize,
                self.keccakf_calls.len(),
                self.signer_recovery_calls.len(),
            ),
            .rows = try std.math.add(
                usize,
                self.keccakf_rows.len(),
                self.signer_recovery_rows.len(),
            ),
        };
    }

    pub fn validateExternalCount(self: *const Ethereum, expected: usize) bool {
        if (self.keccakf_calls.len() != self.keccakf_rows.len() or
            self.signer_recovery_calls.len() != self.signer_recovery_rows.len())
        {
            return false;
        }
        const counts = self.externalCounts() catch return false;
        return counts.calls == expected and counts.rows == expected;
    }
};

pub const Empty = struct {
    pub fn init(_: std.mem.Allocator, _: usize, _: usize) !Empty {
        return .{};
    }
    pub fn deinit(_: *Empty) void {}

    pub fn externalCounts(_: *const Empty) !ExternalCounts {
        return .{ .calls = 0, .rows = 0 };
    }

    pub fn validateExternalCount(_: *const Empty, expected: usize) bool {
        return expected == 0;
    }
};

pub fn State(comptime profile: ExecutionProfile) type {
    return switch (profile) {
        .rv32im_zkvm_v1 => Empty,
        .rv32im_zkvm_poseidon2_v1 => Poseidon2,
        .rv32im_zkvm_keccakf_v1 => Keccakf,
        .rv32im_zkvm_ethereum_v1 => Ethereum,
    };
}
