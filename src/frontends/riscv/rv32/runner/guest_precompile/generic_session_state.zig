//! Generic profile-local storage; product state selection lives above the children.
const std = @import("std");
const call_buffer = @import("stwo_riscv_precompiles").runner.call_buffer;
const keccakf_call_buffer = @import("stwo_riscv_precompiles").runner.keccakf_call_buffer;
const keccakf_v1 = @import("keccakf.zig");
const poseidon2_v1 = @import("poseidon2.zig");
pub const ExternalCounts = @import("stwo_riscv_isa").machine.execution_boundary.ExternalCounts;

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
