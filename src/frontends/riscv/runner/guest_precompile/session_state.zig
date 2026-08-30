//! Profile-local extension storage for one execution segment.

const std = @import("std");
const execution_profile = @import("../../isa/execution_profile.zig");
const call_buffer = @import("call_buffer.zig");
const keccakf_call_buffer = @import("keccakf_call_buffer.zig");
const keccakf_v1 = @import("keccakf_v1.zig");
const poseidon2_v1 = @import("poseidon2_v1.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;

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
};

pub const Empty = struct {
    pub fn init(_: std.mem.Allocator, _: usize, _: usize) !Empty {
        return .{};
    }
    pub fn deinit(_: *Empty) void {}
};

pub fn State(comptime profile: ExecutionProfile) type {
    return switch (profile) {
        .rv32im_zkvm_v1 => Empty,
        .rv32im_zkvm_poseidon2_v1 => Poseidon2,
        .rv32im_zkvm_keccakf_v1 => Keccakf,
    };
}
