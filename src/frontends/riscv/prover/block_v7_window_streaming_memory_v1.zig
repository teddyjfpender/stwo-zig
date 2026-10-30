//! Nonterminal wrapper around the same resident transition collector. Only
//! the explicitly versioned window memory proof is produced here.
const std = @import("std");
const E = @import("block_v7_execution_epoch_v1.zig");
const Joint = @import("block_v7_window_memory_joint_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
pub const Events = @import("block_v7_streaming_memory_v1.zig").Events;
pub const Proof = struct {
    value: Joint.Proof,
    pub fn deinit(self: *Proof) void {
        self.value.deinit();
    }
    pub fn input(self: *const Proof) @import("block_v7_execution_receiver_v1.zig").MemoryProof {
        return .{ .window_joint = &self.value };
    }
};
pub const Stage = struct {
    value: *Joint.For(Cpu).Stage,
    pub fn init(a: std.mem.Allocator, _: std.fs.Dir, policy: @import("block_v7_execution_policy_v1.zig").Policy, events: *Events, high: u8, per: u32, limits: Joint.Limits, cohorts: ?@import("block_v7_memory_cohorts_v1.zig").Limits) !Stage {
        if (cohorts != null or events.spool != null) return error.UnsupportedV7WindowCohorts;
        return .{ .value = try Joint.For(Cpu).Stage.init(a, policy, events.values.items, high, per, limits) };
    }
    pub fn deinit(self: *Stage) void {
        self.value.deinit();
        self.* = undefined;
    }
    pub fn entries(self: *const Stage, a: std.mem.Allocator) ![]E.Entry {
        return a.dupe(E.Entry, &.{try self.value.entry()});
    }
    pub fn checkpointBytes(_: *const Stage) u64 {
        return 0;
    }
    pub fn prove(self: *Stage, epoch: E.Epoch, roster: []const E.Entry) !Proof {
        return self.proveWithExecutor(epoch, roster, null);
    }
    pub fn proveWithExecutor(self: *Stage, epoch: E.Epoch, roster: []const E.Entry, executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor) !Proof {
        self.value.scheme.quotient_executor = executor;
        return .{ .value = try self.value.prove(epoch, roster) };
    }
};
