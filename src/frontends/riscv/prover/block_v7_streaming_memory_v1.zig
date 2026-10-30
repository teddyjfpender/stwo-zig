//! Execution-driver ownership for either original memory layout. The opt-in
//! cohort path externally sorts exact transitions, including terminal reads,
//! then spills bounded original components before drawing the common epoch.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("block_v7_execution_epoch_v1.zig");
const Native = @import("block_v7_native_checkpoint_v1.zig");
const Joint = @import("block_v7_memory_joint_proof_v1.zig");
const Cohort = @import("block_v7_memory_cohorts_v1.zig");
const Spool = @import("block_v7_transition_spool_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const Event = @import("../air/block/memory_transition.zig").Transition;
pub const Events = struct {
    a: std.mem.Allocator,
    max: usize,
    values: std.ArrayList(Event) = .empty,
    spool: ?Spool.Spool = null,
    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, maximum: usize, chunk: ?usize) !Events {
        return .{ .a = a, .max = maximum, .spool = if (chunk) |n| try Spool.Spool.init(a, dir, n, try std.math.add(u64, maximum, 13)) else null };
    }
    fn put(context: *anyopaque, event: Event) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.count() >= self.max) return error.V7ExecutionEventLimit;
        if (self.spool) |*spool| try spool.append(event) else try self.values.append(self.a, event);
    }
    pub fn sink(self: *@This()) Native.EventSink {
        return .{ .context = self, .put = put };
    }
    pub fn count(self: *const Events) u64 {
        return if (self.spool) |*spool| spool.count() else self.values.items.len;
    }
    pub fn storageBytes(self: *const Events) usize {
        return if (self.spool) |*spool| spool.statistics().sort_buffer_bytes else self.values.capacity * @sizeOf(Event);
    }
    pub fn deinit(self: *Events) void {
        if (self.spool) |*spool| spool.deinit();
        self.spool = null;
        self.values.deinit(self.a);
        self.values = .empty;
    }
};
pub const Proof = union(enum) {
    joint: Joint.Proof,
    cohorts: Cohort.Result,
    pub fn deinit(self: *Proof) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
        self.* = undefined;
    }
    pub fn input(self: *const Proof) @import("block_v7_execution_receiver_v1.zig").MemoryProof {
        return switch (self.*) {
            .joint => |*value| .{ .joint = value },
            .cohorts => |*value| .{ .separate = &value.bundle },
        };
    }
};
pub const Stage = struct {
    dir: std.fs.Dir,
    value: union(enum) { joint: *Joint.For(Cpu).Stage, cohorts: Cohort.Owner },
    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, policy: Policy, events: *Events, high: u8, per: u32, joint: Joint.Limits, cohorts: ?Cohort.Limits) !Stage {
        if (cohorts) |limits| {
            const spool = if (events.spool) |*s| s else return error.InvalidV7MemoryStage;
            const plan = try @import("block_v7_terminal_protocol_v1.zig").Plan.init(policy.terminal);
            for (0..13) |i| try spool.append(try plan.transition(i, high));
            var reader = try spool.finish();
            defer reader.deinit();
            return .{ .dir = dir, .value = .{ .cohorts = try Cohort.Owner.collectSorted(a, dir, policy, &reader, spool.count(), per, high, limits) } };
        }
        if (events.spool != null) return error.InvalidV7MemoryStage;
        return .{ .dir = dir, .value = .{ .joint = try Joint.For(Cpu).Stage.init(a, policy, events.values.items, high, per, joint) } };
    }
    pub fn deinit(self: *Stage) void {
        switch (self.value) {
            .joint => |value| value.deinit(),
            .cohorts => |*value| {
                for (0..value.ram.len + 3) |i| {
                    var buf: [64]u8 = undefined;
                    self.dir.deleteFile(Cohort.fileName(&buf, i) catch unreachable) catch {};
                }
                value.deinit();
            },
        }
        self.* = undefined;
    }
    pub fn entries(self: *const Stage, a: std.mem.Allocator) ![]E.Entry {
        return switch (self.value) {
            .cohorts => |*value| value.entries(a),
            .joint => |value| a.dupe(E.Entry, &.{try value.entry()}),
        };
    }
    pub fn checkpointBytes(self: *const Stage) u64 {
        return switch (self.value) {
            .joint => 0,
            .cohorts => |value| value.written_bytes,
        };
    }
    pub fn prove(self: *Stage, epoch: E.Epoch, roster: []const E.Entry) !Proof {
        return self.proveWithExecutor(epoch, roster, null);
    }
    pub fn proveWithExecutor(self: *Stage, epoch: E.Epoch, roster: []const E.Entry, executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor) !Proof {
        return switch (self.value) {
            .joint => |value| blk: {
                value.scheme.quotient_executor = executor;
                break :blk .{ .joint = try value.prove(epoch, roster) };
            },
            .cohorts => |*value| .{ .cohorts = try value.proveWithExecutor(self.dir, epoch, roster, executor) },
        };
    }
};
