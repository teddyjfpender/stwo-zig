//! Arena-bound device path expansion. No host path/digest reconstruction.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Paths = @import("resident_parent_child_paths_v1.zig");
const Packet = @import("resident_parent_child_packet_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 53248;
pub const Slot = enum(u32) { trees, columns, output };
pub fn id(s: Slot) u32 {
    return FIRST_ID + @intFromEnum(s);
}
extern fn stwo_parent_child_paths_v1([*]const Paths.Tree, u32, [*]const Paths.Column, u32, [*]const u32, u32, [*]const u32, u32, [*]const u32, u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
pub const Plan = struct {
    layout: *const Paths.Owned,
    packet: *const Packet.Owned,
    pub fn requirements(self: Plan, a: std.mem.Allocator) ![]cuda.runtime.arena.Requirement {
        const sizes = [_]usize{ self.layout.trees.len * @sizeOf(Paths.Tree) / 4, @max(3, self.layout.columns.len * @sizeOf(Paths.Column) / 4), self.layout.output_words };
        const out = try a.alloc(cuda.runtime.arena.Requirement, 3);
        errdefer a.free(out);
        for (sizes, out, 0..) |n, *v, i| {
            if (n == 0 or n > std.math.maxInt(u32)) return error.ResidentChildPathLimit;
            v.* = .{ .id = FIRST_ID + @as(u32, @intCast(i)), .words = n, .alignment_words = 64, .live_from = .ingress, .live_through = .trace_generation };
        }
        return out;
    }
};
pub const Bound = struct {
    plan: Plan,
    slots: [3]common.Words,
    primed: bool = false,
    executed: bool = false,
    pub fn init(plan: Plan, tx: anytype) !Bound {
        var self = Bound{ .plan = plan, .slots = undefined };
        inline for (std.meta.tags(Slot), 0..) |s, i| self.slots[i] = try tx.slot(id(s));
        return self;
    }
    pub fn output(self: *const Bound) common.Words {
        return self.slots[2];
    }
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.InvalidResidentChildPaths;
        try common.requireStage(session, .ingress);
        const trees = try self.slots[0].cast(Paths.Tree);
        if (trees.len != self.plan.layout.trees.len) return error.InvalidResidentChildPaths;
        try session.context.uploadSlice(Paths.Tree, trees, self.plan.layout.trees);
        if (self.plan.layout.columns.len != 0) {
            const columns = try self.slots[1].cast(Paths.Column);
            if (columns.len != self.plan.layout.columns.len) return error.InvalidResidentChildPaths;
            try session.context.uploadSlice(Paths.Column, columns, self.plan.layout.columns);
        }
        self.primed = true;
    }
    pub fn execute(self: *Bound, session: anytype, raw_packet: common.Words, raw_queries: common.Words, resident_values: common.Words, status: common.Words) !void {
        if (!self.primed or self.executed or raw_packet.len != self.plan.packet.words.len or raw_queries.len != self.plan.packet.query_count or status.len != 1 or resident_values.len > std.math.maxInt(u32)) return error.InvalidResidentChildPaths;
        try common.requireStage(session, .trace_generation);
        const t = try self.slots[0].cast(Paths.Tree);
        const c = try self.slots[1].cast(Paths.Column);
        try common.record(session, .trace_generation, stwo_parent_child_paths_v1(try session.context.deviceSlicePointer(Paths.Tree, t, t.len), @intCast(t.len), try session.context.deviceSlicePointer(Paths.Column, c, c.len), @intCast(self.plan.layout.columns.len), try ptr(session, raw_packet), @intCast(raw_packet.len), try ptr(session, raw_queries), @intCast(raw_queries.len), try ptr(session, resident_values), @intCast(resident_values.len), try ptr(session, self.output()), @intCast(self.output().len), try ptr(session, status), session.context.stream));
        self.executed = true;
    }
};
fn ptr(s: anytype, w: common.Words) ![*]u32 {
    return s.context.deviceSlicePointer(u32, w, w.len);
}

fn forceNative(b: *Bound, s: *cuda.runtime.NativeSession, w: common.Words) !void {
    try b.prime(s);
    try b.execute(s, w, w, w, w);
}
test "resident child paths runtime native full instantiation" {
    std.mem.doNotOptimizeAway(&forceNative);
}
