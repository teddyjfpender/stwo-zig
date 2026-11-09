//! Explicit CPU flavor: real legacy instances plus one typed sponge frontier.
//! No classic Frame.origin is reused to disguise the new source equations.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../word16_global_execution/services/roster.zig");
const Old = @import("../../word16_global_execution/services/gkr_local/frame.zig");
const S = @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge.serialized.frontier;
pub const production_admission_open = false;
pub const DOMAIN = "op-pure-p2-sponge-frontier-cpu/v1";
pub const MAX_LOCAL_TERMS = Old.MAX_LOCAL_TERMS;
pub const Frontier = struct { row_log: u32, fixed_offset: usize, main_offset: usize };
pub const Instance = union(enum) {
    legacy: Old.Instance,
    frontier: Frontier,
    pub fn rowLog(self: Instance) u32 {
        return switch (self) {
            .legacy => |v| v.row_log,
            .frontier => |v| v.row_log,
        };
    }
    pub fn queries(self: Instance) u32 {
        return switch (self) {
            .legacy => |v| v.terms,
            .frontier => S.LOCAL_QUERIES,
        };
    }
    pub fn laneLog(self: Instance) !u32 {
        return switch (self) {
            .legacy => |v| v.laneLog(),
            .frontier => 2,
        };
    }
    pub fn variables(self: Instance) !u32 {
        if (self.rowLog() < 5 or self.rowLog() > 22) return error.SpongeCpuGeometry;
        const n = try std.math.add(u32, self.rowLog(), try self.laneLog());
        if (n > 30) return error.SpongeCpuGeometry;
        return n;
    }
    pub fn rows(self: Instance) !usize {
        _ = try self.variables();
        return @as(usize, 1) << @intCast(self.rowLog());
    }
    pub fn facts(self: Instance) !usize {
        return @as(usize, 1) << @intCast(try self.variables());
    }
    pub fn tag(self: Instance) [3]u32 {
        return switch (self) {
            .legacy => |v| blk: {
                const words = Old.originWords(v.origin);
                break :blk .{ 0, words[0], words[1] };
            },
            .frontier => .{ 1, 0x53504746, 1 },
        };
    }
    pub fn fixedOffset(self: Instance) usize {
        return switch (self) {
            .legacy => |v| v.fixed_offset,
            .frontier => |v| v.fixed_offset,
        };
    }
    pub fn mainOffset(self: Instance) usize {
        return switch (self) {
            .legacy => |v| v.main_offset,
            .frontier => |v| v.main_offset,
        };
    }
};
/// Common-point suffix semantics match the original mixed-height protocol.
pub fn splitPoint(instance: Instance, common: []const core.fields.om31.OM31, verified_variables: usize) !Old.PointSplit {
    const n = try instance.variables();
    if (verified_variables != n or common.len < n) return error.LocalGkrPointGeometryMismatch;
    const point = common[common.len - n ..];
    return .{ .rows = point[0..instance.rowLog()], .lanes = point[instance.rowLog()..] };
}
pub const Roster = struct {
    allocator: std.mem.Allocator,
    legacy: []Old.Instance,
    instances: []Instance,
    pub fn init(a: std.mem.Allocator, setup: *const R.CpuSetup, calls: u32, log: u32, epoch: u32, ordinal: u32) !Roster {
        try S.validatePublic(calls, log, epoch, ordinal);
        // The wide bridge must be physically absent, not merely zero-weight.
        if (!setup.op_only or setup.bridges.sponge.any()) return error.SpongeCpuRequiresDetachedSetup;
        const legacy = try @import("../../word16_global_execution/services/gkr_local/roster.zig").fromOpSetup(a, setup);
        errdefer a.free(legacy);
        const instances = try a.alloc(Instance, legacy.len + 1);
        errdefer a.free(instances);
        for (legacy, instances[0..legacy.len]) |v, *out| {
            if (v.origin == .sponge) return error.SpongeCpuRequiresDetachedSetup;
            out.* = .{ .legacy = v };
        }
        instances[legacy.len] = .{ .frontier = .{ .row_log = log, .fixed_offset = setup.columnCount(0), .main_offset = setup.columnCount(1) } };
        return .{ .allocator = a, .legacy = legacy, .instances = instances };
    }
    pub fn deinit(self: *Roster) void {
        self.allocator.free(self.instances);
        self.allocator.free(self.legacy);
        self.* = undefined;
    }
};
test "sponge CPU typed source tags and global lifted suffix" {
    const O = core.fields.om31.OM31;
    const small = Instance{ .frontier = .{ .row_log = 5, .fixed_offset = 10, .main_offset = 20 } };
    try std.testing.expectEqual(@as(u32, 7), try small.variables());
    try std.testing.expectEqual(@as(usize, 128), try small.facts());
    var common: [11]O = undefined;
    for (&common, 0..) |*v, i| v.* = O.fromBase(core.fields.m31.M31.fromCanonical(@intCast(i)));
    const split = try splitPoint(small, &common, 7);
    try std.testing.expectEqualSlices(O, common[4..9], split.rows);
    try std.testing.expectEqualSlices(O, common[9..], split.lanes);
    try std.testing.expectError(error.LocalGkrPointGeometryMismatch, splitPoint(small, &common, 8));
    const real = Instance{ .legacy = .{ .origin = .{ .core = .cpu }, .row_log = 5, .terms = 15, .fixed_offset = 0, .main_offset = 0 } };
    try std.testing.expect(!std.meta.eql(small.tag(), real.tag()));
}
