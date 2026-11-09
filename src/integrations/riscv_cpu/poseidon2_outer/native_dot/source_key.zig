//! Source-owned R7 authority factories. No root receiver consumes a raw key or
//! a proposed proof root as authority; calls below independently replay source.
const std = @import("std");
const K = @import("outer_authority.zig").Key;
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
pub const SourceKey = struct {
    authority: K,
    binding: union(enum) { cpu: struct { ordinal: u32, native_identity: [32]u8 }, fold: [2][32]u8 },
    pub fn deinit(self: *@This()) void {
        self.authority.deinit();
        self.* = undefined;
    }
    pub fn initCpu(a: std.mem.Allocator, source: CPU.ShapeView) !SourceKey {
        _ = source.op_span orelse return error.R7RequiresOpCpuSource;
        try source.key.requireForOp(source.setup, source.key.profile);
        if (source.expected.kind != .cpu or source.expected.profile != source.key.profile or !std.mem.eql(u8, &source.expected.fixed_identity, &source.key.identity)) return error.R7CpuSourceAuthority;
        if (source.values.cap_log != 0) return error.R7CpuSourceCapVariant;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), source.setup, source.key.profile.config());
        var normalized = source;
        normalized.shape = &shape;
        var trace = try @import("cpu_source.zig").build(a, normalized, true, null);
        defer trace.deinit();
        return .{ .authority = try K.init(a, &trace, source.key.profile), .binding = .{ .cpu = .{ .ordinal = source.expected.ordinal, .native_identity = source.key.identity } } };
    }
    pub fn initFold(a: std.mem.Allocator, profile: @import("../op_profile.zig").Profile, left: *const SourceKey, right: *const SourceKey) !SourceKey {
        if (left.authority.core.base.profile != profile or right.authority.core.base.profile != profile) return error.R7FoldProfileMismatch;
        var trace = try (@import("fold.zig").TraceSource{ .keys = .{ &left.authority, &right.authority } }).build(a);
        defer trace.deinit();
        return .{ .authority = try K.init(a, &trace, profile), .binding = .{ .fold = .{ left.authority.core.base.identity, right.authority.core.base.identity } } };
    }
};
