//! Receiver-derived geometry. Facts are row-major in physical circle storage:
//! index=(physical_row<<lane_log)|lane. Missing padded lanes are exactly0/1.
const std = @import("std");
const Geometry = @import("../../../word16_execution/geometry.zig");
const Types = @import("../types.zig");
pub const Origin = union(enum) { core: Geometry.Role, bridge: Types.Family, bulk: Types.BulkKind, dword: u1, sponge: Types.SpongeKind };
pub const MAX_LOCAL_TERMS: usize = 256;
/// Stable binary tags. v2's original tags/ordering never depend on enum growth.
pub fn originWords(origin: Origin) [2]u32 {
    return switch (origin) {
        .core => |v| .{ 0, @intFromEnum(v) },
        .bridge => |v| .{ 1, @intFromEnum(v) },
        .bulk => |v| .{ 2, @intFromEnum(v) },
        .dword => |v| .{ 3, v },
        .sponge => |v| .{ 4, @intFromEnum(v) },
    };
}
pub fn v3Instances(instances: []const Instance) bool {
    for (instances) |instance| switch (instance.origin) {
        .bulk, .dword, .sponge => return true,
        .bridge => |family| if (@intFromEnum(family) >= Types.V2_FAMILIES) {
            return true;
        },
        .core => {},
    };
    return false;
}
pub const Instance = struct {
    origin: Origin,
    row_log: u32,
    terms: u32,
    fixed_offset: usize,
    main_offset: usize,
    pub fn laneLog(self: Instance) !u32 {
        const limit: u32 = if (self.origin == .sponge) MAX_LOCAL_TERMS else 128;
        if (self.terms == 0 or self.terms > limit) return error.InvalidLocalGkrTerms;
        return @intCast(std.math.log2_int_ceil(u32, self.terms));
    }
    pub fn variables(self: Instance) !u32 {
        const v = try std.math.add(u32, self.row_log, try self.laneLog());
        if (self.row_log < 5 or self.row_log > 22 or v > 30) return error.InvalidLocalGkrGeometry;
        return v;
    }
    pub fn rows(self: Instance) !usize {
        _ = try self.variables();
        return @as(usize, 1) << @intCast(self.row_log);
    }
    pub fn facts(self: Instance) !usize {
        return @as(usize, 1) << @intCast(try self.variables());
    }
};
pub const PointSplit = struct { rows: []const @import("stwo_core").fields.om31.OM31, lanes: []const @import("stwo_core").fields.om31.OM31 };
/// A smaller instance uses the suffix of the COMMON GKR point before splitting
/// row-prefix/lane-suffix. Taking the first global row_log coordinates is wrong.
pub fn splitPoint(instance: Instance, common: []const @import("stwo_core").fields.om31.OM31, verified_variables: usize) !PointSplit {
    const n = try instance.variables();
    if (verified_variables != n or common.len < n) return error.LocalGkrPointGeometryMismatch;
    const local = common[common.len - n ..];
    return .{ .rows = local[0..instance.row_log], .lanes = local[instance.row_log..] };
}
