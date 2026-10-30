//! Finite group placement. Every first commitment precedes every interaction.
//! N=1/M=0 has Local11 geometry; N=1/M=1 has Mixed14 geometry. New group
//! transcript/statement identities remain mandatory in both cases.
const std = @import("std");
pub const VERSION: u32 = 1;
pub const MAX_MEMBERS: usize = 8;
pub const MAX_NATIVE_WIDE_MEMBERS: usize = 32;
/// V1 retains its original admission surface and exact transcript/keys. V2 is
/// an explicit finite native-only profile, never an implicit cap increase.
pub const Profile = enum(u32) { compact_v1 = 1, native_wide_v2 = 2 };
pub fn maxMembers(profile: Profile) usize {
    return if (profile == .compact_v1) MAX_MEMBERS else MAX_NATIVE_WIDE_MEMBERS;
}
pub fn domain(ch: *@import("stwo_core").proof_suites.Blake3.Channel, profile: Profile) void {
    recordDomain(ch, profile);
}
pub fn recordDomain(ch: anytype, profile: Profile) void {
    if (profile == .native_wide_v2) ch.mixU32s(&.{ 0x42384732, 2, MAX_NATIVE_WIDE_MEMBERS, @intFromEnum(profile) });
}
pub const Plan = struct {
    n: usize,
    m: usize,
    pub fn init(n: usize, m: usize) !Plan {
        return initWithProfile(n, m, .compact_v1);
    }
    pub fn initWithProfile(n: usize, m: usize, profile: Profile) !Plan {
        if (n == 0 or n > maxMembers(profile) or m > n or (profile == .native_wide_v2 and m != 0)) return error.InvalidEndpointGroupGeometry;
        const result = Plan{ .n = n, .m = m };
        if (result.traces() > 255 or result.partCount() > 256) return error.InvalidEndpointGroupGeometry;
        return result;
    }
    pub fn traces(self: Plan) usize {
        return 4 * self.n + 3 * self.m + 7;
    }
    pub fn firstRoots(self: Plan) usize {
        return 2 * self.n + 4 + self.m;
    }
    pub fn partCount(self: Plan) usize {
        return 2 * self.n + 3 + self.m;
    }
    pub fn native(self: Plan, i: usize) [3]usize {
        std.debug.assert(i < self.n);
        return .{ 0, 1 + i, 2 * self.n + 4 + self.m + i };
    }
    pub fn endpoint(self: Plan, i: usize) [3]usize {
        std.debug.assert(i < self.n);
        return .{ 0, self.n + 1 + i, 3 * self.n + 4 + self.m + i };
    }
    pub fn range(self: Plan) [3]usize {
        return .{ 0, 2 * self.n + 1, 4 * self.n + 4 + self.m };
    }
    pub fn program(self: Plan) [3]usize {
        return .{ 0, 2 * self.n + 2, 4 * self.n + 5 + self.m };
    }
    pub fn lookup(self: Plan) [3]usize {
        return .{ 0, 2 * self.n + 3, 4 * self.n + 6 + self.m };
    }
    pub fn caller(self: Plan, i: usize) [4]usize {
        std.debug.assert(i < self.m);
        return .{ 0, 2 * self.n + 4 + i, 4 * self.n + 7 + self.m + i, 4 * self.n + 7 + 2 * self.m + i };
    }
};

test "group finite profiles preserve compact8 and admit native32 within exact PCS caps" {
    try std.testing.expectEqual(@as(usize, 63), (try Plan.init(8, 8)).traces());
    try std.testing.expectError(error.InvalidEndpointGroupGeometry, Plan.init(9, 0));
    const wide = try Plan.initWithProfile(32, 0, .native_wide_v2);
    try std.testing.expectEqual(@as(usize, 135), wide.traces());
    try std.testing.expectEqual(@as(usize, 67), wide.partCount());
    try std.testing.expectError(error.InvalidEndpointGroupGeometry, Plan.initWithProfile(33, 0, .native_wide_v2));
    try std.testing.expectError(error.InvalidEndpointGroupGeometry, Plan.initWithProfile(16, 1, .native_wide_v2));
}
