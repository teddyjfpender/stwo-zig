//! Independent source roster, never classic Frame.origin aliases. All five
//! bridge roles and all three range/bitwise providers commit MAIN before draws.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("stwo_riscv_frontend").rv64_air.crypto.keccak_sponge.serialized;
pub const DOMAIN = "op-pure-p2-serialized-sponge-local-gkr/v1";
pub const production_admission_open = false;
pub const security_qualified = false;
pub const Role = enum(u32) { descriptor = 0x53500001, state = 0x53500002, header = 0x53500003, word = 0x53500004, lane = 0x53500005, u16 = 0x53500006, u8 = 0x53500007, and_ = 0x53500008 };
pub const roles = [_]Role{ .descriptor, .state, .header, .word, .lane, .u16, .u8, .and_ };
pub fn mainWidth(role: Role) usize {
    return switch (role) {
        .descriptor => S.descriptor.MAIN,
        .state => S.state.MAIN,
        .header => S.header.MAIN,
        .word => S.word.MAIN,
        .lane => S.lane.MAIN,
        else => 1,
    };
}
pub fn fixedWidth(role: Role) usize {
    return switch (role) {
        .and_ => 3,
        .u16, .u8 => 1,
        else => 3,
    };
}
pub fn localQueries(role: Role) u32 {
    return switch (role) {
        .descriptor => S.descriptor.LOCAL_QUERIES,
        .state => S.state.LOCAL_QUERIES,
        .header => S.header.LOCAL_QUERIES,
        .word => S.word.LOCAL_QUERIES,
        .lane => S.lane.LOCAL_QUERIES,
        else => 1,
    };
}
pub fn interactionWidth(role: Role) usize {
    return switch (role) {
        .descriptor => S.descriptor.OM31_INTER,
        .state => S.state.OM31_INTER,
        .header => S.header.OM31_INTER,
        .word => S.word.OM31_INTER,
        .lane => S.lane.OM31_INTER,
        else => 16,
    };
}
pub const Instance = struct {
    role: Role,
    row_log: u32,
    pub fn queries(self: Instance) u32 {
        return localQueries(self.role);
    }
    pub fn laneLog(self: Instance) u32 {
        return std.math.log2_int_ceil(u32, self.queries());
    }
    pub fn variables(self: Instance) !u32 {
        if (self.row_log < 5 or self.row_log > 22) return error.SpongeLocalGeometry;
        const n = self.row_log + self.laneLog();
        if (n > 30) return error.SpongeLocalGeometry;
        return n;
    }
    pub fn rows(self: Instance) !usize {
        _ = try self.variables();
        return @as(usize, 1) << @intCast(self.row_log);
    }
    pub fn facts(self: Instance) !usize {
        return @as(usize, 1) << @intCast(try self.variables());
    }
};
pub const Geometry = struct {
    calls: u32,
    permutations: u32,
    first_id: u32,
    /// Logs are independently derived, never producer supplied.
    pub fn instances(self: Geometry) ![8]Instance {
        if (self.calls == 0 or self.permutations < self.calls or self.first_id == 0 or @as(u64, self.first_id) + self.permutations >= core.fields.m31.Modulus) return error.SpongeLocalGeometry;
        const counts = [_]u64{ self.calls, @as(u64, self.calls) * 25, self.permutations, @as(u64, self.permutations) * 18, @as(u64, self.permutations) * 25 };
        var out: [8]Instance = undefined;
        for (roles, &out, 0..) |role, *instance, i| {
            const log: u32 = if (i < 5) @max(5, std.math.log2_int_ceil(u64, counts[i] + 1)) else if (role == .u8) 8 else 16;
            instance.* = .{ .role = role, .row_log = log };
            _ = try instance.variables();
        }
        var local_mass: u64 = 0;
        for (out[0..5]) |instance| local_mass = try std.math.add(u64, local_mass, try std.math.mul(u64, try instance.rows(), instance.queries()));
        // Includes positive and negative provider mass. Characteristic wrap
        // must not hide a complete integer multiplicity difference.
        if (local_mass * 2 >= core.fields.m31.Modulus) return error.SpongeLocalMassBound;
        return out;
    }
    pub fn activeRows(self: Geometry, role: Role) u64 {
        return switch (role) {
            .descriptor => self.calls,
            .state => @as(u64, self.calls) * 25,
            .header => self.permutations,
            .word => @as(u64, self.permutations) * 18,
            .lane => @as(u64, self.permutations) * 25,
            .u8 => 256,
            else => 65536,
        };
    }
};
test "serialized sponge authority derives ordered role geometry and bounds" {
    const instances = try (Geometry{ .calls = 74, .permutations = 210, .first_id = 3668 }).instances();
    for (instances, [_]u32{ 7, 11, 8, 12, 13, 16, 8, 16 }) |instance, log| try std.testing.expectEqual(log, instance.row_log);
    var width: usize = 0;
    for (instances[0..5]) |instance| width += mainWidth(instance.role) + fixedWidth(instance.role) + interactionWidth(instance.role);
    try std.testing.expectEqual(@as(usize, 465), width);
    try std.testing.expectError(error.SpongeLocalGeometry, (Geometry{ .calls = 1, .permutations = 0, .first_id = 1 }).instances());
    try std.testing.expectError(error.SpongeLocalGeometry, (Geometry{ .calls = 1, .permutations = 1, .first_id = core.fields.m31.Modulus - 1 }).instances());
    try std.testing.expectError(error.SpongeLocalGeometry, (Geometry{ .calls = 200000, .permutations = 200000, .first_id = 1 }).instances());
}
