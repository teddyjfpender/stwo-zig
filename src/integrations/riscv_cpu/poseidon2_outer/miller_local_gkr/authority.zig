//! Opt-in Miller local-GKR source roster. No production admission is granted.
//! Four instances share one child proof; SSA closes across its two instances.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = A.crypto.bn254_tower.narrow;
const S = N.source;
pub const production_admission_open = false;
pub const security_qualified = false;
pub const DOMAIN = "op-pure-p2-miller-local-gkr/v1";
pub const Role = enum { bytes, carries, arithmetic_ssa, frontier_ssa };
pub const Instance = struct {
    role: Role,
    row_log: u32,
    pub fn queries(self: Instance) u32 {
        return switch (self.role) {
            .bytes => 98,
            .carries => 32,
            .arithmetic_ssa => 8,
            .frontier_ssa => 1,
        };
    }
    pub fn sourceRole(self: Instance) S.Role {
        return if (self.role == .frontier_ssa) .frontier else .arithmetic;
    }
    pub fn laneLog(self: Instance) u32 {
        return @intCast(std.math.log2_int_ceil(u32, self.queries()));
    }
    pub fn variables(self: Instance) !u32 {
        if (self.row_log < S.minimumLog(self.sourceRole()) or self.row_log > S.MAX_LOG) return error.MillerLocalGeometry;
        const n = try std.math.add(u32, self.row_log, self.laneLog());
        if (n > 30) return error.MillerLocalGeometry;
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
    first_id: u32,
    frontier_log: u32,
    arithmetic_log: u32,
    pub fn instances(self: Geometry) ![4]Instance {
        try S.validate(.frontier, .{ .calls = self.calls, .first_id = self.first_id }, self.frontier_log);
        try S.validate(.arithmetic, .{ .calls = self.calls, .first_id = self.first_id }, self.arithmetic_log);
        const out = [4]Instance{
            .{ .role = .bytes, .row_log = self.arithmetic_log },
            .{ .role = .carries, .row_log = self.arithmetic_log },
            .{ .role = .arithmetic_ssa, .row_log = self.arithmetic_log },
            .{ .role = .frontier_ssa, .row_log = self.frontier_log },
        };
        for (out) |instance| _ = try instance.variables();
        return out;
    }
};
pub const Cost = struct {
    old_interaction_columns: usize = 576,
    new_interaction_columns: usize = 80,
    old_cells: u64 = 0,
    new_cells: u64 = 0,
    padded_facts: u64 = 0,
    checkpoint_working_bytes: u64 = 0,
};
pub fn cost(g: Geometry) !Cost {
    const instances = try g.instances();
    const f: u64 = @as(u64, 1) << @intCast(g.frontier_log);
    const a: u64 = @as(u64, 1) << @intCast(g.arithmetic_log);
    var result = Cost{
        .old_cells = f * (S.FIXED + 33 + 16) + a * (S.FIXED + 370 + 560),
        .new_cells = f * (S.FIXED + 33 + 24) + a * (S.FIXED + 370 + 56),
    };
    for (instances) |instance| result.padded_facts += try instance.facts();
    result.checkpoint_working_bytes = result.padded_facts * @import("../../word16_global_execution/services/gkr_local/resource.zig").SOURCE_CHECKPOINT_BYTES_PER_FACT;
    return result;
}
test "Miller local GKR source roster and cost are independently sized and bounded" {
    const c = try cost(.{ .calls = 22185, .first_id = 1, .frontier_log = 19, .arithmetic_log = 20 });
    try std.testing.expectEqual(@as(usize, 576), c.old_interaction_columns);
    try std.testing.expectEqual(@as(usize, 80), c.new_interaction_columns);
    try std.testing.expectEqual(@as(u64, 176685056), c.padded_facts);
    try std.testing.expect(c.new_cells < c.old_cells);
    try std.testing.expect(c.checkpoint_working_bytes > 8 << 30);
    try std.testing.expectError(error.TowerGeometry, (Geometry{ .calls = 22185, .first_id = 1, .frontier_log = 18, .arithmetic_log = 20 }).instances());
    try std.testing.expectError(error.TowerMassBound, (Geometry{ .calls = core.fields.m31.Modulus, .first_id = 1, .frontier_log = 22, .arithmetic_log = 22 }).instances());
}
