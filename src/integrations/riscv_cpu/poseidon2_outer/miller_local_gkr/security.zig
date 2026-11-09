//! Additive source-bound accounting for the isolated four-instance candidate.
//! Retain all original lookup/global/PCS/FRI/hash/recursion terms. This helper
//! neither admits a profile nor certifies whole-protocol security.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("authority.zig");
const N = @import("stwo_riscv_frontend").rv64_air.crypto.bn254_tower.narrow;
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const Policy = @import("../../word16_execution/om31_security_candidate.zig");
pub const Report = struct {
    accounting_profile: []const u8 = "op-miller-local-gkr-additive-source-bounds/v1",
    scopes: u32 = 0,
    instances: u32 = 0,
    max_variables: u32 = 0,
    max_positive_mass_per_scope: u64 = 0,
    sumcheck_rounds: u64 = 0,
    sumcheck_degree_weight: u128 = 0,
    instance_mix_degree_weight: u128 = 0,
    late_binding_degree_weight: u128 = 0,
    degenerate_point_degree_weight: u128 = 0,
    retired_interaction_cells: u64 = 0,
    added_interaction_cells: u64 = 0,
    security_qualified: bool = false,
    pub fn addTo(self: Report, ledger: *Policy.Ledger) !void {
        const terms = [_]struct { term: Policy.AlgebraicTerm, weight: u128 }{
            .{ .term = .gkr_sumcheck, .weight = self.sumcheck_degree_weight },
            .{ .term = .gkr_instance_mix, .weight = self.instance_mix_degree_weight },
            .{ .term = .gkr_late_binding, .weight = self.late_binding_degree_weight },
            .{ .term = .pole_events, .weight = self.degenerate_point_degree_weight },
        };
        for (terms) |term| {
            const at = @intFromEnum(term.term);
            ledger.degree_weight[at] = try std.math.add(u512, ledger.degree_weight[at], term.weight);
        }
    }
    pub fn augmentShape(self: Report, shape: *Bounds.Shape) void {
        if (self.scopes == 0) return;
        shape.max_local_instances = @max(shape.max_local_instances, 4);
        shape.max_gkr_variables = @max(shape.max_gkr_variables, self.max_variables);
    }
};
pub fn derive(geometries: []const Source.Geometry) !Report {
    if (geometries.len > 256) return error.TooManyMillerGkrScopes;
    var out = Report{};
    for (geometries) |geometry| {
        const instances = try geometry.instances();
        try N.micro.validateMass(geometry.calls);
        const conservative_positive = 2 * @as(u64, geometry.calls) * N.dag.STEPS * N.micro.RANGE_QUERIES;
        // Original source geometry already enforces stricter characteristic
        // bounds for both local range and fixed-fanout SSA integer masses.
        if (conservative_positive >= core.fields.m31.Modulus) return error.TowerMassBound;
        var variables: u32 = 0;
        var row_variables: u64 = 0;
        for (instances) |instance| {
            variables = @max(variables, try instance.variables());
            row_variables += instance.row_log;
        }
        const rounds = @as(u64, variables) * (variables - 1) / 2;
        out.scopes += 1;
        out.instances += 4;
        out.max_variables = @max(out.max_variables, variables);
        out.max_positive_mass_per_scope = @max(out.max_positive_mass_per_scope, conservative_positive);
        out.sumcheck_rounds += rounds;
        // Existing candidate ledger's conservative i*3, i+2 and i factors.
        out.sumcheck_degree_weight += 12 * @as(u128, rounds);
        out.instance_mix_degree_weight += 6 * @as(u128, variables);
        out.late_binding_degree_weight += 4;
        out.degenerate_point_degree_weight += 2 * @as(u128, row_variables);
        const cost = try Source.cost(geometry);
        // Global Wire and original field arithmetic remain. Do not subtract
        // their soundness terms merely because fewer columns are committed.
        out.retired_interaction_cells += cost.old_cells -| cost.new_cells;
        out.added_interaction_cells += cost.new_cells -| cost.old_cells;
    }
    return out;
}
test "Miller local GKR additive security keeps independent scope and original authority" {
    const geometry = Source.Geometry{ .calls = 1023, .first_id = 1, .frontier_log = 15, .arithmetic_log = 15 };
    const one = try derive(&.{geometry});
    const two = try derive(&.{ geometry, geometry });
    try std.testing.expectEqual(@as(u32, 22), one.max_variables);
    try std.testing.expectEqual(@as(u64, 231), one.sumcheck_rounds);
    try std.testing.expectEqual(@as(u128, 2772), one.sumcheck_degree_weight);
    try std.testing.expectEqual(@as(u128, 132), one.instance_mix_degree_weight);
    try std.testing.expectEqual(@as(u128, 4), one.late_binding_degree_weight);
    try std.testing.expectEqual(@as(u128, 120), one.degenerate_point_degree_weight);
    try std.testing.expectEqual(one.max_positive_mass_per_scope, two.max_positive_mass_per_scope);
    try std.testing.expectEqual(2 * one.sumcheck_degree_weight, two.sumcheck_degree_weight);
    var ledger = Policy.Ledger{ .degree_weight = @splat(0) };
    try two.addTo(&ledger);
    try ledger.requireRawModuloBits(128);
    try std.testing.expect(!one.security_qualified);
}
