//! Additive schema2 bookkeeping, not a certificate or a replacement for the
//! existing source lookup/global/PCS/FRI/hash/recursion analysis. The old lookup
//! report remains conservative for the SAME local fraction tuples and weights.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("authority.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const Policy = @import("../../word16_execution/om31_security_candidate.zig");
pub const ACCOUNTING_PROFILE = "op-truth-local-gkr-additive-source-bounds/v1";
pub const Report = struct {
    accounting_profile: []const u8 = ACCOUNTING_PROFILE,
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
    security_qualified: bool = false,
    /// Each local scope has independent challenges. Do not sum its integer mass
    /// across scopes and reject an otherwise valid block at the characteristic.
    pub fn addTo(self: Report, ledger: *Policy.Ledger) !void {
        const Term = Policy.AlgebraicTerm;
        for ([_]struct { term: Term, weight: u128 }{ .{ .term = .gkr_sumcheck, .weight = self.sumcheck_degree_weight }, .{ .term = .gkr_instance_mix, .weight = self.instance_mix_degree_weight }, .{ .term = .gkr_late_binding, .weight = self.late_binding_degree_weight }, .{ .term = .pole_events, .weight = self.degenerate_point_degree_weight } }) |item| ledger.degree_weight[@intFromEnum(item.term)] = try std.math.add(u512, ledger.degree_weight[@intFromEnum(item.term)], item.weight);
    }
    /// Complete the source-shape maxima that classic truth did not need for a
    /// GKR child. Existing column/constraint/mask/degree caps remain conservative:
    /// only classic local accumulators are replaced, by three binding residuals.
    pub fn augmentShape(self: Report, shape: *Bounds.Shape) void {
        if (self.scopes == 0) return;
        shape.max_local_instances = @max(shape.max_local_instances, 3);
        shape.max_gkr_variables = @max(shape.max_gkr_variables, self.max_variables);
    }
};
pub fn eligible(d: Wire.TruthDeclaration) bool {
    return d.family == .keccak or ((d.family == .add or d.family == .double) and d.logs[1] != 0);
}
pub fn derive(declarations: []const Wire.TruthDeclaration) !Report {
    if (declarations.len > 256) return error.TooManyTruthLocalGkrScopes;
    var out = Report{};
    for (declarations) |d| {
        if (!eligible(d)) continue;
        if (d.calls == 0) return error.EmptyOpTruth;
        const shapes = try A.shapesForDeclaration(d); // Original program/span/policy checks, no allocation.
        var variables: u32 = 0;
        var positive: u64 = 0;
        var row_variables: u64 = 0;
        for (shapes, 0..) |shape, index| {
            const instance = shape.instance();
            variables = @max(variables, try instance.variables());
            row_variables += instance.row_log;
            if (index == 0 or (d.family != .keccak and index == 1)) positive = try std.math.add(u64, positive, try std.math.mul(u64, try instance.rows(), instance.queries));
        }
        if (positive >= core.fields.m31.Modulus) return error.TruthGkrMassExceeded;
        out.max_positive_mass_per_scope = @max(out.max_positive_mass_per_scope, positive);
        out.max_variables = @max(out.max_variables, variables);
        out.scopes += 1;
        out.instances += 3;
        const rounds = @as(u64, variables) * (variables - 1) / 2;
        out.sumcheck_rounds = try std.math.add(u64, out.sumcheck_rounds, rounds);
        // Existing OM31 candidate ledger's conservative p*i*3*v*(v-1)/2,
        // p*(i+2)*v and p*i formulas, applied per source-owned three-role proof.
        out.sumcheck_degree_weight = try std.math.add(u128, out.sumcheck_degree_weight, 9 * @as(u128, rounds));
        out.instance_mix_degree_weight = try std.math.add(u128, out.instance_mix_degree_weight, 5 * @as(u128, variables));
        out.late_binding_degree_weight += 3;
        // Degenerate MLE coordinates fail closed; retaining their union term is
        // conservative and records the completeness condition explicitly.
        out.degenerate_point_degree_weight = try std.math.add(u128, out.degenerate_point_degree_weight, 2 * @as(u128, row_variables));
        const cost = try A.cost(shapes);
        out.retired_interaction_cells = try std.math.add(u64, out.retired_interaction_cells, cost.old_cells - cost.new_cells);
    }
    return out;
}
test "OP truth local GKR additive accounting preserves independent scope masses" {
    const d = Wire.TruthDeclaration{ .family = .keccak, .first_id = 1, .calls = 338, .logs = .{ 13, 0 } };
    const one = try derive(&.{d});
    const two = try derive(&.{ d, d });
    try std.testing.expectEqual(@as(u32, 1), one.scopes);
    try std.testing.expectEqual(@as(u32, 24), one.max_variables);
    try std.testing.expectEqual(@as(u64, 276), one.sumcheck_rounds);
    try std.testing.expectEqual(@as(u128, 2484), one.sumcheck_degree_weight);
    try std.testing.expectEqual(@as(u128, 120), one.instance_mix_degree_weight);
    try std.testing.expectEqual(@as(u128, 3), one.late_binding_degree_weight);
    try std.testing.expectEqual(@as(u128, 72), one.degenerate_point_degree_weight);
    try std.testing.expectEqual(@as(u64, 15728640), one.max_positive_mass_per_scope);
    try std.testing.expectEqual(@as(u64, 41877504), one.retired_interaction_cells);
    try std.testing.expectEqual(one.max_positive_mass_per_scope, two.max_positive_mass_per_scope);
    try std.testing.expectEqual(2 * one.sumcheck_degree_weight, two.sumcheck_degree_weight);
    var ledger = Policy.Ledger{ .degree_weight = @splat(0) };
    try two.addTo(&ledger);
    try ledger.requireRawModuloBits(128);
    try std.testing.expect(!two.security_qualified);
    var invalid = d;
    invalid.logs[0] = 21;
    try std.testing.expectError(error.InvalidTruthGkrGeometry, derive(&.{invalid}));
    const row = Wire.TruthDeclaration{ .family = .add, .first_id = 1, .calls = 1, .logs = .{ 8, 0 } };
    try std.testing.expect(!eligible(row));
}
