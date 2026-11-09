//! Explicit detached native-source algebraic envelope. Receiver-owned source
//! declarations and bounds are inputs, never a producer claim or certificate.
//! P2/Fiat-Shamir/PCS/FRI and recursive assumptions remain separately required.
const std = @import("std");
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const Policy = @import("../../word16_execution/om31_security_candidate.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const Frame = @import("frame.zig");
const Detached = @import("../sponge_local_gkr/authority.zig");
const Truth = @import("../truth_local_gkr/security.zig");
const Miller = @import("../miller_local_gkr/security.zig");
const MillerGeometry = @import("../miller_local_gkr/authority.zig").Geometry;
const Profile = @import("../op_profile.zig").Profile;
pub const GkrReport = struct {
    scopes: u32 = 0,
    instances: u32 = 0,
    max_variables: u32 = 0,
    sumcheck_rounds: u64 = 0,
    sumcheck_degree_weight: u128 = 0,
    instance_mix_degree_weight: u128 = 0,
    late_binding_degree_weight: u128 = 0,
    degenerate_point_degree_weight: u128 = 0,
    fn addScope(self: *GkrReport, count: u32, variables: u32, row_variables: u64) !void {
        if (count == 0 or count > Policy.MAX_LOCAL_INSTANCES or variables < 5 or variables > Policy.MAX_GKR_VARIABLES) return error.DetachedSecurityShape;
        const rounds = @as(u64, variables) * (variables - 1) / 2;
        self.scopes += 1;
        self.instances += count;
        self.max_variables = @max(self.max_variables, variables);
        self.sumcheck_rounds = try std.math.add(u64, self.sumcheck_rounds, rounds);
        self.sumcheck_degree_weight = try std.math.add(u128, self.sumcheck_degree_weight, @as(u128, count) * 3 * rounds);
        self.instance_mix_degree_weight = try std.math.add(u128, self.instance_mix_degree_weight, @as(u128, count + 2) * variables);
        self.late_binding_degree_weight = try std.math.add(u128, self.late_binding_degree_weight, count);
        self.degenerate_point_degree_weight = try std.math.add(u128, self.degenerate_point_degree_weight, 2 * @as(u128, row_variables));
    }
    pub fn addTo(self: GkrReport, ledger: *Policy.Ledger) !void {
        for ([_]struct { term: Policy.AlgebraicTerm, value: u128 }{
            .{ .term = .gkr_sumcheck, .value = self.sumcheck_degree_weight },
            .{ .term = .gkr_instance_mix, .value = self.instance_mix_degree_weight },
            .{ .term = .gkr_late_binding, .value = self.late_binding_degree_weight },
            .{ .term = .pole_events, .value = self.degenerate_point_degree_weight },
        }) |entry| {
            const i = @intFromEnum(entry.term);
            ledger.degree_weight[i] = try std.math.add(u512, ledger.degree_weight[i], entry.value);
        }
    }
};
pub const Checked = struct {
    accounting_profile: []const u8 = "op-detached-typed-source-security/v1",
    target: []const u8 = "128-bit security target under documented assumptions",
    cpu_and_detached: GkrReport,
    truth: Truth.Report,
    miller: Miller.Report,
    conditional_degree_weight: [Policy.TERM_COUNT]u512,
    raw_modulo_envelope_bits: u16 = Policy.TARGET_BITS + 2 + 21,
    security_qualified: bool = false,
    production_admission: bool = false,
    scope: []const u8 = "conditional native algebraic envelope; P2/hash/FRI/Fiat-Shamir/recursion assumptions are not certified by this ledger",
};
/// Local relation challenges are independent per worker. Global namespaces use
/// the manifest challenge and their signed bounds are therefore joined BEFORE
/// this call by deriveForOpDetached. Keep the original cap envelope in addition
/// to precise lookup/GKR terms, rather than subtracting retired-column errors.
pub fn check(profile: Profile, bounds: *Bounds.DetachedOpReport, cpus: []const []const Frame.Instance, detached: []const Detached.Geometry, local_truth: []const Wire.TruthDeclaration, local_miller: []const MillerGeometry) !Checked {
    if (profile == .reference_b2_q24_p0 or cpus.len != bounds.op.base.cpu_scopes.len or detached.len != bounds.detached_scopes.len) return error.DetachedSecurityShape;
    var gkr = GkrReport{};
    for (cpus) |instances| {
        if (instances.len < 2 or instances.len > Policy.MAX_LOCAL_INSTANCES or instances[instances.len - 1] != .frontier) return error.DetachedSecurityShape;
        var variables: u32 = 0;
        var row_variables: u64 = 0;
        for (instances, 0..) |instance, i| {
            if (i + 1 < instances.len and (instance != .legacy or instance.legacy.origin == .sponge)) return error.DetachedSecurityShape;
            variables = @max(variables, try instance.variables());
            row_variables = try std.math.add(u64, row_variables, instance.rowLog());
        }
        try gkr.addScope(@intCast(instances.len), variables, row_variables);
    }
    for (detached) |geometry| {
        if (!geometry.detached) return error.SpongeLocalScopeFlavor;
        var variables: u32 = 0;
        var row_variables: u64 = 0;
        for (try geometry.instances()) |instance| {
            variables = @max(variables, try instance.variables());
            row_variables = try std.math.add(u64, row_variables, instance.row_log);
        }
        try gkr.addScope(8, variables, row_variables);
    }
    const truth = try Truth.derive(local_truth);
    const miller = try Miller.derive(local_miller);
    truth.augmentShape(&bounds.op.base.shape);
    miller.augmentShape(&bounds.op.base.shape);
    bounds.op.base.shape.max_gkr_variables = @max(bounds.op.base.shape.max_gkr_variables, gkr.max_variables);
    try bounds.op.base.shape.validate();
    var ledger = try Policy.ledgerAtBlowup(Policy.Facts.caps(), profile.config().fri_config.log_blowup_factor);
    const d = bounds.op.base.conditional_degrees;
    for ([_]struct { term: Policy.AlgebraicTerm, value: u128 }{
        .{ .term = .tuple_compression, .value = d.tuple_collision },
        .{ .term = .local_rational_identity, .value = d.local_rational_identity },
        .{ .term = .global_rational_identity, .value = d.global_rational_identity },
        .{ .term = .pole_events, .value = d.poles },
    }) |entry| {
        const i = @intFromEnum(entry.term);
        ledger.degree_weight[i] = try std.math.add(u512, ledger.degree_weight[i], entry.value);
    }
    try gkr.addTo(&ledger);
    try truth.addTo(&ledger);
    try miller.addTo(&ledger);
    try ledger.requireRawModuloBits(Policy.TARGET_BITS + 2 + 21);
    return .{ .cpu_and_detached = gkr, .truth = truth, .miller = miller, .conditional_degree_weight = ledger.degree_weight };
}
test "detached security sums independent source GKR scopes without replacing baseline terms" {
    var r = GkrReport{};
    try r.addScope(8, 24, 96);
    try std.testing.expectEqual(@as(u64, 276), r.sumcheck_rounds);
    try std.testing.expectEqual(@as(u128, 6624), r.sumcheck_degree_weight);
    try std.testing.expectEqual(@as(u128, 240), r.instance_mix_degree_weight);
    try std.testing.expectEqual(@as(u128, 8), r.late_binding_degree_weight);
    try std.testing.expectEqual(@as(u128, 192), r.degenerate_point_degree_weight);
    var ledger = Policy.Ledger{ .degree_weight = @splat(0) };
    ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.composition_mix)] = 17;
    try r.addTo(&ledger);
    try std.testing.expectEqual(@as(u512, 17), ledger.degree_weight[@intFromEnum(Policy.AlgebraicTerm.composition_mix)]);
    try ledger.requireRawModuloBits(128);
    try std.testing.expectError(error.DetachedSecurityShape, r.addScope(129, 24, 96));
}
