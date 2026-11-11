//! Complete additive native algebraic ledger for an independently selected
//! source suite. Execute before wide source keys. This is not certification of
//! the PCS/FRI/hash/Fiat-Shamir/recursive assumptions retained by the profile.
const std = @import("std");
const Suite = @import("pure_p2_source_suite.zig").Suite;
const Base = @import("pure_p2_truth_local_security.zig");
const Miller = @import("miller_local_gkr/security.zig");
const Geometry = @import("miller_local_gkr/authority.zig").Geometry;
const Bounds = @import("../word16_global_execution/services/gkr_local/source_bounds.zig");
const Wire = @import("../word16_global_execution/services/wire.zig");
const Policy = @import("../word16_execution/om31_security_candidate.zig");
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
pub const Checked = struct {
    suite: Suite,
    truth: Base.Checked,
    miller: Miller.Report,
    conditional_degree_weight: [Policy.TERM_COUNT]u512,
    raw_modulo_envelope_bits: u16 = Policy.TARGET_BITS + 2 + 21,
    security_qualified: bool = false,
    scope: []const u8 = "128-bit security target under documented assumptions; additive native algebraic ledger, no whole-protocol certification",
};
pub fn check(profile: Profile, bounds: *Bounds.OpReport, truth: []const Wire.TruthDeclaration, miller: []const Bounds.OpTowerTruthDeclaration, suite: Suite) !Checked {
    try suite.validate();
    if (miller.len > 256) return error.TooManyMillerGkrScopes;
    // Starts from the SAME full caps/lookup/global/PCS/FRI engineering ledger,
    // including exact source lookup terms, even if local truth is classic.
    const baseline = try Base.check(profile, bounds, if (suite.truth == .local_gkr) truth else &.{});
    var geometries: [256]Geometry = undefined;
    for (miller, geometries[0..miller.len]) |decl, *out| out.* = .{ .calls = decl.calls, .first_id = decl.first_id, .frontier_log = decl.frontier_log, .arithmetic_log = decl.arithmetic_log };
    const added = try Miller.derive(if (suite.miller == .local_gkr) geometries[0..miller.len] else &.{});
    added.augmentShape(&bounds.base.shape);
    try bounds.base.shape.validate();
    var ledger = Policy.Ledger{ .degree_weight = baseline.conditional_degree_weight };
    try added.addTo(&ledger);
    try ledger.requireRawModuloBits(Policy.TARGET_BITS + 2 + 21);
    return .{ .suite = suite, .truth = baseline, .miller = added, .conditional_degree_weight = ledger.degree_weight };
}
