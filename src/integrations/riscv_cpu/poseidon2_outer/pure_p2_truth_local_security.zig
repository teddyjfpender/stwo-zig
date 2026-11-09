//! Conditional schema2 algebraic accounting. This augments the existing source
//! lookup/global proof and full engineering envelope; it certifies no theorem,
//! Poseidon/ROM/FRI reduction or recursive construction.
const std = @import("std");
const Local = @import("truth_local_gkr/security.zig");
const Bounds = @import("../word16_global_execution/services/gkr_local/source_bounds.zig");
const Wire = @import("../word16_global_execution/services/wire.zig");
const Policy = @import("../word16_execution/om31_security_candidate.zig");
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
pub const Checked = struct {
    added: Local.Report,
    conditional_degree_weight: [Policy.TERM_COUNT]u512,
    raw_modulo_envelope_bits: u16 = Policy.TARGET_BITS + 2 + 21,
    security_qualified: bool = false,
    scope: []const u8 = "conditional native algebraic envelope only; existing PCS/FRI/hash/FS/binding assumptions and recursion review remain",
};
pub fn check(profile: Profile, bounds: *Bounds.OpReport, declarations: []const Wire.TruthDeclaration) !Checked {
    const added = try Local.derive(declarations);
    added.augmentShape(&bounds.base.shape);
    try bounds.base.shape.validate();
    // Retain the full existing conservative CPU-GKR/global/PCS/FRI envelope.
    // Also add the independently source-derived lookup terms, rather than
    // allowing the new child to replace or erase any pre-existing obligation.
    var ledger = try Policy.ledgerAtBlowup(Policy.Facts.caps(), profile.config().fri_config.log_blowup_factor);
    const d = bounds.base.conditional_degrees;
    for ([_]struct { term: Policy.AlgebraicTerm, weight: u128 }{
        .{ .term = .tuple_compression, .weight = d.tuple_collision },
        .{ .term = .local_rational_identity, .weight = d.local_rational_identity },
        .{ .term = .global_rational_identity, .weight = d.global_rational_identity },
        .{ .term = .pole_events, .weight = d.poles },
    }) |entry| ledger.degree_weight[@intFromEnum(entry.term)] = try std.math.add(u512, ledger.degree_weight[@intFromEnum(entry.term)], entry.weight);
    try added.addTo(&ledger);
    try ledger.requireRawModuloBits(Policy.TARGET_BITS + 2 + 21);
    return .{ .added = added, .conditional_degree_weight = ledger.degree_weight };
}
