//! Native-GKR admission reuses the receiver's M4 source-accounting authority.
//! A weighted provider's valid support is not unit negative integer mass: the
//! membership model bounds unit consumers, while consistency bounds both signs.
//! These are necessary engineering gates, not a whole-protocol certificate.
const std = @import("std");
const Bounds = @import("../gkr_local/source_bounds.zig");
const V2 = @import("v2.zig");
const R = @import("roster.zig");
const M = @import("stwo_core").fields.m31.Modulus;
pub fn characteristicMass(bound: Bounds.Bound) !u64 {
    if(bound.unit_consumer_mass>=M or bound.unit_positive_mass>=M or bound.unit_negative_mass>=M)return error.Om31CandidateCharacteristicWrap;
    const mass = switch (bound.model) {
        .unit_membership_valid_support => bound.unit_consumer_mass,
        .unit_consistency => @max(bound.unit_positive_mass, bound.unit_negative_mass),
    };
    if (mass >= M) return error.Om31CandidateCharacteristicWrap;
    return mass;
}
/// One source-derived row per physical proof, in exact CPU-then-truth order.
/// Global totals bound every proof without trusting a producer's per-proof mass.
pub fn requireInventory(rosters: []const R.Roster, source: *const Bounds.Report) !void {
    const count = try std.math.add(usize,source.cpu_scopes.len,source.truth_scopes.len);
    if(count==0 or rosters.len!=count or source.shape.native_proofs!=count)return error.NativeGkrSourceInventory;
    // Source accounting includes every pair of tuples that can collide under
    // alpha compression. The generic outer ledger alone uses a linear N
    // estimate and is insufficient for this independently derived source gate.
    try source.conditional_degrees.requireLookupOnlyBits(V2.REQUIRED_BITS+V2.SALT_GRINDING_BITS);
    const globals=try source.global_signed.absolute();
    for(rosters,0..) |*roster,index| {
        var masses=V2.RelationMasses{.local=@splat(0),.ram=globals.ram,.kio=globals.kio,.wire=globals.wire};
        if(index<source.cpu_scopes.len) {
            const scope=source.cpu_scopes[index];
            if(scope.namespace_count>V2.LOCAL_RELATIONS)return error.NativeGkrSourceInventory;
            for(scope.relations,0..) |bound,relation|masses.local[relation]=try characteristicMass(bound);
            // OWNER19 has a disjoint JD table partition in addition to ordinary
            // token consistency. Charge their union, never discard the table.
            const owner=@intFromEnum(@import("../gkr_local/fractions.zig").Relation.owner);
            masses.local[owner]=try std.math.add(u64,masses.local[owner],try characteristicMass(scope.owner_table));
        } else {
            for(source.truth_scopes[index-source.cpu_scopes.len].relations,0..) |bound,relation|masses.local[relation]=try characteristicMass(bound);
        }
        try V2.requireNativeGkrSecurity(roster,@intCast(count),masses);
    }
}

test "native GKR source admission distinguishes weighted support from ordinary signed events" {
    try std.testing.expectEqual(@as(u64,17),try characteristicMass(.{.model=.unit_membership_valid_support,.unit_consumer_mass=17,.valid_provider_support=91,.unit_negative_mass=13}));
    try std.testing.expectEqual(@as(u64,23),try characteristicMass(.{.model=.unit_consistency,.unit_positive_mass=19,.unit_negative_mass=23}));
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap,characteristicMass(.{.model=.unit_consistency,.unit_positive_mass=M}));
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap,characteristicMass(.{.unit_consumer_mass=M}));
}
