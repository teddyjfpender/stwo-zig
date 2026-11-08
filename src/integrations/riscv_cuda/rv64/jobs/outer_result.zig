//! Decode and validate host-observed outer results. Device-published native
//! jobs validate the request slab instead; they do not invoke this decoder.
const std = @import("std");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Plan = @import("outer_plan.zig");

pub const Decoded = struct {
    claims: Outer.witness.Claims,
    z: Outer.protocol.O,
    alpha: Outer.protocol.O,
    coefficient: Outer.protocol.O,
    main_root: [32]u8,
    inter_root: [32]u8,
};

fn felt(words: []const u32) !Outer.protocol.O {
    var limbs: [8]Outer.protocol.M = undefined;
    for (&limbs, words[0..8]) |*out, w| {
        if (w >= @import("stwo_core").fields.m31.Modulus) return error.NoncanonicalOuterClaim;
        out.* = Outer.protocol.M.fromCanonical(w);
    }
    return Outer.protocol.O.fromM31Array(limbs);
}
pub fn root(words: []const u32) [32]u8 {
    var out: [32]u8 = undefined;
    for (words[0..8], 0..) |w, i| std.mem.writeInt(u32, out[4 * i ..][0..4], w, .little);
    return out;
}

/// Status latches, canonicality and lookupSum == 0, then the typed fields.
pub fn decode(section: []const u32, expected_words: []const u32) !Decoded {
    const S = Plan.Section;
    if (section.len < S.words or expected_words.len % 4 != 0) return error.OuterSlabSectionTooSmall;
    if (section[S.status] != 0 or section[S.status + 3] != 0) return error.InvalidCircuitDeviceWitness;
    if (section[S.status + 1] != 0) return error.InvalidCircuitDeviceInteraction;
    if (section[S.status + 2] != 0) return error.InvalidOuterDeviceFsParameters;
    var claims: [Plan.n_components]Outer.protocol.O = undefined;
    for (&claims, 0..) |*c, i| c.* = try felt(section[S.claims + 8 * i ..]);
    const d = Decoded{
        .claims = Outer.witness.Claims.fromArray(claims),
        .z = try felt(section[S.challenges..]),
        .alpha = try felt(section[S.challenges + 8 ..]),
        .coefficient = try felt(section[S.challenges + 16 ..]),
        .main_root = root(section[S.main_root..]),
        .inter_root = root(section[S.inter_root..]),
    };
    var outputs: [64]Outer.protocol.Q = undefined;
    const n = expected_words.len / 4;
    if (n > outputs.len) return error.InvalidOm31CircuitOutputCount;
    for (outputs[0..n], 0..) |*q, i| q.* = Outer.protocol.Q.fromU32Unchecked(expected_words[4 * i], expected_words[4 * i + 1], expected_words[4 * i + 2], expected_words[4 * i + 3]);
    const elements = Outer.witness.Elements.init(d.z, d.alpha);
    if (!(try Outer.witness.lookupSum(outputs[0..n], d.claims, &elements)).isZero()) return error.InvalidOm31CircuitLookupSum;
    return d;
}

test "outer results reject incomplete, failed and noncanonical device observations" {
    const t = std.testing;
    const S = Plan.Section;
    var section: [S.words]u32 = @splat(0);
    try t.expectError(error.OuterSlabSectionTooSmall, decode(section[0 .. section.len - 1], &.{}));
    try t.expectError(error.OuterSlabSectionTooSmall, decode(&section, &.{1}));
    for ([_]anyerror{ error.InvalidCircuitDeviceWitness, error.InvalidCircuitDeviceInteraction, error.InvalidOuterDeviceFsParameters, error.InvalidCircuitDeviceWitness }, 0..) |err, i| {
        section[S.status + i] = 1;
        try t.expectError(err, decode(&section, &.{}));
        section[S.status + i] = 0;
    }
    section[S.claims] = @import("stwo_core").fields.m31.Modulus;
    try t.expectError(error.NoncanonicalOuterClaim, decode(&section, &.{}));
}
