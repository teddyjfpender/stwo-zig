//! Private authenticated side/reuse certificate. Every row supplies epoch0
//! unconditionally and MAY supply the identical digest to epoch1. There is no
//! after-only free side. Root-height certificates are explicitly forbidden.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const values = @import("values.zig");
const internal = @import("internal_relations.zig");
const rational = @import("policy_air.zig");
const prefix = @import("prefix.zig");
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const HEIGHT_BITS = 0;
pub const INDEX_BYTES = 6;
pub const DIGEST = 13;
pub const REUSE = 22;
pub const NOT_ROOT_INVERSE = 23;
pub const ACTIVE = 24;
pub const MAIN = 25;
pub const FIXED = 3;
pub const FIRST = 0;
pub const LAST = 1;
pub const INDEX = 2;
pub const SUMS = 4;
pub const INTERACTION = 4 * SUMS;
pub const CONSTRAINTS = 17;
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const Fixed = [FIXED]Q;
pub const Claims = [SUMS]Q;
pub const Term = @import("policy_air.zig").Term;
pub const Challenges = struct { ram: internal.Prepared, bytes: Q };
pub const Shape = struct {
    geometry: values.Geometry,
    sides: u32,
    log_size: u32,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn activeRows(self: Shape) u32 {
        return self.sides;
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 24 or self.sides > self.size()) return error.InvalidPrivateRamSideShape;
    }
    pub fn fixedAt(self: Shape, i: usize) [FIXED]M {
        return .{ M.fromCanonical(@intFromBool(i == 0)), M.fromCanonical(@intFromBool(i + 1 == self.size())), M.fromCanonical(@intCast(i)) };
    }
};
pub fn height(main: *const SecureRow) Q {
    var result = Q.zero();
    for (0..6) |i| result = result.add(E.q(@as(u32, 1) << @intCast(i)).mul(main[HEIGHT_BITS + i]));
    return result;
}
pub fn byteTerm(main: *const SecureRow, alpha: Q, slot: usize) Term {
    return if (slot < 7) .{ .denominator = alpha.sub(main[INDEX_BYTES + slot]), .numerator = main[ACTIVE] } else .{ .denominator = Q.one(), .numerator = Q.zero() };
}
pub fn nodeTerm(main: *const SecureRow, ram: *const internal.Prepared, slot: usize) Term {
    return if (slot < 2) .{ .denominator = ram.node(E.q(@intCast(slot)), height(main), main[INDEX_BYTES..][0..7].*, main[DIGEST..][0..9].*), .numerator = if (slot == 0) main[ACTIVE].neg() else main[ACTIVE].mul(main[REUSE]).neg() } else .{ .denominator = Q.one(), .numerator = Q.zero() };
}
pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    prefix.evaluate(main[ACTIVE], previous[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], shape.sides, @intCast(shape.size()), out);
    for (main[HEIGHT_BITS..][0..6]) |bit| out.emit(bit.mul(bit.sub(Q.one())));
    out.emit(main[REUSE].mul(main[REUSE].sub(Q.one())));
    out.emit(main[ACTIVE].mul(height(main).sub(E.q(shape.geometry.depth()))).mul(main[NOT_ROOT_INVERSE]).sub(main[ACTIVE]));
    for (0..SUMS) |group| {
        var denominators: [3]Q = undefined;
        var numerators: [3]Q = undefined;
        for (0..3) |slot| {
            const term = if (group < 3) byteTerm(main, challenges.bytes, 3 * group + slot) else nodeTerm(main, &challenges.ram, slot);
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        out.emit(rational.triple(rational.secure(interaction, group), rational.secure(previous_interaction, group), fixed[FIRST], claims[group], denominators, numerators));
    }
}
pub fn fill(geometry: values.Geometry, h: u6, index: u64, digest: values.Digest, reuse: bool) !Row {
    if (h >= geometry.depth() or index >= @as(u64, 1) << (geometry.depth() - h)) return error.InvalidPrivateRamSide;
    var row: Row = @splat(M.zero());
    for (0..6) |i| row[HEIGHT_BITS + i] = M.fromCanonical((@as(u32, h) >> @intCast(i)) & 1);
    for (0..7) |i| row[INDEX_BYTES + i] = M.fromCanonical(@intCast((index >> @intCast(8 * i)) & 255));
    for (digest, 0..) |value, i| {
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        row[DIGEST + i] = M.fromCanonical(value);
    }
    row[REUSE] = M.fromCanonical(@intFromBool(reuse));
    row[NOT_ROOT_INVERSE] = try M.fromCanonical(geometry.depth() - h).neg().inv();
    row[ACTIVE] = M.one();
    return row;
}
