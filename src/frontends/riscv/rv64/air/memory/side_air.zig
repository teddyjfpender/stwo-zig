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
pub fn ClaimsFor(comptime C: type) type {
    return [SUMS]C;
}
pub const Claims = ClaimsFor(Q);
pub const Term = rational.Term;
/// Side challenges over constant lane C (QM31 natively, external wires otherwise).
pub fn ChallengesFor(comptime C: type) type {
    return struct { ram: internal.PreparedFor(C), bytes: C };
}
pub const Challenges = ChallengesFor(Q);
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
    return heightFor(Q, main);
}
pub fn heightFor(comptime F: type, main: *const [MAIN]F) F {
    var result = F.zero();
    for (0..6) |i| result = result.add(E.qFor(F, @as(u32, 1) << @intCast(i)).mul(main[HEIGHT_BITS + i]));
    return result;
}
pub fn byteTerm(main: *const SecureRow, alpha: Q, slot: usize) Term {
    return byteTermFor(Q, main, alpha, slot);
}
pub fn byteTermFor(comptime F: type, main: *const [MAIN]F, alpha: F, slot: usize) rational.TermFor(F) {
    return if (slot < 7) .{ .denominator = alpha.sub(main[INDEX_BYTES + slot]), .numerator = main[ACTIVE] } else .{ .denominator = F.one(), .numerator = F.zero() };
}
pub fn nodeTerm(main: *const SecureRow, ram: *const internal.Prepared, slot: usize) Term {
    return nodeTermFor(Q, main, ram, slot);
}
pub fn nodeTermFor(comptime F: type, main: *const [MAIN]F, ram: *const internal.PreparedFor(F), slot: usize) rational.TermFor(F) {
    return if (slot < 2) .{ .denominator = ram.node(E.qFor(F, @intCast(slot)), heightFor(F, main), main[INDEX_BYTES..][0..7].*, main[DIGEST..][0..9].*), .numerator = if (slot == 0) main[ACTIVE].neg() else main[ACTIVE].mul(main[REUSE]).neg() } else .{ .denominator = F.one(), .numerator = F.zero() };
}
pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    return evaluateFor(Q, shape, fixed, main, previous, interaction, previous_interaction, claims, challenges, prefix.rows(shape.sides, @intCast(shape.size())), out);
}
/// Same residuals over any secure lane; `rows` carries the active-row publics.
pub fn evaluateFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous: *const [MAIN]F, interaction: []const F, previous_interaction: []const F, claims: ClaimsFor(F), challenges: *const ChallengesFor(F), rows: prefix.RowsFor(F), out: *E.SinkFor(F)) void {
    prefix.evaluateFor(F, main[ACTIVE], previous[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], rows, out);
    for (main[HEIGHT_BITS..][0..6]) |bit| out.emit(bit.mul(bit.sub(F.one())));
    out.emit(main[REUSE].mul(main[REUSE].sub(F.one())));
    out.emit(main[ACTIVE].mul(heightFor(F, main).sub(E.qFor(F, shape.geometry.depth()))).mul(main[NOT_ROOT_INVERSE]).sub(main[ACTIVE]));
    for (0..SUMS) |group| {
        var denominators: [3]F = undefined;
        var numerators: [3]F = undefined;
        for (0..3) |slot| {
            const term = if (group < 3) byteTermFor(F, main, challenges.bytes, 3 * group + slot) else nodeTermFor(F, main, &challenges.ram, slot);
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        out.emit(rational.tripleFor(F, rational.secureFor(F, interaction, group), rational.secureFor(F, previous_interaction, group), fixed[FIRST], claims[group], denominators, numerators));
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
