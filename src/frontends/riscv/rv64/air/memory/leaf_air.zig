//! Private chunk header. Authenticates aligned full-width addresses ONCE per
//! chunk, connects private word groups to hash IDs, and supplies before/after
//! leaves to the descending node bus. A reuse always has an unconditional
//! BEFORE supply; no free after-only side certificate can enter this relation.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const values = @import("values.zig");
const internal = @import("internal_relations.zig");
const rational = @import("policy_air.zig");
const cell = @import("cell_air.zig");
const prefix = @import("prefix.zig");
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const INDEX_BYTES = 0;
pub const BASE = 7;
pub const CARRY_BITS = 15;
pub const BEFORE = 39;
pub const AFTER = 48;
pub const BEFORE_ID = 57;
pub const AFTER_ID = 58;
pub const CHANGED = 59;
pub const REUSE = 60;
pub const ACTIVE = 61;
pub const MAIN = 62;
pub const FIXED = 3;
pub const FIRST = 0;
pub const LAST = 1;
pub const INDEX = 2;
pub const SUMS = 8;
pub const INTERACTION = 4 * SUMS;
pub const CONSTRAINTS = 63;
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const Fixed = [FIXED]Q;
pub const Claims = [SUMS]Q;
pub const Term = @import("policy_air.zig").Term;
pub const Challenges = struct { ram: internal.Prepared, bytes: Q };
pub const Shape = struct {
    geometry: values.Geometry,
    leaves: u32,
    log_size: u32,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn activeRows(self: Shape) u32 {
        return self.leaves;
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 24 or self.leaves > self.size()) return error.InvalidPrivateRamLeafShape;
    }
    pub fn fixedAt(self: Shape, i: usize) [FIXED]M {
        return .{ M.fromCanonical(@intFromBool(i == 0)), M.fromCanonical(@intFromBool(i + 1 == self.size())), M.fromCanonical(@intCast(i)) };
    }
};
fn carry(main: *const SecureRow, i: usize) Q {
    var result = Q.zero();
    for (0..4) |j| result = result.add(E.q(@as(u32, 1) << @intCast(j)).mul(main[CARRY_BITS + 4 * i + j]));
    return result;
}
pub fn byteTerm(main: *const SecureRow, alpha: Q, slot: usize) Term {
    return if (slot < 15) .{ .denominator = alpha.sub(main[slot]), .numerator = main[ACTIVE] } else .{ .denominator = Q.one(), .numerator = Q.zero() };
}
pub fn nodeTerm(main: *const SecureRow, ram: *const internal.Prepared, slot: usize) Term {
    return switch (slot) {
        0 => .{ .denominator = ram.node(Q.zero(), Q.zero(), main[INDEX_BYTES..][0..7].*, main[BEFORE..][0..9].*), .numerator = main[ACTIVE].neg() },
        1 => .{ .denominator = ram.node(Q.one(), Q.zero(), main[INDEX_BYTES..][0..7].*, main[AFTER..][0..9].*), .numerator = main[ACTIVE].mul(main[CHANGED].add(main[REUSE])).neg() },
        else => .{ .denominator = Q.one(), .numerator = Q.zero() },
    };
}
pub fn digestTerm(main: *const SecureRow, ram: *const internal.Prepared, slot: usize) Term {
    return switch (slot) {
        0 => .{ .denominator = ram.digest(main[BEFORE_ID], main[BEFORE..][0..9].*), .numerator = main[ACTIVE] },
        1 => .{ .denominator = ram.digest(main[AFTER_ID], main[AFTER..][0..9].*), .numerator = main[ACTIVE].mul(main[CHANGED]) },
        else => .{ .denominator = Q.one(), .numerator = Q.zero() },
    };
}
pub fn headerTerm(fixed: *const Fixed, main: *const SecureRow, ram: *const internal.Prepared) Term {
    _ = fixed;
    return .{ .denominator = cell.header(ram, main[BASE..][0..8].*, main[BEFORE_ID], main[AFTER_ID], main[CHANGED]), .numerator = main[ACTIVE].neg() };
}
pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    prefix.evaluate(main[ACTIVE], previous[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], shape.leaves, @intCast(shape.size()), out);
    out.emit(main[CHANGED].mul(main[CHANGED].sub(Q.one())));
    out.emit(main[REUSE].mul(main[REUSE].sub(Q.one())));
    out.emit(main[CHANGED].mul(main[REUSE]));
    for (main[CARRY_BITS..][0..24]) |bit| out.emit(bit.mul(bit.sub(Q.one())));
    for (0..6) |i| {
        const c = carry(main, i);
        out.emit(if (shape.geometry == .chunk512) c.mul(c.sub(Q.one())) else Q.zero());
    }
    out.emit(main[BASE]);
    const factor = E.q(@as(u32, 1) << @intCast(shape.geometry.logBytes() - 8));
    for (0..7) |i| out.emit(factor.mul(main[INDEX_BYTES + i]).add(if (i == 0) Q.zero() else carry(main, i - 1)).sub(main[BASE + i + 1]).sub(E.q(256).mul(if (i == 6) Q.zero() else carry(main, i))));
    for (0..9) |i| out.emit(Q.one().sub(main[CHANGED]).mul(main[AFTER + i].sub(main[BEFORE + i])));
    for (0..SUMS) |group| {
        var denominators: [3]Q = undefined;
        var numerators: [3]Q = undefined;
        for (0..3) |slot| {
            const term = if (group < 5) byteTerm(main, challenges.bytes, 3 * group + slot) else if (group == 5) nodeTerm(main, &challenges.ram, slot) else if (group == 6) digestTerm(main, &challenges.ram, slot) else if (slot == 0) headerTerm(fixed, main, &challenges.ram) else Term{ .denominator = Q.one(), .numerator = Q.zero() };
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        out.emit(rational.triple(rational.secure(interaction, group), rational.secure(previous_interaction, group), fixed[FIRST], claims[group], denominators, numerators));
    }
}
pub const Native = struct { index: u64, before_id: u32, after_id: u32, before: values.Digest, after: values.Digest, changed: bool, reuse: bool };
pub fn fill(geometry: values.Geometry, native: Native) !Row {
    if (native.index >= @as(u64, 1) << geometry.depth() or (native.changed and native.reuse) or (!native.changed and !values.equal(native.before, native.after)) or native.before_id >= core.fields.m31.Modulus or native.after_id >= core.fields.m31.Modulus) return error.InvalidPrivateRamLeaf;
    var row: Row = @splat(M.zero());
    const base = native.index << geometry.logBytes();
    for (0..7) |i| row[INDEX_BYTES + i] = M.fromCanonical(@intCast((native.index >> @intCast(8 * i)) & 255));
    for (0..8) |i| row[BASE + i] = M.fromCanonical(@intCast((base >> @intCast(8 * i)) & 255));
    for (0..6) |i| {
        const c: u32 = @intCast((native.index >> @intCast(8 * i + 16 - geometry.logBytes())) & ((@as(u64, 1) << @intCast(geometry.logBytes() - 8)) - 1));
        for (0..4) |j| row[CARRY_BITS + i * 4 + j] = M.fromCanonical((c >> @intCast(j)) & 1);
    }
    for (native.before, native.after, 0..) |before, after, i| {
        if (before >= core.fields.m31.Modulus or after >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        row[BEFORE + i] = M.fromCanonical(before);
        row[AFTER + i] = M.fromCanonical(after);
    }
    row[BEFORE_ID] = M.fromCanonical(native.before_id);
    row[AFTER_ID] = M.fromCanonical(native.after_id);
    row[CHANGED] = M.fromCanonical(@intFromBool(native.changed));
    row[REUSE] = M.fromCanonical(@intFromBool(native.reuse));
    row[ACTIVE] = M.one();
    return row;
}
