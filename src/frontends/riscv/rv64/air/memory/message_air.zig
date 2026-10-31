//! Canonical private-word source for chunk hashes. This is also the packing
//! authority reused by the upcoming RAM CellTable; no public per-cell ledger.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const values = @import("values.zig");
const relation = @import("internal_relations.zig");
const rational = @import("policy_air.zig");
const prefix = @import("prefix.zig");
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const MAIN = 9;
pub const ACTIVE = 8;
pub const FIXED = 5;
pub const FIRST = 0;
pub const LAST = 1;
pub const INDEX = 2;
pub const HASH_ID = 3;
pub const CELL_ID = 4;
pub const SUMS = 5;
pub const BYTE_SUMS = 3;
pub const INTERACTION = 4 * SUMS;
pub const CONSTRAINTS = 18;
pub const SecureRow = [MAIN]Q;
pub const Row = [MAIN]M;
pub const Fixed = [FIXED]Q;
pub const Claims = [SUMS]Q;
pub const Challenges = struct { bytes: Q, ram: relation.Prepared };
pub const Shape = struct {
    geometry: values.Geometry,
    hashes: u32,
    log_size: u32,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn activeRows(self: Shape) u32 {
        return self.hashes * @as(u32, @intCast(self.geometry.cells()));
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 24 or @as(u64, self.hashes) * self.geometry.cells() > @as(u64, 1) << @intCast(self.log_size)) return error.InvalidRamMessageShape;
    }
    pub fn fixedAt(self: Shape, logical: usize) [FIXED]M {
        return .{ M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical + 1 == self.size())), M.fromCanonical(@intCast(logical)), M.fromCanonical(@intCast(logical / self.geometry.cells())), M.fromCanonical(@intCast(logical % self.geometry.cells())) };
    }
};

pub fn wordValues(bytes: *const [8]Q) [4]Q {
    var result: [4]Q = undefined;
    for (&result, 0..) |*value, i| value.* = bytes[2 * i].add(E.q(256).mul(bytes[2 * i + 1]));
    return result;
}

pub fn byteTerm(main: *const SecureRow, alpha: Q, slot: usize) @import("policy_air.zig").Term {
    return if (slot < 8) .{ .denominator = alpha.sub(main[slot]), .numerator = main[ACTIVE] } else .{ .denominator = Q.one(), .numerator = Q.zero() };
}

pub fn ramTerm(fixed: *const Fixed, main: *const SecureRow, challenges: *const relation.Prepared, slot: usize) @import("policy_air.zig").Term {
    if (slot >= 4) return .{ .denominator = Q.one(), .numerator = Q.zero() };
    const words = wordValues(main[0..8]);
    return .{ .denominator = challenges.payload(fixed[HASH_ID], fixed[CELL_ID].mul(E.q(4)).add(E.q(@intCast(slot))), words[slot]), .numerator = main[ACTIVE].neg() };
}

pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    const active = main[ACTIVE];
    prefix.evaluate(active, previous[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], shape.activeRows(), @intCast(shape.size()), out);
    for (0..8) |i| out.emit(Q.one().sub(active).mul(main[i]));
    for (0..BYTE_SUMS) |group| {
        var denominators: [3]Q = @splat(Q.one());
        var numerators: [3]Q = @splat(Q.zero());
        for (0..3) |slot| {
            const term = byteTerm(main, challenges.bytes, 3 * group + slot);
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        out.emit(rational.triple(rational.secure(interaction, group), rational.secure(previous_interaction, group), fixed[FIRST], claims[group], denominators, numerators));
    }
    for (0..2) |group| {
        var denominators: [3]Q = @splat(Q.one());
        var numerators: [3]Q = @splat(Q.zero());
        for (0..3) |slot| {
            const term = ramTerm(fixed, main, &challenges.ram, 3 * group + slot);
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        const sum = BYTE_SUMS + group;
        out.emit(rational.triple(rational.secure(interaction, sum), rational.secure(previous_interaction, sum), fixed[FIRST], claims[sum], denominators, numerators));
    }
}
