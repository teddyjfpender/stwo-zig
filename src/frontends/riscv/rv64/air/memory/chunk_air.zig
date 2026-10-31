//! Private value-only chunk sponge caller. A constrained zero-output separator
//! between hashes makes every provider input LINEAR in current/previous fields,
//! avoiding sixteen extra physical input columns or high-degree reset products.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const prefix = @import("prefix.zig");
const values = @import("values.zig");
const relation = @import("internal_relations.zig");
const rational = @import("policy_air.zig");
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const MAIN = 24;
pub const OUTPUT = 0;
pub const PAYLOAD = 16;
pub const ACTIVE = 23;
pub const FIXED = 8;
pub const FIRST = 0;
pub const LAST = 1;
pub const INDEX = 2;
pub const HASH_ID = 3;
pub const HASH_FIRST = 4;
pub const LAST_ABSORB = 5;
pub const SQUEEZE = 6;
pub const RESET = 7;
pub const SUMS = 4; // One full-I/O prefix, three tagged RAM packet prefixes.
pub const INTERACTION = 4 * SUMS;
pub const CONSTRAINTS = 35;
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const Fixed = [FIXED]Q;
pub const Claims = [SUMS]Q;
const LegacyRelations = @import("../../../air/relation_challenges.zig").Relations;
pub const PermutationChallenge = @FieldType(LegacyRelations, "poseidon2_io");
pub const Challenges = struct { ram: relation.Prepared, io: PermutationChallenge };
pub const Shape = struct {
    geometry: values.Geometry,
    hashes: u32,
    log_size: u32,
    pub fn stride(self: Shape) usize {
        return self.geometry.permutations() + 1;
    }
    pub fn activeRows(self: Shape) u32 {
        return self.hashes * @as(u32, @intCast(self.stride()));
    }
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 24 or @as(u64, self.hashes) * self.stride() > @as(u64, 1) << @intCast(self.log_size)) return error.InvalidRamChunkShape;
    }
    pub fn fixedAt(self: Shape, logical: usize) [FIXED]M {
        const phase = logical % self.stride();
        return .{ M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical + 1 == self.size())), M.fromCanonical(@intCast(logical)), M.fromCanonical(@intCast(logical / self.stride())), M.fromCanonical(@intFromBool(phase == 0)), M.fromCanonical(@intFromBool(phase + 1 == self.geometry.absorptions())), M.fromCanonical(@intFromBool(phase == self.geometry.absorptions())), M.fromCanonical(@intFromBool(phase + 1 == self.stride())) };
    }
};

pub fn input(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow) [16]Q {
    var result: [16]Q = previous[OUTPUT..][0..16].*;
    for (0..7) |i| result[i] = result[i].add(main[PAYLOAD + i]);
    result[14] = result[14].add(fixed[HASH_FIRST].mul(E.q(32 * values.VERSION + shape.geometry.logBytes())));
    result[15] = result[15].add(fixed[HASH_FIRST].mul(E.q(values.DOMAIN)));
    return result;
}

pub fn digest(main: *const SecureRow, previous: *const SecureRow) [9]Q {
    var result: [9]Q = undefined;
    @memcpy(result[0..7], previous[OUTPUT..][0..7]);
    @memcpy(result[7..9], main[OUTPUT..][0..2]);
    return result;
}

pub fn ioDenominator(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, challenge: PermutationChallenge) Q {
    var tuple: [32]Q = undefined;
    @memcpy(tuple[0..16], &input(shape, fixed, main, previous));
    @memcpy(tuple[16..32], main[OUTPUT..][0..16]);
    return challenge.combine(tuple);
}

pub fn ioTerm(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, challenge: PermutationChallenge) @import("policy_air.zig").Term {
    return .{ .denominator = ioDenominator(shape, fixed, main, previous, challenge), .numerator = main[ACTIVE].mul(Q.one().sub(fixed[RESET])).neg() };
}

pub fn ramTerm(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, challenges: *const relation.Prepared, slot: usize) @import("policy_air.zig").Term {
    if (slot == 7) return .{ .denominator = challenges.digest(fixed[HASH_ID], digest(main, previous)), .numerator = main[ACTIVE].mul(fixed[SQUEEZE]).neg() };
    if (slot >= 8) return .{ .denominator = Q.one(), .numerator = Q.zero() };
    const phase = fixed[INDEX].sub(fixed[HASH_ID].mul(E.q(@intCast(shape.stride()))));
    var is_data = Q.one().sub(fixed[SQUEEZE]).sub(fixed[RESET]);
    if (slot >= (4 * shape.geometry.cells()) % 7) is_data = is_data.sub(fixed[LAST_ABSORB]);
    return .{ .denominator = challenges.payload(fixed[HASH_ID], phase.mul(E.q(7)).add(E.q(@intCast(slot))), main[PAYLOAD + slot]), .numerator = main[ACTIVE].mul(is_data) };
}

pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous_main: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    const active = main[ACTIVE];
    prefix.evaluate(active, previous_main[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], shape.activeRows(), @intCast(shape.size()), out);
    const clear_output = Q.one().sub(active).add(fixed[RESET]);
    for (0..16) |i| out.emit(clear_output.mul(main[OUTPUT + i]));
    const clear_payload = Q.one().sub(active).add(fixed[RESET]).add(fixed[SQUEEZE]);
    for (0..7) |i| out.emit(clear_payload.mul(main[PAYLOAD + i]));
    const tail = (4 * shape.geometry.cells()) % 7;
    for (tail..7) |i| out.emit(active.mul(fixed[LAST_ABSORB]).mul(main[PAYLOAD + i].sub(E.q(@intFromBool(i == tail)))));
    const io_delta = rational.secure(interaction, 0).sub(rational.secure(previous_interaction, 0)).add(fixed[FIRST].mul(claims[0]));
    const io = ioTerm(shape, fixed, main, previous_main, challenges.io);
    out.emit(io_delta.mul(io.denominator).sub(io.numerator));
    for (0..3) |group| {
        var denominators: [3]Q = undefined;
        var numerators: [3]Q = undefined;
        for (0..3) |slot| {
            const term = ramTerm(shape, fixed, main, previous_main, &challenges.ram, group * 3 + slot);
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        out.emit(rational.triple(rational.secure(interaction, group + 1), rational.secure(previous_interaction, group + 1), fixed[FIRST], claims[group + 1], denominators, numerators));
    }
}
