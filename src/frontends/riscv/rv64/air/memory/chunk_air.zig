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
pub fn ClaimsFor(comptime C: type) type {
    return [SUMS]C;
}
pub const Claims = ClaimsFor(Q);
const LegacyRelations = @import("../../../air/relation_challenges.zig").Relations;
pub const PermutationChallenge = @FieldType(LegacyRelations, "poseidon2_io");
/// Poseidon2 full-I/O relation over constant lane C: the pinned Stark-V
/// elements natively; z plus thirty-two alpha powers derived with lane
/// arithmetic from the two draws otherwise. `combine` is the same polynomial.
pub fn PermutationChallengeFor(comptime C: type) type {
    if (C == Q) return PermutationChallenge;
    return struct {
        z: C,
        alpha: C,
        alpha_powers: [32]C,
        pub fn init(z: C, alpha: C) @This() {
            var power = C.one();
            var powers: [32]C = undefined;
            for (&powers) |*slot| {
                slot.* = power;
                power = power.mul(alpha);
            }
            return .{ .z = z, .alpha = alpha, .alpha_powers = powers };
        }
        pub fn combine(self: @This(), tuple: [32]C) C {
            var result = C.zero();
            for (tuple, self.alpha_powers) |value, power| result = result.add(power.mul(value));
            return result.sub(self.z);
        }
    };
}
/// Chunk challenges over constant lane C (QM31 natively, external wires otherwise).
pub fn ChallengesFor(comptime C: type) type {
    return struct { ram: relation.PreparedFor(C), io: PermutationChallengeFor(C) };
}
pub const Challenges = ChallengesFor(Q);
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
    return inputFor(Q, shape, fixed, main, previous);
}
pub fn inputFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous: *const [MAIN]F) [16]F {
    var result: [16]F = previous[OUTPUT..][0..16].*;
    for (0..7) |i| result[i] = result[i].add(main[PAYLOAD + i]);
    result[14] = result[14].add(fixed[HASH_FIRST].mul(E.qFor(F, 32 * values.VERSION + shape.geometry.logBytes())));
    result[15] = result[15].add(fixed[HASH_FIRST].mul(E.qFor(F, values.DOMAIN)));
    return result;
}

pub fn digest(main: *const SecureRow, previous: *const SecureRow) [9]Q {
    return digestFor(Q, main, previous);
}
pub fn digestFor(comptime F: type, main: *const [MAIN]F, previous: *const [MAIN]F) [9]F {
    var result: [9]F = undefined;
    @memcpy(result[0..7], previous[OUTPUT..][0..7]);
    @memcpy(result[7..9], main[OUTPUT..][0..2]);
    return result;
}

pub fn ioDenominator(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, challenge: PermutationChallenge) Q {
    return ioDenominatorFor(Q, shape, fixed, main, previous, challenge);
}
pub fn ioDenominatorFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous: *const [MAIN]F, challenge: PermutationChallengeFor(F)) F {
    var tuple: [32]F = undefined;
    @memcpy(tuple[0..16], &inputFor(F, shape, fixed, main, previous));
    @memcpy(tuple[16..32], main[OUTPUT..][0..16]);
    return challenge.combine(tuple);
}

pub fn ioTerm(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, challenge: PermutationChallenge) rational.Term {
    return ioTermFor(Q, shape, fixed, main, previous, challenge);
}
pub fn ioTermFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous: *const [MAIN]F, challenge: PermutationChallengeFor(F)) rational.TermFor(F) {
    return .{ .denominator = ioDenominatorFor(F, shape, fixed, main, previous, challenge), .numerator = main[ACTIVE].mul(F.one().sub(fixed[RESET])).neg() };
}

pub fn ramTerm(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, challenges: *const relation.Prepared, slot: usize) rational.Term {
    return ramTermFor(Q, shape, fixed, main, previous, challenges, slot);
}
pub fn ramTermFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous: *const [MAIN]F, challenges: *const relation.PreparedFor(F), slot: usize) rational.TermFor(F) {
    if (slot == 7) return .{ .denominator = challenges.digest(fixed[HASH_ID], digestFor(F, main, previous)), .numerator = main[ACTIVE].mul(fixed[SQUEEZE]).neg() };
    if (slot >= 8) return .{ .denominator = F.one(), .numerator = F.zero() };
    const phase = fixed[INDEX].sub(fixed[HASH_ID].mul(E.qFor(F, @intCast(shape.stride()))));
    var is_data = F.one().sub(fixed[SQUEEZE]).sub(fixed[RESET]);
    if (slot >= (4 * shape.geometry.cells()) % 7) is_data = is_data.sub(fixed[LAST_ABSORB]);
    return .{ .denominator = challenges.payload(fixed[HASH_ID], phase.mul(E.qFor(F, 7)).add(E.qFor(F, @intCast(slot))), main[PAYLOAD + slot]), .numerator = main[ACTIVE].mul(is_data) };
}

pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous_main: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    return evaluateFor(Q, shape, fixed, main, previous_main, interaction, previous_interaction, claims, challenges, prefix.rows(shape.activeRows(), @intCast(shape.size())), out);
}
/// Same residuals over any secure lane; `rows` carries the active-row publics.
pub fn evaluateFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous_main: *const [MAIN]F, interaction: []const F, previous_interaction: []const F, claims: ClaimsFor(F), challenges: *const ChallengesFor(F), rows: prefix.RowsFor(F), out: *E.SinkFor(F)) void {
    const active = main[ACTIVE];
    prefix.evaluateFor(F, active, previous_main[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], rows, out);
    const clear_output = F.one().sub(active).add(fixed[RESET]);
    for (0..16) |i| out.emit(clear_output.mul(main[OUTPUT + i]));
    const clear_payload = F.one().sub(active).add(fixed[RESET]).add(fixed[SQUEEZE]);
    for (0..7) |i| out.emit(clear_payload.mul(main[PAYLOAD + i]));
    const tail = (4 * shape.geometry.cells()) % 7;
    for (tail..7) |i| out.emit(active.mul(fixed[LAST_ABSORB]).mul(main[PAYLOAD + i].sub(E.qFor(F, @intFromBool(i == tail)))));
    const io_delta = rational.secureFor(F, interaction, 0).sub(rational.secureFor(F, previous_interaction, 0)).add(fixed[FIRST].mul(claims[0]));
    const io = ioTermFor(F, shape, fixed, main, previous_main, challenges.io);
    out.emit(io_delta.mul(io.denominator).sub(io.numerator));
    for (0..3) |group| {
        var denominators: [3]F = undefined;
        var numerators: [3]F = undefined;
        for (0..3) |slot| {
            const term = ramTermFor(F, shape, fixed, main, previous_main, &challenges.ram, group * 3 + slot);
            denominators[slot] = term.denominator;
            numerators[slot] = term.numerator;
        }
        out.emit(rational.tripleFor(F, rational.secureFor(F, interaction, group + 1), rational.secureFor(F, previous_interaction, group + 1), fixed[FIRST], claims[group + 1], denominators, numerators));
    }
}
