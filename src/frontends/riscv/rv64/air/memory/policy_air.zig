//! Concrete QM31 permission-certificate authority. Byte, policy-ROM and Permit
//! claims must all close in the containing batch proof. Local equations alone
//! do not authorize a producer-selected mapping policy or RAM transition.
const core = @import("stwo_core");
const std = @import("std");
const E = @import("../evaluation.zig");
const policy = @import("policy.zig");
pub const Q = core.fields.qm31.QM31;
pub const M = core.fields.m31.M31;
pub const MAIN = 57;
pub const RANGES = 25; // address8, lower-distance8, upper-distance8, alignment1.
pub const BYTE_SUMS = (RANGES + 2) / 3;
pub const SUMS = BYTE_SUMS + 2;
pub const INTERACTION = 4 * SUMS;
pub const CONSTRAINTS = 35 + SUMS;
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const ADDRESS = 0;
pub const REGION_FIRST = 8;
pub const REGION_LAST = 16;
pub const FROM_FIRST = 24;
pub const TO_LAST = 32;
pub const CARRY_FROM = 40;
pub const CARRY_TO = 47;
pub const READ = 54;
pub const WRITE = 55;
pub const ALIGN = 56;
pub const POLICY_SUM = BYTE_SUMS;
pub const PERMIT_SUM = BYTE_SUMS + 1;
pub const PolicyTuple = [18]Q;
pub const PermitTuple = [11]Q;
pub const Claims = [SUMS]Q;
pub const Term = struct { denominator: Q, numerator: Q };

pub const PolicyChallenge = struct {
    offset: Q,
    coefficients: [18]Q,
    pub fn draw(channel: *@import("../protocol.zig").Channel) PolicyChallenge {
        channel.mixU32s(&.{ 0x52565032, 0x504f4c59 });
        var result = PolicyChallenge{ .offset = channel.drawSecureFelt(), .coefficients = undefined };
        for (&result.coefficients) |*value| value.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: PolicyChallenge, tuple: PolicyTuple) Q {
        var result = self.offset;
        for (tuple, self.coefficients) |value, coefficient| result = result.sub(value.mul(coefficient));
        return result;
    }
};
pub const PermitChallenge = struct {
    offset: Q,
    coefficients: [11]Q,
    pub fn draw(channel: *@import("../protocol.zig").Channel) PermitChallenge {
        channel.mixU32s(&.{ 0x52565032, 0x5045524d });
        var result = PermitChallenge{ .offset = channel.drawSecureFelt(), .coefficients = undefined };
        for (&result.coefficients) |*value| value.* = channel.drawSecureFelt();
        return result;
    }
    pub fn denominator(self: PermitChallenge, tuple: PermitTuple) Q {
        var result = self.offset;
        for (tuple, self.coefficients) |value, coefficient| result = result.sub(value.mul(coefficient));
        return result;
    }
};
pub const Challenges = struct { bytes: Q, policy: PolicyChallenge, permit: PermitChallenge };

pub fn rangeField(index: usize) usize {
    std.debug.assert(index < RANGES);
    return if (index < 8) ADDRESS + index else if (index < 16) FROM_FIRST + index - 8 else if (index < 24) TO_LAST + index - 16 else ALIGN;
}

fn bytes(row: *Row, offset: usize, value: u64) void {
    for (0..8) |i| row[offset + i] = M.fromCanonical(@intCast((value >> @intCast(8 * i)) & 255));
}

pub fn fill(span: policy.Span, address: u64, grant: policy.Grant) !Row {
    if (grant.mask == 0 or address & (span.bytes() - 1) != 0) return error.InvalidRamPolicyCertificate;
    const last = try std.math.add(u64, address, span.bytes() - 1);
    if (address < grant.first or grant.last < last) return error.RamPolicyAccessDenied;
    var row: Row = @splat(M.zero());
    bytes(&row, ADDRESS, address);
    bytes(&row, REGION_FIRST, grant.first);
    bytes(&row, REGION_LAST, grant.last);
    bytes(&row, FROM_FIRST, address - grant.first);
    bytes(&row, TO_LAST, grant.last - last);
    row[READ] = M.fromCanonical(grant.mask & 1);
    row[WRITE] = M.fromCanonical((grant.mask >> 1) & 1);
    row[ALIGN] = M.fromCanonical(@intCast(if (span == .word8) (address & 255) / 8 else ((address >> 8) & 255) / (span.bytes() / 256)));
    var lower_carry: u32 = 0;
    var upper_carry: u32 = 0;
    for (0..8) |i| {
        const end_byte = @as(u32, @intCast((last >> @intCast(8 * i)) & 255));
        lower_carry = (row[REGION_FIRST + i].toU32() + row[FROM_FIRST + i].toU32() + lower_carry) >> 8;
        upper_carry = (end_byte + row[TO_LAST + i].toU32() + upper_carry) >> 8;
        if (i < 7) {
            row[CARRY_FROM + i] = M.fromCanonical(lower_carry);
            row[CARRY_TO + i] = M.fromCanonical(upper_carry);
        }
    }
    if (lower_carry != 0 or upper_carry != 0) return error.InvalidRamPolicyCertificate;
    return row;
}

pub fn policyTuple(main: *const SecureRow) PolicyTuple {
    var result: PolicyTuple = undefined;
    @memcpy(result[0..8], main[REGION_FIRST..][0..8]);
    @memcpy(result[8..16], main[REGION_LAST..][0..8]);
    result[16] = main[READ];
    result[17] = main[WRITE];
    return result;
}

pub fn grantTuple(grant: policy.Grant) PolicyTuple {
    var result: PolicyTuple = undefined;
    for (0..8) |i| {
        result[i] = E.q(@intCast((grant.first >> @intCast(8 * i)) & 255));
        result[8 + i] = E.q(@intCast((grant.last >> @intCast(8 * i)) & 255));
    }
    result[16] = E.q(grant.mask & 1);
    result[17] = E.q((grant.mask >> 1) & 1);
    return result;
}

pub fn permitTuple(main: *const SecureRow, span: policy.Span) PermitTuple {
    var result: PermitTuple = undefined;
    @memcpy(result[0..8], main[ADDRESS..][0..8]);
    result[8] = E.q(span.log());
    result[9] = main[READ];
    result[10] = main[WRITE];
    return result;
}

pub fn secure(columns: []const Q, group: usize) Q {
    const at = 4 * group;
    return columns[at].add(columns[at + 1].mul(Q.fromU32Unchecked(0, 1, 0, 0)))
        .add(columns[at + 2].mul(Q.fromU32Unchecked(0, 0, 1, 0)))
        .add(columns[at + 3].mul(Q.fromU32Unchecked(0, 0, 0, 1)));
}

/// Cyclic prefixes avoid an inverse column per rational term. The first-row
/// correction uses the transcript-bound FINAL claim, not first*previous.
pub fn triple(sum: Q, previous: Q, first: Q, claim: Q, denominators: [3]Q, numerators: [3]Q) Q {
    const pair01 = denominators[0].mul(denominators[1]);
    const product = pair01.mul(denominators[2]);
    const numerator = numerators[0].mul(denominators[1]).mul(denominators[2])
        .add(numerators[1].mul(denominators[0]).mul(denominators[2]))
        .add(numerators[2].mul(pair01));
    return sum.sub(previous).add(first.mul(claim)).mul(product).sub(numerator);
}

pub fn evaluate(span: policy.Span, first: Q, active: Q, main: *const SecureRow, interaction: []const Q, previous: []const Q, claims: Claims, challenges: Challenges, out: *E.Sink) void {
    var carry_lower = Q.zero();
    var carry_upper = Q.zero();
    for (0..8) |i| {
        const next_lower = if (i == 7) Q.zero() else main[CARRY_FROM + i];
        const next_upper = if (i == 7) Q.zero() else main[CARRY_TO + i];
        const end_byte = switch (span) {
            .word8 => if (i == 0) main[ADDRESS].add(E.q(7)) else main[ADDRESS + i],
            .chunk512, .page4096 => if (i == 0) E.q(255) else if (i == 1) main[ADDRESS + 1].add(E.q(@intCast(span.bytes() / 256 - 1))) else main[ADDRESS + i],
        };
        out.emit(active.mul(main[REGION_FIRST + i].add(main[FROM_FIRST + i]).add(carry_lower).sub(main[ADDRESS + i]).sub(E.q(256).mul(next_lower))));
        out.emit(active.mul(end_byte.add(main[TO_LAST + i]).add(carry_upper).sub(main[REGION_LAST + i]).sub(E.q(256).mul(next_upper))));
        if (i < 7) {
            out.emit(active.mul(next_lower).mul(next_lower.sub(Q.one())));
            out.emit(active.mul(next_upper).mul(next_upper.sub(Q.one())));
        }
        carry_lower = next_lower;
        carry_upper = next_upper;
    }
    out.emit(active.mul(main[READ]).mul(main[READ].sub(Q.one())));
    out.emit(active.mul(main[WRITE]).mul(main[WRITE].sub(Q.one())));
    out.emit(active.mul(Q.one().sub(main[READ])).mul(Q.one().sub(main[WRITE])));
    out.emit(active.mul(main[ADDRESS].sub(if (span == .word8) main[ALIGN].mul(E.q(8)) else Q.zero())));
    out.emit(if (span != .word8) active.mul(main[ADDRESS + 1].sub(main[ALIGN].mul(E.q(@intCast(span.bytes() / 256))))) else Q.zero());
    for (0..BYTE_SUMS) |group| {
        var denominators: [3]Q = @splat(Q.one());
        var numerators: [3]Q = @splat(Q.zero());
        for (0..3) |slot| {
            const index = group * 3 + slot;
            if (index < RANGES) {
                denominators[slot] = challenges.bytes.sub(main[rangeField(index)]);
                numerators[slot] = active;
            }
        }
        out.emit(triple(secure(interaction, group), secure(previous, group), first, claims[group], denominators, numerators));
    }
    const policy_delta = secure(interaction, POLICY_SUM).sub(secure(previous, POLICY_SUM)).add(first.mul(claims[POLICY_SUM]));
    const permit_delta = secure(interaction, PERMIT_SUM).sub(secure(previous, PERMIT_SUM)).add(first.mul(claims[PERMIT_SUM]));
    out.emit(policy_delta.mul(challenges.policy.denominator(policyTuple(main))).sub(active));
    out.emit(permit_delta.mul(challenges.permit.denominator(permitTuple(main, span))).add(active));
}
