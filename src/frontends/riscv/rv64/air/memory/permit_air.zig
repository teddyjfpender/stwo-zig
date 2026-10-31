//! Active-prefix shell around the single immutable-policy certificate authority.
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const authority = @import("policy_air.zig");
const policy = @import("policy.zig");
const prefix = @import("prefix.zig");
pub const Q = E.Q;
pub const M = core.fields.m31.M31;
pub const MAIN = authority.MAIN + 1;
pub const ACTIVE = authority.MAIN;
pub const FIXED = 3;
pub const FIRST = 0;
pub const LAST = 1;
pub const INDEX = 2;
pub const SUMS = authority.SUMS;
pub const INTERACTION = authority.INTERACTION;
pub const CONSTRAINTS = authority.CONSTRAINTS + 5;
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const Fixed = [FIXED]Q;
pub const ClaimsFor = authority.ClaimsFor;
pub const Claims = authority.Claims;
pub const ChallengesFor = authority.ChallengesFor;
pub const Challenges = authority.Challenges;
pub const Term = authority.Term;
pub const Shape = struct {
    span: policy.Span,
    certificates: u32,
    log_size: u32,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn activeRows(self: Shape) u32 {
        return self.certificates;
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 24 or self.certificates > self.size()) return error.InvalidPrivateRamPermitShape;
    }
    pub fn fixedAt(self: Shape, i: usize) [FIXED]M {
        return .{ M.fromCanonical(@intFromBool(i == 0)), M.fromCanonical(@intFromBool(i + 1 == self.size())), M.fromCanonical(@intCast(i)) };
    }
};
pub fn term(shape: Shape, main: *const SecureRow, challenge: *const Challenges, group: usize, slot: usize) Term {
    return termFor(Q, shape, main, challenge, group, slot);
}
pub fn termFor(comptime F: type, shape: Shape, main: *const [MAIN]F, challenge: *const ChallengesFor(F), group: usize, slot: usize) authority.TermFor(F) {
    const active = main[ACTIVE];
    if (group < authority.BYTE_SUMS) {
        const index = group * 3 + slot;
        return if (index < authority.RANGES) .{ .denominator = challenge.bytes.sub(main[authority.rangeField(index)]), .numerator = active } else .{ .denominator = F.one(), .numerator = F.zero() };
    }
    if (slot != 0) return .{ .denominator = F.one(), .numerator = F.zero() };
    return if (group == authority.POLICY_SUM) .{ .denominator = challenge.policy.denominator(authority.policyTupleFor(F, main[0..authority.MAIN])), .numerator = active } else .{ .denominator = challenge.permit.denominator(authority.permitTupleFor(F, main[0..authority.MAIN], shape.span)), .numerator = active.neg() };
}
pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    return evaluateFor(Q, shape, fixed, main, previous, interaction, previous_interaction, claims, challenges, prefix.rows(shape.certificates, @intCast(shape.size())), out);
}
/// Same residuals over any secure lane; `rows` carries the active-row publics.
pub fn evaluateFor(comptime F: type, shape: Shape, fixed: *const [FIXED]F, main: *const [MAIN]F, previous: *const [MAIN]F, interaction: []const F, previous_interaction: []const F, claims: ClaimsFor(F), challenges: *const ChallengesFor(F), rows: prefix.RowsFor(F), out: *E.SinkFor(F)) void {
    prefix.evaluateFor(F, main[ACTIVE], previous[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], rows, out);
    authority.evaluateFor(F, shape.span, fixed[FIRST], main[ACTIVE], main[0..authority.MAIN], interaction, previous_interaction, claims, challenges.*, out);
}
pub fn fill(span: policy.Span, address: u64, grant: policy.Grant) !Row {
    var row: Row = undefined;
    @memcpy(row[0..authority.MAIN], &try authority.fill(span, address, grant));
    row[ACTIVE] = M.one();
    return row;
}
