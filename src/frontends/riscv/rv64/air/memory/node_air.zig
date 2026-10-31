//! Private Merkle node caller. Four output states are physical; every input is
//! reconstructed LINEARLY using the qualified ethereum_node_v1 framing. Node
//! positions and unit supply/demand form the separately closed private graph.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const qualified = @import("../../../air/memory_commitment/ethereum_node_v1.zig");
const C = @import("chunk_air.zig");
const relation = @import("internal_relations.zig");
const rational = @import("policy_air.zig");
const prefix = @import("prefix.zig");
const values = @import("values.zig");
pub const M = core.fields.m31.M31;
pub const Q = E.Q;
pub const KIND = 0;
pub const HEIGHT_BITS = 1;
pub const LEFT = 6;
pub const RIGHT = 15;
pub const OUTPUTS = 24;
pub const INDEX_BYTES = 88;
pub const CHILD_BYTES = 95;
pub const CARRIES = 102;
pub const EPOCH = 108;
pub const REUSE = 109;
pub const ACTIVE = 110;
pub const MAIN = 111;
pub const FIXED = 3;
pub const FIRST = 0;
pub const LAST = 1;
pub const INDEX = 2;
pub const SUMS = 9; // 2 IO batches, 2 node batches, 5 byte batches.
pub const INTERACTION = 4 * SUMS;
pub const CONSTRAINTS = 36; // prefix5 + hash bits6 + epoch/reuse3 + carry6 + additions7 + sums9.
pub const Row = [MAIN]M;
pub const SecureRow = [MAIN]Q;
pub const Fixed = [FIXED]Q;
pub const Claims = [SUMS]Q;
pub const Term = @import("policy_air.zig").Term;
pub const Challenges = struct { io: C.PermutationChallenge, ram: relation.Prepared, bytes: Q };
pub const Shape = struct {
    nodes: u32,
    log_size: u32,
    pub fn size(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn activeRows(self: Shape) u32 {
        return self.nodes;
    }
    pub fn validate(self: Shape) !void {
        if (self.log_size < 4 or self.log_size > 24 or self.nodes > self.size()) return error.InvalidPrivateRamNodeShape;
    }
    pub fn fixedAt(self: Shape, i: usize) [FIXED]M {
        return .{ M.fromCanonical(@intFromBool(i == 0)), M.fromCanonical(@intFromBool(i + 1 == self.size())), M.fromCanonical(@intCast(i)) };
    }
};
/// Same framing authority as the qualified node kernel; no separate copied
/// sponge schedule. Inputs and digest are derived, not independently supplied.
pub fn hashRow(main: *const SecureRow) qualified.Row(Q) {
    var row: qualified.Row(Q) = undefined;
    row.kind = main[KIND];
    @memcpy(&row.height_bits, main[HEIGHT_BITS..][0..5]);
    @memcpy(&row.left, main[LEFT..][0..9]);
    @memcpy(&row.right, main[RIGHT..][0..9]);
    for (&row.outputs, 0..) |*output, i| @memcpy(output, main[OUTPUTS + 16 * i ..][0..16]);
    const words = qualified.absorptionWords(Q, row);
    var state: [16]Q = @splat(Q.zero());
    state[15] = E.q(qualified.DOMAIN).add(row.kind);
    for (0..4) |call| {
        if (call < 3) for (0..7) |lane| {
            state[lane] = state[lane].add(words[7 * call + lane]);
        };
        row.inputs[call] = state;
        state = row.outputs[call];
    }
    @memcpy(row.digest[0..7], row.outputs[2][0..7]);
    @memcpy(row.digest[7..9], row.outputs[3][0..2]);
    return row;
}
pub fn height(main: *const SecureRow) Q {
    var result = Q.one().add(E.q(32).mul(main[KIND]));
    for (0..5) |i| result = result.add(E.q(@as(u32, 1) << @intCast(i)).mul(main[HEIGHT_BITS + i]));
    return result;
}
pub fn ioTerm(main: *const SecureRow, challenge: C.PermutationChallenge, slot: usize) Term {
    if (slot >= 4) return .{ .denominator = Q.one(), .numerator = Q.zero() };
    const row = hashRow(main);
    var tuple: [32]Q = undefined;
    @memcpy(tuple[0..16], &row.inputs[slot]);
    @memcpy(tuple[16..32], &row.outputs[slot]);
    return .{ .denominator = challenge.combine(tuple), .numerator = main[ACTIVE].neg() };
}
pub fn nodeTerm(main: *const SecureRow, challenge: *const relation.Prepared, slot: usize) Term {
    if (slot >= 4) return .{ .denominator = Q.one(), .numerator = Q.zero() };
    const row = hashRow(main);
    const h = height(main);
    const active = main[ACTIVE];
    var index = main[INDEX_BYTES..][0..7].*;
    return switch (slot) {
        0 => .{ .denominator = challenge.node(main[EPOCH], h, index, row.digest), .numerator = active.neg() },
        1 => .{ .denominator = challenge.node(Q.one(), h, index, row.digest), .numerator = active.mul(main[REUSE]).neg() },
        2 => .{ .denominator = challenge.node(main[EPOCH], h.sub(Q.one()), main[CHILD_BYTES..][0..7].*, row.left), .numerator = active },
        3 => blk: {
            index = main[CHILD_BYTES..][0..7].*;
            index[0] = index[0].add(Q.one());
            break :blk .{ .denominator = challenge.node(main[EPOCH], h.sub(Q.one()), index, row.right), .numerator = active };
        },
        else => unreachable,
    };
}
pub fn byteTerm(main: *const SecureRow, alpha: Q, slot: usize) Term {
    return if (slot < 14) .{ .denominator = alpha.sub(main[INDEX_BYTES + slot]), .numerator = main[ACTIVE] } else .{ .denominator = Q.one(), .numerator = Q.zero() };
}
pub fn evaluate(shape: Shape, fixed: *const Fixed, main: *const SecureRow, previous: *const SecureRow, interaction: []const Q, previous_interaction: []const Q, claims: Claims, challenges: *const Challenges, out: *E.Sink) void {
    prefix.evaluate(main[ACTIVE], previous[ACTIVE], fixed[FIRST], fixed[LAST], fixed[INDEX], shape.nodes, @intCast(shape.size()), out);
    out.emit(main[KIND].mul(main[KIND].sub(Q.one())));
    for (main[HEIGHT_BITS..][0..5]) |bit| out.emit(bit.mul(bit.sub(Q.one())));
    out.emit(main[EPOCH].mul(main[EPOCH].sub(Q.one())));
    out.emit(main[REUSE].mul(main[REUSE].sub(Q.one())));
    out.emit(main[EPOCH].mul(main[REUSE]));
    for (main[CARRIES..][0..6]) |carry| out.emit(carry.mul(carry.sub(Q.one())));
    for (0..7) |i| {
        const input_carry = if (i == 0) Q.zero() else main[CARRIES + i - 1];
        const output_carry = if (i == 6) Q.zero() else main[CARRIES + i];
        out.emit(E.q(2).mul(main[INDEX_BYTES + i]).add(input_carry).sub(main[CHILD_BYTES + i]).sub(E.q(256).mul(output_carry)));
    }
    for (0..SUMS) |group| {
        var denominators: [3]Q = undefined;
        var numerators: [3]Q = undefined;
        for (0..3) |j| {
            const term = if (group < 2) ioTerm(main, challenges.io, group * 3 + j) else if (group < 4) nodeTerm(main, &challenges.ram, (group - 2) * 3 + j) else byteTerm(main, challenges.bytes, (group - 4) * 3 + j);
            denominators[j] = term.denominator;
            numerators[j] = term.numerator;
        }
        out.emit(rational.triple(rational.secure(interaction, group), rational.secure(previous_interaction, group), fixed[FIRST], claims[group], denominators, numerators));
    }
}
/// Uses the already filled provider outputs: no second permutation execution.
pub fn rowFromRecorded(node_height: u6, index: u64, epoch: u1, reuse: bool, left: values.Digest, right: values.Digest, ios: *const [4]values.PermutationIO) !Row {
    if (node_height == 0 or node_height > 55 or index >= @as(u64, 1) << 55 or (epoch == 1 and reuse)) return error.InvalidPrivateRamNode;
    var row: Row = @splat(M.zero());
    row[KIND] = M.fromCanonical((@as(u32, node_height) - 1) >> 5);
    for (0..5) |i| row[HEIGHT_BITS + i] = M.fromCanonical(((@as(u32, node_height) - 1) >> @intCast(i)) & 1);
    for (left, right, 0..) |l, r, i| {
        if (l >= core.fields.m31.Modulus or r >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        row[LEFT + i] = M.fromCanonical(l);
        row[RIGHT + i] = M.fromCanonical(r);
    }
    for (ios, 0..) |io, call| @memcpy(row[OUTPUTS + 16 * call ..][0..16], &io.output);
    for (0..7) |i| {
        row[INDEX_BYTES + i] = M.fromCanonical(@intCast((index >> @intCast(8 * i)) & 255));
        row[CHILD_BYTES + i] = M.fromCanonical(@intCast(((2 * index) >> @intCast(8 * i)) & 255));
        if (i < 6) row[CARRIES + i] = M.fromCanonical(@intCast((index >> @intCast(8 * i + 7)) & 1));
    }
    row[EPOCH] = M.fromCanonical(epoch);
    row[REUSE] = M.fromCanonical(@intFromBool(reuse));
    row[ACTIVE] = M.one();
    return row;
}
pub fn fill(node_height: u6, index: u64, epoch: u1, reuse: bool, left: values.Digest, right: values.Digest, ios: *const [4]values.PermutationIO) !Row {
    const row = try rowFromRecorded(node_height, index, epoch, reuse, left, right, ios);
    var secure: SecureRow = undefined;
    for (&secure, row) |*field, base| field.* = Q.fromBase(base);
    const reconstructed = hashRow(&secure);
    for (reconstructed.inputs, ios) |input, io| for (input, io.input) |actual, expected| if (!actual.eql(Q.fromBase(expected))) return error.InvalidPrivateRamNodeIO;
    return row;
}
