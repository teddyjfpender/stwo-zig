//! OP-only sparse BN254 tower candidate. Not in ethereum_services_v3 admission.
//! Plain Fq coordinates, explicitly ordered, never a language struct transmute.
//! A=(c0.c0,c0.c1,c0.c2,c1.c0,c1.c1,c1.c2), each pair (real,imag).
//! Packet A[12], raw line c0[2], c3[2], c4[2], G1x, G1y; i²=-1,u³=9+i,w²=u.
//! Outputs replace A, leaving the eight line/point coordinates unchanged.
const std = @import("std");
const C = @import("candidate_curves.zig");
pub const Kind = enum(u8) { mul034 = 12 };
pub const TAG: u64 = 0x0004_0001;
pub const INPUTS = 20;
pub const OUTPUTS = 12;
pub const WORDS = INPUTS * 4;
pub const WRITTEN_WORDS = OUTPUTS * 4;
pub const PACKET_BYTES = INPUTS * 32;
pub const WRITTEN_BYTES = OUTPUTS * 32;
const Pair = [2]u256;
const F = C.Bn254;

fn add(a: Pair, b: Pair) Pair {
    return .{ F.add(a[0], b[0]), F.add(a[1], b[1]) };
}
fn nonresidue(a: Pair) Pair {
    const a2 = F.add(a[0], a[0]);
    const b2 = F.add(a[1], a[1]);
    const a4 = F.add(a2, a2);
    const b4 = F.add(b2, b2);
    const a8 = F.add(a4, a4);
    const b8 = F.add(b4, b4);
    return .{ F.sub(F.add(a8, a[0]), a[1]), F.add(a[0], F.add(b8, a[1])) };
}
pub const Evaluation = struct { out: [OUTPUTS]u256, witness: [14]u256 };
/// Compute every base product once. Witnesses preserve 16-bit carried groups:
/// 0..3 are point-scaled lines, 4..7 nonresidue-scaled lines, 8..13 imaginary partial sums.
pub fn evaluate(inputs: *const [INPUTS]u256) Evaluation {
    var a: [6]Pair = undefined;
    for (&a, 0..) |*v, i| v.* = .{ F.reduce(inputs[2 * i]), F.reduce(inputs[2 * i + 1]) };
    const lines = [3]Pair{
        .{ F.reduce(inputs[12]), F.reduce(inputs[13]) },
        .{ F.reduce(inputs[14]), F.reduce(inputs[15]) },
        .{ F.reduce(inputs[16]), F.reduce(inputs[17]) },
    };
    const g1_x = F.reduce(inputs[18]);
    const g1_y = F.reduce(inputs[19]);
    const scaled0 = Pair{ F.mul(lines[0][0], g1_y), F.mul(lines[0][1], g1_y) };
    const scaled3 = Pair{ F.mul(lines[1][0], g1_x), F.mul(lines[1][1], g1_x) };
    const factors = [5]Pair{ scaled0, scaled3, lines[2], nonresidue(scaled3), nonresidue(lines[2]) };
    const lefts = [6][3]usize{ .{ 0, 4, 5 }, .{ 1, 3, 5 }, .{ 2, 3, 4 }, .{ 0, 2, 3 }, .{ 0, 1, 4 }, .{ 1, 2, 5 } };
    const rights = [6][3]usize{ .{ 0, 4, 3 }, .{ 0, 1, 4 }, .{ 0, 2, 1 }, .{ 1, 4, 0 }, .{ 2, 1, 0 }, .{ 2, 1, 0 } };
    var result: Evaluation = undefined;
    result.witness[0..4].* = .{ scaled0[0], scaled0[1], scaled3[0], scaled3[1] };
    result.witness[4..8].* = .{ factors[3][0], factors[3][1], factors[4][0], factors[4][1] };
    for (lefts, rights, 0..) |lhs, rhs, j| {
        var products: [3][4]u256 = undefined;
        for (&products, lhs, rhs) |*p, ai, bi| {
            const x = a[ai];
            const y = factors[bi];
            p.* = .{ F.mul(x[0], y[0]), F.mul(x[1], y[1]), F.mul(x[0], y[1]), F.mul(x[1], y[0]) };
        }
        result.out[2 * j] = F.add(F.add(F.sub(products[0][0], products[0][1]), F.sub(products[1][0], products[1][1])), F.sub(products[2][0], products[2][1]));
        const partial = F.add(F.add(products[0][2], products[0][3]), products[1][2]);
        result.witness[8 + j] = partial;
        result.out[2 * j + 1] = F.add(F.add(partial, products[1][3]), F.add(products[2][2], products[2][3]));
    }
    return result;
}
/// Inputs may be arbitrary 256-bit representatives. The carried identities and
/// authenticated byte inputs determine a unique canonical final output.
pub fn compute(inputs: *const [INPUTS]u256) [OUTPUTS]u256 {
    return evaluate(inputs).out;
}
/// Candidate executor only. Neither this tag nor its larger packet is appended
/// to the legacy curve roster or its fixed-size per-call capture record.
pub fn execute(before: []const u64) error{TowerPacketShape}![WORDS]u64 {
    if (before.len != WORDS) return error.TowerPacketShape;
    var input: [INPUTS]u256 = undefined;
    for (&input, 0..) |*x, i| {
        x.* = 0;
        for (0..4) |j| x.* |= @as(u256, before[4 * i + j]) << @intCast(64 * j);
    }
    const output = compute(&input);
    var after: [WORDS]u64 = undefined;
    @memcpy(&after, before);
    for (output, 0..) |x, i| for (0..4) |j| {
        after[4 * i + j] = @truncate(x >> @intCast(64 * j));
    };
    return after;
}
