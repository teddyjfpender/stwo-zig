//! OP-only sparse BN254 tower candidate. Not in ethereum_services_v3 admission.
//! Plain Fq coordinates, explicitly ordered, never a language struct transmute.
//! A=(c0.c0,c0.c1,c0.c2,c1.c0,c1.c1,c1.c2), each pair (real,imag).
//! Packet A[12], line c0[2], c3[2], c4[2]; i²=-1,u³=9+i,w²=u.
//! Outputs replace A, leaving the six line coordinates unchanged.
const std = @import("std");
const C = @import("candidate_curves.zig");
pub const Kind = enum(u8) { mul034 = 12 };
pub const TAG: u64 = 0x0003_0130;
pub const INPUTS = 18;
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
    const a9 = F.add(F.add(F.add(a[0], a[0]), F.add(a[0], a[0])), F.add(F.add(a[0], a[0]), F.add(a[0], a[0])));
    const b9 = F.add(F.add(F.add(a[1], a[1]), F.add(a[1], a[1])), F.add(F.add(a[1], a[1]), F.add(a[1], a[1])));
    return .{ F.sub(F.add(a9, a[0]), a[1]), F.add(a[0], F.add(b9, a[1])) };
}
/// Independent tower multiplication. Inputs may be any 256-bit representatives;
/// Wire35 must authenticate all input bytes, and the AIR checks canonical output.
pub fn compute(inputs: *const [INPUTS]u256) [OUTPUTS]u256 {
    var a: [6]Pair = undefined;
    for (&a, 0..) |*v, i| v.* = .{ F.reduce(inputs[2 * i]), F.reduce(inputs[2 * i + 1]) };
    var line: [3]Pair = undefined;
    for (&line, 0..) |*v, i| v.* = .{ F.reduce(inputs[12 + 2 * i]), F.reduce(inputs[13 + 2 * i]) };
    var result: [6]Pair = @splat(.{ 0, 0 });
    for (a, 0..) |x, i| for (line, [_]usize{ 0, 3, 4 }) |y, j| {
        var u = i % 3 + j % 3;
        var w = i / 3 + j / 3;
        var value = C.fp2Mul(F, u256, x, y);
        if (w == 2) {
            w = 0;
            u += 1;
        }
        if (u >= 3) {
            u -= 3;
            value = nonresidue(value);
        }
        result[u + 3 * w] = add(result[u + 3 * w], value);
    };
    var out: [OUTPUTS]u256 = undefined;
    for (result, 0..) |v, i| {
        out[2 * i] = v[0];
        out[2 * i + 1] = v[1];
    }
    return out;
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
