//! Native advice recipe only. The polynomial authority authenticates every
//! normalization, bound, product and output through the closed provider graph.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const L = @import("layout.zig");
pub const Request = @import("../trace.zig").Request;
pub const MulRequest = @import("../../multiplication/trace.zig").Request;
pub const Row = struct { main: [L.MAIN]M, support: [2]MulRequest };
fn limbs(output: []M, start: usize, value: u64) void {
    for (0..4) |i| output[start + i] = M.fromCanonical(@as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
}
fn negateCarries(m: []M, src: usize, dst: usize, carry_start: usize, negative: bool, word: bool) void {
    var carry: u32 = 0;
    for (0..4) |i| {
        if (word and i == 2) carry = 0;
        const v: u32 = if (word and i >= 2) 0 else m[src + i].v;
        carry = if (negative) (v + m[dst + i].v + carry) >> 16 else 0;
        m[carry_start + i] = M.fromCanonical(carry);
    }
}
const Operands = struct { op: usize, word: bool, rem: bool, mask: u64, sign_a: bool, sign_b: bool, neg_a: bool, neg_b: bool, abs_a: u64, abs_b: u64, zero: bool, quotient: u64, remainder: u64, product: u128 };
fn normalizeOperands(request: Request) !Operands {
    var op: usize = 0;
    while (op < L.OPCODES.len and L.OPCODES[op] != request.opcode) : (op += 1) {}
    if (op == L.OPCODES.len) return error.InvalidProductDivisionOpcode;
    const word = op >= 4;
    const rem = op % 4 >= 2;
    const signed = op % 2 == 0;
    const mask: u64 = if (word) std.math.maxInt(u32) else std.math.maxInt(u64);
    const x = request.a & mask;
    const y = request.b & mask;
    const sign_a = ((x >> @as(u6, if (word) 31 else 63)) & 1) != 0;
    const sign_b = ((y >> @as(u6, if (word) 31 else 63)) & 1) != 0;
    const neg_a = signed and sign_a;
    const neg_b = signed and sign_b;
    const abs_a = (if (neg_a) 0 -% x else x) & mask;
    const abs_b = (if (neg_b) 0 -% y else y) & mask;
    const zero = abs_b == 0;
    const quotient = if (zero) 0 else abs_a / abs_b;
    const remainder = if (zero) abs_a else abs_a % abs_b;
    return .{ .op = op, .word = word, .rem = rem, .mask = mask, .sign_a = sign_a, .sign_b = sign_b, .neg_a = neg_a, .neg_b = neg_b, .abs_a = abs_a, .abs_b = abs_b, .zero = zero, .quotient = quotient, .remainder = remainder, .product = @as(u128, quotient) * abs_b };
}
fn supportFrom(n: Operands) [2]MulRequest {
    return .{
        .{ .opcode = .MUL, .a = n.quotient, .b = n.abs_b, .result = @truncate(n.product) },
        .{ .opcode = .MULHU, .a = n.quotient, .b = n.abs_b, .result = @intCast(n.product >> 64) },
    };
}
/// Bounded scalar planning recipe, without constructing a wide witness.
pub fn support(request: Request) ![2]MulRequest {
    return supportFrom(try normalizeOperands(request));
}
pub fn row(request: Request) !Row {
    const n = try normalizeOperands(request);
    const gap = if (n.zero) 0 else n.abs_b - n.remainder - 1;
    const neg_out = if (n.rem) n.neg_a else n.neg_a != n.neg_b;
    const chosen = if (n.rem) n.remainder else n.quotient;
    const normalized = (if (neg_out) 0 -% chosen else chosen) & n.mask;
    var result = Row{ .main = @splat(M.zero()), .support = supportFrom(n) };
    const m = &result.main;
    for ([_]usize{ L.A, L.B, L.C, L.ABS_A, L.ABS_B, L.QUOTIENT, L.REMAINDER, L.PRODUCT_LOW, L.PRODUCT_HIGH, L.GAP, L.OUT }, [_]u64{ request.a, request.b, request.result, n.abs_a, n.abs_b, n.quotient, n.remainder, @truncate(n.product), @intCast(n.product >> 64), gap, normalized }) |start, value| limbs(m, start, value);
    m[L.SELECTORS + n.op] = M.one();
    m[L.COUNT] = M.one();
    m[L.SIGN_A] = M.fromCanonical(@intFromBool(n.sign_a));
    m[L.SIGN_B] = M.fromCanonical(@intFromBool(n.sign_b));
    m[L.SIGN_OUT32] = M.fromCanonical(@intCast((normalized >> 31) & 1));
    m[L.NEG_A] = M.fromCanonical(@intFromBool(n.neg_a));
    m[L.NEG_B] = M.fromCanonical(@intFromBool(n.neg_b));
    m[L.NEG_OUT] = M.fromCanonical(@intFromBool(neg_out));
    m[L.ZERO] = M.fromCanonical(@intFromBool(n.zero));
    m[L.ZERO_DIV] = M.fromCanonical(@intFromBool(n.zero and !n.rem));
    var sum_b: u32 = 0;
    for (m[L.ABS_B..][0..4]) |v| sum_b += v.v;
    if (sum_b != 0) m[L.DIVISOR_INVERSE] = try M.fromCanonical(sum_b).inv();
    negateCarries(m, L.A, L.ABS_A, L.CARRY_A, n.neg_a, n.word);
    negateCarries(m, L.B, L.ABS_B, L.CARRY_B, n.neg_b, n.word);
    var carry: u32 = 0;
    var borrow: i64 = 0;
    var out_carry: u32 = 0;
    for (0..4) |i| {
        carry = (m[L.PRODUCT_LOW + i].v + m[L.REMAINDER + i].v + carry) >> 16;
        m[L.CARRY_SUM + i] = M.fromCanonical(carry);
        if (!n.zero) {
            const value = @as(i64, m[L.ABS_B + i].v) - m[L.REMAINDER + i].v - (if (i == 0) @as(i64, 1) else borrow);
            borrow = @intFromBool(value < 0);
            m[L.BORROW_GAP + i] = M.fromCanonical(@intCast(borrow));
        }
        if (n.word and i == 2) out_carry = 0;
        const limb = @as(u16, @truncate(chosen >> @as(u6, @intCast(16 * i))));
        out_carry = if (neg_out) (@as(u32, limb) + m[L.OUT + i].v + out_carry) >> 16 else 0;
        m[L.CARRY_OUT + i] = M.fromCanonical(out_carry);
    }
    return result;
}
