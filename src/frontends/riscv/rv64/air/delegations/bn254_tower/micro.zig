//! Narrow degree-three arithmetic row for the immutable Miller-line DAG.
//! This is a closed-admission foundation: the physical local-SSA relation and
//! global input frontier must close before the OP request guard can be opened.
const std = @import("std");
const E = @import("../../evaluation.zig");
const B = @import("../curves/spec.zig");
const D = @import("dag.zig");
const Big = B.Big;
/// The signed linear terms are bounded independently in both directions.
/// They deliberately appear with both signs in this envelope: this is a
/// no-wrap certificate for all immutable instructions, not the AIR identity.
const envelope = B.Def{
    .limbs = 32,
    .coords = 7,
    .written = 1,
    .inputs = 7,
    .outputs = 1,
    .witnesses = 0,
    .modulus = .{ .constant = B.BN254_P },
    .asymmetric_carries = true,
    .relations = &.{&.{
        .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = 1 },
        .{ .a = .{ .in = 2 }, .b = .{ .in = 3 }, .coef = 1 },
        .{ .a = .{ .in = 4 }, .b = .{ .in = 5 }, .coef = 1 },
        .{ .a = .{ .in = 6 }, .coef = 1 },
        .{ .a = .{ .in = 6 }, .coef = -1 },
        .{ .a = .{ .out = 0 }, .coef = 1 },
        .{ .a = .{ .out = 0 }, .coef = -1 },
    }},
};
pub const G = B.deriveRelation(envelope, envelope.relations[0]);
pub const ACTIVE = 0;
pub const OPERANDS = 1;
pub const RESULT = OPERANDS + 7 * 32;
pub const QUOTIENT = RESULT + 32;
pub const CARRY = QUOTIENT + G.q_bytes;
// A carry is one source-bounded U15 limb, not two bytes plus a top-bit query.
// It is authenticated by a distinct immutable carry-range table.
pub const CARRY_LIMIT: u32 = 1 << G.carry_bits;
pub const DISTANCE = CARRY + G.carries;
pub const BORROW = DISTANCE + 32;
pub const MAIN = BORROW + 15;
pub const Row = [MAIN]u32;
/// Source-owned periodic preprocessing. Literal constraints prevent a constant
/// zero/nine operand becoming an unconstrained local-bus exemption.
pub const Fixed = enum(usize) { addend_negative, output_negative, literal0, literal1, literal2, literal3, literal4, literal5, literal6, nine0, nine1, nine2, nine3, nine4, nine5, nine6 };
pub const FIXED = @typeInfo(Fixed).@"enum".fields.len;
pub fn fixed(step: usize) [FIXED]u32 {
    std.debug.assert(step < D.STEPS);
    const instruction = D.PROGRAM[step];
    var out: [FIXED]u32 = @splat(0);
    out[@intFromEnum(Fixed.addend_negative)] = @intFromBool(instruction.addend_negative);
    out[@intFromEnum(Fixed.output_negative)] = @intFromBool(instruction.output_negative);
    for (instruction.operands(), 0..) |id, slot| {
        out[@intFromEnum(Fixed.literal0) + slot] = @intFromBool(D.literal(id) != null);
        out[@intFromEnum(Fixed.nine0) + slot] = @intFromBool(id == D.NINE);
    }
    return out;
}
fn put(row: *Row, start: usize, bytes: usize, x: Big) void {
    for (0..bytes) |i| row[start + i] = B.limbOf(x, i);
}
pub fn read(row: *const Row, start: usize) u256 {
    var value: u256 = 0;
    for (0..32) |i| value |= @as(u256, row[start + i]) << @intCast(8 * i);
    return value;
}
/// A row's quotient and carry advice is computed from integer byte arithmetic;
/// none of these witness computations substitutes for its AIR constraints.
pub fn fill(step: usize, values: *const [D.VALUES]u256) Row {
    const instruction = D.PROGRAM[step];
    var row: Row = @splat(0);
    row[ACTIVE] = 1;
    var operands: [D.OPERANDS]u256 = undefined;
    for (instruction.operands(), &operands, 0..) |id, *operand, slot| {
        operand.* = D.read(values, id);
        put(&row, OPERANDS + 32 * slot, 32, operand.*);
    }
    const output = D.result(instruction, &operands);
    put(&row, RESULT, 32, output);
    var positive = G.kp;
    var negative: Big = 0;
    for (0..3) |i| positive += @as(Big, operands[2 * i]) * operands[2 * i + 1];
    if (instruction.addend_negative) negative += operands[6] else positive += operands[6];
    if (instruction.output_negative) negative += output else positive += output;
    std.debug.assert(positive >= negative and (positive - negative) % B.BN254_P == 0);
    const quotient = (positive - negative) / B.BN254_P;
    std.debug.assert(quotient >> @intCast(8 * G.q_bytes) == 0);
    put(&row, QUOTIENT, G.q_bytes, quotient);
    var coefficients: [B.MAX_COEFFICIENTS + 2]i64 = @splat(0);
    for (0..3) |pair| for (0..32) |i| for (0..32) |j| {
        coefficients[i + j] += @as(i64, row[OPERANDS + pair * 64 + i]) * row[OPERANDS + pair * 64 + 32 + j];
    };
    for (0..32) |i| {
        const add: i64 = row[OPERANDS + 6 * 32 + i];
        const result_byte: i64 = row[RESULT + i];
        coefficients[i] += if (instruction.addend_negative) -add else add;
        coefficients[i] += if (instruction.output_negative) -result_byte else result_byte;
    }
    for (0..G.coefficients) |n| coefficients[n] += B.limbOf(G.kp, n);
    for (0..G.q_bytes) |i| for (0..32) |j| {
        coefficients[i + j] -= @as(i64, row[QUOTIENT + i]) * B.limbOf(B.BN254_P, j);
    };
    var carry: i64 = 0;
    const radix: i64 = @as(i64, 1) << @intCast(8 * G.group);
    for (0..G.groups) |group| {
        var sum = carry;
        for (0..G.group) |offset| sum += coefficients[group * G.group + offset] << @intCast(8 * offset);
        std.debug.assert(@mod(sum, radix) == 0);
        carry = @divExact(sum, radix);
        if (group == G.carries) {
            std.debug.assert(carry == 0);
            break;
        }
        const encoded: i64 = carry + @as(i64, @intCast(G.carry_offset));
        std.debug.assert(encoded >= 0 and encoded < (@as(i64, 1) << @intCast(G.carry_bits)));
        row[CARRY + group] = @intCast(encoded);
    }
    finishCanonical(&row, output);
    return row;
}
fn finishCanonical(row: *Row, output: u256) void {
    put(row, DISTANCE, 32, B.BN254_P - 1 - output);
    var borrow: u32 = 0;
    for (0..15) |i| {
        const total = row[RESULT + 2 * i] + 256 * row[RESULT + 2 * i + 1] + row[DISTANCE + 2 * i] + 256 * row[DISTANCE + 2 * i + 1] + borrow + @intFromBool(i == 0);
        const modulus: u32 = @intCast((B.BN254_P >> @intCast(16 * i)) & 0xffff);
        std.debug.assert(total == modulus or total == modulus + 65536);
        borrow = @intFromBool(total != modulus);
        row[BORROW + i] = borrow;
    }
}
inline fn k(comptime F: type, value: u32) F {
    return E.qFor(F, value);
}
fn chunk(comptime F: type, v: anytype, start: usize, i: usize) F {
    return v.main(start + 2 * i).add(v.main(start + 2 * i + 1).mul(k(F, 256)));
}
fn carryValue(comptime F: type, v: anytype, i: usize) F {
    if (i >= G.carries) return F.zero();
    return v.main(CARRY + i).sub(v.main(ACTIVE).mul(k(F, @intCast(G.carry_offset))));
}
fn coefficient(comptime F: type, v: anytype, n: usize) F {
    var value = F.zero();
    if (n < 63) {
        const first = if (n >= 32) n - 31 else 0;
        for (0..3) |pair| for (first..@min(n + 1, 32)) |i| {
            value = value.add(v.main(OPERANDS + pair * 64 + i).mul(v.main(OPERANDS + pair * 64 + 32 + n - i)));
        };
    }
    if (n < 32) {
        const addend = v.main(OPERANDS + 6 * 32 + n);
        const output = v.main(RESULT + n);
        value = value.add(addend.mul(F.one().sub(v.fixed(@intFromEnum(Fixed.addend_negative)).mul(k(F, 2)))));
        value = value.add(output.mul(F.one().sub(v.fixed(@intFromEnum(Fixed.output_negative)).mul(k(F, 2)))));
    }
    value = value.add(v.main(ACTIVE).mul(k(F, B.limbOf(G.kp, n))));
    const first = if (n >= 32) n - 31 else 0;
    var i = first;
    while (i < G.q_bytes and i <= n) : (i += 1) value = value.sub(v.main(QUOTIENT + i).mul(k(F, B.limbOf(B.BN254_P, n - i))));
    return value;
}
/// Caller additionally supplies exact activity/call span and closes all range,
/// local SSA and global Wire35 relations. Maximum algebraic degree is three
/// including periodic fixed selectors; range lookups remain separate authority.
pub fn emitMain(comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    emitSelected(F, v, F.one(), sink);
}
pub fn emitSelected(comptime F: type, v: anytype, arithmetic: F, sink: *E.SinkFor(F)) void {
    const active = v.main(ACTIVE);
    E.booleanFor(F, sink, active);
    for (0..7) |slot| for (0..32) |byte| {
        const literal = v.fixed(@intFromEnum(Fixed.literal0) + slot);
        const expected = if (byte == 0) v.fixed(@intFromEnum(Fixed.nine0) + slot).mul(k(F, 9)).mul(active) else F.zero();
        sink.emit(literal.mul(v.main(OPERANDS + 32 * slot + byte)).sub(expected));
    };
    for (0..G.groups) |group| {
        var sum = F.zero();
        for (0..G.group) |offset| {
            const n = G.group * group + offset;
            if (n < G.coefficients) sum = sum.add(coefficient(F, v, n).mul(k(F, @as(u32, 1) << @intCast(8 * offset))));
        }
        if (group > 0) sum = sum.add(carryValue(F, v, group - 1));
        sink.emit(arithmetic.mul(sum.sub(carryValue(F, v, group).mul(k(F, @as(u32, 1) << @intCast(8 * G.group))))));
    }
    for (0..15) |i| E.booleanFor(F, sink, v.main(BORROW + i));
    for (0..16) |i| {
        var residual = chunk(F, v, RESULT, i).add(chunk(F, v, DISTANCE, i)).sub(active.mul(k(F, @intCast((B.BN254_P >> @intCast(16 * i)) & 0xffff))));
        if (i == 0) residual = residual.add(active);
        if (i > 0) residual = residual.add(v.main(BORROW + i - 1));
        if (i < 15) residual = residual.sub(v.main(BORROW + i).mul(k(F, 65536)));
        sink.emit(arithmetic.mul(residual));
    }
}
/// Durable relation advice retained after owned MAIN commitment. Each row's
/// expensive products/division/carry witness is constructed once, then encoded
/// into the trace and this narrow record. Replay does no field multiplication,
/// modular division or DAG evaluation.
pub const Advice = struct {
    values: [D.VALUES]u256,
    quotients: [D.STEPS][G.q_bytes]u8,
    carries: [D.STEPS][G.carries]u16,
    pub fn record(self: *@This(), step: usize, row: *const Row) void {
        for (&self.quotients[step], 0..) |*value, i| value.* = @intCast(row[QUOTIENT + i]);
        for (&self.carries[step], 0..) |*value, i| value.* = @intCast(row[CARRY + i]);
    }
    pub fn replay(self: *const @This(), step: usize) Row {
        var row: Row = @splat(0);
        row[ACTIVE] = 1;
        for (D.PROGRAM[step].operands(), 0..) |id, slot| put(&row, OPERANDS + 32 * slot, 32, D.read(&self.values, id));
        const output = self.values[D.PROGRAM[step].output];
        put(&row, RESULT, 32, output);
        for (self.quotients[step], 0..) |value, i| row[QUOTIENT + i] = value;
        for (self.carries[step], 0..) |value, i| row[CARRY + i] = value;
        finishCanonical(&row, output);
        return row;
    }
};

/// Only writes need byte authority: authenticated frontier bytes and every
/// canonical result make operand ranges follow by the acyclic exact-fanout SSA
/// relation. Quotients/carries/distance remain explicit local range queries.
pub const BYTE_QUERIES = 32 + G.q_bytes + 32;
pub const CARRY_QUERIES = G.carries;
pub const RANGE_QUERIES = BYTE_QUERIES + CARRY_QUERIES;
pub fn rangeQueryLimit(index: usize) u32 {
    std.debug.assert(index < RANGE_QUERIES);
    return if (index < BYTE_QUERIES) 256 else CARRY_LIMIT;
}
pub fn rangeQuery(row: *const Row, index: usize) u32 {
    std.debug.assert(index < RANGE_QUERIES);
    if (index < 32) return row[RESULT + index];
    const q = index - 32;
    if (q < G.q_bytes) return row[QUOTIENT + q];
    const distance = q - G.q_bytes;
    if (distance < 32) return row[DISTANCE + distance];
    return row[CARRY + distance - 32];
}
pub fn validateMass(calls: u64) error{TowerMassBound}!void {
    const max_calls = (B.M31 - 1) / @max(@as(u64, D.READS), @as(u64, D.STEPS * RANGE_QUERIES));
    if (calls == 0 or calls > max_calls) return error.TowerMassBound;
}
