//! Numeric reference for the NEW MAC12 row. Input canonicality is conditional
//! source-SSA authority, never a producer validity bit.
const std = @import("std");
const S = @import("source.zig");
const Canon = @import("canonical_word16.zig");
const P = S.B.P;
pub const Inputs = [25]u256;
pub const Coefficients = [12]i32;
pub fn expression(input: *const Inputs, coefficients: Coefficients) i1024 {
    var out: i1024 = input[24];
    for (coefficients, 0..) |c, i| out += @as(i1024, c) * @as(i1024, input[2 * i]) * @as(i1024, input[2 * i + 1]);
    return out;
}
fn put(row: *S.Row, start: usize, count: usize, value: anytype) void {
    for (0..count) |i| row[start + i] = @intCast((value >> @intCast(8 * i)) & 255);
}
pub fn read(row: *const S.Row, start: usize, count: usize) u272 {
    var v: u272 = 0;
    for (0..count) |i| v |= @as(u272, row[start + i]) << @intCast(8 * i);
    return v;
}
fn coefficientsValid(c: Coefficients) bool {
    for (c) |x| if (@abs(x) > 18) return false;
    return true;
}
pub fn fill(input: *const Inputs, c: Coefficients) !S.Row {
    for (input) |x| if (x >= P) return error.Mac12NoncanonicalInput;
    if (!coefficientsValid(c)) return error.Mac12CoefficientBound;
    const value: u256 = @intCast(@mod(expression(input, c), @as(i1024, P)));
    return fillOutput(input, c, value);
}
/// Adversarial physical probe only. Canonical input inheritance must reject
/// such a value; this exposes its otherwise valid integer arithmetic witness.
pub fn fillRawInputsForTesting(input: *const Inputs, c: Coefficients) !S.Row {
    if (!@import("builtin").is_test) @compileError("test-only raw MAC inputs");
    for (input) |x| if (x >= 2 * P) return error.Mac12RawInputBound;
    if (!coefficientsValid(c)) return error.Mac12CoefficientBound;
    const value: u256 = @intCast(@mod(expression(input, c), @as(i1024, P)));
    return fillOutput(input, c, value);
}
pub fn aliasForTesting(input: *const Inputs, c: Coefficients) !S.Row {
    if (!@import("builtin").is_test) @compileError("test-only output+p");
    const value: u256 = @intCast(@mod(expression(input, c), @as(i1024, P)));
    return fillOutput(input, c, value + P);
}
fn fillOutput(input: *const Inputs, c: Coefficients, value: u256) !S.Row {
    var row: S.Row = @splat(0);
    row[S.ACTIVE] = 1;
    for (input, 0..) |x, i| put(&row, S.INPUT + 32 * i, 32, x);
    Canon.fill(&row, S.canonical, value);
    const q = @divExact(expression(input, c) - @as(i1024, value), @as(i1024, P));
    row[S.SIGN] = @intFromBool(q < 0);
    const magnitude: u272 = @intCast(@abs(q));
    if (magnitude >> 264 != 0) return error.Mac12QuotientBound;
    put(&row, S.QUOTIENT, 33, magnitude);
    var previous: i64 = 0;
    for (0..65) |n| {
        const total = coefficient(&row, c, n) + previous;
        if (n == 64) {
            if (total != 0) return error.Mac12TerminalCarry;
            break;
        }
        if (@mod(total, 256) != 0) return error.Mac12CarriedEquation;
        previous = @divExact(total, 256);
        if (previous < -S.B.OFFSET or previous >= S.B.OFFSET) return error.Mac12CarryBound;
        put(&row, S.CARRY + 3 * n, 3, @as(u32, @intCast(previous + S.B.OFFSET)));
    }
    return row;
}
pub fn coefficient(row: *const S.Row, c: Coefficients, n: usize) i64 {
    var total: i64 = 0;
    if (n < 63) for (c, 0..) |weight, term| {
        const first = if (n >= 32) n - 31 else 0;
        for (first..@min(n + 1, 32)) |i| total += @as(i64, weight) * row[S.INPUT + 64 * term + i] * row[S.INPUT + 64 * term + 32 + n - i];
    };
    if (n < 32) total += @as(i64, row[S.INPUT + 32 * 24 + n]) - @as(i64, row[S.OUTPUT + n]);
    const first = if (n >= 32) n - 31 else 0;
    var i = first;
    while (i < 33 and i <= n) : (i += 1) total -= (if (row[S.SIGN] == 0) @as(i64, 1) else -1) * @as(i64, row[S.QUOTIENT + i]) * @as(i64, @intCast((P >> @intCast(8 * (n - i))) & 255));
    return total;
}
fn carry(row: *const S.Row, n: usize) i64 {
    return @as(i64, @intCast(read(row, S.CARRY + 3 * n, 3))) - @as(i64, row[S.ACTIVE]) * S.B.OFFSET;
}
pub fn arithmeticValid(row: *const S.Row, c: Coefficients) bool {
    if (!coefficientsValid(c) or row[S.ACTIVE] > 1 or row[S.SIGN] > row[S.ACTIVE]) return false;
    for (0..65) |n| {
        var total = coefficient(row, c, n);
        if (n > 0) total += carry(row, n - 1);
        if (n < 64) total -= 256 * carry(row, n);
        if (total != 0) return false;
    }
    return true;
}
pub fn valid(row: *const S.Row, c: Coefficients) bool {
    if (!arithmeticValid(row, c)) return false;
    if (row[S.ACTIVE] == 0) {
        for (row) |v| if (v != 0) return false;
        return true;
    }
    for (0..25) |i| {
        for (row[S.INPUT + 32 * i ..][0..32]) |v| if (v >= 256) return false;
        if (read(row, S.INPUT + 32 * i, 32) >= P) return false;
    }
    for (row[S.OUTPUT..S.CARRY]) |v| if (v >= 256) return false;
    for (0..64) |i| {
        for (row[S.CARRY + 3 * i ..][0..3]) |v| if (v >= 256) return false;
        if (row[S.CARRY + 3 * i + 2] >= 64) return false;
    }
    for (row[S.DISTANCE..S.BORROW]) |v| if (v >= 256) return false;
    return Canon.valid(row, S.canonical, 1);
}
