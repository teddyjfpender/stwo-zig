const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const Mul = rv.arithmetic.multiplication;
const L = Mul.layout;
const P = Mul.provider;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = rv.evaluation;
const a = std.testing.allocator;
pub fn reference(op: E.O, lhs: u64, rhs: u64) u64 {
    return switch (op) {
        .MUL => lhs *% rhs,
        .MULHU => @truncate((@as(u128, lhs) * rhs) >> 64),
        .MULH => @bitCast(@as(i64, @truncate((@as(i128, @as(i64, @bitCast(lhs))) * @as(i64, @bitCast(rhs))) >> 64))),
        .MULHSU => @bitCast(@as(i64, @truncate((@as(i128, @as(i64, @bitCast(lhs))) * @as(i128, rhs)) >> 64))),
        .MULW => blk: {
            const low: u32 = @as(u32, @truncate(lhs)) *% @as(u32, @truncate(rhs));
            break :blk @bitCast(@as(i64, @as(i32, @bitCast(low))));
        },
        else => unreachable,
    };
}
pub fn requests() [80]Mul.trace.Request {
    const corners = [_]u64{ 0, 1, 0xffffffffffffffff, 0x8000000000000000, 0x7fffffffffffffff, 0xdeadbeef80000001, 0xfedcba9876543210, 0x00000000ffffffff };
    var out: [80]Mul.trace.Request = undefined;
    for (L.OPCODES, 0..) |op, j| for (0..16) |i| {
        const lhs = corners[i % corners.len];
        const rhs = if (i == 2) std.math.maxInt(u64) else corners[(3 * i + i / 8 + 1) % corners.len];
        out[j * 16 + i] = .{ .opcode = op, .a = lhs, .b = rhs, .result = reference(op, lhs, rhs) };
    };
    return out;
}
fn challenges() P.Challenges {
    var result: P.Challenges = .{ .offset = Q.fromU32Unchecked(71, 9, 12, 3), .coefficients = undefined };
    for (&result.coefficients, 0..) |*c, i| c.* = Q.fromU32Unchecked(@intCast(3 * i + 5), @intCast(i + 1), 11, 17);
    return result;
}
fn check(trace: *const Mul.trace.Trace, ch: P.Challenges, alpha: Q, claim: Q, expect_valid: bool) !void {
    var residuals: [L.CONSTRAINTS]Q = undefined;
    const n = trace.domainSize();
    var any_failure = false;
    for (0..n) |i| {
        const r = rv.witness.physical(i, trace.log_size);
        const before = rv.witness.physical((i + n - 1) % n, trace.log_size);
        var fixed: [3]Q = undefined;
        var main: P.Values = undefined;
        var current: P.Interaction = undefined;
        var previous: P.Interaction = @splat(Q.zero());
        for (&fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
        for (&main, 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + r]);
        for (&current, 0..) |*v, c| {
            v.* = Q.fromBase(trace.interaction[c * n + r]);
            if (c >= L.INTERACTION - 4) previous[c] = Q.fromBase(trace.interaction[c * n + before]);
        }
        const previous_count = Q.fromBase(trace.main[L.COUNT * n + before]);
        var sink = E.Sink{ .values = &residuals };
        const prepared = rv.range.cpu.PreparedAlpha.init(alpha);
        P.evaluate(fixed, &main, &current, &previous, previous_count, trace.count, ch, &prepared, claim, &sink);
        try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), sink.count);
        for (residuals, 0..) |residual, c| if (!residual.isZero()) {
            if (expect_valid) std.debug.print("MUL row{d} constraint{d}\n", .{ i, c });
            any_failure = true;
        };
    }
    try std.testing.expectEqual(!expect_valid, any_failure);
}
test "MUL byte schoolbook all5 signed high W full64 and padding bind one mixed claim" {
    const input = requests();
    var trace = try Mul.trace.Trace.init(a, &input);
    defer trace.deinit();
    const ch = challenges();
    const alpha = Q.fromU32Unchecked(19, 23, 5, 7);
    const claim = try trace.generateInteraction(ch, alpha);
    try check(&trace, ch, alpha, claim, true);
    var expected = Q.zero();
    for (input) |request| expected = expected.sub(try ch.denominator(&try Mul.trace.requestTuple(request)).inv());
    for (trace.byte_counts, 0..) |count, byte| expected = expected.add((try alpha.sub(E.q(@intCast(byte))).inv()).mul(E.q(@intCast(count))));
    try std.testing.expect(expected.eql(claim));
    const row = rv.witness.physical(0, trace.log_size);
    trace.main[L.CARRY_HIGH * trace.domainSize() + row] = M.fromCanonical(8);
    try check(&trace, ch, alpha, claim, false);
}
test "MUL source key ignores count and constructors release every allocation failure" {
    const input = requests();
    try std.testing.checkAllAllocationFailures(a, initRelease, .{input[0..3]});
    var empty = try Mul.trace.Trace.initWithLog(a, &.{}, 7);
    defer empty.deinit();
    var full = try Mul.trace.Trace.initWithLog(a, &input, 7);
    defer full.deinit();
    try std.testing.expectEqualSlices(M, empty.fixed, full.fixed);
}
fn initRelease(allocator: std.mem.Allocator, input: []const Mul.trace.Request) !void {
    var trace = try Mul.trace.Trace.init(allocator, input);
    defer trace.deinit();
}

test "MUL dense extension polynomial fifth differences vanish through degree4" {
    var base: [3 + L.MAIN + 2 * L.INTERACTION + 1]Q = undefined;
    var direction: @TypeOf(base) = undefined;
    for (&base, &direction, 0..) |*b, *d, i| {
        b.* = Q.fromU32Unchecked(@intCast(3 * i + 2), 7, @intCast(i + 1), 11);
        d.* = Q.fromU32Unchecked(5, @intCast(2 * i + 1), 13, @intCast(i + 3));
    }
    var difference: [L.CONSTRAINTS]Q = @splat(Q.zero());
    const coefficients = [_]i32{ 1, -5, 10, -10, 5, -1 };
    const alpha = rv.range.cpu.PreparedAlpha.init(Q.fromU32Unchecked(17, 31, 2, 9));
    for (coefficients, 0..) |coefficient, t| {
        var point: @TypeOf(base) = undefined;
        for (&point, base, direction) |*v, b, d| v.* = b.add(d.mul(E.q(@intCast(t))));
        var residuals: [L.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        P.evaluate(point[0..3].*, point[3..][0..L.MAIN], point[3 + L.MAIN ..][0..L.INTERACTION], point[3 + L.MAIN + L.INTERACTION ..][0..L.INTERACTION], point[point.len - 1], 7, challenges(), &alpha, Q.fromU32Unchecked(13, 2, 9, 1), &sink);
        for (&difference, residuals) |*sum, value| sum.* = if (coefficient > 0) sum.add(value.mul(E.q(@intCast(coefficient)))) else sum.sub(value.mul(E.q(@intCast(-coefficient))));
    }
    for (difference) |value| try std.testing.expect(value.isZero());
}
