const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64_air;
const D = rv.arithmetic.division;
const E = rv.evaluation;
const a = std.testing.allocator;
pub fn expected(op: E.O, left: u64, right: u64) u64 {
    const word = rv.operations.word(op);
    const signed = rv.operations.signedDiv(op);
    const remainder = rv.operations.remainder(op);
    const mask: u64 = if (word) 0xffffffff else std.math.maxInt(u64);
    var value: u64 = undefined;
    if (signed) {
        const lhs: i128 = if (word) @as(i32, @bitCast(@as(u32, @truncate(left)))) else @as(i64, @bitCast(left));
        const rhs: i128 = if (word) @as(i32, @bitCast(@as(u32, @truncate(right)))) else @as(i64, @bitCast(right));
        const result = if (rhs == 0) (if (remainder) lhs else @as(i128, -1)) else if (remainder) @rem(lhs, rhs) else @divTrunc(lhs, rhs);
        value = @truncate(@as(u128, @bitCast(result)));
    } else value = if (right & mask == 0) (if (remainder) left & mask else mask) else if (remainder) (left & mask) % (right & mask) else (left & mask) / (right & mask);
    return if (word) @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(value)))))) else value;
}
pub fn fixtures() [64]D.trace.Request {
    var requests: [64]D.trace.Request = undefined;
    const pairs = [_][2]u64{ .{ 0, 0 }, .{ 0xffffffffffffffff, 0 }, .{ 0x8000000000000000, 0xffffffffffffffff }, .{ 0xffffffff80000000, 0xffffffffffffffff }, .{ 0xfffffffffffffff9, 3 }, .{ 7, 0xfffffffffffffffd }, .{ 0xf123456789abcdef, 0x123456789 }, .{ 0xabcdef0180000001, 0x1234567800000002 } };
    var i: usize = 0;
    for (D.layout.OPCODES) |op| for (pairs) |pair| {
        requests[i] = .{ .opcode = op, .a = pair[0], .b = pair[1], .result = expected(op, pair[0], pair[1]) };
        i += 1;
    };
    return requests;
}
fn checkRows(trace: *const D.trace.Trace, challenges: D.provider.Challenges, claim: E.Q) !void {
    const n = trace.domainSize();
    for (0..n) |i| {
        const row = rv.program.provider.physical(i, trace.log_size);
        const prior = rv.program.provider.physical((i + n - 1) % n, trace.log_size);
        var geometry: [D.layout.FIXED]E.Q = undefined;
        var physical: D.layout.Physical = undefined;
        var current: [D.layout.INTERACTION]E.Q = undefined;
        var previous: [D.layout.INTERACTION]E.Q = undefined;
        for (&geometry, 0..) |*value, c| value.* = E.Q.fromBase(trace.fixed[c * n + row]);
        for (&physical, 0..) |*value, c| value.* = E.Q.fromBase(trace.main[c * n + row]);
        for (&current, &previous, 0..) |*now, *before, c| {
            now.* = E.Q.fromBase(trace.interaction[c * n + row]);
            before.* = E.Q.fromBase(trace.interaction[c * n + prior]);
        }
        var residuals: [D.layout.CONSTRAINTS]E.Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        D.provider.evaluate(geometry, &physical, &current, &previous, E.Q.fromBase(trace.main[D.layout.COUNT * n + prior]), trace.count, challenges, claim, &sink);
        try std.testing.expectEqual(D.layout.CONSTRAINTS, sink.count);
        for (residuals, 0..) |value, constraint| if (!value.isZero()) {
            std.debug.print("division row{d} constraint{d}\n", .{ i, constraint });
            return error.InvalidDivisionResidual;
        };
    }
}
test "division provider all signed unsigned W corners and exact typed tuple close" {
    const requests = fixtures();
    var trace = try D.trace.Trace.init(a, &requests);
    defer trace.deinit();
    var channel = rv.protocol.Channel{};
    const challenges = D.provider.Challenges.draw(&channel);
    const claim = try trace.generateInteraction(challenges);
    var expected_claim = E.Q.zero();
    for (requests) |request| {
        const tuple = try D.trace.requestTuple(request);
        expected_claim = expected_claim.sub(try challenges.denominator(&tuple).inv());
    }
    try std.testing.expect(claim.eql(expected_claim));
    try checkRows(&trace, challenges, claim);
    const row = rv.program.provider.physical(0, trace.log_size);
    trace.main[D.layout.WORD_START * trace.domainSize() + row] = @import("stwo_core").fields.m31.M31.fromCanonical(2);
    try std.testing.expectError(error.InvalidDivisionResidual, checkRows(&trace, challenges, claim));
}
fn allocateRelease(allocator: std.mem.Allocator) !void {
    const requests = fixtures();
    var trace = try D.trace.Trace.init(allocator, requests[0..1]);
    defer trace.deinit();
    var channel = rv.protocol.Channel{};
    _ = try trace.generateInteraction(D.provider.Challenges.draw(&channel));
}
test "division provider allocation failure and interaction lifecycle close" {
    try std.testing.checkAllAllocationFailures(a, allocateRelease, .{});
    const requests = fixtures();
    var trace = try D.trace.Trace.init(a, requests[0..3]);
    defer trace.deinit();
    try std.testing.expectError(error.DivisionByZero, trace.generateInteraction(.{ .offset = E.Q.zero(), .coefficients = @splat(E.Q.zero()) }));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    var channel = rv.protocol.Channel{};
    const challenge = D.provider.Challenges.draw(&channel);
    const claim = try trace.generateInteraction(challenge);
    try checkRows(&trace, challenge, claim);
    try std.testing.expectError(error.InvalidRv64DivisionPhase, trace.generateInteraction(challenge));
    var stale = try D.trace.Trace.init(a, requests[0..1]);
    defer stale.deinit();
    stale.request_metadata[0].a ^= 0x8000000000000000;
    const stale_claim = try stale.generateInteraction(challenge);
    try std.testing.expectError(error.InvalidDivisionResidual, checkRows(&stale, challenge, stale_claim));
}
test "division service opcode admission and exact padded source cost" {
    try std.testing.expectEqual(@as(usize, 1135), D.layout.MAIN);
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(D.trace.Request));
    try std.testing.expectEqual(@as(usize, 37191680), D.layout.MAIN * 8192 * 4);
    try std.testing.expectError(error.InvalidRv64DivisionOpcode, D.trace.Trace.init(a, &.{.{ .opcode = .MUL, .a = 1, .b = 2, .result = 2 }}));
}

test "division fixed geometry excludes request count and committed count cannot drift" {
    const first = try D.trace.fixedColumns(a, 1, 5);
    defer a.free(first);
    const other = try D.trace.fixedColumns(a, 17, 5);
    defer a.free(other);
    try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, first, other);
    const requests = fixtures();
    var trace = try D.trace.Trace.init(a, requests[0..3]);
    defer trace.deinit();
    var channel = rv.protocol.Channel{};
    const challenges = D.provider.Challenges.draw(&channel);
    const claim = try trace.generateInteraction(challenges);
    try checkRows(&trace, challenges, claim);
    trace.count = 4;
    try std.testing.expectError(error.InvalidDivisionResidual, checkRows(&trace, challenges, claim));
}
