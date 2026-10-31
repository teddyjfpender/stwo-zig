const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = rv.crypto.secp256k1;
const C = S.cpu_bus;
const E = rv.evaluation;
const Q = E.Q;
const M = core.fields.m31.M31;
const profile = @import("stwo_riscv_frontend").rv64.execution_profile;
const physical = rv.witness.physical;
const calls = [_]C.Call{ .{ .kind = .add, .call_id = 37, .clock = 1, .pointer = 0x100001fe0 }, .{ .kind = .double, .call_id = 91, .clock = 3, .pointer = 0x100001fe0 }, .{ .kind = .add, .call_id = 38, .clock = 6, .pointer = 0x100001fe0 } };
fn challenges() S.bridge.equations.CallChallenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x53435055, 29 });
    return S.bridge.equations.CallChallenges.draw(&channel);
}
fn secure(data: []const M, row: usize) Q {
    return Q.fromM31(data[row], data[32 + row], data[64 + row], data[96 + row]);
}
fn native(execution: profile.Profile, mutate: bool) !void {
    const a = std.testing.allocator;
    const ch = challenges();
    var columns = try C.build(a, 6, 5, &calls, .{ 37, 91 }, execution, ch);
    defer columns.deinit();
    const bus = C.Bus{ .calls = .{ 2, 1 }, .first_ids = .{ 37, 91 }, .execution_profile = execution, .challenges = ch, .claim = columns.claim };
    try bus.validate(6);
    var f: E.Fixed = @splat(Q.zero());
    var m: E.Main = @splat(Q.zero());
    var counts: [2]u32 = @splat(0);
    var prior: [2]Q = .{ E.q(2), E.q(1) };
    for (0..32) |i| {
        var flags: [3]Q = @splat(Q.zero());
        var tag: u64 = 0;
        var pointer: u64 = 0;
        for (calls) |call| if (call.clock == i + 1) {
            const kind: usize = if (call.kind == .add) 0 else 1;
            counts[kind] += 1;
            flags[kind + 1] = Q.one();
            tag = if (execution == .ethereum_services_v1) (if (kind == 0) profile.SECP_ADD_TAG else profile.SECP_DOUBLE_TAG) else (if (kind == 0) profile.SECP_ADD_WORD_TAG else profile.SECP_DOUBLE_WORD_TAG);
            pointer = call.pointer;
        };
        if (i == 1) {
            flags[0] = Q.one();
            tag = profile.KECCAK_TAG;
        }
        f[E.L.fixed.opcode_start + @intFromEnum(E.O.ECALL)] = flags[0].add(flags[1]).add(flags[2]);
        for (0..8) |byte| {
            m[E.L.byte(.a, byte)] = E.q(@intCast((pointer >> @as(u6, @intCast(8 * byte))) & 255));
            m[E.L.byte(.b, byte)] = E.q(@intCast((tag >> @as(u6, @intCast(8 * byte))) & 255));
        }
        const row = physical(i, 5);
        const prev = physical((i + 31) % 32, 5);
        const view = E.View{ .f = &f, .m = &m };
        var residuals: [C.CONSTRAINTS + C.SELECTOR_CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        C.evaluateSelectors(view, flags, execution, &sink);
        C.evaluate(view, .{ E.q(@intCast(i)), E.q(@intFromBool(i == 0)), E.q(@intFromBool(i == 31)) }, .{ flags[1], flags[2] }, .{ E.q(counts[0]), E.q(counts[1]) }, prior, secure(columns.storage, row), secure(columns.storage, prev), bus, &sink);
        try std.testing.expectEqual(residuals.len, sink.count);
        for (residuals) |v| try std.testing.expect(v.isZero());
        if (mutate and i == 0) {
            var wrong = bus;
            wrong.claim = wrong.claim.add(Q.one());
            sink = .{ .values = &residuals };
            C.evaluate(view, .{ E.q(0), Q.one(), Q.zero() }, .{ flags[1], flags[2] }, .{ E.q(counts[0]), E.q(counts[1]) }, prior, secure(columns.storage, row), secure(columns.storage, prev), wrong, &sink);
            try std.testing.expect(!residuals[C.CONSTRAINTS - 1].isZero());
            if (execution == .ethereum_services_v2) {
                m[E.L.byte(.b, 0)] = E.q(1);
                sink = .{ .values = &residuals };
                C.evaluateSelectors(view, flags, execution, &sink);
                try std.testing.expect(!residuals[4].isZero());
            }
        }
        prior = .{ E.q(counts[0]), E.q(counts[1]) };
    }
}
test "projective CPU header uses affine per-kind counters and one circular prefix" {
    try native(.ethereum_services_v1, true);
    try native(.ethereum_services_v2, true);
}
test "projective CPU header admission rejects wrong profiles spans ordering and truncation" {
    const a = std.testing.failing_allocator;
    const ch = challenges();
    try std.testing.expectError(error.InvalidSecpCpuProfile, C.build(a, 6, 5, &calls, .{ 37, 91 }, .keccak_service_v1, ch));
    var wrong = calls;
    wrong[1].clock = 1;
    try std.testing.expectError(error.InvalidSecpCpuOrder, C.build(a, 6, 5, &wrong, .{ 37, 91 }, .ethereum_services_v2, ch));
    wrong = calls;
    wrong[0].call_id = 1 << 32;
    try std.testing.expectError(error.InvalidSecpCpuOrder, C.build(a, 6, 5, &wrong, .{ 37, 91 }, .ethereum_services_v2, ch));
    const bus = C.Bus{ .calls = .{ 2, 1 }, .first_ids = .{ core.fields.m31.Modulus - 1, 1 }, .execution_profile = .ethereum_services_v2, .challenges = ch, .claim = Q.zero() };
    try std.testing.expectError(error.InvalidSecpCallSpan, bus.validate(6));
}
fn allocationRun(a: std.mem.Allocator) !void {
    var columns = try C.build(a, 6, 5, &calls, .{ 37, 91 }, .ethereum_services_v2, challenges());
    defer columns.deinit();
}
test "projective CPU prefix construction releases every allocation and inverse failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRun, .{});
    var ch = challenges();
    ch.offset = Q.zero();
    ch.coefficients = @splat(Q.zero());
    try std.testing.expectError(error.DivisionByZero, C.build(std.testing.allocator, 6, 5, &calls, .{ 37, 91 }, .ethereum_services_v2, ch));
}
fn dense(i: usize) Q {
    return Q.fromU32Unchecked(@intCast(17 * i + 3), @intCast(19 * i + 5), @intCast(23 * i + 7), @intCast(29 * i + 11));
}
test "projective CPU selector and batched header equations have arbitrary QM31 degree at most three" {
    var residuals: [5][C.CONSTRAINTS + C.SELECTOR_CONSTRAINTS]Q = undefined;
    const bus = C.Bus{ .calls = .{ 2, 1 }, .first_ids = .{ 37, 91 }, .execution_profile = .ethereum_services_v2, .challenges = challenges(), .claim = dense(7) };
    for (0..5) |sample| {
        const x = E.q(@intCast(sample));
        var f: E.Fixed = @splat(Q.zero());
        var m: E.Main = @splat(Q.zero());
        f[E.L.fixed.opcode_start + @intFromEnum(E.O.ECALL)] = dense(11).add(x.mul(dense(13)));
        for (0..8) |i| {
            m[E.L.byte(.a, i)] = dense(i + 17).add(x.mul(dense(i + 31)));
            m[E.L.byte(.b, i)] = dense(i + 47).add(x.mul(dense(i + 61)));
        }
        var flags: [3]Q = undefined;
        var geometry: [3]Q = undefined;
        var counts: [2]Q = undefined;
        var previous: [2]Q = undefined;
        for (&flags, 0..) |*v, i| v.* = dense(i + 79).add(x.mul(dense(i + 97)));
        for (&geometry, 0..) |*v, i| v.* = dense(i + 103).add(x.mul(dense(i + 127)));
        for (&counts, 0..) |*v, i| v.* = dense(i + 151).add(x.mul(dense(i + 179)));
        for (&previous, 0..) |*v, i| v.* = dense(i + 191).add(x.mul(dense(i + 223)));
        var sink = E.Sink{ .values = &residuals[sample] };
        const view = E.View{ .f = &f, .m = &m };
        C.evaluateSelectors(view, flags, .ethereum_services_v2, &sink);
        C.evaluate(view, geometry, .{ flags[1], flags[2] }, counts, previous, dense(251).add(x.mul(dense(277))), dense(281).add(x.mul(dense(307))), bus, &sink);
        try std.testing.expectEqual(residuals[sample].len, sink.count);
    }
    for (0..4) |order| for (0..4 - order) |sample| for (0..residuals[0].len) |i| {
        residuals[sample][i] = residuals[sample + 1][i].sub(residuals[sample][i]);
    };
    for (residuals[0]) |v| try std.testing.expect(v.isZero());
}
