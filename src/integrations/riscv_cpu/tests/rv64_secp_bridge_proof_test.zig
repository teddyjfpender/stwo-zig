const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = rv.crypto.secp256k1;
const P = S.program;
const Bridge = S.bridge;
const L = Bridge.layout;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const physical = rv.witness.physical;
const F = @import("../delegations/secp256k1/fixture.zig");
const fixture = @import("../delegations/secp256k1/bridge_fixture.zig");
const makeCalls = fixture.makeCalls;
fn challenges() Bridge.equations.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x53425254, 37 });
    const ch = S.equations.Challenges.draw(&channel);
    return .{ .wire = ch.wire, .bytes = ch.bytes, .call = Bridge.equations.CallChallenges.draw(&channel), .ram = rv.relations.Challenges.draw(&channel) };
}
fn secure(data: []const M, n: usize, row: usize, column: usize) Q {
    return Q.fromM31(data[column * n + row], data[(column + 1) * n + row], data[(column + 2) * n + row], data[(column + 3) * n + row]);
}
fn allRows(trace: *const Bridge.trace.Trace, ch: Bridge.equations.Challenges, claim: Q) !void {
    const n = trace.size();
    for (0..n) |logical| {
        const row = physical(logical, trace.log_size);
        const prev = physical((logical + n - 1) % n, trace.log_size);
        var fixed: [L.FIXED]Q = undefined;
        var main: [L.MAIN]Q = undefined;
        var previous: [L.PREVIOUS_MAIN]Q = undefined;
        var header: [2]Q = undefined;
        var interaction: [L.BATCHES]Q = undefined;
        for (&fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + row]);
        for (&main, 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + row]);
        for (&previous, 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + prev]);
        for (&header, 0..) |*v, c| v.* = Q.fromBase(trace.main[(L.ACTIVE + c) * n + prev]);
        for (&interaction, 0..) |*v, b| v.* = secure(trace.interaction, n, row, 4 * b);
        var residuals: [L.CONSTRAINTS]Q = undefined;
        var sink = rv.evaluation.Sink{ .values = &residuals };
        Bridge.equations.emit(trace.program, .{ .packet_format = trace.packet_format, .fixed = &fixed, .main = &main, .previous_main = &previous, .previous_header = &header }, &interaction, secure(trace.interaction, n, prev, L.INTERACTION - 4), claim, ch, .{ .calls = trace.calls, .first_id = trace.first_id }, &sink);
        try std.testing.expectEqual(residuals.len, sink.count);
        for (residuals, 0..) |v, i| if (!v.isZero()) {
            std.debug.print("secp bridge residual row{} term{}={any}\n", .{ logical, i, v });
            return error.NonzeroBridgeResidual;
        };
    }
}
test "projective32B bridge preserves BE wire order readonly RHS and strict RAM clocks" {
    const a = std.testing.allocator;
    for ([_]*const P.Program{ &P.add, &P.double }) |program| {
        const calls = try makeCalls(a, program, 3);
        defer a.free(calls);
        var trace = try Bridge.trace.Trace.init(a, program, calls, 1);
        defer trace.deinit();
        const ch = challenges();
        const claim = try trace.generateInteraction(ch);
        try allRows(&trace, ch, claim);
        try std.testing.expectEqual(@as(usize, 207), L.FIXED + L.MAIN + L.INTERACTION);
    }
}
test "projective bridge keys are count independent and rejects truncation and bad permissions" {
    const a = std.testing.allocator;
    const calls = try makeCalls(a, &P.add, 3);
    defer a.free(calls);
    var x = try Bridge.trace.Trace.initWithLog(a, &P.add, &.{}, 31, 5);
    defer x.deinit();
    var y = try Bridge.trace.Trace.initWithLog(a, &P.add, calls, 1, 5);
    defer y.deinit();
    try std.testing.expectEqualSlices(M, x.fixed, y.fixed);
    calls[0].clock = 1 << 22;
    try std.testing.expectError(error.InvalidSecpBridgeCall, Bridge.trace.Trace.init(a, &P.add, calls, 1));
    calls[0].clock = 3;
    calls[0].previous_clocks[0] = 12;
    try std.testing.expectError(error.InvalidSecpBridgeClock, Bridge.trace.Trace.init(a, &P.add, calls, 1));
    calls[0].previous_clocks[0] = 0;
    calls[0].writable[0] = false;
    try std.testing.expectError(error.InvalidSecpBridgePermission, Bridge.trace.Trace.init(a, &P.add, calls, 1));
    calls[0].writable[0] = true;
    calls[0].after[12] +%= 1;
    try std.testing.expectError(error.InvalidSecpBridgeRhsMutation, Bridge.trace.Trace.init(a, &P.add, calls, 1));
    try std.testing.expectError(error.InvalidSecpCallSpan, Bridge.trace.Trace.initWithLog(std.testing.failing_allocator, &P.add, calls, core.fields.m31.Modulus - 2, 5));
}
test "projective coordinate bridge closes modular wire RAM and call claims in one fresh proof" {
    try fixture.run(std.testing.allocator, .add, 3, false);
    try fixture.run(std.testing.allocator, .double, 3, false);
}
test "projective coordinate bridge rejects final predecessor sampled value mutation" {
    try fixture.run(std.testing.allocator, .add, 1, true);
}
test "projective coordinate bridge empty complete provider roster proves" {
    try fixture.run(std.testing.allocator, .add, 0, false);
}
test "projective word-packet v2 bridge proves with the same arithmetic and explicit byte mapping" {
    try fixture.runWords(std.testing.allocator, .add, 3, false);
    try fixture.runWords(std.testing.allocator, .double, 3, false);
}
fn dense(i: usize) Q {
    return Q.fromU32Unchecked(@intCast(17 * i + 3), @intCast(19 * i + 5), @intCast(23 * i + 7), @intCast(29 * i + 11));
}
test "projective coordinate bridge arbitrary QM31 residuals have degree at most four in both formats" {
    const ch = challenges();
    for ([_]Bridge.equations.PacketFormat{ .big_endian_bytes_v1, .little_endian_words_v2 }) |format| {
        var differences: [6][L.CONSTRAINTS]Q = undefined;
        for (0..6) |sample| {
            const x = Q.fromBase(M.fromCanonical(@intCast(sample)));
            var fixed: [L.FIXED]Q = undefined;
            var main: [L.MAIN]Q = undefined;
            var previous: [L.PREVIOUS_MAIN]Q = undefined;
            var header: [2]Q = undefined;
            var current: [L.BATCHES]Q = undefined;
            for (&fixed, 0..) |*v, i| v.* = dense(i + 1).add(x.mul(dense(i + 501)));
            for (&main, 0..) |*v, i| v.* = dense(i + 1001).add(x.mul(dense(i + 2003)));
            for (&previous, 0..) |*v, i| v.* = dense(i + 4001).add(x.mul(dense(i + 5003)));
            for (&header, 0..) |*v, i| v.* = dense(i + 6001).add(x.mul(dense(i + 7001)));
            for (&current, 0..) |*v, i| v.* = dense(i + 8001).add(x.mul(dense(i + 9001)));
            var sink = rv.evaluation.Sink{ .values = &differences[sample] };
            Bridge.equations.emit(&P.add, .{ .packet_format = format, .fixed = &fixed, .main = &main, .previous_main = &previous, .previous_header = &header }, &current, dense(10001).add(x.mul(dense(11003))), dense(12001), ch, .{ .calls = 3, .first_id = 7 }, &sink);
            try std.testing.expectEqual(differences[sample].len, sink.count);
        }
        for (0..5) |order| for (0..5 - order) |sample| for (0..L.CONSTRAINTS) |i| {
            differences[sample][i] = differences[sample + 1][i].sub(differences[sample][i]);
        };
        for (differences[0]) |v| try std.testing.expect(v.isZero());
    }
}
test "projective coordinate and modular quotients join existing pool with256KiB worker stacks" {
    const engine = @import("stwo_prover_engine");
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try fixture.runWords(std.testing.allocator, .add, 22, false);
}
