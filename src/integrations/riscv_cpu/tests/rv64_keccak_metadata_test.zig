const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const Sources = @import("../delegations/keccak/sources.zig");
const Fixture = @import("rv64_keccak_proof_test.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const physical = rv.witness.physical;
fn callsFixture() [3]K.bridge.trace.Call {
    var calls: [3]K.bridge.trace.Call = undefined;
    var before = Fixture.inputState(17);
    for (&calls, 0..) |*call, i| {
        const after = Fixture.reference(before);
        call.* = .{ .call_id = i + 1, .clock = 3 + 8 * i, .pointer = 0x1ff8, .before = before, .after = after, .previous_clocks = @splat(if (i == 0) 0 else @intCast(4 * (3 + 8 * (i - 1)))) };
        before = after;
    }
    return calls;
}
fn challenges() struct { k: K.equations.Challenges, b: K.bridge.equations.Challenges } {
    var channel = core.channel.blake2s.Blake2sChannel{};
    channel.mixU32s(&.{ 0x4b4d4554, 37 });
    const k = K.equations.Challenges.draw(&channel);
    return .{ .k = k, .b = .{ .io = k.io, .call = K.bridge.equations.CallChallenges.draw(&channel), .ram = rv.relations.Challenges.draw(&channel), .bytes = channel.drawSecureFelt() } };
}
test "Keccak packed metadata expands every original row exactly without permutation replay" {
    const a = std.testing.allocator;
    const inputs = [_]K.trace.State{ Fixture.inputState(0), Fixture.inputState(7), Fixture.inputState(19) };
    var trace = try K.trace.Trace.init(a, &inputs, core.fields.m31.Modulus - 3);
    defer trace.deinit();
    try std.testing.expectEqual(@as(usize, 488), @sizeOf(K.trace.PackedRow));
    for (0..trace.size()) |logical| {
        const original = trace.mainRow(logical);
        const expanded = try trace.metadataRow(logical);
        try std.testing.expectEqualSlices(M, &original, &expanded);
    }
}
test "Keccak lookup claims and interaction bytes survive immediate main release" {
    const a = std.testing.allocator;
    const calls = callsFixture();
    var original = try Sources.Trace.init(a, &calls, 1, 6, 7);
    defer original.deinit();
    var released = try Sources.Trace.init(a, &calls, 1, 6, 7);
    defer released.deinit();
    const counts = try K.interaction.Counts.fromTrace(&original.permutation);
    try released.releaseMain();
    const after = try K.interaction.Counts.fromTrace(&released.permutation);
    try std.testing.expectEqualSlices(u64, &counts.chi, &after.chi);
    try std.testing.expectEqualSlices(u64, &counts.xor5, &after.xor5);
    const ch = challenges();
    const left = try original.generate(ch.k, ch.b);
    const right = try released.generate(ch.k, ch.b);
    inline for (.{ "permutation", "chi", "xor5", "bridge" }) |name| try std.testing.expect(@field(left, name).eql(@field(right, name)));
    try std.testing.expectEqualSlices(M, original.permutation.interaction, released.permutation.interaction);
    try std.testing.expectEqualSlices(M, original.chi.interaction, released.chi.interaction);
    try std.testing.expectEqualSlices(M, original.xor5.interaction, released.xor5.interaction);
    try std.testing.expectEqualSlices(M, original.bridge.interaction, released.bridge.interaction);
}
fn arenaRun(a: std.mem.Allocator) !void {
    const calls = callsFixture();
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var trace = try Sources.Trace.initWithMainAllocator(a, arena.allocator(), &calls, 1, 6, 7);
    defer trace.deinit();
    _ = try trace.takeMain();
    arena.deinit();
    owns_arena = false;
    const ch = challenges();
    _ = try trace.generate(ch.k, ch.b);
}
test "Keccak adopted main arena may die before challenge and all allocation failures clean up" {
    try arenaRun(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, arenaRun, .{});
}
test "Keccak bridge narrow call metadata reproduces every original column and padding count" {
    const a = std.testing.allocator;
    const calls = callsFixture();
    var trace = try K.bridge.trace.Trace.init(a, &calls, 1);
    defer trace.deinit();
    const n = trace.size();
    var counts: [256]u64 = @splat(0);
    for (0..n) |logical| {
        const row = try trace.metadataRow(logical);
        const r = physical(logical, trace.log_size);
        for (row, 0..) |v, c| try std.testing.expect(v.eql(trace.main[c * n + r]));
        for (K.bridge.layout.RANGE_COLUMNS) |c| counts[row[c].v] += 1;
    }
    try std.testing.expectEqualSlices(u64, &counts, &trace.byte_counts);
}
test "Keccak metadata changes remain untrusted by committed AIR lookup authority" {
    const a = std.testing.allocator;
    const input = [_]K.trace.State{Fixture.inputState(0)};
    var trace = try K.trace.Trace.init(a, &input, 1);
    defer trace.deinit();
    const ch = challenges();
    trace.metadata[2].state_a[0] ^= 1;
    // Bypass native tuple preflight with the retained malicious recipe: the
    // unchanged AIR must still reject a committed metadata substitution.
    const claim = try @import("rv64_keccak_interaction_oracle.zig").generate(&trace, ch.k);
    const logical: usize = 2;
    const row = physical(logical, trace.log_size);
    const prior = physical(1, trace.log_size);
    const n = trace.size();
    var f: [K.layout.FIXED]Q = undefined;
    var main: [K.layout.MAIN]Q = undefined;
    var shifted: [4][K.layout.STATE]Q = undefined;
    var previous_header: [3]Q = undefined;
    for (&f, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + row]);
    const base = trace.mainRow(logical);
    for (&main, base) |*v, b| v.* = Q.fromBase(b);
    for (K.layout.MASK_OFFSETS[1..], 0..) |offset, j| {
        const other: usize = @intCast(@mod(@as(isize, @intCast(logical)) + offset, @as(isize, @intCast(n))));
        const b = trace.mainRow(other);
        for (&shifted[j], b[0..K.layout.STATE]) |*v, value| v.* = Q.fromBase(value);
    }
    for (&previous_header, 0..) |*v, i| v.* = Q.fromBase(trace.main[(K.layout.ACTIVE_A + i) * n + prior]);
    var current: [K.layout.BATCHES]Q = undefined;
    for (&current, 0..) |*v, b| v.* = secure(trace.interaction, n, row, 4 * b);
    var residuals: [K.layout.CONSTRAINTS]Q = undefined;
    var sink = rv.evaluation.Sink{ .values = &residuals };
    K.equations.emit(.{ .fixed = &f, .main = &main, .state_minus_two = &shifted[0], .state_minus_one = &shifted[1], .state_plus_one = &shifted[2], .state_plus_two = &shifted[3], .previous_header = &previous_header }, &current, secure(trace.interaction, n, prior, K.layout.INTERACTION - 4), claim, ch.k, .{ .calls = 1, .first_id = 1 }, &sink);
    var nonzero = false;
    for (residuals[K.layout.DIRECT..]) |v| nonzero = nonzero or !v.isZero();
    try std.testing.expect(nonzero);
}
fn secure(data: []const M, n: usize, r: usize, c: usize) Q {
    return Q.fromM31(data[c * n + r], data[(c + 1) * n + r], data[(c + 2) * n + r], data[(c + 3) * n + r]);
}
test "Keccak table multiplicity metadata cannot change committed counts" {
    const a = std.testing.allocator;
    const counts: [8192]u64 = @splat(0);
    var trace = try K.tables.Trace.init(a, .chi, &counts);
    defer trace.deinit();
    trace.multiplicities[0] = 1;
    const ch = challenges();
    const claim = try trace.generateInteraction(ch.k);
    const n = trace.size();
    const r = physical(0, trace.log_size);
    const prior = physical(n - 1, trace.log_size);
    var tuple: [6]Q = undefined;
    for (&tuple, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
    const component = K.component.Component{ .kind = .chi, .log_size = 13, .challenges = ch.k, .claim = claim };
    try std.testing.expect(!K.component.tableResidual(&component, &tuple, Q.one(), Q.fromBase(trace.main[r]), secure(trace.interaction, n, r, 0), secure(trace.interaction, n, prior, 0)).isZero());
}
