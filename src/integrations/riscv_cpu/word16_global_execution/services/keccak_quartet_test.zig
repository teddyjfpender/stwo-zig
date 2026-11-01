const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const KR = @import("../keccak/shared/roster.zig");
const SR = @import("../secp/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const G = @import("../protocol.zig");
const E = @import("execution.zig");
const F = @import("fixture.zig");
const Suite = @import("../../word16_execution/pcs_suite.zig").Suite;
const a = std.testing.allocator;
fn masksCount(m: anytype) usize {
    var n: usize = 0;
    for (m.items) |tree| for (tree) |column| {
        n += column.len;
    };
    return n;
}
test "Services quartet uses the same4n authority with648 fewer interaction columns and OODS samples" {
    var ch = G.T.P.Channel{};
    const base = K.component.Component{ .kind = .permutation, .log_size = 5, .calls = 1, .challenges = K.equations.Challenges.draw(&ch), .claim = G.Q.zero() };
    const quart = K.quartet_component.Component{ .base = base };
    try std.testing.expectEqual(@as(u8, 5), try quart.constraintDegreeBound(K.layout.DIRECT));
    try std.testing.expectEqual(base.maxConstraintLogDegreeBound(), quart.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(u32, 2), quart.compositionLogSplit());
    try std.testing.expectEqual(@as(usize, 648), base.interactionCount() - quart.interactionCount());
    const point = core.circle.secureFieldPointFromRandomSeed(G.Q.fromBase(core.fields.m31.M31.fromCanonical(17)));
    var old = try base.maskPoints(a, point, 13);
    defer old.deinit(a);
    var next = try quart.maskPoints(a, point, 13);
    defer next.deinit(a);
    try std.testing.expectEqual(@as(usize, 648), masksCount(old) - masksCount(next));
    try std.testing.expectEqual(@as(usize, 1956), KR.truthWidths(.quartet_v3)[2]);
    const inputs: [3]K.trace.State = .{ @splat(0), @splat(1), @splat(0xffffffffffffffff) };
    var triple = try K.trace.Trace.initWithLog(a, &inputs, 1, 6);
    defer triple.deinit();
    var quartet = try K.trace.Trace.initWithLog(a, &inputs, 1, 6);
    defer quartet.deinit();
    const q3 = try K.interaction.generate(&triple, base.challenges);
    const q4 = try K.interaction.generateForPolicy(&quartet, base.challenges, .quartet_v3, .{});
    try std.testing.expect(q3.eql(q4));
}
fn expectRebindingRejected(c: *const F.Case, truths: []const R.Truth) !void {
    const requests = [_]P.Request{ c.bundle.cpus[0].request, c.bundle.cpus[1].request };
    _ = try P.admit(a, &c.keys(), truths, &requests, c.expected());
    const specs = try a.alloc([32]u8, 2 + truths.len);
    defer a.free(specs);
    var first: u64 = 0;
    for (c.keys(), requests, 0..) |key, request, i| {
        var channel = G.T.P.Channel{};
        try P.beginCpu(&channel, key, request, c.expected(), i, first, try P.firstIds(&requests, i));
        first += request.base.cpu.steps;
        specs[i] = channel.digestBytes();
        try c.bundle.cpus[i].claims.local();
    }
    for (truths, 0..) |truth, i| {
        var channel = G.T.P.Channel{};
        P.beginTruth(&channel, truth, c.expected(), i);
        specs[2 + i] = channel.digestBytes();
    }
    var resealed = try G.Manifest.init(a, specs, c.bundle.manifest.roots);
    defer resealed.deinit();
    try resealed.check(specs); // Admission and resealing are genuinely valid.
    var candidate = c.bundle;
    candidate.manifest = resealed;
    if (E.verify(a, &c.keys(), truths, c.expected(), &candidate)) |_| return error.AcceptedKeccakProfileReplay else |_| {}
}
test "Services quartet actual mixed proofs verify with fresh authority and reject both resealed profile substitutions" {
    var legacy = try F.Case.init(a);
    defer legacy.deinit();
    var explicit = try F.Case.initMutationWithKeccakPolicy(a, .none, Suite.production(), .triple_v2);
    defer explicit.deinit();
    for (legacy.bundle.cpus, explicit.bundle.cpus) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    for (legacy.bundle.truths, explicit.bundle.truths) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    var quart = try F.Case.initMutationWithKeccakPolicy(a, .none, Suite.production(), .quartet_v3);
    defer quart.deinit();
    try E.verify(a, &quart.keys(), &quart.truths(), quart.expected(), &quart.bundle);
    try std.testing.expectEqualSlices(u8, &legacy.ktruth.key.root, &quart.ktruth.key.root);
    for (legacy.bundle.cpus, quart.bundle.cpus) |x, y| try std.testing.expectEqualDeep(x.request, y.request);
    try std.testing.expectEqualDeep(legacy.bundle.manifest.roots, quart.bundle.manifest.roots);
    try std.testing.expect(!std.mem.eql(u8, &legacy.bundle.manifest.digest, &quart.bundle.manifest.digest));
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, quart.setups[0].materials.geometry, quart.setups[0].bridges);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, quart.setups[1].materials.geometry, quart.setups[1].bridges);
    defer s1.deinit();
    var kt = try KR.TruthSetup.initWithSuiteAndPolicy(a, quart.ktruth.log, Suite.production(), .quartet_v3);
    defer kt.deinit();
    var at = try SR.TruthSetup.init(a, .add, quart.addtruth.logs);
    defer at.deinit();
    var dt = try SR.TruthSetup.init(a, .double, quart.doubletruth.logs);
    defer dt.deinit();
    const fresh = [_]R.Truth{ .{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = &at, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = &dt, .first_id = 1, .calls = 1 } } };
    try E.verify(a, &.{ &s0, &s1 }, &fresh, quart.expected(), &quart.bundle);
    try expectRebindingRejected(&quart, &legacy.truths());
    try expectRebindingRejected(&legacy, &quart.truths());
}
test "Services quartet physically valid false K output still rejects the shared IO debt" {
    var c = try F.Case.initMutationWithKeccakPolicy(a, .wrong_keccak_output, Suite.production(), .quartet_v3);
    defer c.deinit();
    // verify performs every physical proof before this final global IO closure.
    try std.testing.expectError(error.UnclosedCombinedKeccakIo, E.verify(a, &c.keys(), &c.truths(), c.expected(), &c.bundle));
}
test "Services quartet legacy shared route refuses the alternative authority explicitly" {
    var setup = try KR.TruthSetup.initWithSuiteAndPolicy(a, 5, Suite.production(), .quartet_v3);
    defer setup.deinit();
    const Old = @import("../keccak/shared/protocol.zig");
    try std.testing.expectError(error.UnsupportedLegacyKeccakTruthPolicy, Old.validateSpans(&.{.{ .setup = &setup, .first_id = 1, .calls = 1 }}, 1));
}
