const std = @import("std");
const F = @import("sponge_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const T = @import("types.zig");
const KR = @import("../keccak/shared/roster.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;

test "v3 Keccak sponge: CPU bridges, global RAM and one Keccak-f truth verify with fresh keys and wire" {
    var c = try F.Case.init(a, .none, false);
    defer c.deinit();
    // Known answers from the real executor: Keccak-256 of A's message and of
    // A's digest (C chains the hash across shards).
    var msg: [F.LEN_A]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = F.messageByte(i);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&msg, &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &c.captured_digests[0]);
    std.crypto.hash.sha3.Keccak256.hash(&c.captured_digests[0], &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &c.captured_digests[1]);
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 3), c.bundle.manifest.roots.len);
    try std.testing.expectEqual(@as(u32, 2), c.bundle.cpus[0].request.sponge.first_id);
    try std.testing.expectEqual(@as(u32, 5), c.bundle.cpus[1].request.sponge.first_id);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, c.truths(&buffer), &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    for (F.BRIDGES, loaded.cpu_declarations) |x, y| try std.testing.expect(std.meta.eql(x, y.bridges));
    try std.testing.expectEqual(@as(u32, 3), loaded.bundle.cpus[0].request.sponge.perms);
    try std.testing.expectEqual(@as(u32, 2), loaded.bundle.cpus[1].request.sponge.calls);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.BRIDGES[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.BRIDGES[1]);
    defer s1.deinit();
    var kt = try KR.TruthSetup.init(a, F.KECCAK_LOG);
    defer kt.deinit();
    const fresh = [_]R.Truth{.{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = F.KECCAK_IDS } }};
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle);
    // A receiver without the sponge bridges refuses the proofs.
    var bare = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, .{});
    defer bare.deinit();
    try std.testing.expectError(error.InvalidCombinedBridgePresence, E.verify(a, &.{ &s0, &bare }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle));
    // The truth must cover the sponge permutation IDs.
    const short = [_]R.Truth{.{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = F.KECCAK_IDS - 1 } }};
    try std.testing.expectError(error.InvalidCombinedTruthSpan, E.verify(a, &.{ &s0, &s1 }, &short, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle));
    // A shard's sponge first ID is receiver-checked.
    loaded.bundle.cpus[1].request.sponge.first_id += 1;
    try std.testing.expectError(error.InvalidCombinedTruthSpan, E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle));
    loaded.bundle.cpus[1].request.sponge.first_id -= 1;
    // A nonzero absent claim is rejected.
    loaded.bundle.cpus[1].claims.extras[0].ram = G.Q.one();
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle));
}

test "v3 Keccak sponge: permutations split across two truth spans close the same IO11 bus" {
    var c = try F.Case.init(a, .none, true);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 4), c.bundle.manifest.roots.len);
}

test "v3 Keccak sponge adversarial: wrong permutation input fails IO11, forged and stale messages fail RAM" {
    const cases = [_]struct { m: F.Case.Mutation, err: anyerror }{
        .{ .m = .wrong_truth_input, .err = error.UnclosedCombinedKeccakIo },
        .{ .m = .forged_message, .err = error.UnclosedCombinedRam },
        .{ .m = .stale_message, .err = error.UnclosedCombinedRam },
    };
    for (cases) |case| {
        var c = try F.Case.init(a, case.m, false);
        defer c.deinit();
        const keys = c.keys();
        var buffer: [2]R.Truth = undefined;
        try std.testing.expectError(case.err, E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle));
    }
}
