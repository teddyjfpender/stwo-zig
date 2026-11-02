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

test "v3 Keccak sponge with the throughput Keccak-f truth: fresh keys and wire verify; compact receiver and forged IO reject" {
    var c = try F.Case.initPolicy(a, .none, false, .throughput_v1);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    // The wire names the profile in the truth's second log word (21).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, c.truths(&buffer), &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    try std.testing.expectEqual(@as(u32, 21), loaded.truth_declarations[0].logs[1]);
    try std.testing.expectEqual(KR.TruthSetup.Policy.throughput_v1, try W.keccakPolicy(loaded.truth_declarations[0].logs[1]));
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.BRIDGES[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.BRIDGES[1]);
    defer s1.deinit();
    var kt = try KR.TruthSetup.initPolicy(a, F.KECCAK_LOG, @import("../keccak/shared/key.zig").Key.Suite.production(), .throughput_v1);
    defer kt.deinit();
    const fresh = [_]R.Truth{.{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = F.KECCAK_IDS } }};
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle);
    // A compact-profile receiver (different fixed tables, transcript identity
    // and interaction width) refuses the throughput truth proof.
    var compact = try KR.TruthSetup.init(a, F.KECCAK_LOG);
    defer compact.deinit();
    try std.testing.expect(!std.mem.eql(u8, &compact.key.root, &kt.key.root));
    const wrong = [_]R.Truth{.{ .keccak = .{ .setup = &compact, .first_id = 1, .calls = F.KECCAK_IDS } }};
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &wrong, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)));
    // A tampered truth claim no longer balances IO11.
    loaded.bundle.truths[0].claims[1] = loaded.bundle.truths[0].claims[1].add(G.Q.one());
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)));
    // Exact committed cells of the truth proof (cost.json computation:
    // MAIN + INTERACTION column logs), throughput vs compact at this log.
    var cells: [2]u64 = @splat(0);
    for ([_]*const KR.TruthSetup{ &compact, &kt }, &cells) |setup, *out| for (1..3) |tree| {
        const logs = try setup.logs(a, tree);
        defer a.free(logs);
        for (logs) |l| out.* += @as(u64, 1) << @intCast(l);
    };
    try std.testing.expectEqual(@as(u64, (1923 + 2596) * 128 + 5 * (8192 + 1024)), cells[0]);
    try std.testing.expectEqual(@as(u64, (1923 + 608) * 128 + 5 * ((1 << 21) + (1 << 16))), cells[1]);
}

test "v3 Keccak sponge throughput adversarial: wrong permutation input fails IO11" {
    var c = try F.Case.initPolicy(a, .wrong_truth_input, false, .throughput_v1);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try std.testing.expectError(error.UnclosedCombinedKeccakIo, E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle));
}

test "v3 Keccak sponge with the throughput-quartet Keccak-f truth: fresh keys and wire verify; throughput-v1 and compact receivers reject" {
    var c = try F.Case.initPolicy(a, .none, false, .throughput_quartet_v1);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, c.truths(&buffer), &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    // The wire names the profile: 21 | 4 << 8.
    try std.testing.expectEqual(W.KECCAK_THROUGHPUT_QUARTET_WORD, loaded.truth_declarations[0].logs[1]);
    try std.testing.expectEqual(KR.TruthSetup.Policy.throughput_quartet_v1, try W.keccakPolicy(loaded.truth_declarations[0].logs[1]));
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.BRIDGES[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.BRIDGES[1]);
    defer s1.deinit();
    const suite = @import("../keccak/shared/key.zig").Key.Suite.production();
    var kq = try KR.TruthSetup.initPolicy(a, F.KECCAK_LOG, suite, .throughput_quartet_v1);
    defer kq.deinit();
    const fresh = [_]R.Truth{.{ .keccak = .{ .setup = &kq, .first_id = 1, .calls = F.KECCAK_IDS } }};
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle);
    // A throughput-v1 receiver has the SAME fixed root (same tables and
    // geometry); only the transcript identity and the interaction width
    // differ, and it must still refuse the quartet truth proof.
    var kt = try KR.TruthSetup.initPolicy(a, F.KECCAK_LOG, suite, .throughput_v1);
    defer kt.deinit();
    try std.testing.expectEqualSlices(u8, &kt.key.root, &kq.key.root);
    const t1 = [_]R.Truth{.{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = F.KECCAK_IDS } }};
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &t1, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)));
    var compact = try KR.TruthSetup.init(a, F.KECCAK_LOG);
    defer compact.deinit();
    const wrong = [_]R.Truth{.{ .keccak = .{ .setup = &compact, .first_id = 1, .calls = F.KECCAK_IDS } }};
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &wrong, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)));
    // A tampered truth claim no longer balances IO11.
    loaded.bundle.truths[0].claims[1] = loaded.bundle.truths[0].claims[1].add(G.Q.one());
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)));
    loaded.bundle.truths[0].claims[1] = loaded.bundle.truths[0].claims[1].sub(G.Q.one());
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle);
    // A relabelled wire word (quartet proof declared as throughput-v1) is
    // rebuilt as a throughput-v1 key by the receiver and rejected.
    try std.testing.expectEqual(KR.TruthSetup.Policy.throughput_v1, try W.keccakPolicy(21));
    // Exact committed cells: (1923 + 456) per row + both throughput tables.
    var cells: [2]u64 = @splat(0);
    for ([_]*const KR.TruthSetup{ &kt, &kq }, &cells) |setup, *out| for (1..3) |tree| {
        const logs = try setup.logs(a, tree);
        defer a.free(logs);
        for (logs) |l| out.* += @as(u64, 1) << @intCast(l);
    };
    try std.testing.expectEqual(@as(u64, (1923 + 608) * 128 + 5 * ((1 << 21) + (1 << 16))), cells[0]);
    try std.testing.expectEqual(@as(u64, (1923 + 456) * 128 + 5 * ((1 << 21) + (1 << 16))), cells[1]);
}

test "v3 Keccak sponge throughput-quartet adversarial: wrong permutation input fails IO11, forged and stale messages fail RAM" {
    const cases = [_]struct { m: F.Case.Mutation, err: anyerror }{
        .{ .m = .wrong_truth_input, .err = error.UnclosedCombinedKeccakIo },
        .{ .m = .forged_message, .err = error.UnclosedCombinedRam },
        .{ .m = .stale_message, .err = error.UnclosedCombinedRam },
    };
    for (cases) |case| {
        var c = try F.Case.initPolicy(a, case.m, false, .throughput_quartet_v1);
        defer c.deinit();
        const keys = c.keys();
        var buffer: [2]R.Truth = undefined;
        try std.testing.expectError(case.err, E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle));
    }
}

test "v3 Keccak sponge with the 27-row throughput Keccak-f truth: fresh keys and wire verify; pair29 receivers reject; adversarial IO/RAM" {
    var c = try F.Case.initPolicy(a, .none, false, .throughput_r27_v1);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, c.truths(&buffer), &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    try std.testing.expectEqual(W.KECCAK_THROUGHPUT_R27_WORD, loaded.truth_declarations[0].logs[1]);
    try std.testing.expectEqual(KR.TruthSetup.Policy.throughput_r27_v1, try W.keccakPolicy(loaded.truth_declarations[0].logs[1]));
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.BRIDGES[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.BRIDGES[1]);
    defer s1.deinit();
    const suite = @import("../keccak/shared/key.zig").Key.Suite.production();
    var kr = try KR.TruthSetup.initPolicy(a, F.KECCAK_LOG, suite, .throughput_r27_v1);
    defer kr.deinit();
    const fresh = [_]R.Truth{.{ .keccak = .{ .setup = &kr, .first_id = 1, .calls = F.KECCAK_IDS } }};
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle);
    // pair29 quartet / throughput-v1 receivers: different fixed geometry.
    for ([_]KR.TruthSetup.Policy{ .throughput_quartet_v1, .throughput_v1, .triple_v2 }) |other| {
        var ko = try KR.TruthSetup.initPolicy(a, F.KECCAK_LOG, suite, other);
        defer ko.deinit();
        try std.testing.expect(!std.mem.eql(u8, &ko.key.root, &kr.key.root));
        const wrong = [_]R.Truth{.{ .keccak = .{ .setup = &ko, .first_id = 1, .calls = F.KECCAK_IDS } }};
        try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &wrong, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)));
    }
    loaded.bundle.truths[0].claims[1] = loaded.bundle.truths[0].claims[1].add(G.Q.one());
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)));
    // Exact committed cells: (1923 + 480) per row + both throughput tables.
    var cells: u64 = 0;
    for (1..3) |tree| {
        const logs = try kr.logs(a, tree);
        defer a.free(logs);
        for (logs) |l| cells += @as(u64, 1) << @intCast(l);
    }
    try std.testing.expectEqual(@as(u64, (1923 + 480) * 128 + 5 * ((1 << 21) + (1 << 16))), cells);
    const cases = [_]struct { m: F.Case.Mutation, err: anyerror }{
        .{ .m = .wrong_truth_input, .err = error.UnclosedCombinedKeccakIo },
        .{ .m = .forged_message, .err = error.UnclosedCombinedRam },
        .{ .m = .stale_message, .err = error.UnclosedCombinedRam },
    };
    for (cases) |case| {
        var bad = try F.Case.initPolicy(a, case.m, false, .throughput_r27_v1);
        defer bad.deinit();
        const bad_keys = bad.keys();
        var bad_buffer: [2]R.Truth = undefined;
        try std.testing.expectError(case.err, E.verify(a, &bad_keys, bad.truths(&bad_buffer), bad.expected(), &bad.bundle));
    }
}

// Regression (real-block InvalidCombinedRangePhase): the v3 Ethereum route's
// fused-tail + byte-pair CPU layout puts a second (byte-pair) multiplicity
// column on the log-16 AND table, and the sponge permutation bridge's byte-AND
// service multiplicities must still merge into that table.
test "v3 Keccak sponge with fused-tail and byte-pair CPU layouts: service AND/range multiplicities merge; fresh keys and wire verify" {
    const layouts = [_]F.Case.Layout{ .{ .cpu_fused_tail = true }, .{ .cpu_fused_tail = true, .cpu_u8_pairs = true } };
    for (layouts) |layout| {
        var c = try F.Case.initLayout(a, .none, false, .triple_v2, layout);
        defer c.deinit();
        const keys = c.keys();
        var buffer: [2]R.Truth = undefined;
        try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try W.write(a, tmp.dir, &keys, c.truths(&buffer), &c.bundle);
        var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = F.STEPS });
        defer loaded.deinit(a);
        for (loaded.cpu_declarations) |d| try std.testing.expect(d.geometry.cpu_fused_tail == layout.cpu_fused_tail and d.geometry.cpu_u8_pairs == layout.cpu_u8_pairs);
        var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.BRIDGES[0]);
        defer s0.deinit();
        var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.BRIDGES[1]);
        defer s1.deinit();
        var kt = try KR.TruthSetup.init(a, F.KECCAK_LOG);
        defer kt.deinit();
        const fresh = [_]R.Truth{.{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = F.KECCAK_IDS } }};
        const expected = F.expectedFor(s0.materials.program.identity, c.loaded);
        try E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle);
        // The layout is transcript-bound: a receiver with the other layout on
        // a shard refuses the proofs.
        var g = loaded.cpu_declarations[1].geometry;
        if (layout.cpu_u8_pairs) g.cpu_u8_pairs = false else g.cpu_fused_tail = false;
        var other = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, g, F.BRIDGES[1]);
        defer other.deinit();
        try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &other }, &fresh, expected, &loaded.bundle)));
        // A tampered absent claim still fails.
        loaded.bundle.cpus[1].claims.extras[0].ram = G.Q.one();
        try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle));
    }
}

test "v3 Keccak sponge byte-pair adversarial: wrong permutation input fails IO11, forged and stale messages fail RAM" {
    const cases = [_]struct { m: F.Case.Mutation, err: anyerror }{
        .{ .m = .wrong_truth_input, .err = error.UnclosedCombinedKeccakIo },
        .{ .m = .forged_message, .err = error.UnclosedCombinedRam },
        .{ .m = .stale_message, .err = error.UnclosedCombinedRam },
    };
    for (cases) |case| {
        var c = try F.Case.initLayout(a, case.m, false, .triple_v2, .{ .cpu_fused_tail = true, .cpu_u8_pairs = true });
        defer c.deinit();
        const keys = c.keys();
        var buffer: [2]R.Truth = undefined;
        try std.testing.expectError(case.err, E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle));
    }
}

test "service AND merge into the pair AND table: AND column grows, pair column kept, joint mass and phase checked" {
    const Tables = @import("stwo_riscv_frontend").rv64_air.providers.tables;
    const physical = @import("stwo_riscv_frontend").rv64_air.witness.physical;
    var setup = try Tables.Setup.init(a, .byte_and);
    defer setup.deinit();
    const counts = try a.alloc(u64, 65536);
    defer a.free(counts);
    const pairs = try a.alloc(u64, 65536);
    defer a.free(pairs);
    const extra = try a.alloc(u64, 65536);
    defer a.free(extra);
    for (counts, pairs, extra, 0..) |*c, *p, *x, i| {
        c.* = i % 3;
        p.* = (i * 7) % 5;
        x.* = (i * 11) % 4;
    }
    var table = try Tables.Request.initWithPairs(a, &setup, counts, pairs);
    defer table.deinit();
    // Layout mismatch (classic merge into a pair table) is refused.
    try std.testing.expectError(error.InvalidCombinedRangePhase, R.mergeAndTable(&table, false, extra));
    try R.mergeAndTable(&table, true, extra);
    for (0..65536) |i| {
        const row = physical(i, 16);
        try std.testing.expectEqual(@as(u32, @intCast(counts[i] + extra[i])), table.main[row].v);
        try std.testing.expectEqual(@as(u32, @intCast(pairs[i])), table.main[65536 + row].v);
    }
    // Joint AND + pair mass must stay below p: pair mass alone near p leaves
    // no room for the service counts.
    const heavy_pairs = try a.dupe(u64, pairs);
    defer a.free(heavy_pairs);
    @memset(counts, 0);
    @memset(heavy_pairs, 0);
    heavy_pairs[0] = (1 << 31) - 2;
    var heavy = try Tables.Request.initWithPairs(a, &setup, counts, heavy_pairs);
    defer heavy.deinit();
    try std.testing.expectError(error.CombinedRangeMassExceeded, R.mergeAndTable(&heavy, true, extra));
    // Classic table: the pair layout is refused, the classic one merges.
    var classic = try Tables.Request.init(a, &setup, counts);
    defer classic.deinit();
    try std.testing.expectError(error.InvalidCombinedRangePhase, R.mergeAndTable(&classic, true, extra));
    try R.mergeAndTable(&classic, false, extra);
    try std.testing.expectEqual(@as(u32, @intCast(extra[5])), classic.main[physical(5, 16)].v);
    // After interaction generation the table is no longer mergeable.
    var channel = @import("stwo_core").channel.blake2s.Blake2sChannel{};
    _ = try table.generateInteraction(Tables.Challenges.draw(&channel));
    try std.testing.expectError(error.InvalidCombinedRangePhase, R.mergeAndTable(&table, true, extra));
}
