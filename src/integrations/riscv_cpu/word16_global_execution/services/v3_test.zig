const std = @import("std");
const F = @import("v3_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const T = @import("types.zig");
const HR = @import("../sha256/roster.zig");
const AR = @import("../arith256/roster.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;

test "v3 all services: SHA-256, arith256_mod and bulk memory prove together and verify with a fresh receiver" {
    var c = try F.Case.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.truths();
    try E.verify(a, &keys, &truths, c.expected(), &c.bundle);
    // 2 CPU + 2 truth roots.
    try std.testing.expectEqual(@as(usize, 4), c.bundle.manifest.roots.len);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, &truths, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 2, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    for (F.BRIDGES, loaded.cpu_declarations) |x, y| try std.testing.expect(std.meta.eql(x, y.bridges));
    try std.testing.expectEqual(@as(u32, 1), loaded.bundle.cpus[0].request.calls[3]);
    try std.testing.expectEqual(@as(u32, 1), loaded.bundle.cpus[1].request.calls[4]);
    try std.testing.expectEqual(@as(u32, 4), loaded.bundle.cpus[0].request.bulk.set_words);
    try std.testing.expectEqual(@as(u32, 4), loaded.bundle.cpus[1].request.bulk.copy_words);
    // Fresh receiver keys built only from receiver-chosen declarations.
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.BRIDGES[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.BRIDGES[1]);
    defer s1.deinit();
    var ht = try HR.TruthSetup.init(a, F.SHA_LOG);
    defer ht.deinit();
    var at = try AR.TruthSetup.init(a, F.ARITH_LOG);
    defer at.deinit();
    const fresh = F.truthsFor(&ht, &at);
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle);
    // A receiver missing any one family's bridge in shard 0 refuses the proofs.
    for ([_]T.Logs{
        .{ .arith256_mod = 5, .bulk = .{ .desc = 5, .set = 5 } },
        .{ .sha256 = 5, .bulk = .{ .desc = 5, .set = 5 } },
        .{ .sha256 = 5, .arith256_mod = 5 },
    }) |bridges| {
        var partial = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, bridges);
        defer partial.deinit();
        if (E.verify(a, &.{ &partial, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)) |_| return error.AcceptedWithoutBridge else |_| {}
    }
    // A receiver without the arith256_mod truth refuses (spans must cover calls).
    if (E.verify(a, &.{ &s0, &s1 }, fresh[0..1], F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)) |_| return error.AcceptedWithoutTruth else |_| {}
    // Unused truth claim slots are pinned to zero.
    loaded.bundle.truths[1].claims[2] = G.Q.one();
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle));
}

test "v3 all services adversarial: false outputs fail Wire35, forged copies/fills/stale reads fail global RAM" {
    const cases = [_]struct { m: F.Case.Mutation, err: anyerror }{
        .{ .m = .wrong_sha_output, .err = error.UnclosedCombinedSecpWire },
        .{ .m = .wrong_arith_output, .err = error.UnclosedCombinedSecpWire },
        .{ .m = .wrong_copied_word, .err = error.UnclosedCombinedRam },
        .{ .m = .wrong_fill, .err = error.UnclosedCombinedRam },
        .{ .m = .stale_copy_source, .err = error.UnclosedCombinedRam },
    };
    for (cases) |case| {
        var c = try F.Case.init(a, case.m);
        defer c.deinit();
        const keys = c.keys();
        const truths = c.truths();
        try std.testing.expectError(case.err, E.verify(a, &keys, &truths, c.expected(), &c.bundle));
    }
}

test "v3 all services with the fused-tail CPU layout verify with a fresh receiver; legacy keys refuse them" {
    const Geo = @import("../../word16_execution/geometry.zig");
    var legacy = try F.Case.init(a, .none);
    defer legacy.deinit();
    var c = try F.Case.initWith(a, .none, .{ .cpu_fused_tail = true });
    defer c.deinit();
    const keys = c.keys();
    const truths = c.truths();
    try E.verify(a, &keys, &truths, c.expected(), &c.bundle);
    // Exact committed-cell delta: only CPU interaction, -4 columns per shard.
    for (keys, legacy.keys()) |fused_setup, legacy_setup| {
        const x = try Geo.cells(&fused_setup.materials.shapes());
        const y = try Geo.cells(&legacy_setup.materials.shapes());
        try std.testing.expectEqual(y.fixed, x.fixed);
        try std.testing.expectEqual(y.main, x.main);
        try std.testing.expectEqual(y.interaction - 4 * (@as(u64, 1) << @intCast(F.CPU_LOG)), x.interaction);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, &truths, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 2, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    for (loaded.cpu_declarations) |d| try std.testing.expect(d.geometry.cpu_fused_tail);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.BRIDGES[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.BRIDGES[1]);
    defer s1.deinit();
    var ht = try HR.TruthSetup.init(a, F.SHA_LOG);
    defer ht.deinit();
    var at = try AR.TruthSetup.init(a, F.ARITH_LOG);
    defer at.deinit();
    const fresh = F.truthsFor(&ht, &at);
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle);
    // A receiver with the legacy layout on either shard refuses the fused
    // proofs, and fused keys refuse the legacy proofs (layout is transcript-bound).
    for (0..2) |shard| {
        var g = loaded.cpu_declarations[shard].geometry;
        g.cpu_fused_tail = false;
        var wrong = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, g, F.BRIDGES[shard]);
        defer wrong.deinit();
        const pair: [2]*const R.CpuSetup = if (shard == 0) .{ &wrong, &s1 } else .{ &s0, &wrong };
        if (E.verify(a, &pair, &fresh, F.expectedFor(s0.materials.program.identity, c.loaded), &loaded.bundle)) |_| return error.AcceptedFusedProofWithLegacyKeys else |_| {}
    }
    if (E.verify(a, &.{ &s0, &s1 }, &fresh, legacy.expected(), &legacy.bundle)) |_| return error.AcceptedLegacyProofWithFusedKeys else |_| {}
}

test "v3 all services fused tail adversarial: global closure still rejects forged fills and copies" {
    for ([_]struct { m: F.Case.Mutation, err: anyerror }{
        .{ .m = .wrong_fill, .err = error.UnclosedCombinedRam },
        .{ .m = .wrong_sha_output, .err = error.UnclosedCombinedSecpWire },
    }) |case| {
        var c = try F.Case.initWith(a, case.m, .{ .cpu_fused_tail = true });
        defer c.deinit();
        const keys = c.keys();
        const truths = c.truths();
        try std.testing.expectError(case.err, E.verify(a, &keys, &truths, c.expected(), &c.bundle));
    }
}
