//! LS-D64 in the v3 services lane: real CPU STARKs with the dword component,
//! a fresh wire receiver, mixed presence, and closure-only rejections.
const std = @import("std");
const F = @import("ls_dword_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const T = @import("types.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;
/// Shard 1's 38 dword rows need the tail instance after a log5 head.
const BOTH = [2]T.Logs{ .{ .ls_dword = 5 }, .{ .ls_dword = 5, .ls_dword_tail = 5 } };

test "v3 LS-D64: both shards route LD/SD to the dword row and verify with fresh keys and wire" {
    var c = try F.Case.init(a, BOTH, .none);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, &.{}, c.expected(), &c.bundle);
    for (c.bundle.cpus, F.DWORD_ROWS, F.GENERAL_ROWS) |cpu, d, g| {
        try std.testing.expectEqual(d, cpu.request.ls_dword);
        try std.testing.expectEqual(g, cpu.request.base.memory.ls_count);
        try std.testing.expect(!cpu.claims.ls_dword[0].owner.isZero());
        try std.testing.expect(!cpu.claims.ls_dword[0].ram.isZero());
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, &.{}, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 0, .max_total_steps = F.STEPS });
    defer loaded.deinit(a);
    for (BOTH, loaded.cpu_declarations) |x, y| try std.testing.expect(std.meta.eql(x, y.bridges));
    try std.testing.expectEqual(F.DWORD_ROWS[1], loaded.bundle.cpus[1].request.ls_dword);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, loaded.cpu_declarations[0].bridges);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, loaded.cpu_declarations[1].bridges);
    defer s1.deinit();
    const expected = F.expectedFor(s0.materials.program.identity, c.final);
    try E.verify(a, &.{ &s0, &s1 }, &.{}, expected, &loaded.bundle);
    try std.testing.expect(!loaded.bundle.cpus[1].claims.ls_dword[1].owner.isZero());
    // A receiver without the LS-D64 component (or without its tail) refuses the shard.
    var no_tail = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, .{ .ls_dword = 5 });
    defer no_tail.deinit();
    try std.testing.expectError(error.InvalidCombinedServiceCount, E.verify(a, &.{ &s0, &no_tail }, &.{}, expected, &loaded.bundle));
    var bare = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, .{});
    defer bare.deinit();
    try std.testing.expectError(error.InvalidCombinedBridgePresence, E.verify(a, &.{ &s0, &bare }, &.{}, expected, &loaded.bundle));
    // The public split is transcript-bound: moving a row between chips fails.
    loaded.bundle.cpus[1].request.ls_dword -= 1;
    loaded.bundle.cpus[1].request.base.memory.ls_count += 1;
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &.{}, expected, &loaded.bundle)));
    loaded.bundle.cpus[1].request.ls_dword += 1;
    loaded.bundle.cpus[1].request.base.memory.ls_count -= 1;
    // Shifting OWNER debt between the LS32 and LS-D64 ledger shares keeps the
    // CPU-local sum but is bound by both component prefixes.
    const shift = G.Q.one();
    loaded.bundle.cpus[1].claims.ls_dword[1].owner = loaded.bundle.cpus[1].claims.ls_dword[1].owner.add(shift);
    loaded.bundle.cpus[1].claims.base.ls.owner = loaded.bundle.cpus[1].claims.base.ls.owner.sub(shift);
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &.{}, expected, &loaded.bundle)));
    loaded.bundle.cpus[1].claims.ls_dword[1].owner = loaded.bundle.cpus[1].claims.ls_dword[1].owner.sub(shift);
    loaded.bundle.cpus[1].claims.base.ls.owner = loaded.bundle.cpus[1].claims.base.ls.owner.add(shift);
    try E.verify(a, &.{ &s0, &s1 }, &.{}, expected, &loaded.bundle);
}

test "v3 LS-D64: mixed presence (dword on shard 0 only) closes the same global RAM chain" {
    var c = try F.Case.init(a, .{ .{ .ls_dword = 5 }, .{} }, .none);
    // Shard 1 then proves all its LD/SD in the LS32 instances.
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, &.{}, c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(u32, 0), c.bundle.cpus[1].request.ls_dword);
    try std.testing.expectEqual(F.DWORD_ROWS[1] + F.GENERAL_ROWS[1], c.bundle.cpus[1].request.base.memory.ls_count);
    // A nonzero absent dword claim is rejected.
    c.bundle.cpus[1].claims.ls_dword[0].range8 = G.Q.one();
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
}

test "v3 LS-D64 adversarial: LB as LD, double consumption, shifted base and RAM predecessor are rejected by closure" {
    const cases = [_]struct { m: F.Case.Mutation, err: anyerror }{
        .{ .m = .lb_as_dword, .err = error.UnclosedCombinedCpuRelations },
        .{ .m = .double_consume, .err = error.UnclosedCombinedCpuRelations },
        .{ .m = .shifted_base, .err = error.UnclosedCombinedCpuRelations },
        .{ .m = .ram_predecessor, .err = error.UnclosedCombinedRam },
    };
    for (cases) |case| {
        var c = try F.Case.init(a, BOTH, case.m);
        defer c.deinit();
        const keys = c.keys();
        try std.testing.expectError(case.err, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
    }
}
