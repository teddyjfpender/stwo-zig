const std = @import("std");
const F = @import("bulk_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const a = std.testing.allocator;

test "v3 bulk memset/memcpy bridges prove and verify with a fresh receiver over the wire" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, &.{}, c.expected(), &c.bundle);
    // Fresh receiver: independently rebuilt keys, bundle read back from the wire.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, &.{}, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 0, .max_total_steps = 6 });
    defer loaded.deinit(a);
    for (F.bridges, loaded.cpu_declarations) |x, y| try std.testing.expect(std.meta.eql(x, y.bridges));
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.bridges[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.bridges[1]);
    defer s1.deinit();
    try E.verify(a, &.{ &s0, &s1 }, &.{}, F.expectedFor(s0.materials.program.identity), &loaded.bundle);
    try std.testing.expectEqual(@as(u32, 1), loaded.bundle.cpus[0].request.bulk.calls);
    try std.testing.expectEqual(@as(u32, 4), loaded.bundle.cpus[0].request.bulk.set_words);
    try std.testing.expectEqual(@as(u32, 4), loaded.bundle.cpus[1].request.bulk.copy_words);
}

test "v3 bulk receiver rejects wrong copies, fills and stale reads" {
    for ([_]F.Case.Mutation{ .wrong_copied_word, .wrong_fill, .stale_source }) |mutation| {
        var c = try F.Case.initMutation(a, mutation);
        defer c.deinit();
        const keys = c.keys();
        try std.testing.expectError(error.UnclosedCombinedRam, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
    }
}

test "v3 bulk receiver rejects free absent bulk debts and a roster without bulk keys" {
    const G = @import("../protocol.zig");
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    // A copy claim on the memset-only shard, balanced elsewhere, is refused.
    c.bundle.cpus[0].claims.bulk[1].ram = G.Q.one();
    c.bundle.cpus[1].claims.bulk[1].ram = c.bundle.cpus[1].claims.bulk[1].ram.sub(G.Q.one());
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
    c.bundle.cpus[0].claims.bulk[1].ram = G.Q.zero();
    c.bundle.cpus[1].claims.bulk[1].ram = c.bundle.cpus[1].claims.bulk[1].ram.add(G.Q.one());
    // A receiver whose keys omit the bulk bridges (v2 roster) refuses the bundle.
    var v2 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[0].materials.geometry, .{});
    defer v2.deinit();
    if (E.verify(a, &.{ &v2, c.setups[1] }, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedBulkWithoutKeys else |_| {}
    // Claimed word counts are transcript-bound: changing one breaks verification.
    c.bundle.cpus[1].request.bulk.copy_words = 3;
    if (E.verify(a, &keys, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedWrongBulkCount else |_| {}
}
