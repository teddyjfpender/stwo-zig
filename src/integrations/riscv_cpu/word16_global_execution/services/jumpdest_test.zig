const std = @import("std");
const F = @import("jumpdest_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const BM = @import("stwo_riscv_frontend").rv64_air.crypto.bulk_memory;
const a = std.testing.allocator;

test "v3 jumpdest bridges prove and verify with a fresh receiver over the wire" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, &.{}, c.expected(), &c.bundle);
    // Fresh receiver: independently rebuilt keys, bundle read back from the wire.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, &.{}, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 0, .max_total_steps = 5 });
    defer loaded.deinit(a);
    for (F.bridges, loaded.cpu_declarations) |x, y| try std.testing.expect(std.meta.eql(x, y.bridges));
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, F.bridges[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, F.bridges[1]);
    defer s1.deinit();
    try E.verify(a, &.{ &s0, &s1 }, &.{}, F.expectedFor(s0.materials.program.identity), &loaded.bundle);
    try std.testing.expectEqual(@as(u32, 1), loaded.bundle.cpus[0].request.bulk.jump_calls);
    try std.testing.expectEqual(@as(u32, 2), loaded.bundle.cpus[0].request.bulk.jump_rows);
    try std.testing.expectEqual(@as(u32, 1), loaded.bundle.cpus[1].request.bulk.jump_rows);
    try std.testing.expectEqual(@as(u32, 0), loaded.bundle.cpus[0].request.bulk.calls);
    // Known answer: JUMPDESTs of call 0 at bytes 0, 3, 10 only.
    try std.testing.expectEqual(@as(u64, (1 << 0) | (1 << 3) | (1 << 10)), F.bitmaps().first[0]);
    try std.testing.expectEqual(@as(u64, 0), F.bitmaps().first[1]);
}

test "v3 jumpdest receiver rejects a wrong code word, a stale code read and a wrong length" {
    for ([_]F.Case.Mutation{ .wrong_code_word, .stale_code, .wrong_length }) |mutation| {
        var c = try F.Case.initMutation(a, mutation);
        defer c.deinit();
        const keys = c.keys();
        try std.testing.expectError(error.UnclosedCombinedRam, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
    }
}

test "v3 jumpdest receiver rejects free absent debts, a roster without the bridges and a changed row count" {
    const G = @import("../protocol.zig");
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    // A memset-desc claim on a JUMPDEST-only shard, balanced elsewhere, is refused.
    c.bundle.cpus[0].claims.bulk[0].owner = G.Q.one();
    c.bundle.cpus[1].claims.bulk[3].owner = c.bundle.cpus[1].claims.bulk[3].owner.sub(G.Q.one());
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
    c.bundle.cpus[0].claims.bulk[0].owner = G.Q.zero();
    c.bundle.cpus[1].claims.bulk[3].owner = c.bundle.cpus[1].claims.bulk[3].owner.add(G.Q.one());
    // A receiver whose keys omit the JUMPDEST bridges refuses the bundle.
    var bare = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[0].materials.geometry, .{});
    defer bare.deinit();
    if (E.verify(a, &.{ &bare, c.setups[1] }, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedJumpdestWithoutKeys else |_| {}
    // A receiver keyed with a table at the wrong log refuses it too.
    var wrong = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[0].materials.geometry, .{ .bulk = .{ .jdesc = 5, .jscan = 5, .jtab = BM.types.TABLE_LOG + 1 } });
    defer wrong.deinit();
    if (E.verify(a, &.{ &wrong, c.setups[1] }, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedJumpdestWrongTable else |_| {}
    // Scan-row counts are transcript-bound: changing one breaks verification.
    c.bundle.cpus[0].request.bulk.jump_rows = 1;
    if (E.verify(a, &keys, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedWrongJumpdestCount else |_| {}
}
