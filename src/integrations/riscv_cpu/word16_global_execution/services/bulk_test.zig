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

const X = @import("bulk_ext_fixture.zig");
const T = @import("types.zig");

test "v3 bulk unaligned memcpy and memcmp bridges prove and verify with a fresh receiver over the wire" {
    var c = try X.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, &.{}, c.expected(), &c.bundle);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try W.write(a, tmp.dir, &keys, &.{}, &c.bundle);
    var loaded = try W.read(a, tmp.dir, .{ .max_cpus = 2, .max_truths = 0, .max_total_steps = 5 });
    defer loaded.deinit(a);
    for (X.bridges, loaded.cpu_declarations) |x, y| try std.testing.expect(std.meta.eql(x, y.bridges));
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &X.WORDS }, loaded.cpu_declarations[0].geometry, X.bridges[0]);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &X.WORDS }, loaded.cpu_declarations[1].geometry, X.bridges[1]);
    defer s1.deinit();
    try E.verify(a, &.{ &s0, &s1 }, &.{}, X.expectedFor(s0.materials.program.identity), &loaded.bundle);
    const r0 = loaded.bundle.cpus[0].request.bulk;
    const r1 = loaded.bundle.cpus[1].request.bulk;
    try std.testing.expectEqual(T.BulkCounts{ .calls = 1, .ucopy_rows = 4 }, r0);
    try std.testing.expectEqual(T.BulkCounts{ .cmp_calls = 1, .cmp_words = 2 }, r1);
}

test "v3 bulk extension receiver rejects a wrong source byte, a wrong compared word and a forged result" {
    for ([_]X.Case.Mutation{ .wrong_source_byte, .wrong_compare_word }) |mutation| {
        var c = try X.Case.initMutation(a, mutation);
        defer c.deinit();
        const keys = c.keys();
        try std.testing.expectError(error.UnclosedCombinedRam, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
    }
    // An honest prover cannot even build a forged result.
    try std.testing.expectError(error.InvalidBulkMemoryResult, X.Case.initMutation(a, .forged_result));
}

test "v3 bulk extension receiver rejects absent extension debts, keys without the extension and changed counts" {
    const G = @import("../protocol.zig");
    var c = try X.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    // A cmp claim on the copy-only shard, balanced on the memcmp shard.
    c.bundle.cpus[0].claims.bulk[5].ram = G.Q.one();
    c.bundle.cpus[1].claims.bulk[5].ram = c.bundle.cpus[1].claims.bulk[5].ram.sub(G.Q.one());
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &keys, &.{}, c.expected(), &c.bundle));
    c.bundle.cpus[0].claims.bulk[5].ram = G.Q.zero();
    c.bundle.cpus[1].claims.bulk[5].ram = c.bundle.cpus[1].claims.bulk[5].ram.add(G.Q.one());
    try E.verify(a, &keys, &.{}, c.expected(), &c.bundle);
    // Receivers whose keys omit the extension kinds (aligned-only roster).
    var aligned = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &X.WORDS }, c.setups[1].materials.geometry, .{ .bulk = .{ .desc = 5 } });
    defer aligned.deinit();
    if (E.verify(a, &.{ c.setups[0], &aligned }, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedBulkExtensionWithoutKeys else |_| {}
    // Transcript-bound counts: one fewer compared word, one fewer ucopy row.
    c.bundle.cpus[1].request.bulk.cmp_words = 1;
    if (E.verify(a, &keys, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedWrongBulkCount else |_| {}
    c.bundle.cpus[1].request.bulk.cmp_words = 2;
    c.bundle.cpus[0].request.bulk.ucopy_rows = 3;
    if (E.verify(a, &keys, &.{}, c.expected(), &c.bundle)) |_| return error.AcceptedWrongBulkCount else |_| {}
}

test "v3 bulk aligned-only rosters and counts serialize without extension fields" {
    const json = std.json.Stringify.value;
    var w = std.Io.Writer.Allocating.init(a);
    defer w.deinit();
    try json(T.Logs{ .bulk = .{ .desc = 5, .copy = 6 } }, .{}, &w.writer);
    try json(T.BulkCounts{ .calls = 1, .copy_words = 4 }, .{}, &w.writer);
    try std.testing.expectEqualStrings("{\"keccak\":null,\"add\":null,\"double\":null,\"bulk\":{\"desc\":5,\"copy\":6,\"set\":null}}{\"calls\":1,\"copy_words\":4,\"set_words\":0}", w.written());
    w.clearRetainingCapacity();
    try json(T.Bulk{ .cdesc = 5, .cmp = 6 }, .{}, &w.writer);
    try json(T.BulkCounts{ .cmp_calls = 1, .cmp_words = 2 }, .{}, &w.writer);
    try std.testing.expectEqualStrings("{\"desc\":null,\"copy\":null,\"set\":null,\"cdesc\":5,\"cmp\":6}{\"calls\":0,\"copy_words\":0,\"set_words\":0,\"cmp_calls\":1,\"cmp_words\":2}", w.written());
}
