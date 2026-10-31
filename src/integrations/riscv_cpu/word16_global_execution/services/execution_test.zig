const std = @import("std");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const a = std.testing.allocator;
test "One CPU proof per shard joins K ADD DOUBLE shared RAM and independently sized truths" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.truths();
    try E.verify(a, &keys, &truths, c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 5), c.bundle.manifest.roots.len);
    const R = @import("roster.zig");
    const KR = @import("../keccak/shared/roster.zig");
    const SR = @import("../secp/roster.zig");
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[0].materials.geometry, c.setups[0].bridges);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[1].materials.geometry, c.setups[1].bridges);
    defer s1.deinit();
    var kt = try KR.TruthSetup.init(a, c.ktruth.log);
    defer kt.deinit();
    var at = try SR.TruthSetup.init(a, .add, c.addtruth.logs);
    defer at.deinit();
    var dt = try SR.TruthSetup.init(a, .double, c.doubletruth.logs);
    defer dt.deinit();
    const fresh = [_]R.Truth{ .{ .keccak = .{ .setup = &kt, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = &at, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = &dt, .first_id = 1, .calls = 1 } } };
    try E.verify(a, &.{ &s0, &s1 }, &fresh, c.expected(), &c.bundle);
}

test "Actual valid mixed local proofs reject cross family RAM reset and false K or secp output" {
    for ([_]F.Case.Mutation{ .cross_family_reset, .wrong_keccak_output, .wrong_secp_output, .wrong_pointer }) |mutation| {
        var c = try F.Case.initMutation(a, mutation);
        defer c.deinit();
        const keys = c.keys();
        const truths = c.truths();
        const expected = switch (mutation) {
            .cross_family_reset => error.UnclosedCombinedRam,
            .wrong_keccak_output => error.UnclosedCombinedKeccakIo,
            .wrong_secp_output => error.UnclosedCombinedSecpWire,
            .wrong_pointer => error.UnclosedCombinedCpuRelations,
            else => unreachable,
        };
        try std.testing.expectError(expected, E.verify(a, &keys, &truths, c.expected(), &c.bundle));
    }
}
test "Combined receiver rejects free absent debts missing roots and wrong typed spans" {
    const G = @import("../protocol.zig");
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.truths();
    c.bundle.cpus[0].claims.extras[1].ram = G.Q.one();
    c.bundle.cpus[1].claims.extras[1].ram = c.bundle.cpus[1].claims.extras[1].ram.sub(G.Q.one());
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &keys, &truths, c.expected(), &c.bundle));
    c.bundle.cpus[0].claims.extras[1].ram = G.Q.zero();
    c.bundle.cpus[1].claims.extras[1].ram = c.bundle.cpus[1].claims.extras[1].ram.add(G.Q.one());
    var missing = try G.Manifest.init(a, c.bundle.manifest.specs[0..4], c.bundle.manifest.roots[0..4]);
    defer missing.deinit();
    var candidate = c.bundle;
    candidate.manifest = missing;
    try std.testing.expectError(error.IncompleteGlobalExecutionManifest, E.verify(a, &keys, &truths, c.expected(), &candidate));
    var gap = truths;
    gap[0].keccak.first_id = 2;
    try std.testing.expectError(error.InvalidCombinedTruthSpan, E.verify(a, &keys, &gap, c.expected(), &c.bundle));
    var swapped = truths;
    std.mem.swap(@TypeOf(truths[0]), &swapped[0], &swapped[1]);
    try std.testing.expectError(error.InvalidCombinedTruthSpan, E.verify(a, &keys, &swapped, c.expected(), &c.bundle));
    const rr = try a.dupe(G.Receipt, c.bundle.manifest.roots);
    defer a.free(rr);
    rr[2].main.bytes[0] ^= 1;
    var root = try G.Manifest.init(a, c.bundle.manifest.specs, rr);
    defer root.deinit();
    candidate = c.bundle;
    candidate.manifest = root;
    if (E.verify(a, &keys, &truths, c.expected(), &candidate)) |_| return error.AcceptedWrongMixedRoot else |_| {}
    c.bundle.truths[0].claims[0] = c.bundle.truths[0].claims[0].add(G.Q.one());
    c.bundle.truths[1].claims[0] = c.bundle.truths[1].claims[0].sub(G.Q.one());
    if (E.verify(a, &keys, &truths, c.expected(), &c.bundle)) |_| return error.AcceptedMixedBalancedClaims else |_| {}
}

fn produceStored(a2: std.mem.Allocator, c: *const F.Case, store: *@import("../retained_main_store.zig").Store) !E.Bundle {
    var captured = try F.Captured.init(a2);
    defer captured.deinit();
    return E.produceWithStorage(a2, &c.keys(), &c.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, c.expected(), store);
}
fn mainBytes(logs: []const u32) usize {
    var bytes: usize = 0;
    for (logs) |log| bytes += (@as(usize, 1) << @intCast(log)) * 4;
    return std.mem.alignForward(usize, bytes, std.heap.pageSize());
}
test "Combined mapped CPU and all truth MAIN preserve every proof manifest and wire with refusal cleanup" {
    const Store = @import("../retained_main_store.zig").Store;
    const W = @import("wire.zig");
    var c = try F.Case.init(a);
    defer c.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var expected_bytes: usize = 0;
    var cpu_bytes: usize = 0;
    for (c.keys()) |key| {
        const logs = try key.logs(a, 1);
        defer a.free(logs);
        cpu_bytes += mainBytes(logs);
    }
    expected_bytes = cpu_bytes;
    for (c.truths()) |truth| {
        const logs = try truth.logs(a, 1);
        defer a.free(logs);
        expected_bytes += mainBytes(logs);
    }
    var store = try Store.init(path, expected_bytes);
    defer store.deinit();
    var mapped = try produceStored(a, &c, &store);
    defer mapped.deinit(a);
    try std.testing.expectEqual(expected_bytes, store.stats().total_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try E.verify(a, &c.keys(), &c.truths(), c.expected(), &mapped);
    try std.testing.expectEqualDeep(c.bundle.manifest.roots, mapped.manifest.roots);
    try std.testing.expectEqualDeep(c.bundle.manifest.specs, mapped.manifest.specs);
    try std.testing.expectEqualDeep(c.bundle.manifest.digest, mapped.manifest.digest);
    for (c.bundle.cpus, mapped.cpus) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    for (c.bundle.truths, mapped.truths) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    var resident_dir = try tmp.dir.makeOpenPath("resident", .{});
    defer resident_dir.close();
    var mapped_dir = try tmp.dir.makeOpenPath("mapped", .{});
    defer mapped_dir.close();
    try W.write(a, resident_dir, &c.keys(), &c.truths(), &c.bundle);
    try W.write(a, mapped_dir, &c.keys(), &c.truths(), &mapped);
    for ([_][]const u8{ "bundle.json", "cells.bin", "cpu-0.bin", "cpu-1.bin", "truth-0.bin", "truth-1.bin", "truth-2.bin" }) |name| {
        const x = try resident_dir.readFileAlloc(a, name, 16 << 20);
        defer a.free(x);
        const y = try mapped_dir.readFileAlloc(a, name, 16 << 20);
        defer a.free(y);
        try std.testing.expectEqualSlices(u8, x, y);
    }
    // First-spill refusal and truth-phase refusal after both CPU spills must
    // drain all earlier mapped owners without requiring a successful proof.
    for ([_]usize{ 1, cpu_bytes }) |cap| {
        var refused = try Store.init(path, cap);
        defer refused.deinit();
        try std.testing.expectError(error.RetainedMainBudgetExceeded, produceStored(a, &c, &refused));
        try std.testing.expectEqual(@as(usize, 0), refused.stats().live_bytes);
        try std.testing.expectEqual(if (cap == 1) @as(usize, 0) else cpu_bytes, refused.stats().total_bytes);
    }
}
