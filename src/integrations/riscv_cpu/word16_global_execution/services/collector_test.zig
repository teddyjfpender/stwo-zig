const std = @import("std");
const C = @import("collector.zig");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const a = std.testing.allocator;
test "Streaming collector and retired capture records preserve every physical proof and global obligation" {
    var expected = try F.Case.init(a);
    defer expected.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var builder = C.Builder.init(a, F.image());
    defer builder.deinit();
    for (&captured.native, &captured.tapes) |*n, *t| {
        try std.testing.expectEqual(@as(usize, 0), n.cpu.?.functions.items.len);
        try builder.append(n, t);
        n.cpu.?.releaseCaptureRecords();
    }
    var advice = try builder.finish();
    defer advice.deinit();
    try std.testing.expectError(error.InvalidServiceCollectorPhase, builder.finish());
    try std.testing.expectEqualDeep(captured.advice.initial, advice.initial);
    try std.testing.expectEqualDeep(captured.advice.terminal, advice.terminal);
    for (captured.advice.events, advice.events) |x, y| try std.testing.expectEqualDeep(x, y);
    for (captured.advice.keccak, advice.keccak) |x, y| try std.testing.expectEqualDeep(x, y);
    for (captured.advice.secp, advice.secp) |xx, yy| for (xx, yy) |x, y| try std.testing.expectEqualDeep(x, y);
    var candidate = try E.produceWithOptions(a, &expected.keys(), &expected.truths(), &.{ &captured.native[0], &captured.native[1] }, &advice, expected.expected(), .{ .consume_memory_events = true });
    defer candidate.deinit(a);
    for (advice.events) |events| try std.testing.expectEqual(@as(usize, 0), events.len);
    try E.verify(a, &expected.keys(), &expected.truths(), expected.expected(), &candidate);
    try std.testing.expectEqualDeep(expected.bundle.manifest.digest, candidate.manifest.digest);
    for (expected.bundle.cpus, candidate.cpus) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
    for (expected.bundle.truths, candidate.truths) |x, y| try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
}
fn allocationCollect(allocator: std.mem.Allocator, captured: *F.Captured) !void {
    var builder = C.Builder.init(allocator, F.image());
    defer builder.deinit();
    for (&captured.native, &captured.tapes) |*n, *t| try builder.append(n, t);
    var result = try builder.finish();
    defer result.deinit();
}
test "Streaming collector cleans every allocation failure including final boundary handoff" {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationCollect, .{&captured});
}
test "Partially mutated chronological ledger is poisoned on append failure" {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    const saved = captured.native[0].cpu.?.services.items[0].tag;
    captured.native[0].cpu.?.services.items[0].tag = 0xffffffff;
    defer captured.native[0].cpu.?.services.items[0].tag = saved;
    var builder = C.Builder.init(a, F.image());
    defer builder.deinit();
    // The ordinary store occurs before this invalid service, so the ledger
    // already owns a predecessor entry when the append must fail.
    try std.testing.expectError(error.UnqualifiedCombinedServiceTag, builder.append(&captured.native[0], &captured.tapes[0]));
    try std.testing.expect(builder.ledger.states.count() != 0);
    try std.testing.expectError(error.InvalidServiceCollectorPhase, builder.append(&captured.native[1], &captured.tapes[1]));
    try std.testing.expectError(error.InvalidServiceCollectorPhase, builder.finish());
}
test "Retired capture records cannot silently fall back to a closed memory constructor" {
    var c = try F.Case.init(a);
    defer c.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    captured.native[0].cpu.?.releaseCaptureRecords();
    const Source = @import("../../word16_execution/sources.zig").Source;
    try std.testing.expectError(error.MissingPreparedMemoryRecords, Source.fromPrepared(a, &c.setups[0].materials, F.image(), &captured.native[0]));
    try std.testing.expect(captured.native[0].cpu != null);
}

/// Segment 1's starting image (the fixture image after segment 0's writes,
/// as the first pass checkpoints it): the 25 fixture words, two pages.
const StartImage = struct {
    const front = @import("stwo_riscv_frontend");
    const P = front.rv64.memory.PAGE_SIZE;
    pages: [2][P]u8 = @splat(@splat(0)),
    entries: [2]front.rv64.checkpoint.Entry = undefined,
    fn init(self: *StartImage, after_first: *const C.Builder) !front.rv64.checkpoint.Checkpoint {
        const first_page = F.ADDRESS / P;
        for (0..25) |i| {
            const address = F.ADDRESS + 8 * i;
            const value = if (after_first.ledger.states.get(address)) |state| state.value else try F.image().initialWord(address);
            const page = &self.pages[@intCast(address / P - first_page)];
            std.mem.writeInt(u64, page[@intCast(address % P)..][0..8], value, .little);
        }
        for (&self.entries, 0..) |*e, i| e.* = .{ .index = first_page + i, .page = &self.pages[i] };
        return .{ .cpu = undefined, .counters = .{}, .pages = &self.entries, .written = &.{} };
    }
};
fn expectSameAdvice(expected: *const C.Advice, actual: *const C.Advice) !void {
    inline for (.{ "events", "keccak", "secp", "sha256", "arith256_mod", "curves", "bulk", "sponge", "initial", "terminal" }) |field|
        try std.testing.expectEqualDeep(@field(expected, field), @field(actual, field));
}
test "M8 two-phase ledger merges to exactly the serial advice, and falls back to it on a value disagreement" {
    const LS = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2;
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var serial = C.Builder.init(a, F.image());
    defer serial.deinit();
    try serial.append(&captured.native[0], &captured.tapes[0]);
    var start: StartImage = .{};
    const checkpoint = try start.init(&serial);
    try serial.append(&captured.native[1], &captured.tapes[1]);
    var expected = try serial.finish();
    defer expected.deinit();
    // Segment 1 reads words segment 0 wrote: the patch must restore real
    // (epoch 1) clocks, not just INITIAL ones.
    var from_first: usize = 0;
    for (expected.events[1]) |e| from_first += @intFromBool(e.before.epoch == 1);
    for (expected.keccak[1]) |c| for (c.predecessors) |s| {
        from_first += @intFromBool(s.epoch == 1);
    };
    for (expected.secp[1]) |calls| for (calls) |c| for (c.predecessors) |s| {
        from_first += @intFromBool(s.epoch == 1);
    };
    try std.testing.expect(from_first != 0);
    for ([_]bool{ false, true }) |disagree| {
        var builder = C.Builder.init(a, F.image());
        defer builder.deinit();
        const before = C.local_stats;
        for (0..2) |i| {
            var none: ?[]LS.native.Event = null;
            var local = try C.prepareLocal(a, F.image(), null, &captured.native[i], &captured.tapes[i], i, &none, &checkpoint);
            if (disagree and i == 1) local.ledger.initial.items[0].state.value +%= 1;
            try builder.appendLocal(&local, &captured.native[i], &captured.tapes[i], &none);
        }
        try std.testing.expectEqual(@as(u64, @intFromBool(disagree)), C.local_stats.fallbacks - before.fallbacks);
        try std.testing.expect(disagree or C.local_stats.touched - before.touched >= 24);
        var advice = try builder.finish();
        defer advice.deinit();
        try expectSameAdvice(&expected, &advice);
    }
}
fn allocationTwoPhase(allocator: std.mem.Allocator, captured: *F.Captured, checkpoint: *const @import("stwo_riscv_frontend").rv64.checkpoint.Checkpoint) !void {
    const LS = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2;
    var builder = C.Builder.init(allocator, F.image());
    defer builder.deinit();
    for (0..2) |i| {
        var none: ?[]LS.native.Event = null;
        var local = try C.prepareLocal(allocator, F.image(), null, &captured.native[i], &captured.tapes[i], i, &none, checkpoint);
        try builder.appendLocal(&local, &captured.native[i], &captured.tapes[i], &none);
    }
    var result = try builder.finish();
    defer result.deinit();
}
test "M8 two-phase ledger cleans every allocation failure (phase 1, fallback and merge)" {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    var serial = C.Builder.init(a, F.image());
    defer serial.deinit();
    try serial.append(&captured.native[0], &captured.tapes[0]);
    var start: StartImage = .{};
    const checkpoint = try start.init(&serial);
    try std.testing.checkAllAllocationFailures(a, allocationTwoPhase, .{ &captured, &checkpoint });
}
test {
    // Inline collector.zig tests (THP advice, M8 two-phase ledger patch).
    _ = C;
}
