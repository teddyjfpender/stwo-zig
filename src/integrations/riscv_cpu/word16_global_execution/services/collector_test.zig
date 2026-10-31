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
