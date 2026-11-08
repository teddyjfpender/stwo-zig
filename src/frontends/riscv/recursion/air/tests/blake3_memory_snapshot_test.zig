const std = @import("std");
const source = @import("../blake3_memory_snapshot.zig");
const state = @import("../../../runner/memory_state.zig");
test "BLAKE3 Span retained snapshot respects boundary custody and preserves clocks" {
    const a = std.testing.allocator;
    var words = [_]state.WordState{
        .{ .addr = 12, .initial_word = 0x0000ff2a, .final_word = 0x80000001, .final_clock = 123 },
        .{ .addr = 16, .initial_word = 7, .final_word = 7, .final_clock = 0, .role = .{ .is_public_input = true } },
        .{ .addr = 20, .initial_word = 0, .final_word = 42, .final_clock = 99, .role = .{ .is_public_output = true } },
    };
    const snapshot = state.Snapshot{ .layout = std.mem.zeroes(state.MemoryLayout), .segment_role = .single(), .words = &words };
    var entry = try source.fromSnapshot(a, &snapshot, .entry, .ordinary_boundary);
    defer entry.deinit();
    var exit = try source.fromSnapshot(a, &snapshot, .exit, .ordinary_boundary);
    defer exit.deinit();
    var continuation = try source.fromSnapshot(a, &snapshot, .exit, .continuation);
    defer continuation.deinit();
    try std.testing.expect(!std.meta.eql(exit.root, continuation.root));
    try std.testing.expectEqual(@as(u32, 0), (try entry.statement(12, 99, 100)).clock);
    try std.testing.expectEqual(@as(u32, 123), (try exit.statement(12, 99, 100)).clock);
    try std.testing.expectError(error.PublicMemoryCustody, entry.statement(16, 99, 100));
    try std.testing.expectError(error.PublicMemoryCustody, exit.statement(20, 99, 100));
    try std.testing.expectError(error.NotOrdinaryMemoryProjection, continuation.statement(12, 99, 100));
    // The projection owns its source records and remains stable after caller edits.
    words[0].final_word = 0;
    words[0].final_clock = 999;
    var prepared = try exit.prepareWord(a, 12, 99, 100);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, 1), prepared.boundary_row[0].toU32());
    try std.testing.expectEqual(@as(u32, 128), prepared.boundary_row[3].toU32());
    try std.testing.expectEqual(@as(u32, 123), prepared.boundary_row[6].toU32());
    words[1].addr = 12;
    try std.testing.expectError(error.UnsortedSnapshotWords, source.fromSnapshot(a, &snapshot, .entry, .continuation));
}
