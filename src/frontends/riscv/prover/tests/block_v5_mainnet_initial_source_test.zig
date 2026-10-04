//! Opt-in pinned mainnet source regression: one instruction, no preflight or
//! STARK proving. Exercises the real ELF layout and complete initial image.
const std = @import("std");
const writer = @import("../block_v5_memory_source_writer_v1.zig");
const runner = @import("../../runner/mod.zig");
const replay_mod = @import("../block_memory_replay.zig");
const sorted_mod = @import("../block_v5_memory_replay_adapter_v1.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const initial = @import("../block_v5_initial_sources_v1.zig");
const base = "autoresearch/notes/2026-09-24-ethereum-block-delivery/";

fn readPinned(a: std.mem.Allocator, path: []const u8, expected_hex: []const u8, maximum: usize) ![]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, maximum);
    errdefer a.free(bytes);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualDeep(expected, initial.sha256(bytes));
    return bytes;
}
fn snapshotRoot(a: std.mem.Allocator, words: []const @import("../../runner/memory_state.zig").WordState, comptime field: []const u8) ![32]u8 {
    var leaves: std.ArrayList(tree.Leaf) = .empty;
    defer leaves.deinit(a);
    for (words) |word| if (@field(word, field) != 0) {
        try leaves.append(a, .{ .index = try tree.memoryIndex(word.addr), .value = @field(word, field) });
    };
    return (try tree.TreeHasher.init(.memory).root(leaves.items)).bytes;
}

test "block-v5 pinned mainnet initial image validates canonical IO stack overlap" {
    const a = std.testing.allocator;
    const elf = try readPinned(a, base ++ "ethereum-block-sha-default-v3.elf", "ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688", 32 * 1024 * 1024);
    defer a.free(elf);
    const input = try readPinned(a, base ++ "fixture/stwo-runner-input-evm-hints.bin", "737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82", 4 * 1024 * 1024);
    defer a.free(input);
    var session = try runner.EthereumShaExecutionSession.init(a, elf, .{ .input = input, .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(1);
    defer segment.deinit();
    const layout = segment.base.rw_memory.layout;
    try std.testing.expectEqual(@as(u32, 0x1000001), layout.io_end);
    try std.testing.expectEqual(@as(u32, 0x1000000), layout.stack_bottom);
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var replay = try replay_mod.Replay.initFromSnapshot(a, dir.dir, segment.base.entry_cpu.regs, &segment.base.rw_memory, 16);
    defer replay.deinit();
    try replay.appendResult(&segment.base);
    var sorted = try replay.finish();
    sorted.deinit();
    const supplied = writer.Input{
        .layout = layout,
        .initial_words = replay.words,
        .public_input = input,
        .initial_registers = segment.base.entry_cpu.regs,
        .expected_final_registers = segment.base.exit_cpu.regs,
        .expected_initial_rw_root = try snapshotRoot(a, segment.base.rw_memory.words, "initial_word"),
        .expected_final_rw_root = try snapshotRoot(a, segment.base.rw_memory.words, "final_word"),
        .expected_total_events = replay.spooler.event_count,
    };
    var early = supplied;
    early.expected_total_events = 0;
    const admitted = try writer.validateInitial(early);
    try std.testing.expectEqualDeep(layout, admitted.layout);
    var wrong = early;
    wrong.layout.program_end = layout.io_base + 1;
    try std.testing.expectError(error.InvalidV5InitialSourceLayout, writer.validateInitial(wrong));
    wrong = early;
    wrong.caps.max_initial_words = replay.words.len - 1;
    try std.testing.expectError(error.V5SourceFileCapExceeded, writer.validateInitial(wrong));
    var result = try writer.write(dir.dir, supplied, sorted_mod.fromReplay(&replay));
    defer result.deinit();
    try std.testing.expectEqualDeep(supplied.expected_initial_rw_root, result.initial_pins.initial_rw_root);
    try std.testing.expectEqualDeep(supplied.expected_final_rw_root, result.final_rw_root);
    try std.testing.expectEqual(replay.spooler.event_count, result.event_count);
    _ = try result.initial_pins.digest();
}
