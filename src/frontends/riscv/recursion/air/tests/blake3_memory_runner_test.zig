const std = @import("std");
const source = @import("../blake3_memory_snapshot.zig");
const Session = @import("../../../runner/segment_session.zig").ExecutionSession(.rv32im_zkvm_v1);

test "BLAKE3 Span memory source follows real adjacent runner segments" {
    const a = std.testing.allocator;
    const instructions = [_]u32{
        0x0010_0137, // LUI x2, 0x100
        0x1001_0113, // ADDI x2, x2, 0x100
        0x0550_0093, // ADDI x1, x0, 0x55
        0x0011_2023, // SW x1, 0(x2)
        0x0001_2183, // LW x3, 0(x2)
        0x0010_8093, // ADDI x1, x1, 1
        0x0011_2023, // SW x1, 0(x2)
        0x0000_0073, // ECALL
    };
    const elf = @import("../../../runner/tests/segment_continuation_test.zig").makeTestElf(&instructions);
    var session = try Session.init(a, &elf, .{});
    defer session.deinit();
    var first = try session.startSegment(4);
    defer first.deinit();
    var second = try session.resumeSegment(first.continuation.?, 100);
    defer second.deinit();
    try first.rw_memory.requireContinuationTo(second.rw_memory);
    var first_exit = try source.fromSnapshot(a, &first.rw_memory, .exit, .continuation);
    defer first_exit.deinit();
    var second_entry = try source.fromSnapshot(a, &second.rw_memory, .entry, .continuation);
    defer second_entry.deinit();
    try std.testing.expectEqual(first_exit.root, second_entry.root);
    var second_exit = try source.fromSnapshot(a, &second.rw_memory, .exit, .continuation);
    defer second_exit.deinit();
    try std.testing.expect(!std.meta.eql(first_exit.root, second_exit.root));
    var boundary = try source.fromSnapshot(a, &second.rw_memory, .exit, .ordinary_boundary);
    defer boundary.deinit();
    const executed_word = for (second.rw_memory.words) |word| {
        if (word.addr == 0x0010_0100) break word;
    } else return error.MissingExecutedWord;
    try std.testing.expectEqual(@as(u32, 0x55), executed_word.initial_word);
    try std.testing.expectEqual(@as(u32, 0x56), executed_word.final_word);
    try std.testing.expect(executed_word.final_clock > 0);
    var prepared = try boundary.prepareWord(a, executed_word.addr, 99, 100);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, 0x56), prepared.boundary_row[0].toU32());
    try std.testing.expectEqual(executed_word.final_clock, prepared.boundary_row[6].toU32());
    for (prepared.paths) |path| try std.testing.expectEqual(boundary.root, path.computed_root.?);
}
