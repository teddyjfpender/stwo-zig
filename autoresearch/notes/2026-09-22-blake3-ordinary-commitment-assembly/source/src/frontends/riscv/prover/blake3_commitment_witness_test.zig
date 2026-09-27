const std = @import("std");
const witness = @import("blake3_commitment_witness.zig");
const program = @import("../air/program/commitment.zig");
const tree = @import("../air/memory_commitment/blake3_byte_tree.zig");
const state = @import("../runner/memory_state.zig");
const public = @import("../air/public_data.zig");
const logup = @import("../air/public_logup.zig");

test "BLAKE3 Span ordinary commitment assembly preserves decoded fields and memory custody" {
    const a = std.testing.allocator;
    var rom = [_]state.WordState{
        .{ .addr = 0x1000, .initial_word = 0xfff02083, .final_word = 0xfff02083, .final_clock = 0, .role = .{} }, // LW x1,-1(x0): canonical negative field
        .{ .addr = 0x1004, .initial_word = 0x0000006f, .final_word = 0x0000006f, .final_clock = 0, .role = .{} },
    };
    var words = [_]state.WordState{
        .{ .addr = 16, .initial_word = 42, .final_word = 255, .final_clock = 3, .role = .{} },
        .{ .addr = 20, .initial_word = 9, .final_word = 9, .final_clock = 0, .role = .{ .is_public_input = true } },
        .{ .addr = 24, .initial_word = 0, .final_word = 7, .final_clock = 4, .role = .{ .is_public_output = true } },
    };
    var snapshot = state.Snapshot{ .layout = std.mem.zeroes(state.MemoryLayout), .segment_role = .single(), .words = &words, .program_words = &rom };
    const rows = [_]struct { pc: u32, inst_word: u32 }{.{ .pc = 0x1000, .inst_word = rom[0].initial_word }};
    const extra = @import("../air/program/table.zig").Fetch{ .pc = 0x1004, .word = rom[1].initial_word };
    var built = try witness.build(a, @as(program.DeclaredDecodeAuthority, .base), .{&rows}, &snapshot, extra, 100);
    defer built.deinit();
    try std.testing.expectEqual(@as(usize, 3), built.boundaries.len);
    try std.testing.expectEqual(@as(u32, 1), built.program.rows[0].multiplicity);
    try std.testing.expectEqual(@as(u32, 1), built.program.rows[1].multiplicity);
    try std.testing.expect(built.program.rows[0].values[3] > 255);
    const opening = try built.program.opening(0x1003);
    try std.testing.expectEqual(built.program.rows[0].values[3], opening.value);
    const hasher = tree.TreeHasher.init(.program);
    try std.testing.expectEqual(built.program.root, opening.computedRoot(&hasher));
    var data = public.Blake3PublicData{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 1,
        .initial_regs = @splat(0),
        .final_regs = @splat(0),
        .reg_last_clock = @splat(0),
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = public.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{ .input_start = 0, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0, .output_data_addr = 0, .output_words = &.{} },
    };
    try built.bindPublic(&data);
    try std.testing.expectEqual(built.program.root, data.program_root.?);
    const relations = @import("../air/relation_challenges.zig").Relations.dummy();
    const sums = try logup.blake3RelationSums(&data, &relations);
    try std.testing.expect(sums.merkle.isZero());
    try std.testing.expectEqual(try logup.memoryAccessSum(&data, &relations), sums.memory_access);
    data.final_rw_root.?.bytes[31] ^= 0x80;
    const before = data;
    try std.testing.expectError(error.CommitmentRootMismatch, built.bindPublic(&data));
    try std.testing.expectEqualDeep(before, data);
    var prepared = try built.prepareBoundary(a, 0);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(u32, 42), prepared.boundary_row[0].toU32());
    for (prepared.paths) |path| try std.testing.expectEqual(built.initial.root, path.computed_root.?);
    try std.testing.expectError(error.InvalidMemoryBoundaryNamespace, witness.build(a, @as(program.DeclaredDecodeAuthority, .base), .{&rows}, &snapshot, extra, 0x7ffffffe));
    rom[0].initial_word = 0x00100093;
    try std.testing.expectError(error.ProgramWordChanged, witness.build(a, @as(program.DeclaredDecodeAuthority, .base), .{&rows}, &snapshot, extra, 100));
}
