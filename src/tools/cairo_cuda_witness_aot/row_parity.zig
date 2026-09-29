//! Differential fixture for register carry, stores and atomics across helpers.
const std = @import("std");
const model = @import("cairo_witness_model");
const writer = @import("writer.zig");

pub fn generate(allocator: std.mem.Allocator, output_path: []const u8) !void {
    var instructions: std.ArrayList(model.Inst) = .empty;
    defer instructions.deinit(allocator);
    for (0..6) |index| try instructions.append(allocator, .{ .op = .input, .dst = @intCast(index), .a = @intCast(index), .b = 0, .imm = 0 });
    var next: u16 = 6;
    var state = [4]u16{ 0, 1, 2, 3 };
    for (0..70) |round| {
        for ([_]u16{ state[0], state[1], state[2], state[3], 4, 5 }) |register|
            try instructions.append(allocator, .{ .op = .deduce_arg, .dst = 0, .a = register, .b = 0, .imm = 0 });
        try instructions.append(allocator, .{ .op = .deduce_call, .dst = next, .a = 0, .b = 4, .imm = @intFromEnum(model.DeduceKind.blake_g) });
        state = .{ next, next + 1, next + 2, next + 3 };
        next += 4;
        for (state, 0..) |register, coordinate|
            try instructions.append(allocator, .{ .op = .col_write, .dst = 0, .a = register, .b = 0, .imm = @intCast(round * 4 + coordinate) });
        try instructions.append(allocator, .{ .op = .lookup_word, .dst = 0, .a = state[0], .b = 0, .imm = @intCast(round) });
        try instructions.append(allocator, .{ .op = .sub_word, .dst = 0, .a = state[3], .b = 0, .imm = @intCast(round) });
        try instructions.append(allocator, .{ .op = .u32_and, .dst = next, .a = state[0], .b = 0, .imm = 31 });
        try instructions.append(allocator, .{ .op = .mult_push, .dst = 0, .a = next, .b = 0, .imm = 0 });
        next += 1;
    }
    // Keep the first result live through every helper and use it after round 70.
    try instructions.append(allocator, .{ .op = .u32_xor, .dst = next, .a = state[0], .b = 6, .imm = 0 });
    try instructions.append(allocator, .{ .op = .col_write, .dst = 0, .a = next, .b = 0, .imm = 280 });
    var program: model.Program = .{ .label = "row_parity", .semantic_hash = 0, .insts = instructions.items, .n_regs = next + 1, .n_inputs = 6, .n_cols = 281, .n_mult_tables = 1, .n_lookup_words = 70, .n_sub_words = 70 };
    program.semantic_hash = program.calculatedSemanticHash();
    var source = std.Io.Writer.Allocating.init(allocator);
    defer source.deinit();
    try writer.emitCanonical(allocator, &source.writer, program, std.fs.cwd());
    try std.fs.cwd().makePath(output_path);
    var directory = try std.fs.cwd().openDir(output_path, .{});
    defer directory.close();
    var file = try directory.createFile("kernel.cu", .{});
    defer file.close();
    try file.writeAll(source.written());
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source.written(), &digest, .{});
    const encoded = std.fmt.bytesToHex(digest, .lower);
    const kernel = try std.fmt.allocPrint(allocator, "stwo_jit_witness_{x:0>16}", .{program.semantic_hash});
    defer allocator.free(kernel);
    var receipt = std.Io.Writer.Allocating.init(allocator);
    defer receipt.deinit();
    try std.json.Stringify.value(.{ .schema = "stwo-cairo-cuda-row-parity-v1", .source_sha256 = @as([]const u8, &encoded), .kernel = kernel, .deduction_count = 70, .full_proof_verified = false }, .{}, &receipt.writer);
    var record = try directory.createFile("receipt.json", .{});
    defer record.close();
    try record.writeAll(receipt.written());
}
