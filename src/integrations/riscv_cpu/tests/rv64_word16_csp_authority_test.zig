const std = @import("std");
const front = @import("stwo_riscv_frontend");
const Image = @import("../word16_qualification/csp_image.zig");
const Capture = @import("../word16_qualification/csp_capture.zig").Capture;
const Cell = front.rv64_air.memory.closed_ram.types.Cell;
const a = std.testing.allocator;
const symbols = front.rv64.csp_contract.Symbols{ .input_start = 0x2000, .input_end = 0x3000, .halt_flag = 0x3000, .output_len = 0x3004, .output_data = 0x3008, .output_end = 0x4000, .stack_bottom = 0x4000, .stack_top = 0x5000 };
const pc: u64 = 0x100001000;
fn elf() [304]u8 {
    var bytes: [304]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 243, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[24..32], pc, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u32, bytes[68..72], 5, .little);
    std.mem.writeInt(u64, bytes[72..80], 256, .little);
    std.mem.writeInt(u64, bytes[80..88], pc, .little);
    std.mem.writeInt(u64, bytes[96..104], 48, .little);
    std.mem.writeInt(u64, bytes[104..112], 48, .little);
    std.mem.writeInt(u64, bytes[112..120], 1, .little);
    // Four SD output writes, then len=32 and halt=1. Invalid following ROM
    // demonstrates that the capture stops exactly at the admitted completion.
    const words = [_]u32{ 0x000030b7, 0x0000b423, 0x0000b823, 0x0000bc23, 0x0200b023, 0x02000113, 0x0020a223, 0x00100113, 0x0020a023, 0xffffffff, 0, 0 };
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[256 + 4 * i ..][0..4], word, .little);
    return bytes;
}
fn hash(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
const Fixture = struct {
    tmp: std.testing.TmpDir,
    elf_path: []u8,
    input_path: []u8,
    elf_hash: [64]u8,
    input_hash: [64]u8,
    fn init() !Fixture {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const bytes = elf();
        try tmp.dir.writeFile(.{ .sub_path = "guest.elf", .data = &bytes });
        try tmp.dir.writeFile(.{ .sub_path = "input", .data = &.{1} });
        const elf_path = try tmp.dir.realpathAlloc(a, "guest.elf");
        errdefer a.free(elf_path);
        return .{ .tmp = tmp, .elf_path = elf_path, .input_path = try tmp.dir.realpathAlloc(a, "input"), .elf_hash = hash(&bytes), .input_hash = hash(&.{1}) };
    }
    fn config(self: *const Fixture) Image.Config {
        return .{ .guest = .{ .elf = self.elf_path, .input = self.input_path, .symbols = symbols, .expected_digest = "0000000000000000000000000000000000000000000000000000000000000000" }, .elf_sha256 = &self.elf_hash, .input_sha256 = &self.input_hash, .expected_steps = 9 };
    }
    fn deinit(self: *Fixture) void {
        a.free(self.elf_path);
        a.free(self.input_path);
        self.tmp.cleanup();
    }
};
test "CSP32 receiver binds completion and all output bytes to terminal RAM" {
    var cells: [5]Cell = undefined;
    for (&cells, 0..) |*cell, i| cell.* = .{ .address = symbols.halt_flag + 8 * @as(u64, @intCast(i)), .state = .{ .value = if (i == 0) 0x2000000001 else 0, .epoch = 1, .tick = 36, .rights = 3 } };
    try Image.validateOutput(symbols, @splat(0), &cells);
    cells[0].state.value ^= 1;
    try std.testing.expectError(error.UntrustedCspCompletion, Image.validateOutput(symbols, @splat(0), &cells));
    cells[0].state.value ^= 1;
    cells[0].state.value ^= @as(u64, 1) << 32;
    try std.testing.expectError(error.UntrustedCspCompletion, Image.validateOutput(symbols, @splat(0), &cells));
    cells[0].state.value ^= @as(u64, 1) << 32;
    cells[4].state.value = @as(u64, 1) << 56;
    try std.testing.expectError(error.UntrustedCspOutput, Image.validateOutput(symbols, @splat(0), &cells));
    try std.testing.expectError(error.MissingCspTerminalWord, Image.validateOutput(symbols, @splat(0), cells[0..4]));
}
test "CSP32 compact capture preserves high PC and stops once at completion" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var image = try Image.Owner.init(a, fixture.config());
    defer image.deinit();
    var capture = try Capture.run(a, &image);
    defer capture.deinit();
    try std.testing.expectEqual(@as(usize, 9), capture.tape.len);
    try std.testing.expectEqual(pc + 36, capture.boundary.final_pc);
    try std.testing.expectEqual(@as(u64, 0), try image.admission().image.initialWord(symbols.halt_flag));
    try std.testing.expectEqual(@as(u32, 34), capture.boundary.register_clocks[2]);
    try std.testing.expectEqual(@as(usize, 6), capture.tape.memory_before.items.len);
    image.config.expected_steps = 10;
    try std.testing.expectError(error.IncompleteCspExecution, Capture.run(a, &image));
}
test "CSP32 receiver rejects foreign ELF input output and instruction permissions" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var config = fixture.config();
    config.elf_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expectError(error.EthereumInputIdentityMismatch, Image.Owner.init(a, config));
    config = fixture.config();
    config.input_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expectError(error.EthereumInputIdentityMismatch, Image.Owner.init(a, config));
    var image = try Image.Owner.init(a, fixture.config());
    defer image.deinit();
    image.expected[0] = 1;
    try std.testing.expectError(error.CspNativeOutputMismatch, Capture.run(a, &image));
    var bytes = elf();
    std.mem.writeInt(u32, bytes[68..72], 7, .little);
    try fixture.tmp.dir.writeFile(.{ .sub_path = "guest.elf", .data = &bytes });
    fixture.elf_hash = hash(&bytes);
    try std.testing.expectError(error.MutableCspInstructions, Image.Owner.init(a, fixture.config()));
}
fn allocationCase(allocator: std.mem.Allocator, config: Image.Config) !void {
    var image = try Image.Owner.init(allocator, config);
    defer image.deinit();
    var capture = try Capture.run(allocator, &image);
    defer capture.deinit();
    capture.releaseTape();
    capture.releaseTape();
}
test "CSP32 image and one-pass compact capture release every failed allocation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{fixture.config()});
}
test "qualification LS ladder preserves complete strict-prefix coverage and never grows padded rows" {
    const Geometry = @import("../word16_execution/geometry.zig").Geometry;
    const Coverage = @import("../word16_execution/coverage.zig");
    const Planner = @import("../word16_qualification/native_geometry.zig");
    for ([_]u32{ 0, 1, 30, 31, 32, 33, 62, 63, 64, 65, 65535, 65536, 549261, (1 << 22) - 1 }) |count| {
        const single = Geometry{ .cpu_log = 22, .ls_log = try Coverage.minimalPrefixLog(count) };
        try std.testing.expectEqualDeep(single, try Planner.choose(single, count, false));
        const chosen = try Planner.choose(single, count, true);
        const actual = try chosen.lsCounts(count);
        try std.testing.expectEqual(count, actual.head + actual.tail);
        try std.testing.expect(actual.head < @as(u64, 1) << @intCast(chosen.ls_log));
        if (chosen.ls_tail_log) |log| {
            try std.testing.expect(actual.tail > 0 and actual.tail < @as(u64, 1) << @intCast(log));
            try std.testing.expect(chosen.lsRows() < single.lsRows());
        } else try std.testing.expectEqual(@as(u32, 0), actual.tail);
    }
    const selected = try Planner.choose(.{ .cpu_log = 21, .ls_log = 20 }, 549261, true);
    try std.testing.expectEqual(@as(u32, 524287), (try selected.lsCounts(549261)).head);
    try std.testing.expectEqual(@as(u32, 24974), (try selected.lsCounts(549261)).tail);
}
