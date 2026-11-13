//! Real pinned ELF fixture and exact native-capture/tree comparisons.
//! Kept independent of speculative-reader test orchestration.
const std = @import("std");
const Capture = @import("capture.zig");
const Request = @import("../../rv64_ethereum_request.zig");
const a = std.testing.allocator;
pub fn image() [144]u8 {
    var bytes: [144]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 243, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[24..32], 4096, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u32, bytes[68..72], 5, .little);
    std.mem.writeInt(u64, bytes[72..80], 120, .little);
    std.mem.writeInt(u64, bytes[80..88], 4096, .little);
    std.mem.writeInt(u64, bytes[96..104], 24, .little);
    std.mem.writeInt(u64, bytes[104..112], 24, .little);
    std.mem.writeInt(u64, bytes[112..120], 4, .little);
    // lui x1,0xc00; addi x2,zero,43; sw x2,4(x1);
    // addi x2,zero,1; sw x2,0(x1); terminal: jal zero,0.
    const words = [_]u32{ 0x00c000b7, 0x02b00113, 0x0020a223, 0x00100113, 0x0020a023, 0x0000006f };
    for (words, 0..) |word, i| std.mem.writeInt(u32, bytes[120 + 4 * i ..][0..4], word, .little);
    return bytes;
}

pub const Fixture = struct {
    temp: std.testing.TmpDir,
    elf: []u8,
    input: []u8,
    output: []u8,
    elf_hash: [64]u8,
    input_hash: [64]u8,
    pub fn init() !Fixture {
        var temp = std.testing.tmpDir(.{});
        errdefer temp.cleanup();
        const bytes = image();
        try temp.dir.writeFile(.{ .sub_path = "guest.elf", .data = &bytes });
        try temp.dir.writeFile(.{ .sub_path = "input", .data = &.{1} });
        const elf = try temp.dir.realpathAlloc(a, "guest.elf");
        errdefer a.free(elf);
        const input = try temp.dir.realpathAlloc(a, "input");
        errdefer a.free(input);
        const root = try temp.dir.realpathAlloc(a, ".");
        defer a.free(root);
        const output = try std.fs.path.join(a, &.{ root, "artifacts" });
        return .{ .temp = temp, .elf = elf, .input = input, .output = output, .elf_hash = std.fmt.bytesToHex(Request.sha(&bytes), .lower), .input_hash = std.fmt.bytesToHex(Request.sha(&.{1}), .lower) };
    }
    pub fn config(self: *const Fixture) Request.Config {
        return .{ .elf = self.elf, .input = self.input, .elf_sha256 = &self.elf_hash, .input_sha256 = &self.input_hash, .expected_output = "00" ** 43, .symbols = .{ .input_start = 0x800000, .input_end = 0xc00000, .halt_flag = 0xc00000, .output_len = 0xc00004, .output_data = 0xc00008, .output_end = 0x1000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .heap_start = 0x2100000, .heap_end = 0x2200000 }, .output_directory = self.output, .terminal_pc = 4116, .batch_steps = 3, .max_steps = 10, .profile_stages = false, .workers = 1 };
    }
    pub fn deinit(self: *Fixture) void {
        a.free(self.output);
        a.free(self.input);
        a.free(self.elf);
        self.temp.cleanup();
    }
};
pub fn same(expected: *const Capture.Owner, actual: *const Capture.Owner) !void {
    try std.testing.expectEqual(expected.total_steps, actual.total_steps);
    try std.testing.expectEqual(expected.final_pc, actual.final_pc);
    try std.testing.expectEqualDeep(expected.final_registers, actual.final_registers);
    try std.testing.expectEqual(expected.native.items.len, actual.native.items.len);
    for (expected.native.items, actual.native.items) |left, right| try sameNative(left, right);
    try std.testing.expectEqualDeep(expected.advice, actual.advice);
}
pub fn sameNative(left: anytype, right: anytype) !void {
    {
        try std.testing.expectEqualDeep(left.raw_counts, right.raw_counts);
        try std.testing.expectEqualDeep(left.alu, right.alu);
        try std.testing.expectEqualDeep(left.binary, right.binary);
        try std.testing.expectEqualDeep(left.shift, right.shift);
        try std.testing.expectEqualDeep(left.shift_weights, right.shift_weights);
        try std.testing.expectEqualDeep(left.division, right.division);
        try std.testing.expectEqualDeep(left.multiplication, right.multiplication);
        try std.testing.expectEqualDeep(left.cpu.?.metadata, right.cpu.?.metadata);
        try std.testing.expectEqualDeep(left.cpu.?.public, right.cpu.?.public);
        try std.testing.expectEqualDeep(left.jalr, right.jalr);
    }
}

pub fn expectSameTree(x: std.fs.Dir, y: std.fs.Dir) !void {
    var walker = try x.walk(a);
    defer walker.deinit();
    var files: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const left = try x.readFileAlloc(a, entry.path, 1 << 30);
        defer a.free(left);
        const right = y.readFileAlloc(a, entry.path, 1 << 30) catch |err| {
            std.debug.print("segment tree lacks {s}: {s}\n", .{ entry.path, @errorName(err) });
            return err;
        };
        defer a.free(right);
        try std.testing.expectEqualSlices(u8, left, right);
        files += 1;
    }
    var count: usize = 0;
    var other = try y.walk(a);
    defer other.deinit();
    while (try other.next()) |entry| count += @intFromBool(entry.kind == .file);
    try std.testing.expectEqual(files, count);
    try std.testing.expect(files >= 4);
}
