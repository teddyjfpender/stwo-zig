//! Fixed-width public RAM sidecar. Streaming bounds avoid constructing a
//! hundreds-of-megabytes JSON string for real Ethereum touched sets.
const std = @import("std");
const Cell = @import("memory/statement.zig").Cell;
const WIDTH = 23;
const BLOCK = 2048;
const MAGIC = "RV64RAM1";
pub fn write(dir: std.fs.Dir, initial: []const Cell, terminal: []const Cell) !void {
    if (initial.len > 1 << 22 or terminal.len != initial.len) return error.InvalidMemorySidecarCount;
    var file = try dir.createFile("cells.bin", .{ .exclusive = true });
    errdefer dir.deleteFile("cells.bin") catch {};
    defer file.close();
    var header: [16]u8 = undefined;
    @memcpy(header[0..8], MAGIC);
    std.mem.writeInt(u32, header[8..12], @intCast(initial.len), .little);
    std.mem.writeInt(u32, header[12..16], @intCast(terminal.len), .little);
    try file.writeAll(&header);
    var buffer: [WIDTH * BLOCK]u8 = undefined;
    for ([_][]const Cell{ initial, terminal }) |cells| {
        var at: usize = 0;
        while (at < cells.len) {
            const count: usize = @min(BLOCK, cells.len - at);
            for (cells[at..][0..count], 0..) |cell, i| {
                const b = buffer[WIDTH * i ..][0..WIDTH];
                std.mem.writeInt(u64, b[0..8], cell.address, .little);
                std.mem.writeInt(u64, b[8..16], cell.state.value, .little);
                std.mem.writeInt(u16, b[16..18], cell.state.epoch, .little);
                std.mem.writeInt(u32, b[18..22], cell.state.tick, .little);
                b[22] = cell.state.rights;
            }
            try file.writeAll(buffer[0 .. WIDTH * count]);
            at += count;
        }
    }
    try file.sync();
}
pub const Owned = struct {
    initial: []Cell,
    terminal: []Cell,
    pub fn deinit(self: Owned, a: std.mem.Allocator) void {
        a.free(self.initial);
        a.free(self.terminal);
    }
};
pub fn read(a: std.mem.Allocator, dir: std.fs.Dir, expected: u32) !Owned {
    if (expected > 1 << 22) return error.InvalidMemorySidecarCount;
    var file = try dir.openFile("cells.bin", .{});
    defer file.close();
    if (try file.getEndPos() != 16 + 2 * @as(u64, expected) * WIDTH) return error.InvalidMemorySidecarSize;
    var header: [16]u8 = undefined;
    if (try file.readAll(&header) != header.len or !std.mem.eql(u8, header[0..8], MAGIC) or std.mem.readInt(u32, header[8..12], .little) != expected or std.mem.readInt(u32, header[12..16], .little) != expected) return error.InvalidMemorySidecarHeader;
    const initial = try a.alloc(Cell, expected);
    errdefer a.free(initial);
    const terminal = try a.alloc(Cell, expected);
    errdefer a.free(terminal);
    var buffer: [WIDTH * BLOCK]u8 = undefined;
    for ([_][]Cell{ initial, terminal }) |cells| {
        var at: usize = 0;
        while (at < cells.len) {
            const count: usize = @min(BLOCK, cells.len - at);
            const bytes = buffer[0 .. WIDTH * count];
            if (try file.readAll(bytes) != bytes.len) return error.TruncatedMemorySidecar;
            for (cells[at..][0..count], 0..) |*cell, i| {
                const b = buffer[WIDTH * i ..][0..WIDTH];
                const tick = std.mem.readInt(u32, b[18..22], .little);
                if (tick >= 1 << 24 or b[22] > 3) return error.NoncanonicalMemorySidecar;
                cell.* = .{ .address = std.mem.readInt(u64, b[0..8], .little), .state = .{ .value = std.mem.readInt(u64, b[8..16], .little), .epoch = std.mem.readInt(u16, b[16..18], .little), .tick = @intCast(tick), .rights = @intCast(b[22]) } };
            }
            at += count;
        }
    }
    return .{ .initial = initial, .terminal = terminal };
}

test "public RAM sidecar streams full blocks without losing high limbs" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cells = try a.alloc(Cell, BLOCK + 2);
    defer a.free(cells);
    for (cells, 0..) |*cell, i| cell.* = .{ .address = 0xfedcba9800000000 + 8 * @as(u64, @intCast(i)), .state = .{ .value = 0x9876543200000000 + @as(u64, @intCast(i)), .epoch = 65535, .tick = 0xffffff, .rights = 3 } };
    try write(tmp.dir, cells, cells);
    const decoded = try read(a, tmp.dir, @intCast(cells.len));
    defer decoded.deinit(a);
    for (cells, decoded.initial, decoded.terminal) |want, x, y| {
        try std.testing.expectEqualDeep(want, x);
        try std.testing.expectEqualDeep(want, y);
    }
    try std.testing.expectError(error.PathAlreadyExists, write(tmp.dir, cells, cells));
    try std.testing.expectError(error.InvalidMemorySidecarSize, read(a, tmp.dir, @intCast(cells.len - 1)));
}
test "public RAM sidecar rejects noncanonical clock and rights" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cells = [_]Cell{.{ .address = 8, .state = .{ .value = 5, .rights = 3 } }};
    try write(tmp.dir, &cells, &cells);
    var file = try tmp.dir.openFile("cells.bin", .{ .mode = .read_write });
    defer file.close();
    try file.seekTo(16 + 22);
    try file.writeAll(&.{4});
    try std.testing.expectError(error.NoncanonicalMemorySidecar, read(a, tmp.dir, 1));
    try file.seekTo(16 + 22);
    try file.writeAll(&.{3});
    try file.seekTo(16 + 21);
    try file.writeAll(&.{1});
    try std.testing.expectError(error.NoncanonicalMemorySidecar, read(a, tmp.dir, 1));
}
fn oomRead(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    const decoded = try read(a, dir, 1);
    defer decoded.deinit(a);
}
test "public RAM sidecar read cleans every partial allocation failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cells = [_]Cell{.{ .address = 8, .state = .{ .value = 5, .rights = 3 } }};
    try write(tmp.dir, &cells, &cells);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, oomRead, .{tmp.dir});
}
