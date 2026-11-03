//! Independent native SHA witness digests, with compact inputs only on disk.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = A.crypto.sha256.native;
const L = A.crypto.sha256.layout;
const a = std.heap.page_allocator;
fn fixture(dir: std.fs.Dir, id: usize, calls: usize, log: u32) !void {
    try L.validateGeometry(calls, 1, log);
    const rows = @as(usize, 1) << @intCast(log);
    const inputs = try a.alloc(N.Input, calls);
    defer a.free(inputs);
    var rng = std.Random.DefaultPrng.init(0x736861256 + id);
    const random = rng.random();
    for (inputs) |*input| {
        for (&input.state) |*word| word.* = random.int(u32);
        random.bytes(&input.block);
    }
    const expected = try a.alloc(u32, L.MAIN * rows);
    defer a.free(expected);
    var padding: N.Row = undefined;
    _ = N.fill(&padding, N.PADDING);
    var row: N.Row = undefined;
    for (0..rows) |logical| {
        const values = if (logical < calls) blk: {
            _ = N.fill(&row, inputs[logical]);
            row[L.ACTIVE] = 1;
            break :blk &row;
        } else &padding;
        const physical = A.memory.closed_ram.trace.physical(logical, log);
        for (values, 0..) |value, column| expected[column * rows + physical] = value;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(expected), &digest, .{});
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(a);
    for ([_]u32{ 0x52565348, 1, @intCast(id), log, @intCast(calls), L.MAIN }) |word| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, word, .little);
        try encoded.appendSlice(a, &b);
    }
    for (inputs) |input| {
        for (input.state) |word| {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, word, .little);
            try encoded.appendSlice(a, &b);
        }
        try encoded.appendSlice(a, &input.block);
    }
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = encoded.items });
    const meta = try std.json.Stringify.valueAlloc(a, .{ .id = id, .calls = calls, .log = log, .main_columns = L.MAIN, .expected_words = expected.len, .expected_sha256 = std.fmt.bytesToHex(digest, .lower) }, .{ .whitespace = .indent_2 });
    defer a.free(meta);
    const json = try std.fmt.allocPrint(a, "case-{}.json", .{id});
    defer a.free(json);
    try dir.writeFile(.{ .sub_path = json, .data = meta });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    for ([_]usize{ 0, 1, 3, 33, 8193 }, [_]u32{ 5, 5, 5, 6, 14 }, 0..) |calls, log, id| try fixture(dir, id, calls, log);
}
