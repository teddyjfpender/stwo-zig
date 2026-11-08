//! Independent native arith256 witnesses: compact inputs and matrix digests.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = A.crypto.arith256.native;
const L = A.crypto.arith256.layout;
const a = std.heap.page_allocator;
fn fixture(dir: std.fs.Dir, id: usize, calls: usize, log: u32) !void {
    try L.validateGeometry(calls, 1, log);
    const rows = @as(usize, 1) << @intCast(log);
    const inputs = try a.alloc(N.Input, calls);
    defer a.free(inputs);
    var rng = std.Random.DefaultPrng.init(0x6172697468256 + id);
    const random = rng.random();
    for (inputs, 0..) |*input, i| {
        input.* = .{ .a = random.int(u256), .b = random.int(u256), .c = random.int(u256), .m = random.int(u256), .r_before = random.int(u256) };
        switch (i % 9) {
            0 => input.m = 0,
            1 => input.m = 1,
            2 => {
                input.a = std.math.maxInt(u256);
                input.b = std.math.maxInt(u256);
                input.c = std.math.maxInt(u256);
                input.m = std.math.maxInt(u256);
            },
            3 => input.m = @as(u256, 1) << 255,
            4 => {
                input.a = 0;
                input.b = 0;
                input.c = std.math.maxInt(u256);
                input.m = 2;
            },
            else => {},
        }
    }
    const counts = try A.crypto.arith256.trace.byteCounts(inputs, rows);
    const expected = try a.alloc(u32, L.MAIN * rows);
    defer a.free(expected);
    var row: N.Row = undefined;
    for (0..rows) |logical| {
        A.crypto.arith256.trace.nativeRow(&row, inputs, &counts, logical);
        const physical = A.memory.closed_ram.trace.physical(logical, log);
        for (row, 0..) |value, column| expected[column * rows + physical] = value;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(expected), &digest, .{});
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(a);
    for ([_]u32{ 0x52564152, 1, @intCast(id), log, @intCast(calls), L.MAIN }) |word| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, word, .little);
        try encoded.appendSlice(a, &b);
    }
    for (inputs) |input| for ([_]u256{ input.a, input.b, input.c, input.m, input.r_before }) |value| {
        var b: [32]u8 = undefined;
        std.mem.writeInt(u256, &b, value, .little);
        try encoded.appendSlice(a, &b);
    };
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = encoded.items });
    const metadata = try std.json.Stringify.valueAlloc(a, .{ .id = id, .calls = calls, .log = log, .main_columns = L.MAIN, .expected_words = expected.len, .expected_sha256 = std.fmt.bytesToHex(digest, .lower), .byte_counts = counts }, .{ .whitespace = .indent_2 });
    defer a.free(metadata);
    const json = try std.fmt.allocPrint(a, "case-{}.json", .{id});
    defer a.free(json);
    try dir.writeFile(.{ .sub_path = json, .data = metadata });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    for ([_]usize{ 0, 1, 3, 9, 257 }, [_]u32{ 8, 8, 8, 8, 10 }, 0..) |calls, log, id| try fixture(dir, id, calls, log);
}
