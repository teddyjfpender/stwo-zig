//! Research C ABI for source-pinned component measurements; not a prover API.
const std = @import("std");
const compression = @import("stwo_core").crypto.blake3_compression;
const witness = @import("recursion/air/blake3_compression_witness.zig");
const prime: u64 = 0xffffffff00000001;
fn canonical(x: u64) u64 {
    return if (x >= prime) x - prime else x;
}
export fn local_hash(input: [*]const u64, n: u32, output: [*]u64, mode: u32) void {
    var h = std.crypto.hash.Blake3.init(.{});
    var bytes: [512]u8 = undefined;
    var at: usize = 0;
    while (at < n) {
        const count: usize = @min(if (mode == 1) @as(usize, 7) else 64, n - at);
        for (0..count) |i| std.mem.writeInt(u64, bytes[i * 8 ..][0..8], canonical(input[at + i]), .little);
        h.update(bytes[0 .. count * 8]);
        at += count;
    }
    var out: [64]u8 = undefined;
    h.final(out[0..if (mode == 0) @as(usize, 32) else 64]);
    for (0..if (mode == 0) @as(usize, 4) else 8) |i| output[i] = canonical(std.mem.readInt(u64, out[i * 8 ..][0..8], .little));
}
export fn local_compress_case(cv: *const [8]u32, block: *const [16]u32, counter: u64, len: u8, flags: u8, out: *[16]u32) void {
    out.* = compression.compress(cv.*, block.*, counter, len, flags) catch unreachable;
}
export fn local_expand_case(cv: *const [8]u32, block: *const [16]u32, counter: u32, len: u32, flags: u32, out: *[16]u32, checksum: *u64) void {
    const prepared = witness.prepare(42, cv.*, block.*, counter, len, flags) catch unreachable;
    out.* = prepared.output;
    var sum: u64 = 0;
    for (prepared.g_rows) |row| for (row) |v| {
        sum +%= v.toU32();
    };
    for (prepared.xor_rows) |row| for (row) |v| {
        sum +%= v.toU32();
    };
    checksum.* = sum;
}
export fn local_batch(op: u32, words: u32, rounds: u32) u64 {
    const input = std.heap.page_allocator.alloc(u64, @max(words, 8)) catch unreachable;
    defer std.heap.page_allocator.free(input);
    for (input, 0..) |*v, j| v.* = @as(u64, @intCast(j)) * 0x1234567;
    var out: [8]u64 = undefined;
    var block: [16]u32 = undefined;
    for (&block, 0..) |*v, j| v.* = @as(u32, @intCast(j)) *% 0x1234567;
    var sum: u64 = 0;
    for (0..rounds) |i| {
        input[0] = i;
        block[0] = @intCast(i);
        if (op < 3) {
            local_hash(input.ptr, words, &out, op);
            for (out[0..if (op == 0) @as(usize, 4) else 8]) |v| sum +%= v;
        } else if (op == 3) {
            const result = compression.compress(compression.IV, block, 0, 64, 11) catch unreachable;
            for (result) |v| sum +%= v;
        } else {
            var result: [16]u32 = undefined;
            var checksum: u64 = undefined;
            local_expand_case(&compression.IV, &block, 0, 64, 11, &result, &checksum);
            sum +%= checksum;
        }
    }
    return sum;
}
