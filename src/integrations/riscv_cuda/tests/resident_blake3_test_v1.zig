//! Actual-device oracle; CPU work here is independent verification, never a
//! fallback inside the resident prover. Test inputs cover BLAKE3 chunk carries.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../../backends/cuda/abi/runtime.zig");
const K = @import("../../../backends/cuda/abi/stages/blake3.zig");
const check = @import("../../../backends/cuda/runtime/error.zig").check;
const M = core.fields.m31.M31;
const F = core.channel.blake3.Frame;
const Device = struct {
    handle: *anyopaque,
    stream: *anyopaque,
    pointers: [128][*]u32 = undefined,
    count: usize = 0,
    fn init() !Device {
        var h: ?*anyopaque = null;
        try check(R.stwo_exec_context_create_options(&.{ .device_ordinal = 0 }, &h));
        errdefer {
            if (h) |v| check(R.stwo_exec_context_destroy(v)) catch {};
        }
        var stream: ?*anyopaque = null;
        try check(R.stwo_exec_context_stream(h.?, &stream));
        return .{ .handle = h.?, .stream = stream.? };
    }
    fn clear(self: *Device) void {
        check(R.stwo_exec_context_sync(self.handle)) catch {};
        for (self.pointers[0..self.count]) |p| check(R.stwo_exec_context_free_u32(self.handle, p)) catch {};
        self.count = 0;
    }
    fn deinit(self: *Device) void {
        self.clear();
        check(R.stwo_exec_context_destroy(self.handle)) catch {};
    }
    fn alloc(self: *Device, comptime T: type, n: usize) ![]T {
        if (self.count == self.pointers.len) return error.TestDeviceLimit;
        var p: ?[*]u32 = null;
        try check(R.stwo_exec_context_alloc_u32(self.handle, n * @sizeOf(T) / 4, &p));
        self.pointers[self.count] = p.?;
        self.count += 1;
        return @as([*]T, @ptrCast(@alignCast(p.?)))[0..n];
    }
    fn upload(self: *Device, comptime T: type, v: []const T) ![]T {
        const out = try self.alloc(T, v.len);
        try check(R.stwo_exec_context_memcpy_h2d_async(self.handle, out.ptr, v.ptr, v.len * @sizeOf(T)));
        try check(R.stwo_exec_context_sync(self.handle));
        return out;
    }
    fn read(self: *Device, comptime T: type, out: []T, device: []const T) !void {
        try std.testing.expectEqual(out.len, device.len);
        try check(R.stwo_exec_context_memcpy_d2h_async(self.handle, out.ptr, device.ptr, out.len * @sizeOf(T)));
        try check(R.stwo_exec_context_sync(self.handle));
    }
};
fn digest(hash: K.Hash) [32]u8 {
    var out: [32]u8 = undefined;
    for (hash.words, 0..) |word, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .little);
    return out;
}
fn equal(expected: [32]u8, actual: K.Hash) !void {
    try std.testing.expectEqualSlices(u8, &expected, &digest(actual));
}
fn leaf(values: []const u32) [32]u8 {
    var h = core.vcs_lifted.blake3_merkle.MerkleHasher.defaultWithInitialState();
    for (values) |v| {
        const m = M.fromCanonical(v);
        h.updateLeaf(&.{m});
    }
    return h.finalize();
}
pub fn run() !void {
    const a = std.testing.allocator;
    var d = try Device.init();
    defer d.deinit();
    var rng = std.Random.DefaultPrng.init(0xb3);
    // Both compression and1024byte chunk boundaries after the28byte domain prefix.
    for ([_]usize{ 1, 8, 9, 10, 16, 17, 248, 249, 250, 255, 256, 257, 505, 506, 1017, 4097, 8192 }) |width| {
        defer d.clear();
        const rows = 8;
        const input = try a.alloc(u32, rows * width);
        defer a.free(input);
        for (input) |*v| v.* = rng.random().int(u32) % 0x7fffffff;
        const source = try d.upload(u32, input);
        const output = try d.alloc(K.Hash, rows);
        try check(K.stwo_blake3_contiguous_leaf_on(rows, source.ptr, rows, source.len, output.ptr, d.stream));
        var actual: [rows]K.Hash = undefined;
        try d.read(K.Hash, &actual, output);
        const row = try a.alloc(u32, width);
        defer a.free(row);
        for (actual, 0..) |hash, r| {
            for (row, 0..) |*v, c| v.* = input[c * rows + r];
            try equal(leaf(row), hash);
        }
        const state = try d.alloc(K.State, rows);
        try check(K.stwo_blake3_progressive_init_on(rows, state.ptr, d.stream));
        const first = @max(@as(usize, 1), width / 2);
        try check(K.stwo_blake3_progressive_absorb_lifted_on(rows, rows, 0, source.ptr, rows, first * rows, state.ptr, d.stream));
        if (first < width) try check(K.stwo_blake3_progressive_absorb_lifted_on(rows, rows, @intCast(first), source.ptr + first * rows, rows, (width - first) * rows, state.ptr, d.stream));
        const p = try d.alloc(K.Hash, rows);
        try check(K.stwo_blake3_progressive_finalize_on(rows, @intCast(width), state.ptr, p.ptr, d.stream));
        var repeated: [rows]K.Hash = undefined;
        try d.read(K.Hash, &repeated, p);
        try std.testing.expectEqualDeep(actual, repeated);
        var current = output;
        var host = actual;
        var size: usize = rows;
        while (size > 1) {
            size /= 2;
            const next = try d.alloc(K.Hash, size);
            try check(K.stwo_blake3_layer_on(current.ptr, @intCast(size), next.ptr, d.stream));
            var received: [rows]K.Hash = undefined;
            try d.read(K.Hash, received[0..size], next);
            for (0..size) |i| {
                const want = (F{ .node = .{ .left = digest(host[2 * i]), .right = digest(host[2 * i + 1]) } }).hash();
                try equal(want, received[i]);
            }
            host = received;
            current = next;
        }
        try std.testing.expect(K.stwo_blake3_contiguous_leaf_on(rows, source.ptr, rows - 1, source.len, output.ptr, d.stream) != 0);
    }
    // True mixed-height lifting, canonical column order, progressive prefix reuse.
    {
        defer d.clear();
        const x = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
        const y = [_]u32{ 11, 12, 13, 14 };
        const dx = try d.upload(u32, &x);
        const dy = try d.upload(u32, &y);
        const out = try d.alloc(K.Hash, 8);
        const segments = [_]K.MixedSegment{ .{ .columns = dx.ptr, .stride_words = 8, .capacity_words = 8, .source_size = 8 }, .{ .columns = dy.ptr, .stride_words = 4, .capacity_words = 4, .source_size = 4 } };
        try check(K.stwo_blake3_mixed_leaf_on(8, 2, &segments, out.ptr, d.stream));
        var got: [8]K.Hash = undefined;
        try d.read(K.Hash, &got, out);
        for (0..8) |i| try equal(leaf(&.{ x[i], y[((i >> 2) << 1) | (i & 1)] }), got[i]);
        const prefix = try d.alloc(K.State, 8);
        try check(K.stwo_blake3_mixed_seeded_on(8, 1, &segments, 0, 0, null, prefix.ptr, null, d.stream));
        const second = try d.alloc(K.Hash, 8);
        try check(K.stwo_blake3_mixed_seeded_on(8, 1, segments[1..].ptr, 1, 8, prefix.ptr, null, second.ptr, d.stream));
        var again: [8]K.Hash = undefined;
        try d.read(K.Hash, &again, second);
        try std.testing.expectEqualDeep(got, again);
    }
    // Original FRI leaf order is row-major QM31 coordinates, at fold logs0/2.
    {
        defer d.clear();
        var coords: [32]u32 = undefined;
        for (&coords, 0..) |*v, i| v.* = @intCast(i + 100);
        const source = try d.upload(u32, &coords);
        for ([_]u32{ 0, 2 }) |fold| {
            const rows: usize = @as(usize, 1) << @intCast(fold);
            const out = try d.alloc(K.Hash, 8 / rows);
            try check(K.stwo_blake3_fri_leaf_on(8, source.ptr, 8, 32, fold, out.ptr, d.stream));
            var actual: [8]K.Hash = undefined;
            try d.read(K.Hash, actual[0..out.len], out);
            for (actual[0..out.len], 0..) |hash, i| {
                var words: [16]u32 = undefined;
                for (0..rows) |r| for (0..4) |c| {
                    words[4 * r + c] = coords[c * 8 + i * rows + r];
                };
                try equal(leaf(words[0 .. rows * 4]), hash);
            }
        }
    }
    // Resident channel: no state download is needed between operations.
    {
        defer d.clear();
        const ch = try d.alloc(K.Channel, 1);
        const buffer = try d.alloc(u32, 64);
        try check(K.stwo_blake3_channel_on(&ch[0], null, 0, 0, 0, 0, d.stream));
        var cpu = core.channel.blake3.Channel{};
        var observed: [1]K.Channel = undefined;
        try d.read(K.Channel, &observed, ch);
        try std.testing.expectEqualSlices(u8, &cpu.digestBytes(), std.mem.asBytes(&observed[0].digest));
        const values = [_]u32{ 0, 1, 0x7ffffffe, 17, 99, 42, 100, 222 };
        const data = try d.upload(u32, &values);
        try check(K.stwo_blake3_channel_on(&ch[0], data.ptr, data.len, @intCast(data.len), 1, 0, d.stream));
        cpu.mixU32s(&values);
        const root = (F{ .leaf = &.{M.fromCanonical(9)} }).hash();
        const root_words: [8]u32 = @bitCast(root);
        const dr = try d.upload(u32, &root_words);
        try check(K.stwo_blake3_channel_on(&ch[0], dr.ptr, 8, 8, 4, 0, d.stream));
        cpu.mixRoot(root);
        const integer = [_]u32{ 0x12345678, 0x9abcdef0 };
        const di = try d.upload(u32, &integer);
        try check(K.stwo_blake3_channel_on(&ch[0], di.ptr, 2, 2, 3, 0, d.stream));
        cpu.mixU64(0x9abcdef012345678);
        const felt = core.fields.qm31.QM31.fromM31Array(.{ M.fromCanonical(7), M.fromCanonical(9), M.fromCanonical(11), M.fromCanonical(13) });
        const felt_words = [_]u32{ 7, 9, 11, 13 };
        const df = try d.upload(u32, &felt_words);
        try check(K.stwo_blake3_channel_on(&ch[0], df.ptr, 4, 4, 2, 0, d.stream));
        cpu.mixFelts(&.{felt});
        try check(K.stwo_blake3_channel_on(&ch[0], buffer.ptr, buffer.len, 3, 5, 1024, d.stream));
        const expected = try cpu.drawSecureFelts(a, 3);
        defer a.free(expected);
        var result: [12]u32 = undefined;
        try d.read(u32, &result, buffer[0..12]);
        for (expected, 0..) |q, i| for (q.toM31Array(), 0..) |v, j| try std.testing.expectEqual(v.v, result[4 * i + j]);
        try check(K.stwo_blake3_channel_on(&ch[0], buffer.ptr, buffer.len, 1, 9, 1, d.stream));
        var raw: [8]u32 = undefined;
        try d.read(u32, &raw, buffer[0..8]);
        try std.testing.expectEqualDeep(cpu.drawU32s(), raw);
        try d.read(K.Channel, &observed, ch);
        try std.testing.expectEqual(cpu.n_draws, @as(u64, observed[0].counter[0]) | (@as(u64, observed[0].counter[1]) << 32));
        try std.testing.expectEqual(@as(u32, 0), observed[0].error_code);
        const nonce = try d.alloc(u64, 1);
        const want = cpu.grind(12);
        try std.testing.expect(want < 1 << 20);
        try check(K.stwo_blake3_pow_range_on(&ch[0], 12, 0, 1 << 20, &nonce[0], d.stream));
        var actual: [1]u64 = undefined;
        try d.read(u64, &actual, nonce);
        try std.testing.expectEqual(want, actual[0]);
        // Search and absorb entirely on device, then derive exact raw queries.
        try check(K.stwo_blake3_grind_on(&ch[0], 12, 1 << 24, 128, &nonce[0], d.stream));
        cpu.mixU64(want);
        try d.read(u64, &actual, nonce);
        try std.testing.expectEqual(want, actual[0]);
        const queries = try d.alloc(u32, 70);
        try check(K.stwo_blake3_query_on(&ch[0], 21, 70, queries.ptr, queries.len, d.stream));
        const expected_queries = try core.queries.drawQueries(&cpu, a, 21, 70);
        defer a.free(expected_queries);
        var actual_queries: [70]u32 = undefined;
        try d.read(u32, &actual_queries, queries);
        for (expected_queries, actual_queries) |expected_query, actual_query| try std.testing.expectEqual(expected_query, @as(usize, actual_query));
        try d.read(K.Channel, &observed, ch);
        try std.testing.expectEqual(cpu.n_draws, @as(u64, observed[0].counter[0]) | (@as(u64, observed[0].counter[1]) << 32));
        const verdict = try d.upload(u32, &.{0});
        try check(K.stwo_blake3_channel_verdict_on(ch.ptr, 1, &verdict[0], d.stream));
        var verdict_value: [1]u32 = undefined;
        try d.read(u32, &verdict_value, verdict);
        try std.testing.expectEqual(@as(u32, 0), verdict_value[0]);
        observed[0].counter = @splat(std.math.maxInt(u32));
        const overflow = try d.upload(K.Channel, &observed);
        try check(K.stwo_blake3_query_on(&overflow[0], 21, 1, queries.ptr, queries.len, d.stream));
        try check(K.stwo_blake3_channel_verdict_on(overflow.ptr, 1, &verdict[0], d.stream));
        try d.read(u32, &verdict_value, verdict);
        try std.testing.expectEqual(@as(u32, 1), verdict_value[0]);
        try std.testing.expect(K.stwo_blake3_channel_on(&ch[0], buffer.ptr, buffer.len, 1, 5, 0, d.stream) != 0);
    }
    std.debug.print("resident_blake3 canonical_cpu_oracle=passed domains=leaf,node,words,felts,integer,root,draw,pow numeric_cpu_fallback=false\n", .{});
}
