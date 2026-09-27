//! Commitment primitives only: no STARK, recursion, guest or device execution.
const std = @import("std");
const core = @import("stwo_core");
const batch = core.crypto.blake3_equal_messages4;
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M = core.fields.m31.M31;
const Compact = @import("vcs_lifted/compact_blake3_leaf.zig").Hasher;
const columns_mod = @import("vcs_lifted/columns.zig");
const Leaf = @import("vcs_lifted/leaves.zig").Operations(H);
const CompactLeaf = @import("vcs_lifted/leaves.zig").Operations(Compact);
const Prover = @import("vcs_lifted/prover.zig").MerkleProverLifted(H);

fn independent(prefix: []const u8, payload: []const u8) H.Hash {
    var state = std.crypto.hash.Blake3.init(.{});
    state.update(prefix);
    state.update(payload);
    var result: H.Hash = undefined;
    state.final(&result);
    return result;
}

test "BLAKE3 leaf batch full tree matches independent std across blocks chunks and prefixes" {
    const a = std.testing.allocator;
    const max_length = 131073;
    const storage = try a.alloc(u8, max_length * 4);
    defer a.free(storage);
    var bytes: [4][]u8 = undefined;
    for (&bytes, 0..) |*lane, index| lane.* = storage[index * max_length ..][0..max_length];
    var rng = std.Random.DefaultPrng.init(0x2026092615);
    for (bytes) |lane| rng.random().bytes(lane);
    var prefix: [1025]u8 = undefined;
    rng.random().bytes(&prefix);
    const lengths = [_]usize{ 0, 1, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 4095, 4096, 4097, 7168, 8192, 16384, 65536, 131073 };
    const prefix_lengths = [_]usize{ 0, 1, 26, 63, 64, 65, 1023, 1024, 1025 };
    for (prefix_lengths) |prefix_length| for (lengths) |length| {
        var messages: [4][]const u8 = undefined;
        for (&messages, bytes) |*message, lane| message.* = lane[0..length];
        const actual = try batch.hashPrefixed(prefix[0..prefix_length], &messages);
        for (actual, messages) |digest, message| {
            const expected = independent(prefix[0..prefix_length], message);
            try std.testing.expectEqualSlices(u8, &expected, &digest);
        }
    };
}

test "BLAKE3 leaf batch rejects mismatched extents before reader work" {
    const bytes = [_]u8{ 0, 1, 2, 3 };
    for (0..4) |lane| {
        var messages: [4][]const u8 = @splat(&bytes);
        messages[lane] = bytes[0..3];
        try std.testing.expectError(error.Blake3BatchLengthMismatch, batch.hashPrefixed("prefix", &messages));
    }
}

fn checkDirect(count: usize) !void {
    const a = std.testing.allocator;
    const values = try a.alloc([8]M, count);
    defer a.free(values);
    const columns = try a.alloc(columns_mod.ColumnRef, count);
    defer a.free(columns);
    for (values, columns, 0..) |*row_values, *column, i| {
        for (row_values, 0..) |*value, row| value.* = M.fromU64((i * 0x1020304 + row * 0x112233 + 0x7ffffffe) % 0x7fffffff);
        column.* = .{ .values = row_values, .log_size = 3, .original_index = i };
    }
    const payloads = try a.alloc(u8, count * 4 * 4);
    defer a.free(payloads);
    var messages: [4][]const u8 = undefined;
    const scalar_values = try a.alloc(M, count);
    defer a.free(scalar_values);
    for (0..4) |lane| {
        const payload = payloads[lane * count * 4 ..][0 .. count * 4];
        for (columns, 0..) |column, i| std.mem.writeInt(u32, payload[i * 4 ..][0..4], column.values[2 + lane].toU32(), .little);
        messages[lane] = payload;
    }
    const direct = H.hashDirectM31LeavesWithSeed4(H.leafSeed(), columns, 2);
    const packed_digests = H.hashPackedLeavesWithSeed4(H.leafSeed(), &messages);
    const compact = if (count <= Compact.max_columns) Compact.hashDirectM31LeavesWithSeed4(Compact.leafSeed(), columns, 2) else direct;
    for (0..4) |lane| {
        for (columns, scalar_values) |column, *value| value.* = column.values[2 + lane];
        const encoded = try (core.channel.blake3.Frame{ .leaf = scalar_values }).encode(a);
        defer a.free(encoded);
        const expected = independent(&.{}, encoded);
        var scalar = H.defaultWithInitialState();
        scalar.updateLeaf(scalar_values);
        try std.testing.expectEqualSlices(u8, &expected, &direct[lane]);
        try std.testing.expectEqualSlices(u8, &expected, &packed_digests[lane]);
        try std.testing.expectEqualSlices(u8, &expected, &compact[lane]);
        try std.testing.expectEqualSlices(u8, &expected, &scalar.finalize());
    }
    if (count > 0) {
        values[count / 2][4] = values[count / 2][4].add(M.one());
        const mutated = H.hashDirectM31LeavesWithSeed4(H.leafSeed(), columns, 2);
        for (0..4) |lane| try std.testing.expect(std.mem.eql(u8, &direct[lane], &mutated[lane]) == (lane != 2));
    }
}

test "BLAKE3 leaf batch direct and packed hooks preserve framing endianness and independent lanes" {
    for ([_]usize{ 0, 1, 4, 9, 10, 16, 24, 27, 54, 68, 92, 170, 249, 250, 255, 256, 257, 512, Compact.max_columns, 8192 }) |count| try checkDirect(count);
}

fn checkBuilder(mixed: bool, count: usize, log_size: u32) !void {
    const a = std.testing.allocator;
    const rows = @as(usize, 1) << @intCast(log_size);
    const backing = try a.alloc(M, count * rows);
    defer a.free(backing);
    const columns = try a.alloc(columns_mod.ColumnRef, count);
    defer a.free(columns);
    for (columns, 0..) |*column, i| {
        const col_log = if (mixed and i % 3 == 0) @max(@as(u32, 1), log_size - 1) else log_size;
        const values = backing[i * rows ..][0 .. @as(usize, 1) << @intCast(col_log)];
        for (values, 0..) |*value, row| value.* = M.fromU64(i * 0x12345 + row * 0x778899 + 1);
        column.* = .{ .values = values, .log_size = col_log, .original_index = i };
    }
    std.sort.heap(columns_mod.ColumnRef, columns, {}, struct {
        fn less(_: void, x: columns_mod.ColumnRef, y: columns_mod.ColumnRef) bool {
            return if (x.log_size == y.log_size) x.original_index < y.original_index else x.log_size < y.log_size;
        }
    }.less);
    const values = try a.alloc(M, count);
    defer a.free(values);
    for ([_]usize{ 1, 2, 3, 7, 64 }) |batch_size| {
        const actual = try Leaf.buildBatched(a, a, columns, batch_size);
        defer a.free(actual);
        const compact = try CompactLeaf.buildBatched(a, a, columns, batch_size);
        defer a.free(compact);
        const scalar = try Leaf.build(a, a, columns);
        defer a.free(scalar);
        for (actual, compact, scalar, 0..) |digest, compact_digest, scalar_digest, position| {
            for (columns, values) |column, *value| {
                const shift: std.math.Log2Int(usize) = @intCast(log_size - column.log_size + 1);
                const index = ((position >> shift) << 1) + (position & 1);
                value.* = column.values[index];
            }
            const encoded = try (core.channel.blake3.Frame{ .leaf = values }).encode(a);
            defer a.free(encoded);
            const expected = independent(&.{}, encoded);
            try std.testing.expectEqualSlices(u8, &expected, &digest);
            try std.testing.expectEqualSlices(u8, &expected, &compact_digest);
            try std.testing.expectEqualSlices(u8, &expected, &scalar_digest);
        }
    }
}

test "BLAKE3 leaf batch actual builder preserves mixed lifting scalar tails and batch geometry" {
    try checkBuilder(false, 4, 1);
    try checkBuilder(false, 54, 4);
    try checkBuilder(true, 92, 5);
    try checkBuilder(true, 257, 4);
}

test "BLAKE3 leaf batch empty actual builder retains literal frame" {
    const a = std.testing.allocator;
    const actual = try Leaf.buildBatched(a, a, &.{}, 3);
    defer a.free(actual);
    const encoded = try (core.channel.blake3.Frame{ .leaf = &.{} }).encode(a);
    defer a.free(encoded);
    const expected = independent(&.{}, encoded);
    try std.testing.expectEqual(@as(usize, 1), actual.len);
    try std.testing.expectEqualSlices(u8, &expected, &actual[0]);
}

test "BLAKE3 leaf batch lazy secure coordinates preserves offset and every scalar tail" {
    const Secure = @import("secure_column.zig").SecureColumnByCoords;
    const a = std.testing.allocator;
    var source = try Secure.zeros(a, 16);
    defer source.deinit(a);
    for (source.columns, 0..) |column, coord| for (column, 0..) |*value, row| {
        value.* = M.fromU64(coord * 0x112233 + row * 0x334455 + 1);
    };
    for ([_]usize{ 1, 2, 3, 4, 5, 6, 7, 8 }) |length| {
        var digests: [16]H.Hash = @splat(@splat(0xaa));
        Prover.testing.hashLazyLeafRange(&source, &digests, 3, 3 + length);
        for (digests, 0..) |digest, row| {
            if (row < 3 or row >= 3 + length) {
                try std.testing.expectEqualSlices(u8, &@as(H.Hash, @splat(0xaa)), &digest);
            } else {
                var values: [4]M = undefined;
                for (&values, source.columns) |*value, column| value.* = column[row];
                const encoded = try (core.channel.blake3.Frame{ .leaf = &values }).encode(a);
                defer a.free(encoded);
                try std.testing.expectEqualSlices(u8, &independent(&.{}, encoded), &digest);
            }
        }
    }
}

fn allocationFixture(a: std.mem.Allocator) !void {
    const short = [_]M{ M.one(), M.zero() };
    const long = [_]M{ M.fromCanonical(11), M.fromCanonical(22), M.fromCanonical(33), M.fromCanonical(44) };
    const columns = [_]columns_mod.ColumnRef{
        .{ .values = &short, .log_size = 1, .original_index = 0 },
        .{ .values = &long, .log_size = 2, .original_index = 1 },
    };
    const result = try Leaf.buildBatched(a, a, &columns, 3);
    defer a.free(result);
}

test "BLAKE3 leaf batch builder releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFixture, .{});
}

test "BLAKE3 leaf batch canonical commitment roots preserve every layer" {
    const a = std.testing.allocator;
    const CompactProver = @import("vcs_lifted/prover.zig").MerkleProverLifted(Compact);
    for ([_]usize{ 2, 32, 512 }) |rows| {
        const backing = try a.alloc(M, rows * 3);
        defer a.free(backing);
        const input = [_][]const M{ backing[0..rows], backing[rows .. rows + rows / 2], backing[rows * 2 ..][0..rows] };
        for (backing, 0..) |*value, i| value.* = M.fromU64(i * 0x123456 + 1);
        // All nonempty columns must have at least two rows.
        const admitted = if (rows == 2) input[2..3] else input[0..];
        const sorted = try columns_mod.sortByLogSizeAsc(a, admitted);
        defer a.free(sorted);
        var tree = try Prover.commit(a, admitted);
        defer tree.deinit(a);
        var compact = try CompactProver.commit(a, admitted);
        defer compact.deinit(a);
        const expected = try Leaf.build(a, a, sorted);
        defer a.free(expected);
        const values = try a.alloc(M, sorted.len);
        defer a.free(values);
        const max_log: u32 = @intCast(std.math.log2_int(usize, rows));
        for (expected, 0..) |*digest, position| {
            for (sorted, values) |column, *value| {
                const shift: std.math.Log2Int(usize) = @intCast(max_log - column.log_size + 1);
                value.* = column.values[((position >> shift) << 1) + (position & 1)];
            }
            const encoded = try (core.channel.blake3.Frame{ .leaf = values }).encode(a);
            defer a.free(encoded);
            const reference = independent(&.{}, encoded);
            try std.testing.expectEqualSlices(u8, &reference, digest);
        }
        var count = rows;
        var level: usize = max_log;
        while (true) {
            try std.testing.expectEqualSlices(H.Hash, expected[0..count], tree.layers[level]);
            try std.testing.expectEqualSlices(H.Hash, expected[0..count], compact.layers[level]);
            if (count == 1) break;
            for (0..count / 2) |i| {
                const encoded = try (core.channel.blake3.Frame{ .node = .{ .left = expected[2 * i], .right = expected[2 * i + 1] } }).encode(a);
                defer a.free(encoded);
                expected[i] = independent(&.{}, encoded);
            }
            count /= 2;
            level -= 1;
        }
    }
}

comptime {
    _ = Prover;
}

test "BLAKE3 bounded leaf builder diagnostic" {
    const benchmark = @import("blake3_leaf_batch_benchmark.zig");
    try std.testing.expectError(error.InvalidBlake3LeafBenchmarkGeometry, benchmark.run(std.testing.allocator, 0, 16384, false));
    for ([_]usize{ 4, 24, 54, 92, 170, 257 }) |count| {
        const report = try benchmark.run(std.heap.smp_allocator, count, 16384, false);
        for (report.samples, 0..) |sample, index| std.debug.print("BLAKE3_LEAF_BUILDER rows={d} columns={d} mixed={} sample={d} batch_first={} scalar_ns={d} batch4_ns={d}\n", .{ report.rows, report.columns, report.mixed, index, sample.batch_first, sample.scalar_ns, sample.batch4_ns });
    }
    const report = try benchmark.run(std.heap.smp_allocator, 92, 16384, true);
    for (report.samples, 0..) |sample, index| std.debug.print("BLAKE3_LEAF_BUILDER rows={d} columns={d} mixed={} sample={d} batch_first={} scalar_ns={d} batch4_ns={d}\n", .{ report.rows, report.columns, report.mixed, index, sample.batch_first, sample.scalar_ns, sample.batch4_ns });
}
