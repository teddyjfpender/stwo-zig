const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const compact = engine.vcs_lifted.compact_blake_state;
const B = core.crypto.blake2s_backend;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Column = struct { values: []const M, log_size: u32, original_index: usize };
fn runCase(comptime H: type, mode: B.BackendMode, workers: usize) !void {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const old_mode = B.getDefaultBackendMode();
    defer B.setDefaultBackendMode(old_mode);
    const seed = H.defaultWithInitialStateWithMode(mode);
    var array = try compact.Array(H).init(a, 2, seed);
    defer array.deinit();
    var raw = try a.alloc(H, 2);
    defer a.free(raw);
    @memset(raw, seed);
    var histories = std.ArrayList(Column).empty;
    defer histories.deinit(a);
    var backings = std.ArrayList([]M).empty;
    defer {
        for (backings.items) |v| a.free(v);
        backings.deinit(a);
    }
    var previous_log: u32 = 1;
    const logs = [_]u32{ 1, 3, 7, 14 };
    const widths = [_]usize{ 15, 1, 17, 65 };
    for (logs, widths, 0..) |log, width, stage| {
        const count = @as(usize, 1) << @intCast(log);
        if (log > previous_log) {
            const shift: std.math.Log2Int(usize) = @intCast(log - previous_log + 1);
            const next = try a.alloc(H, count);
            for (next, 0..) |*value, index| value.* = raw[((index >> shift) << 1) + (index & 1)];
            a.free(raw);
            raw = next;
            try array.expand(count, shift);
        }
        const data = try a.alloc(M, count * width);
        try backings.append(a, data);
        const columns = try a.alloc(Column, width);
        defer a.free(columns);
        for (columns, 0..) |*column, c| {
            const values = data[c * count ..][0..count];
            for (values, 0..) |*value, row| value.* = M.fromCanonical(@intCast((row * 17731 + c * 257 + stage * 991) % core.fields.m31.Modulus));
            column.* = .{ .values = values, .log_size = log, .original_index = c };
            for (raw, 0..) |*hasher, row| hasher.updateLeaf(values[row..][0..1]);
        }
        try histories.appendSlice(a, columns);
        // A changing process default must never change captured stream selection.
        B.setDefaultBackendMode(if (mode == .scalar) .simd else .scalar);
        // Column is layout-compatible with the engine reference without aliases.
        const refs = try a.alloc(engine.vcs_lifted.prover.MerkleProverLifted(H).ColumnRef, width);
        defer a.free(refs);
        for (refs, columns) |*ref, col| ref.* = .{ .values = col.values, .log_size = col.log_size, .original_index = col.original_index };
        try array.update(refs);
        try std.testing.expectEqual(mode, array.metadata.selection.requested);
        try std.testing.expectEqual(raw[0].inner.ctx.buf_len, array.metadata.buf_len);
        if (stage == 1) try std.testing.expectEqual(@as(usize, 64), array.metadata.buf_len);
        const hashes = try a.alloc(H.Hash, count);
        defer a.free(hashes);
        try array.finalizeInto(hashes);
        for (raw, hashes) |value, actual| {
            var hasher = value;
            try std.testing.expectEqualDeep(hasher.finalize(), actual);
        }
        for ([_]usize{ 0, 1, count / 2, count - 1 }) |row| {
            var oracle = std.crypto.hash.blake2.Blake2s256.init(.{});
            if (H.domainPrefixBytes() != 0) oracle.update(&core.vcs_lifted.blake2_merkle.LEAF_PREFIX);
            for (histories.items) |column| {
                const shift: std.math.Log2Int(usize) = @intCast(log - column.log_size + 1);
                const value = column.values[((row >> shift) << 1) + (row & 1)].v;
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, value, .little);
                oracle.update(&bytes);
            }
            var expected: [32]u8 = undefined;
            oracle.final(&expected);
            try std.testing.expectEqualDeep(expected, hashes[row]);
        }
        previous_log = log;
    }
}
test "vcs_lifted 96 byte native Blake leaves preserve full terminal block mixed heights chunks pools and captured mode" {
    try std.testing.expectEqual(@as(usize, 96), @sizeOf(compact.State));
    inline for (.{ core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher }) |H| {
        for ([_]B.BackendMode{ .scalar, .simd, .auto }) |mode| for ([_]usize{ 1, 4 }) |workers| try runCase(H, mode, workers);
    }
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    var array = try compact.Array(H).init(allocator, 2, H.defaultWithInitialStateWithMode(.scalar));
    defer array.deinit();
    try array.expand(32, 5);
    var output: [32]H.Hash = undefined;
    try array.finalizeInto(&output);
}
test "vcs_lifted 96 byte native Blake owners clean allocation failures and expansion is retryable" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
    const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    var failing = std.testing.FailingAllocator.init(a, .{});
    var array = try compact.Array(H).init(failing.allocator(), 2, H.defaultWithInitialStateWithMode(.scalar));
    defer array.deinit();
    const before = array.get(0);
    const ptr = array.states.ptr;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, array.expand(32, 5));
    try std.testing.expectEqual(ptr, array.states.ptr);
    try std.testing.expectEqualDeep(before, array.get(0));
    failing.fail_index = std.math.maxInt(usize);
    try array.expand(32, 5);
    try std.testing.expectEqual(@as(usize, 32), array.states.len);
}

test "vcs_lifted 96 byte split batches add no Blake compression compared with raw H authority" {
    inline for (.{ core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher }) |H| {
        const seed = H.defaultWithInitialStateWithMode(.scalar);
        var array = try compact.Array(H).init(a, 4, seed);
        defer array.deinit();
        var data: [65][4]M = undefined;
        var columns: [65]engine.vcs_lifted.prover.MerkleProverLifted(H).ColumnRef = undefined;
        for (&data, &columns, 0..) |*values, *column, c| {
            for (values, 0..) |*v, row| v.* = M.fromCanonical(@intCast(c * 31 + row * 19));
            column.* = .{ .values = values, .log_size = 2, .original_index = c };
        }
        var raw = [_]H{seed} ** 4;
        B.resetTestCompressionCounts();
        var expected: [4]H.Hash = undefined;
        for (&raw, &expected, 0..) |*hasher, *hash, row| {
            for (columns) |column| hasher.updateLeaf(column.values[row..][0..1]);
            hash.* = hasher.finalize();
        }
        const raw_counts = B.testCompressionCounts();
        B.resetTestCompressionCounts();
        var begin: usize = 0;
        for ([_]usize{ 1, 16, 17, 64, 65 }) |end| {
            try array.update(columns[begin..end]);
            begin = end;
        }
        var actual: [4]H.Hash = undefined;
        try array.finalizeInto(&actual);
        try std.testing.expectEqualDeep(expected, actual);
        try std.testing.expectEqualDeep(raw_counts, B.testCompressionCounts());
        try std.testing.expectEqual(@as(u64, if (H.domainPrefixBytes() == 0) 20 else 24), raw_counts.scalar);
    }
}

fn nativeTreeCase(allocator: std.mem.Allocator, comptime H: type, tail: bool) !void {
    const P = engine.vcs_lifted.prover.MerkleProverLifted(H);
    const widths = [_]usize{ 17, 33, 1, 17, 2 };
    const logs = [_]u32{ 1, 2, 4, 6, 10 };
    const total = 70;
    var columns: [total][]const M = undefined;
    var initialized: usize = 0;
    defer for (columns[0..initialized]) |values| allocator.free(values);
    for (logs, widths) |log, width| for (0..width) |_| {
        const values = try allocator.alloc(M, @as(usize, 1) << @intCast(log));
        for (values, 0..) |*value, row| value.* = M.fromCanonical(@intCast(initialized * 101 + row * 17));
        columns[initialized] = values;
        initialized += 1;
    };
    var oracle = try P.testing.commitWithWorkerOverride(allocator, &columns, 1);
    defer oracle.deinit(allocator);
    const sorted = try P.sortColumnsByLogSizeAsc(allocator, &columns);
    defer allocator.free(sorted);
    var stream = P.StreamingCommitter.initCompactBlake(allocator);
    var alive = true;
    defer if (alive) stream.deinit();
    const split: usize = if (tail) 50 else total;
    var offset: usize = 0;
    while (offset < split) {
        const end = @min(split, offset + 7);
        try stream.addColumns(sorted[offset..end]);
        offset = end;
    }
    try std.testing.expectEqual(@as(usize, 0), stream.leaf_hashers.len);
    try std.testing.expect(stream.native_states != null);
    var actual = if (tail) try stream.finalizeLiftedTail(sorted[split..]) else try stream.finalize();
    alive = false;
    defer actual.deinit(allocator);
    try std.testing.expectEqual(oracle.layers.len, actual.layers.len);
    for (oracle.layers, actual.layers) |expected, got| try std.testing.expectEqualSlices(H.Hash, expected, got);
}
test "vcs_lifted compact native constructor matches raw tree for incremental and mixed-height cached tail" {
    inline for (.{ core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher }) |H| {
        try nativeTreeCase(a, H, false);
        try nativeTreeCase(a, H, true);
    }
}
fn nativeTreeAllocation(allocator: std.mem.Allocator) !void {
    try nativeTreeCase(allocator, core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, true);
}
test "vcs_lifted compact native stream and cached-tail owners clean every allocation failure" {
    try std.testing.checkAllAllocationFailures(a, nativeTreeAllocation, .{});
}
