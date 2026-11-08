//! Bounded host leaf-builder diagnostic. No prover, transcript, device or guest.
//! Times allocation, column reads, lifting/staging and complete leaf digests.
//! Column construction, independent digest checks and upper Merkle layers are
//! outside the timer; logical buffers are not a process RSS measurement.
const std = @import("std");
const core = @import("stwo_core");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M = core.fields.m31.M31;
const Column = @import("vcs_lifted/columns.zig").ColumnRef;
const leaves = @import("vcs_lifted/leaves.zig");

// Same original streaming leaf state, with only the new four-leaf hooks hidden.
// This instantiates the unchanged generic scalar/batched builder as the baseline.
const Scalar = struct {
    inner: H,
    pub const Hash = H.Hash;
    pub const Children = H.Children;
    pub const NodeSeed = H.NodeSeed;
    pub const nodeSeed = H.nodeSeed;
    pub const hashChildren = H.hashChildren;
    pub const hashChildrenWithSeed = H.hashChildrenWithSeed;
    pub const hashChildrenWithSeed4 = H.hashChildrenWithSeed4;
    pub fn defaultWithInitialState() @This() {
        return .{ .inner = H.defaultWithInitialState() };
    }
    pub fn updateLeaf(self: *@This(), values: []const M) void {
        self.inner.updateLeaf(values);
    }
    pub fn updateLeafPackedBytes(self: *@This(), bytes: []const u8) void {
        self.inner.updateLeafPackedBytes(bytes);
    }
    pub fn finalize(self: *const @This()) Hash {
        return self.inner.finalize();
    }
};

pub const Sample = struct { batch_first: bool, scalar_ns: u64, batch4_ns: u64 };
pub const Report = struct { rows: usize, columns: usize, mixed: bool, samples: [4]Sample };
const Timed = struct { ns: u64, digests: []H.Hash };
fn timed(comptime Hasher: type, a: std.mem.Allocator, columns: []const Column) !Timed {
    var timer = try std.time.Timer.start();
    const digests = try leaves.Operations(Hasher).buildBatched(a, a, columns, 1024);
    std.mem.doNotOptimizeAway(digests.ptr);
    const elapsed = timer.read();
    return .{ .ns = elapsed, .digests = digests };
}
fn equal(a: []const H.Hash, b: []const H.Hash) !void {
    if (!std.mem.eql(H.Hash, a, b)) return error.Blake3LeafBenchmarkDigestMismatch;
}
fn independent(a: std.mem.Allocator, columns: []const Column, rows: usize) ![]H.Hash {
    const digests = try a.alloc(H.Hash, rows);
    errdefer a.free(digests);
    const bytes = try a.alloc(u8, columns.len * 4);
    defer a.free(bytes);
    const max_log: u32 = @intCast(std.math.log2_int(usize, rows));
    const framing = core.channel.blake3.framing;
    const prefix = framing.PROTOCOL_ID ++ [_]u8{@intFromEnum(framing.Domain.leaf)};
    for (digests, 0..) |*digest, position| {
        for (columns, 0..) |column, i| {
            const shift: std.math.Log2Int(usize) = @intCast(max_log - column.log_size + 1);
            const index = ((position >> shift) << 1) + (position & 1);
            std.mem.writeInt(u32, bytes[i * 4 ..][0..4], column.values[index].toU32(), .little);
        }
        var state = std.crypto.hash.Blake3.init(.{});
        state.update(prefix);
        state.update(bytes);
        state.final(digest);
    }
    return digests;
}

pub fn run(a: std.mem.Allocator, count: usize, rows: usize, mixed: bool) !Report {
    if (count == 0 or count > 1024 or rows < 4 or rows > 32768 or !std.math.isPowerOfTwo(rows)) return error.InvalidBlake3LeafBenchmarkGeometry;
    const backing = try a.alloc(M, count * rows);
    defer a.free(backing);
    const columns = try a.alloc(Column, count);
    defer a.free(columns);
    const max_log: u32 = @intCast(std.math.log2_int(usize, rows));
    for (columns, 0..) |*column, i| {
        const log_size = if (mixed and i % 3 == 0) max_log - 1 else max_log;
        const extent = @as(usize, 1) << @intCast(log_size);
        const values = backing[i * rows ..][0..extent];
        for (values, 0..) |*value, row| value.* = M.fromU64(i * 0x112233 + row * 0x010203 + 17);
        column.* = .{ .values = values, .log_size = log_size, .original_index = i };
    }
    std.sort.heap(Column, columns, {}, struct {
        fn less(_: void, x: Column, y: Column) bool {
            return if (x.log_size == y.log_size) x.original_index < y.original_index else x.log_size < y.log_size;
        }
    }.less);
    const expected = try independent(a, columns, rows);
    defer a.free(expected);
    const warm_scalar = try timed(Scalar, a, columns);
    defer a.free(warm_scalar.digests);
    const warm_batch = try timed(H, a, columns);
    defer a.free(warm_batch.digests);
    try equal(expected, warm_scalar.digests);
    try equal(expected, warm_batch.digests);
    var report = Report{ .rows = rows, .columns = count, .mixed = mixed, .samples = undefined };
    for (&report.samples, 0..) |*sample, index| {
        const batch_first = index == 1 or index == 2;
        const first = if (batch_first) try timed(H, a, columns) else try timed(Scalar, a, columns);
        defer a.free(first.digests);
        const second = if (batch_first) try timed(Scalar, a, columns) else try timed(H, a, columns);
        defer a.free(second.digests);
        try equal(expected, first.digests);
        try equal(expected, second.digests);
        sample.* = .{ .batch_first = batch_first, .scalar_ns = if (batch_first) second.ns else first.ns, .batch4_ns = if (batch_first) first.ns else second.ns };
    }
    return report;
}
