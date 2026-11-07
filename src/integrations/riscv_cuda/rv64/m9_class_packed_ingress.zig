//! M9 L1a packed class ingress, host side (STWO_RV64_M9_CLASS_PACKED_INGRESS=1).
//!
//! Instead of host-unpacking a node's class statics (FIXED forest columns,
//! assignment task records) and uploading the logical words, a node stages
//! the cache_pack `lz4_blocks` payloads as they are held in the class cache,
//! uploads them (~28x fewer bytes [M]) and enqueues
//! `stwo_rv64_m9_class_unpack_stream` (backends/cuda/native/rv64/
//! m9_class_unpack.cu), which writes the exact host-unpack words straight
//! into the consumer buffers (e.g. the FIXED coefficient buffer at its sorted
//! plan offsets, the node region's task section).
//!
//! This file has no dependency on the prover: `Packed` is any value with the
//! fields of circuit_cpu/om31/cache_pack.zig `Packed` (data, words, channels,
//! encoding, blocks{offset, bytes, raw}). Integration call sites are listed
//! in design/riscv-proving-stack/rv64-m9-packed-ingress.md.
const std = @import("std");

pub const flag = "STWO_RV64_M9_CLASS_PACKED_INGRESS";
pub fn enabled() bool {
    const value = std.posix.getenv(flag) orelse return false;
    return std.mem.eql(u8, value, "1");
}

pub const BLOCK_WORDS: usize = 16384;
/// ABI mirrors of m9_class_unpack.h (static_asserted there: 16 and 48 bytes).
pub const DeviceBlock = extern struct { offset: u64, bytes: u32, raw: u32 };
pub const DeviceJob = extern struct {
    data: u64,
    blocks: u64,
    output: u64,
    data_bytes: u64,
    words: u64,
    channels: u32,
    first_block: u32,
};
comptime {
    std.debug.assert(@sizeOf(DeviceBlock) == 16);
    std.debug.assert(@sizeOf(DeviceJob) == 48);
}
/// `stwo_rv64_m9_class_unpack_stream(stream, jobs, n_jobs, total_blocks, status)`.
pub const LaunchStream = *const fn (?*anyopaque, *const DeviceJob, u32, u32, *u32) callconv(.c) c_int;
pub const launch_symbol = "stwo_rv64_m9_class_unpack_stream";
pub const status_names = [_][]const u8{ "shape", "length", "lz4", "offset" };

pub const Error = error{ PackedIngressNeedsLz4Blocks, PackedIngressShape, PackedIngressTooManyBlocks, PackedIngressStagingTooSmall };

/// One decode target: a packed value and the device address of its output
/// (exactly `words` u32, 4-byte aligned; 16-byte alignment takes the vector
/// store path).
pub fn Target(comptime Packed: type) type {
    return struct { value: *const Packed, output: u64 };
}

/// Word layout of the single staging buffer a node uploads:
///   [jobs: n x 48 B][blocks: total x 16 B][payloads, each 16-byte aligned]
/// All three are written by `fill` into pinned memory; `stage_words` is the
/// arena allocation. The device output buffers are NOT part of it.
pub const Layout = struct {
    n_jobs: u32,
    total_blocks: u32,
    jobs_offset: usize = 0, // bytes
    blocks_offset: usize,
    data_offset: usize,
    stage_bytes: usize,
    logical_bytes: u64,
    pub fn stageWords(self: Layout) usize {
        return self.stage_bytes / 4;
    }
};

fn alignUp(n: usize, a: usize) usize {
    return (n + a - 1) / a * a;
}

/// Shape-checks every value (lz4_blocks, channel count, block count) the way
/// the device does and returns the staging layout. A value that is not
/// `lz4_blocks` (portable delta_varint/raw: non-Linux or no liblz4) returns
/// PackedIngressNeedsLz4Blocks: the caller keeps the host unpack path.
pub fn plan(comptime Packed: type, targets: []const Target(Packed)) Error!Layout {
    var blocks: usize = 0;
    var data: usize = 0;
    var logical: u64 = 0;
    for (targets) |t| {
        const v = t.value;
        if (v.encoding != .lz4_blocks) return error.PackedIngressNeedsLz4Blocks;
        const ch: usize = v.channels;
        if (ch == 0 or ch > 128 or !std.math.isPowerOfTwo(ch) or v.words % ch != 0 or v.words == 0) return error.PackedIngressShape;
        if (v.blocks.len != (v.words + BLOCK_WORDS - 1) / BLOCK_WORDS) return error.PackedIngressShape;
        if (t.output % 4 != 0 or t.output == 0) return error.PackedIngressShape;
        blocks += v.blocks.len;
        data = alignUp(data, 16) + v.data.len;
        logical += v.words * 4;
    }
    if (targets.len == 0 or blocks == 0 or blocks > std.math.maxInt(u32)) return error.PackedIngressTooManyBlocks;
    const blocks_offset = alignUp(targets.len * @sizeOf(DeviceJob), 16);
    const data_offset = alignUp(blocks_offset + blocks * @sizeOf(DeviceBlock), 16);
    return .{ .n_jobs = @intCast(targets.len), .total_blocks = @intCast(blocks), .blocks_offset = blocks_offset, .data_offset = data_offset, .stage_bytes = alignUp(data_offset + data, 16), .logical_bytes = logical };
}

/// Writes jobs, block tables and payloads into `pinned` (>= stage_bytes,
/// later uploaded verbatim to device address `stage_device`). Device
/// pointers inside the job table are absolute (stage_device + offsets).
pub fn fill(comptime Packed: type, layout: Layout, targets: []const Target(Packed), pinned: []u8, stage_device: u64) Error!void {
    if (pinned.len < layout.stage_bytes or stage_device % 16 != 0) return error.PackedIngressStagingTooSmall;
    @memset(pinned[0..layout.stage_bytes], 0);
    var block_at: usize = layout.blocks_offset;
    var data_at: usize = layout.data_offset;
    var first: u32 = 0;
    for (targets, 0..) |t, i| {
        const v = t.value;
        data_at = alignUp(data_at, 16);
        const job = DeviceJob{ .data = stage_device + data_at, .blocks = stage_device + block_at, .output = t.output, .data_bytes = v.data.len, .words = v.words, .channels = v.channels, .first_block = first };
        @memcpy(pinned[i * @sizeOf(DeviceJob) ..][0..@sizeOf(DeviceJob)], std.mem.asBytes(&job));
        for (v.blocks) |b| {
            const d = DeviceBlock{ .offset = b.offset, .bytes = b.bytes, .raw = @intFromBool(b.raw) };
            @memcpy(pinned[block_at..][0..@sizeOf(DeviceBlock)], std.mem.asBytes(&d));
            block_at += @sizeOf(DeviceBlock);
        }
        @memcpy(pinned[data_at..][0..v.data.len], v.data);
        data_at += v.data.len;
        first += @intCast(v.blocks.len);
    }
    std.debug.assert(first == layout.total_blocks);
}

/// Projection used by the report: bytes the node no longer moves over the
/// link and CPU-ns of host unpack it no longer spends.
pub fn savedLinkBytes(layout: Layout) u64 {
    return layout.logical_bytes -| layout.stage_bytes;
}

// ---------------------------------------------------------------------------
const Mock = struct {
    const Encoding = enum { raw, delta_varint, lz4_blocks };
    const Block = struct { offset: usize, bytes: u32, raw: bool };
    data: []const u8,
    words: usize,
    channels: u8,
    encoding: Encoding,
    blocks: []const Block = &.{},
};

test "packed ingress layout, job prefix and absolute device pointers" {
    const a = std.testing.allocator;
    const d0 = [_]u8{ 1, 2, 3, 4, 5 };
    const d1 = [_]u8{9} ** 37;
    const b0 = [_]Mock.Block{ .{ .offset = 0, .bytes = 2, .raw = false }, .{ .offset = 2, .bytes = 3, .raw = false } };
    const b1 = [_]Mock.Block{.{ .offset = 0, .bytes = 37, .raw = true }};
    const v0 = Mock{ .data = &d0, .words = BLOCK_WORDS + 8, .channels = 8, .encoding = .lz4_blocks, .blocks = &b0 };
    const v1 = Mock{ .data = &d1, .words = 1024, .channels = 1, .encoding = .lz4_blocks, .blocks = &b1 };
    const targets = [_]Target(Mock){ .{ .value = &v0, .output = 0x1000_0000 }, .{ .value = &v1, .output = 0x2000_0004 } };
    const layout = try plan(Mock, &targets);
    try std.testing.expectEqual(@as(u32, 2), layout.n_jobs);
    try std.testing.expectEqual(@as(u32, 3), layout.total_blocks);
    try std.testing.expectEqual(@as(usize, 96), layout.blocks_offset);
    try std.testing.expectEqual(@as(usize, 96 + 48), layout.data_offset);
    try std.testing.expectEqual(@as(usize, 144 + 16 + 37 + 11), layout.stage_bytes);
    const pinned = try a.alloc(u8, layout.stage_bytes);
    defer a.free(pinned);
    const base: u64 = 0x7000_0000;
    try fill(Mock, layout, &targets, pinned, base);
    const jobs = std.mem.bytesAsSlice(DeviceJob, pinned[0 .. 2 * @sizeOf(DeviceJob)]);
    try std.testing.expectEqual(base + 144, jobs[0].data);
    try std.testing.expectEqual(base + 96, jobs[0].blocks);
    try std.testing.expectEqual(@as(u32, 0), jobs[0].first_block);
    try std.testing.expectEqual(base + 160, jobs[1].data);
    try std.testing.expectEqual(base + 96 + 32, jobs[1].blocks);
    try std.testing.expectEqual(@as(u32, 2), jobs[1].first_block);
    try std.testing.expectEqual(@as(u64, 0x2000_0004), jobs[1].output);
    const blocks = std.mem.bytesAsSlice(DeviceBlock, pinned[96..144]);
    try std.testing.expectEqual(@as(u64, 2), blocks[1].offset);
    try std.testing.expectEqual(@as(u32, 1), blocks[2].raw);
    try std.testing.expectEqualSlices(u8, &d0, pinned[144..149]);
    try std.testing.expectEqualSlices(u8, &d1, pinned[160..197]);
    try std.testing.expectEqual(@as(u64, (BLOCK_WORDS + 8 + 1024) * 4 - layout.stage_bytes), savedLinkBytes(layout));
}

test "packed ingress refuses non-lz4 values and device-illegal shapes" {
    const d = [_]u8{0};
    const b = [_]Mock.Block{.{ .offset = 0, .bytes = 1, .raw = false }};
    const portable = Mock{ .data = &d, .words = 8, .channels = 8, .encoding = .delta_varint };
    try std.testing.expectError(error.PackedIngressNeedsLz4Blocks, plan(Mock, &.{.{ .value = &portable, .output = 64 }}));
    const odd = Mock{ .data = &d, .words = 9, .channels = 3, .encoding = .lz4_blocks, .blocks = &b };
    try std.testing.expectError(error.PackedIngressShape, plan(Mock, &.{.{ .value = &odd, .output = 64 }}));
    const missing = Mock{ .data = &d, .words = BLOCK_WORDS * 2, .channels = 1, .encoding = .lz4_blocks, .blocks = &b };
    try std.testing.expectError(error.PackedIngressShape, plan(Mock, &.{.{ .value = &missing, .output = 64 }}));
    const ok = Mock{ .data = &d, .words = 8, .channels = 8, .encoding = .lz4_blocks, .blocks = &b };
    try std.testing.expectError(error.PackedIngressShape, plan(Mock, &.{.{ .value = &ok, .output = 2 }}));
    try std.testing.expectError(error.PackedIngressTooManyBlocks, plan(Mock, &.{}));
}
