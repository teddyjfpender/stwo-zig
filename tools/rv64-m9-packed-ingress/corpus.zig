//! M9 L1a corpus tool. Packs u32 tables with the production producer-cache
//! codec (src/integrations/circuit_cpu/om31/cache_pack.zig, liblz4 on Linux),
//! verifies and times the HOST unpack, and writes a container the CUDA parity
//! bench (bench.cu) decodes on the device and compares word-for-word.
//!
//!   corpus synth <out.m9pk> <scale>          production-shaped synthetic class
//!   corpus shapes <out.m9pk>                  channel/partial-block/raw edge cases
//!   corpus raw <out.m9pk> <ch>:<file.u32>... real dumped tables (one value each)
//!
//! Container (little endian): "M9PKCLS1", u32 n_values, then per value:
//!   u32 tag(0 fixed column, 1 tasks), u32 channels, u64 words, u32 encoding
//!   (0 raw, 1 delta_varint, 2 lz4_blocks), u32 n_blocks, u64 data_bytes,
//!   n_blocks x {u64 offset, u32 bytes, u32 raw}, data, words x u32 expected
//!   (= cache_pack host unpack output, itself checked equal to the source).
const std = @import("std");
const Pack = @import("cache_pack");

const Value = struct { tag: u32, channels: u8, words: []u32 };

fn writeValue(w: anytype, a: std.mem.Allocator, v: Value, stats: *Stats) !void {
    var timer = try std.time.Timer.start();
    var encoded = try Pack.pack(a, v.words, v.channels);
    defer encoded.deinit(a);
    const pack_ns = timer.lap();
    const out = try a.alloc(u32, v.words.len);
    defer a.free(out);
    timer.reset();
    try encoded.unpack(out); // single thread, the per-shard unit of cache_unpack
    const unpack_ns = timer.read();
    if (!std.mem.eql(u32, out, v.words)) return error.HostUnpackMismatch;
    try w.writeInt(u32, v.tag, .little);
    try w.writeInt(u32, v.channels, .little);
    try w.writeInt(u64, v.words.len, .little);
    try w.writeInt(u32, @intFromEnum(encoded.encoding), .little);
    try w.writeInt(u32, @intCast(encoded.blocks.len), .little);
    try w.writeInt(u64, encoded.data.len, .little);
    for (encoded.blocks) |b| {
        try w.writeInt(u64, b.offset, .little);
        try w.writeInt(u32, b.bytes, .little);
        try w.writeInt(u32, @intFromBool(b.raw), .little);
    }
    try w.writeAll(encoded.data);
    try w.writeAll(std.mem.sliceAsBytes(out));
    stats.logical += v.words.len * 4;
    stats.physical += encoded.heldBytes();
    stats.unpack_ns += unpack_ns;
    stats.pack_ns += pack_ns;
    stats.values += 1;
    if (encoded.encoding != .lz4_blocks) stats.not_lz4 += 1;
    var raw_blocks: usize = 0;
    for (encoded.blocks) |b| raw_blocks += @intFromBool(b.raw);
    stats.raw_blocks += raw_blocks;
    stats.blocks += encoded.blocks.len;
    if (v.tag == 1) {
        stats.task_logical += v.words.len * 4;
        stats.task_physical += encoded.heldBytes();
    }
}
const Stats = struct { values: usize = 0, logical: usize = 0, physical: usize = 0, task_logical: usize = 0, task_physical: usize = 0, unpack_ns: u64 = 0, pack_ns: u64 = 0, blocks: usize = 0, raw_blocks: usize = 0, not_lz4: usize = 0 };

/// Production-shaped synthetic leaf class. Shapes follow the measured 24628607
/// leaf classes (GPU_OUTER_PP_PACK / GPU_OUTER_PLAN_PACK adopt lines): FIXED
/// ~0.50 GB at ~42x, tasks ~0.43 GB (8-word records) at ~20x. Column content
/// mimics preprocessed circuit columns: wire-address progressions with jumps,
/// small multiplicities, selector runs and zero padding to a power of two.
fn synth(a: std.mem.Allocator, scale: usize, list: *std.ArrayListUnmanaged(Value)) !void {
    var prng = std.Random.DefaultPrng.init(0x6d39_7061_636b);
    const r = prng.random();
    const n_cols: usize = 30;
    const rows: usize = (@as(usize, 1) << 22) / scale; // 30 x 2^22 x 4 B = 0.50 GB
    for (0..n_cols) |col| {
        const words = try a.alloc(u32, rows);
        const live = rows - rows / 5; // padded tail
        var x: u32 = r.int(u32) & 0x7fffff;
        for (words, 0..) |*w, i| {
            if (i >= live) {
                w.* = 0;
                continue;
            }
            w.* = switch (col % 6) {
                0 => @intCast(i), // sequence / row index
                1 => blk: { // wire progression with occasional jumps
                    if (r.uintLessThan(u32, 64) == 0) x +%= r.uintLessThan(u32, 1 << 16);
                    x +%= 3;
                    break :blk x & 0x7fffffff;
                },
                2 => if ((i / 4096) % 3 == 0) 1 else 0, // selector runs
                3 => if (r.uintLessThan(u32, 48) == 0) r.uintLessThan(u32, 4) else 0, // multiplicity
                4 => @intCast((i * 7) & 0xffff), // periodic table column
                else => blk: {
                    if (r.uintLessThan(u32, 96) == 0) x = r.int(u32) & 0x7fffffff;
                    x +%= 1;
                    break :blk x & 0x7fffffff;
                },
            };
        }
        try list.append(a, .{ .tag = 0, .channels = 1, .words = words });
    }
    // Tasks: {kind, out, args[6]}; out sequential, args reference recent vars.
    const n_tasks: usize = (13_400_000) / scale; // ~0.43 GB
    const tasks = try a.alloc(u32, n_tasks * 8);
    var out: u32 = 1 << 20;
    var kind: u32 = 0;
    for (0..n_tasks) |i| {
        if (r.uintLessThan(u32, 256) == 0) kind = r.uintLessThan(u32, 16);
        out += 1;
        const rec = tasks[i * 8 ..][0..8];
        rec[0] = kind;
        rec[1] = out;
        const arity: usize = if (kind < 4) 2 else if (kind < 8) 3 else if (kind == 12 or kind == 13) 2 else 1;
        for (0..6) |j| rec[2 + j] = if (j < arity) out - 1 - (if (r.uintLessThan(u32, 24) == 0) r.uintLessThan(u32, 4096) else @as(u32, @intCast(j))) else 0;
    }
    try list.append(a, .{ .tag = 1, .channels = 8, .words = tasks });
}

/// Edge shapes: every legal channel count, partial last blocks, incompressible
/// (raw-block) and highly repetitive (overlapping-match) payloads.
fn shapes(a: std.mem.Allocator, list: *std.ArrayListUnmanaged(Value)) !void {
    var prng = std.Random.DefaultPrng.init(0x5348_4150_4553);
    const r = prng.random();
    for ([_]u8{ 1, 2, 4, 8, 16, 32, 64, 128 }) |channels| {
        for ([_]usize{ 1, 3 }) |full| for ([_]usize{ 0, 1, 7 }) |extra_rows| for (0..3) |content| {
            const words = try a.alloc(u32, full * Pack.BLOCK_WORDS + extra_rows * channels);
            for (words, 0..) |*w, i| w.* = switch (content) {
                0 => r.int(u32), // incompressible -> raw blocks
                1 => @intCast((i / channels) * 5 + i % channels), // long periodic matches
                else => if (r.uintLessThan(u32, 8) == 0) r.int(u32) else @intCast(i / 3), // mixed literals/matches
            };
            try list.append(a, .{ .tag = 2, .channels = channels, .words = words });
        };
    }
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(gpa.allocator());
    defer std.process.argsFree(gpa.allocator(), args);
    if (args.len < 3) return error.Usage;
    var list: std.ArrayListUnmanaged(Value) = .empty;
    defer {
        for (list.items) |v| a.free(v.words);
        list.deinit(a);
    }
    if (std.mem.eql(u8, args[1], "synth")) {
        try synth(a, if (args.len > 3) try std.fmt.parseUnsigned(usize, args[3], 10) else 1, &list);
    } else if (std.mem.eql(u8, args[1], "shapes")) {
        try shapes(a, &list);
    } else if (std.mem.eql(u8, args[1], "raw")) {
        for (args[3..]) |spec| {
            const colon = std.mem.indexOfScalar(u8, spec, ':') orelse return error.Usage;
            const channels = try std.fmt.parseUnsigned(u8, spec[0..colon], 10);
            const bytes = try std.fs.cwd().readFileAlloc(a, spec[colon + 1 ..], 1 << 34);
            defer a.free(bytes);
            if (bytes.len % 4 != 0 or bytes.len == 0) return error.RawLength;
            const words = try a.alloc(u32, bytes.len / 4);
            @memcpy(std.mem.sliceAsBytes(words), bytes);
            try list.append(a, .{ .tag = if (channels == 8) 1 else 0, .channels = channels, .words = words });
        }
    } else return error.Usage;
    const file = try std.fs.cwd().createFile(args[2], .{});
    defer file.close();
    var buffer: [1 << 16]u8 = undefined;
    var fw = file.writer(&buffer);
    const w = &fw.interface;
    try w.writeAll("M9PKCLS1");
    try w.writeInt(u32, @intCast(list.items.len), .little);
    var stats: Stats = .{};
    for (list.items) |v| try writeValue(w, a, v, &stats);
    try w.flush();
    std.debug.print(
        "M9_CORPUS values={} logical_bytes={} physical_bytes={} ratio={d:.1} task_logical={} task_physical={} blocks={} raw_blocks={} non_lz4_values={} host_unpack_1t_ns={} host_unpack_1t_GBps={d:.2} pack_ns={}\n",
        .{ stats.values, stats.logical, stats.physical, @as(f64, @floatFromInt(stats.logical)) / @as(f64, @floatFromInt(stats.physical)), stats.task_logical, stats.task_physical, stats.blocks, stats.raw_blocks, stats.not_lz4, stats.unpack_ns, @as(f64, @floatFromInt(stats.logical)) / @as(f64, @floatFromInt(stats.unpack_ns)), stats.pack_ns },
    );
}
