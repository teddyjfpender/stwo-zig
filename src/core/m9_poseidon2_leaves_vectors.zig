//! Golden-vector emitter for the M9 Poseidon2 mixed-leaf CUDA parity gate.
//!   zig run -OReleaseFast src/core/m9_poseidon2_leaves_vectors.zig -- OUT.txt
//! Columns are never shipped: both sides regenerate them with
//! poseidon2_m31_mixed_leaf.columnWord(case_seed, column_id, source_row).
//! Segments sharing (source_log, col_base, n_columns) alias one physical slab
//! on the GPU (this keeps 2^24-row x 200-column cases inside a 2 GB budget).
//! Text format (one record per line, decimal u32):
//!   CASE name kind(D|C) case_seed log_size n_segments split n_rows n_prefix_rows
//!   SEG source_log n_columns col_base
//!   R row d0..d8            expected leaf digest (full chain)
//!   P row s0..s23           expected prefix state of segments[0..split]
//!   END
const std = @import("std");
const X = @import("vcs_lifted/poseidon2_m31_mixed_leaf.zig");

const Seg = struct { log: u5, width: u32, base: u32 };
const Case = struct { name: []const u8, kind: u8, seed: u64, segs: []const Seg, split: usize = 0 };

const Slabs = std.AutoHashMap(u128, []u32);

fn slabFor(a: std.mem.Allocator, slabs: *Slabs, seed: u64, seg: Seg) ![]u32 {
    const key: u128 = (@as(u128, seed) << 64) | (@as(u128, seg.log) << 56) | (@as(u128, seg.base) << 24) | seg.width;
    if (slabs.get(key)) |s| return s;
    const rows = @as(usize, 1) << seg.log;
    _ = a;
    const data = try std.heap.page_allocator.alloc(u32, rows * seg.width);
    for (0..seg.width) |c| for (0..rows) |r| {
        data[c * rows + r] = X.columnWord(seed, seg.base + c, r);
    };
    try slabs.put(key, data);
    return data;
}

fn sampleRows(a: std.mem.Allocator, rng: std.Random, log: u5, budget: usize) ![]usize {
    const rows = @as(usize, 1) << log;
    if (rows <= budget) {
        const out = try a.alloc(usize, rows);
        for (out, 0..) |*x, i| x.* = i;
        return out;
    }
    const out = try a.alloc(usize, budget);
    for (out, 0..) |*x, i| x.* = if (i < 16) i else if (i < 32) rows - 1 - (i - 16) else rng.uintLessThan(usize, rows);
    return out;
}

fn emit(a: std.mem.Allocator, w: anytype, slabs: *Slabs, rng: std.Random, case: Case) !void {
    var segments = try a.alloc(X.Segment, case.segs.len);
    for (case.segs, segments) |seg, *out| {
        const data = try slabFor(a, slabs, case.seed, seg);
        out.* = .{ .columns = data, .stride_words = @as(usize, 1) << seg.log, .n_columns = seg.width, .source_log_size = seg.log };
    }
    const log_size = case.segs[case.segs.len - 1].log;
    const rows = try sampleRows(a, rng, log_size, 1024);
    const digests = try a.alloc([X.DIGEST_WORDS]u32, rows.len);
    try X.hashRows(log_size, segments, 0, null, 0, rows, digests);
    var prefix_rows: []usize = &.{};
    var prefixes: [][X.STATE_WORDS]u32 = &.{};
    if (case.kind == 'C') {
        const seed_log = case.segs[case.split - 1].log;
        prefix_rows = try sampleRows(a, rng, seed_log, 256);
        prefixes = try a.alloc([X.STATE_WORDS]u32, prefix_rows.len);
        try X.prefixRows(seed_log, segments[0..case.split], 0, null, 0, prefix_rows, prefixes);
        // Cross-check the chain on the CPU before emitting.
        const seed_rows = @as(usize, 1) << seed_log;
        const all = try a.alloc(usize, seed_rows);
        for (all, 0..) |*x, i| x.* = i;
        const bank = try a.alloc([X.STATE_WORDS]u32, seed_rows);
        try X.prefixRows(seed_log, segments[0..case.split], 0, null, 0, all, bank);
        var absorbed: u32 = 0;
        for (case.segs[0..case.split]) |s| absorbed += s.width;
        const chained = try a.alloc([X.DIGEST_WORDS]u32, rows.len);
        try X.hashRows(log_size, segments[case.split..], absorbed, bank, seed_log, rows, chained);
        for (digests, chained) |d, c| if (!std.mem.eql(u32, &d, &c)) return error.CpuChainMismatch;
    }
    try w.print("CASE {s} {c} {d} {d} {d} {d} {d} {d}\n", .{ case.name, case.kind, case.seed, log_size, case.segs.len, case.split, rows.len, prefix_rows.len });
    for (case.segs) |s| try w.print("SEG {d} {d} {d}\n", .{ s.log, s.width, s.base });
    for (rows, digests) |r, d| {
        try w.print("R {d}", .{r});
        for (d) |x| try w.print(" {d}", .{x});
        try w.writeByte('\n');
    }
    for (prefix_rows, prefixes) |r, p| {
        try w.print("P {d}", .{r});
        for (p) |x| try w.print(" {d}", .{x});
        try w.writeByte('\n');
    }
    try w.writeAll("END\n");
}

/// Single height; at log >= 20 wide cases alias 8-column chunks.
fn singleHeight(a: std.mem.Allocator, log: u5, width: u32) ![]Seg {
    if (log < 20 or width <= 16) {
        const s = try a.alloc(Seg, 1);
        s[0] = .{ .log = log, .width = width, .base = 0 };
        return s;
    }
    const n = (width + 7) / 8;
    const s = try a.alloc(Seg, n);
    for (s, 0..) |*x, i| {
        const w: u32 = @min(8, width - @as(u32, @intCast(i)) * 8);
        x.* = .{ .log = log, .width = w, .base = if (w == 8) 0 else 100 };
    }
    return s;
}

// 24628607 CPU0 FIXED-tree source heights (M7 hash-budget census, 203 cols).
const cpu0_fixed = [_][2]u32{ .{ 6, 48 }, .{ 9, 9 }, .{ 10, 8 }, .{ 11, 8 }, .{ 12, 11 }, .{ 13, 9 }, .{ 15, 10 }, .{ 16, 9 }, .{ 17, 38 }, .{ 19, 44 }, .{ 21, 6 }, .{ 23, 3 } };

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const args = try std.process.argsAlloc(a);
    if (args.len < 2) return error.Usage;
    const file = try std.fs.cwd().createFile(args[1], .{});
    defer file.close();
    var buffer: [1 << 16]u8 = undefined;
    var fw = file.writer(&buffer);
    const w = &fw.interface;
    var prng = std.Random.DefaultPrng.init(0x4d39_5032);
    const rng = prng.random();
    var cases: std.ArrayList(Case) = .empty;
    const widths = [_]u32{ 1, 2, 3, 11, 12, 13, 23, 24, 25, 36, 47, 64, 100, 128, 199, 200 };
    const logs = [_]u5{ 10, 12, 14, 16, 18, 20, 22, 24 };
    for (logs) |log| for (widths) |width| {
        try cases.append(a, .{ .name = try std.fmt.allocPrint(a, "single-l{d}-w{d}", .{ log, width }), .kind = 'D', .seed = 0x1000 + @as(u64, log) * 256 + width, .segs = try singleHeight(a, log, width) });
    };
    // Random mixed multi-height shapes (total width <= 200).
    for (0..24) |i| {
        const max_log: u5 = @intCast(10 + i % 11);
        const n = 2 + rng.uintLessThan(usize, 11);
        const segs = try a.alloc(Seg, n);
        var total: u32 = 0;
        var col: u32 = 0;
        for (segs) |*s| {
            const width: u32 = @max(1, @min(1 + rng.uintLessThan(u32, 40), 200 -| total));
            total += width;
            s.* = .{ .log = @intCast(1 + rng.uintLessThan(u32, max_log)), .width = width, .base = col };
            col += width;
        }
        std.mem.sort(Seg, segs, {}, struct {
            fn lt(_: void, x: Seg, y: Seg) bool { return x.log < y.log; }
        }.lt);
        segs[n - 1].log = max_log;
        try cases.append(a, .{ .name = try std.fmt.allocPrint(a, "mixed-{d}", .{i}), .kind = 'D', .seed = 0x2000 + i, .segs = segs });
        if (i % 2 == 0 and max_log <= 18) {
            try cases.append(a, .{ .name = try std.fmt.allocPrint(a, "chain-{d}", .{i}), .kind = 'C', .seed = 0x2000 + i, .segs = segs, .split = 1 + rng.uintLessThan(usize, n - 1) });
        }
    }
    const fixed = try a.alloc(Seg, cpu0_fixed.len);
    var base: u32 = 0;
    for (cpu0_fixed, fixed) |g, *s| {
        s.* = .{ .log = @intCast(g[0]), .width = g[1], .base = base };
        base += g[1];
    }
    try cases.append(a, .{ .name = "cpu0-fixed-24628607", .kind = 'D', .seed = 0x3000, .segs = fixed });
    try cases.append(a, .{ .name = "cpu0-fixed-24628607-chain-l19", .kind = 'C', .seed = 0x3000, .segs = fixed, .split = 10 });
    try cases.append(a, .{ .name = "composition-l23-w16", .kind = 'D', .seed = 0x3001, .segs = &.{.{ .log = 23, .width = 16, .base = 0 }} });
    var slabs = Slabs.init(a);
    for (cases.items) |case| {
        try emit(a, w, &slabs, rng, case);
        // Large slabs are case-local; drop them to bound memory.
        if (case.segs[case.segs.len - 1].log >= 18) {
            var it = slabs.valueIterator();
            while (it.next()) |slab| std.heap.page_allocator.free(slab.*);
            slabs.clearRetainingCapacity();
        }
    }
    try w.flush();
    std.debug.print("wrote {d} cases\n", .{cases.items.len});
}
