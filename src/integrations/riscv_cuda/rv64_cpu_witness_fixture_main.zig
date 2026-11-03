//! Independent native formatter oracle; not an execution or AIR proof.
const std = @import("std");
const core = @import("stwo_core");
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const Metadata = @import("stwo_riscv_cpu_integration").rv64_cpu_source.Metadata;
const IO = @import("rv64/fixture_io.zig");
const a = std.heap.page_allocator;
fn fixture(dir: std.fs.Dir, id: u32, log: u32, count: u32) !void {
    const n = @as(usize, 1) << @intCast(log);
    const raw = [_]u32{ 0x00108093, 0x002081b3, 0x00008067, 0x00208463, 0xff80b303, 0x0060b423, 0x123453b7, 0x00000417, 0x000004ef, 0x00000073 };
    var entries: [raw.len]X.features.Entry = undefined;
    var rom: [32 * X.layout.rom.FIXED]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
    for (raw, &entries, 0..) |word, *entry, i| {
        entry.* = X.features.Entry.fromDecoded(word, 4096 + 16 * i);
        if (!entry.compactValid()) return error.BadOracleInstruction;
        for (0..2) |edge| {
            if (edge == 1 and !entry.hasTakenEdge()) continue;
            const rp = X.layout.physical(2 * i + edge, 5);
            for (entry.romTupleCompact(edge == 1), 0..) |v, c| rom[c * 32 + rp] = v;
        }
    }
    const metadata = try a.alloc(Metadata, count);
    defer a.free(metadata);
    const matrix = try a.alloc(core.fields.m31.M31, X.layout.compact.COUNT * n);
    defer a.free(matrix);
    var counts16: [65536]u32 = @splat(0);
    var counts8: [256]u32 = @splat(0);
    var rom_counts: [32]u32 = @splat(0);
    var pairs: [65536]u32 = @splat(0);
    var rng = std.Random.DefaultPrng.init(0xcafe789 + id);
    for (0..n) |logical| {
        var row: X.row.Main = undefined;
        if (logical < count) {
            const index = logical % raw.len;
            const entry = entries[index];
            const taken = entry.hasTakenEdge() and (logical / raw.len) % 2 != 0;
            const c: u64 = if (entry.branch) @intFromBool(taken) else rng.random().int(u64);
            const next = if (entry.dynamic_next) 0x123450 else entry.staticNext(taken);
            var values = [5]u64{ rng.random().int(u64), rng.random().int(u64), c, rng.random().int(u64), next };
            var clocks: [3]u32 = undefined;
            for (entry.ids, 0..) |reg, slot| {
                if (reg == 0) values[if (slot == 2) 3 else slot] = 0;
                const tick: u32 = @intCast(4 * logical + slot + 1);
                clocks[slot] = if (reg == 0) 0 else rng.random().intRangeLessThan(u32, 0, tick);
            }
            metadata[logical] = .{ .values = values, .clocks = clocks, .rom_row = @intCast(2 * index + @intFromBool(taken)) };
            row = try X.row.compact.active(entry, @intCast(logical), next, .{ .a = values[0], .b = values[1], .c = values[2], .previous_rd = values[3] }, clocks);
            rom_counts[X.layout.physical(metadata[logical].rom_row, 5)] += 1;
        } else row = try X.row.compact.padding(@intCast(logical), 8192);
        const physical = X.layout.physical(logical, log);
        for (row[0..X.layout.compact.COUNT], 0..) |v, col| matrix[col * n + physical] = v;
        for (0..3) |slot| {
            counts16[row[X.layout.compact.gap16 + slot].v] += 1;
            const hi = row[X.layout.compact.gap8 + slot].v;
            if (log > 22) counts16[128 * hi] += 1 else counts8[hi] += 1;
        }
        if (log <= 22) {
            pairs[row[X.layout.compact.gap8].v * 256 + row[X.layout.compact.gap8 + 1].v] += 1;
            pairs[row[X.layout.compact.gap8 + 2].v * 256] += 1;
        }
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564357, 2, id, log, count, 5, 8192, 37 });
    try w.writeAll(std.mem.sliceAsBytes(metadata));
    try w.writeAll(std.mem.sliceAsBytes(&rom));
    try w.writeAll(std.mem.sliceAsBytes(matrix));
    try IO.words(w, &counts16);
    try IO.words(w, &counts8);
    try IO.words(w, &rom_counts);
    try IO.words(w, &pairs);
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 3 and std.mem.eql(u8, args[1], "--bridge")) {
        try std.fs.cwd().makePath(args[2]);
        var d = try std.fs.cwd().openDir(args[2], .{});
        defer d.close();
        const bridge = @import("rv64/bridge_witness_fixture.zig");
        try bridge.write(a, d, 0, null, 0);
        try bridge.write(a, d, 1, null, 3);
        try bridge.write(a, d, 2, .add, 3);
        try bridge.write(a, d, 3, .double, 9);
        try bridge.write(a, d, 4, .sha256, 2);
        try bridge.write(a, d, 5, .arith256_mod, 3);
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "--secp")) {
        try std.fs.cwd().makePath(args[2]);
        var d = try std.fs.cwd().openDir(args[2], .{});
        defer d.close();
        const oracle = @import("rv64/secp_witness_fixture.zig");
        try oracle.write(a, d, 0, .add, 0);
        try oracle.write(a, d, 1, .double, 1);
        try oracle.write(a, d, 2, .add, 3);
        try oracle.write(a, d, 3, .double, 9);
        return;
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "--keccak")) {
        try std.fs.cwd().makePath(args[2]);
        var directory = try std.fs.cwd().openDir(args[2], .{});
        defer directory.close();
        const oracle = @import("rv64/keccak_witness_fixture.zig");
        try oracle.write(a, directory, 0, 5, 1);
        try oracle.write(a, directory, 1, 6, 3);
        try oracle.write(a, directory, 2, 8, 18);
        return;
    }
    if (args.len < 2 or args.len > 3) return error.ExpectedDirectoryAndOptionalLarge;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    try fixture(dir, 0, 5, 0);
    try fixture(dir, 1, 5, 31);
    try fixture(dir, 2, 13, 3077);
    if (args.len == 3) try fixture(dir, 3, 22, (1 << 22) - 1);
}
