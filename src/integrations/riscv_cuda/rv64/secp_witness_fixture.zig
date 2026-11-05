//! Independent original native secp whole-matrix oracle.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = A.crypto.curves;
const IO = @import("fixture_io.zig");
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, id: u32, comptime kind: C.spec.SecpKind, calls: u32) !void {
    const T = C.trace.Trace(kind);
    const N = T.N;
    const L = T.L;
    const log: u32 = 8;
    const n = 1 << log;
    const packets = try a.alloc(N.Packet, calls);
    defer a.free(packets);
    var rng = std.Random.DefaultPrng.init(0x617131 + id);
    for (packets, 0..) |*p, i| {
        rng.random().bytes(p);
        if (i == 0) @memset(p, 255);
        if (i == 1) @memset(p, 0);
    }
    const counts = try T.byteCounts(packets, n);
    const matrix = try a.alloc(u32, L.MAIN * n);
    defer a.free(matrix);
    var row: N.Row = undefined;
    for (0..n) |r| {
        try T.nativeRow(&row, packets, &counts, r);
        const physical = A.word16_execution.layout.physical(r, log);
        for (row, 0..) |v, c| matrix[c * n + physical] = v;
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52565357, 1, id, log, calls, 17, L.MAIN, if (kind == .add) 0 else 1 });
    try w.writeAll(std.mem.sliceAsBytes(packets));
    try IO.words(w, matrix);
    for (counts) |count| try IO.words(w, &.{@intCast(count)});
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
}
