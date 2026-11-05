//! Native curve semantic and full-column oracle; no device-derived expectations.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = A.crypto.curves;
const IO = @import("fixture_io.zig");
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, id: u32, comptime op: C.spec.Op, calls: u32) !void {
    const T = C.trace.Trace(op);
    const N = T.N;
    const L = T.L;
    const d = L.DEF;
    const log: u32 = 8;
    const n = 1 << log;
    const packets = try a.alloc(N.Packet, calls);
    defer a.free(packets);
    var rng = std.Random.DefaultPrng.init(0x917613 + id);
    for (packets, 0..) |*packet, j| {
        rng.random().bytes(packet);
        if (op == .bn254_g1_add or op == .bn254_g1_double) {
            for (0..d.inputs) |i| {
                var x = N.operand(packet, i) % C.spec.BN254_P;
                if (j == 0) x = i + 1;
                if (op == .bn254_g1_double and i == 1 and x == 0) x = 1;
                for (0..d.limbs) |b| packet[i * d.limbs + b] = C.spec.limbOf(x, b);
            }
            if (op == .bn254_g1_add and N.operand(packet, 0) == N.operand(packet, 2)) packet[64] ^= 1;
        } else if (op == .arith384_mont) {
            packet[96] |= 1;
            if (j < 3) {
                @memset(packet[96..144], if (j == 2) 255 else 0);
                packet[96] = if (j == 0) 1 else if (j == 1) 3 else 255;
            }
            if (j == 3) {
                @memset(packet[96..144], 0);
                packet[96] = 1;
                packet[143] = 128;
            }
        } else if (j == 0) @memset(packet, 255) else if (j == 1) @memset(packet, 0);
    }
    const counts = try T.byteCounts(packets, n);
    const matrix = try a.alloc(u32, L.MAIN * n);
    defer a.free(matrix);
    var row: N.Row = undefined;
    for (0..n) |r| {
        try T.nativeRow(&row, packets, &counts, r);
        const p = A.word16_execution.layout.physical(r, log);
        for (row, 0..) |v, c| matrix[c * n + p] = v;
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52565357, 1, id, log, calls, 17, L.MAIN, @intFromEnum(op) - 5 });
    try w.writeAll(std.mem.sliceAsBytes(packets));
    try IO.words(w, matrix);
    for (counts) |c| try IO.words(w, &.{@intCast(c)});
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
}
