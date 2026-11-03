//! Original native bridge rows and histograms, independent of the CUDA formatter.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak.word16_bridge;
const W = A.crypto.secp256k1.word16_bridge;
const M = @import("stwo_core").fields.m31.M31;
fn put(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try out.appendSlice(a, &b);
}
fn word(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u64) !void {
    try put(out, a, @truncate(v));
    try put(out, a, @intCast(v >> 32));
}
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, id: u32, wire: ?W.types.Kind, count: usize) !void {
    const coords = if (wire) |kind| W.types.coordinates(kind) else 25;
    var log: u32 = 5;
    while ((@as(usize, 1) << @intCast(log)) <= count * coords) log += 1;
    const n = @as(usize, 1) << @intCast(log);
    const width: usize = if (wire != null) W.layout.MAIN else K.layout.MAIN;
    const matrix = try a.alloc(M, width * n);
    defer a.free(matrix);
    @memset(matrix, M.zero());
    var counts16: [65536]u32 = @splat(0);
    var counts8: [256]u32 = @splat(0);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(a);
    var mask: u32 = 0;
    if (wire) |kind| for (0..coords) |c| {
        if (W.types.isWritten(kind, c)) mask |= @as(u32, 1) << @intCast(c);
    };
    for ([_]u32{ 0x52564252, 1, id, log, @intCast(count), @intCast(width), @intFromBool(wire != null), @intCast(coords), mask }) |v| try put(&encoded, a, v);
    var rng = std.Random.DefaultPrng.init(@as(u64, 0x627269646765) + id);
    const random = rng.random();
    for (0..count) |call| {
        const pointer: u64 = 0x1234ffe0 + 1024 * call;
        const epoch: u16 = @intCast(1 + call / 2);
        const tick: u24 = @intCast(0x12300 + 100 * call);
        var k: K.types.Call = undefined;
        var w: W.types.Call = undefined;
        k.pointer = pointer;
        k.epoch = epoch;
        k.tick = tick;
        w.pointer = pointer;
        w.epoch = epoch;
        w.tick = tick;
        try word(&encoded, a, pointer);
        try put(&encoded, a, epoch);
        try put(&encoded, a, tick);
        const words = if (wire != null) 4 * coords else 25;
        for (0..words) |i| {
            const before = if (i % 5 == 0) std.math.maxInt(u64) else random.int(u64);
            const written = if (wire) |kind| W.types.isWritten(kind, i / 4) else true;
            const after = if (written) random.int(u64) else before;
            const pred = A.memory.closed_ram.types.State{ .value = before, .epoch = if (i % 2 == 0) epoch else epoch - 1, .tick = if (i % 2 == 0) tick - 123 else 0x23456, .rights = if (written) 3 else 1 };
            if (wire != null) {
                w.before[i] = before;
                w.after[i] = after;
                w.predecessors[i] = pred;
            } else {
                k.before[i] = before;
                k.after[i] = after;
                k.predecessors[i] = pred;
            }
            try word(&encoded, a, before);
            try word(&encoded, a, after);
            try word(&encoded, a, pred.value);
            try put(&encoded, a, @as(u32, pred.epoch) | (@as(u32, pred.rights) << 16));
            try put(&encoded, a, pred.tick);
        }
        if (wire) |kind| try W.source.validate(kind, w) else try K.source.validate(k);
        for (0..coords) |c| {
            var buffer: [W.layout.MAIN]M = undefined;
            if (wire) |kind| buffer = W.source.nativeRow(kind, w, c, @intCast(7 + call)) else @memcpy(buffer[0..K.layout.MAIN], &K.source.nativeRow(k, c, @intCast(7 + call)));
            const row = buffer[0..width];
            const p = A.memory.closed_ram.trace.physical(call * coords + c, log);
            for (row, 0..) |v, column| matrix[column * n + p] = v;
            if (wire != null) {
                for (W.layout.U16) |col| counts16[row[col].v] += 1;
                for (W.layout.U8) |col| counts8[row[col].v] += 1;
            } else {
                for (K.layout.U16) |col| counts16[row[col].v] += 1;
                for (K.layout.U8) |col| counts8[row[col].v] += 1;
            }
        }
    }
    const padding: u32 = @intCast(n - count * coords);
    counts16[0] += padding * @as(u32, if (wire != null) W.layout.U16.len else K.layout.U16.len);
    counts8[0] += padding * @as(u32, if (wire != null) W.layout.U8.len else K.layout.U8.len);
    try encoded.appendSlice(a, std.mem.sliceAsBytes(matrix));
    try encoded.appendSlice(a, std.mem.sliceAsBytes(&counts16));
    try encoded.appendSlice(a, std.mem.sliceAsBytes(&counts8));
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = encoded.items });
}
