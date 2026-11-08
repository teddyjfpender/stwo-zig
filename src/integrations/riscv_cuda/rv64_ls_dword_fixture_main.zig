//! Compact-event to physical MAIN oracle. Never an execution verifier.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.memory.load_store_dword;
const IO = @import("rv64/fixture_io.zig");
const a = std.heap.page_allocator;
fn pair(w: anytype, value: u64) !void {
    try IO.words(w, &.{ @truncate(value), @truncate(value >> 32) });
}
fn fixture(dir: std.fs.Dir, id: u32, log: u32, count: u32) !void {
    const n = @as(usize, 1) << @intCast(log);
    const expected = try a.alloc(core.fields.m31.M31, D.layout.MAIN * n);
    defer a.free(expected);
    @memset(expected, core.fields.m31.M31.zero());
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564457, 1, id, log, count, D.layout.MAIN, 14, 0 });
    var rng = std.Random.DefaultPrng.init(0x32fea + id);
    for (0..count) |i| {
        const store = i % 2 == 0;
        const address = rng.random().int(u64) & ~@as(u64, 7);
        const immediate: u64 = switch (i % 4) {
            0 => 0,
            1 => 8,
            2 => 0xfffffffffffffff8,
            else => 0x1234ffff0000fff8,
        };
        const before_value = rng.random().int(u64);
        const b = if (store) rng.random().int(u64) else 0;
        const epoch: u16 = if (i % 3 == 0) 65535 else if (i % 3 == 1) 1 else 0;
        const old_epoch: u16 = if (i % 3 == 1) 0 else epoch;
        const tick: u24 = if (i % 4 == 0) 1 else if (i % 4 == 1) 65536 else 0xffffff;
        const old_tick: u24 = if (old_epoch != epoch) 0xffffff else if (i % 4 == 0) 0 else tick - 1 - @as(u24, @intCast(i % 65535));
        const rights: u2 = if (i % 5 == 0) 3 else if (store) 2 else 1;
        const event = D.source.Event{ .opcode = if (store) .SD else .LD, .a = address -% immediate, .immediate = immediate, .b = b, .c = if (store) 0 else before_value, .before = .{ .value = before_value, .epoch = old_epoch, .tick = old_tick, .rights = rights }, .after = .{ .value = if (store) b else before_value, .epoch = epoch, .tick = tick, .rights = rights }, .epoch = epoch, .tick = tick };
        try D.source.validate(event);
        const row = D.source.row(event);
        const physical = A.memory.closed_ram.trace.physical(i, log);
        for (row, 0..) |v, c| expected[c * n + physical] = v;
        try pair(w, event.a);
        try pair(w, event.immediate);
        try pair(w, event.b);
        try pair(w, before_value);
        try IO.words(w, &.{ old_epoch, epoch, old_tick, tick, rights, @intFromBool(store) });
    }
    for (expected) |v| try IO.words(w, &.{v.v});
    const filename = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(filename);
    try dir.writeFile(.{ .sub_path = filename, .data = bytes.items });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    try fixture(dir, 0, 5, 0);
    try fixture(dir, 1, 5, 31);
    try fixture(dir, 2, 13, 3077);
    try fixture(dir, 3, 20, (1 << 20) - 1);
    std.debug.print("PASS native LS-D64 witness fixtures=4\n", .{});
}
