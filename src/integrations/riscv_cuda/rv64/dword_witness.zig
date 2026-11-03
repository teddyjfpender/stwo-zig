//! Compact native-event ingress for the resident LS-D64 MAIN expander.
//! Event validation is witness preparation, not proof or execution acceptance.
const std = @import("std");
const D = @import("stwo_riscv_frontend").rv64_air.memory.load_store_dword;
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
pub const words_per_event: usize = 14;
pub const main_columns: usize = 39;
pub const Event = D.source.Event;
pub const Job = struct { events: ?Slice, output: Slice, verdict: Slice, log: u32, count: u32 };
pub const Plan = struct {
    rows: usize,
    event_words: usize,
    main_words: usize,
    ingress_bytes: usize,
    device_bytes: usize,
    pub fn init(log: u32, count: u32) !Plan {
        if (log < 5 or log > 22 or count >= @as(u32, 1) << @intCast(log)) return error.InvalidGeometry;
        const rows = @as(usize, 1) << @intCast(log);
        const event_words = try std.math.mul(usize, count, words_per_event);
        const main_words = try std.math.mul(usize, rows, main_columns);
        return .{ .rows = rows, .event_words = event_words, .main_words = main_words, .ingress_bytes = try std.math.mul(usize, event_words, 4), .device_bytes = try std.math.mul(usize, try std.math.add(usize, try std.math.add(usize, event_words, main_words), 1), 4) };
    }
};
/// Packs the same event slice used by native Source.init. The GPU derives
/// after/C and padding, so no wide MAIN or redundant result is uploaded.
pub fn pack(a: std.mem.Allocator, events: []const Event) ![]u32 {
    if (events.len >= 1 << 22) return error.InvalidGeometry;
    const out = try a.alloc(u32, try std.math.mul(usize, events.len, words_per_event));
    errdefer a.free(out);
    for (events, 0..) |e, i| {
        try encode(e, out[i * words_per_event ..][0..words_per_event]);
    }
    return out;
}
/// Stable filter directly from captured.advice.events[shard], matching the
/// CPU services pipeline's LS-D64 partition without allocating an Event copy.
/// The receiver-owned head/tail geometry selects subranges of this output.
pub fn packRouted(a: std.mem.Allocator, events: []const Event) ![]u32 {
    var count: usize = 0;
    for (events) |e| count += @intFromBool(D.source.admits(e));
    if (count >= 1 << 22) return error.InvalidGeometry;
    const out = try a.alloc(u32, try std.math.mul(usize, count, words_per_event));
    errdefer a.free(out);
    var i: usize = 0;
    for (events) |e| if (D.source.admits(e)) {
        try encode(e, out[i * words_per_event ..][0..words_per_event]);
        i += 1;
    };
    return out;
}
fn encode(e: Event, w: *[words_per_event]u32) !void {
    try D.source.validate(e);
    for ([_]u64{ e.a, e.immediate, e.b, e.before.value }, 0..) |v, k| {
        w[2 * k] = @truncate(v);
        w[2 * k + 1] = @truncate(v >> 32);
    }
    w[8] = e.before.epoch;
    w[9] = e.epoch;
    w[10] = e.before.tick;
    w[11] = e.tick;
    w[12] = e.before.rights;
    w[13] = @intFromBool(e.opcode == .SD);
}
comptime {
    if (D.layout.MAIN != main_columns or D.layout.STORED.len != main_columns) @compileError("LS-D64 witness layout changed");
    const stored = [_]usize{ 0, 1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 36, 37, 38, 39, 68, 75, 76, 77, 78 };
    for (stored, D.layout.STORED) |x, y| if (x != y) @compileError("native compact LS-D64 ordering changed; regenerate CUDA witness");
}
test "LS-D64 compact ingress uses actual native events and rejects altered results" {
    const a = std.testing.allocator;
    var e = Event{ .opcode = .SD, .a = 0, .immediate = 0xfffffffffffffff8, .b = 0x123456789abcdef0, .epoch = 7, .tick = 65536, .before = .{ .value = 9, .epoch = 7, .tick = 65535, .rights = 3 }, .after = .{ .value = 0x123456789abcdef0, .epoch = 7, .tick = 65536, .rights = 3 } };
    const words = try pack(a, &.{e});
    defer a.free(words);
    try std.testing.expectEqualSlices(u32, &.{ 0, 0, 0xfffffff8, 0xffffffff, 0x9abcdef0, 0x12345678, 9, 0, 7, 7, 65535, 65536, 3, 1 }, words);
    var general = e;
    general.opcode = .SW;
    const routed = try packRouted(a, &.{ general, e, general, e });
    defer a.free(routed);
    try std.testing.expectEqualSlices(u32, words, routed[0..words_per_event]);
    try std.testing.expectEqualSlices(u32, words, routed[words_per_event..]);
    e.after.value = 1;
    try std.testing.expectError(error.InvalidLoadStoreEvent, pack(a, &.{e}));
    const p = try Plan.init(20, (1 << 20) - 1);
    try std.testing.expectEqual(@as(usize, 39 << 20), p.main_words);
    try std.testing.expectEqual(@as(usize, 56 * ((1 << 20) - 1)), p.ingress_bytes);
    try std.testing.expectError(error.InvalidGeometry, Plan.init(20, 1 << 20));
}
