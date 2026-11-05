//! Compact execution/public inputs for resident memory witness formatting.
//! No projected RAM/OWNER tuple, limb, carry, gap or MAIN column is built here.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const Event = extern struct {
    a: u64,
    immediate: u64,
    b: u64,
    c: u64,
    before_value: u64,
    before_epoch: u32,
    epoch: u32,
    before_tick: u32,
    tick: u32,
    rights: u32,
    flag: u32,
};
pub const Cell = extern struct {
    address: u64,
    value: u64,
    epoch: u32,
    tick: u32,
    rights: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(Event) != 64 or @offsetOf(Event, "before_epoch") != 40 or @offsetOf(Event, "flag") != 60) @compileError("compact LS event ABI changed");
    if (@sizeOf(Cell) != 32 or @offsetOf(Cell, "epoch") != 16) @compileError("compact public RAM cell ABI changed");
}
pub fn events(a: std.mem.Allocator, input: []const A.memory.load_store_v2.native.Event) ![]Event {
    const out = try a.alloc(Event, input.len);
    errdefer a.free(out);
    for (input, out) |e, *v| {
        const spec = try A.memory.load_store_v2.native.describe(e.opcode);
        v.* = .{ .a = e.a, .immediate = e.immediate, .b = e.b, .c = e.c, .before_value = e.before.value, .before_epoch = e.before.epoch, .epoch = e.epoch, .before_tick = e.before.tick, .tick = e.tick, .rights = e.before.rights, .flag = @intCast(spec.flag) };
    }
    return out;
}
/// Stable service routing directly into compact advice. Avoid materializing
/// full native Event partitions before immediately encoding and freeing them.
pub fn routedEvents(a: std.mem.Allocator, input: []const A.memory.load_store_v2.native.Event, dword_enabled: bool, want_dword: bool) ![]Event {
    var count: usize = 0;
    for (input) |e| if ((dword_enabled and A.memory.load_store_dword.source.admits(e)) == want_dword) {
        count += 1;
    };
    const out = try a.alloc(Event, count);
    errdefer a.free(out);
    var at: usize = 0;
    for (input) |e| if ((dword_enabled and A.memory.load_store_dword.source.admits(e)) == want_dword) {
        const spec = try A.memory.load_store_v2.native.describe(e.opcode);
        out[at] = .{ .a = e.a, .immediate = e.immediate, .b = e.b, .c = e.c, .before_value = e.before.value, .before_epoch = e.before.epoch, .epoch = e.epoch, .before_tick = e.before.tick, .tick = e.tick, .rights = e.before.rights, .flag = @intCast(spec.flag) };
        at += 1;
    };
    return out;
}
pub fn cells(a: std.mem.Allocator, input: []const A.memory.closed_ram.types.Cell) ![]Cell {
    const out = try a.alloc(Cell, input.len);
    for (input, out) |c, *v| v.* = .{ .address = c.address, .value = c.state.value, .epoch = c.state.epoch, .tick = c.state.tick, .rights = c.state.rights };
    return out;
}

test "device family witness memory input keeps raw64 values and public state" {
    const input = [_]A.memory.closed_ram.types.Cell{.{ .address = 0x123456789abcdef0, .state = .{ .value = 0xfedcba9876543210, .epoch = 3, .tick = 65537, .rights = 3 } }};
    const data = try cells(std.testing.allocator, &input);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqual(@as(u64, 0x123456789abcdef0), data[0].address);
    try std.testing.expectEqual(@as(u32, 65537), data[0].tick);
    try std.testing.expectEqual(@as(u32, 0), data[0].reserved);
}

test "compact event routing preserves stable native partition including unaligned dwords" {
    const a = std.testing.allocator;
    const E = A.memory.load_store_v2.native.Event;
    const store = E{ .opcode = .SD, .a = 8, .immediate = 0, .b = 0x123456789abcdef0, .epoch = 7, .tick = 65536, .before = .{ .value = 9, .epoch = 7, .tick = 65535, .rights = 3 }, .after = .{ .value = 0x123456789abcdef0, .epoch = 7, .tick = 65536, .rights = 3 } };
    var byte = store;
    byte.opcode = .SB;
    byte.a = 17;
    var unaligned = store;
    unaligned.a = 9;
    var load = store;
    load.opcode = .LD;
    load.a = 24;
    const input = [_]E{ store, byte, unaligned, load, byte };
    const general = try routedEvents(a, &input, true, false);
    defer a.free(general);
    const dword = try routedEvents(a, &input, true, true);
    defer a.free(dword);
    const expected_general = try events(a, &.{ byte, unaligned, byte });
    defer a.free(expected_general);
    const expected_dword = try events(a, &.{ store, load });
    defer a.free(expected_dword);
    try std.testing.expectEqualDeep(expected_general, general);
    try std.testing.expectEqualDeep(expected_dword, dword);
    const disabled = try routedEvents(a, &input, false, false);
    defer a.free(disabled);
    const original = try events(a, &input);
    defer a.free(original);
    try std.testing.expectEqualDeep(original, disabled);
    const empty = try routedEvents(a, &input, false, true);
    defer a.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    try std.testing.checkAllAllocationFailures(a, routeAllocationProbe, .{&input});
}
fn routeAllocationProbe(a: std.mem.Allocator, input: []const A.memory.load_store_v2.native.Event) !void {
    const result = try routedEvents(a, input, true, false);
    defer a.free(result);
}
