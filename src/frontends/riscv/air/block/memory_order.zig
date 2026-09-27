//! Typed sorted-memory adjacency constraints for the new block protocol.
//! This is a gadget, not a complete memory AIR: callers must authenticate the
//! adjacent rows, bind their event permutation, and prove first-value loading.
//! No hash boundary or old local-clock memory bus is removed by this module.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/definition.zig");
const effects = @import("../../recursion/air/relation_effect.zig");
const M = core.fields.m31.M31;
const Id = lang.types.ValueId;
const span = lang.source.SourceSpan.generated();
pub const STABLE_NAME = "block.memory_order.v1";
pub const DIRECT_CONSTRAINT_COUNT = 41;
pub const RELATION_EVENT_COUNT = 24;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, "a1de6d7d98a71bbab8f3dad997f76bb0e8337e74465f648c09bf2ffa85df4c28") catch @compileError("invalid memory order identity");
    break :blk digest;
};
pub const Layout = struct {
    pub const active = 0;
    pub const same = 1;
    pub const previous_key = 2;
    pub const current_key = 7;
    pub const previous_clock = 12;
    pub const current_clock = 20;
    pub const previous_value = 28;
    pub const current_value = 32;
    pub const key_gap = 36;
    pub const key_carry = 41;
    pub const clock_gap = 46;
    pub const clock_carry = 54;
    pub const len = 62;
};
pub const Row = [Layout.len]M;
pub const Point = struct {
    space: u1,
    address: u32,
    clock: u64,
    /// Previous point: post-access value. Current point: pre-access value.
    value: u32,
    pub fn key(self: Point) u64 {
        return (@as(u64, self.space) << 32) | self.address;
    }
};
pub const Definition = struct {
    arena: lang.ir.Arena,
    /// Stable input order for composition with the block-memory row AIR.
    inputs: [Layout.len]Id,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
};
/// Inputs are logical cells. The future memory assembly must map predecessor
/// cells to authenticated row masks or a constrained continuation relation.
pub fn build(a: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    var ids: [Layout.len]Id = undefined;
    for (&ids, 0..) |*id, i| {
        var name: [48]u8 = undefined;
        const selector = i < 2 or (i >= Layout.key_carry and i < Layout.clock_gap) or i >= Layout.clock_carry;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "memory_order.input_{d}", .{i}), if (selector) .selector else .byte, span);
    }
    var ops = Ops{ .arena = &arena, .active = ids[Layout.active] };
    const one = try arena.constantField(1, span);
    const same = ids[Layout.same];
    const different = try arena.sub(one, same, span);
    try ops.zero(try arena.mul(ids[0], try arena.sub(ids[0], one, span), span));
    try ops.bit(same);
    try ops.bit(ids[Layout.previous_key + 4]);
    try ops.bit(ids[Layout.current_key + 4]);
    for (ids[Layout.key_carry..Layout.clock_gap]) |id| try ops.bit(id);
    for (ids[Layout.clock_carry..]) |id| try ops.bit(id);
    for (0..5) |i| try ops.gatedEqual(same, ids[Layout.previous_key + i], ids[Layout.current_key + i]);
    for (0..4) |i| try ops.gatedEqual(same, ids[Layout.previous_value + i], ids[Layout.current_value + i]);
    try ops.strictIncrease(5, different, ids[Layout.previous_key..][0..5].*, ids[Layout.current_key..][0..5].*, ids[Layout.key_gap..][0..5].*, ids[Layout.key_carry..][0..5].*);
    try ops.strictIncrease(8, same, ids[Layout.previous_clock..][0..8].*, ids[Layout.current_clock..][0..8].*, ids[Layout.clock_gap..][0..8].*, ids[Layout.clock_carry..][0..8].*);
    // Every byte in an integer equation is lookup constrained. Integer
    // residuals are at most 511 in magnitude, so M31 cannot hide a wrap.
    const zero = try arena.constantUnsigned(.byte, 0, span);
    const byte_ids = ids[Layout.previous_key..Layout.key_carry].* ++ ids[Layout.clock_gap..Layout.clock_carry].* ++ .{zero};
    comptime std.debug.assert(byte_ids.len == 48);
    for (0..byte_ids.len / 2) |i| {
        _ = try effects.appendGroup(1, &arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = byte_ids[2 * i ..][0..2], .weight = ids[Layout.active] }}, span);
    }
    try lang.validate.validate(&arena);
    const identity = try lang.digest.computeIdentity(&arena);
    if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidMemoryOrderIdentity;
    return .{ .arena = arena, .inputs = ids };
}
const Ops = struct {
    arena: *lang.ir.Arena,
    active: Id,
    count: usize = 0,
    fn zero(self: *Ops, value: Id) !void {
        var name: [48]u8 = undefined;
        _ = try self.arena.assertZero(try std.fmt.bufPrint(&name, "memory_order.constraint_{d}", .{self.count}), value, null, .semantic, span);
        self.count += 1;
    }
    fn bit(self: *Ops, value: Id) !void {
        const one = try self.arena.constantField(1, span);
        try self.zero(try self.arena.mul(self.active, try self.arena.mul(value, try self.arena.sub(value, one, span), span), span));
    }
    fn gatedEqual(self: *Ops, gate: Id, lhs: Id, rhs: Id) !void {
        try self.zero(try self.arena.mul(self.active, try self.arena.mul(gate, try self.arena.sub(lhs, rhs, span), span), span));
    }
    fn strictIncrease(self: *Ops, comptime n: usize, gate: Id, previous: [n]Id, current: [n]Id, gap: [n]Id, carry: [n]Id) !void {
        const radix = try self.arena.constantField(256, span);
        var incoming = try self.arena.constantField(1, span);
        for (0..n) |i| {
            const sum = try self.arena.add(try self.arena.add(previous[i], gap[i], span), incoming, span);
            const out = try self.arena.add(current[i], try self.arena.mul(radix, carry[i], span), span);
            try self.gatedEqual(gate, sum, out);
            incoming = carry[i];
        }
        try self.gatedEqual(gate, incoming, try self.arena.constantField(0, span));
    }
};
pub fn witness(previous: Point, current: Point) !Row {
    if (current.key() < previous.key()) return error.MemoryAddressOrder;
    const same = current.key() == previous.key();
    if (same and current.clock <= previous.clock) return error.MemoryClockOrder;
    if (same and current.value != previous.value) return error.MemoryValueDiscontinuity;
    var row: Row = @splat(M.zero());
    row[Layout.active] = M.one();
    row[Layout.same] = M.fromCanonical(@intFromBool(same));
    writeBytes(row[Layout.previous_key..][0..5], previous.key());
    writeBytes(row[Layout.current_key..][0..5], current.key());
    writeBytes(row[Layout.previous_clock..][0..8], previous.clock);
    writeBytes(row[Layout.current_clock..][0..8], current.clock);
    writeBytes(row[Layout.previous_value..][0..4], previous.value);
    writeBytes(row[Layout.current_value..][0..4], current.value);
    if (same) {
        writeGap(8, previous.clock, current.clock, row[Layout.clock_gap..][0..8], row[Layout.clock_carry..][0..8]);
    } else {
        writeGap(5, previous.key(), current.key(), row[Layout.key_gap..][0..5], row[Layout.key_carry..][0..5]);
    }
    return row;
}
fn writeBytes(out: []M, value: u64) void {
    for (out, 0..) |*item, i| item.* = M.fromCanonical(@as(u8, @truncate(value >> @intCast(i * 8))));
}
fn writeGap(comptime n: usize, previous: u64, current: u64, gap: *[n]M, carries: *[n]M) void {
    writeBytes(gap, current - previous - 1);
    var incoming: u16 = 1;
    for (0..n) |i| {
        const byte: u8 = @truncate(previous >> @intCast(i * 8));
        incoming = (@as(u16, byte) + @as(u16, @intCast(gap[i].toU32())) + incoming) >> 8;
        carries[i] = M.fromCanonical(incoming);
    }
    std.debug.assert(incoming == 0);
}
