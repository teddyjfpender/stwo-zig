//! Checked conditional u64 increment on authenticated little-endian byte words.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 24;
pub const PREPROCESSED_COLUMN_COUNT = 9;
pub const LOGICAL_INPUT_COUNT = 33;
pub const DIRECT_CONSTRAINT_COUNT = 16;
pub const RELATION_EVENT_COUNT = 13;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 7;
pub const INTERACTION_COLUMN_COUNT = 28;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "ffff10e710fb18dd0e9d0f442ed4ac62a7458e774d90e8f22e05f060377794dd") catch @compileError("invalid counter step digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Caller = @import("blake3_frame_route.zig").Caller;
pub const Endpoint = @import("blake3_byte_route.zig").Endpoint;
pub const Schedule = struct { source: Caller, increment: Endpoint, destination: Caller, uses: [2]u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3CounterStep;
    }
};
pub fn computeSemanticDigest(a: std.mem.Allocator) ![32]u8 {
    var d = try buildRaw(a);
    defer d.deinit();
    return (try lang.digest.computeIdentity(&d.arena)).bytes;
}
pub fn build(a: std.mem.Allocator) !Definition {
    var d = try buildRaw(a);
    errdefer d.deinit();
    try d.validate();
    return d;
}
fn buildRaw(a: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var ids: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&ids, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_counter_step.value_{d}", .{i}), if (i >= 1 and i <= 16) .byte else .felt, span);
    }
    const zero = try arena.constantField(0, span);
    const radix = try arena.constantField(256, span);
    for (0..8) |i| {
        const carry = if (i == 0) ids[0] else ids[16 + i];
        var buf: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_counter_step.bit_{d}", .{i}), try arena.mul(carry, try arena.sub(carry, ids[24], span), span), null, .semantic, span);
        const next = if (i == 7) zero else ids[17 + i];
        const sum = try arena.add(ids[1 + i], carry, span);
        const expected = try arena.add(ids[9 + i], try arena.mul(radix, next, span), span);
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_counter_step.byte_{d}", .{i}), try arena.sub(sum, expected, span), null, .semantic, span);
    }
    for (0..8) |i| _ = try effects.appendGroup(1, &arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = &.{ ids[1 + 2 * i], ids[2 + 2 * i] }, .weight = ids[24] }}, span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[27], ids[28], ids[0], zero, zero, zero }, .weight = ids[24] }}, span);
    for (0..2) |i| {
        const offset = try arena.constantField(@intCast(i), span);
        _ = try effects.appendGroup(2, &arena, .{
            .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[25], try arena.add(ids[26], offset, span) } ++ ids[1 + 4 * i ..][0..4].*), .weight = ids[24] },
            .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[29], try arena.add(ids[30], offset, span) } ++ ids[9 + 4 * i ..][0..4].*), .weight = ids[31 + i] },
        }, span);
    }
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*event, i| event.* = @enumFromInt(i);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if (s.source.first_wire > p - 2 or s.destination.first_wire > p - 2 or (s.source.circuit == s.destination.circuit and s.source.first_wire < s.destination.first_wire + 2 and s.destination.first_wire < s.source.first_wire + 2)) return error.InvalidBlake3CounterStep;
    const fields = [_]u32{ 1, s.source.circuit, s.source.first_wire, s.increment.circuit, s.increment.wire, s.destination.circuit, s.destination.first_wire, s.uses[0], s.uses[1] };
    var row: Row = @splat(M31.zero());
    for (row[24..], fields) |*out, value| {
        if (value >= p) return error.InvalidBlake3CounterStep;
        out.* = M31.fromCanonical(value);
    }
    return row;
}
pub fn logicalRow(s: Schedule, value: u64, increment: u1) !Row {
    const next = std.math.add(u64, value, increment) catch return error.Blake3CounterExhausted;
    var row = try fixedRow(s);
    row[0] = M31.fromCanonical(increment);
    var carry: u16 = increment;
    for (0..8) |i| {
        const shift: u6 = @intCast(8 * i);
        const byte: u8 = @truncate(value >> shift);
        row[1 + i] = M31.fromCanonical(byte);
        row[9 + i] = M31.fromCanonical(@as(u8, @truncate(next >> shift)));
        carry = (@as(u16, byte) + carry) >> 8;
        if (i < 7) row[17 + i] = M31.fromCanonical(carry);
    }
    return row;
}
