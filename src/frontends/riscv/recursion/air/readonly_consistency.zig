//! Sorted sparse read-only table; authentication comes from its input multiset.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 19;
pub const PREPROCESSED_COLUMN_COUNT = 6;
pub const LOGICAL_INPUT_COUNT = 25;
pub const DIRECT_CONSTRAINT_COUNT = 10;
pub const RELATION_EVENT_COUNT = 9;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 5;
pub const INTERACTION_COLUMN_COUNT = 20;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "78428ee7716d1956a5725eb6383fbff7ed833250401a83a48b9c4f66372e4c7f") catch @compileError("invalid read-only consistency digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
/// Each table needs distinct input/chain namespaces. The caller anchors rank
/// zero to (index=0,value=0) and authenticates exactly one input per sorted row.
pub const Schedule = struct { table: u32, chain: u32, rank: u32, last: bool };
pub const Entry = struct { index: u32, value: M31 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidReadonlyConsistency;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "readonly_consistency.value_{d}", .{i}), if (i < 12) .byte else .felt, span);
    }
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const radix = try arena.constantField(256, span);
    for (0..3) |i| {
        var buf: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "readonly_consistency.carry_{d}", .{i}), try arena.mul(ids[12 + i], try arena.sub(ids[12 + i], ids[19], span), span), null, .semantic, span);
    }
    for (0..4) |i| {
        var buf: [48]u8 = undefined;
        const carry = if (i == 0) zero else ids[11 + i];
        const next = if (i == 3) zero else ids[12 + i];
        const sum = try arena.add(try arena.add(ids[4 + i], ids[8 + i], span), carry, span);
        const expected = try arena.add(ids[i], try arena.mul(radix, next, span), span);
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "readonly_consistency.order_{d}", .{i}), try arena.sub(sum, expected, span), null, .semantic, span);
    }
    const gap_sum = try arena.add(try arena.add(ids[8], ids[9], span), try arena.add(ids[10], ids[11], span), span);
    _ = try arena.assertZero("readonly_consistency.zero", try arena.mul(gap_sum, ids[17], span), null, .semantic, span);
    _ = try arena.assertZero("readonly_consistency.inverse", try arena.sub(try arena.mul(gap_sum, ids[18], span), try arena.sub(ids[19], ids[17], span), span), null, .semantic, span);
    const equal = try arena.mul(try arena.sub(ids[19], ids[20], span), ids[17], span);
    _ = try arena.assertZero("readonly_consistency.value", try arena.mul(equal, try arena.sub(ids[15], ids[16], span), span), null, .semantic, span);
    for (0..6) |i| _ = try effects.appendGroup(1, &arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = &.{ ids[2 * i], ids[2 * i + 1] }, .weight = ids[19] }}, span);
    const lo = try arena.add(ids[0], try arena.mul(radix, ids[1], span), span);
    const hi = try arena.add(ids[2], try arena.mul(radix, ids[3], span), span);
    const prev_lo = try arena.add(ids[4], try arena.mul(radix, ids[5], span), span);
    const prev_hi = try arena.add(ids[6], try arena.mul(radix, ids[7], span), span);
    _ = try effects.appendGroup(3, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[21], lo, hi, ids[15], zero, zero }, .weight = ids[19] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[22], ids[23], prev_lo, prev_hi, ids[16], zero }, .weight = ids[19] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[22], try arena.add(ids[23], one, span), lo, hi, ids[15], zero }, .weight = ids[24] },
    }, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*event, i| event.* = @enumFromInt(i);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if (s.table == s.chain or s.table >= p or s.chain >= p or s.rank >= p - 1) return error.InvalidReadonlyConsistency;
    var row: Row = @splat(M31.zero());
    const fields = [_]u32{ 1, @intFromBool(s.rank == 0), s.table, s.chain, s.rank, @intFromBool(!s.last) };
    for (row[19..], fields) |*out, value| out.* = M31.fromCanonical(value);
    return row;
}
pub fn logicalRow(s: Schedule, previous: Entry, current: Entry) !Row {
    if (current.index < previous.index or current.value.v >= core.fields.m31.Modulus or previous.value.v >= core.fields.m31.Modulus) return error.InvalidReadonlyConsistency;
    if (s.rank == 0 and (previous.index != 0 or !previous.value.isZero())) return error.InvalidReadonlyConsistency;
    if (s.rank != 0 and current.index == previous.index and !current.value.eql(previous.value)) return error.InconsistentReadonlyValue;
    var row = try fixedRow(s);
    const gap = current.index - previous.index;
    var carry: u32 = 0;
    var sum: u32 = 0;
    for (0..4) |i| {
        const shift: u5 = @intCast(8 * i);
        const prev_byte = (previous.index >> shift) & 255;
        const gap_byte = (gap >> shift) & 255;
        row[i] = M31.fromCanonical((current.index >> shift) & 255);
        row[4 + i] = M31.fromCanonical(prev_byte);
        row[8 + i] = M31.fromCanonical(gap_byte);
        carry = (prev_byte + gap_byte + carry) >> 8;
        if (i < 3) row[12 + i] = M31.fromCanonical(carry);
        sum += gap_byte;
    }
    row[15] = current.value;
    row[16] = previous.value;
    row[17] = M31.fromCanonical(@intFromBool(gap == 0));
    row[18] = if (sum == 0) M31.zero() else try M31.fromCanonical(sum).inv();
    return row;
}
