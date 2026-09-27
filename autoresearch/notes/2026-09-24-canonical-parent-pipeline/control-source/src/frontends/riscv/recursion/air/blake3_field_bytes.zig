//! Canonical little-endian M31 coordinates from one authenticated QM31 wire.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 24;
pub const PREPROCESSED_COLUMN_COUNT = 9;
pub const LOGICAL_INPUT_COUNT = 33;
pub const DIRECT_CONSTRAINT_COUNT = 8;
pub const RELATION_EVENT_COUNT = 17;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 9;
pub const INTERACTION_COLUMN_COUNT = 36;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "751f8d3a07d29de0f9e882b13c7b68e11f25cfffcd781620059123ed92a72542") catch @compileError("invalid field byte digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct { source_circuit: u32, source_wire: u32, destination_circuit: u32, destination_first: u32, uses: [4]u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3FieldBytes;
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
    var ids: [LOGICAL_INPUT_COUNT]Id = undefined;
    for (&ids, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_field_bytes.value_{d}", .{i}), if (i >= 4 and i < 20) .byte else .felt, span);
    }
    const enable = ids[24];
    const and_op = try arena.constantUnsigned(.{ .bounded_uint = .{ .bits = 2, .representation = .canonical_field } }, 0, span);
    const high_mask = try arena.constantUnsigned(.byte, 127, span);
    for (0..4) |i| {
        const bytes = ids[4 + i * 4 ..][0..4];
        var sum = bytes[0];
        for (1..4) |j| sum = try arena.add(sum, try arena.mul(bytes[j], try arena.constantField(@as(u32, 1) << @as(u5, @intCast(8 * j)), span), span), span);
        var d = try arena.mul(enable, try arena.constantField(892, span), span);
        for (bytes) |byte| d = try arena.sub(d, byte, span);
        for ([_]Id{ try arena.mul(enable, try arena.sub(sum, ids[i], span), span), try arena.sub(try arena.mul(d, ids[20 + i], span), enable, span) }, 0..) |root, j| {
            var buf: [48]u8 = undefined;
            _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_field_bytes.check_{d}", .{2 * i + j}), root, null, .semantic, span);
        }
        _ = try effects.appendGroup(4, &arena, .{
            .{ .domain = .range_check_8_8, .role = .request, .values = &.{ bytes[0], bytes[1] }, .weight = enable },
            .{ .domain = .range_check_8_8, .role = .request, .values = &.{ bytes[2], bytes[3] }, .weight = enable },
            .{ .domain = .bitwise, .role = .request, .values = &.{ bytes[3], high_mask, bytes[3], and_op }, .weight = enable },
            .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[27], try arena.add(ids[28], try arena.constantField(@intCast(i), span), span) } ++ bytes.*), .weight = ids[29 + i] },
        }, span);
    }
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[25], ids[26] } ++ ids[0..4].*), .weight = enable }}, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*event, i| event.* = @enumFromInt(i);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if (s.source_circuit == s.destination_circuit or s.destination_first > p - 4) return error.InvalidBlake3FieldBytes;
    const fields = [5]u32{ 1, s.source_circuit, s.source_wire, s.destination_circuit, s.destination_first } ++ s.uses;
    var row: Row = @splat(M31.zero());
    for (row[24..], fields) |*value, field| {
        if (field >= p) return error.InvalidBlake3FieldBytes;
        value.* = M31.fromCanonical(field);
    }
    return row;
}
pub fn logicalRow(s: Schedule, value: core.fields.qm31.QM31) !Row {
    var row = try fixedRow(s);
    row[0..4].* = value.toM31Array();
    for (row[0..4], 0..) |coordinate, i| {
        var sum: u32 = 0;
        for (row[4 + 4 * i ..][0..4], 0..) |*byte, j| {
            const n = (coordinate.toU32() >> @as(u5, @intCast(j * 8))) & 255;
            byte.* = M31.fromCanonical(n);
            sum += n;
        }
        row[20 + i] = try M31.fromCanonical(892 - sum).inv();
    }
    return row;
}
