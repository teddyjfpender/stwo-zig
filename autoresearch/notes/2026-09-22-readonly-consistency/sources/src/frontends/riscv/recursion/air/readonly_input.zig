//! Authenticate bounded u32 index bytes and a scalar value into a read-only tuple.
//! The index provider must constrain all four consumed coordinates to bytes.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 5;
pub const PREPROCESSED_COLUMN_COUNT = 6;
pub const LOGICAL_INPUT_COUNT = 11;
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "79d8d1f12a6892a82e5d7ac54bc0b5ef4f1f32771e0e1b26e27c7866852a797d") catch @compileError("invalid read-only input digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Endpoint = @import("blake3_byte_route.zig").Endpoint;
pub const Schedule = struct { index: Endpoint, value: Endpoint, table: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidReadonlyInput;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "readonly_input.value_{d}", .{i}), .felt, span);
    }
    const zero = try arena.constantField(0, span);
    const radix = try arena.constantField(256, span);
    const lo = try arena.add(ids[0], try arena.mul(radix, ids[1], span), span);
    const hi = try arena.add(ids[2], try arena.mul(radix, ids[3], span), span);
    const events = try effects.appendGroup(3, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[6], ids[7] } ++ ids[0..4].*), .weight = ids[5] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[8], ids[9], ids[4], zero, zero, zero }, .weight = ids[5] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[10], lo, hi, ids[4], zero, zero }, .weight = ids[5] },
    }, span);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    if (s.table == s.index.circuit or s.table == s.value.circuit or std.meta.eql(s.index, s.value)) return error.InvalidReadonlyInput;
    var row: Row = @splat(M31.zero());
    const fields = [_]u32{ 1, s.index.circuit, s.index.wire, s.value.circuit, s.value.wire, s.table };
    for (row[5..], fields) |*out, value| {
        if (value >= core.fields.m31.Modulus) return error.InvalidReadonlyInput;
        out.* = M31.fromCanonical(value);
    }
    return row;
}
pub fn logicalRow(s: Schedule, index: u32, value: M31) !Row {
    if (value.v >= core.fields.m31.Modulus) return error.InvalidReadonlyInput;
    var row = try fixedRow(s);
    for (0..4) |i| row[i] = M31.fromCanonical((index >> @as(u5, @intCast(8 * i))) & 255);
    row[4] = value;
    return row;
}
