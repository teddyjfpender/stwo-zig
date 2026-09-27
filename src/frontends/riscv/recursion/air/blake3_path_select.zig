//! Conditional Merkle word swap driven by an authenticated scalar query bit.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 17;
pub const PREPROCESSED_COLUMN_COUNT = 12;
pub const LOGICAL_INPUT_COUNT = 29;
pub const DIRECT_CONSTRAINT_COUNT = 9;
pub const RELATION_EVENT_COUNT = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 3;
pub const INTERACTION_COLUMN_COUNT = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "ca02f857d38bd44000ddfe833db1ce15cee6a3d983921b01facef5b5df665b7f") catch @compileError("invalid path select digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Endpoint = @import("blake3_byte_route.zig").Endpoint;
pub const Schedule = struct { bit: Endpoint, current: Endpoint, sibling: Endpoint, destination_circuit: u32, left_wire: u32, right_wire: u32, left_uses: u32, right_uses: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3PathSelect;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_path_select.value_{d}", .{i}), .felt, span);
    }
    _ = try arena.assertZero("blake3_path_select.bit", try arena.mul(ids[0], try arena.sub(ids[0], ids[17], span), span), null, .semantic, span);
    for (0..4) |i| {
        const delta = try arena.mul(ids[0], try arena.sub(ids[5 + i], ids[1 + i], span), span);
        var buf: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_path_select.left_{d}", .{i}), try arena.sub(ids[9 + i], try arena.add(ids[1 + i], delta, span), span), null, .semantic, span);
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_path_select.right_{d}", .{i}), try arena.sub(ids[13 + i], try arena.sub(ids[5 + i], delta, span), span), null, .semantic, span);
    }
    const zero = try arena.constantField(0, span);
    const events = try effects.appendGroup(5, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[18], ids[19], ids[0], zero, zero, zero }, .weight = ids[17] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[20], ids[21] } ++ ids[1..5].*), .weight = ids[17] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[22], ids[23] } ++ ids[5..9].*), .weight = ids[17] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[24], ids[25] } ++ ids[9..13].*), .weight = ids[27] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[24], ids[26] } ++ ids[13..17].*), .weight = ids[28] },
    }, span);
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    if (s.destination_circuit == s.current.circuit or s.destination_circuit == s.sibling.circuit or s.left_wire == s.right_wire or (s.left_uses == 0 and s.right_uses == 0)) return error.InvalidBlake3PathSelect;
    var row: Row = @splat(M31.zero());
    const fields = [_]u32{ 1, s.bit.circuit, s.bit.wire, s.current.circuit, s.current.wire, s.sibling.circuit, s.sibling.wire, s.destination_circuit, s.left_wire, s.right_wire, s.left_uses, s.right_uses };
    for (row[17..], fields) |*out, field| {
        if (field >= core.fields.m31.Modulus) return error.InvalidBlake3PathSelect;
        out.* = M31.fromCanonical(field);
    }
    return row;
}
pub fn logicalRow(s: Schedule, bit: u1, current: u32, sibling: u32) !Row {
    var row = try fixedRow(s);
    row[0] = M31.fromCanonical(bit);
    for (0..4) |i| {
        const shift: u5 = @intCast(i * 8);
        row[1 + i] = M31.fromCanonical((current >> shift) & 255);
        row[5 + i] = M31.fromCanonical((sibling >> shift) & 255);
        row[9 + i] = row[(if (bit == 0) @as(usize, 1) else 5) + i];
        row[13 + i] = row[(if (bit == 0) @as(usize, 5) else 1) + i];
    }
    return row;
}
