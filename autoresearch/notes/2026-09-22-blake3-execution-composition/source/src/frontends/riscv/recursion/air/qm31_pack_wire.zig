//! Repack four scalar recursion wires into one QM31 wire without host-only joins.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
pub const PREPROCESSED_COLUMN_COUNT = 8;
pub const LOGICAL_INPUT_COUNT = 12;
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 5;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 3;
pub const INTERACTION_COLUMN_COUNT = 12;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, "aa96adb02a58779fe9b1248419126894a259c0c4e2c3ebedc1717e7f089db58b") catch @compileError("invalid QM31 packing digest");
    break :blk bytes;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct { source_circuit: u32, source_nodes: [4]u32, destination_circuit: u32, destination_wire: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 0 or self.arena.effectsView().len != 5) return error.InvalidQm31PackWire;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "qm31_pack_wire.value_{d}", .{i}), .felt, span);
    }
    const zero = try arena.constantField(0, span);
    var events: [5]lang.types.EffectId = undefined;
    for (0..4) |i| events[i] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[5], ids[6 + i], ids[i], zero, zero, zero }, .weight = ids[4] }}, span))[0];
    events[4] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[10], ids[11] } ++ ids[0..4].*), .weight = ids[4] }}, span))[0];
    return .{ .arena = arena, .events = events };
}
pub fn fixedRow(s: Schedule) !Row {
    const p = core.fields.m31.Modulus;
    if (s.source_circuit >= p or s.destination_circuit >= p or s.source_circuit == s.destination_circuit or s.destination_wire >= p) return error.InvalidQm31PackWire;
    var row: Row = @splat(M31.zero());
    row[4] = M31.one();
    row[5] = M31.fromCanonical(s.source_circuit);
    for (s.source_nodes, 0..) |node, i| {
        if (node >= p) return error.InvalidQm31PackWire;
        row[6 + i] = M31.fromCanonical(node);
    }
    row[10] = M31.fromCanonical(s.destination_circuit);
    row[11] = M31.fromCanonical(s.destination_wire);
    return row;
}
pub fn logicalRow(s: Schedule, value: core.fields.qm31.QM31) !Row {
    var row = try fixedRow(s);
    const coordinates = value.toM31Array();
    for (coordinates) |c| if (c.v >= core.fields.m31.Modulus) return error.InvalidQm31PackWire;
    row[0..4].* = coordinates;
    return row;
}

/// The existing AIR weights every consume and emit by column 4. Positive
/// multiplicity supports several secure consumers without duplicate pack rows.
pub fn weightedFixedRow(s: Schedule, multiplicity: u32) !Row {
    if (multiplicity == 0 or multiplicity >= core.fields.m31.Modulus) return error.InvalidQm31PackWire;
    var row = try fixedRow(s);
    row[4] = M31.fromCanonical(multiplicity);
    return row;
}
pub fn weightedLogicalRow(s: Schedule, value: core.fields.qm31.QM31, multiplicity: u32) !Row {
    var row = try logicalRow(s, value);
    row[4] = (try weightedFixedRow(s, multiplicity))[4];
    return row;
}
