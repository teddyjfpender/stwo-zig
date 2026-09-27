//! Private base-field wire producer. Authentication comes from joined consumers.
//! Three extension coordinates are literal zero in the emitted tuple.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 1;
pub const PREPROCESSED_COLUMN_COUNT = 6;
pub const LOGICAL_INPUT_COUNT = 7;
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 1;
pub const INTERACTION_COLUMN_COUNT = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, "0e9790e1ea7f067a8fdfb5c82d3da5ed184bb81cf44aef07493f7c67a6a005de") catch @compileError("invalid scalar wire digest");
    break :blk bytes;
};
pub const Row = [7]M31;
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [2]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 0 or self.arena.effectsView().len != 2) return error.InvalidScalarWireSource;
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
    var ids: [7]lang.types.ValueId = undefined;
    for (&ids, 0..) |*id, i| {
        var buf: [40]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "scalar_wire_source.value_{d}", .{i}), .felt, span);
    }
    const zero = try arena.constantField(0, span);
    const events = try effects.appendGroup(2, &arena, .{
        .{ .domain = .recursion_wire, .role = .emit, .values = &.{ ids[1], ids[2], ids[0], zero, zero, zero }, .weight = ids[3] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &.{ ids[4], ids[5], ids[0], zero, zero, zero }, .weight = ids[6] },
    }, span);
    return .{ .arena = arena, .events = events };
}
pub fn logicalRow(circuit: u32, node: u32, uses: u32, value: M31) !Row {
    const p = core.fields.m31.Modulus;
    if (circuit >= p or node >= p or uses >= p or value.v >= p) return error.InvalidScalarWireSource;
    return .{ value, M31.fromCanonical(circuit), M31.fromCanonical(node), M31.fromCanonical(uses), M31.zero(), M31.zero(), M31.zero() };
}

/// Route a canonical scalar producer into a query-specific arithmetic node.
pub fn routedRow(circuit: u32, node: u32, uses: u32, source_circuit: u32, source_node: u32, value: M31) !Row {
    if (source_circuit >= core.fields.m31.Modulus or source_node >= core.fields.m31.Modulus or (source_circuit == circuit and source_node == node)) return error.InvalidScalarWireSource;
    var row = try logicalRow(circuit, node, uses, value);
    row[4..7].* = .{ M31.fromCanonical(source_circuit), M31.fromCanonical(source_node), M31.one() };
    return row;
}
