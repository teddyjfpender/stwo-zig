//! Compression public-boundary bridge. Fixed columns must be derived from the
//! verifier's statement and canonical plan, not supplied as a prover authority.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const Id = lang.types.ValueId;
const M31 = core.fields.m31.M31;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 4;
pub const PREPROCESSED_COLUMN_COUNT = 8;
pub const LOGICAL_INPUT_COUNT = 12;
pub const DIRECT_CONSTRAINT_COUNT = 4;
pub const RELATION_EVENT_COUNT = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 1;
pub const INTERACTION_COLUMN_COUNT = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "9ea716f35720f161794bbdead035331efaaf25dadf69f34f2bdd2e8f091e76fb") catch @compileError("invalid BLAKE3 boundary digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [1]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 4 or self.arena.effectsView().len != 1) return error.InvalidBlake3Boundary;
    }
};
pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var d = try buildRaw(allocator);
    defer d.deinit();
    return (try lang.digest.computeIdentity(&d.arena)).bytes;
}
pub fn build(allocator: std.mem.Allocator) !Definition {
    var d = try buildRaw(allocator);
    errdefer d.deinit();
    try d.validate();
    return d;
}
fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var ids: [12]Id = undefined;
    for (&ids, 0..) |*id, i| {
        var buf: [40]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_boundary.value_{d}", .{i}), .felt, span);
    }
    for (0..4) |i| {
        var buf: [40]u8 = undefined;
        const root = try arena.mul(ids[4], try arena.sub(ids[i], ids[8 + i], span), span);
        _ = try arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_boundary.byte_{d}", .{i}), root, null, .semantic, span);
    }
    const events = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[5], ids[6] } ++ ids[0..4].*), .weight = ids[7] }}, span);
    return .{ .arena = arena, .events = events };
}
pub fn logicalRow(circuit: u32, wire: u32, weight: M31, expected: u32) !Row {
    var coordinates: [4]M31 = undefined;
    for (&coordinates, 0..) |*byte, i| byte.* = M31.fromCanonical((expected >> @as(u5, @intCast(i * 8))) & 255);
    return logicalCoordinates(circuit, wire, weight, coordinates);
}
/// Bind arbitrary field coordinates, including scalar challenge wires. This
/// preserves the same AIR; packed hash words use logicalRow's byte encoding.
pub fn logicalCoordinates(circuit: u32, wire: u32, weight: M31, coordinates: [4]M31) !Row {
    if (circuit >= core.fields.m31.Modulus or wire >= core.fields.m31.Modulus) return error.InvalidBlake3Boundary;
    var row: Row = undefined;
    row[0..4].* = coordinates;
    row[8..12].* = coordinates;
    row[4..8].* = .{ M31.one(), M31.fromCanonical(circuit), M31.fromCanonical(wire), weight };
    return row;
}
