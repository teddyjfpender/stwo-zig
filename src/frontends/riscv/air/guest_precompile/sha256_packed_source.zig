//! SHA DAG sources: caller-bound initial/message words and fixed K constants.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/definition.zig");
const effects = @import("../../recursion/air/relation_effect.zig");
const graph = @import("sha256_compression_graph.zig");
const sha = @import("sha256_compression.zig");
const M = core.fields.m31.M31;
const span = lang.source.SourceSpan.generated();
pub const production_active = false;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, "0a79e0274e7ab21fac36ac10fc0034f10ec871e0128e0f9f29301272c60532b2") catch unreachable;
    break :blk result;
};
pub const PHYSICAL_MAIN_COLUMN_COUNT = 5;
pub const PREPROCESSED_COLUMN_COUNT = 8;
pub const LOGICAL_INPUT_COUNT = 13;
pub const DIRECT_CONSTRAINT_COUNT = 4;
pub const RELATION_EVENT_COUNT = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn validate(self: *const @This()) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.effectsView().len != RELATION_EVENT_COUNT or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT) return error.InvalidShaSourceSemantics;
    }
    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
    }
};
pub fn build(a: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    var ids: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&ids, 0..) |*id, i| {
        var name: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "sha.source.value_{d}", .{i}), if (i < 4) .byte else .felt, span);
    }
    const one = try arena.constantField(1, span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = ids[0..2], .weight = one }}, span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = ids[2..4], .weight = one }}, span);
    for (0..4) |i| {
        var name: [48]u8 = undefined;
        _ = try arena.assertZero(try std.fmt.bufPrint(&name, "sha.source.constant_{d}", .{i}), try arena.mul(ids[8], try arena.sub(ids[i], ids[9 + i], span), span), null, .semantic, span);
    }
    const boundary = try arena.add(ids[5], try arena.constantField(graph.input_boundary_offset, span), span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ ids[4], boundary } ++ ids[0..4].*), .weight = ids[7] }}, span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ ids[4], ids[5] } ++ ids[0..4].*), .weight = ids[6] }}, span);
    try lang.validate.validate(&arena);
    const result = Definition{ .arena = arena, .events = .{ @enumFromInt(0), @enumFromInt(1), @enumFromInt(2), @enumFromInt(3) } };
    try result.validate();
    return result;
}
pub fn row(call_id: u32, wire: u32, value: u32, uses: *const [graph.wire_count]u32) !Row {
    if (call_id == 0 or call_id >= core.fields.m31.Modulus or wire >= graph.source_count) return error.InvalidShaSource;
    var result: Row = @splat(M.zero());
    for (0..4) |i| result[i] = M.fromCanonical((value >> @as(u5, @intCast(i * 8))) & 255);
    result[4] = M.fromCanonical(call_id);
    result[5] = M.fromCanonical(wire);
    result[6] = M.fromCanonical(uses[wire]);
    if (wire < 24) {
        result[7] = M.one();
    } else {
        result[8] = M.one();
        const constant = sha.round_constants[wire - 24];
        for (0..4) |i| result[9 + i] = M.fromCanonical((constant >> @as(u5, @intCast(i * 8))) & 255);
    }
    return result;
}
