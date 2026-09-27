//! Bytewise feedforward XOR, with wire endpoints from a verifier-owned plan.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 12;
pub const PREPROCESSED_COLUMN_COUNT = 6;
pub const LOGICAL_INPUT_COUNT = 18;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 7;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 4;
pub const INTERACTION_COLUMN_COUNT = 16;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "46f94e6dd6cfca03e0995cdd905f95f9bedc3aa477b47c38c9474f0a3f47405e") catch @compileError("invalid BLAKE3 XOR call digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct { circuit: u32, input: [2]u32, output: u32, uses: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != 0 or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3XorCall;
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
    var main: [12]Id = undefined;
    var pp: [6]Id = undefined;
    for (&main, 0..) |*id, i| {
        var buf: [40]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_xor.byte_{d}", .{i}), .byte, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [40]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_xor.fixed_{d}", .{i}), .felt, span);
    }
    const operation = try arena.constantUnsigned(.{ .bounded_uint = .{ .bits = 2, .representation = .canonical_field } }, 2, span);
    for (0..4) |i| _ = try effects.appendGroup(1, &arena, .{.{ .domain = .bitwise, .role = .request, .values = &.{ main[i], main[4 + i], main[8 + i], operation }, .weight = pp[0] }}, span);
    for (0..2) |i| _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[2 + i] } ++ main[4 * i ..][0..4].*), .weight = pp[0] }}, span);
    _ = try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[4] } ++ main[8..12].*), .weight = pp[5] }}, span);
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*id, i| id.* = @enumFromInt(i);
    return .{ .arena = arena, .events = events };
}
pub fn logicalRow(schedule: Schedule, input: [2]u32) !Row {
    var row = try fixedRow(schedule);
    for ([3]u32{ input[0], input[1], input[0] ^ input[1] }, 0..) |word, i| for (0..4) |j| {
        row[i * 4 + j] = M31.fromCanonical((word >> @as(u5, @intCast(j * 8))) & 255);
    };
    return row;
}
pub fn fixedRow(schedule: Schedule) !Row {
    var row: Row = @splat(M31.zero());
    const pp = [6]u32{ 1, schedule.circuit, schedule.input[0], schedule.input[1], schedule.output, schedule.uses };
    for (row[12..], pp) |*field, word| {
        if (word >= core.fields.m31.Modulus) return error.InvalidBlake3XorCall;
        field.* = M31.fromCanonical(word);
    }
    return row;
}
