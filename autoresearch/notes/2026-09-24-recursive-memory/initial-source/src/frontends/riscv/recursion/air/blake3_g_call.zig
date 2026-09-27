//! Packed G with authenticated-plan wire endpoints. All fixed columns must be
//! committed by the verifier's key. Padding retains valid zero-table requests.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const arithmetic = @import("blake3_g_packed.zig");
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
pub const PHYSICAL_MAIN_COLUMN_COUNT = arithmetic.COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = 16;
pub const LOGICAL_INPUT_COUNT = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const DIRECT_CONSTRAINT_COUNT = arithmetic.CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT = arithmetic.EVENT_COUNT + 10;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = @as(usize, RELATION_EVENT_COUNT) / LOOKUP_BATCH_SIZE;
pub const INTERACTION_COLUMN_COUNT = INTERACTION_BATCH_COUNT * 4;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "aa7e3136eb8a2694fb077f3ba8026a65b94cff70d2361827bcaa6d6f9d9de897") catch @compileError("invalid BLAKE3 G call digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct { circuit: u32, input: [6]u32, output: [4]u32, uses: [4]u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3GCall;
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
    const ordered = try arithmetic.buildForCall(PREPROCESSED_COLUMN_COUNT, allocator);
    var base = ordered.definition;
    errdefer base.deinit();
    const arena = &base.arena;
    const span = lang.source.SourceSpan.generated();
    const pp = ordered.fixed;
    for (base.input, 0..) |word, i| {
        _ = try effects.appendGroup(1, arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[2 + i] } ++ word), .weight = pp[0] }}, span);
    }
    for (base.output, 0..) |word, i| {
        _ = try effects.appendGroup(1, arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[8 + i] } ++ word), .weight = pp[12 + i] }}, span);
    }
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*id, i| id.* = @enumFromInt(i);
    return .{ .arena = base.arena, .events = events };
}
pub fn logicalRow(schedule: Schedule, input: [6]u32) !Row {
    var row = try fixedRow(schedule);
    row[0..PHYSICAL_MAIN_COLUMN_COUNT].* = try arithmetic.witness(input);
    return row;
}
pub fn fixedRow(schedule: Schedule) !Row {
    var row: Row = @splat(M31.zero());
    const pp = [2]u32{ 1, schedule.circuit } ++ schedule.input ++ schedule.output ++ schedule.uses;
    for (row[PHYSICAL_MAIN_COLUMN_COUNT..], pp) |*field, word| {
        if (word >= core.fields.m31.Modulus) return error.InvalidBlake3GCall;
        field.* = M31.fromCanonical(word);
    }
    return row;
}
