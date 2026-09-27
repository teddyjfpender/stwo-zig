//! Caller-bound round: fixed imports/exports, with internal G wires eliminated.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const arithmetic = @import("blake3_round_packed.zig");
const g_arithmetic = @import("blake3_g_packed.zig");
const effects = @import("relation_effect.zig");
const Id = lang.types.ValueId;
pub const DIRECT_PROGRAM_NODE_LIMIT: usize = 4096;
pub const DIRECT_PROGRAM_CONSTRAINT_LIMIT: usize = 768;
pub const PHYSICAL_MAIN_COLUMN_COUNT = arithmetic.COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = 66;
pub const LOGICAL_INPUT_COUNT = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const DIRECT_CONSTRAINT_COUNT = arithmetic.CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT = arithmetic.EVENT_COUNT + 48;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = @as(usize, RELATION_EVENT_COUNT) / LOOKUP_BATCH_SIZE;
pub const INTERACTION_COLUMN_COUNT = INTERACTION_BATCH_COUNT * 4;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "f7dedd17e90886b9c829575f4d9504c8a0761199e82bdcf1b53933ae7fc2640f") catch @compileError("invalid BLAKE3 round digest");
    break :blk out;
};
pub const Row = [LOGICAL_INPUT_COUNT]core.fields.m31.M31;
pub const Schedule = struct { circuit: u32, input: [32]u32, output: [16]u32, uses: [16]u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    ports: arithmetic.Ports,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const id = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &id.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3RoundGeometry;
    }
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
};
pub fn build(a: std.mem.Allocator) !Definition {
    var result = try buildRaw(a);
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn computeSemanticDigest(a: std.mem.Allocator) ![32]u8 {
    var result = try buildRaw(a);
    defer result.deinit();
    return (try lang.digest.computeIdentity(&result.arena)).bytes;
}
fn buildRaw(a: std.mem.Allocator) !Definition {
    var source = try arithmetic.build(a);
    defer source.deinit();
    var ops = g_arithmetic.Typed{ .arena = lang.ir.Arena.init(a) };
    errdefer ops.arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var ids: [PHYSICAL_MAIN_COLUMN_COUNT]Id = undefined;
    var next: usize = 0;
    for (source.arena.nodesView()) |node| {
        if (node.key.op != .input) continue;
        var buf: [48]u8 = undefined;
        ids[next] = try ops.arena.input(try std.fmt.bufPrint(&buf, "blake3_round.value_{d}", .{next}), node.key.ty, span);
        next += 1;
    }
    if (next != ids.len) return error.InvalidBlake3RoundGeometry;
    var pp: [PREPROCESSED_COLUMN_COUNT]Id = undefined;
    for (&pp, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try ops.arena.input(try std.fmt.bufPrint(&buf, "blake3_round.fixed_{d}", .{i}), .felt, span);
    }
    ops.predeclared = &ids;
    const ports = try arithmetic.populate(&ops);
    for (ports.input, 0..) |word, i| _ = try effects.appendGroup(1, &ops.arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[2 + i] } ++ word), .weight = pp[0] }}, span);
    for (ports.output, 0..) |word, i| _ = try effects.appendGroup(1, &ops.arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[34 + i] } ++ word), .weight = pp[50 + i] }}, span);
    try lang.validate.validate(&ops.arena);
    if (ops.columns != PHYSICAL_MAIN_COLUMN_COUNT or ops.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or ops.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidBlake3RoundGeometry;
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (&events, 0..) |*id, i| id.* = @enumFromInt(i);
    return .{ .arena = ops.arena, .ports = ports, .events = events };
}
pub fn fixedRow(schedule: Schedule) !Row {
    var row: Row = @splat(core.fields.m31.M31.zero());
    const fields = [2]u32{ 1, schedule.circuit } ++ schedule.input ++ schedule.output ++ schedule.uses;
    for (row[PHYSICAL_MAIN_COLUMN_COUNT..], fields) |*field, value| {
        if (value >= core.fields.m31.Modulus) return error.InvalidBlake3RoundSchedule;
        field.* = core.fields.m31.M31.fromCanonical(value);
    }
    return row;
}
pub fn logicalRow(schedule: Schedule, input: [32]u32) !Row {
    var row = try fixedRow(schedule);
    row[0..PHYSICAL_MAIN_COLUMN_COUNT].* = (try arithmetic.witness(input)).row;
    return row;
}
