//! Four authenticated opening terms accumulated without intermediate wires.
//! The admitted schedule owns every wire coordinate and output multiplicity.
//! The four products remain degree two, with unrestricted QM31 operands.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/mod.zig");
const effects = @import("relation_effect.zig");
const arithmetic = @import("qm31_mul.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.detached_opening_accumulate4.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 41;
pub const PREPROCESSED_COLUMN_COUNT: usize = 13;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 5;
pub const RELATION_EVENT_COUNT: usize = 10;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 5;
pub const INTERACTION_COLUMN_COUNT: usize = 20;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, "9359de479b47fc345f0adb457f6eff19359efa6be4ceffb6aff3fbc11fce18e0") catch @compileError("invalid opening accumulation AIR digest");
    break :blk value;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const TERM_COUNT: usize = 4;
pub const Schedule = struct { circuit: u32, accumulator: u32, lhs: [TERM_COUNT]u32, rhs: [TERM_COUNT]u32, output: u32, uses: u32 };
pub const Definition = struct {
    arena: lang.ir.Arena,
    roots: [DIRECT_CONSTRAINT_COUNT]Id,
    constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        const identity = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidDetachedOpeningAccumulate4;
        for (self.constraints, self.roots, 0..) |constraint, root, i| if (lang.types.idIndex(constraint) != i or (self.arena.constraint(constraint) orelse return error.InvalidDetachedOpeningAccumulate4).root != root) return error.InvalidDetachedOpeningAccumulate4;
        for (self.events, 0..) |event, i| if (lang.types.idIndex(event) != i) return error.InvalidDetachedOpeningAccumulate4;
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}
pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var result = try buildRaw(allocator);
    defer result.deinit();
    return (try lang.digest.computeIdentity(&result.arena)).bytes;
}
fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var main: [PHYSICAL_MAIN_COLUMN_COUNT]Id = undefined;
    var pp: [PREPROCESSED_COLUMN_COUNT]Id = undefined;
    for (&main, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "opening_accumulate4.main_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "opening_accumulate4.fixed_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    var roots: [DIRECT_CONSTRAINT_COUNT]Id = undefined;
    roots[0] = try arena.sub(main[0], pp[0], span);
    const accumulator = main[1..5].*;
    const output = main[37..41].*;
    var expected = accumulator;
    for (0..TERM_COUNT) |term| {
        const lhs = main[5 + term * 4 ..][0..4].*;
        const rhs = main[21 + term * 4 ..][0..4].*;
        const product = try arithmetic.productCoordinates(&arena, lhs, rhs, span);
        for (&expected, product) |*sum, word| sum.* = try arena.add(sum.*, word, span);
    }
    for (expected, output, 1..) |sum, word, i| roots[i] = try arena.sub(sum, word, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, i| {
        var buf: [48]u8 = undefined;
        constraint.* = try arena.assertZero(try std.fmt.bufPrint(&buf, "opening_accumulate4.constraint_{d}", .{i}), root, null, .semantic, span);
    }
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    events[0] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[2] } ++ accumulator), .weight = pp[0] }}, span))[0];
    for (0..TERM_COUNT) |term| {
        events[1 + term * 2] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[3 + term] } ++ main[5 + term * 4 ..][0..4].*), .weight = pp[0] }}, span))[0];
        events[2 + term * 2] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[7 + term] } ++ main[21 + term * 4 ..][0..4].*), .weight = pp[0] }}, span))[0];
    }
    events[9] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[11] } ++ output), .weight = pp[12] }}, span))[0];
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}
pub fn logicalRow(schedule: Schedule, accumulator: QM31, lhs: [TERM_COUNT]QM31, rhs: [TERM_COUNT]QM31, output: QM31) !Row {
    var result: Row = @splat(M31.zero());
    result[0] = M31.one();
    result[1..5].* = accumulator.toM31Array();
    for (lhs, rhs, 0..) |left, right, term| {
        result[5 + term * 4 ..][0..4].* = left.toM31Array();
        result[21 + term * 4 ..][0..4].* = right.toM31Array();
    }
    result[37..41].* = output.toM31Array();
    const pp = result[PHYSICAL_MAIN_COLUMN_COUNT..];
    pp[0] = M31.one();
    const words = .{ schedule.circuit, schedule.accumulator } ++ schedule.lhs ++ schedule.rhs ++ .{ schedule.output, schedule.uses };
    for (pp[1..], words) |*field, word| {
        if (word >= core.fields.m31.Modulus) return error.InvalidDetachedOpeningAccumulate4;
        field.* = M31.fromCanonical(word);
    }
    return result;
}
