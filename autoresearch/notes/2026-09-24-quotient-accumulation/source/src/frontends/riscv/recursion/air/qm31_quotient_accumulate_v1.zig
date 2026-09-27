//! Native positive quotient accumulation with an explicit nonzero denominator.
//! Single-use reciprocal and product wires remain local to this component.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.qm31_quotient_accumulate.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 21;
pub const PREPROCESSED_COLUMN_COUNT: usize = 7;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 9;
pub const RELATION_EVENT_COUNT: usize = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var value: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&value, "4546ad4a7d14d5e7143930e6538d53faf4e8948431f3e443e8d54579e157ce75") catch @compileError("invalid quotient accumulation AIR digest");
    break :blk value;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct { circuit: u32, denominator: u32, numerator: u32, accumulator: u32, output: u32, uses: u32 };
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
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidQm31QuotientAccumulate;
        for (self.constraints, self.roots, 0..) |constraint, root, i| if (lang.types.idIndex(constraint) != i or (self.arena.constraint(constraint) orelse return error.InvalidQm31QuotientAccumulate).root != root) return error.InvalidQm31QuotientAccumulate;
        for (self.events, 0..) |event, i| if (lang.types.idIndex(event) != i) return error.InvalidQm31QuotientAccumulate;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "qm31_quotient_accumulate.main_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "qm31_quotient_accumulate.fixed_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    var roots: [DIRECT_CONSTRAINT_COUNT]Id = undefined;
    roots[0] = try arena.sub(main[0], pp[0], span);
    const product = @import("qm31_mul.zig");
    const denominator = main[1..5].*;
    const reciprocal_product = try product.productCoordinates(&arena, denominator, main[17..21].*, span);
    const zero = try arena.constantField(0, span);
    for (reciprocal_product, 0..) |word, i| roots[1 + i] = try arena.sub(word, if (i == 0) main[0] else zero, span);
    var delta: [4]Id = undefined;
    for (&delta, main[13..17], main[9..13]) |*word, output, accumulator| word.* = try arena.sub(output, accumulator, span);
    const recovered = try product.productCoordinates(&arena, denominator, delta, span);
    for (recovered, main[5..9], 0..) |word, numerator, i| roots[5 + i] = try arena.sub(word, numerator, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, i| {
        var buf: [48]u8 = undefined;
        constraint.* = try arena.assertZero(try std.fmt.bufPrint(&buf, "qm31_quotient_accumulate.constraint_{d}", .{i}), root, null, .semantic, span);
    }
    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    for (0..3) |i| events[i] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[2 + i] } ++ main[1 + 4 * i ..][0..4].*), .weight = pp[0] }}, span))[0];
    events[3] = (try effects.appendGroup(1, &arena, .{.{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[5] } ++ main[13..17].*), .weight = pp[6] }}, span))[0];
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}
pub fn logicalRow(schedule: Schedule, denominator: QM31, numerator: QM31, accumulator: QM31) !Row {
    const reciprocal = try denominator.inv();
    var result: Row = @splat(M31.zero());
    result[0] = M31.one();
    result[1..5].* = denominator.toM31Array();
    result[5..9].* = numerator.toM31Array();
    result[9..13].* = accumulator.toM31Array();
    result[13..17].* = accumulator.add(numerator.mul(reciprocal)).toM31Array();
    result[17..21].* = reciprocal.toM31Array();
    const words = [_]u32{ 1, schedule.circuit, schedule.denominator, schedule.numerator, schedule.accumulator, schedule.output, schedule.uses };
    for (result[PHYSICAL_MAIN_COLUMN_COUNT..], words) |*field, word| {
        if (word >= core.fields.m31.Modulus) return error.InvalidQm31QuotientAccumulate;
        field.* = M31.fromCanonical(word);
    }
    return result;
}
