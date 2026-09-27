//! Experimental fixed subtraction-product AIR: (a - b) * factor = output.
//! Its single-use intermediate is local; all external wire uses remain bound.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const product = @import("qm31_mul.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.qm31_sub_mul.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 17;
pub const PREPROCESSED_COLUMN_COUNT: usize = 7;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 24;
pub const DIRECT_CONSTRAINT_COUNT: usize = 5;
pub const RELATION_EVENT_COUNT: usize = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, "9eb981d37251406e7afcc56bf0046686365ea8a20c904c09250fa9310fe28382") catch @compileError("invalid QM31 subtraction-product digest");
    break :blk bytes;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Schedule = struct {
    circuit: u32,
    output: u32,
    minuend: u32,
    subtrahend: u32,
    factor: u32,
    uses: u32,
};
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
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidQm31SubMul;
        for (self.constraints, self.roots, 0..) |constraint, root, i| if (lang.types.idIndex(constraint) != i or (self.arena.constraint(constraint) orelse return error.InvalidQm31SubMul).root != root) return error.InvalidQm31SubMul;
        for (self.events, 0..) |event, i| if (lang.types.idIndex(event) != i) return error.InvalidQm31SubMul;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "qm31_sub_mul.main_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "qm31_sub_mul.fixed_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    var difference: [4]Id = undefined;
    for (&difference, main[1..5], main[5..9]) |*out, a, b| out.* = try arena.sub(a, b, span);
    const expected = try product.productCoordinates(&arena, difference, main[9..13].*, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]Id = undefined;
    roots[0] = try arena.sub(main[0], pp[0], span);
    for (expected, main[13..17], 1..) |value, out, i| roots[i] = try arena.sub(value, out, span);
    var constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, i| {
        var buf: [48]u8 = undefined;
        constraint.* = try arena.assertZero(try std.fmt.bufPrint(&buf, "qm31_sub_mul.constraint_{d}", .{i}), root, null, .semantic, span);
    }
    const events = try effects.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[3] } ++ main[1..5].*), .weight = pp[0] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[4] } ++ main[5..9].*), .weight = pp[0] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[5] } ++ main[9..13].*), .weight = pp[0] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[2] } ++ main[13..17].*), .weight = pp[6] },
    }, span);
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}
pub fn logicalRow(schedule: Schedule, a: QM31, b: QM31, factor: QM31) !Row {
    var result: Row = @splat(M31.zero());
    result[0] = M31.one();
    result[1..5].* = a.toM31Array();
    result[5..9].* = b.toM31Array();
    result[9..13].* = factor.toM31Array();
    result[13..17].* = a.sub(b).mul(factor).toM31Array();
    const pp = result[PHYSICAL_MAIN_COLUMN_COUNT..];
    pp[0] = M31.one();
    for (pp[1..7], [_]u32{ schedule.circuit, schedule.output, schedule.minuend, schedule.subtrahend, schedule.factor, schedule.uses }) |*field, value| {
        if (value >= core.fields.m31.Modulus) return error.InvalidQm31SubMul;
        field.* = M31.fromCanonical(value);
    }
    return result;
}
