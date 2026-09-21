//! Detached verifier multiplication and multiply-add with fixed wire routing.
//! The product remains local when its only authenticated consumer is the sum.
//! Schedule coefficients are preprocessing, never proof-dependent selectors.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const product = @import("qm31_mul.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Id = lang.types.ValueId;
pub const STABLE_NAME = "recursion.qm31_mul_add.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 17;
pub const PREPROCESSED_COLUMN_COUNT: usize = 10;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = 27;
pub const DIRECT_CONSTRAINT_COUNT: usize = 5;
pub const RELATION_EVENT_COUNT: usize = 4;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 2;
pub const INTERACTION_COLUMN_COUNT: usize = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, "eb8d491f5b07bf17fb4b6b4e7c408da1289dd1907b66926547bd39d204b0f849") catch @compileError("invalid QM31 multiply-add digest");
    break :blk bytes;
};
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Operation = enum {
    multiply,
    product_plus_addend,
    product_minus_addend,
    addend_minus_product,
    pub fn apply(self: Operation, a: QM31, b: QM31, addend: QM31) QM31 {
        const ab = a.mul(b);
        return switch (self) {
            .multiply => ab,
            .product_plus_addend => ab.add(addend),
            .product_minus_addend => ab.sub(addend),
            .addend_minus_product => addend.sub(ab),
        };
    }
};
pub const Schedule = struct {
    circuit: u32,
    output: u32,
    lhs: u32,
    rhs: u32,
    addend: u32 = 0,
    uses: u32,
    operation: Operation = .multiply,
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
        if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidQm31MulAdd;
        for (self.constraints, self.roots, 0..) |constraint, root, i| if (lang.types.idIndex(constraint) != i or (self.arena.constraint(constraint) orelse return error.InvalidQm31MulAdd).root != root) return error.InvalidQm31MulAdd;
        for (self.events, 0..) |event, i| if (lang.types.idIndex(event) != i) return error.InvalidQm31MulAdd;
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
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "qm31_mul_add.main_{d}", .{i}), if (i == 0) .selector else .felt, span);
    }
    for (&pp, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "qm31_mul_add.fixed_{d}", .{i}), if (i == 0 or i == 7) .selector else .felt, span);
    }
    const expected = try product.productCoordinates(&arena, main[1..5].*, main[5..9].*, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]Id = undefined;
    roots[0] = try arena.sub(main[0], pp[0], span);
    // a*b = output_sign*out + addend_coefficient*c. Both sides have
    // degree two, including the verifier-owned preprocessing columns.
    for (expected, main[9..13], main[13..17], 1..) |ab, c, out, i| {
        roots[i] = try arena.sub(ab, try arena.add(try arena.mul(pp[8], out, span), try arena.mul(pp[9], c, span), span), span);
    }
    var constraints: [DIRECT_CONSTRAINT_COUNT]lang.types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, i| {
        var buf: [48]u8 = undefined;
        constraint.* = try arena.assertZero(try std.fmt.bufPrint(&buf, "qm31_mul_add.constraint_{d}", .{i}), root, null, .semantic, span);
    }
    const events = try effects.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[3] } ++ main[1..5].*), .weight = pp[0] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[4] } ++ main[5..9].*), .weight = pp[0] },
        .{ .domain = .recursion_wire, .role = .consume, .values = &(.{ pp[1], pp[5] } ++ main[9..13].*), .weight = pp[7] },
        .{ .domain = .recursion_wire, .role = .emit, .values = &(.{ pp[1], pp[2] } ++ main[13..17].*), .weight = pp[6] },
    }, span);
    return .{ .arena = arena, .roots = roots, .constraints = constraints, .events = events };
}
pub fn logicalRow(schedule: Schedule, a: QM31, b: QM31, addend: QM31) !Row {
    if (schedule.operation == .multiply and (!addend.isZero() or schedule.addend != 0)) return error.InvalidQm31MulAdd;
    var result: Row = @splat(M31.zero());
    result[0] = M31.one();
    result[1..5].* = a.toM31Array();
    result[5..9].* = b.toM31Array();
    result[9..13].* = addend.toM31Array();
    result[13..17].* = schedule.operation.apply(a, b, addend).toM31Array();
    const pp = result[PHYSICAL_MAIN_COLUMN_COUNT..];
    pp[0] = M31.one();
    for (pp[1..7], [_]u32{ schedule.circuit, schedule.output, schedule.lhs, schedule.rhs, schedule.addend, schedule.uses }) |*field, value| {
        if (value >= core.fields.m31.Modulus) return error.InvalidQm31MulAdd;
        field.* = M31.fromCanonical(value);
    }
    pp[7] = if (schedule.operation == .multiply) M31.zero() else M31.one();
    pp[8] = if (schedule.operation == .addend_minus_product) M31.one().neg() else M31.one();
    pp[9] = switch (schedule.operation) {
        .multiply => M31.zero(),
        .product_plus_addend => M31.one().neg(),
        .product_minus_addend, .addend_minus_product => M31.one(),
    };
    return result;
}
