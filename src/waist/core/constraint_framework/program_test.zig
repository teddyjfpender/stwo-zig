const std = @import("std");
const cf = @import("mod.zig");
const expr = @import("expr.zig");
const program_mod = @import("program.zig");
const M31 = @import("../fields/m31.zig").M31;
const QM31 = @import("../fields/qm31.zig").QM31;

fn build(
    arena: *cf.ExprArena,
    evaluator: *cf.ExprEvaluator,
    constant: u32,
) !void {
    const column = try evaluator.nextTraceMask();
    const parameter = try arena.baseParam("scale");
    const scaled = try evaluator.addIntermediate(
        try arena.baseMul(column, parameter),
    );
    const base = try arena.baseAdd(
        scaled,
        try arena.baseConst(M31.fromCanonical(constant)),
    );
    const extension = try arena.extFromBase(base);
    try evaluator.addConstraint(extension);
    try evaluator.addConstraint(try arena.extMul(
        extension,
        try arena.extParam("challenge"),
    ));
}

test "constraint program is canonical and evaluates symbolic expressions" {
    const allocator = std.testing.allocator;
    var arena = cf.ExprArena.init(allocator);
    defer arena.deinit();
    var evaluator = try cf.ExprEvaluator.init(&arena, allocator);
    defer evaluator.deinit();
    try build(&arena, &evaluator, 7);

    var program = try program_mod.lower(allocator, &evaluator);
    defer program.deinit(allocator);
    try program.validate();
    try std.testing.expectEqual(@as(usize, 2), program.constraint_roots.len);
    try std.testing.expectEqualStrings("scale", program.base_parameters[0]);
    try std.testing.expectEqualStrings(
        "challenge",
        program.extension_parameters[0],
    );

    var assignment = expr.Assignment.init(allocator);
    defer assignment.deinit();
    try assignment.setColumn(
        .{ .interaction = 1, .idx = 0, .offset = 0 },
        M31.fromCanonical(5),
    );
    try assignment.setParam("scale", M31.fromCanonical(3));
    const challenge = QM31.fromM31Array(.{
        M31.fromCanonical(11),
        M31.fromCanonical(13),
        M31.fromCanonical(17),
        M31.fromCanonical(19),
    });
    try assignment.setExtParam("challenge", challenge);
    try assignment.setParam("intermediate0", M31.fromCanonical(15));

    const actual = try program.evaluate(allocator, &assignment);
    defer allocator.free(actual);
    for (evaluator.constraints.items, actual) |constraint, value| {
        try std.testing.expect((try expr.evalExt(constraint, &assignment)).eql(value));
    }
}

test "constraint program digest is stable and semantic" {
    const allocator = std.testing.allocator;
    var first_arena = cf.ExprArena.init(allocator);
    defer first_arena.deinit();
    var first_eval = try cf.ExprEvaluator.init(&first_arena, allocator);
    defer first_eval.deinit();
    try build(&first_arena, &first_eval, 7);

    var second_arena = cf.ExprArena.init(allocator);
    defer second_arena.deinit();
    var second_eval = try cf.ExprEvaluator.init(&second_arena, allocator);
    defer second_eval.deinit();
    try build(&second_arena, &second_eval, 7);

    var changed_arena = cf.ExprArena.init(allocator);
    defer changed_arena.deinit();
    var changed_eval = try cf.ExprEvaluator.init(&changed_arena, allocator);
    defer changed_eval.deinit();
    try build(&changed_arena, &changed_eval, 8);

    var first = try program_mod.lower(allocator, &first_eval);
    defer first.deinit(allocator);
    var second = try program_mod.lower(allocator, &second_eval);
    defer second.deinit(allocator);
    var changed = try program_mod.lower(allocator, &changed_eval);
    defer changed.deinit(allocator);

    const first_digest = try first.semanticDigest();
    const second_digest = try second.semanticDigest();
    const changed_digest = try changed.semanticDigest();
    try std.testing.expectEqual(first_digest, second_digest);
    try std.testing.expect(!std.mem.eql(u8, &first_digest, &changed_digest));
}

test "constraint program rejects forward references and empty roots" {
    var invalid = program_mod.Program{
        .base = @constCast(&[_]program_mod.BaseInstruction{
            .{ .neg = 0 },
        }),
        .extension = @constCast(&[_]program_mod.ExtInstruction{}),
        .base_parameters = @constCast(&[_][]u8{}),
        .extension_parameters = @constCast(&[_][]u8{}),
        .constraint_roots = @constCast(&[_]u32{}),
    };
    try std.testing.expectError(
        error.EmptyConstraintProgram,
        invalid.validate(),
    );

    invalid.constraint_roots = @constCast(&[_]u32{0});
    try std.testing.expectError(
        error.InvalidBaseInstruction,
        invalid.validate(),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = cf.ExprArena.init(allocator);
    defer arena.deinit();
    var evaluator = try cf.ExprEvaluator.init(&arena, allocator);
    defer evaluator.deinit();
    try build(&arena, &evaluator, 7);

    var program = try program_mod.lower(allocator, &evaluator);
    defer program.deinit(allocator);
    _ = try program.semanticDigest();
}

test "constraint program releases every partial lowering allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
