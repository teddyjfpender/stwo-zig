const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const benchmark = @import("materialization_direct_benchmark.zig");
const direct_program = @import("materialization_direct_program.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");

test "retained direct evaluator binds columns and names the first failed root" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const gate = try arena.input("gate", .selector, span);
    const input = try arena.input("input", .felt, span);
    const square = try arena.mul(input, input, span);
    const selected = [_]@TypeOf(square){square};
    var program = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = gate,
        .selected = &selected,
        .materialization_column_start = 2,
    });
    defer program.deinit();

    const base = [_]benchmark.ValueColumn{
        .{ .value = gate, .physical_column = 0 },
        .{ .value = input, .physical_column = 1 },
    };
    var evaluator = try benchmark.Evaluator.init(
        std.testing.allocator,
        &program,
        &base,
        3,
    );
    defer evaluator.deinit();

    const identity = try evaluator.identityDigest();
    try std.testing.expect(!std.mem.allEqual(u8, &identity, 0));
    try std.testing.expectEqual(@as(u64, program.counts.nodes * 4), try evaluator.retainedScratchBytes());

    var row = [_]M31{
        M31.one(),
        M31.fromCanonical(3),
        M31.fromCanonical(9),
    };
    try std.testing.expect((try evaluator.evaluateRow(&row)).allRootsZero());
    row[2] = M31.fromCanonical(10);
    const failed = try evaluator.evaluateRow(&row);
    try std.testing.expectEqual(@as(u32, 1), failed.nonzero_roots);
    try std.testing.expectEqual(@as(?u32, 0), failed.first_nonzero_root);
    row[0] = M31.zero();
    try std.testing.expect((try evaluator.evaluateRow(&row)).allRootsZero());
}

test "retained direct evaluator traverses column-major traces without allocation" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const input = try arena.input("input", .felt, span);
    const doubled = try arena.add(input, input, span);
    const selected = [_]@TypeOf(doubled){doubled};
    var program = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = 1,
    });
    defer program.deinit();
    const base = [_]benchmark.ValueColumn{
        .{ .value = input, .physical_column = 0 },
    };
    var evaluator = try benchmark.Evaluator.init(
        std.testing.allocator,
        &program,
        &base,
        2,
    );
    defer evaluator.deinit();

    const inputs = [_]M31{ M31.fromCanonical(3), M31.fromCanonical(4) };
    const outputs = [_]M31{ M31.fromCanonical(6), M31.fromCanonical(8) };
    const columns = [_][]const M31{ &inputs, &outputs };
    const prepared = try evaluator.prepareTrace(&columns);
    const result = prepared.execute();
    try std.testing.expect(result.allRootsZero());
    try std.testing.expectEqual(@as(u64, 2), result.rows);
    try std.testing.expectEqual(@as(u64, 2), result.root_evaluations);

    const short_outputs = outputs[0..1];
    const malformed = [_][]const M31{ &inputs, short_outputs };
    try std.testing.expectError(
        error.InvalidTraceShape,
        evaluator.prepareTrace(&malformed),
    );
}

test "retained direct evaluator releases every partial allocation" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const input = try arena.input("input", .felt, span);
    const squared = try arena.mul(input, input, span);
    const selected = [_]@TypeOf(squared){squared};
    var program = try direct_program.extract(std.testing.allocator, &arena, .{
        .gate = null,
        .selected = &selected,
        .materialization_column_start = 1,
    });
    defer program.deinit();
    const base = [_]benchmark.ValueColumn{
        .{ .value = input, .physical_column = 0 },
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        evaluatorAllocationFailureCase,
        .{ &program, &base },
    );
}

fn evaluatorAllocationFailureCase(
    allocator: std.mem.Allocator,
    program: *const direct_program.Program,
    base: *const [1]benchmark.ValueColumn,
) !void {
    var evaluator = try benchmark.Evaluator.init(
        allocator,
        program,
        base,
        2,
    );
    defer evaluator.deinit();
}
