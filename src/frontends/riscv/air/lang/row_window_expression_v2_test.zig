const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const compat_layout = @import("compat_layout.zig");
const expression = @import("row_window_expression_v2.zig");
const row_window = @import("row_window.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const window_ir = @import("window_ir_v2.zig");

test "row-window expression v2: arena interns shifted expressions and derives exact degree" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var arena = window_ir.Arena.init(std.testing.allocator, 0);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const pair = interactionPair(&fixture.plan, &fixture.layout);
    const current = try arena.shiftedColumn(pair.current, generated);
    const duplicate = try arena.shiftedColumn(pair.current, generated);
    try std.testing.expectEqual(current, duplicate);
    const previous = try arena.shiftedColumn(pair.previous, generated);
    const product = try arena.mul(current, previous, generated);
    const three = try arena.constantField(3, generated);
    const root = try arena.add(product, three, generated);

    var degrees = try window_ir.analyzeDegrees(std.testing.allocator, &arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(window_ir.Degree, 2), degrees.maximum);
    try std.testing.expectEqual(@as(window_ir.Degree, 2), degrees.value(root).?);
    try std.testing.expectError(
        error.NonCanonicalConstant,
        arena.constantField(m31.Modulus, generated),
    );

    const roots = [_]types.WindowValueId{root};
    var program = try expression.compile(
        std.testing.allocator,
        &arena,
        &roots,
        3,
        &fixture.plan,
        &fixture.imported,
        &fixture.layout,
    );
    defer program.deinit();
    try program.validate(
        &arena,
        &fixture.plan,
        &fixture.imported,
        &fixture.layout,
    );
    try std.testing.expectEqual(@as(expression.Degree, 2), program.maximum_degree);
    try std.testing.expect(program.nodes[0].sample != null);
    try std.testing.expect(program.nodes[2].sample == null);
}

test "row-window expression v2: prepared materialization is cyclic and allocation-free" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var built = try GoodExpression.init(std.testing.allocator, &fixture);
    defer built.deinit();
    var traces = try OwnedTraces.init(
        std.testing.allocator,
        fixture.plan.tree_column_counts,
        4,
    );
    defer traces.deinit();
    const prepared = try expression.PreparedEvaluator.init(
        &built.program,
        &built.arena,
        &fixture.plan,
        &fixture.imported,
        &fixture.layout,
        traces.view(),
    );

    var scratch: [5]M31 = .{M31.zero()} ** 5;
    var row_outputs: [1]M31 = .{M31.zero()};
    try prepared.evaluateRow(0, &scratch, &row_outputs);
    const expected_first = traceValue(.interaction, 0, 0)
        .mul(traceValue(.interaction, 0, 3)).add(M31.fromCanonical(3));
    try std.testing.expect(expected_first.eql(row_outputs[0]));

    var materialized: [4]M31 = .{M31.zero()} ** 4;
    const output_columns = [_][]M31{&materialized};
    try prepared.materialize(&scratch, &row_outputs, &output_columns);
    for (materialized, 0..) |actual, row| {
        const previous = if (row == 0) 3 else row - 1;
        const expected = traceValue(.interaction, 0, row)
            .mul(traceValue(.interaction, 0, previous)).add(M31.fromCanonical(3));
        try std.testing.expect(expected.eql(actual));
    }

    // The hot API accepts no allocator. Aliases fail before any destination
    // write, so a rejected call cannot corrupt a future row or its source.
    const before = scratch;
    try std.testing.expectError(
        error.OutputAliasesScratch,
        prepared.evaluateRow(0, &scratch, scratch[0..1]),
    );
    try std.testing.expectEqualDeep(before, scratch);
}

test "row-window expression v2: dead cross-owner and excess-degree AIR fails closed" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const generated = source.SourceSpan.generated();
    const pair = interactionPair(&fixture.plan, &fixture.layout);

    {
        var arena = window_ir.Arena.init(std.testing.allocator, 0);
        defer arena.deinit();
        const semantic = try arena.shiftedColumn(semanticCurrent(&fixture.plan), generated);
        const interaction = try arena.shiftedColumn(pair.current, generated);
        const root = try arena.add(semantic, interaction, generated);
        const roots = [_]types.WindowValueId{root};
        try std.testing.expectError(
            error.CrossOwnerExpression,
            expression.compile(
                std.testing.allocator,
                &arena,
                &roots,
                3,
                &fixture.plan,
                &fixture.imported,
                &fixture.layout,
            ),
        );
    }
    {
        var arena = window_ir.Arena.init(std.testing.allocator, 0);
        defer arena.deinit();
        const root = try arena.shiftedColumn(pair.current, generated);
        _ = try arena.constantField(7, generated);
        const roots = [_]types.WindowValueId{root};
        try std.testing.expectError(
            error.UnusedExpression,
            expression.compile(
                std.testing.allocator,
                &arena,
                &roots,
                3,
                &fixture.plan,
                &fixture.imported,
                &fixture.layout,
            ),
        );
    }
    {
        var arena = window_ir.Arena.init(std.testing.allocator, 0);
        defer arena.deinit();
        const current = try arena.shiftedColumn(pair.current, generated);
        const previous = try arena.shiftedColumn(pair.previous, generated);
        const root = try arena.mul(current, previous, generated);
        const roots = [_]types.WindowValueId{root};
        try std.testing.expectError(
            error.DegreeLimitExceeded,
            expression.compile(
                std.testing.allocator,
                &arena,
                &roots,
                1,
                &fixture.plan,
                &fixture.imported,
                &fixture.layout,
            ),
        );
    }
}

test "row-window expression v2: identity and trace mutations are rejected" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var built = try GoodExpression.init(std.testing.allocator, &fixture);
    defer built.deinit();

    built.program.program_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidExpressionDigest,
        built.program.validate(
            &built.arena,
            &fixture.plan,
            &fixture.imported,
            &fixture.layout,
        ),
    );
    built.program.program_digest[0] ^= 1;

    const saved_owner = built.program.nodes[0].owner;
    built.program.nodes[0].owner = null;
    try std.testing.expectError(
        error.InvalidCompiledNode,
        built.program.validate(
            &built.arena,
            &fixture.plan,
            &fixture.imported,
            &fixture.layout,
        ),
    );
    built.program.nodes[0].owner = saved_owner;

    const saved_root = built.program.roots[0];
    built.program.roots[0] = @enumFromInt(built.program.nodes.len);
    try std.testing.expectError(
        error.InvalidRoot,
        built.program.validate(
            &built.arena,
            &fixture.plan,
            &fixture.imported,
            &fixture.layout,
        ),
    );
    built.program.roots[0] = saved_root;

    const pair = interactionPair(&fixture.plan, &fixture.layout);
    const prior_offset = fixture.plan.shifted_columns[
        @intFromEnum(pair.previous)
    ].offset;
    fixture.plan.shifted_columns[@intFromEnum(pair.previous)].offset = .current;
    try std.testing.expectError(
        error.InvalidShiftedColumn,
        built.program.validate(
            &built.arena,
            &fixture.plan,
            &fixture.imported,
            &fixture.layout,
        ),
    );
    fixture.plan.shifted_columns[@intFromEnum(pair.previous)].offset = prior_offset;

    var traces = try OwnedTraces.init(
        std.testing.allocator,
        fixture.plan.tree_column_counts,
        4,
    );
    defer traces.deinit();
    var wrong = traces.view();
    wrong.main = wrong.main[0 .. wrong.main.len - 1];
    try std.testing.expectError(
        error.InvalidTraceGeometry,
        expression.PreparedEvaluator.init(
            &built.program,
            &built.arena,
            &fixture.plan,
            &fixture.imported,
            &fixture.layout,
            wrong,
        ),
    );

    const first_value = @constCast(traces.trees[0][0]);
    const saved_value = first_value[0];
    first_value[0].v = m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalTraceValue,
        expression.PreparedEvaluator.init(
            &built.program,
            &built.arena,
            &fixture.plan,
            &fixture.imported,
            &fixture.layout,
            traces.view(),
        ),
    );
    first_value[0] = saved_value;

    const prepared = try expression.PreparedEvaluator.init(
        &built.program,
        &built.arena,
        &fixture.plan,
        &fixture.imported,
        &fixture.layout,
        traces.view(),
    );
    var scratch: [5]M31 = .{M31.zero()} ** 5;
    var row_outputs: [1]M31 = .{M31.zero()};
    const aliased_outputs = [_][]M31{@constCast(traces.trees[0][0])};
    try std.testing.expectError(
        error.OutputAliasesInput,
        prepared.materialize(&scratch, &row_outputs, &aliased_outputs),
    );
}

test "row-window expression v2: compilation releases every partial allocation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var arena = window_ir.Arena.init(std.testing.allocator, 0);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const pair = interactionPair(&fixture.plan, &fixture.layout);
    const current = try arena.shiftedColumn(pair.current, generated);
    const previous = try arena.shiftedColumn(pair.previous, generated);
    const root = try arena.mul(current, previous, generated);
    const roots = [_]types.WindowValueId{root};
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        compileAllocationCase,
        .{ &arena, &roots, &fixture },
    );
}

const Fixture = struct {
    imported: shadow_program.ImportedProgram,
    layout: compat_layout.Layout,
    plan: row_window.Plan,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var imported = try shadow_program.buildProduction(
            allocator,
            .lui,
            source.SourceSpan.generated(),
        );
        errdefer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var plan = try row_window.build(allocator, &imported, &layout);
        errdefer plan.deinit();
        return .{ .imported = imported, .layout = layout, .plan = plan };
    }

    fn deinit(self: *Fixture) void {
        self.plan.deinit();
        self.imported.deinit();
        self.* = undefined;
    }
};

const GoodExpression = struct {
    arena: window_ir.Arena,
    program: expression.Program,

    fn init(allocator: std.mem.Allocator, fixture: *const Fixture) !GoodExpression {
        var arena = window_ir.Arena.init(allocator, 0);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        const pair = interactionPair(&fixture.plan, &fixture.layout);
        const current = try arena.shiftedColumn(pair.current, generated);
        const previous = try arena.shiftedColumn(pair.previous, generated);
        const product = try arena.mul(current, previous, generated);
        const three = try arena.constantField(3, generated);
        const root = try arena.add(product, three, generated);
        const roots = [_]types.WindowValueId{root};
        const program = try expression.compile(
            allocator,
            &arena,
            &roots,
            3,
            &fixture.plan,
            &fixture.imported,
            &fixture.layout,
        );
        return .{ .arena = arena, .program = program };
    }

    fn deinit(self: *GoodExpression) void {
        self.program.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

const ShiftPair = struct {
    current: types.ShiftedColumnId,
    previous: types.ShiftedColumnId,
};

fn interactionPair(
    plan: *const row_window.Plan,
    layout: *const compat_layout.Layout,
) ShiftPair {
    const column = plan.columns[2 + layout.main().len];
    return .{
        .current = @enumFromInt(column.shifted.start),
        .previous = @enumFromInt(column.shifted.start + 1),
    };
}

fn semanticCurrent(plan: *const row_window.Plan) types.ShiftedColumnId {
    return @enumFromInt(plan.columns[2].shifted.start);
}

const OwnedTraces = struct {
    allocator: std.mem.Allocator,
    trees: [3][]const []const M31,

    fn init(
        allocator: std.mem.Allocator,
        counts: [3]u32,
        row_count: usize,
    ) !OwnedTraces {
        var result = OwnedTraces{
            .allocator = allocator,
            .trees = .{ &.{}, &.{}, &.{} },
        };
        var initialized_trees: usize = 0;
        errdefer {
            for (result.trees[0..initialized_trees]) |columns| {
                for (columns) |column| allocator.free(column);
                allocator.free(columns);
            }
        }
        for (&result.trees, counts, 0..) |*tree, count, tree_index| {
            const columns = try allocator.alloc([]const M31, count);
            var initialized_columns: usize = 0;
            errdefer {
                for (columns[0..initialized_columns]) |column| allocator.free(column);
                allocator.free(columns);
            }
            for (columns, 0..) |*column, column_index| {
                const values = try allocator.alloc(M31, row_count);
                for (values, 0..) |*value, row| {
                    value.* = traceValue(
                        @enumFromInt(tree_index),
                        column_index,
                        row,
                    );
                }
                column.* = values;
                initialized_columns += 1;
            }
            tree.* = columns;
            initialized_trees += 1;
        }
        return result;
    }

    fn deinit(self: *OwnedTraces) void {
        for (self.trees) |columns| {
            for (columns) |column| self.allocator.free(column);
            self.allocator.free(columns);
        }
        self.* = undefined;
    }

    fn view(self: *const OwnedTraces) expression.TraceColumns {
        return .{
            .preprocessed = self.trees[0],
            .main = self.trees[1],
            .interaction = self.trees[2],
        };
    }
};

fn traceValue(tree: compat_layout.Tree, column: usize, row: usize) M31 {
    return M31.fromCanonical(@intCast(
        1 + @as(usize, @intFromEnum(tree)) * 10_000 + column * 100 + row,
    ));
}

fn compileAllocationCase(
    allocator: std.mem.Allocator,
    arena: *const window_ir.Arena,
    roots: []const types.WindowValueId,
    fixture: *const Fixture,
) !void {
    var program = try expression.compile(
        allocator,
        arena,
        roots,
        3,
        &fixture.plan,
        &fixture.imported,
        &fixture.layout,
    );
    program.deinit();
}
