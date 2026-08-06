const std = @import("std");
const cut_set = @import("materialization_cut_set.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "cut set imports the exact 426-value Poseidon baseline and replays canonically" {
    var first_fixture = try PoseidonFixture.init(std.testing.allocator);
    defer first_fixture.deinit();
    var first_plan = try first_fixture.makePlan(std.testing.allocator);
    defer first_plan.deinit();
    var first = try cut_set.fromDegree3Plan(
        std.testing.allocator,
        &first_fixture.arena,
        &first_plan,
    );
    defer first.deinit();
    const first_roots = poseidon.values(first_fixture.definition.outputs);
    const request: cut_set.Request = .{ .roots = &first_roots, .gate = first_fixture.gate };
    try first.validateAgainst(std.testing.allocator, &first_fixture.arena, request);
    try std.testing.expectEqual(@as(usize, 426), first.values.len);

    for (first_plan.materializations, 0..) |item, plan_index| {
        const cut_index = first.indexOf(item.source_value) orelse
            return error.TestExpectedEqual;
        const entry = first.entries[types.idIndex(cut_index)];
        try std.testing.expectEqual(item.body_degree, entry.body_degree);
        try std.testing.expectEqual(item.constraint_degree, entry.constraint_degree);
        const plan_dependencies = first_plan.dependenciesFor(@enumFromInt(plan_index)).?;
        const cut_dependencies = first.dependenciesFor(cut_index).?;
        try std.testing.expectEqual(plan_dependencies.len, cut_dependencies.len);
        for (plan_dependencies, cut_dependencies) |plan_dependency, cut_dependency| {
            const expected = first_plan.materializations[types.idIndex(plan_dependency)].source_value;
            try std.testing.expectEqual(expected, first.values[types.idIndex(cut_dependency)]);
        }
    }

    var reversed: [426]types.ValueId = undefined;
    for (&reversed, 0..) |*value, index|
        value.* = first.values[first.values.len - 1 - index];
    var reordered = try cut_set.build(
        std.testing.allocator,
        &first_fixture.arena,
        request,
        &reversed,
    );
    defer reordered.deinit();
    try expectSameCutSet(&first, &reordered);
}

test "tiny DAG brute force admits exactly the complete degree-three cut chain" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = [_]types.ValueId{fixture.root};
    const request: cut_set.Request = .{ .roots = &roots, .gate = fixture.gate };

    for (0..4) |mask| {
        var selected: [3]types.ValueId = undefined;
        var len: usize = 0;
        if (mask & 1 != 0) {
            selected[len] = fixture.ab;
            len += 1;
        }
        if (mask & 2 != 0) {
            selected[len] = fixture.abc;
            len += 1;
        }
        selected[len] = fixture.root;
        len += 1;
        var result = cut_set.build(
            std.testing.allocator,
            &fixture.arena,
            request,
            selected[0..len],
        ) catch |failure| {
            try std.testing.expect(mask != 3);
            try std.testing.expect(failure == error.InfeasibleEquality);
            continue;
        };
        defer result.deinit();
        try std.testing.expectEqual(@as(usize, 3), mask);
        try std.testing.expectEqualSlices(
            cut_set.CutIndex,
            &.{@as(cut_set.CutIndex, @enumFromInt(0))},
            result.dependenciesFor(@enumFromInt(1)).?,
        );
        try std.testing.expectEqual(@as(cut_set.Degree, 3), result.entries[2].constraint_degree);
    }
}

test "cut set rejects malformed selections context and degree overflow" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = [_]types.ValueId{fixture.root};
    const request: cut_set.Request = .{ .roots = &roots, .gate = fixture.gate };

    try expectBuildError(
        error.DuplicateSelection,
        &fixture.arena,
        request,
        &.{ fixture.ab, fixture.ab, fixture.abc, fixture.root },
    );
    try expectBuildError(
        error.SelectionUnreachable,
        &fixture.arena,
        request,
        &.{ fixture.detached, fixture.ab, fixture.abc, fixture.root },
    );
    try expectBuildError(error.MissingRoot, &fixture.arena, request, &.{ fixture.ab, fixture.abc });
    const unknown: types.ValueId = @enumFromInt(fixture.arena.nodeCount() + 7);
    const unknown_roots = [_]types.ValueId{unknown};
    try expectBuildError(error.InvalidRoot, &fixture.arena, .{ .roots = &unknown_roots, .gate = null }, &.{unknown});
    const word_roots = [_]types.ValueId{fixture.word};
    try expectBuildError(error.InvalidRootType, &fixture.arena, .{ .roots = &word_roots, .gate = null }, &.{fixture.word});
    const valid = [_]types.ValueId{ fixture.ab, fixture.abc, fixture.root };
    try expectBuildError(
        error.InvalidGate,
        &fixture.arena,
        .{ .roots = &roots, .gate = unknown },
        &valid,
    );
    try expectBuildError(
        error.ImpossibleDegreeBudget,
        &fixture.arena,
        .{ .roots = &roots, .gate = fixture.gate, .policy = .{
            .maximum_constraint_degree = 1,
        } },
        &valid,
    );
    try expectBuildError(
        error.InfeasibleEquality,
        &fixture.arena,
        .{ .roots = &roots, .gate = fixture.gate, .policy = .{ .row_mask_degree = 1 } },
        &valid,
    );

    var overflow_arena = ir.Arena.init(std.testing.allocator);
    defer overflow_arena.deinit();
    var square = try overflow_arena.input("square", .felt, source.SourceSpan.generated());
    for (0..64) |_| square = try overflow_arena.mul(
        square,
        square,
        source.SourceSpan.generated(),
    );
    const overflow_roots = [_]types.ValueId{square};
    try expectBuildError(error.DegreeOverflow, &overflow_arena, .{ .roots = &overflow_roots, .gate = null }, &.{square});
}

test "validation detects corruption and edits are transactional" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = [_]types.ValueId{fixture.root};
    const request: cut_set.Request = .{ .roots = &roots, .gate = fixture.gate };
    var result = try cut_set.build(
        std.testing.allocator,
        &fixture.arena,
        request,
        &.{ fixture.root, fixture.abc, fixture.ab },
    );
    defer result.deinit();

    result.program_digest[0] ^= 1;
    try expectValidationError(error.ProgramDigestMismatch, &result, &fixture.arena, request);
    result.program_digest[0] ^= 1;
    try expectValidationError(error.GateMismatch, &result, &fixture.arena, .{ .roots = &roots, .gate = null });
    try expectValidationError(
        error.PolicyMismatch,
        &result,
        &fixture.arena,
        .{ .roots = &roots, .gate = fixture.gate, .policy = .{ .row_mask_degree = 1 } },
    );

    std.mem.swap(types.ValueId, &result.values[0], &result.values[1]);
    try expectValidationError(error.SelectionNotCanonical, &result, &fixture.arena, request);
    std.mem.swap(types.ValueId, &result.values[0], &result.values[1]);
    const saved_dependency = result.dependencies[0];
    result.dependencies[0] = @enumFromInt(1);
    try expectValidationError(error.InvalidDependency, &result, &fixture.arena, request);
    result.dependencies[0] = saved_dependency;
    result.entries[0].body_degree += 1;
    try expectValidationError(error.InvalidStoredDegree, &result, &fixture.arena, request);
    result.entries[0].body_degree -= 1;
    const saved_value = result.values[0];
    result.values[0] = fixture.detached;
    try expectValidationError(error.SelectionUnreachable, &result, &fixture.arena, request);
    result.values[0] = saved_value;

    try expectEditError(
        error.InvalidEdit,
        &result,
        &fixture.arena,
        request,
        .{ .swap = .{ .remove = fixture.ab, .add = fixture.ab } },
    );
    try expectEditError(error.InfeasibleEquality, &result, &fixture.arena, request, .{ .remove = fixture.ab });
    var added = try result.edited(
        std.testing.allocator,
        &fixture.arena,
        request,
        .{ .add = fixture.a },
    );
    defer added.deinit();
    try added.validateAgainst(std.testing.allocator, &fixture.arena, request);

    var trusted_added = try result.editedTrusted(
        std.testing.allocator,
        &fixture.arena,
        request,
        .{ .add = fixture.a },
    );
    defer trusted_added.deinit();
    try expectSameCutSet(&added, &trusted_added);
    try trusted_added.validateAgainst(std.testing.allocator, &fixture.arena, request);

    const unknown: types.ValueId = @enumFromInt(fixture.arena.nodeCount() + 1);
    try std.testing.expectError(error.InvalidSelection, result.editedTrusted(
        std.testing.allocator,
        &fixture.arena,
        request,
        .{ .add = unknown },
    ));
}

test "Poseidon cut-set import releases every partial allocation" {
    var fixture = try PoseidonFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        importFailureCase,
        .{ &fixture.arena, &plan },
    );
}

fn expectSameCutSet(lhs: *const cut_set.CutSet, rhs: *const cut_set.CutSet) !void {
    try std.testing.expectEqual(lhs.program_digest, rhs.program_digest);
    try std.testing.expectEqualSlices(types.ValueId, lhs.roots, rhs.roots);
    try std.testing.expectEqualSlices(types.ValueId, lhs.values, rhs.values);
    try std.testing.expectEqualSlices(cut_set.Entry, lhs.entries, rhs.entries);
    try std.testing.expectEqualSlices(cut_set.CutIndex, lhs.dependencies, rhs.dependencies);
}

fn expectBuildError(
    expected: anyerror,
    arena: *const ir.Arena,
    request: cut_set.Request,
    values: []const types.ValueId,
) !void {
    try std.testing.expectError(expected, cut_set.build(std.testing.allocator, arena, request, values));
}

fn expectValidationError(
    expected: anyerror,
    result: *const cut_set.CutSet,
    arena: *const ir.Arena,
    request: cut_set.Request,
) !void {
    try std.testing.expectError(expected, result.validateAgainst(std.testing.allocator, arena, request));
}

fn expectEditError(
    expected: anyerror,
    result: *const cut_set.CutSet,
    arena: *const ir.Arena,
    request: cut_set.Request,
    edit: cut_set.Edit,
) !void {
    try std.testing.expectError(expected, result.edited(std.testing.allocator, arena, request, edit));
}

fn importFailureCase(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    plan: *const materializer.Plan,
) !void {
    var result = try cut_set.fromDegree3Plan(allocator, arena, plan);
    defer result.deinit();
}

const TinyFixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    a: types.ValueId,
    word: types.ValueId,
    detached: types.ValueId,
    ab: types.ValueId,
    abc: types.ValueId,
    root: types.ValueId,

    fn init(allocator: std.mem.Allocator) !TinyFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = source.SourceSpan.generated();
        const gate = try arena.input("gate", .selector, span);
        const a = try arena.input("a", .felt, span);
        const b = try arena.input("b", .felt, span);
        const c = try arena.input("c", .felt, span);
        const d = try arena.input("d", .felt, span);
        const word = try arena.input("word", .word32, span);
        const detached = try arena.mul(a, d, span);
        const ab = try arena.mul(a, b, span);
        const abc = try arena.mul(ab, c, span);
        const root = try arena.mul(abc, d, span);
        return .{
            .arena = arena,
            .gate = gate,
            .a = a,
            .word = word,
            .detached = detached,
            .ab = ab,
            .abc = abc,
            .root = root,
        };
    }

    fn deinit(self: *TinyFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const PoseidonFixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    definition: poseidon.Definition,

    fn init(allocator: std.mem.Allocator) !PoseidonFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = source.SourceSpan.generated();
        const gate = try arena.input("riscv.poseidon2_m31.enabled", .selector, span);
        const definition = try poseidon.define(&arena, poseidon.DefinitionSpans.uniform(span));
        return .{ .arena = arena, .gate = gate, .definition = definition };
    }

    fn deinit(self: *PoseidonFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn makePlan(self: *const PoseidonFixture, allocator: std.mem.Allocator) !materializer.Plan {
        const roots = poseidon.values(self.definition.outputs);
        return materializer.plan(allocator, &self.arena, .{ .roots = &roots, .gate = self.gate });
    }
};
