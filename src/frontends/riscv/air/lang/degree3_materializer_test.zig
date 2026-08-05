const std = @import("std");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "degree-three materializer cuts a gated product deterministically" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input("enabled", .selector, generated);
    const a = try arena.input("a", .felt, generated);
    const b = try arena.input("b", .felt, generated);
    const c = try arena.input("c", .felt, generated);
    const product = try arena.mul(a, b, generated);
    const cube = try arena.mul(product, c, generated);

    var result = try materializer.plan(std.testing.allocator, &arena, .{
        .roots = &.{cube},
        .gate = gate,
    });
    defer result.deinit();
    try result.validate(std.testing.allocator, &arena);

    try std.testing.expectEqualStrings(
        "stwo.typed-air.materialize.degree-bounded-v1",
        materializer.policy_id,
    );
    try std.testing.expectEqual(@as(u16, 1), materializer.policy_version);
    try std.testing.expectEqual(@as(usize, 2), result.materializations.len);
    try std.testing.expectEqual(product, result.materializations[0].source_value);
    try std.testing.expectEqual(cube, result.materializations[1].source_value);
    try std.testing.expectEqual(materializer.Reason.degree, result.materializations[0].reason);
    try std.testing.expectEqual(materializer.Reason.output, result.materializations[1].reason);
    try std.testing.expectEqual(@as(materializer.Degree, 2), result.materializations[0].body_degree);
    try std.testing.expectEqual(@as(materializer.Degree, 3), result.materializations[0].constraint_degree);
    try std.testing.expectEqual(@as(materializer.Degree, 2), result.materializations[1].body_degree);
    try std.testing.expectEqual(@as(materializer.Degree, 3), result.materializations[1].constraint_degree);
    try std.testing.expectEqual(@as(usize, 0), result.dependenciesFor(@enumFromInt(0)).?.len);
    try std.testing.expectEqualSlices(
        materializer.MaterializationId,
        &.{@as(materializer.MaterializationId, @enumFromInt(0))},
        result.dependenciesFor(@enumFromInt(1)).?,
    );
    try std.testing.expectEqual(
        @as(materializer.MaterializationId, @enumFromInt(1)),
        result.outputs[0].materialization,
    );
    try std.testing.expect(std.mem.startsWith(
        u8,
        result.materializations[0].stable_name.slice(),
        "air.mat.v1.mul.generated.",
    ));
}

test "degree-three materializer derives the exact Poseidon compatibility schedule" {
    var fixture = try PoseidonFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var result = try fixture.makePlan(std.testing.allocator);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 426), result.materializations.len);
    try std.testing.expectEqual(@as(usize, poseidon.WIDTH), result.outputs.len);
    const first = fixture.spans.body.external_rounds[0];
    try std.testing.expectEqual(@as(usize, 0), countStage(&result, .add, first.constants, .degree));
    try std.testing.expectEqual(@as(usize, 32), countStage(&result, .mul, first.sbox, .degree));
    for (fixture.spans.body.external_rounds[1..]) |spans| {
        try std.testing.expectEqual(@as(usize, 16), countStage(&result, .add, spans.constants, .degree));
        try std.testing.expectEqual(@as(usize, 32), countStage(&result, .mul, spans.sbox, .degree));
    }
    for (fixture.spans.body.internal_rounds) |spans| {
        try std.testing.expectEqual(@as(usize, 1), countStage(&result, .add, spans.constant, .degree));
        try std.testing.expectEqual(@as(usize, 2), countStage(&result, .mul, spans.sbox, .degree));
    }

    for (result.materializations[0 .. result.materializations.len - poseidon.WIDTH], 0..) |item, index| {
        if (index != 0) try std.testing.expect(
            types.idIndex(result.materializations[index - 1].source_value) <
                types.idIndex(item.source_value),
        );
        try std.testing.expectEqual(materializer.Reason.degree, item.reason);
    }

    const roots = poseidon.values(fixture.definition.outputs);
    for (roots, 0..) |root, lane| {
        const cursor = result.materializations.len - poseidon.WIDTH + lane;
        const item = result.materializations[cursor];
        try std.testing.expectEqual(root, item.source_value);
        try expectStage(
            item,
            .add,
            fixture.spans.body.external_rounds[poseidon.N_EXTERNAL_ROUNDS - 1].linear,
            .output,
        );
        try std.testing.expectEqual(root, result.outputs[lane].root);
        try std.testing.expectEqual(
            @as(materializer.MaterializationId, @enumFromInt(cursor)),
            result.outputs[lane].materialization,
        );
    }
    for (result.materializations) |item| {
        try std.testing.expect(item.body_degree <= 2);
        try std.testing.expectEqual(@as(materializer.Degree, 1), item.context_degree);
        try std.testing.expectEqual(@as(materializer.Degree, 3), item.constraint_degree);
        try std.testing.expect(item.stable_name.slice().len > 64);
    }
    try result.validate(std.testing.allocator, &fixture.arena);
}

test "materialization allocation and names replay identically in clean arenas" {
    var first_fixture = try PoseidonFixture.init(std.testing.allocator);
    defer first_fixture.deinit();
    var second_fixture = try PoseidonFixture.init(std.testing.allocator);
    defer second_fixture.deinit();
    var first = try first_fixture.makePlan(std.testing.allocator);
    defer first.deinit();
    var second = try second_fixture.makePlan(std.testing.allocator);
    defer second.deinit();

    try std.testing.expectEqual(first.program_digest, second.program_digest);
    try std.testing.expectEqualSlices(
        materializer.Materialization,
        first.materializations,
        second.materializations,
    );
    try std.testing.expectEqualSlices(materializer.Output, first.outputs, second.outputs);
    try std.testing.expectEqualSlices(
        materializer.MaterializationId,
        first.dependencies,
        second.dependencies,
    );
}

test "degree-three materializer rejects malformed roots gates masks and overflow" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const felt = try arena.input("felt", .felt, generated);
    const word = try arena.input("word", .word32, generated);
    const condition = try arena.input("condition", .bit, generated);
    const gate_a = try arena.input("gate-a", .selector, generated);
    const gate_b = try arena.input("gate-b", .selector, generated);
    const composite_gate = try arena.select(condition, gate_a, gate_b, generated);
    const unknown = try types.idFromIndex(types.ValueId, 99_999);

    try std.testing.expectError(
        error.EmptyRoots,
        materializer.plan(std.testing.allocator, &arena, .{ .roots = &.{}, .gate = gate_a }),
    );
    try std.testing.expectError(
        error.InvalidRoot,
        materializer.plan(std.testing.allocator, &arena, .{ .roots = &.{unknown}, .gate = gate_a }),
    );
    try std.testing.expectError(
        error.InvalidRootType,
        materializer.plan(std.testing.allocator, &arena, .{ .roots = &.{word}, .gate = gate_a }),
    );
    try std.testing.expectError(
        error.InvalidGate,
        materializer.plan(std.testing.allocator, &arena, .{ .roots = &.{felt}, .gate = unknown }),
    );
    try std.testing.expectError(
        error.InvalidGateType,
        materializer.plan(std.testing.allocator, &arena, .{ .roots = &.{felt}, .gate = felt }),
    );
    try std.testing.expectError(
        error.UnsupportedGateExpression,
        materializer.plan(std.testing.allocator, &arena, .{ .roots = &.{felt}, .gate = composite_gate }),
    );
    try std.testing.expectError(
        error.ImpossibleDegreeBudget,
        materializer.plan(std.testing.allocator, &arena, .{
            .roots = &.{felt},
            .gate = gate_a,
            .policy = .{ .maximum_constraint_degree = 1 },
        }),
    );
    try std.testing.expectError(
        error.ImpossibleDegreeBudget,
        materializer.plan(std.testing.allocator, &arena, .{
            .roots = &.{felt},
            .gate = gate_a,
            .policy = .{ .row_mask_degree = 2 },
        }),
    );

    var overflow = felt;
    for (0..64) |_| overflow = try arena.mul(overflow, overflow, generated);
    try std.testing.expectError(
        error.DegreeOverflow,
        materializer.plan(std.testing.allocator, &arena, .{
            .roots = &.{overflow},
            .gate = null,
        }),
    );
}

test "degree-three materializer ignores unreachable degree overflow" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const root = try arena.input("reachable", .felt, generated);
    var detached = try arena.input("unreachable", .felt, generated);
    for (0..64) |_| detached = try arena.mul(detached, detached, generated);

    var result = try materializer.plan(std.testing.allocator, &arena, .{
        .roots = &.{root},
        .gate = null,
    });
    defer result.deinit();
    try result.validate(std.testing.allocator, &arena);
    try std.testing.expectEqual(@as(usize, 1), result.materializations.len);
    try std.testing.expect(types.idIndex(detached) > types.idIndex(root));
}

test "degree-three policy pins transparent operations reuse and tie breaks" {
    const generated = source.SourceSpan.generated();
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const gate = try arena.input("enabled", .selector, generated);
        const condition = try arena.input("condition", .bit, generated);
        const a = try arena.input("a", .felt, generated);
        const b = try arena.input("b", .felt, generated);
        const branch = try arena.mul(a, b, generated);
        const root = try arena.select(condition, branch, a, generated);
        var result = try materializer.plan(std.testing.allocator, &arena, .{
            .roots = &.{root},
            .gate = gate,
        });
        defer result.deinit();
        try std.testing.expectEqual(@as(usize, 2), result.materializations.len);
        try std.testing.expectEqual(branch, result.materializations[0].source_value);
        try std.testing.expectEqual(root, result.materializations[1].source_value);
        try std.testing.expectEqual(materializer.Reason.degree, result.materializations[0].reason);
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const gate = try arena.input("enabled", .selector, generated);
        const a = try arena.input("a", .felt, generated);
        const b = try arena.input("b", .felt, generated);
        const c = try arena.input("c", .felt, generated);
        const product = try arena.mul(a, b, generated);
        const cubic = try arena.mul(product, c, generated);
        const difference = try arena.sub(cubic, a, generated);
        const root = try arena.neg(difference, generated);
        var result = try materializer.plan(std.testing.allocator, &arena, .{
            .roots = &.{root},
            .gate = gate,
        });
        defer result.deinit();
        try std.testing.expectEqual(@as(usize, 2), result.materializations.len);
        try std.testing.expectEqual(product, result.materializations[0].source_value);
        try std.testing.expectEqual(root, result.materializations[1].source_value);
        try std.testing.expect(!containsSource(&result, cubic));
        try std.testing.expect(!containsSource(&result, difference));
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const a = try arena.input("a", .felt, generated);
        const b = try arena.input("b", .felt, generated);
        const c = try arena.input("c", .felt, generated);
        const d = try arena.input("d", .felt, generated);
        const reused = try arena.mul(a, b, generated);
        const less_used = try arena.mul(c, d, generated);
        const shared_root = try arena.mul(reused, less_used, generated);
        const reuse_root = try arena.neg(reused, generated);

        const e = try arena.input("e", .felt, generated);
        const f = try arena.input("f", .felt, generated);
        const g = try arena.input("g", .felt, generated);
        const h = try arena.input("h", .felt, generated);
        const lower_id = try arena.mul(e, f, generated);
        const higher_id = try arena.mul(g, h, generated);
        const tie_root = try arena.mul(lower_id, higher_id, generated);
        var result = try materializer.plan(std.testing.allocator, &arena, .{
            .roots = &.{ shared_root, reuse_root, tie_root },
            .gate = null,
        });
        defer result.deinit();

        try std.testing.expect(containsSource(&result, reused));
        try std.testing.expect(!containsSource(&result, less_used));
        try std.testing.expect(containsSource(&result, lower_id));
        try std.testing.expect(!containsSource(&result, higher_id));
        try std.testing.expectEqual(reused, result.materializations[0].source_value);
        try std.testing.expectEqual(lower_id, result.materializations[1].source_value);
        try std.testing.expectEqual(shared_root, result.materializations[2].source_value);
        try std.testing.expectEqual(reuse_root, result.materializations[3].source_value);
        try std.testing.expectEqual(tie_root, result.materializations[4].source_value);
    }
}

test "plan validator rejects corrupt names degrees ordering dependencies and outputs" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input("enabled", .selector, generated);
    const a = try arena.input("a", .felt, generated);
    const b = try arena.input("b", .felt, generated);
    const c = try arena.input("c", .felt, generated);
    const ab = try arena.mul(a, b, generated);
    const root = try arena.mul(ab, c, generated);
    var result = try materializer.plan(std.testing.allocator, &arena, .{
        .roots = &.{root},
        .gate = gate,
    });
    defer result.deinit();

    const saved_source = result.materializations[0].source_value;
    result.materializations[0].source_value = a;
    try std.testing.expectError(
        error.InvalidMaterialization,
        result.validate(std.testing.allocator, &arena),
    );
    result.materializations[0].source_value = saved_source;

    result.materializations[0].stable_name.bytes[0] ^= 1;
    try std.testing.expectError(
        error.InvalidMaterializationName,
        result.validate(std.testing.allocator, &arena),
    );
    result.materializations[0].stable_name.bytes[0] ^= 1;

    result.materializations[0].constraint_degree = 2;
    try std.testing.expectError(
        error.InvalidMaterializationDegree,
        result.validate(std.testing.allocator, &arena),
    );
    result.materializations[0].constraint_degree = 3;

    std.mem.swap(
        materializer.Materialization,
        &result.materializations[0],
        &result.materializations[1],
    );
    try std.testing.expectError(
        error.InvalidMaterializationOrder,
        result.validate(std.testing.allocator, &arena),
    );
    std.mem.swap(
        materializer.Materialization,
        &result.materializations[0],
        &result.materializations[1],
    );

    const saved_dependency = result.dependencies[0];
    result.dependencies[0] = @enumFromInt(1);
    try std.testing.expectError(
        error.InvalidDependency,
        result.validate(std.testing.allocator, &arena),
    );
    result.dependencies[0] = saved_dependency;

    const saved_output = result.outputs[0].materialization;
    result.outputs[0].materialization = @enumFromInt(99);
    try std.testing.expectError(
        error.InvalidOutput,
        result.validate(std.testing.allocator, &arena),
    );
    result.outputs[0].materialization = saved_output;

    result.program_digest[0] ^= 1;
    try std.testing.expectError(
        error.ProgramDigestMismatch,
        result.validate(std.testing.allocator, &arena),
    );
}

test "Poseidon materializer releases every partial allocation" {
    var fixture = try PoseidonFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const roots = poseidon.values(fixture.definition.outputs);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{ &fixture.arena, &roots, fixture.gate },
    );
}

fn countStage(
    result: *const materializer.Plan,
    op: materializer.SourceOp,
    span: source.SourceSpan,
    reason: materializer.Reason,
) usize {
    var count: usize = 0;
    for (result.materializations) |item| {
        if (item.source_op == op and item.reason == reason and
            std.meta.eql(item.source_span, span)) count += 1;
    }
    return count;
}

fn containsSource(result: *const materializer.Plan, value: types.ValueId) bool {
    for (result.materializations) |item| if (item.source_value == value) return true;
    return false;
}

fn expectStage(
    item: materializer.Materialization,
    op: materializer.SourceOp,
    span: source.SourceSpan,
    reason: materializer.Reason,
) !void {
    try std.testing.expectEqual(op, item.source_op);
    try std.testing.expect(std.meta.eql(span, item.source_span));
    try std.testing.expectEqual(reason, item.reason);
}

fn dependenciesAt(
    result: *const materializer.Plan,
    index: usize,
) []const materializer.MaterializationId {
    return result.dependenciesFor(@enumFromInt(index)).?;
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    roots: *const [poseidon.WIDTH]types.ValueId,
    gate: types.ValueId,
) !void {
    var result = try materializer.plan(allocator, arena, .{
        .roots = roots,
        .gate = gate,
    });
    defer result.deinit();
}

const PoseidonFixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,

    fn init(allocator: std.mem.Allocator) !PoseidonFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource("air/components/poseidon2_m31.typed.zig");
        const gate_span = try spanAt(source_id, 1);
        const gate = try arena.input("riscv.poseidon2_m31.enabled", .selector, gate_span);
        const spans = try distinctSpans(source_id);
        const definition = try poseidon.define(&arena, spans);
        return .{ .arena = arena, .gate = gate, .spans = spans, .definition = definition };
    }

    fn deinit(self: *PoseidonFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn makePlan(self: *const PoseidonFixture, allocator: std.mem.Allocator) !materializer.Plan {
        const roots = poseidon.values(self.definition.outputs);
        return materializer.plan(allocator, &self.arena, .{
            .roots = &roots,
            .gate = self.gate,
        });
    }
};

fn distinctSpans(source_id: types.SourceId) !poseidon.DefinitionSpans {
    var next_line: u32 = 2;
    const declaration = try spanAt(source_id, next_line);
    next_line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, next_line);
        next_line += 1;
    }
    const initial_linear = try spanAt(source_id, next_line);
    next_line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, next_line),
            .sbox = try spanAt(source_id, next_line + 1),
            .linear = try spanAt(source_id, next_line + 2),
        };
        next_line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}
