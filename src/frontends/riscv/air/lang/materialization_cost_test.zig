const std = @import("std");
const cost = @import("materialization_cost.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const types = @import("types.zig");

test "materialization costs globally share a hand-computed direct DAG" {
    var fixture = try TinyFixture.init(std.testing.allocator, false);
    defer fixture.deinit();
    const roots = [_]types.ValueId{ fixture.y, fixture.z };
    const selected = roots;
    var report = try cost.analyze(std.testing.allocator, &fixture.arena, .{
        .roots = &roots,
        .gate = null,
        .selected = &selected,
        .geometry = .{
            .base_main_columns = 2,
            .fixed_direct_roots = 0,
            .interaction_columns = 1,
        },
        .log_sizes = &.{2},
    });
    defer report.deinit();

    try std.testing.expectEqual(@as(u64, 2), report.vector.materialization_count);
    try std.testing.expectEqual(@as(u64, 2), report.vector.base_main_columns);
    try std.testing.expectEqual(@as(u64, 4), report.vector.candidate_main_columns);
    try std.testing.expectEqual(@as(u64, 2), report.vector.direct_roots);
    try std.testing.expectEqual(@as(u64, 9), report.vector.canonical_direct_nodes);
    try std.testing.expectEqual(@as(u64, 2), report.vector.canonical_direct_additions);
    try std.testing.expectEqual(@as(u64, 2), report.vector.canonical_direct_subtractions);
    try std.testing.expectEqual(@as(u64, 0), report.vector.canonical_direct_negations);
    // The shared `a * b` is one node globally, not one multiplication per root.
    try std.testing.expectEqual(@as(u64, 1), report.vector.canonical_direct_multiplications);
    try std.testing.expectEqual(@as(u64, 4), report.vector.unique_committed_column_reads);
    try std.testing.expectEqual(@as(u64, 5), report.vector.canonical_streaming_peak_live_nodes);
    try std.testing.expectEqual(@as(u64, 5), report.vector.semantic_witness_nodes);

    try std.testing.expectEqualDeep(cost.ScenarioCost{
        .log_size = 2,
        .rows = 4,
        .main_cells = 16,
        .interaction_cells = 4,
        .committed_cells = 20,
        .main_bytes = 64,
        .interaction_bytes = 16,
        .committed_bytes = 80,
    }, report.scenarios[0]);
}

test "gate row mask and negation use one shared canonical context" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input("gate", .selector, generated);
    const value = try arena.input("value", .felt, generated);
    const negated = try arena.neg(value, generated);
    const roots = [_]types.ValueId{negated};

    var report = try cost.analyze(std.testing.allocator, &arena, .{
        .roots = &roots,
        .gate = gate,
        .policy = .{ .row_mask_degree = 1 },
        .selected = &roots,
        .geometry = .{
            .base_main_columns = 2,
            .fixed_direct_roots = 0,
            .interaction_columns = 0,
        },
    });
    defer report.deinit();

    try std.testing.expectEqual(@as(u64, 8), report.vector.canonical_direct_nodes);
    try std.testing.expectEqual(@as(u64, 0), report.vector.canonical_direct_additions);
    try std.testing.expectEqual(@as(u64, 1), report.vector.canonical_direct_subtractions);
    try std.testing.expectEqual(@as(u64, 1), report.vector.canonical_direct_negations);
    try std.testing.expectEqual(@as(u64, 2), report.vector.canonical_direct_multiplications);
    try std.testing.expectEqual(@as(u64, 3), report.vector.unique_committed_column_reads);
    try std.testing.expectEqual(@as(u64, 4), report.vector.canonical_streaming_peak_live_nodes);
    // Gate and physical context are deliberately outside the semantic closure.
    try std.testing.expectEqual(@as(u64, 2), report.vector.semantic_witness_nodes);
}

test "Pareto helpers preserve equality dominance and incomparability" {
    var fixture = try TinyFixture.init(std.testing.allocator, false);
    defer fixture.deinit();
    const roots = [_]types.ValueId{ fixture.y, fixture.z };
    var report = try cost.analyze(std.testing.allocator, &fixture.arena, .{
        .roots = &roots,
        .gate = null,
        .selected = &roots,
        .log_sizes = &.{3},
    });
    defer report.deinit();

    try std.testing.expect(report.eql(&report));
    try std.testing.expect(!report.dominates(&report));
    try std.testing.expectEqual(std.math.Order.eq, report.canonicalOrder(&report));

    var structurally_smaller = report;
    structurally_smaller.vector.canonical_direct_nodes -= 1;
    try std.testing.expect(structurally_smaller.dominates(&report));
    try std.testing.expect(!report.dominates(&structurally_smaller));

    var fewer_columns = report;
    fewer_columns.vector.candidate_main_columns -= 1;
    fewer_columns.vector.canonical_direct_multiplications += 1;
    var fewer_multiplications = report;
    fewer_multiplications.vector.candidate_main_columns += 1;
    fewer_multiplications.vector.canonical_direct_multiplications -= 1;
    try std.testing.expect(!fewer_columns.dominates(&fewer_multiplications));
    try std.testing.expect(!fewer_multiplications.dominates(&fewer_columns));
    try std.testing.expectEqual(
        std.math.Order.lt,
        fewer_columns.canonicalOrder(&fewer_multiplications),
    );
}

test "cost geometry rejects every unchecked shape" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const root = try arena.input("root", .felt, source.SourceSpan.generated());
    const roots = [_]types.ValueId{root};

    try std.testing.expectError(error.InvalidLogSize, cost.analyze(
        std.testing.allocator,
        &arena,
        .{ .roots = &roots, .gate = null, .selected = &roots, .log_sizes = &.{64} },
    ));
    try std.testing.expectError(error.InvalidScenarioOrder, cost.analyze(
        std.testing.allocator,
        &arena,
        .{ .roots = &roots, .gate = null, .selected = &roots, .log_sizes = &.{ 3, 3 } },
    ));
    try std.testing.expectError(error.GeometryOverflow, cost.analyze(
        std.testing.allocator,
        &arena,
        .{
            .roots = &roots,
            .gate = null,
            .selected = &roots,
            .geometry = .{ .base_main_columns = std.math.maxInt(u64) },
        },
    ));
    try std.testing.expectError(error.GeometryOverflow, cost.analyze(
        std.testing.allocator,
        &arena,
        .{
            .roots = &roots,
            .gate = null,
            .selected = &roots,
            .geometry = .{ .field_element_bytes = std.math.maxInt(u64) },
            .log_sizes = &.{0},
        },
    ));
}

test "candidate validation rejects noncanonical incomplete and infeasible cuts" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input("gate", .selector, generated);
    const a = try arena.input("a", .felt, generated);
    const b = try arena.input("b", .felt, generated);
    const c = try arena.input("c", .felt, generated);
    const product = try arena.mul(a, b, generated);
    const cube = try arena.mul(product, c, generated);
    const detached = try arena.neg(c, generated);
    const roots = [_]types.ValueId{cube};

    try std.testing.expectError(error.NonCanonicalSelection, cost.analyze(
        std.testing.allocator,
        &arena,
        .{
            .roots = &roots,
            .gate = gate,
            .selected = &.{ cube, product },
        },
    ));
    try std.testing.expectError(error.MissingSelectedRoot, cost.analyze(
        std.testing.allocator,
        &arena,
        .{ .roots = &roots, .gate = gate, .selected = &.{product} },
    ));
    try std.testing.expectError(error.SelectedValueOutsideRootClosure, cost.analyze(
        std.testing.allocator,
        &arena,
        .{ .roots = &roots, .gate = gate, .selected = &.{ cube, detached } },
    ));
    try std.testing.expectError(error.InfeasibleSelection, cost.analyze(
        std.testing.allocator,
        &arena,
        .{ .roots = &roots, .gate = gate, .selected = &.{cube} },
    ));

    var valid = try cost.analyze(std.testing.allocator, &arena, .{
        .roots = &roots,
        .gate = gate,
        .selected = &.{ product, cube },
    });
    defer valid.deinit();
    try std.testing.expectEqual(@as(u64, 2), valid.vector.materialization_count);

    var overflow_arena = ir.Arena.init(std.testing.allocator);
    defer overflow_arena.deinit();
    var square = try overflow_arena.input("square", .felt, generated);
    for (0..64) |_| square = try overflow_arena.mul(square, square, generated);
    const overflow_roots = [_]types.ValueId{square};
    try std.testing.expectError(error.DegreeOverflow, cost.analyze(
        std.testing.allocator,
        &overflow_arena,
        .{ .roots = &overflow_roots, .gate = null, .selected = &overflow_roots },
    ));
}

test "cost reports ignore allocation and independent input insertion order" {
    var first = try TinyFixture.init(std.testing.allocator, false);
    defer first.deinit();
    var second = try TinyFixture.init(std.testing.allocator, true);
    defer second.deinit();
    const first_roots = [_]types.ValueId{ first.y, first.z };
    const second_roots = [_]types.ValueId{ second.y, second.z };

    var first_report = try cost.analyze(std.testing.allocator, &first.arena, .{
        .roots = &first_roots,
        .gate = null,
        .selected = &first_roots,
        .log_sizes = &.{ 4, 8 },
    });
    defer first_report.deinit();
    var replay = try cost.analyze(std.testing.allocator, &first.arena, .{
        .roots = &first_roots,
        .gate = null,
        .selected = &first_roots,
        .log_sizes = &.{ 4, 8 },
    });
    defer replay.deinit();
    var second_report = try cost.analyze(std.testing.allocator, &second.arena, .{
        .roots = &second_roots,
        .gate = null,
        .selected = &second_roots,
        .log_sizes = &.{ 4, 8 },
    });
    defer second_report.deinit();

    try std.testing.expect(first_report.eql(&replay));
    try std.testing.expect(first_report.eql(&second_report));
}

test "canonical Poseidon baseline reports the frozen component geometry" {
    const materializer = @import("degree3_materializer.zig");
    const poseidon = @import("typed_poseidon2.zig");
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input("riscv.poseidon2_m31.enabled", .selector, generated);
    const definition = try poseidon.define(&arena, poseidon.DefinitionSpans.uniform(generated));
    const roots = poseidon.values(definition.outputs);
    var plan = try materializer.plan(std.testing.allocator, &arena, .{
        .roots = &roots,
        .gate = gate,
    });
    defer plan.deinit();
    const selected = try std.testing.allocator.alloc(types.ValueId, plan.materializations.len);
    defer std.testing.allocator.free(selected);
    for (plan.materializations, selected) |item, *value| value.* = item.source_value;
    std.mem.sort(types.ValueId, selected, {}, valueLessThan);

    var report = try cost.analyze(std.testing.allocator, &arena, .{
        .roots = &roots,
        .gate = gate,
        .selected = selected,
        .geometry = .{ .fixed_direct_roots = poseidon_fixed.fixed_root_count },
        .fixed_direct_program = poseidon_fixed.program,
        .log_sizes = &.{ 10, 20 },
    });
    defer report.deinit();

    try std.testing.expectEqual(@as(u64, 426), report.vector.materialization_count);
    try std.testing.expectEqual(@as(u64, 19), report.vector.base_main_columns);
    try std.testing.expectEqual(@as(u64, 445), report.vector.candidate_main_columns);
    try std.testing.expectEqual(@as(u64, 430), report.vector.direct_roots);
    try std.testing.expectEqual(@as(u64, 8), report.vector.interaction_columns);
    try std.testing.expectEqual(@as(u64, 3_460), report.vector.canonical_direct_nodes);
    try std.testing.expectEqual(@as(u64, 1_346), report.vector.canonical_direct_additions);
    try std.testing.expectEqual(@as(u64, 429), report.vector.canonical_direct_subtractions);
    try std.testing.expectEqual(@as(u64, 0), report.vector.canonical_direct_negations);
    try std.testing.expectEqual(@as(u64, 1_080), report.vector.canonical_direct_multiplications);
    try std.testing.expectEqual(@as(u64, 2_171), report.vector.semantic_witness_nodes);
    try std.testing.expectEqual(@as(u64, 445), report.vector.unique_committed_column_reads);
    try std.testing.expectEqual(@as(u64, 39), report.vector.canonical_streaming_peak_live_nodes);
    try std.testing.expectEqual(@as(u64, 445 * 1024), report.scenarios[0].main_cells);
    try std.testing.expectEqual(@as(u64, 8 * 1024), report.scenarios[0].interaction_cells);
    try std.testing.expectEqual(
        @as(u64, (445 + 8) * 1024 * 4),
        report.scenarios[0].committed_bytes,
    );
}

test "materialization cost construction releases every partial allocation" {
    var fixture = try TinyFixture.init(std.testing.allocator, false);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{ &fixture.arena, fixture.y, fixture.z },
    );
}

const TinyFixture = struct {
    arena: ir.Arena,
    y: types.ValueId,
    z: types.ValueId,

    fn init(allocator: std.mem.Allocator, reverse_inputs: bool) !TinyFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        var a: types.ValueId = undefined;
        var b: types.ValueId = undefined;
        if (reverse_inputs) {
            b = try arena.input("b", .felt, generated);
            a = try arena.input("a", .felt, generated);
        } else {
            a = try arena.input("a", .felt, generated);
            b = try arena.input("b", .felt, generated);
        }
        const shared = try arena.mul(a, b, generated);
        const y = try arena.add(shared, a, generated);
        const z = try arena.add(shared, b, generated);
        return .{ .arena = arena, .y = y, .z = z };
    }

    fn deinit(self: *TinyFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    y: types.ValueId,
    z: types.ValueId,
) !void {
    const roots = [_]types.ValueId{ y, z };
    var report = try cost.analyze(allocator, arena, .{
        .roots = &roots,
        .gate = null,
        .selected = &roots,
        .log_sizes = &.{ 4, 8 },
    });
    defer report.deinit();
}

fn valueLessThan(_: void, lhs: types.ValueId, rhs: types.ValueId) bool {
    return @intFromEnum(lhs) < @intFromEnum(rhs);
}
