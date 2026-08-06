const std = @import("std");
const search_policy = @import("cost_aware_materializer.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "cost-frontier search is deterministic feasible and replayable" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    const config = tinyConfig(64);

    var first = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer first.deinit();
    var replay = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer replay.deinit();

    try std.testing.expect(first.eql(&replay));
    try first.validateAgainst(std.testing.allocator, &fixture.arena, &plan, config);
    try std.testing.expect(first.attempted_evaluations != 0);
    try std.testing.expect(first.feasible_unique_proposals != 0);
    try std.testing.expect(first.baseline.cut.values.len == plan.materializations.len);
    try std.testing.expectEqual(@as(search_policy.EditKind, .seed), first.baseline.provenance.kind);
    for (first.frontier, 0..) |*proposal, index| {
        try std.testing.expect(proposal.provenance.kind != .seed);
        if (index != 0) try std.testing.expect(std.mem.order(
            u8,
            &first.frontier[index - 1].proposal_digest,
            &proposal.proposal_digest,
        ) == .lt);
    }
}

test "search budget is explicit and baseline survives truncation" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    const config = tinyConfig(1);
    var result = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 1), result.attempted_evaluations);
    try std.testing.expect(result.budget_exhausted);
    try std.testing.expectEqual(plan.materializations.len, result.baseline.cut.values.len);
    try result.validateAgainst(std.testing.allocator, &fixture.arena, &plan, config);
}

test "search configuration and retained identities fail closed" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();

    var invalid = tinyConfig(8);
    invalid.max_passes = 0;
    try std.testing.expectError(error.InvalidPassLimit, search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        invalid,
    ));
    invalid = tinyConfig(8);
    invalid.beam_width = 1;
    try std.testing.expectError(error.InvalidBeamWidth, search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        invalid,
    ));
    invalid = tinyConfig(8);
    invalid.log_sizes = &.{ 4, 4 };
    try std.testing.expectError(error.InvalidScenarioOrder, search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        invalid,
    ));

    const config = tinyConfig(8);
    var result = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer result.deinit();
    result.result_digest[0] ^= 1;
    try std.testing.expectError(error.ResultDigestMismatch, result.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    ));
    result.result_digest[0] ^= 1;
    result.baseline.report.vector.canonical_direct_nodes += 1;
    try std.testing.expectError(error.DigestMismatch, result.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    ));
}

test "bounded Poseidon search preserves the exact accepted seed" {
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
    const config = search_policy.SearchConfig{
        .max_passes = 1,
        .max_candidate_evaluations = 48,
        .beam_width = 24,
        .frontier_limit = 24,
        .geometry = .{ .fixed_direct_roots = poseidon_fixed.fixed_root_count },
        .fixed_direct_program = poseidon_fixed.program,
        .log_sizes = &.{6},
    };
    var result = try search_policy.search(
        std.testing.allocator,
        &arena,
        &plan,
        config,
    );
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 426), result.baseline.cut.values.len);
    try std.testing.expectEqual(@as(u64, 445), result.baseline.report.vector.candidate_main_columns);
    try std.testing.expectEqual(@as(u64, 2_171), result.baseline.report.vector.semantic_witness_nodes);
    try std.testing.expectEqual(@as(u64, 3_460), result.baseline.report.vector.canonical_direct_nodes);
    try std.testing.expectEqual(@as(u64, 445), result.baseline.report.vector.unique_committed_column_reads);
    try std.testing.expectEqual(
        @as(u64, 39),
        result.baseline.report.vector.canonical_streaming_peak_live_nodes,
    );
    try std.testing.expectEqual(@as(u32, 48), result.attempted_evaluations);
    try std.testing.expect(result.budget_exhausted);
    try result.validateAgainst(std.testing.allocator, &arena, &plan, config);
}

test "cost-frontier search releases every partial allocation" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{ &fixture.arena, &plan },
    );
}

const TinyFixture = struct {
    arena: ir.Arena,
    gate: types.ValueId,
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
        const ab = try arena.mul(a, b, span);
        const abc = try arena.mul(ab, c, span);
        const abd = try arena.mul(ab, d, span);
        const joined = try arena.mul(abc, abd, span);
        const root = try arena.add(joined, ab, span);
        return .{ .arena = arena, .gate = gate, .root = root };
    }

    fn deinit(self: *TinyFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn makePlan(self: *const TinyFixture, allocator: std.mem.Allocator) !materializer.Plan {
        const roots = [_]types.ValueId{self.root};
        return materializer.plan(allocator, &self.arena, .{
            .roots = &roots,
            .gate = self.gate,
        });
    }
};

fn tinyConfig(max_evaluations: u32) search_policy.SearchConfig {
    return .{
        .max_passes = 2,
        .max_candidate_evaluations = max_evaluations,
        .beam_width = 16,
        .frontier_limit = 16,
        .geometry = .{
            .base_main_columns = 2,
            .fixed_direct_roots = 0,
            .interaction_columns = 1,
        },
        .log_sizes = &.{},
    };
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    plan: *const materializer.Plan,
) !void {
    var result = try search_policy.search(allocator, arena, plan, tinyConfig(3));
    defer result.deinit();
}
