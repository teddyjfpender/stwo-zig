const std = @import("std");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const search_policy = @import("cost_aware_materializer.zig");
const ir = @import("ir.zig");
const manifest = @import("materialization_frontier_manifest.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const projection = @import("materialization_frontier_projection.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "search and STWAIRM projection share every canonical digest preimage" {
    var fixture = try TinyFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.plan(std.testing.allocator);
    defer plan.deinit();
    const config = tinyConfig();
    var result = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer result.deinit();
    var projected = try projection.fromSearch(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
        &result,
    );
    defer projected.deinit();
    const view = projected.view();

    try std.testing.expectEqualSlices(
        u8,
        &result.configuration_digest,
        &manifest.computeConfigurationDigest(view),
    );
    try expectProposalParity(&result.baseline, view.baseline, view);
    try std.testing.expectEqual(result.frontier.len, view.frontier.len);
    for (result.frontier, view.frontier) |*search_proposal, receipt_proposal|
        try expectProposalParity(search_proposal, receipt_proposal, view);
    try std.testing.expectEqualSlices(
        u8,
        &result.result_digest,
        &manifest.computeResultDigest(view),
    );

    const bytes = try manifest.encodeAlloc(std.testing.allocator, view);
    defer std.testing.allocator.free(bytes);
    var decoded = try manifest.decodeAlloc(std.testing.allocator, bytes);
    defer decoded.deinit();
    const replay = try manifest.encodeAlloc(std.testing.allocator, decoded.view());
    defer std.testing.allocator.free(replay);
    try std.testing.expectEqualSlices(u8, bytes, replay);
}

test "typed semantic search remains authenticated and legacy projection fails closed" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const instruction_clock = try arena.input("clock", .clock, generated);
    const previous_clock = try arena.input("previous-clock", .clock, generated);
    const active = try arena.input("active", .bit, generated);
    const register = try arena.input("register", .register_index, generated);
    const value = try arena.constantUnsigned(.byte, 0, generated);
    var schedule = try effects.AccessSchedule.begin(
        &arena,
        instruction_clock,
        active,
        generated,
    );
    const group = try schedule.registerRead(.{
        .index = register,
        .previous_clock = previous_clock,
        .value = .{ value, value, value, value },
    }, generated);
    const roots = [_]types.ValueId{
        arena.effectValues(group.emit).?[2],
        arena.effectValues(group.clock_gap).?[0],
    };
    var plan = try materializer.plan(std.testing.allocator, &arena, .{
        .roots = &roots,
        .gate = null,
    });
    defer plan.deinit();
    try std.testing.expectEqual(
        digest.register_group_format_version,
        plan.program_digest_format,
    );

    const config = tinyConfig();
    var result = try search_policy.search(
        std.testing.allocator,
        &arena,
        &plan,
        config,
    );
    defer result.deinit();
    try std.testing.expectEqual(
        digest.register_group_format_version,
        result.baseline.cut.program_digest_format,
    );
    try result.validateAgainst(std.testing.allocator, &arena, &plan, config);
    try std.testing.expectError(
        error.UnsupportedSemanticDigestFormat,
        projection.fromSearch(
            std.testing.allocator,
            &arena,
            &plan,
            config,
            &result,
        ),
    );
}

test "Poseidon projection binds the explicit fixed direct program and exact costs" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input("riscv.poseidon2_m31.enabled", .selector, generated);
    const definition = try poseidon.define(
        &arena,
        poseidon.DefinitionSpans.uniform(generated),
    );
    const roots = poseidon.values(definition.outputs);
    var plan = try materializer.plan(std.testing.allocator, &arena, .{
        .roots = &roots,
        .gate = gate,
    });
    defer plan.deinit();
    const config = search_policy.SearchConfig{
        .max_passes = 1,
        .max_candidate_evaluations = 16,
        .beam_width = 24,
        .frontier_limit = 24,
        .geometry = .{ .fixed_direct_roots = poseidon_fixed.fixed_root_count },
        .fixed_direct_program = poseidon_fixed.program,
        .log_sizes = &.{6},
    };
    var result = try search_policy.search(std.testing.allocator, &arena, &plan, config);
    defer result.deinit();
    var projected = try projection.fromSearch(
        std.testing.allocator,
        &arena,
        &plan,
        config,
        &result,
    );
    defer projected.deinit();

    try std.testing.expectEqual(
        manifest.CostScope.poseidon2_permutation_direct_v1,
        projected.cost_model.scope,
    );
    try std.testing.expectEqualSlices(
        u8,
        &poseidon_fixed.canonical_digest,
        &projected.cost_model.fixed_program_digest,
    );
    try std.testing.expectEqual(
        @as(u64, 3_460),
        projected.baseline.cost.canonical_direct_nodes,
    );
    try std.testing.expectEqual(
        @as(u64, 445),
        projected.baseline.cost.unique_committed_column_reads,
    );
    try std.testing.expectEqual(
        @as(u64, 39),
        projected.baseline.cost.canonical_streaming_peak_live_nodes,
    );
}

fn expectProposalParity(
    searched: *const search_policy.Proposal,
    projected: manifest.Proposal,
    receipt: manifest.Manifest,
) !void {
    try std.testing.expectEqualSlices(u8, &searched.cut_digest, &projected.cut_digest);
    try std.testing.expectEqualSlices(
        u8,
        &searched.proposal_digest,
        &projected.proposal_digest,
    );
    try std.testing.expectEqualSlices(
        u8,
        &searched.cut_digest,
        &manifest.computeCutDigest(receipt.identity, projected.selected_values),
    );
    try std.testing.expectEqualSlices(
        u8,
        &searched.proposal_digest,
        &manifest.computeProposalDigest(
            projected.cut_digest,
            receipt.cost_model.cost_model_digest,
            projected.cost,
            receipt.scenarios,
            projected.scenario_costs,
        ),
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
        const ab = try arena.mul(a, b, span);
        const abc = try arena.mul(ab, c, span);
        const root = try arena.mul(abc, ab, span);
        return .{ .arena = arena, .gate = gate, .root = root };
    }

    fn plan(self: *const TinyFixture, allocator: std.mem.Allocator) !materializer.Plan {
        const roots = [_]types.ValueId{self.root};
        return materializer.plan(allocator, &self.arena, .{
            .roots = &roots,
            .gate = self.gate,
        });
    }

    fn deinit(self: *TinyFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn tinyConfig() search_policy.SearchConfig {
    return .{
        .max_passes = 1,
        .max_candidate_evaluations = 16,
        .beam_width = 24,
        .frontier_limit = 24,
        .geometry = .{ .base_main_columns = 2, .interaction_columns = 1 },
        .log_sizes = &.{2},
    };
}
