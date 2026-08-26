const std = @import("std");
const search_policy = @import("cost_aware_materializer.zig");
const cost = @import("materialization_cost.zig");
const frontier_digest = @import("materialization_frontier_digest.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "result validation closes the complete search accounting equation" {
    var fixture = try BranchFixture.init(std.testing.allocator, 1);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    const config = searchConfig(16, 13);
    var result = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer result.deinit();

    result.duplicate_proposals += 1;
    try std.testing.expectError(error.InvalidSearchAccounting, result.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    ));
}

test "a locally authenticated baseline duplicate remains forbidden" {
    var fixture = try BranchFixture.init(std.testing.allocator, 1);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    const config = searchConfig(16, 13);
    var result = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer result.deinit();

    const original_frontier = result.frontier;
    const forged = try std.testing.allocator.alloc(search_policy.Proposal, 1);
    defer std.testing.allocator.free(forged);
    result.frontier = forged;
    defer result.frontier = original_frontier;
    forged[0] = result.baseline;
    forged[0].provenance = .{
        .kind = .add,
        .pass = 1,
        .parent_cut_digest = result.baseline.cut_digest,
        .added = result.baseline.cut.values[0],
    };
    authenticateLocalMutation(&result);

    try std.testing.expectError(error.InvalidBaseline, result.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    ));
}

test "provenance rejects impossible edit state before exact replay" {
    var fixture = try BranchFixture.init(std.testing.allocator, 1);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    const config = searchConfig(16, 13);
    var result = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer result.deinit();

    const original_frontier = result.frontier;
    const forged = try std.testing.allocator.alloc(search_policy.Proposal, 1);
    defer std.testing.allocator.free(forged);
    result.frontier = forged;
    defer result.frontier = original_frontier;
    forged[0] = result.baseline;
    forged[0].provenance = .{
        .kind = .remove,
        .pass = 1,
        .parent_cut_digest = result.baseline.cut_digest,
        .removed = result.baseline.cut.values[0],
    };
    authenticateLocalMutation(&result);

    try std.testing.expectError(error.InvalidProvenance, result.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    ));
}

test "exact replay rejects locally plausible but false edit provenance" {
    var fixture = try BranchFixture.init(std.testing.allocator, 1);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    const config = searchConfig(16, 13);
    var result = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    );
    defer result.deinit();
    try std.testing.expect(result.frontier.len != 0);

    const proposal = &result.frontier[0];
    proposal.provenance = .{
        .kind = .add,
        .pass = 1,
        .parent_cut_digest = result.baseline.cut_digest,
        .added = proposal.cut.roots[0],
    };
    authenticateLocalMutation(&result);
    try std.testing.expectError(error.SearchReplayMismatch, result.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        config,
    ));
}

test "frontier truncation retains every coordinate minimum with canonical ties" {
    var fixture = try BranchFixture.init(std.testing.allocator, 16);
    defer fixture.deinit();
    var plan = try fixture.makePlan(std.testing.allocator);
    defer plan.deinit();
    const full_config = searchConfig(64, 64);
    var full = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        full_config,
    );
    defer full.deinit();
    const limited_config = searchConfig(64, 13);
    var limited = try search_policy.search(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        limited_config,
    );
    defer limited.deinit();

    try std.testing.expectEqual(@as(usize, 16), full.frontier.len);
    try std.testing.expect(!full.frontier_truncated);
    try std.testing.expectEqual(@as(usize, 13), limited.frontier.len);
    try std.testing.expect(limited.frontier_truncated);
    for (limited.frontier, full.frontier[0..limited.frontier.len]) |kept, canonical| {
        try std.testing.expectEqual(canonical.proposal_digest, kept.proposal_digest);
    }
    inline for (std.meta.fields(cost.CostVector)) |field| {
        var minimum: u64 = std.math.maxInt(u64);
        for (full.frontier) |proposal|
            minimum = @min(minimum, @field(proposal.report.vector, field.name));
        var retained = false;
        for (limited.frontier) |proposal| {
            if (@field(proposal.report.vector, field.name) == minimum)
                retained = true;
        }
        try std.testing.expect(retained);
    }
    try full.validateAgainst(std.testing.allocator, &fixture.arena, &plan, full_config);
    try limited.validateAgainst(std.testing.allocator, &fixture.arena, &plan, limited_config);
}

fn authenticateLocalMutation(result: *search_policy.Result) void {
    result.result_digest = frontier_digest.computeResult(
        result.configuration_digest,
        result.baseline,
        result.*,
        result.frontier,
    );
}

fn searchConfig(max_evaluations: u32, frontier_limit: u16) search_policy.SearchConfig {
    return .{
        .max_passes = 1,
        .max_candidate_evaluations = max_evaluations,
        .beam_width = 64,
        .frontier_limit = frontier_limit,
        .geometry = .{
            .base_main_columns = 0,
            .fixed_direct_roots = 0,
            .interaction_columns = 0,
        },
        .log_sizes = &.{},
    };
}

const BranchFixture = struct {
    allocator: std.mem.Allocator,
    arena: ir.Arena,
    roots: []types.ValueId,

    fn init(allocator: std.mem.Allocator, branch_count: usize) !BranchFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const roots = try allocator.alloc(types.ValueId, branch_count);
        errdefer allocator.free(roots);
        const span = source.SourceSpan.generated();
        for (roots, 0..) |*root, branch| {
            const a = try branchInput(&arena, branch, "a", span);
            const b = try branchInput(&arena, branch, "b", span);
            const c = try branchInput(&arena, branch, "c", span);
            const d = try branchInput(&arena, branch, "d", span);
            const x = try arena.mul(a, b, span);
            const y = try arena.mul(x, c, span);
            root.* = try arena.mul(y, d, span);
        }
        return .{ .allocator = allocator, .arena = arena, .roots = roots };
    }

    fn deinit(self: *BranchFixture) void {
        self.allocator.free(self.roots);
        self.arena.deinit();
        self.* = undefined;
    }

    fn makePlan(
        self: *const BranchFixture,
        allocator: std.mem.Allocator,
    ) !materializer.Plan {
        return materializer.plan(allocator, &self.arena, .{
            .roots = self.roots,
            .gate = null,
        });
    }
};

fn branchInput(
    arena: *ir.Arena,
    branch: usize,
    suffix: []const u8,
    span: source.SourceSpan,
) !types.ValueId {
    var buffer: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&buffer, "search.branch.{d}.{s}", .{
        branch,
        suffix,
    });
    return arena.input(name, .felt, span);
}
