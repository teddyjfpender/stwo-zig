//! Fail-closed projection from an authenticated bounded search to `STWAIRM`.

const std = @import("std");
const digest = @import("digest.zig");
const search_policy = @import("cost_aware_materializer.zig");
const frontier_digest = @import("materialization_frontier_digest.zig");
const ir = @import("ir.zig");
const manifest = @import("materialization_frontier_manifest.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const types = @import("types.zig");

pub const Error = search_policy.Error || manifest.ManifestError || error{
    CostOverflow,
    UnsupportedSemanticDigestFormat,
    UnsupportedCostScope,
};

pub const Owned = struct {
    allocator: std.mem.Allocator,
    roots: []u32,
    scenarios: []manifest.Scenario,
    baseline: manifest.Proposal,
    frontier: []manifest.Proposal,
    identity: manifest.Identity,
    search: manifest.SearchConfig,
    cost_model: manifest.CostModelIdentity,
    geometry: manifest.Geometry,
    run: manifest.RunAccounting,

    pub fn view(self: *const Owned) manifest.Manifest {
        return .{
            .identity = self.identity,
            .search = self.search,
            .cost_model = self.cost_model,
            .geometry = self.geometry,
            .scenarios = self.scenarios,
            .run = self.run,
            .baseline = self.baseline,
            .frontier = self.frontier,
        };
    }

    pub fn deinit(self: *Owned) void {
        deinitProposal(self.allocator, self.baseline);
        for (self.frontier) |proposal| deinitProposal(self.allocator, proposal);
        self.allocator.free(self.frontier);
        self.allocator.free(self.scenarios);
        self.allocator.free(self.roots);
        self.* = undefined;
    }
};

/// Replays and authenticates `result` before copying any receipt authority.
pub fn fromSearch(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    seed_plan: *const materializer.Plan,
    config: search_policy.SearchConfig,
    result: *const search_policy.Result,
) Error!Owned {
    try result.validateAgainst(allocator, arena, seed_plan, config);
    if (result.baseline.cut.program_digest_format != digest.format_version)
        return error.UnsupportedSemanticDigestFormat;

    const roots = try idsAlloc(allocator, result.baseline.cut.roots);
    errdefer allocator.free(roots);
    const scenarios = try allocator.alloc(manifest.Scenario, config.log_sizes.len);
    errdefer allocator.free(scenarios);
    for (config.log_sizes, scenarios) |log_size, *scenario| scenario.* = .{
        .log_size = log_size,
        .rows = checkedRows(log_size) catch return error.CostOverflow,
    };

    const model_view = try search_policy.costModelIdentity(allocator, config);
    const model = try projectCostModel(model_view);
    const geometry = projectGeometry(config.geometry);
    const identity = blk: {
        var value = manifest.Identity{
            .semantic_digest = result.baseline.cut.program_digest,
            .roots = roots,
            .gate = if (result.baseline.cut.gate) |gate| @intFromEnum(gate) else null,
            .seed_policy_version = materializer.policy_version,
            .maximum_constraint_degree = result.baseline.cut.policy.maximum_constraint_degree,
            .row_mask_degree = result.baseline.cut.policy.row_mask_degree,
            .identity_digest = undefined,
        };
        value.identity_digest = manifest.computeIdentityDigest(value);
        break :blk value;
    };
    const search = manifest.SearchConfig{
        .version = search_policy.search_digest_version,
        .max_passes = config.max_passes,
        .beam_width = config.beam_width,
        .max_candidate_evaluations = config.max_candidate_evaluations,
        .frontier_limit = config.frontier_limit,
        .configuration_digest = result.configuration_digest,
    };

    const baseline = try proposalAlloc(allocator, &result.baseline);
    errdefer deinitProposal(allocator, baseline);
    const frontier = try allocator.alloc(manifest.Proposal, result.frontier.len);
    errdefer allocator.free(frontier);
    var initialized: usize = 0;
    errdefer for (frontier[0..initialized]) |proposal|
        deinitProposal(allocator, proposal);
    while (initialized < frontier.len) : (initialized += 1)
        frontier[initialized] = try proposalAlloc(
            allocator,
            &result.frontier[initialized],
        );

    const owned = Owned{
        .allocator = allocator,
        .roots = roots,
        .scenarios = scenarios,
        .baseline = baseline,
        .frontier = frontier,
        .identity = identity,
        .search = search,
        .cost_model = model,
        .geometry = geometry,
        .run = .{
            .attempted_evaluations = result.attempted_evaluations,
            .feasible_unique_proposals = result.feasible_unique_proposals,
            .duplicate_proposals = result.duplicate_proposals,
            .rejected_infeasible = result.rejected_infeasible,
            .passes_completed = result.passes_completed,
            .budget_exhausted = result.budget_exhausted,
            .frontier_truncated = result.frontier_truncated,
            .result_digest = result.result_digest,
        },
    };
    try manifest.validateCanonical(owned.view());
    return owned;
}

fn projectCostModel(
    value: frontier_digest.CostModelIdentity,
) Error!manifest.CostModelIdentity {
    const scope: manifest.CostScope = if (std.mem.eql(
        u8,
        value.scope_id,
        search_policy.semantic_equalities_cost_scope,
    ))
        .semantic_equalities_only
    else if (std.mem.eql(u8, value.scope_id, poseidon_fixed.cost_scope_id))
        .poseidon2_permutation_direct_v1
    else
        return error.UnsupportedCostScope;
    const result = manifest.CostModelIdentity{
        .scope = scope,
        .scope_version = value.scope_version,
        .fixed_program_format_version = value.fixed_program_format_version,
        .fixed_program_digest = value.fixed_program_digest,
        .fixed_column_count = value.fixed_column_count,
        .fixed_node_count = value.fixed_node_count,
        .fixed_root_count = value.fixed_root_count,
        .evaluation_schedule = value.evaluation_schedule,
        .cost_model_digest = frontier_digest.computeCostModel(value),
    };
    return result;
}

fn projectGeometry(value: anytype) manifest.Geometry {
    return .{
        .preprocessed_columns = value.preprocessed_columns,
        .base_main_columns = value.base_main_columns,
        .fixed_direct_roots = value.fixed_direct_roots,
        .interaction_columns = value.interaction_columns,
        .field_element_bytes = value.field_element_bytes,
    };
}

fn proposalAlloc(
    allocator: std.mem.Allocator,
    proposal: *const search_policy.Proposal,
) std.mem.Allocator.Error!manifest.Proposal {
    const selected = try idsAlloc(allocator, proposal.cut.values);
    errdefer allocator.free(selected);
    const scenario_costs = try allocator.alloc(
        manifest.ScenarioCost,
        proposal.report.scenarios.len,
    );
    errdefer allocator.free(scenario_costs);
    for (proposal.report.scenarios, scenario_costs) |source, *destination|
        destination.* = .{
            .main_cells = source.main_cells,
            .interaction_cells = source.interaction_cells,
            .committed_cells = source.committed_cells,
            .main_bytes = source.main_bytes,
            .interaction_bytes = source.interaction_bytes,
            .committed_bytes = source.committed_bytes,
        };
    return .{
        .proposal_digest = proposal.proposal_digest,
        .cut_digest = proposal.cut_digest,
        .provenance = .{
            .kind = proposal.provenance.kind,
            .pass = proposal.provenance.pass,
            .parent_cut_digest = proposal.provenance.parent_cut_digest,
            .removed = optionalId(proposal.provenance.removed),
            .added = optionalId(proposal.provenance.added),
        },
        .selected_values = selected,
        .cost = projectCost(proposal.report.vector),
        .scenario_costs = scenario_costs,
    };
}

fn projectCost(value: anytype) manifest.CostVector {
    var result: manifest.CostVector = undefined;
    inline for (std.meta.fields(manifest.CostVector)) |field|
        @field(result, field.name) = @field(value, field.name);
    return result;
}

fn idsAlloc(allocator: std.mem.Allocator, ids: anytype) ![]u32 {
    const result = try allocator.alloc(u32, ids.len);
    for (ids, result) |value, *destination| destination.* = switch (@typeInfo(@TypeOf(value))) {
        .@"enum" => @intFromEnum(value),
        else => @intCast(value),
    };
    return result;
}

fn optionalId(value: ?types.ValueId) ?u32 {
    return if (value) |present| @intFromEnum(present) else null;
}

fn checkedRows(log_size: u8) error{CostOverflow}!u64 {
    if (log_size >= @bitSizeOf(u64)) return error.CostOverflow;
    return @as(u64, 1) << @intCast(log_size);
}

fn deinitProposal(allocator: std.mem.Allocator, proposal: manifest.Proposal) void {
    allocator.free(proposal.scenario_costs);
    allocator.free(proposal.selected_values);
}
