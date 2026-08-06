//! Bounded deterministic search for materialization cost-frontier proposals.
//!
//! This is an experimental policy, not a production layout authority. Every
//! candidate is rebuilt by `materialization_cut_set` and measured by the
//! globally hash-consed direct-DAG model. Search uses no timing, randomness,
//! floating point, or backend identity. The accepted degree-bounded plan is
//! retained separately even when an explored proposal dominates it.

const std = @import("std");
const cost = @import("materialization_cost.zig");
const cut_set = @import("materialization_cut_set.zig");
const digest = @import("digest.zig");
const frontier_digest = @import("materialization_frontier_digest.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const fixed_direct = @import("materialization_fixed_direct.zig");
const retention = @import("materialization_frontier_retention.zig");
const neighbourhood = @import("materialization_neighbourhood.zig");
const types = @import("types.zig");

pub const policy_id = "stwo.typed-air.materialize.cost-frontier-v1";
pub const policy_version: u16 = 1;
pub const cut_digest_version = frontier_digest.cut_digest_version;
pub const proposal_digest_version = frontier_digest.proposal_digest_version;
pub const search_digest_version = frontier_digest.search_digest_version;
pub const semantic_equalities_cost_scope =
    "stwo.typed-air.cost.semantic-equalities-only";

pub const SearchConfig = struct {
    max_passes: u16 = 3,
    max_candidate_evaluations: u32 = 4_096,
    beam_width: u16 = 64,
    frontier_limit: u16 = 128,
    geometry: cost.Geometry = .{},
    fixed_direct_program: ?fixed_direct.Program = null,
    log_sizes: []const u8 = &.{ 4, 6, 10, 14, 18 },

    pub fn validate(self: SearchConfig) ValidationError!void {
        if (self.max_passes == 0 or self.max_passes > 32)
            return error.InvalidPassLimit;
        if (self.max_candidate_evaluations == 0 or
            self.max_candidate_evaluations > 1_000_000)
        {
            return error.InvalidEvaluationLimit;
        }
        if (self.log_sizes.len > 16) return error.TooManyScenarios;
        for (self.log_sizes, 0..) |log_size, index| {
            if (log_size >= @bitSizeOf(u64)) return error.InvalidLogSize;
            if (index != 0 and self.log_sizes[index - 1] >= log_size)
                return error.InvalidScenarioOrder;
        }
        if (self.geometry.field_element_bytes == 0)
            return error.InvalidCellWidth;
        const fixed_roots: u64 = if (self.fixed_direct_program) |program|
            @intCast(program.prefix_roots.len + program.suffix_roots.len)
        else
            0;
        if (fixed_roots != self.geometry.fixed_direct_roots)
            return error.FixedRootCountMismatch;
        const minimum = retention.rankedCoordinateCount(self.log_sizes.len);
        if (self.beam_width < minimum or self.beam_width > 4_096)
            return error.InvalidBeamWidth;
        if (self.frontier_limit < minimum or self.frontier_limit > 4_096)
            return error.InvalidFrontierLimit;
    }
};

pub const EditKind = frontier_digest.EditKind;

pub const Provenance = struct {
    kind: EditKind,
    pass: u16,
    parent_cut_digest: digest.Digest,
    removed: ?types.ValueId = null,
    added: ?types.ValueId = null,
};

pub const Proposal = struct {
    cut: cut_set.CutSet,
    report: cost.Report,
    cut_digest: digest.Digest,
    proposal_digest: digest.Digest,
    provenance: Provenance,

    pub fn deinit(self: *Proposal) void {
        self.report.deinit();
        self.cut.deinit();
        self.* = undefined;
    }

    pub fn eql(self: *const Proposal, other: *const Proposal) bool {
        return std.mem.eql(u8, &self.cut_digest, &other.cut_digest) and
            std.mem.eql(u8, &self.proposal_digest, &other.proposal_digest) and
            std.meta.eql(self.provenance, other.provenance) and
            std.mem.eql(types.ValueId, self.cut.values, other.cut.values) and
            self.report.eql(&other.report);
    }
};

pub const Result = struct {
    allocator: std.mem.Allocator,
    configuration_digest: digest.Digest,
    result_digest: digest.Digest,
    baseline: Proposal,
    /// Nondominated, non-seed proposals in proposal-digest order.
    frontier: []Proposal,
    attempted_evaluations: u32,
    feasible_unique_proposals: u32,
    duplicate_proposals: u32,
    rejected_infeasible: u32,
    passes_completed: u16,
    budget_exhausted: bool,
    frontier_truncated: bool,

    pub fn deinit(self: *Result) void {
        for (self.frontier) |*proposal| proposal.deinit();
        self.allocator.free(self.frontier);
        self.baseline.deinit();
        self.* = undefined;
    }

    pub fn eql(self: *const Result, other: *const Result) bool {
        if (!std.mem.eql(u8, &self.configuration_digest, &other.configuration_digest) or
            !std.mem.eql(u8, &self.result_digest, &other.result_digest) or
            !self.baseline.eql(&other.baseline) or
            self.frontier.len != other.frontier.len or
            self.attempted_evaluations != other.attempted_evaluations or
            self.feasible_unique_proposals != other.feasible_unique_proposals or
            self.duplicate_proposals != other.duplicate_proposals or
            self.rejected_infeasible != other.rejected_infeasible or
            self.passes_completed != other.passes_completed or
            self.budget_exhausted != other.budget_exhausted or
            self.frontier_truncated != other.frontier_truncated)
        {
            return false;
        }
        for (self.frontier, other.frontier) |*lhs, *rhs| {
            if (!lhs.eql(rhs)) return false;
        }
        return true;
    }

    /// Recomputes every retained cut, cost, and digest, then exactly replays the
    /// bounded search and rejects any result that differs from that replay.
    pub fn validateAgainst(
        self: *const Result,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        seed_plan: *const materializer.Plan,
        config: SearchConfig,
    ) Error!void {
        try config.validate();
        if (self.attempted_evaluations > config.max_candidate_evaluations or
            self.feasible_unique_proposals > self.attempted_evaluations or
            @as(u64, self.attempted_evaluations) !=
                @as(u64, self.feasible_unique_proposals) +
                    @as(u64, self.duplicate_proposals) +
                    @as(u64, self.rejected_infeasible) or
            self.passes_completed > config.max_passes or
            self.frontier.len > config.frontier_limit)
        {
            return error.InvalidSearchAccounting;
        }

        var expected_cut = try cut_set.fromDegree3Plan(allocator, arena, seed_plan);
        defer expected_cut.deinit();
        const model = try costModelIdentity(allocator, config);
        const model_digest = frontier_digest.computeCostModel(model);
        const expected_config_digest = configurationDigestWithModel(
            &expected_cut,
            config,
            model_digest,
        );
        if (!std.mem.eql(u8, &self.configuration_digest, &expected_config_digest))
            return error.ConfigurationDigestMismatch;
        try validateProposal(&self.baseline, allocator, arena, config, model_digest);
        if (!sameAuthority(&self.baseline.cut, &expected_cut) or
            !validSeedProvenance(self.baseline.provenance))
        {
            return error.InvalidBaseline;
        }

        for (self.frontier, 0..) |*proposal, index| {
            try validateProposal(proposal, allocator, arena, config, model_digest);
            if (!sameRequest(&proposal.cut, &expected_cut) or
                !validEditProvenance(
                    proposal.provenance,
                    self.passes_completed,
                    proposal.cut.values,
                ))
            {
                return error.InvalidProvenance;
            }
            if (std.mem.eql(
                u8,
                &proposal.cut_digest,
                &self.baseline.cut_digest,
            )) return error.InvalidBaseline;
            if (index != 0 and !retention.digestLess(
                self.frontier[index - 1].proposal_digest,
                proposal.proposal_digest,
            )) return error.NonCanonicalFrontier;
            if (self.baseline.report.dominates(&proposal.report))
                return error.DominatedFrontier;
            for (self.frontier[0..index]) |*prior| {
                if (prior.report.dominates(&proposal.report) or
                    proposal.report.dominates(&prior.report))
                {
                    return error.DominatedFrontier;
                }
            }
        }
        const expected_result_digest = resultDigest(self);
        if (!std.mem.eql(u8, &self.result_digest, &expected_result_digest))
            return error.ResultDigestMismatch;
        var replay = try search(allocator, arena, seed_plan, config);
        defer replay.deinit();
        if (!self.eql(&replay)) return error.SearchReplayMismatch;
    }
};

pub const ValidationError = error{
    ConfigurationDigestMismatch,
    CountOverflow,
    DigestMismatch,
    DominatedFrontier,
    FixedRootCountMismatch,
    InvalidBaseline,
    InvalidBeamWidth,
    InvalidCellWidth,
    InvalidEvaluationLimit,
    InvalidFrontierLimit,
    InvalidLogSize,
    InvalidPassLimit,
    InvalidProvenance,
    InvalidScenarioOrder,
    InvalidSearchAccounting,
    NonCanonicalFrontier,
    ProposalDigestMismatch,
    ResultDigestMismatch,
    SearchReplayMismatch,
    TooManyScenarios,
};
pub const Error = std.mem.Allocator.Error ||
    cut_set.Error ||
    cost.Error ||
    materializer.Error ||
    ValidationError;

const Stored = struct {
    proposal: Proposal,
};

/// Explores a bounded deterministic edge neighbourhood from an authenticated
/// H-003 plan. Feasible proposals may seed the next pass even when dominated,
/// so a useful multi-edit route need not improve every intermediate state.
pub fn search(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    seed_plan: *const materializer.Plan,
    config: SearchConfig,
) Error!Result {
    try config.validate();
    var baseline_cut = try cut_set.fromDegree3Plan(allocator, arena, seed_plan);
    var baseline_cut_owned = true;
    errdefer if (baseline_cut_owned) baseline_cut.deinit();
    const model = try costModelIdentity(allocator, config);
    const model_digest = frontier_digest.computeCostModel(model);
    const configuration_digest = configurationDigestWithModel(
        &baseline_cut,
        config,
        model_digest,
    );
    var baseline = try makeProposal(
        allocator,
        arena,
        baseline_cut,
        config,
        model_digest,
        .{
            .kind = .seed,
            .pass = 0,
            .parent_cut_digest = .{0} ** 32,
        },
    );
    baseline_cut_owned = false;
    var baseline_owned = true;
    errdefer if (baseline_owned) baseline.deinit();

    var stored: std.ArrayList(Stored) = .empty;
    defer stored.deinit(allocator);
    errdefer for (stored.items) |*item| item.proposal.deinit();
    try stored.append(allocator, .{ .proposal = baseline });
    baseline_owned = false;

    var seen = std.AutoHashMap(digest.Digest, void).init(allocator);
    defer seen.deinit();
    try seen.put(stored.items[0].proposal.cut_digest, {});

    var pareto: std.ArrayList(usize) = .empty;
    defer pareto.deinit(allocator);
    try pareto.append(allocator, 0);
    var beam = try allocator.alloc(usize, 1);
    defer allocator.free(beam);
    beam[0] = 0;

    var attempted: u32 = 0;
    var feasible: u32 = 0;
    var duplicates: u32 = 0;
    var rejected: u32 = 0;
    var passes: u16 = 0;
    var budget_exhausted = false;

    search_passes: while (passes < config.max_passes and beam.len != 0) {
        if (attempted == config.max_candidate_evaluations) {
            budget_exhausted = true;
            break :search_passes;
        }
        passes += 1;
        var next: std.ArrayList(usize) = .empty;
        defer next.deinit(allocator);

        for (beam) |seed_index| {
            if (attempted == config.max_candidate_evaluations) {
                budget_exhausted = true;
                break :search_passes;
            }
            var candidate_edits = try neighbourhood.Neighbourhood.init(
                allocator,
                arena,
                &stored.items[seed_index].proposal.cut,
                config.max_candidate_evaluations - attempted,
            );
            defer candidate_edits.deinit();
            budget_exhausted = budget_exhausted or candidate_edits.truncated;
            for (candidate_edits.edits) |edit| {
                if (attempted == config.max_candidate_evaluations) {
                    budget_exhausted = true;
                    break :search_passes;
                }
                attempted = try increment(attempted);
                var candidate_cut = stored.items[seed_index].proposal.cut.editedTrusted(
                    allocator,
                    arena,
                    .{
                        .roots = stored.items[seed_index].proposal.cut.roots,
                        .gate = stored.items[seed_index].proposal.cut.gate,
                        .policy = stored.items[seed_index].proposal.cut.policy,
                    },
                    edit,
                ) catch |failure| switch (failure) {
                    error.InfeasibleEquality => {
                        rejected = try increment(rejected);
                        continue;
                    },
                    else => return failure,
                };
                var candidate_cut_owned = true;
                errdefer if (candidate_cut_owned) candidate_cut.deinit();
                const candidate_digest = cutDigest(&candidate_cut);
                if (seen.contains(candidate_digest)) {
                    duplicates = try increment(duplicates);
                    candidate_cut.deinit();
                    candidate_cut_owned = false;
                    continue;
                }
                try seen.put(candidate_digest, {});

                var proposal = try makeProposal(
                    allocator,
                    arena,
                    candidate_cut,
                    config,
                    model_digest,
                    provenanceFor(
                        edit,
                        passes,
                        stored.items[seed_index].proposal.cut_digest,
                    ),
                );
                candidate_cut_owned = false;
                var proposal_owned = true;
                errdefer if (proposal_owned) proposal.deinit();
                try stored.append(allocator, .{ .proposal = proposal });
                proposal_owned = false;
                const new_index = stored.items.len - 1;
                try next.append(allocator, new_index);
                feasible = try increment(feasible);
                try retention.updatePareto(allocator, stored.items, &pareto, new_index);
            }
        }

        const retained = try retention.selectRetained(
            allocator,
            stored.items,
            next.items,
            config.beam_width,
        );
        allocator.free(beam);
        beam = retained;
    }

    var non_seed: std.ArrayList(usize) = .empty;
    defer non_seed.deinit(allocator);
    for (pareto.items) |index| if (index != 0)
        try non_seed.append(allocator, index);
    const retained_frontier = try retention.selectRetained(
        allocator,
        stored.items,
        non_seed.items,
        config.frontier_limit,
    );
    defer allocator.free(retained_frontier);
    const frontier_truncated = retained_frontier.len != non_seed.items.len;

    const frontier = try allocator.alloc(Proposal, retained_frontier.len);
    errdefer allocator.free(frontier);
    const moved = try allocator.alloc(bool, stored.items.len);
    defer allocator.free(moved);
    @memset(moved, false);
    moved[0] = true;
    for (retained_frontier, frontier) |index, *proposal| {
        proposal.* = stored.items[index].proposal;
        moved[index] = true;
    }
    for (stored.items, moved) |*item, was_moved| {
        if (!was_moved) item.proposal.deinit();
    }
    const result_baseline = stored.items[0].proposal;
    stored.clearRetainingCapacity();

    var result = Result{
        .allocator = allocator,
        .configuration_digest = configuration_digest,
        .result_digest = undefined,
        .baseline = result_baseline,
        .frontier = frontier,
        .attempted_evaluations = attempted,
        .feasible_unique_proposals = feasible,
        .duplicate_proposals = duplicates,
        .rejected_infeasible = rejected,
        .passes_completed = passes,
        .budget_exhausted = budget_exhausted,
        .frontier_truncated = frontier_truncated,
    };
    result.result_digest = resultDigest(&result);
    return result;
}

pub fn costModelIdentity(
    allocator: std.mem.Allocator,
    config: SearchConfig,
) Error!frontier_digest.CostModelIdentity {
    if (config.fixed_direct_program) |program| {
        const model = try program.identity(allocator);
        return .{
            .scope_id = model.scope_id,
            .scope_version = model.scope_version,
            .fixed_program_format_version = model.format_version,
            .fixed_program_digest = model.digest,
            .fixed_column_count = model.column_count,
            .fixed_node_count = model.node_count,
            .fixed_root_count = model.fixed_root_count,
            .evaluation_schedule = .fixed_prefix_candidate_equalities_fixed_suffix,
        };
    }
    return .{
        .scope_id = semantic_equalities_cost_scope,
        .scope_version = 1,
        .fixed_program_format_version = 0,
        .fixed_program_digest = .{0} ** 32,
        .fixed_column_count = 0,
        .fixed_node_count = 0,
        .fixed_root_count = 0,
        .evaluation_schedule = .candidate_equalities_only,
    };
}

pub fn configurationDigest(
    allocator: std.mem.Allocator,
    cut: *const cut_set.CutSet,
    config: SearchConfig,
) Error!digest.Digest {
    const model = try costModelIdentity(allocator, config);
    return configurationDigestWithModel(
        cut,
        config,
        frontier_digest.computeCostModel(model),
    );
}

fn configurationDigestWithModel(
    cut: *const cut_set.CutSet,
    config: SearchConfig,
    model_digest: digest.Digest,
) digest.Digest {
    return frontier_digest.computeConfiguration(
        cut.program_digest,
        cutDigest(cut),
        policy_id,
        policy_version,
        model_digest,
        config,
        config.geometry,
        config.log_sizes,
    );
}

pub fn cutDigest(cut: *const cut_set.CutSet) digest.Digest {
    return frontier_digest.computeCut(
        cut.program_digest,
        materializer.policy_version,
        if (cut.gate) |gate| @intFromEnum(gate) else null,
        cut.policy.maximum_constraint_degree,
        cut.policy.row_mask_degree,
        cut.roots,
        cut.values,
    );
}

pub fn proposalDigest(
    cut_digest: digest.Digest,
    model_digest: digest.Digest,
    report: *const cost.Report,
) digest.Digest {
    return frontier_digest.computeProposalCombined(
        cut_digest,
        model_digest,
        report.vector,
        report.scenarios,
    );
}

fn makeProposal(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    candidate_cut: cut_set.CutSet,
    config: SearchConfig,
    model_digest: digest.Digest,
    provenance: Provenance,
) Error!Proposal {
    const candidate_digest = cutDigest(&candidate_cut);
    var report = try cost.analyze(allocator, arena, .{
        .roots = candidate_cut.roots,
        .gate = candidate_cut.gate,
        .policy = candidate_cut.policy,
        .selected = candidate_cut.values,
        .geometry = config.geometry,
        .fixed_direct_program = config.fixed_direct_program,
        .log_sizes = config.log_sizes,
    });
    errdefer report.deinit();
    return .{
        .cut = candidate_cut,
        .report = report,
        .cut_digest = candidate_digest,
        .proposal_digest = proposalDigest(candidate_digest, model_digest, &report),
        .provenance = provenance,
    };
}

fn validateProposal(
    proposal: *const Proposal,
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    config: SearchConfig,
    model_digest: digest.Digest,
) Error!void {
    try proposal.cut.validateAgainst(allocator, arena, .{
        .roots = proposal.cut.roots,
        .gate = proposal.cut.gate,
        .policy = proposal.cut.policy,
    });
    const expected_cut_digest = cutDigest(&proposal.cut);
    if (!std.mem.eql(u8, &proposal.cut_digest, &expected_cut_digest))
        return error.DigestMismatch;
    var expected_report = try cost.analyze(allocator, arena, .{
        .roots = proposal.cut.roots,
        .gate = proposal.cut.gate,
        .policy = proposal.cut.policy,
        .selected = proposal.cut.values,
        .geometry = config.geometry,
        .fixed_direct_program = config.fixed_direct_program,
        .log_sizes = config.log_sizes,
    });
    defer expected_report.deinit();
    if (!proposal.report.eql(&expected_report)) return error.DigestMismatch;
    const expected_proposal_digest = proposalDigest(
        expected_cut_digest,
        model_digest,
        &expected_report,
    );
    if (!std.mem.eql(u8, &proposal.proposal_digest, &expected_proposal_digest))
        return error.ProposalDigestMismatch;
}

fn sameAuthority(lhs: *const cut_set.CutSet, rhs: *const cut_set.CutSet) bool {
    return sameRequest(lhs, rhs) and
        std.mem.eql(types.ValueId, lhs.values, rhs.values);
}

fn sameRequest(lhs: *const cut_set.CutSet, rhs: *const cut_set.CutSet) bool {
    return std.mem.eql(u8, &lhs.program_digest, &rhs.program_digest) and
        lhs.gate == rhs.gate and
        std.meta.eql(lhs.policy, rhs.policy) and
        std.mem.eql(types.ValueId, lhs.roots, rhs.roots);
}

fn validSeedProvenance(provenance: Provenance) bool {
    return provenance.kind == .seed and
        provenance.pass == 0 and
        provenance.removed == null and
        provenance.added == null and
        std.mem.allEqual(u8, &provenance.parent_cut_digest, 0);
}

fn validEditProvenance(
    provenance: Provenance,
    passes: u16,
    selected: []const types.ValueId,
) bool {
    if (provenance.pass == 0 or provenance.pass > passes or
        std.mem.allEqual(u8, &provenance.parent_cut_digest, 0))
    {
        return false;
    }
    return switch (provenance.kind) {
        .seed => false,
        .remove => provenance.removed != null and provenance.added == null and
            !containsValue(selected, provenance.removed.?),
        .add => provenance.removed == null and provenance.added != null and
            containsValue(selected, provenance.added.?),
        .swap => provenance.removed != null and provenance.added != null and
            provenance.removed.? != provenance.added.? and
            !containsValue(selected, provenance.removed.?) and
            containsValue(selected, provenance.added.?),
    };
}

fn containsValue(values: []const types.ValueId, wanted: types.ValueId) bool {
    var low: usize = 0;
    var high = values.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (@intFromEnum(values[middle]) < @intFromEnum(wanted))
            low = middle + 1
        else
            high = middle;
    }
    return low < values.len and values[low] == wanted;
}

fn provenanceFor(
    edit: cut_set.Edit,
    pass: u16,
    parent: digest.Digest,
) Provenance {
    return switch (edit) {
        .remove => |value| .{
            .kind = .remove,
            .pass = pass,
            .parent_cut_digest = parent,
            .removed = value,
        },
        .add => |value| .{
            .kind = .add,
            .pass = pass,
            .parent_cut_digest = parent,
            .added = value,
        },
        .swap => |change| .{
            .kind = .swap,
            .pass = pass,
            .parent_cut_digest = parent,
            .removed = change.remove,
            .added = change.add,
        },
    };
}

fn resultDigest(result: *const Result) digest.Digest {
    return frontier_digest.computeResult(
        result.configuration_digest,
        result.baseline,
        result.*,
        result.frontier,
    );
}

fn increment(value: u32) ValidationError!u32 {
    return std.math.add(u32, value, 1) catch error.CountOverflow;
}
