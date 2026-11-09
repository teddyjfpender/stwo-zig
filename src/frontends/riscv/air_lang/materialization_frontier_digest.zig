//! Shared canonical identity for in-memory and `STWAIRM` proposals.
//!
//! The manifest codec and bounded search intentionally call these same
//! preimage functions. Artifact framing may add identity, configuration, and
//! accounting context, but a cut or proposal never acquires a second digest.

const std = @import("std");
const semantic = @import("digest.zig");

pub const Digest = semantic.Digest;
pub const cut_digest_version: u16 = 1;
pub const proposal_digest_version: u16 = 1;
pub const search_digest_version: u16 = 1;
pub const typed_cut_digest_version: u16 = 2;
pub const typed_search_digest_version: u16 = 2;
pub const IdentityError = error{UnsupportedSemanticDigestFormat};
pub const EditKind = enum(u8) { seed, remove, add, swap };
pub const EvaluationSchedule = enum(u8) {
    candidate_equalities_only = 0,
    fixed_prefix_candidate_equalities_fixed_suffix = 1,
};
pub const CostModelIdentity = struct {
    scope_id: []const u8,
    scope_version: u16,
    fixed_program_format_version: u16,
    fixed_program_digest: Digest,
    fixed_column_count: u32,
    fixed_node_count: u32,
    fixed_root_count: u32,
    evaluation_schedule: EvaluationSchedule,
};
pub const seed_policy_id = "stwo.typed-air.materialize.degree-bounded-v1";
pub const cut_digest_domain = "stwo-zig/typed-air/cost-frontier/cut";
pub const proposal_digest_domain = "stwo-zig/typed-air/cost-frontier/proposal";
pub const config_digest_domain = "stwo-zig/typed-air/cost-frontier/config";
pub const result_digest_domain = "stwo-zig/typed-air/cost-frontier/result";
pub const cost_model_digest_domain = "stwo-zig/typed-air/cost-model";

const geometry_fields = .{
    "preprocessed_columns",
    "base_main_columns",
    "fixed_direct_roots",
    "interaction_columns",
    "field_element_bytes",
};
const cost_vector_fields = .{
    "materialization_count",
    "base_main_columns",
    "candidate_main_columns",
    "direct_roots",
    "interaction_columns",
    "canonical_direct_nodes",
    "canonical_direct_additions",
    "canonical_direct_subtractions",
    "canonical_direct_negations",
    "canonical_direct_multiplications",
    "unique_committed_column_reads",
    "canonical_streaming_peak_live_nodes",
    "semantic_witness_nodes",
};
const scenario_cost_fields = .{
    "main_cells",
    "interaction_cells",
    "committed_cells",
    "main_bytes",
    "interaction_bytes",
    "committed_bytes",
};

pub fn computeConfiguration(
    semantic_digest: Digest,
    seed_cut_digest: Digest,
    policy_id: []const u8,
    policy_version: u16,
    cost_model_digest: Digest,
    config: anytype,
    geometry: anytype,
    scenarios: anytype,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(config_digest_domain);
    hashInt(&hash, u16, search_digest_version);
    hashString(&hash, policy_id);
    hashInt(&hash, u16, policy_version);
    hash.update(&semantic_digest);
    hash.update(&seed_cut_digest);
    hash.update(&cost_model_digest);
    hashInt(&hash, u16, config.max_passes);
    hashInt(&hash, u32, config.max_candidate_evaluations);
    hashInt(&hash, u16, config.beam_width);
    hashInt(&hash, u16, config.frontier_limit);
    inline for (geometry_fields) |field|
        hashInt(&hash, u64, @field(geometry, field));
    hashInt(&hash, u16, @intCast(scenarios.len));
    for (scenarios) |scenario| hashInt(&hash, u8, scenarioLogSize(scenario));
    return hash.finalResult();
}

/// Version-aware configuration identity. The format-1 branch deliberately
/// delegates to the historical preimage; typed formats use a new preimage and
/// bind the semantic format immediately before the semantic digest bytes.
pub fn computeConfigurationForIdentity(
    semantic_digest_format: u16,
    semantic_digest: Digest,
    seed_cut_digest: Digest,
    policy_id: []const u8,
    policy_version: u16,
    cost_model_digest: Digest,
    config: anytype,
    geometry: anytype,
    scenarios: anytype,
) IdentityError!Digest {
    if (semantic_digest_format == semantic.format_version) {
        return computeConfiguration(
            semantic_digest,
            seed_cut_digest,
            policy_id,
            policy_version,
            cost_model_digest,
            config,
            geometry,
            scenarios,
        );
    }
    try validateTypedSemanticFormat(semantic_digest_format);

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(config_digest_domain);
    hashInt(&hash, u16, typed_search_digest_version);
    hashString(&hash, policy_id);
    hashInt(&hash, u16, policy_version);
    hashInt(&hash, u16, semantic_digest_format);
    hash.update(&semantic_digest);
    hash.update(&seed_cut_digest);
    hash.update(&cost_model_digest);
    hashInt(&hash, u16, config.max_passes);
    hashInt(&hash, u32, config.max_candidate_evaluations);
    hashInt(&hash, u16, config.beam_width);
    hashInt(&hash, u16, config.frontier_limit);
    inline for (geometry_fields) |field|
        hashInt(&hash, u64, @field(geometry, field));
    hashInt(&hash, u16, @intCast(scenarios.len));
    for (scenarios) |scenario| hashInt(&hash, u8, scenarioLogSize(scenario));
    return hash.finalResult();
}

pub fn computeCostModel(identity: CostModelIdentity) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(cost_model_digest_domain);
    hashInt(&hash, u16, search_digest_version);
    hashString(&hash, identity.scope_id);
    hashInt(&hash, u16, identity.scope_version);
    hashInt(&hash, u16, identity.fixed_program_format_version);
    hash.update(&identity.fixed_program_digest);
    hashInt(&hash, u32, identity.fixed_column_count);
    hashInt(&hash, u32, identity.fixed_node_count);
    hashInt(&hash, u32, identity.fixed_root_count);
    hashInt(&hash, u8, @intFromEnum(identity.evaluation_schedule));
    return hash.finalResult();
}

/// Exact bounded-search result identity, including edit provenance. Both the
/// in-memory result and `STWAIRM` projection use this preimage.
pub fn computeResult(
    configuration_digest: Digest,
    baseline_proposal: anytype,
    run: anytype,
    frontier: anytype,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(result_digest_domain);
    hashInt(&hash, u16, search_digest_version);
    hash.update(&configuration_digest);
    hash.update(&baseline_proposal.proposal_digest);
    hashInt(&hash, u32, run.attempted_evaluations);
    hashInt(&hash, u32, run.feasible_unique_proposals);
    hashInt(&hash, u32, run.duplicate_proposals);
    hashInt(&hash, u32, run.rejected_infeasible);
    hashInt(&hash, u16, run.passes_completed);
    hashInt(&hash, u8, @intFromBool(run.budget_exhausted));
    hashInt(&hash, u8, @intFromBool(run.frontier_truncated));
    hashInt(&hash, u16, @intCast(frontier.len));
    hashProvenance(&hash, baseline_proposal.provenance);
    for (frontier) |proposal| {
        hash.update(&proposal.proposal_digest);
        hashProvenance(&hash, proposal.provenance);
    }
    return hash.finalResult();
}

pub fn computeCut(
    semantic_digest: Digest,
    seed_policy_version: u16,
    gate: ?u32,
    maximum_constraint_degree: u64,
    row_mask_degree: u64,
    roots: anytype,
    selected: anytype,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(cut_digest_domain);
    hashInt(&hash, u16, cut_digest_version);
    hashString(&hash, seed_policy_id);
    hashInt(&hash, u16, seed_policy_version);
    hash.update(&semantic_digest);
    hashOptionalId(&hash, gate);
    hashInt(&hash, u64, maximum_constraint_degree);
    hashInt(&hash, u64, row_mask_degree);
    hashIds(&hash, roots);
    hashIds(&hash, selected);
    return hash.finalResult();
}

/// Version-aware cut identity with an exact format-1 compatibility branch.
pub fn computeCutForIdentity(
    semantic_digest_format: u16,
    semantic_digest: Digest,
    seed_policy_version: u16,
    gate: ?u32,
    maximum_constraint_degree: u64,
    row_mask_degree: u64,
    roots: anytype,
    selected: anytype,
) IdentityError!Digest {
    if (semantic_digest_format == semantic.format_version) {
        return computeCut(
            semantic_digest,
            seed_policy_version,
            gate,
            maximum_constraint_degree,
            row_mask_degree,
            roots,
            selected,
        );
    }
    try validateTypedSemanticFormat(semantic_digest_format);

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(cut_digest_domain);
    hashInt(&hash, u16, typed_cut_digest_version);
    hashString(&hash, seed_policy_id);
    hashInt(&hash, u16, seed_policy_version);
    hashInt(&hash, u16, semantic_digest_format);
    hash.update(&semantic_digest);
    hashOptionalId(&hash, gate);
    hashInt(&hash, u64, maximum_constraint_degree);
    hashInt(&hash, u64, row_mask_degree);
    hashIds(&hash, roots);
    hashIds(&hash, selected);
    return hash.finalResult();
}

fn validateTypedSemanticFormat(format: u16) IdentityError!void {
    if (format != semantic.typed_effect_format_version and
        format != semantic.register_group_format_version and
        format != semantic.memory_access_format_version)
    {
        return error.UnsupportedSemanticDigestFormat;
    }
}

pub fn computeProposalCombined(
    cut_digest: Digest,
    cost_model_digest: Digest,
    vector: anytype,
    scenarios: anytype,
) Digest {
    var hash = beginProposal(cut_digest, cost_model_digest, vector, scenarios.len);
    for (scenarios) |scenario| {
        hashInt(&hash, u8, scenario.log_size);
        hashInt(&hash, u64, scenario.rows);
        hashScenarioCost(&hash, scenario);
    }
    return hash.finalResult();
}

pub fn computeProposalSplit(
    cut_digest: Digest,
    cost_model_digest: Digest,
    vector: anytype,
    scenarios: anytype,
    scenario_costs: anytype,
) Digest {
    std.debug.assert(scenarios.len == scenario_costs.len);
    var hash = beginProposal(cut_digest, cost_model_digest, vector, scenarios.len);
    for (scenarios, scenario_costs) |scenario, scenario_cost| {
        hashInt(&hash, u8, scenario.log_size);
        hashInt(&hash, u64, scenario.rows);
        hashScenarioCost(&hash, scenario_cost);
    }
    return hash.finalResult();
}

fn beginProposal(
    cut_digest: Digest,
    cost_model_digest: Digest,
    vector: anytype,
    scenario_count: usize,
) std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(proposal_digest_domain);
    hashInt(&hash, u16, proposal_digest_version);
    hash.update(&cut_digest);
    hash.update(&cost_model_digest);
    inline for (cost_vector_fields) |field|
        hashInt(&hash, u64, @field(vector, field));
    hashInt(&hash, u16, @intCast(scenario_count));
    return hash;
}

fn hashScenarioCost(hash: anytype, scenario: anytype) void {
    inline for (scenario_cost_fields) |field|
        hashInt(hash, u64, @field(scenario, field));
}

fn hashProvenance(hash: anytype, provenance: anytype) void {
    hashInt(hash, u8, @intFromEnum(provenance.kind));
    hashInt(hash, u16, provenance.pass);
    hash.update(&provenance.parent_cut_digest);
    hashOptionalRawId(hash, provenance.removed);
    hashOptionalRawId(hash, provenance.added);
}

fn hashIds(hash: anytype, values: anytype) void {
    hashInt(hash, u32, @intCast(values.len));
    for (values) |value| hashInt(hash, u32, rawId(value));
}

fn rawId(value: anytype) u32 {
    return switch (@typeInfo(@TypeOf(value))) {
        .@"enum" => @intFromEnum(value),
        .int, .comptime_int => @intCast(value),
        else => @compileError("materialization identity requires u32-like IDs"),
    };
}

fn scenarioLogSize(scenario: anytype) u8 {
    return switch (@typeInfo(@TypeOf(scenario))) {
        .int, .comptime_int => @intCast(scenario),
        else => @intCast(scenario.log_size),
    };
}

fn hashOptionalRawId(hash: anytype, value: anytype) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u32, rawId(present));
    } else hashInt(hash, u8, 0);
}

fn hashOptionalId(hash: anytype, value: ?u32) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u32, present);
    } else hashInt(hash, u8, 0);
}

fn hashString(hash: anytype, value: []const u8) void {
    hashInt(hash, u16, @intCast(value.len));
    hash.update(value);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
