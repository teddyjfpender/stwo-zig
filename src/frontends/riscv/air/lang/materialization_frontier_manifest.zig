//! Canonical receipt for bounded materialization cost-frontier experiments.
//!
//! This module owns no AIR or search types. Callers project validated search
//! results into the plain views below. The `STWAIRM\0` encoding is a proposal
//! artifact only: it is not imported by production proving or verification.

const std = @import("std");
const frontier_digest = @import("materialization_frontier_digest.zig");
const cost_model_schema = @import("materialization_frontier_cost_model.zig");
const checks = @import("materialization_frontier_manifest_validate.zig");
const lengths = @import("materialization_frontier_manifest_lengths.zig");
const wire = @import("materialization_frontier_manifest_wire.zig");

const Cursor = wire.Cursor;
const addLength = wire.addLength;
const beginHash = wire.beginHash;
const hashInt = wire.hashInt;
const writeInt = wire.writeInt;

pub const magic = "STWAIRM\x00";
pub const format_version: u16 = 1;
pub const policy_id = "stwo.typed-air.materialize.cost-frontier-v1";
pub const policy_version: u16 = 1;
pub const seed_policy_id = frontier_digest.seed_policy_id;
pub const cut_digest_version = frontier_digest.cut_digest_version;
pub const proposal_digest_version = frontier_digest.proposal_digest_version;
pub const search_digest_version = frontier_digest.search_digest_version;
pub const identity_digest_domain = "stwo-zig/typed-air/materialization-frontier-identity-v1";
pub const cut_digest_domain = frontier_digest.cut_digest_domain;
pub const proposal_digest_domain = frontier_digest.proposal_digest_domain;
pub const configuration_digest_domain = frontier_digest.config_digest_domain;
pub const result_digest_domain = frontier_digest.result_digest_domain;
pub const artifact_digest_domain = "stwo-zig/typed-air/materialization-frontier-artifact-v1";

pub const Digest = [32]u8;
pub const max_artifact_bytes: usize = 16 * 1024 * 1024;
pub const max_roots: usize = 4_096;
pub const max_scenarios: usize = 16;
pub const max_frontier_proposals: usize = 4_096;
pub const max_selected_per_proposal: usize = 16_384;
pub const max_total_selected_values: usize = 1_048_576;

const section_count: u8 = 4;
const section_header_bytes: usize = 6;

const Section = enum(u8) {
    identity = 1,
    search = 2,
    scenarios = 3,
    candidates = 4,
};

pub const SeedPolicy = enum(u8) { degree_bounded_v1 = 1 };
pub const Neighborhood = enum(u8) { semantic_dag_edge_v1 = 1 };
pub const EditKind = frontier_digest.EditKind;
pub const EvaluationSchedule = cost_model_schema.EvaluationSchedule;
pub const CostScope = cost_model_schema.Scope;
pub const CostModelIdentity = cost_model_schema.Identity;
pub const semanticOnlyCostModel = cost_model_schema.semanticOnly;
pub const poseidon2PermutationDirectCostModel =
    cost_model_schema.poseidon2PermutationDirect;

pub const Identity = struct {
    semantic_digest: Digest,
    roots: []const u32,
    gate: ?u32,
    seed_policy: SeedPolicy = .degree_bounded_v1,
    seed_policy_version: u16 = 1,
    maximum_constraint_degree: u64,
    row_mask_degree: u64,
    identity_digest: Digest,
};

pub const SearchConfig = struct {
    version: u16 = 1,
    neighborhood: Neighborhood = .semantic_dag_edge_v1,
    max_passes: u16,
    beam_width: u16,
    max_candidate_evaluations: u32,
    frontier_limit: u16,
    configuration_digest: Digest,
};

pub const Geometry = struct {
    preprocessed_columns: u64 = 0,
    base_main_columns: u64,
    fixed_direct_roots: u64,
    interaction_columns: u64,
    field_element_bytes: u64,
};

pub const Scenario = struct { log_size: u8, rows: u64 };

pub const CostVector = struct {
    materialization_count: u64,
    base_main_columns: u64,
    candidate_main_columns: u64,
    direct_roots: u64,
    interaction_columns: u64,
    canonical_direct_nodes: u64,
    canonical_direct_additions: u64,
    canonical_direct_subtractions: u64,
    canonical_direct_negations: u64,
    canonical_direct_multiplications: u64,
    unique_committed_column_reads: u64,
    canonical_streaming_peak_live_nodes: u64,
    semantic_witness_nodes: u64,
};

pub const ScenarioCost = struct {
    main_cells: u64,
    interaction_cells: u64,
    committed_cells: u64,
    main_bytes: u64,
    interaction_bytes: u64,
    committed_bytes: u64,
};

pub const Provenance = struct {
    kind: EditKind,
    pass: u16,
    parent_cut_digest: Digest,
    removed: ?u32 = null,
    added: ?u32 = null,
};

pub const Proposal = struct {
    proposal_digest: Digest,
    cut_digest: Digest,
    provenance: Provenance,
    selected_values: []const u32,
    cost: CostVector,
    scenario_costs: []const ScenarioCost,
};

pub const RunAccounting = struct {
    attempted_evaluations: u32,
    feasible_unique_proposals: u32,
    duplicate_proposals: u32,
    rejected_infeasible: u32,
    passes_completed: u16,
    budget_exhausted: bool,
    frontier_truncated: bool,
    result_digest: Digest,
};

pub const Manifest = struct {
    identity: Identity,
    search: SearchConfig,
    cost_model: CostModelIdentity,
    geometry: Geometry,
    scenarios: []const Scenario,
    run: RunAccounting,
    baseline: Proposal,
    frontier: []const Proposal,
};

pub const ManifestError = error{
    ArtifactTooLarge,
    BadMagic,
    UnsupportedVersion,
    UnsupportedSearchVersion,
    InvalidSectionCount,
    InvalidSectionOrder,
    InvalidEnum,
    NonCanonicalEncoding,
    Truncated,
    TrailingBytes,
    TrailingSectionBytes,
    LengthLimitExceeded,
    CountLimitExceeded,
    InvalidIdentity,
    InvalidCostModel,
    InvalidSearchConfig,
    InvalidScenario,
    InvalidScenarioOrder,
    InvalidProposal,
    NonCanonicalSelection,
    NonCanonicalFrontier,
    DuplicateCut,
    DominatedFrontier,
    DigestMismatch,
    ConfigurationDigestMismatch,
    ResultDigestMismatch,
    InconsistentCount,
    InvalidRunAccounting,
    InconsistentCost,
    CostOverflow,
};

pub const Decoded = struct {
    allocator: std.mem.Allocator,
    identity: Identity,
    search: SearchConfig,
    cost_model: CostModelIdentity,
    geometry: Geometry,
    scenarios: []Scenario,
    run: RunAccounting,
    baseline: Proposal,
    frontier: []Proposal,

    pub fn view(self: *const Decoded) Manifest {
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

    pub fn deinit(self: *Decoded) void {
        self.allocator.free(self.identity.roots);
        self.allocator.free(self.scenarios);
        deinitProposal(self.allocator, self.baseline);
        for (self.frontier) |proposal| deinitProposal(self.allocator, proposal);
        self.allocator.free(self.frontier);
        self.* = undefined;
    }
};

/// Encodes only a fully self-consistent, canonical frontier.
pub fn encodeAlloc(allocator: std.mem.Allocator, manifest: Manifest) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try writeCanonical(bytes.writer(allocator), manifest);
    return bytes.toOwnedSlice(allocator);
}

pub fn validateCanonical(manifest: Manifest) ManifestError!void {
    return validate(manifest);
}

/// Validates the complete input before emitting its first byte.
pub fn writeCanonical(writer: anytype, manifest: Manifest) !void {
    try validate(manifest);
    const section_lengths = try lengths.payloads(manifest, max_artifact_bytes);
    var total: usize = 12;
    for (section_lengths) |length|
        total = try addLength(total, section_header_bytes + @as(usize, length));
    if (total > max_artifact_bytes) return error.ArtifactTooLarge;

    try writer.writeAll(magic);
    try writeInt(writer, u16, format_version);
    try writeInt(writer, u8, section_count);
    try writeInt(writer, u8, 0);
    try writeSectionHeader(writer, .identity, section_lengths[0]);
    try writeIdentity(writer, manifest.identity);
    try writeSectionHeader(writer, .search, section_lengths[1]);
    try writeSearch(writer, manifest.search, manifest.cost_model);
    try writeSectionHeader(writer, .scenarios, section_lengths[2]);
    try writeScenarios(writer, manifest.geometry, manifest.scenarios);
    try writeSectionHeader(writer, .candidates, section_lengths[3]);
    try writeRun(writer, manifest.run, manifest.frontier.len);
    try writeProposal(writer, manifest.baseline);
    for (manifest.frontier) |proposal| try writeProposal(writer, proposal);
}

pub fn decodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) !Decoded {
    if (bytes.len > max_artifact_bytes) return error.ArtifactTooLarge;
    var cursor = Cursor{ .bytes = bytes };
    if (!std.mem.eql(u8, try cursor.take(magic.len), magic)) return error.BadMagic;
    if (try cursor.int(u16) != format_version) return error.UnsupportedVersion;
    if (try cursor.int(u8) != section_count) return error.InvalidSectionCount;
    if (try cursor.int(u8) != 0) return error.NonCanonicalEncoding;

    var sections: [section_count][]const u8 = undefined;
    for (&sections, 0..) |*section, index| {
        const raw_tag = try cursor.int(u8);
        const tag = wire.enumFromInt(Section, raw_tag) orelse return error.InvalidEnum;
        if (@intFromEnum(tag) != index + 1) return error.InvalidSectionOrder;
        if (try cursor.int(u8) != 0) return error.NonCanonicalEncoding;
        const length = try cursor.int(u32);
        if (length > max_artifact_bytes) return error.LengthLimitExceeded;
        section.* = try cursor.take(length);
    }
    if (cursor.position != bytes.len) return error.TrailingBytes;

    const identity = try readIdentity(allocator, sections[0]);
    var identity_owned = true;
    errdefer if (identity_owned) allocator.free(identity.roots);
    const search_data = try readSearch(sections[1]);
    const scenario_data = try readScenarios(allocator, sections[2]);
    var scenarios_owned = true;
    errdefer if (scenarios_owned) allocator.free(scenario_data.scenarios);
    var candidate_data = try readCandidates(
        allocator,
        sections[3],
        scenario_data.scenarios.len,
    );
    var candidates_owned = true;
    errdefer if (candidates_owned) candidate_data.deinit(allocator);

    var result = Decoded{
        .allocator = allocator,
        .identity = identity,
        .search = search_data.search,
        .cost_model = search_data.cost_model,
        .geometry = scenario_data.geometry,
        .scenarios = scenario_data.scenarios,
        .run = candidate_data.run,
        .baseline = candidate_data.baseline,
        .frontier = candidate_data.frontier,
    };
    identity_owned = false;
    scenarios_owned = false;
    candidates_owned = false;
    errdefer result.deinit();
    try validate(result.view());
    return result;
}

pub fn computeIdentityDigest(identity: Identity) Digest {
    var hash = beginHash(identity_digest_domain);
    hash.update(&identity.semantic_digest);
    hashInt(&hash, u8, @intFromEnum(identity.seed_policy));
    hashInt(&hash, u16, identity.seed_policy_version);
    hashInt(&hash, u64, identity.maximum_constraint_degree);
    hashInt(&hash, u64, identity.row_mask_degree);
    hashInt(&hash, u32, @intCast(identity.roots.len));
    for (identity.roots) |root| hashInt(&hash, u32, root);
    hashInt(&hash, u8, @intFromBool(identity.gate != null));
    if (identity.gate) |gate| hashInt(&hash, u32, gate);
    return hash.finalResult();
}

/// Byte-exact projection of `cost_aware_materializer.cutDigest`. Unlike the
/// separate receipt identity and artifact digest, this uses the search
/// authority's existing domain and preimage without manifest-only context.
pub fn computeCutDigest(identity: Identity, selected_values: []const u32) Digest {
    return frontier_digest.computeCut(
        identity.semantic_digest,
        identity.seed_policy_version,
        identity.gate,
        identity.maximum_constraint_degree,
        identity.row_mask_degree,
        identity.roots,
        selected_values,
    );
}

/// Byte-exact projection of `cost_aware_materializer.proposalDigest`.
pub fn computeProposalDigest(
    cut_digest: Digest,
    cost_model_digest: Digest,
    cost: CostVector,
    scenarios: []const Scenario,
    scenario_costs: []const ScenarioCost,
) Digest {
    return frontier_digest.computeProposalSplit(
        cut_digest,
        cost_model_digest,
        cost,
        scenarios,
        scenario_costs,
    );
}

pub fn computeConfigurationDigest(manifest: Manifest) Digest {
    return frontier_digest.computeConfiguration(
        manifest.identity.semantic_digest,
        manifest.baseline.cut_digest,
        policy_id,
        policy_version,
        manifest.cost_model.cost_model_digest,
        manifest.search,
        manifest.geometry,
        manifest.scenarios,
    );
}

/// Byte-exact projection of the search result digest over canonical order.
pub fn computeResultDigest(manifest: Manifest) Digest {
    return frontier_digest.computeResult(
        manifest.search.configuration_digest,
        manifest.baseline,
        manifest.run,
        manifest.frontier,
    );
}

/// Authenticates the complete framing, including provenance and receipt-only
/// metadata deliberately absent from search cut and proposal identities.
pub fn computeArtifactDigest(bytes: []const u8) Digest {
    var hash = beginHash(artifact_digest_domain);
    hashInt(&hash, u64, bytes.len);
    hash.update(bytes);
    return hash.finalResult();
}

fn validate(manifest: Manifest) ManifestError!void {
    try validateIdentity(manifest.identity);
    try cost_model_schema.validate(
        manifest.cost_model,
        manifest.geometry.fixed_direct_roots,
    );
    try validateScenarios(manifest.geometry, manifest.scenarios);
    try validateSearch(manifest.search, manifest.scenarios.len);
    if (manifest.frontier.len > max_frontier_proposals or
        manifest.frontier.len > manifest.search.frontier_limit)
        return error.CountLimitExceeded;
    try checks.validateRun(manifest.search, manifest.run, manifest.frontier.len);

    try validateProposal(manifest, manifest.baseline, true);
    if (!std.mem.eql(
        u8,
        &manifest.search.configuration_digest,
        &computeConfigurationDigest(manifest),
    )) return error.ConfigurationDigestMismatch;
    var previous: ?Digest = null;
    for (manifest.frontier, 0..) |proposal, index| {
        try validateProposal(manifest, proposal, false);
        if (previous) |prior| if (std.mem.order(u8, &prior, &proposal.proposal_digest) != .lt)
            return error.NonCanonicalFrontier;
        previous = proposal.proposal_digest;
        if (std.mem.eql(u8, &manifest.baseline.cut_digest, &proposal.cut_digest))
            return error.DuplicateCut;
        if (checks.dominates(manifest.baseline, proposal)) return error.DominatedFrontier;
        for (manifest.frontier[0..index]) |prior| {
            if (std.mem.eql(u8, &prior.cut_digest, &proposal.cut_digest))
                return error.DuplicateCut;
            if (checks.dominates(prior, proposal) or checks.dominates(proposal, prior))
                return error.DominatedFrontier;
        }
    }
    if (!std.mem.eql(u8, &manifest.run.result_digest, &computeResultDigest(manifest)))
        return error.ResultDigestMismatch;
}

fn validateIdentity(identity: Identity) ManifestError!void {
    if (identity.seed_policy != .degree_bounded_v1 or identity.seed_policy_version != 1 or
        identity.roots.len == 0 or identity.roots.len > max_roots or
        identity.maximum_constraint_degree == 0 or
        identity.row_mask_degree >= identity.maximum_constraint_degree)
        return error.InvalidIdentity;
    if (!std.mem.eql(u8, &identity.identity_digest, &computeIdentityDigest(identity)))
        return error.DigestMismatch;
}

fn validateSearch(search: SearchConfig, scenario_count: usize) ManifestError!void {
    if (search.version != 1) return error.UnsupportedSearchVersion;
    const ranked_coordinates = std.meta.fields(CostVector).len +
        scenario_count * std.meta.fields(ScenarioCost).len;
    if (search.neighborhood != .semantic_dag_edge_v1 or search.max_passes == 0 or
        search.max_passes > 32 or search.max_candidate_evaluations == 0 or
        search.max_candidate_evaluations > 1_000_000 or search.beam_width < ranked_coordinates or
        search.beam_width > 4_096 or search.frontier_limit < ranked_coordinates or
        search.frontier_limit > 4_096)
        return error.InvalidSearchConfig;
}

fn validateScenarios(geometry: Geometry, scenarios: []const Scenario) ManifestError!void {
    if (geometry.field_element_bytes == 0 or scenarios.len > max_scenarios)
        return error.InvalidScenario;
    for (scenarios, 0..) |scenario, index| {
        if (scenario.log_size >= 64 or scenario.rows != (@as(u64, 1) << @intCast(scenario.log_size)))
            return error.InvalidScenario;
        if (index != 0 and scenarios[index - 1].log_size >= scenario.log_size)
            return error.InvalidScenarioOrder;
    }
}

fn validateProposal(manifest: Manifest, proposal: Proposal, baseline: bool) ManifestError!void {
    if (proposal.selected_values.len == 0 or proposal.selected_values.len > max_selected_per_proposal)
        return error.CountLimitExceeded;
    if (!wire.strictlyIncreasing(proposal.selected_values)) return error.NonCanonicalSelection;
    for (manifest.identity.roots) |root| if (!wire.contains(proposal.selected_values, root))
        return error.InvalidProposal;
    try checks.validateProvenance(proposal, baseline, manifest.run.passes_completed);
    if (proposal.scenario_costs.len != manifest.scenarios.len) return error.InconsistentCount;
    if (!std.mem.eql(u8, &proposal.cut_digest, &computeCutDigest(manifest.identity, proposal.selected_values)))
        return error.DigestMismatch;
    const expected = computeProposalDigest(
        proposal.cut_digest,
        manifest.cost_model.cost_model_digest,
        proposal.cost,
        manifest.scenarios,
        proposal.scenario_costs,
    );
    if (!std.mem.eql(u8, &proposal.proposal_digest, &expected)) return error.DigestMismatch;
    try checks.validateCost(manifest.geometry, manifest.scenarios, proposal);
}

fn writeIdentity(writer: anytype, identity: Identity) !void {
    try writer.writeAll(&identity.semantic_digest);
    try writeInt(writer, u8, @intFromEnum(identity.seed_policy));
    try writeInt(writer, u16, identity.seed_policy_version);
    try writeInt(writer, u64, identity.maximum_constraint_degree);
    try writeInt(writer, u64, identity.row_mask_degree);
    try writeInt(writer, u32, @intCast(identity.roots.len));
    for (identity.roots) |root| try writeInt(writer, u32, root);
    try writeInt(writer, u8, @intFromBool(identity.gate != null));
    if (identity.gate) |gate| try writeInt(writer, u32, gate);
    try writer.writeAll(&identity.identity_digest);
}

fn writeSearch(
    writer: anytype,
    search: SearchConfig,
    cost_model: CostModelIdentity,
) !void {
    try writeInt(writer, u16, search.version);
    try writeInt(writer, u8, @intFromEnum(search.neighborhood));
    try writeInt(writer, u16, search.max_passes);
    try writeInt(writer, u16, search.beam_width);
    try writeInt(writer, u32, search.max_candidate_evaluations);
    try writeInt(writer, u16, search.frontier_limit);
    try writeInt(writer, u8, @intFromEnum(cost_model.scope));
    try writeInt(writer, u16, cost_model.scope_version);
    try writeInt(writer, u16, cost_model.fixed_program_format_version);
    try writer.writeAll(&cost_model.fixed_program_digest);
    try writeInt(writer, u32, cost_model.fixed_column_count);
    try writeInt(writer, u32, cost_model.fixed_node_count);
    try writeInt(writer, u32, cost_model.fixed_root_count);
    try writeInt(writer, u8, @intFromEnum(cost_model.evaluation_schedule));
    try writer.writeAll(&cost_model.cost_model_digest);
    try writer.writeAll(&search.configuration_digest);
}

fn writeRun(writer: anytype, run: RunAccounting, frontier_count: usize) !void {
    try writer.writeAll(&run.result_digest);
    try writeInt(writer, u32, run.attempted_evaluations);
    try writeInt(writer, u32, run.feasible_unique_proposals);
    try writeInt(writer, u32, run.duplicate_proposals);
    try writeInt(writer, u32, run.rejected_infeasible);
    try writeInt(writer, u16, run.passes_completed);
    try writeInt(writer, u8, @intFromBool(run.budget_exhausted));
    try writeInt(writer, u8, @intFromBool(run.frontier_truncated));
    try writeInt(writer, u16, @intCast(frontier_count));
}

fn writeScenarios(writer: anytype, geometry: Geometry, scenarios: []const Scenario) !void {
    inline for (std.meta.fields(Geometry)) |field| try writeInt(writer, u64, @field(geometry, field.name));
    try writeInt(writer, u16, @intCast(scenarios.len));
    for (scenarios) |scenario| {
        try writeInt(writer, u8, scenario.log_size);
        try writeInt(writer, u64, scenario.rows);
    }
}

fn writeProposal(writer: anytype, proposal: Proposal) !void {
    try writer.writeAll(&proposal.proposal_digest);
    try writer.writeAll(&proposal.cut_digest);
    try writeInt(writer, u8, @intFromEnum(proposal.provenance.kind));
    try writeInt(writer, u16, proposal.provenance.pass);
    try writer.writeAll(&proposal.provenance.parent_cut_digest);
    try wire.writeOptionalU32(writer, proposal.provenance.removed);
    try wire.writeOptionalU32(writer, proposal.provenance.added);
    try writeInt(writer, u32, @intCast(proposal.selected_values.len));
    for (proposal.selected_values) |value| try writeInt(writer, u32, value);
    inline for (std.meta.fields(CostVector)) |field| try writeInt(writer, u64, @field(proposal.cost, field.name));
    try writeInt(writer, u16, @intCast(proposal.scenario_costs.len));
    for (proposal.scenario_costs) |cost| inline for (std.meta.fields(ScenarioCost)) |field|
        try writeInt(writer, u64, @field(cost, field.name));
}

fn readIdentity(allocator: std.mem.Allocator, bytes: []const u8) !Identity {
    var cursor = Cursor{ .bytes = bytes };
    const semantic_digest = try cursor.digest();
    const seed_policy = wire.enumFromInt(SeedPolicy, try cursor.int(u8)) orelse return error.InvalidEnum;
    const seed_policy_version = try cursor.int(u16);
    const maximum_constraint_degree = try cursor.int(u64);
    const row_mask_degree = try cursor.int(u64);
    const root_count = try cursor.int(u32);
    if (root_count > max_roots) return error.CountLimitExceeded;
    const roots = try allocator.alloc(u32, root_count);
    errdefer allocator.free(roots);
    for (roots) |*root| root.* = try cursor.int(u32);
    const gate = switch (try cursor.int(u8)) {
        0 => null,
        1 => try cursor.int(u32),
        else => return error.InvalidEnum,
    };
    const identity_digest = try cursor.digest();
    try cursor.finishSection();
    return .{
        .semantic_digest = semantic_digest,
        .roots = roots,
        .gate = gate,
        .seed_policy = seed_policy,
        .seed_policy_version = seed_policy_version,
        .maximum_constraint_degree = maximum_constraint_degree,
        .row_mask_degree = row_mask_degree,
        .identity_digest = identity_digest,
    };
}

const SearchData = struct {
    search: SearchConfig,
    cost_model: CostModelIdentity,
};

fn readSearch(bytes: []const u8) !SearchData {
    var cursor = Cursor{ .bytes = bytes };
    const version = try cursor.int(u16);
    const neighborhood = wire.enumFromInt(Neighborhood, try cursor.int(u8)) orelse
        return error.InvalidEnum;
    const max_passes = try cursor.int(u16);
    const beam_width = try cursor.int(u16);
    const max_candidate_evaluations = try cursor.int(u32);
    const frontier_limit = try cursor.int(u16);
    const cost_model = CostModelIdentity{
        .scope = wire.enumFromInt(CostScope, try cursor.int(u8)) orelse
            return error.InvalidEnum,
        .scope_version = try cursor.int(u16),
        .fixed_program_format_version = try cursor.int(u16),
        .fixed_program_digest = try cursor.digest(),
        .fixed_column_count = try cursor.int(u32),
        .fixed_node_count = try cursor.int(u32),
        .fixed_root_count = try cursor.int(u32),
        .evaluation_schedule = wire.enumFromInt(
            EvaluationSchedule,
            try cursor.int(u8),
        ) orelse return error.InvalidEnum,
        .cost_model_digest = try cursor.digest(),
    };
    const search = SearchConfig{
        .version = version,
        .neighborhood = neighborhood,
        .max_passes = max_passes,
        .beam_width = beam_width,
        .max_candidate_evaluations = max_candidate_evaluations,
        .frontier_limit = frontier_limit,
        .configuration_digest = try cursor.digest(),
    };
    try cursor.finishSection();
    return .{ .search = search, .cost_model = cost_model };
}

const ScenarioData = struct { geometry: Geometry, scenarios: []Scenario };
fn readScenarios(allocator: std.mem.Allocator, bytes: []const u8) !ScenarioData {
    var cursor = Cursor{ .bytes = bytes };
    const geometry = Geometry{
        .preprocessed_columns = try cursor.int(u64),
        .base_main_columns = try cursor.int(u64),
        .fixed_direct_roots = try cursor.int(u64),
        .interaction_columns = try cursor.int(u64),
        .field_element_bytes = try cursor.int(u64),
    };
    const count = try cursor.int(u16);
    if (count > max_scenarios) return error.CountLimitExceeded;
    const scenarios = try allocator.alloc(Scenario, count);
    errdefer allocator.free(scenarios);
    for (scenarios) |*scenario| scenario.* = .{
        .log_size = try cursor.int(u8),
        .rows = try cursor.int(u64),
    };
    try cursor.finishSection();
    return .{ .geometry = geometry, .scenarios = scenarios };
}

const CandidateData = struct {
    run: RunAccounting,
    baseline: Proposal,
    frontier: []Proposal,
    fn deinit(self: *CandidateData, allocator: std.mem.Allocator) void {
        deinitProposal(allocator, self.baseline);
        for (self.frontier) |proposal| deinitProposal(allocator, proposal);
        allocator.free(self.frontier);
    }
};

fn readCandidates(allocator: std.mem.Allocator, bytes: []const u8, scenario_count: usize) !CandidateData {
    var cursor = Cursor{ .bytes = bytes };
    const result_digest = try cursor.digest();
    const run = RunAccounting{
        .attempted_evaluations = try cursor.int(u32),
        .feasible_unique_proposals = try cursor.int(u32),
        .duplicate_proposals = try cursor.int(u32),
        .rejected_infeasible = try cursor.int(u32),
        .passes_completed = try cursor.int(u16),
        .budget_exhausted = try wire.readBool(&cursor),
        .frontier_truncated = try wire.readBool(&cursor),
        .result_digest = result_digest,
    };
    const frontier_count = try cursor.int(u16);
    if (frontier_count > max_frontier_proposals) return error.CountLimitExceeded;
    var total_selected: usize = 0;
    const baseline = try readProposal(allocator, &cursor, scenario_count, &total_selected);
    errdefer deinitProposal(allocator, baseline);
    const frontier = try allocator.alloc(Proposal, frontier_count);
    errdefer allocator.free(frontier);
    var initialized: usize = 0;
    errdefer for (frontier[0..initialized]) |proposal| deinitProposal(allocator, proposal);
    while (initialized < frontier.len) : (initialized += 1)
        frontier[initialized] = try readProposal(allocator, &cursor, scenario_count, &total_selected);
    try cursor.finishSection();
    return .{ .run = run, .baseline = baseline, .frontier = frontier };
}

fn readProposal(
    allocator: std.mem.Allocator,
    cursor: *Cursor,
    scenario_count: usize,
    total_selected: *usize,
) !Proposal {
    const proposal_digest = try cursor.digest();
    const cut_digest = try cursor.digest();
    const kind = wire.enumFromInt(EditKind, try cursor.int(u8)) orelse return error.InvalidEnum;
    const provenance = Provenance{
        .kind = kind,
        .pass = try cursor.int(u16),
        .parent_cut_digest = try cursor.digest(),
        .removed = try wire.readOptionalU32(cursor),
        .added = try wire.readOptionalU32(cursor),
    };
    const selected_count = try cursor.int(u32);
    if (selected_count > max_selected_per_proposal) return error.CountLimitExceeded;
    total_selected.* = std.math.add(usize, total_selected.*, selected_count) catch return error.CountLimitExceeded;
    if (total_selected.* > max_total_selected_values) return error.CountLimitExceeded;
    const selected = try allocator.alloc(u32, selected_count);
    errdefer allocator.free(selected);
    for (selected) |*value| value.* = try cursor.int(u32);
    var cost: CostVector = undefined;
    inline for (std.meta.fields(CostVector)) |field| @field(cost, field.name) = try cursor.int(u64);
    if (try cursor.int(u16) != scenario_count) return error.InconsistentCount;
    const scenario_costs = try allocator.alloc(ScenarioCost, scenario_count);
    errdefer allocator.free(scenario_costs);
    for (scenario_costs) |*scenario_cost| {
        inline for (std.meta.fields(ScenarioCost)) |field|
            @field(scenario_cost.*, field.name) = try cursor.int(u64);
    }
    return .{
        .proposal_digest = proposal_digest,
        .cut_digest = cut_digest,
        .provenance = provenance,
        .selected_values = selected,
        .cost = cost,
        .scenario_costs = scenario_costs,
    };
}

fn writeSectionHeader(writer: anytype, section: Section, length: u32) !void {
    try writeInt(writer, u8, @intFromEnum(section));
    try writeInt(writer, u8, 0);
    try writeInt(writer, u32, length);
}
fn deinitProposal(allocator: std.mem.Allocator, proposal: Proposal) void {
    allocator.free(proposal.selected_values);
    allocator.free(proposal.scenario_costs);
}
comptime {
    if (magic.len != 8) @compileError("materialization frontier magic must be 8 bytes");
    if (std.meta.fields(CostVector).len != 13) @compileError("cost vector wire width changed");
    if (std.meta.fields(ScenarioCost).len != 6) @compileError("scenario cost wire width changed");
}
