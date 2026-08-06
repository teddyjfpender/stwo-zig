//! Deterministic H-009 Poseidon cost-frontier artifact and readable views.

const std = @import("std");
const search_policy = @import("cost_aware_materializer.zig");
const ir = @import("ir.zig");
const manifest = @import("materialization_frontier_manifest.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const projection = @import("materialization_frontier_projection.zig");
const source = @import("source.zig");

pub const binary_filename = "frontier.stwairm";
pub const tsv_filename = "frontier-v1.tsv";
pub const markdown_filename = "frontier-v1.md";
pub const pinned_log_sizes = [_]u8{ 4, 6, 10, 14, 18 };
pub const pinned_config = search_policy.SearchConfig{
    .max_passes = 1,
    .max_candidate_evaluations = 2_048,
    .beam_width = 64,
    .frontier_limit = 128,
    .geometry = .{
        .preprocessed_columns = 0,
        .base_main_columns = 19,
        .fixed_direct_roots = poseidon_fixed.fixed_root_count,
        .interaction_columns = 8,
        .field_element_bytes = 4,
    },
    .fixed_direct_program = poseidon_fixed.program,
    .log_sizes = &pinned_log_sizes,
};

pub const Artifact = struct {
    allocator: std.mem.Allocator,
    binary: []u8,
    tsv: []u8,
    markdown: []u8,

    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.markdown);
        self.allocator.free(self.tsv);
        self.allocator.free(self.binary);
        self.* = undefined;
    }
};

pub fn generate(allocator: std.mem.Allocator) !Artifact {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const gate = try arena.input(
        "riscv.poseidon2_m31.enabled",
        .selector,
        generated,
    );
    const definition = try poseidon.define(
        &arena,
        poseidon.DefinitionSpans.uniform(generated),
    );
    const roots = poseidon.values(definition.outputs);
    var seed = try materializer.plan(allocator, &arena, .{
        .roots = &roots,
        .gate = gate,
    });
    defer seed.deinit();
    var result = try search_policy.search(allocator, &arena, &seed, pinned_config);
    defer result.deinit();
    var projected = try projection.fromSearch(
        allocator,
        &arena,
        &seed,
        pinned_config,
        &result,
    );
    defer projected.deinit();

    const binary = try manifest.encodeAlloc(allocator, projected.view());
    errdefer allocator.free(binary);
    var decoded = try manifest.decodeAlloc(allocator, binary);
    defer decoded.deinit();
    var tsv: std.ArrayList(u8) = .empty;
    errdefer tsv.deinit(allocator);
    try writeTsv(tsv.writer(allocator), decoded.view());
    var markdown: std.ArrayList(u8) = .empty;
    errdefer markdown.deinit(allocator);
    try writeMarkdown(markdown.writer(allocator), decoded.view());
    const owned_tsv = try tsv.toOwnedSlice(allocator);
    errdefer allocator.free(owned_tsv);
    const owned_markdown = try markdown.toOwnedSlice(allocator);
    return .{
        .allocator = allocator,
        .binary = binary,
        .tsv = owned_tsv,
        .markdown = owned_markdown,
    };
}

pub fn writeTsv(writer: anytype, value: manifest.Manifest) !void {
    try manifest.validateCanonical(value);
    try writer.writeAll("record\tkey\tvalue\n");
    try meta(writer, "format", "STWAIRM-v1");
    try meta(writer, "policy", manifest.policy_id);
    try meta(writer, "cost_scope", value.cost_model.scope.id());
    try metaInt(writer, "cost_scope_version", value.cost_model.scope_version);
    try metaDigest(writer, "semantic_digest", value.identity.semantic_digest);
    try metaDigest(writer, "cost_model_digest", value.cost_model.cost_model_digest);
    try metaDigest(writer, "fixed_program_digest", value.cost_model.fixed_program_digest);
    try metaDigest(writer, "configuration_digest", value.search.configuration_digest);
    try metaDigest(writer, "result_digest", value.run.result_digest);
    try metaInt(writer, "attempted_evaluations", value.run.attempted_evaluations);
    try metaInt(writer, "feasible_unique_proposals", value.run.feasible_unique_proposals);
    try metaInt(writer, "duplicate_proposals", value.run.duplicate_proposals);
    try metaInt(writer, "rejected_infeasible", value.run.rejected_infeasible);
    try metaInt(writer, "passes_completed", value.run.passes_completed);
    try metaInt(writer, "budget_exhausted", @intFromBool(value.run.budget_exhausted));
    try metaInt(writer, "frontier_truncated", @intFromBool(value.run.frontier_truncated));
    try metaInt(writer, "frontier_count", value.frontier.len);
    try writer.writeAll("scenario\tordinal\tlog_size\trows\n");
    for (value.scenarios, 0..) |scenario, ordinal|
        try writer.print("scenario\t{d}\t{d}\t{d}\n", .{
            ordinal,
            scenario.log_size,
            scenario.rows,
        });

    try writer.writeAll(
        "proposal\tclass\tordinal\tproposal_digest\tcut_digest\tparent_cut_digest" ++
            "\tedit\tpass\tremoved\tadded\tselected_count\tselected_values" ++
            "\tmaterializations\tbase_main\tcandidate_main\tdirect_roots" ++
            "\tinteraction_columns\tdirect_nodes\tadditions\tsubtractions" ++
            "\tnegations\tmultiplications\tcommitted_reads\tstreaming_peak_live" ++
            "\tsemantic_witness_nodes\n",
    );
    try writeProposalTsv(writer, "baseline", 0, value.baseline);
    for (value.frontier, 0..) |proposal, ordinal|
        try writeProposalTsv(writer, "frontier", ordinal, proposal);

    try writer.writeAll(
        "proposal_scenario\tclass\tproposal_ordinal\tscenario_ordinal\tlog_size" ++
            "\trows\tmain_cells\tinteraction_cells\tcommitted_cells" ++
            "\tmain_bytes\tinteraction_bytes\tcommitted_bytes\n",
    );
    try writeScenarioCosts(writer, "baseline", 0, value.baseline, value.scenarios);
    for (value.frontier, 0..) |proposal, ordinal|
        try writeScenarioCosts(writer, "frontier", ordinal, proposal, value.scenarios);
}

pub fn writeMarkdown(writer: anytype, value: manifest.Manifest) !void {
    try manifest.validateCanonical(value);
    const semantic_hex = std.fmt.bytesToHex(value.identity.semantic_digest, .lower);
    const model_hex = std.fmt.bytesToHex(value.cost_model.cost_model_digest, .lower);
    const config_hex = std.fmt.bytesToHex(value.search.configuration_digest, .lower);
    const result_hex = std.fmt.bytesToHex(value.run.result_digest, .lower);
    try writer.writeAll(
        "# H-009 Poseidon2 materialization cost frontier\n\n" ++
            "> Experimental proposal evidence only. This artifact changes no production " ++
            "layout, proof statement, prover, verifier, or transcript.\n\n",
    );
    try writer.print(
        "The bounded deterministic search completed **{d}** pass over **{d}** " ++
            "candidate edits and retained **{d}** non-seed Pareto proposals. " ++
            "It makes no global-optimality claim.\n\n",
        .{ value.run.passes_completed, value.run.attempted_evaluations, value.frontier.len },
    );
    try writer.writeAll("## Identity\n\n| Field | Value |\n| --- | --- |\n");
    try writer.print(
        "| Cost scope | `{s}` |\n| Semantic digest | `{s}` |\n" ++
            "| Cost-model digest | `{s}` |\n| Search configuration | `{s}` |\n" ++
            "| Result digest | `{s}` |\n",
        .{ value.cost_model.scope.id(), &semantic_hex, &model_hex, &config_hex, &result_hex },
    );
    try writer.print(
        "| Fixed/equality direct roots | {d} + {d} = {d} |\n" ++
            "| Main / interaction columns | {d} / {d} |\n\n",
        .{
            value.cost_model.fixed_root_count,
            value.baseline.cost.materialization_count,
            value.baseline.cost.direct_roots,
            value.baseline.cost.candidate_main_columns,
            value.baseline.cost.interaction_columns,
        },
    );
    try writer.writeAll(
        "The fixed scope is the 430-root Poseidon permutation direct AIR: enabler " ++
            "booleanity, 426 candidate equalities, wide/io booleanity, and mutual " ++
            "exclusion. The surrounding hash-component shell and LogUp algebra are " ++
            "outside this cost scope.\n\n",
    );
    try writer.writeAll("## Baseline structural vector\n\n| Coordinate | Value |\n| --- | ---: |\n");
    inline for (std.meta.fields(manifest.CostVector)) |field|
        try writer.print("| `{s}` | {d} |\n", .{
            field.name,
            @field(value.baseline.cost, field.name),
        });
    try writer.writeAll(
        "\n`canonical_streaming_peak_live_nodes` is an idealized root-folding " ++
            "schedule. Current CPU and Metal evaluators retain one scratch value per " ++
            "canonical direct node; H-010 measures actual work and memory separately.\n\n",
    );
    var equal_to_baseline: usize = 0;
    for (value.frontier) |proposal| if (sameCosts(value.baseline, proposal)) {
        equal_to_baseline += 1;
    };
    try writer.print(
        "## Frontier\n\n**{d}/{d}** retained proposals have the exact baseline " ++
            "structural and scenario vector. Equal objective points remain separate " ++
            "because they name different authenticated cut sets.\n\n",
        .{ equal_to_baseline, value.frontier.len },
    );
    try writer.writeAll(
        "| # | Proposal digest | Edit | Pass | Removed | Added | Materials | " ++
            "Direct nodes | Baseline-equivalent |\n| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n",
    );
    for (value.frontier, 0..) |proposal, ordinal| {
        const proposal_hex = std.fmt.bytesToHex(proposal.proposal_digest, .lower);
        try writer.print(
            "| {d} | `{s}` | {s} | {d} | ",
            .{
                ordinal,
                &proposal_hex,
                @tagName(proposal.provenance.kind),
                proposal.provenance.pass,
            },
        );
        try writeOptional(writer, proposal.provenance.removed);
        try writer.writeAll(" | ");
        try writeOptional(writer, proposal.provenance.added);
        try writer.print(" | {d} | {d} | {s} |\n", .{
            proposal.cost.materialization_count,
            proposal.cost.canonical_direct_nodes,
            if (sameCosts(value.baseline, proposal)) "yes" else "no",
        });
    }
}

fn writeProposalTsv(
    writer: anytype,
    class: []const u8,
    ordinal: usize,
    proposal: manifest.Proposal,
) !void {
    const proposal_hex = std.fmt.bytesToHex(proposal.proposal_digest, .lower);
    const cut_hex = std.fmt.bytesToHex(proposal.cut_digest, .lower);
    const parent_hex = std.fmt.bytesToHex(proposal.provenance.parent_cut_digest, .lower);
    try writer.print("proposal\t{s}\t{d}\t{s}\t{s}\t{s}\t{s}\t{d}\t", .{
        class,
        ordinal,
        &proposal_hex,
        &cut_hex,
        &parent_hex,
        @tagName(proposal.provenance.kind),
        proposal.provenance.pass,
    });
    try writeOptional(writer, proposal.provenance.removed);
    try writer.writeByte('\t');
    try writeOptional(writer, proposal.provenance.added);
    try writer.print("\t{d}\t", .{proposal.selected_values.len});
    for (proposal.selected_values, 0..) |selected, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.print("{d}", .{selected});
    }
    inline for (std.meta.fields(manifest.CostVector)) |field|
        try writer.print("\t{d}", .{@field(proposal.cost, field.name)});
    try writer.writeByte('\n');
}

fn writeScenarioCosts(
    writer: anytype,
    class: []const u8,
    proposal_ordinal: usize,
    proposal: manifest.Proposal,
    scenarios: []const manifest.Scenario,
) !void {
    for (proposal.scenario_costs, scenarios, 0..) |cost, scenario, ordinal|
        try writer.print(
            "proposal_scenario\t{s}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\t{d}\n",
            .{
                class,
                proposal_ordinal,
                ordinal,
                scenario.log_size,
                scenario.rows,
                cost.main_cells,
                cost.interaction_cells,
                cost.committed_cells,
                cost.main_bytes,
                cost.interaction_bytes,
                cost.committed_bytes,
            },
        );
}

fn sameCosts(lhs: manifest.Proposal, rhs: manifest.Proposal) bool {
    if (!std.meta.eql(lhs.cost, rhs.cost) or
        lhs.scenario_costs.len != rhs.scenario_costs.len)
    {
        return false;
    }
    for (lhs.scenario_costs, rhs.scenario_costs) |lhs_cost, rhs_cost|
        if (!std.meta.eql(lhs_cost, rhs_cost)) return false;
    return true;
}

fn writeOptional(writer: anytype, value: ?u32) !void {
    if (value) |present|
        try writer.print("{d}", .{present})
    else
        try writer.writeByte('-');
}

fn meta(writer: anytype, key: []const u8, value: []const u8) !void {
    try writer.print("meta\t{s}\t{s}\n", .{ key, value });
}

fn metaInt(writer: anytype, key: []const u8, value: anytype) !void {
    try writer.print("meta\t{s}\t{d}\n", .{ key, value });
}

fn metaDigest(writer: anytype, key: []const u8, value: manifest.Digest) !void {
    const hex = std.fmt.bytesToHex(value, .lower);
    try meta(writer, key, &hex);
}
