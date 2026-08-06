const std = @import("std");
const manifest = @import("materialization_frontier_manifest.zig");
const test_support = @import("materialization_frontier_manifest_test_support.zig");

const proposalScenarioCountOffset = test_support.proposalScenarioCountOffset;
const proposalWireLength = test_support.proposalWireLength;
const runWireLength = test_support.runWireLength;
const section = test_support.section;

test "cost frontier manifest is deterministic and round trips canonically" {
    var fixture: Fixture = undefined;
    fixture.init();
    const view = fixture.view();
    const first = try manifest.encodeAlloc(std.testing.allocator, view);
    defer std.testing.allocator.free(first);
    const second = try manifest.encodeAlloc(std.testing.allocator, view);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualSlices(u8, first, second);
    try std.testing.expect(std.mem.startsWith(u8, first, manifest.magic));

    var decoded = try manifest.decodeAlloc(std.testing.allocator, first);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u32, view.identity.roots, decoded.identity.roots);
    try std.testing.expectEqual(view.frontier.len, decoded.frontier.len);
    try std.testing.expect(std.meta.eql(view.run, decoded.run));
    var found_zero_value = false;
    for (decoded.frontier) |proposal| if (proposal.selected_values[0] == 0) {
        try std.testing.expectEqual(@as(?u32, 0), proposal.provenance.added);
        found_zero_value = true;
    };
    try std.testing.expect(found_zero_value);
    try std.testing.expectEqualSlices(
        u8,
        &manifest.computeArtifactDigest(first),
        &manifest.computeArtifactDigest(second),
    );
    const round_trip = try manifest.encodeAlloc(std.testing.allocator, decoded.view());
    defer std.testing.allocator.free(round_trip);
    try std.testing.expectEqualSlices(u8, first, round_trip);
}

test "ordered roots, u64 policy degrees, and search digests preserve authority" {
    var fixture: Fixture = undefined;
    fixture.init();
    const canonical_cut = fixture.baseline.cut_digest;
    var expected_cut: manifest.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_cut,
        "5f9815157569dc1f209c9b9b4d4848ff2d379232e38b080834ed34bdaa837fbe",
    );
    var expected_proposal: manifest.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_proposal,
        "303aca2b1d6aa92076408d276713283a8d675a86e7d424ce155793d43c2e1128",
    );
    try std.testing.expectEqualSlices(u8, &expected_cut, &fixture.baseline.cut_digest);
    try std.testing.expectEqualSlices(u8, &expected_proposal, &fixture.baseline.proposal_digest);

    std.mem.swap(u32, &fixture.roots[0], &fixture.roots[1]);
    fixture.identity.maximum_constraint_degree = 1_000;
    fixture.identity.row_mask_degree = 300;
    fixture.refreshDigests();
    try std.testing.expect(!std.mem.eql(u8, &canonical_cut, &fixture.baseline.cut_digest));
    const bytes = try manifest.encodeAlloc(std.testing.allocator, fixture.view());
    defer std.testing.allocator.free(bytes);
    var decoded = try manifest.decodeAlloc(std.testing.allocator, bytes);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 20, 10 }, decoded.identity.roots);
    try std.testing.expectEqual(@as(u64, 1_000), decoded.identity.maximum_constraint_degree);
    try std.testing.expectEqual(@as(u64, 300), decoded.identity.row_mask_degree);
}

test "ordered root identity preserves duplicate output multiplicity" {
    var fixture: Fixture = undefined;
    fixture.init();
    const distinct_identity = fixture.identity.identity_digest;

    fixture.roots[1] = fixture.roots[0];
    fixture.refreshDigests();
    try std.testing.expect(!std.mem.eql(
        u8,
        &distinct_identity,
        &fixture.identity.identity_digest,
    ));

    const bytes = try manifest.encodeAlloc(std.testing.allocator, fixture.view());
    defer std.testing.allocator.free(bytes);
    var decoded = try manifest.decodeAlloc(std.testing.allocator, bytes);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 10, 10 }, decoded.identity.roots);
    try std.testing.expectEqualSlices(
        u8,
        &fixture.identity.identity_digest,
        &decoded.identity.identity_digest,
    );
}

test "cost frontier wire header and scalar widths are explicit little endian" {
    var fixture: Fixture = undefined;
    fixture.init();
    const bytes = try manifest.encodeAlloc(std.testing.allocator, fixture.view());
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings(manifest.magic, bytes[0..8]);
    try std.testing.expectEqual(manifest.format_version, std.mem.readInt(u16, bytes[8..10], .little));
    try std.testing.expectEqual(@as(u8, 4), bytes[10]);
    try std.testing.expectEqual(@as(u8, 0), bytes[11]);

    const identity = try section(bytes, 1);
    try std.testing.expectEqual(@as(u8, 1), identity.payload[32]);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, identity.payload[33..35], .little));
    try std.testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, identity.payload[35..43], .little));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, identity.payload[51..55], .little));
    try std.testing.expectEqual(@as(u32, 10), std.mem.readInt(u32, identity.payload[55..59], .little));
    try std.testing.expectEqual(@as(u32, 20), std.mem.readInt(u32, identity.payload[59..63], .little));

    const search = try section(bytes, 2);
    try std.testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, search.payload[3..5], .little));
    try std.testing.expectEqual(@as(u16, 32), std.mem.readInt(u16, search.payload[5..7], .little));
    try std.testing.expectEqual(@as(u32, 64), std.mem.readInt(u32, search.payload[7..11], .little));
}

test "encoder rejects malformed identity, search, scenarios, and costs before writing" {
    var fixture: Fixture = undefined;
    fixture.init();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(std.testing.allocator);

    fixture.identity.identity_digest[0] ^= 1;
    try std.testing.expectError(
        error.DigestMismatch,
        manifest.writeCanonical(output.writer(std.testing.allocator), fixture.view()),
    );
    try std.testing.expectEqual(@as(usize, 0), output.items.len);
    fixture.identity.identity_digest[0] ^= 1;

    fixture.search.beam_width = 24;
    try std.testing.expectError(
        error.InvalidSearchConfig,
        manifest.writeCanonical(output.writer(std.testing.allocator), fixture.view()),
    );
    fixture.search.beam_width = 32;

    fixture.scenarios[1] = fixture.scenarios[0];
    try std.testing.expectError(
        error.InvalidScenarioOrder,
        manifest.writeCanonical(output.writer(std.testing.allocator), fixture.view()),
    );
    fixture.scenarios[1] = .{ .log_size = 10, .rows = 1 << 10 };

    fixture.baseline.cost.candidate_main_columns += 1;
    fixture.refreshDigests();
    try std.testing.expectError(
        error.InconsistentCost,
        manifest.writeCanonical(output.writer(std.testing.allocator), fixture.view()),
    );
    try std.testing.expectEqual(@as(usize, 0), output.items.len);

    fixture.init();
    fixture.geometry.field_element_bytes = std.math.maxInt(u64);
    fixture.refreshDigests();
    try std.testing.expectError(
        error.CostOverflow,
        manifest.writeCanonical(output.writer(std.testing.allocator), fixture.view()),
    );
}

test "search bounds and complete run accounting match the bounded policy" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.search.max_passes = 33;
    try std.testing.expectError(error.InvalidSearchConfig, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
    fixture.init();
    fixture.search.max_candidate_evaluations = 1_000_001;
    try std.testing.expectError(error.InvalidSearchConfig, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
    fixture.init();
    fixture.search.frontier_limit = 24;
    try std.testing.expectError(error.InvalidSearchConfig, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));

    fixture.init();
    fixture.run.feasible_unique_proposals = 1;
    try std.testing.expectError(error.InvalidRunAccounting, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
    fixture.init();
    fixture.run.budget_exhausted = true;
    try std.testing.expectError(error.InvalidRunAccounting, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
    fixture.init();
    fixture.search.configuration_digest[0] ^= 1;
    try std.testing.expectError(error.ConfigurationDigestMismatch, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
    fixture.init();
    fixture.run.result_digest[0] ^= 1;
    try std.testing.expectError(error.ResultDigestMismatch, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));

    fixture.init();
    var limited = fixture.view();
    limited.frontier = &.{};
    limited.search.max_candidate_evaluations = 1;
    limited.run = .{
        .attempted_evaluations = 0,
        .feasible_unique_proposals = 0,
        .duplicate_proposals = 0,
        .rejected_infeasible = 0,
        .passes_completed = 1,
        .budget_exhausted = false,
        .frontier_truncated = false,
        .result_digest = undefined,
    };
    limited.search.configuration_digest = manifest.computeConfigurationDigest(limited);
    limited.run.result_digest = manifest.computeResultDigest(limited);
    const bytes = try manifest.encodeAlloc(std.testing.allocator, limited);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(limited.search.beam_width > limited.search.max_candidate_evaluations);
    try std.testing.expect(limited.search.frontier_limit > limited.search.max_candidate_evaluations);
}

test "encoder rejects noncanonical cuts, digests, provenance, and counts" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.baseline_selected[1] = fixture.baseline_selected[0];
    try std.testing.expectError(error.NonCanonicalSelection, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));

    fixture.init();
    fixture.frontier[0].cut_digest[0] ^= 1;
    try std.testing.expectError(error.DigestMismatch, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));

    fixture.init();
    fixture.frontier[0].provenance.pass = 0;
    try std.testing.expectError(error.InvalidProposal, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));

    fixture.init();
    fixture.frontier[0].provenance.pass = fixture.run.passes_completed + 1;
    try std.testing.expectError(error.InvalidProposal, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
    fixture.init();
    fixture.run.attempted_evaluations = 1;
    try std.testing.expectError(error.InvalidRunAccounting, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
}

test "frontier rejects duplicate, reordered, and dominated proposals" {
    var fixture: Fixture = undefined;
    fixture.init();
    std.mem.swap(manifest.Proposal, &fixture.frontier[0], &fixture.frontier[1]);
    try std.testing.expectError(error.NonCanonicalFrontier, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));

    fixture.init();
    fixture.frontier[0].selected_values = &fixture.baseline_selected;
    fixture.frontier[0].provenance = .{
        .kind = .add,
        .pass = 1,
        .parent_cut_digest = fixture.frontier[1].cut_digest,
        .added = 10,
    };
    fixture.frontier[0].cut_digest = manifest.computeCutDigest(
        fixture.identity,
        fixture.frontier[0].selected_values,
    );
    fixture.frontier[0].proposal_digest = manifest.computeProposalDigest(
        fixture.frontier[0].cut_digest,
        fixture.cost_model.cost_model_digest,
        fixture.frontier[0].cost,
        &fixture.scenarios,
        fixture.frontier[0].scenario_costs,
    );
    try std.testing.expectError(error.DuplicateCut, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));

    fixture.init();
    fixture.frontier[0].cost = fixture.baseline.cost;
    fixture.frontier[0].cost.canonical_direct_nodes += 1;
    fixture.refreshDigests();
    try std.testing.expectError(error.DominatedFrontier, manifest.encodeAlloc(
        std.testing.allocator,
        fixture.view(),
    ));
}

test "decoder rejects every truncation and trailing data" {
    var fixture: Fixture = undefined;
    fixture.init();
    const bytes = try manifest.encodeAlloc(std.testing.allocator, fixture.view());
    defer std.testing.allocator.free(bytes);
    for (0..bytes.len) |end| {
        var accepted = false;
        if (manifest.decodeAlloc(std.testing.allocator, bytes[0..end])) |value| {
            var decoded = value;
            decoded.deinit();
            accepted = true;
        } else |_| {}
        try std.testing.expect(!accepted);
    }

    const extended = try std.testing.allocator.alloc(u8, bytes.len + 1);
    defer std.testing.allocator.free(extended);
    @memcpy(extended[0..bytes.len], bytes);
    extended[bytes.len] = 0;
    try std.testing.expectError(error.TrailingBytes, manifest.decodeAlloc(
        std.testing.allocator,
        extended,
    ));

    const candidate = try section(bytes, 4);
    const section_extended = try std.testing.allocator.alloc(u8, bytes.len + 1);
    defer std.testing.allocator.free(section_extended);
    @memcpy(section_extended[0..bytes.len], bytes);
    section_extended[bytes.len] = 0;
    std.mem.writeInt(
        u32,
        section_extended[candidate.header_start + 2 ..][0..4],
        @intCast(candidate.payload.len + 1),
        .little,
    );
    try std.testing.expectError(error.TrailingSectionBytes, manifest.decodeAlloc(
        std.testing.allocator,
        section_extended,
    ));
}

test "decoder rejects envelope, enum, count, and digest corruption" {
    var fixture: Fixture = undefined;
    fixture.init();
    const canonical = try manifest.encodeAlloc(std.testing.allocator, fixture.view());
    defer std.testing.allocator.free(canonical);

    var bytes = try std.testing.allocator.dupe(u8, canonical);
    bytes[0] ^= 1;
    try std.testing.expectError(error.BadMagic, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    std.mem.writeInt(u16, bytes[8..10], 2, .little);
    try std.testing.expectError(error.UnsupportedVersion, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    bytes[10] = 3;
    try std.testing.expectError(error.InvalidSectionCount, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    bytes[12] = 9;
    try std.testing.expectError(error.InvalidEnum, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    bytes[12] = 2;
    try std.testing.expectError(error.InvalidSectionOrder, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    bytes[13] = 1;
    try std.testing.expectError(error.NonCanonicalEncoding, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    std.mem.writeInt(u32, bytes[14..18], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.LengthLimitExceeded, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const identity = try section(bytes, 1);
    bytes[identity.payload_start + 32] = 0xff;
    try std.testing.expectError(error.InvalidEnum, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const identity_count = (try section(bytes, 1)).payload_start + 51;
    std.mem.writeInt(u32, bytes[identity_count..][0..4], manifest.max_roots + 1, .little);
    try std.testing.expectError(error.CountLimitExceeded, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const identity_roots = (try section(bytes, 1)).payload_start + 55;
    std.mem.writeInt(u32, bytes[identity_roots..][0..4], 20, .little);
    try std.testing.expectError(error.DigestMismatch, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const identity_digest = (try section(bytes, 1)).payload_start;
    bytes[identity_digest] ^= 1;
    try std.testing.expectError(error.DigestMismatch, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const search = try section(bytes, 2);
    bytes[search.payload_start + 2] = 0xff;
    try std.testing.expectError(error.InvalidEnum, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const configuration_digest = (try section(bytes, 2)).payload_start + 95;
    bytes[configuration_digest] ^= 1;
    try std.testing.expectError(error.ConfigurationDigestMismatch, manifest.decodeAlloc(
        std.testing.allocator,
        bytes,
    ));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const run_payload = (try section(bytes, 4)).payload_start;
    bytes[run_payload] ^= 1;
    try std.testing.expectError(error.ResultDigestMismatch, manifest.decodeAlloc(
        std.testing.allocator,
        bytes,
    ));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const budget_flag = (try section(bytes, 4)).payload_start + 50;
    bytes[budget_flag] = 2;
    try std.testing.expectError(error.InvalidEnum, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const attempted = (try section(bytes, 4)).payload_start + 32;
    std.mem.writeInt(u32, bytes[attempted..][0..4], 1, .little);
    try std.testing.expectError(error.InvalidRunAccounting, manifest.decodeAlloc(
        std.testing.allocator,
        bytes,
    ));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const candidates = try section(bytes, 4);
    bytes[candidates.payload_start + runWireLength() + 64] = 0xff;
    try std.testing.expectError(error.InvalidEnum, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const optional_removed = (try section(bytes, 4)).payload_start + runWireLength() + 99;
    bytes[optional_removed] = 2;
    try std.testing.expectError(error.InvalidEnum, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const candidate_payload = (try section(bytes, 4)).payload_start;
    bytes[candidate_payload + runWireLength()] ^= 1;
    try std.testing.expectError(error.DigestMismatch, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);

    bytes = try std.testing.allocator.dupe(u8, canonical);
    const scenario_count = (try section(bytes, 4)).payload_start + runWireLength() +
        proposalScenarioCountOffset(3, false, false);
    std.mem.writeInt(u16, bytes[scenario_count..][0..2], 1, .little);
    try std.testing.expectError(error.InconsistentCount, manifest.decodeAlloc(std.testing.allocator, bytes));
    std.testing.allocator.free(bytes);
}

test "decoder independently enforces canonical frontier order" {
    var fixture: Fixture = undefined;
    fixture.init();
    const canonical = try manifest.encodeAlloc(std.testing.allocator, fixture.view());
    defer std.testing.allocator.free(canonical);
    const bytes = try std.testing.allocator.dupe(u8, canonical);
    defer std.testing.allocator.free(bytes);
    const candidates = try section(bytes, 4);
    const baseline_len = proposalWireLength(3, fixture.scenarios.len, false, false);
    const frontier_len = proposalWireLength(3, fixture.scenarios.len, true, true);
    const first = candidates.payload_start + runWireLength() + baseline_len;
    const second = first + frontier_len;
    for (0..frontier_len) |index| std.mem.swap(u8, &bytes[first + index], &bytes[second + index]);
    try std.testing.expectError(error.NonCanonicalFrontier, manifest.decodeAlloc(
        std.testing.allocator,
        bytes,
    ));
}

test "manifest encoding and decoding release every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        encodeFailureCase,
        .{},
    );
    var fixture: Fixture = undefined;
    fixture.init();
    const bytes = try manifest.encodeAlloc(std.testing.allocator, fixture.view());
    defer std.testing.allocator.free(bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        decodeFailureCase,
        .{bytes},
    );
}

fn encodeFailureCase(allocator: std.mem.Allocator) !void {
    var fixture: Fixture = undefined;
    fixture.init();
    const bytes = try manifest.encodeAlloc(allocator, fixture.view());
    defer allocator.free(bytes);
}

fn decodeFailureCase(allocator: std.mem.Allocator, bytes: []const u8) !void {
    var decoded = try manifest.decodeAlloc(allocator, bytes);
    defer decoded.deinit();
}

const Fixture = struct {
    roots: [2]u32,
    scenarios: [2]manifest.Scenario,
    baseline_selected: [3]u32,
    frontier_selected: [2][3]u32,
    baseline_scenario_costs: [2]manifest.ScenarioCost,
    frontier_scenario_costs: [2][2]manifest.ScenarioCost,
    identity: manifest.Identity,
    search: manifest.SearchConfig,
    cost_model: manifest.CostModelIdentity,
    geometry: manifest.Geometry,
    run: manifest.RunAccounting,
    baseline: manifest.Proposal,
    frontier: [2]manifest.Proposal,

    fn init(self: *Fixture) void {
        self.roots = .{ 10, 20 };
        self.scenarios = .{
            .{ .log_size = 4, .rows = 1 << 4 },
            .{ .log_size = 10, .rows = 1 << 10 },
        };
        self.baseline_selected = .{ 3, 10, 20 };
        self.frontier_selected = .{ .{ 0, 10, 20 }, .{ 5, 10, 20 } };
        self.geometry = .{
            .base_main_columns = 19,
            .fixed_direct_roots = 4,
            .interaction_columns = 8,
            .field_element_bytes = 4,
        };
        self.search = .{
            .max_passes = 3,
            .beam_width = 32,
            .max_candidate_evaluations = 64,
            .frontier_limit = 32,
            .configuration_digest = undefined,
        };
        self.cost_model = manifest.poseidon2PermutationDirectCostModel();
        self.identity = .{
            .semantic_digest = [_]u8{0x5a} ** 32,
            .roots = &self.roots,
            .gate = 2,
            .maximum_constraint_degree = 3,
            .row_mask_degree = 0,
            .identity_digest = undefined,
        };
        self.identity.identity_digest = manifest.computeIdentityDigest(self.identity);
        self.baseline_scenario_costs = scenarioCosts(self.geometry, 3, self.scenarios);
        self.frontier_scenario_costs = .{
            scenarioCosts(self.geometry, 3, self.scenarios),
            scenarioCosts(self.geometry, 3, self.scenarios),
        };
        self.baseline = .{
            .proposal_digest = undefined,
            .cut_digest = undefined,
            .provenance = .{
                .kind = .seed,
                .pass = 0,
                .parent_cut_digest = [_]u8{0} ** 32,
            },
            .selected_values = &self.baseline_selected,
            .cost = costVector(self.geometry, 3, 30, 5, 3, 1, 5, 10, 8),
            .scenario_costs = &self.baseline_scenario_costs,
        };
        self.frontier = .{
            .{
                .proposal_digest = undefined,
                .cut_digest = undefined,
                .provenance = undefined,
                .selected_values = &self.frontier_selected[0],
                .cost = costVector(self.geometry, 3, 40, 8, 4, 1, 4, 11, 10),
                .scenario_costs = &self.frontier_scenario_costs[0],
            },
            .{
                .proposal_digest = undefined,
                .cut_digest = undefined,
                .provenance = undefined,
                .selected_values = &self.frontier_selected[1],
                .cost = costVector(self.geometry, 3, 20, 3, 2, 0, 8, 8, 6),
                .scenario_costs = &self.frontier_scenario_costs[1],
            },
        };
        self.run = .{
            .attempted_evaluations = 2,
            .feasible_unique_proposals = 2,
            .duplicate_proposals = 0,
            .rejected_infeasible = 0,
            .passes_completed = 2,
            .budget_exhausted = false,
            .frontier_truncated = false,
            .result_digest = undefined,
        };
        self.refreshDigests();
    }

    fn refreshDigests(self: *Fixture) void {
        self.identity.identity_digest = manifest.computeIdentityDigest(self.identity);
        self.baseline.cut_digest = manifest.computeCutDigest(
            self.identity,
            self.baseline.selected_values,
        );
        self.baseline.proposal_digest = manifest.computeProposalDigest(
            self.baseline.cut_digest,
            self.cost_model.cost_model_digest,
            self.baseline.cost,
            &self.scenarios,
            self.baseline.scenario_costs,
        );
        self.search.configuration_digest = manifest.computeConfigurationDigest(self.view());
        for (&self.frontier, 0..) |*proposal, index| {
            proposal.provenance = .{
                .kind = .swap,
                .pass = @intCast(index + 1),
                .parent_cut_digest = self.baseline.cut_digest,
                .removed = 3,
                .added = proposal.selected_values[0],
            };
            proposal.cut_digest = manifest.computeCutDigest(self.identity, proposal.selected_values);
            proposal.proposal_digest = manifest.computeProposalDigest(
                proposal.cut_digest,
                self.cost_model.cost_model_digest,
                proposal.cost,
                &self.scenarios,
                proposal.scenario_costs,
            );
        }
        if (std.mem.order(
            u8,
            &self.frontier[0].proposal_digest,
            &self.frontier[1].proposal_digest,
        ) == .gt) std.mem.swap(manifest.Proposal, &self.frontier[0], &self.frontier[1]);
        self.run.result_digest = manifest.computeResultDigest(self.view());
    }

    fn view(self: *const Fixture) manifest.Manifest {
        return .{
            .identity = self.identity,
            .search = self.search,
            .cost_model = self.cost_model,
            .geometry = self.geometry,
            .scenarios = &self.scenarios,
            .run = self.run,
            .baseline = self.baseline,
            .frontier = &self.frontier,
        };
    }
};

fn costVector(
    geometry: manifest.Geometry,
    materializations: u64,
    nodes: u64,
    additions: u64,
    subtractions: u64,
    negations: u64,
    multiplications: u64,
    reads: u64,
    peak: u64,
) manifest.CostVector {
    return .{
        .materialization_count = materializations,
        .base_main_columns = geometry.base_main_columns,
        .candidate_main_columns = geometry.base_main_columns + materializations,
        .direct_roots = geometry.fixed_direct_roots + materializations,
        .interaction_columns = geometry.interaction_columns,
        .canonical_direct_nodes = nodes,
        .canonical_direct_additions = additions,
        .canonical_direct_subtractions = subtractions,
        .canonical_direct_negations = negations,
        .canonical_direct_multiplications = multiplications,
        .unique_committed_column_reads = reads,
        .canonical_streaming_peak_live_nodes = peak,
        .semantic_witness_nodes = 100,
    };
}

fn scenarioCosts(
    geometry: manifest.Geometry,
    materializations: u64,
    scenarios: [2]manifest.Scenario,
) [2]manifest.ScenarioCost {
    var result: [2]manifest.ScenarioCost = undefined;
    for (scenarios, &result) |scenario, *cost| {
        const main_cells = (geometry.base_main_columns + materializations) * scenario.rows;
        const interaction_cells = geometry.interaction_columns * scenario.rows;
        const committed_cells = main_cells + interaction_cells;
        cost.* = .{
            .main_cells = main_cells,
            .interaction_cells = interaction_cells,
            .committed_cells = committed_cells,
            .main_bytes = main_cells * geometry.field_element_bytes,
            .interaction_bytes = interaction_cells * geometry.field_element_bytes,
            .committed_bytes = committed_cells * geometry.field_element_bytes,
        };
    }
    return result;
}
