//! Focused A1 gates for value-only real-receipt ingestion. Fixture values
//! exercise the schema and must not be cited as benchmark evidence.

const std = @import("std");
const fixed_profile = @import("fixed_profile.zig");
const frontier = @import("fri_profile_frontier.zig");
const protocol = @import("protocol.zig");

const COLUMN_LOG_DEGREE: u32 = 20;

test "A1 receipt observations emit deterministic source-local V1.1 comparisons" {
    const leaf_v1 = try fixtureObservation(.{
        .source = .native_leaf,
        .log_blowup_factor = 1,
        .canonical_proof_bytes = 1_389_904,
        .fixed_wire_bytes = 2_111_588,
        .work_unit = .compiled_graph_nodes,
        .work_units = 512_183,
        .native_verify_ns = 6_966_000_000,
        .extra_provider_calls = 31,
        .receipt_label = "fixture/leaf/v1",
    });
    const leaf_v11 = try fixtureObservation(.{
        .source = .native_leaf,
        .log_blowup_factor = 2,
        .canonical_proof_bytes = 775_619,
        .fixed_wire_bytes = 1_098_116,
        .work_unit = .compiled_graph_nodes,
        .work_units = 263_803,
        .native_verify_ns = 13_451_000_000,
        .extra_provider_calls = 31,
        .receipt_label = "fixture/leaf/v1.1",
    });
    const binary_v1 = try fixtureObservation(.{
        .source = .binary_outer,
        .log_blowup_factor = 1,
        .canonical_proof_bytes = 130_000,
        .fixed_wire_bytes = null,
        .work_unit = .air_constraints,
        .work_units = 1_200,
        .native_verify_ns = 4_000_000_000,
        .extra_provider_calls = 83,
        .receipt_label = "fixture/binary/v1",
    });
    const binary_v11 = try fixtureObservation(.{
        .source = .binary_outer,
        .log_blowup_factor = 2,
        .canonical_proof_bytes = 90_000,
        .fixed_wire_bytes = null,
        .work_unit = .air_constraints,
        .work_units = 900,
        .native_verify_ns = 5_000_000_000,
        .extra_provider_calls = 83,
        .receipt_label = "fixture/binary/v1.1",
    });

    const insertion_order = [_]frontier.ObservationV1{
        binary_v11,
        leaf_v1,
        binary_v1,
        leaf_v11,
    };
    var forward = frontier.ObservationSetV1.init();
    for (insertion_order) |observation| try forward.ingest(observation);
    var reverse = frontier.ObservationSetV1.init();
    var at = insertion_order.len;
    while (at != 0) {
        at -= 1;
        try reverse.ingest(insertion_order[at]);
    }
    try forward.validate();
    try reverse.validate();
    try expectObservationSlicesEqual(forward.active(), reverse.active());
    try std.testing.expectEqual(
        try forward.identityDigest(),
        try reverse.identityDigest(),
    );

    const forward_comparisons = try forward.comparisons();
    const reverse_comparisons = try reverse.comparisons();
    try forward_comparisons.validateAgainst(&forward);
    try reverse_comparisons.validateAgainst(&reverse);
    try std.testing.expectEqual(@as(u8, 2), forward_comparisons.count);
    try expectComparisonSlicesEqual(
        forward_comparisons.active(),
        reverse_comparisons.active(),
    );
    try std.testing.expectEqual(
        try forward_comparisons.identityDigest(),
        try reverse_comparisons.identityDigest(),
    );
    var noncanonical_order = forward_comparisons;
    std.mem.swap(
        frontier.ComparisonV1,
        &noncanonical_order.comparisons[0],
        &noncanonical_order.comparisons[1],
    );
    try std.testing.expectError(
        error.InvalidComparison,
        noncanonical_order.validate(),
    );

    const leaf = forward_comparisons.active()[0];
    try std.testing.expectEqual(
        frontier.ObservationSourceV1.native_leaf,
        leaf.source,
    );
    try std.testing.expectEqual(
        frontier.ParetoRelationV1.tradeoff,
        leaf.pareto_relation,
    );
    try std.testing.expectEqual(
        frontier.DeltaDirectionV1.decrease,
        leaf.canonical_proof_bytes.direction,
    );
    try std.testing.expectEqual(
        @as(u64, 614_285),
        leaf.canonical_proof_bytes.magnitude,
    );
    try std.testing.expectEqual(
        frontier.DeltaDirectionV1.increase,
        leaf.native_verify_ns.direction,
    );
    try std.testing.expectEqual(
        @as(u64, 6_485_000_000),
        leaf.native_verify_ns.magnitude,
    );
    try std.testing.expectEqual(
        @as(u64, 2_111_588),
        leaf.fixed_wire_bytes.?.baseline,
    );
    try std.testing.expectEqual(
        @as(u64, 1_098_116),
        leaf.fixed_wire_bytes.?.candidate,
    );

    const binary = forward_comparisons.active()[1];
    try std.testing.expectEqual(
        frontier.ObservationSourceV1.binary_outer,
        binary.source,
    );
    try std.testing.expect(binary.fixed_wire_bytes == null);
    try std.testing.expectEqual(
        frontier.VerifierWorkUnitV1.air_constraints,
        binary.work_unit,
    );
    try std.testing.expectEqual(
        frontier.ParetoRelationV1.tradeoff,
        binary.pareto_relation,
    );

    try std.testing.expect(!frontier.PROTOCOL_ACTIVATION);
    try std.testing.expect(!frontier.FROZEN_V1_MUTATED);
    try std.testing.expectEqual(
        @as(usize, 0),
        frontier.HEAP_ALLOCATIONS_PER_INGEST,
    );
    try std.testing.expect(frontier.OBSERVATION_SET_STATIC_BYTES <= 64 * 1024);
    try std.testing.expect(frontier.COMPARISON_SET_STATIC_BYTES <= 64 * 1024);
}

test "A1 receipt ingestion is mutation and coverage fail atomic" {
    const baseline = try fixtureObservation(.{
        .source = .native_leaf,
        .log_blowup_factor = 1,
        .canonical_proof_bytes = 1_000,
        .fixed_wire_bytes = 2_000,
        .work_unit = .compiled_graph_nodes,
        .work_units = 10_000,
        .native_verify_ns = 30_000,
        .extra_provider_calls = 7,
        .receipt_label = "mutation/baseline",
    });
    const candidate = try fixtureObservation(.{
        .source = .native_leaf,
        .log_blowup_factor = 2,
        .canonical_proof_bytes = 700,
        .fixed_wire_bytes = 1_200,
        .work_unit = .compiled_graph_nodes,
        .work_units = 6_000,
        .native_verify_ns = 50_000,
        .extra_provider_calls = 7,
        .receipt_label = "mutation/candidate",
    });

    var measurements = frontier.ObservationSetV1.init();
    try measurements.ingest(baseline);
    const before = try measurements.identityDigest();

    var mutated = candidate;
    mutated.canonical_proof_bytes -= 1;
    try std.testing.expectError(
        error.InvalidObservation,
        measurements.ingest(mutated),
    );
    try std.testing.expectEqual(before, try measurements.identityDigest());
    try std.testing.expectError(
        error.DuplicateObservation,
        measurements.ingest(baseline),
    );
    try std.testing.expectEqual(before, try measurements.identityDigest());

    mutated = candidate;
    mutated.tree_paths.path_depths[0] += 1;
    try std.testing.expectError(
        error.InvalidPathDimensions,
        mutated.validate(),
    );
    mutated = candidate;
    mutated.observation_id[0] ^= 1;
    try std.testing.expectError(error.InvalidObservation, mutated.validate());

    var empty_receipt_input = try fixtureInput(.{
        .source = .native_leaf,
        .log_blowup_factor = 2,
        .canonical_proof_bytes = 700,
        .fixed_wire_bytes = 1_200,
        .work_unit = .compiled_graph_nodes,
        .work_units = 6_000,
        .native_verify_ns = 50_000,
        .extra_provider_calls = 7,
        .receipt_label = "will-be-cleared",
    });
    empty_receipt_input.receipt_sha256 = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.EmptyReceiptIdentity,
        frontier.ObservationV1.seal(empty_receipt_input),
    );
    var wrong_work_unit = empty_receipt_input;
    wrong_work_unit.receipt_sha256 = receiptDigest("wrong-work-unit");
    wrong_work_unit.verifier_work.unit = .air_constraints;
    try std.testing.expectError(
        error.InvalidVerifierWork,
        frontier.ObservationV1.seal(wrong_work_unit),
    );

    var missing_baseline = frontier.ObservationSetV1.init();
    try missing_baseline.ingest(candidate);
    try std.testing.expectError(
        error.MissingFrozenV1Baseline,
        missing_baseline.comparisons(),
    );

    const candidate_without_wire = try fixtureObservation(.{
        .source = .native_leaf,
        .log_blowup_factor = 2,
        .canonical_proof_bytes = 700,
        .fixed_wire_bytes = null,
        .work_unit = .compiled_graph_nodes,
        .work_units = 6_000,
        .native_verify_ns = 50_000,
        .extra_provider_calls = 7,
        .receipt_label = "mutation/no-wire",
    });
    try std.testing.expectError(
        error.CoverageMismatch,
        frontier.ComparisonV1.init(&baseline, &candidate_without_wire),
    );

    try measurements.ingest(candidate);
    var comparisons = try measurements.comparisons();
    var comparison_mutation = comparisons.active()[0];
    comparison_mutation.canonical_proof_bytes.magnitude += 1;
    try std.testing.expectError(
        error.InvalidComparison,
        comparison_mutation.validate(),
    );
    comparisons.comparisons[0].comparison_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidComparison,
        comparisons.validate(),
    );
}

test "A1 path arithmetic rejects overflow before observation publication" {
    const maximum_depths = [_]u32{std.math.maxInt(u32)} **
        frontier.MAX_OBSERVED_TREES;
    try std.testing.expectError(
        error.ArithmeticOverflow,
        frontier.TreePathDimensionsV1.init(
            std.math.maxInt(u32),
            &maximum_depths,
        ),
    );

    const maximum_layer = frontier.FriLayerDimensionsV1{
        .fold_width = @as(u32, 1) << 31,
        .authentication_path_depth = std.math.maxInt(u32),
    };
    const maximum_layers = [_]frontier.FriLayerDimensionsV1{maximum_layer} **
        frontier.MAX_OBSERVED_FRI_LAYERS;
    try std.testing.expectError(
        error.ArithmeticOverflow,
        frontier.FriPathDimensionsV1.init(
            std.math.maxInt(u32),
            &maximum_layers,
            1,
        ),
    );
}

const FixtureOptions = struct {
    source: frontier.ObservationSourceV1,
    log_blowup_factor: u32,
    canonical_proof_bytes: u64,
    fixed_wire_bytes: ?u64,
    work_unit: frontier.VerifierWorkUnitV1,
    work_units: u64,
    native_verify_ns: u64,
    extra_provider_calls: u64,
    receipt_label: []const u8,
};

fn fixtureObservation(options: FixtureOptions) !frontier.ObservationV1 {
    return frontier.ObservationV1.seal(try fixtureInput(options));
}

fn fixtureInput(options: FixtureOptions) !frontier.ObservationInputV1 {
    const profile = try frontier.MeasuredProfileV1.initV1Candidate(
        COLUMN_LOG_DEGREE,
        options.log_blowup_factor,
    );
    const trace_depth = try std.math.add(
        u32,
        COLUMN_LOG_DEGREE,
        options.log_blowup_factor,
    );
    const tree_depths = [_]u32{trace_depth} ** protocol.COMMITMENT_TREE_COUNT;
    const tree_paths = try frontier.TreePathDimensionsV1.init(
        profile.candidate.n_queries,
        &tree_depths,
    );

    var config = protocol.PCS_CONFIG.fri_config;
    config.log_blowup_factor = options.log_blowup_factor;
    config.n_queries = profile.candidate.n_queries;
    const schedule = try fixed_profile.FriSchedule.init(
        COLUMN_LOG_DEGREE,
        config,
    );
    var layers: [fixed_profile.MAX_FRI_ROUNDS]frontier.FriLayerDimensionsV1 =
        undefined;
    for (schedule.active(), layers[0..schedule.count]) |round, *layer| {
        layer.* = .{
            .fold_width = round.fold_width,
            .authentication_path_depth = round.authentication_path_depth,
        };
    }
    const fri_paths = try frontier.FriPathDimensionsV1.init(
        profile.candidate.n_queries,
        layers[0..schedule.count],
        profile.candidate.terminal_domain_values,
    );
    const path_provider_calls = try std.math.add(
        u64,
        tree_paths.authentication_digest_count,
        fri_paths.authentication_digest_count,
    );
    const provider_calls = try std.math.add(
        u64,
        path_provider_calls,
        options.extra_provider_calls,
    );
    const receipt_sha256 = receiptDigest(options.receipt_label);
    return .{
        .source = options.source,
        .profile = profile,
        .canonical_proof_bytes = options.canonical_proof_bytes,
        .fixed_wire_bytes = options.fixed_wire_bytes,
        .tree_paths = tree_paths,
        .fri_paths = fri_paths,
        .verifier_work = .{
            .unit = options.work_unit,
            .exact_units = options.work_units,
            .native_verify_ns = options.native_verify_ns,
        },
        .poseidon2_provider_calls = provider_calls,
        .receipt_sha256 = receipt_sha256,
    };
}

fn receiptDigest(label: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &result, .{});
    return result;
}

fn expectObservationSlicesEqual(
    expected: []const frontier.ObservationV1,
    actual: []const frontier.ObservationV1,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right|
        try std.testing.expectEqualDeep(left, right);
}

fn expectComparisonSlicesEqual(
    expected: []const frontier.ComparisonV1,
    actual: []const frontier.ComparisonV1,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right|
        try std.testing.expectEqualDeep(left, right);
}
