const std = @import("std");

const artifact = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const stage_mod = @import("recursive_node_stage_adapter_v1.zig");

test "recursive node canonical codec and ordered children" {
    const geometries = try fixtureGeometries();
    const registry = try fixtureRegistry(&geometries);
    const left = try fixtureArtifact(
        try artifact.TaskCoordinateV1.init(0, 0),
        &registry,
        &geometries[0],
        .{ fixtureRef(1), artifact.ArtifactRefV1.zero() },
    );
    const right = try fixtureArtifact(
        try artifact.TaskCoordinateV1.init(0, 1),
        &registry,
        &geometries[0],
        .{ fixtureRef(2), artifact.ArtifactRefV1.zero() },
    );
    const parent = try fixtureArtifact(
        try artifact.TaskCoordinateV1.init(1, 0),
        &registry,
        &geometries[2],
        .{ try left.artifactRef(), try right.artifactRef() },
    );
    try parent.validateAgainstChildren(&left, &right);
    const encoded = try parent.encodeCanonical();
    const decoded = try artifact.RecursiveNodeArtifactV1.decodeCanonical(
        &encoded,
    );
    try std.testing.expectEqualDeep(parent, decoded);

    var reversed = parent;
    std.mem.swap(
        artifact.ArtifactRefV1,
        &reversed.ordered_children[0],
        &reversed.ordered_children[1],
    );
    reversed = try artifact.RecursiveNodeArtifactV1.seal(reversed);
    try std.testing.expectError(
        error.InvalidChildOrder,
        reversed.validateAgainstChildren(&left, &right),
    );
}

test "coordinate kind height and empty relabel mutations fail closed" {
    const geometries = try fixtureGeometries();
    const registry = try fixtureRegistry(&geometries);
    const empty = try fixtureArtifact(
        try artifact.TaskCoordinateV1.init(0, 210),
        &registry,
        &geometries[1],
        .{ fixtureRef(3), artifact.ArtifactRefV1.zero() },
    );
    try std.testing.expectEqual(artifact.NodeKindV1.empty, empty.node_kind);

    var relabeled = empty;
    relabeled.node_kind = .real;
    try std.testing.expectError(
        error.InvalidNodeKind,
        artifact.RecursiveNodeArtifactV1.seal(relabeled),
    );

    var wrong_height = empty;
    wrong_height.coordinate = try artifact.TaskCoordinateV1.init(1, 105);
    wrong_height.node_kind = try artifact.expectedNodeKind(
        wrong_height.coordinate,
    );
    try std.testing.expectError(
        error.InvalidStage,
        artifact.RecursiveNodeArtifactV1.seal(wrong_height),
    );

    var wrong_ordinal = empty;
    wrong_ordinal.coordinate.global_ordinal += 1;
    try std.testing.expectError(
        error.InvalidTaskCoordinate,
        artifact.RecursiveNodeArtifactV1.seal(wrong_ordinal),
    );
}

test "registry rejects circuit profile PCS and layout substitutions" {
    const geometries = try fixtureGeometries();
    const registry = try fixtureRegistry(&geometries);
    const base = try fixtureArtifact(
        try artifact.TaskCoordinateV1.init(0, 7),
        &registry,
        &geometries[0],
        .{ fixtureRef(4), artifact.ArtifactRefV1.zero() },
    );
    try registry.admit(&base, &geometries[0]);

    inline for (.{
        "circuit_identity_sha256",
        "profile_identity_sha256",
        "pcs_identity_sha256",
        "padding_layout_identity_sha256",
    }) |field_name| {
        var mutation = base;
        @field(mutation, field_name) = fixtureId(240);
        mutation = try artifact.RecursiveNodeArtifactV1.seal(mutation);
        try std.testing.expectError(
            error.RegistryArtifactMismatch,
            registry.admit(&mutation, &geometries[0]),
        );
    }

    var root_mutation = base;
    root_mutation.preprocessed_root[0] ^= 1;
    root_mutation = try artifact.RecursiveNodeArtifactV1.seal(root_mutation);
    try std.testing.expectError(
        error.RegistryArtifactMismatch,
        registry.admit(&root_mutation, &geometries[0]),
    );

    // The production common fold uses the exact universal 36-row manifest,
    // whose authenticated preprocessing tree contains 570 columns.  The
    // registry schema must represent that geometry without truncation while
    // still rejecting values beyond its fixed wire capacity.
    try std.testing.expectEqual(@as(u16, 4), registry_mod.SCHEMA_VERSION);
    try std.testing.expectEqual(
        @as(usize, 1024),
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT,
    );
    var universal_geometry = geometries[0];
    universal_geometry.preprocessed_column_count = 570;
    @memset(universal_geometry.preprocessed_column_log_sizes[0..570], 9);
    @memset(universal_geometry.preprocessed_column_log_sizes[570..], 0);
    universal_geometry.proof_shape.tree_column_counts[0] = 570;
    @memset(
        universal_geometry.proof_shape.tree_column_log_sizes[0][0..570],
        10,
    );
    @memset(
        universal_geometry.proof_shape.tree_column_log_sizes[0][570..],
        0,
    );
    @memset(
        universal_geometry.proof_shape.tree_column_sample_counts[0][0..570],
        1,
    );
    universal_geometry.proof_shape.tree_column_sample_counts[0][0] = 3;
    universal_geometry.proof_shape.sampled_value_count = 585;
    universal_geometry.proof_shape.queried_value_count =
        (570 + 5 + 6 + 2) * 193;
    universal_geometry.proof_shape.table_layout_identity_sha256 =
        fixtureId(242);
    universal_geometry.proof_shape = try registry_mod.FixedProofShapeV3.seal(
        universal_geometry.proof_shape,
    );
    universal_geometry = try registry_mod.AuthenticatedGeometryV1.seal(
        universal_geometry,
    );
    try universal_geometry.validate();

    var overflow = universal_geometry;
    overflow.preprocessed_column_count = 1025;
    try std.testing.expectError(
        error.InvalidCircuitGeometry,
        registry_mod.AuthenticatedGeometryV1.seal(overflow),
    );
}

test "padding parity computes target and rejects every drift class" {
    var geometries = try fixtureGeometries();
    var registry = try fixtureRegistry(&geometries);
    const parity = try registry_mod.PaddingParityV1.derive(
        &registry,
        geometries,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 8, 8, 8 },
        parity.target_component_log_sizes[0..3],
    );

    var forged_geometries = geometries;
    forged_geometries[1].circuit_identity_sha256 = fixtureId(239);
    forged_geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        forged_geometries[1],
    );
    var forged_parity = parity;
    forged_parity.geometry_authority_identities[1] =
        forged_geometries[1].authority_identity_sha256;
    forged_parity = registry_mod.testing.resealParity(forged_parity);
    try std.testing.expectError(
        error.CircuitNotRegistered,
        forged_parity.validate(&registry, &forged_geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].active_component_log_sizes[0] = 9;
    geometries[1].padded_component_log_sizes[0] = 9;
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.PaddingComponentTargetMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].component_count = 2;
    geometries[1].active_component_log_sizes[2] = 0;
    geometries[1].padded_component_log_sizes[2] = 0;
    geometries[1].proof_shape.claimed_sum_count = 2;
    geometries[1].proof_shape = try registry_mod.FixedProofShapeV3.seal(
        geometries[1].proof_shape,
    );
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.PaddingComponentCountMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].preprocessed_column_log_sizes[0] -= 1;
    geometries[1].proof_shape.tree_column_log_sizes[0][0] -= 1;
    geometries[1].proof_shape.maximum_merkle_depth = 9;
    geometries[1].proof_shape.trace_sibling_count = 36 * 193;
    geometries[1].proof_shape = try registry_mod.FixedProofShapeV3.seal(
        geometries[1].proof_shape,
    );
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.PreprocessedColumnLayoutMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].trace_log_size += 1;
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.TraceLogSizeMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].pcs.fri_query_count += 1;
    geometries[1].pcs = try registry_mod.PcsConfigV1.seal(
        geometries[1].pcs,
    );
    geometries[1].proof_shape.query_count += 1;
    geometries[1].proof_shape.queried_value_count =
        17 * geometries[1].proof_shape.query_count;
    geometries[1].proof_shape.trace_path_count =
        4 * geometries[1].proof_shape.query_count;
    geometries[1].proof_shape.trace_sibling_count =
        37 * geometries[1].proof_shape.query_count;
    geometries[1].proof_shape.fri_value_count =
        32 * geometries[1].proof_shape.query_count;
    geometries[1].proof_shape.fri_sibling_count =
        14 * geometries[1].proof_shape.query_count;
    geometries[1].proof_shape = try registry_mod.FixedProofShapeV3.seal(
        geometries[1].proof_shape,
    );
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.PcsConfigMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].padding_layout_identity_sha256 = fixtureId(241);
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.PaddingLayoutMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].proof_shape.tree_column_log_sizes[1][0] -= 1;
    geometries[1].proof_shape.trace_sibling_count = 36 * 193;
    geometries[1].proof_shape = try registry_mod.FixedProofShapeV3.seal(
        geometries[1].proof_shape,
    );
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.FixedProofWireShapeMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );

    geometries = try fixtureGeometries();
    geometries[1].proof_shape.sampled_value_count += 1;
    geometries[1].proof_shape.tree_column_sample_counts[0][0] += 1;
    geometries[1].proof_shape = try registry_mod.FixedProofShapeV3.seal(
        geometries[1].proof_shape,
    );
    geometries[1] = try registry_mod.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    registry = try fixtureRegistry(&geometries);
    try std.testing.expectError(
        error.FixedProofWireShapeMismatch,
        registry_mod.PaddingParityV1.derive(&registry, geometries),
    );
}

test "mock 256-node fold has canonical order and one-leaf ancestor path" {
    var plan = try stage_mod.MockHomogeneousFoldPlanV1.init();
    try plan.validate();
    try std.testing.expectEqual(@as(usize, 255), plan.tasks.len);
    const path = try plan.ancestorPath(17);
    const expected_indices = [_]u32{ 8, 4, 2, 1, 0, 0, 0, 0 };
    for (path, expected_indices, 1..) |coordinate, index, height| {
        try std.testing.expectEqual(@as(u8, @intCast(height)), coordinate.height);
        try std.testing.expectEqual(index, coordinate.index);
    }
    try std.testing.expectEqual(@as(u32, 510), path[7].global_ordinal);

    std.mem.swap(
        artifact.TaskCoordinateV1,
        &plan.tasks[0].left,
        &plan.tasks[0].right,
    );
    try std.testing.expectError(error.InvalidMockFoldPlan, plan.validate());
}

test "parent StageAdapter releases both leases after sealing" {
    const geometries = try fixtureGeometries();
    const registry = try fixtureRegistry(&geometries);
    const child_refs = [2]artifact.ArtifactRefV1{
        fixtureRef(71),
        fixtureRef(72),
    };
    const parent = try fixtureArtifact(
        try artifact.TaskCoordinateV1.init(1, 0),
        &registry,
        &geometries[2],
        child_refs,
    );
    var counters = MockAdapter.Counters{};
    const authorities = MockAdapter.Authorities{ .counters = &counters };
    var context = MockAdapter.BuildContext{ .artifact = parent };
    const expected = MockAdapter.ExpectedTask{
        .coordinate = parent.coordinate,
    };
    const Runner = stage_mod.FoldStageAdapter(MockAdapter);
    const sealed = try Runner.completeParent(
        &authorities,
        &context,
        child_refs,
        &expected,
    );
    try sealed.validate();
    try std.testing.expectEqual(@as(u8, 2), counters.opened);
    try std.testing.expectEqual(@as(u8, 2), counters.leases_deinitialized);
    try std.testing.expectEqual(@as(u8, 1), counters.owned_deinitialized);

    counters = .{};
    context = .{ .artifact = parent };
    var left = MockAdapter.Lease{
        .counters = &counters,
        .ref = child_refs[0],
    };
    var right = MockAdapter.Lease{
        .counters = &counters,
        .ref = child_refs[1],
    };
    _ = try Runner.completeParentFromLeases(
        &context,
        &left,
        &right,
        &expected,
    );
    try std.testing.expectEqual(@as(u8, 0), counters.opened);
    try std.testing.expectEqual(@as(u8, 2), counters.leases_deinitialized);
    try std.testing.expectEqual(@as(u8, 1), counters.owned_deinitialized);
}

test "parent StageAdapter releases acquired leases on error paths" {
    const geometries = try fixtureGeometries();
    const registry = try fixtureRegistry(&geometries);
    const child_refs = [2]artifact.ArtifactRefV1{
        fixtureRef(73),
        fixtureRef(74),
    };
    const parent = try fixtureArtifact(
        try artifact.TaskCoordinateV1.init(1, 0),
        &registry,
        &geometries[2],
        child_refs,
    );
    const Runner = stage_mod.FoldStageAdapter(MockAdapter);
    const expected = MockAdapter.ExpectedTask{
        .coordinate = parent.coordinate,
    };

    var counters = MockAdapter.Counters{
        .fail_fresh_kind = child_refs[1].kind,
    };
    var context = MockAdapter.BuildContext{ .artifact = parent };
    var left = MockAdapter.Lease{
        .counters = &counters,
        .ref = child_refs[0],
    };
    var right = MockAdapter.Lease{
        .counters = &counters,
        .ref = child_refs[1],
    };
    try std.testing.expectError(
        error.MockFreshFailure,
        Runner.completeParentFromLeases(
            &context,
            &left,
            &right,
            &expected,
        ),
    );
    try std.testing.expectEqual(@as(u8, 2), counters.leases_deinitialized);
    try std.testing.expectEqual(@as(u8, 0), counters.owned_deinitialized);

    counters = .{ .fail_open_kind = child_refs[1].kind };
    context = .{ .artifact = parent };
    const authorities = MockAdapter.Authorities{ .counters = &counters };
    try std.testing.expectError(
        error.MockOpenFailure,
        Runner.completeParent(
            &authorities,
            &context,
            child_refs,
            &expected,
        ),
    );
    try std.testing.expectEqual(@as(u8, 1), counters.opened);
    try std.testing.expectEqual(@as(u8, 1), counters.leases_deinitialized);
}

test "fixed proof shape is minted from complete expanded cold capture" {
    var raw_queries = [_]usize{0} ** 193;
    var deep_answers = [_]u8{0} ** 193;
    var sampled_values = [_]u8{0} ** 19;
    var queried_values = [_]u8{0} ** (17 * 193);
    var last_layer = [_]u8{0};
    var one_point = [_]u8{0};
    var three_points = [_]u8{ 0, 0, 0 };
    const tree0_samples = [_][]const u8{
        &three_points,
        &one_point,
        &one_point,
        &one_point,
    };
    const tree1_samples = [_][]const u8{&one_point} ** 5;
    const tree2_samples = [_][]const u8{&one_point} ** 6;
    const tree3_samples = [_][]const u8{&one_point} ** 2;
    const sampled_points = [_][]const []const u8{
        &tree0_samples,
        &tree1_samples,
        &tree2_samples,
        &tree3_samples,
    };
    const tree0_logs = [_]u32{ 10, 9, 9, 8 };
    const tree1_logs = [_]u32{ 9, 8, 8, 7, 7 };
    const tree2_logs = [_]u32{ 9, 9, 8, 8, 7, 7 };
    const tree3_logs = [_]u32{ 9, 9 };
    const column_logs = [_][]const u32{
        &tree0_logs,
        &tree1_logs,
        &tree2_logs,
        &tree3_logs,
    };
    var tree0_siblings = [_]u8{0} ** (10 * 193);
    var tree1_siblings = [_]u8{0} ** (9 * 193);
    var tree2_siblings = [_]u8{0} ** (9 * 193);
    var tree3_siblings = [_]u8{0} ** (9 * 193);
    const paths = [_]ShapePath{
        .{ .positions = &raw_queries, .path_depth = 10, .siblings = &tree0_siblings },
        .{ .positions = &raw_queries, .path_depth = 9, .siblings = &tree1_siblings },
        .{ .positions = &raw_queries, .path_depth = 9, .siblings = &tree2_siblings },
        .{ .positions = &raw_queries, .path_depth = 9, .siblings = &tree3_siblings },
    };
    var fri0_values = [_]u8{0} ** (16 * 193);
    var fri1_values = [_]u8{0} ** (16 * 193);
    var fri0_siblings = [_]u8{0} ** (9 * 193);
    var fri1_siblings = [_]u8{0} ** (5 * 193);
    var layers = [_]ShapeLayer{
        .{
            .fold_width = 16,
            .path_depth = 9,
            .query_count = 193,
            .positions = &raw_queries,
            .values = &fri0_values,
            .siblings = &fri0_siblings,
        },
        .{
            .fold_width = 16,
            .path_depth = 5,
            .query_count = 193,
            .positions = &raw_queries,
            .values = &fri1_values,
            .siblings = &fri1_siblings,
        },
    };
    const commitments = [_]u8{ 1, 2, 3, 4 };
    var capture = ShapeCapture{
        .commitments = &commitments,
        .column_log_sizes = &column_logs,
        .sampled_points = &sampled_points,
        .sampled_values = &sampled_values,
        .queried_values = &queried_values,
        .deep_answers = &deep_answers,
        .trace_paths = &paths,
        .queries = .{ .raw = &raw_queries },
        .fri = .{ .layers = &layers },
        .last_layer_coefficients = &last_layer,
    };
    const derived = try registry_mod.sealProofShapeFromCapture(
        &capture,
        3,
        8,
        fixtureId(41),
    );
    try std.testing.expectEqual(
        try fixtureProofShape(.{ 9, 8, 8, 7 }),
        derived,
    );

    layers[0].values = layers[0].values[0 .. layers[0].values.len - 1];
    capture.fri.layers = &layers;
    try std.testing.expectError(
        error.InvalidFixedProofShape,
        registry_mod.sealProofShapeFromCapture(
            &capture,
            3,
            8,
            fixtureId(41),
        ),
    );
}

test "current concrete shapes remain explicitly unadmitted" {
    const diagnostic = registry_mod.currentShapeDiagnostic();
    try std.testing.expectEqual(@as(u16, 36), diagnostic.universal_component_count);
    try std.testing.expect(
        !diagnostic.ethereum_incremental_leaf_wrapper_geometry_authenticated,
    );
    try std.testing.expect(
        !diagnostic.canonical_empty_field_geometry_authenticated,
    );
    try std.testing.expect(
        !diagnostic.common_fold_field_geometry_authenticated,
    );
    try std.testing.expect(!diagnostic.parity_authority_available);
    try std.testing.expectEqual(
        registry_mod.GapV1.missing_ethereum_incremental_leaf_wrapper_geometry,
        diagnostic.first_gap,
    );
}

const ShapePath = struct {
    positions: []const usize,
    path_depth: u32,
    siblings: []const u8,
};

const ShapeLayer = struct {
    fold_width: u32,
    path_depth: u32,
    query_count: usize,
    positions: []const usize,
    values: []const u8,
    siblings: []const u8,
};

const ShapeCapture = struct {
    commitments: []const u8,
    column_log_sizes: []const []const u32,
    sampled_points: []const []const []const u8,
    sampled_values: []const u8,
    queried_values: []const u8,
    deep_answers: []const u8,
    trace_paths: []const ShapePath,
    queries: struct { raw: []const usize },
    fri: struct { layers: []const ShapeLayer },
    last_layer_coefficients: []const u8,
};

const MockAdapter = struct {
    pub const stage_kind = artifact.StageKindV1.fold;

    pub const Counters = struct {
        opened: u8 = 0,
        leases_deinitialized: u8 = 0,
        owned_deinitialized: u8 = 0,
        fail_open_kind: ?u32 = null,
        fail_fresh_kind: ?u32 = null,
    };

    pub const Authorities = struct { counters: *Counters };
    pub const BuildContext = struct {
        artifact: artifact.RecursiveNodeArtifactV1,
    };
    pub const ExpectedTask = struct {
        coordinate: artifact.TaskCoordinateV1,
    };
    pub const Lease = struct {
        counters: *Counters,
        ref: artifact.ArtifactRefV1,

        pub fn deinit(self: *Lease) void {
            self.counters.leases_deinitialized += 1;
        }
    };
    pub const OwnedArtifact = struct {
        counters: *Counters,
        artifact_value: artifact.RecursiveNodeArtifactV1,

        pub fn deinit(self: *OwnedArtifact) void {
            self.counters.owned_deinitialized += 1;
        }
    };

    pub fn coldOpen(
        authorities: *const Authorities,
        ref: artifact.ArtifactRefV1,
    ) !Lease {
        try ref.validate();
        if (authorities.counters.fail_open_kind == ref.kind)
            return error.MockOpenFailure;
        authorities.counters.opened += 1;
        return .{ .counters = authorities.counters, .ref = ref };
    }

    pub fn reference(lease: *Lease) !artifact.ArtifactRefV1 {
        try lease.ref.validate();
        return lease.ref;
    }

    pub fn describe(
        expected: *const ExpectedTask,
    ) !stage_mod.StageDescriptionV1 {
        return .{
            .stage_kind = stage_kind,
            .coordinate = expected.coordinate,
            .input_count = 2,
        };
    }

    pub fn deriveSemanticInputs(
        context: *const BuildContext,
        child_refs: [2]artifact.ArtifactRefV1,
        expected: *const ExpectedTask,
    ) !artifact.SemanticInputsV1 {
        if (!std.meta.eql(context.artifact.coordinate, expected.coordinate) or
            !std.meta.eql(context.artifact.ordered_children, child_refs))
        {
            return error.InvalidChildOrder;
        }
        return context.artifact.semanticInputs();
    }

    pub fn validateFresh(
        lease: *Lease,
        _: *const ExpectedTask,
    ) !void {
        if (lease.counters.fail_fresh_kind == lease.ref.kind)
            return error.MockFreshFailure;
    }

    pub fn buildParent(
        context: *BuildContext,
        left: *Lease,
        right: *Lease,
        _: *const ExpectedTask,
    ) !OwnedArtifact {
        var value = context.artifact;
        value.ordered_children = .{ left.ref, right.ref };
        value = try artifact.RecursiveNodeArtifactV1.seal(value);
        return .{
            .counters = left.counters,
            .artifact_value = value,
        };
    }

    pub fn seal(
        owned: *OwnedArtifact,
    ) !artifact.RecursiveNodeArtifactV1 {
        return owned.artifact_value;
    }
};

fn fixtureGeometries() ![registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1 {
    const active = [registry_mod.ROLE_COUNT][3]u8{
        .{ 7, 8, 6 },
        .{ 5, 7, 8 },
        .{ 8, 6, 7 },
    };
    var result: [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1 = undefined;
    for (&result, 0..) |*geometry, ordinal| {
        var active_logs = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
        var padded_logs = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
        var preprocessed_logs = [_]u8{0} **
            registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
        @memcpy(active_logs[0..3], &active[ordinal]);
        const padded_source = [3]u8{ 8, 8, 8 };
        const preprocessed_source = [4]u8{ 9, 8, 8, 7 };
        @memcpy(padded_logs[0..3], &padded_source);
        @memcpy(preprocessed_logs[0..4], &preprocessed_source);
        const proof_shape = try fixtureProofShape(preprocessed_source);
        geometry.* = try registry_mod.AuthenticatedGeometryV1.seal(.{
            .role = @enumFromInt(ordinal),
            .authenticated_padding = true,
            .component_count = 3,
            .preprocessed_column_count = 4,
            .trace_log_size = 9,
            .active_component_log_sizes = active_logs,
            .padded_component_log_sizes = padded_logs,
            .preprocessed_column_log_sizes = preprocessed_logs,
            .circuit_identity_sha256 = fixtureId(@intCast(10 + ordinal)),
            .program_identity_sha256 = fixtureId(@intCast(20 + ordinal)),
            .profile_identity_sha256 = fixtureId(@intCast(30 + ordinal)),
            .padding_layout_identity_sha256 = fixtureId(40),
            .preprocessed_root = fixtureDigest(@intCast(45 + ordinal)),
            .pcs = registry_mod.PcsConfigV1.secureTemporalParent(),
            .output_abi = registry_mod.OutputAbiV1.nodePublic(),
            .proof_shape = proof_shape,
            .authority_identity_sha256 = undefined,
        });
    }
    return result;
}

fn fixtureProofShape(
    preprocessed_logs: [4]u8,
) !registry_mod.FixedProofShapeV3 {
    var tree_logs = [_][registry_mod.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry_mod.MAX_TREE_COLUMN_COUNT,
    } ** registry_mod.FIXED_PROOF_TREE_COUNT;
    for (preprocessed_logs, 0..) |base_log, index|
        tree_logs[0][index] = base_log + 1;
    const main_logs = [5]u8{ 9, 8, 8, 7, 7 };
    const interaction_logs = [6]u8{ 9, 9, 8, 8, 7, 7 };
    const composition_logs = [2]u8{ 9, 9 };
    @memcpy(tree_logs[1][0..5], &main_logs);
    @memcpy(tree_logs[2][0..6], &interaction_logs);
    @memcpy(tree_logs[3][0..2], &composition_logs);
    var sample_counts = [_][registry_mod.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry_mod.MAX_TREE_COLUMN_COUNT,
    } ** registry_mod.FIXED_PROOF_TREE_COUNT;
    @memset(sample_counts[0][0..4], 1);
    @memset(sample_counts[1][0..5], 1);
    @memset(sample_counts[2][0..6], 1);
    @memset(sample_counts[3][0..2], 1);
    sample_counts[0][0] = 3;
    var fri_fold_widths = [_]u8{0} **
        registry_mod.MAX_FRI_LAYER_COUNT;
    var fri_path_depths = [_]u8{0} **
        registry_mod.MAX_FRI_LAYER_COUNT;
    fri_fold_widths[0] = 16;
    fri_fold_widths[1] = 16;
    fri_path_depths[0] = 9;
    fri_path_depths[1] = 5;
    return registry_mod.FixedProofShapeV3.seal(.{
        .maximum_merkle_depth = 10,
        .claimed_sum_count = 3,
        .fri_layer_count = 2,
        .query_count = 193,
        .maximum_fold_width = 16,
        .column_log_degree = 8,
        .sampled_value_count = 19,
        .queried_value_count = 17 * 193,
        .trace_path_count = 4 * 193,
        .trace_sibling_count = 37 * 193,
        .fri_value_count = 32 * 193,
        .fri_sibling_count = 14 * 193,
        .last_layer_coefficient_count = 1,
        .tree_column_counts = .{ 4, 5, 6, 2 },
        .tree_column_log_sizes = tree_logs,
        .tree_column_sample_counts = sample_counts,
        .fri_layer_fold_widths = fri_fold_widths,
        .fri_layer_path_depths = fri_path_depths,
        .table_layout_identity_sha256 = fixtureId(41),
        .identity_sha256 = undefined,
    });
}

fn fixtureRegistry(
    geometries: *const [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1,
) !registry_mod.RecursiveCircuitRegistryV1 {
    var entries: [registry_mod.ROLE_COUNT]registry_mod.RegistryEntryV1 = undefined;
    for (&entries, geometries) |*entry, *geometry|
        entry.* = try registry_mod.RegistryEntryV1.fromGeometry(geometry);
    return registry_mod.RecursiveCircuitRegistryV1.seal(entries);
}

fn fixtureArtifact(
    coordinate: artifact.TaskCoordinateV1,
    registry: *const registry_mod.RecursiveCircuitRegistryV1,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    children: [2]artifact.ArtifactRefV1,
) !artifact.RecursiveNodeArtifactV1 {
    const stage_kind: artifact.StageKindV1 = if (coordinate.height == 0)
        .leaf_wrapper
    else if (coordinate.height == artifact.ROOT_HEIGHT)
        .root
    else
        .fold;
    const public = try fixtureNodePublic(coordinate.global_ordinal + 1);
    return artifact.RecursiveNodeArtifactV1.seal(.{
        .stage_kind = stage_kind,
        .node_kind = try artifact.expectedNodeKind(coordinate),
        .child_count = if (coordinate.height == 0) 1 else 2,
        .coordinate = coordinate,
        .node_public = public,
        .campaign_namespace_sha256 = fixtureId(50),
        .circuit_identity_sha256 = geometry.circuit_identity_sha256,
        .program_identity_sha256 = geometry.program_identity_sha256,
        .profile_identity_sha256 = geometry.profile_identity_sha256,
        .pcs_identity_sha256 = geometry.pcs.identity_sha256,
        .padding_layout_identity_sha256 = geometry.padding_layout_identity_sha256,
        .registry_identity_sha256 = registry.identity_sha256,
        .node_public_abi_sha256 = artifact.nodePublicAbiIdentity(),
        .statement_identity_sha256 = public.statement_identity_sha256,
        .output_identity_sha256 = public.output_identity_sha256,
        .ordered_children = children,
        .proof_ref = fixtureRef(60),
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
}

fn fixtureNodePublic(seed: u32) !artifact.NodePublicV1 {
    var words = [_]u32{0} ** artifact.STATEMENT_WORD_COUNT;
    words[0] = seed;
    return artifact.NodePublicV1.seal(.{
        .statement_words = words,
        .statement_identity_sha256 = fixtureId(seed + 1),
        .node_authority_sha256 = fixtureId(seed + 2),
        .subtree_sha256 = fixtureId(seed + 3),
        .subtree_digest = fixtureDigest(seed + 4),
        .output_identity_sha256 = undefined,
    });
}

fn fixtureRef(seed: u32) artifact.ArtifactRefV1 {
    return .{
        .kind = @as(u32, 0x1000) + seed,
        .format_version = 1,
        .schema_version = 1,
        .byte_count = @as(u64, 100) + @as(u64, seed),
        .sha256 = fixtureId(seed),
    };
}

fn fixtureId(seed: u32) [32]u8 {
    var result: [32]u8 = undefined;
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, seed, .little);
    for (0..8) |word_index| {
        @memcpy(result[word_index * 4 ..][0..4], &encoded);
    }
    return result;
}

fn fixtureDigest(seed: u32) [artifact.DIGEST_WORD_COUNT]u32 {
    return [_]u32{seed + 1} ** artifact.DIGEST_WORD_COUNT;
}
