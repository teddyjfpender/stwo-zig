const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const subject = integration.recursive_common_wrapper_authority_v2;
const artifact_mod = integration.recursive_node_artifact_v2;
const field_public = integration.recursive_field_node_public_v2;
const registry_mod = integration.recursive_circuit_registry_v1;
const fold_input = integration.recursive_common_fold_input_v2;

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const recursion = frontend.recursion;
const Hasher = recursion.engine.Hasher;
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(Hasher);

const QUERY_COUNT: usize = 193;

test "field wrapper admission requires exact expanded cold proof shape" {
    var capture = CaptureFixture{};
    capture.init();
    const fixture = try Fixture.init(&capture.capture);
    var evidence = MockEvidence{
        .artifact_value = fixture.children[0],
        .geometry_value = fixture.geometries[1],
        .capture_value = &capture.capture,
    };
    const Owned = subject.OwnedFreshWrapperAdmissionV2(MockEvidence);
    var owned = try Owned.initOwned(evidence, fixture.registry);
    defer owned.deinit();
    evidence = undefined;
    try owned.validate();
    try std.testing.expectEqual(
        registry_mod.CircuitRoleV1.canonical_empty_field_v2,
        try owned.view().role(),
    );

    capture.capture.deep_answers = capture.deep_answers[0 .. QUERY_COUNT - 1];
    try std.testing.expectError(
        error.FreshWrapperCaptureMismatch,
        owned.validate(),
    );
}

test "field wrapper derives the ordered parent without SHA semantics" {
    var left_capture = CaptureFixture{};
    left_capture.init();
    var right_capture = CaptureFixture{};
    right_capture.init();
    const fixture = try Fixture.init(&left_capture.capture);
    const left = subject.FreshWrapperViewV2{
        .artifact = &fixture.children[0],
        .geometry = &fixture.geometries[1],
        .capture = &left_capture.capture,
    };
    const right = subject.FreshWrapperViewV2{
        .artifact = &fixture.children[1],
        .geometry = &fixture.geometries[1],
        .capture = &right_capture.capture,
    };
    const coordinate = try artifact_mod.TaskCoordinateV1.init(1, 105);
    const parent = try subject.deriveParentNodePublic(
        left,
        right,
        coordinate,
        &fixture.registry,
    );
    try parent.validateAgainst(left, right, coordinate, &fixture.registry);
    try parent.node_public.validateParentAgainst(
        &fixture.children[0].node_public,
        &fixture.children[1].node_public,
    );
    try std.testing.expectEqual(
        field_public.parentSourceDigest(
            &fixture.children[0].node_public,
            &fixture.children[1].node_public,
        ),
        parent.node_public.source_digest,
    );
    try std.testing.expectError(
        error.ChildCoordinateMismatch,
        subject.deriveParentNodePublic(
            right,
            left,
            coordinate,
            &fixture.registry,
        ),
    );
}

test "field common fold input retains two distinct live leases" {
    var left_capture = CaptureFixture{};
    left_capture.init();
    var right_capture = CaptureFixture{};
    right_capture.init();
    const fixture = try Fixture.init(&left_capture.capture);
    const left = subject.FreshWrapperViewV2{
        .artifact = &fixture.children[0],
        .geometry = &fixture.geometries[1],
        .capture = &left_capture.capture,
    };
    const right = subject.FreshWrapperViewV2{
        .artifact = &fixture.children[1],
        .geometry = &fixture.geometries[1],
        .capture = &right_capture.capture,
    };
    const coordinate = try artifact_mod.TaskCoordinateV1.init(1, 105);
    const input = try fold_input.FreshFoldInputV2.init(
        left,
        right,
        coordinate,
        &fixture.registry,
    );
    try input.validateAgainst(&fixture.registry);
    try input.outputNodePublic().validateParentAgainst(
        &fixture.children[0].node_public,
        &fixture.children[1].node_public,
    );
    try std.testing.expectError(
        error.AliasedCommonFoldChild,
        fold_input.FreshFoldInputV2.init(
            left,
            left,
            coordinate,
            &fixture.registry,
        ),
    );
}

const CaptureFixture = struct {
    commitments: [subject.COMMITMENT_TREE_COUNT]Hasher.Hash = undefined,
    tree0_logs: [2]u32 = .{ 9, 9 },
    tree1_logs: [1]u32 = .{9},
    tree2_logs: [1]u32 = .{9},
    tree3_logs: [1]u32 = .{9},
    column_logs: [subject.COMMITMENT_TREE_COUNT][]u32 = undefined,
    one_point: [1]CirclePointQM31 = undefined,
    three_points: [3]CirclePointQM31 = undefined,
    tree0_sample_columns: [2][]CirclePointQM31 = undefined,
    tree1_sample_columns: [1][]CirclePointQM31 = undefined,
    tree2_sample_columns: [1][]CirclePointQM31 = undefined,
    tree3_sample_columns: [1][]CirclePointQM31 = undefined,
    sampled_points: [subject.COMMITMENT_TREE_COUNT][][]CirclePointQM31 = undefined,
    sampled_values: [7]QM31 = [_]QM31{QM31.zero()} ** 7,
    queried_values: [5 * QUERY_COUNT]M31 = [_]M31{M31.zero()} ** (5 * QUERY_COUNT),
    raw_queries: [QUERY_COUNT]usize = [_]usize{0} ** QUERY_COUNT,
    unique_queries: [1]usize = .{0},
    deep_answers: [QUERY_COUNT]QM31 = [_]QM31{QM31.zero()} ** QUERY_COUNT,
    tree0_siblings: [9 * QUERY_COUNT]Hasher.Hash = undefined,
    tree1_siblings: [9 * QUERY_COUNT]Hasher.Hash = undefined,
    tree2_siblings: [9 * QUERY_COUNT]Hasher.Hash = undefined,
    tree3_siblings: [9 * QUERY_COUNT]Hasher.Hash = undefined,
    trace_paths: [subject.COMMITMENT_TREE_COUNT]MerklePathCapture = undefined,
    fri0_values: [16 * QUERY_COUNT]QM31 = [_]QM31{QM31.zero()} ** (16 * QUERY_COUNT),
    fri1_values: [16 * QUERY_COUNT]QM31 = [_]QM31{QM31.zero()} ** (16 * QUERY_COUNT),
    fri0_siblings: [9 * QUERY_COUNT]Hasher.Hash = undefined,
    fri1_siblings: [5 * QUERY_COUNT]Hasher.Hash = undefined,
    fri_layers: [2]FriLayerCapture = undefined,
    last_layer: [1]QM31 = .{QM31.one()},
    capture: subject.ProofCapture = undefined,

    fn init(self: *CaptureFixture) void {
        self.commitments = std.mem.zeroes(@TypeOf(self.commitments));
        self.one_point = std.mem.zeroes(@TypeOf(self.one_point));
        self.three_points = std.mem.zeroes(@TypeOf(self.three_points));
        self.tree0_siblings = std.mem.zeroes(@TypeOf(self.tree0_siblings));
        self.tree1_siblings = std.mem.zeroes(@TypeOf(self.tree1_siblings));
        self.tree2_siblings = std.mem.zeroes(@TypeOf(self.tree2_siblings));
        self.tree3_siblings = std.mem.zeroes(@TypeOf(self.tree3_siblings));
        self.fri0_siblings = std.mem.zeroes(@TypeOf(self.fri0_siblings));
        self.fri1_siblings = std.mem.zeroes(@TypeOf(self.fri1_siblings));
        self.column_logs = .{
            self.tree0_logs[0..],
            self.tree1_logs[0..],
            self.tree2_logs[0..],
            self.tree3_logs[0..],
        };
        self.tree0_sample_columns = .{
            self.three_points[0..],
            self.one_point[0..],
        };
        self.tree1_sample_columns = .{self.one_point[0..]};
        self.tree2_sample_columns = .{self.one_point[0..]};
        self.tree3_sample_columns = .{self.one_point[0..]};
        self.sampled_points = .{
            self.tree0_sample_columns[0..],
            self.tree1_sample_columns[0..],
            self.tree2_sample_columns[0..],
            self.tree3_sample_columns[0..],
        };
        self.trace_paths = .{
            .{
                .positions = self.raw_queries[0..],
                .path_depth = 9,
                .siblings = self.tree0_siblings[0..],
            },
            .{
                .positions = self.raw_queries[0..],
                .path_depth = 9,
                .siblings = self.tree1_siblings[0..],
            },
            .{
                .positions = self.raw_queries[0..],
                .path_depth = 9,
                .siblings = self.tree2_siblings[0..],
            },
            .{
                .positions = self.raw_queries[0..],
                .path_depth = 9,
                .siblings = self.tree3_siblings[0..],
            },
        };
        self.fri_layers = .{
            .{
                .commitment = std.mem.zeroes(Hasher.Hash),
                .folding_alpha = QM31.one(),
                .fold_step = 4,
                .fold_width = 16,
                .path_depth = 9,
                .query_count = QUERY_COUNT,
                .positions = self.raw_queries[0..],
                .values = self.fri0_values[0..],
                .siblings = self.fri0_siblings[0..],
            },
            .{
                .commitment = std.mem.zeroes(Hasher.Hash),
                .folding_alpha = QM31.one(),
                .fold_step = 4,
                .fold_width = 16,
                .path_depth = 5,
                .query_count = QUERY_COUNT,
                .positions = self.raw_queries[0..],
                .values = self.fri1_values[0..],
                .siblings = self.fri1_siblings[0..],
            },
        };
        self.capture = .{
            .queries = .{
                .raw = self.raw_queries[0..],
                .unique = self.unique_queries[0..],
            },
            .commitments = self.commitments[0..],
            .column_log_sizes = self.column_logs[0..],
            .sampled_points = self.sampled_points[0..],
            .sampled_values = self.sampled_values[0..],
            .queried_values = self.queried_values[0..],
            .deep_answers = self.deep_answers[0..],
            .trace_paths = self.trace_paths[0..],
            .fri = .{ .layers = self.fri_layers[0..] },
            .last_layer_coefficients = self.last_layer[0..],
            .proof_of_work = 0,
            .composition_randomness = QM31.one(),
            .oods_seed = QM31.one(),
            .deep_randomness = QM31.one(),
        };
    }
};

const MockEvidence = struct {
    artifact_value: artifact_mod.RecursiveNodeArtifactV2,
    geometry_value: registry_mod.AuthenticatedGeometryV1,
    capture_value: *const subject.ProofCapture,

    pub fn deinit(_: *MockEvidence) void {}

    pub fn validateFresh(
        self: *const MockEvidence,
        registry: *const subject.Registry,
    ) !void {
        try registry.admitV2(&self.artifact_value, &self.geometry_value);
    }

    pub fn artifact(
        self: *const MockEvidence,
    ) *const artifact_mod.RecursiveNodeArtifactV2 {
        return &self.artifact_value;
    }

    pub fn geometry(
        self: *const MockEvidence,
    ) *const registry_mod.AuthenticatedGeometryV1 {
        return &self.geometry_value;
    }

    pub fn proofCapture(self: *const MockEvidence) *const subject.ProofCapture {
        return self.capture_value;
    }
};

const Fixture = struct {
    geometries: [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1,
    registry: registry_mod.RecursiveCircuitRegistryV1,
    children: [2]artifact_mod.RecursiveNodeArtifactV2,

    fn init(capture: *const subject.ProofCapture) !Fixture {
        var geometries: [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1 = undefined;
        for (&geometries, 0..) |*geometry, ordinal|
            geometry.* = try fixtureGeometry(
                @enumFromInt(ordinal),
                @intCast(ordinal + 1),
                capture,
            );
        var entries: [registry_mod.ROLE_COUNT]registry_mod.RegistryEntryV1 = undefined;
        for (&entries, &geometries) |*entry, *geometry|
            entry.* = try registry_mod.RegistryEntryV1.fromGeometry(geometry);
        const registry = try registry_mod.RecursiveCircuitRegistryV1.seal(entries);
        return .{
            .geometries = geometries,
            .registry = registry,
            .children = .{
                try fixtureArtifact(210, &registry, &geometries[1], 11),
                try fixtureArtifact(211, &registry, &geometries[1], 21),
            },
        };
    }
};

fn fixtureGeometry(
    role: registry_mod.CircuitRoleV1,
    seed: u32,
    capture: *const subject.ProofCapture,
) !registry_mod.AuthenticatedGeometryV1 {
    var active = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    var padded = [_]u8{0} ** registry_mod.MAX_COMPONENT_COUNT;
    @memset(active[0..36], 8);
    @memset(padded[0..36], 8);
    var preprocessed = [_]u8{0} **
        registry_mod.MAX_PREPROCESSED_COLUMN_COUNT;
    @memset(preprocessed[0..2], 8);
    return registry_mod.AuthenticatedGeometryV1.seal(.{
        .role = role,
        .authenticated_padding = true,
        .component_count = 36,
        .preprocessed_column_count = 2,
        .trace_log_size = 8,
        .active_component_log_sizes = active,
        .padded_component_log_sizes = padded,
        .preprocessed_column_log_sizes = preprocessed,
        .circuit_identity_sha256 = sha(seed + 1),
        .program_identity_sha256 = sha(seed + 2),
        .profile_identity_sha256 = sha(seed + 3),
        .padding_layout_identity_sha256 = sha(100),
        .preprocessed_root = digest(seed + 4),
        .pcs = registry_mod.PcsConfigV1.secureTemporalParent(),
        .output_abi = registry_mod.OutputAbiV1.fieldNodePublicV2(),
        .proof_shape = try registry_mod.sealProofShapeFromCapture(
            capture,
            36,
            8,
            sha(101),
        ),
        .authority_identity_sha256 = undefined,
    });
}

fn fixtureArtifact(
    index: u32,
    registry: *const subject.Registry,
    geometry: *const subject.Geometry,
    seed: u32,
) !artifact_mod.RecursiveNodeArtifactV2 {
    const job = try fixtureJob();
    const statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, index);
    const words = try statement.canonicalWords();
    var canonical: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&canonical, words) |*destination, word| destination.* = word.toU32();
    const node_public = try field_public.NodePublicV2.initLeaf(
        try artifact_mod.TaskCoordinateV1.init(0, index),
        canonical,
        recursion.poseidon2_channel.hashBytes("empty-source", seed),
    );
    const entry = try registry.entry(.canonical_empty_field_v2);
    return artifact_mod.RecursiveNodeArtifactV2.seal(.{
        .stage_kind = .leaf_wrapper,
        .node_kind = .empty,
        .child_count = 1,
        .coordinate = node_public.coordinate,
        .node_public = node_public,
        .campaign_namespace_sha256 = sha(200),
        .circuit_identity_sha256 = entry.circuit_identity_sha256,
        .program_identity_sha256 = entry.program_identity_sha256,
        .profile_identity_sha256 = entry.profile_identity_sha256,
        .pcs_identity_sha256 = entry.pcs_identity_sha256,
        .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
        .registry_identity_sha256 = registry.identity_sha256,
        .node_public_abi_sha256 = field_public.abiIdentitySha256(),
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .ordered_children = .{
            fixtureRef(14, 1, seed + 4),
            artifact_mod.ArtifactRefV1.zero(),
        },
        .proof_ref = fixtureRef(8, 1, seed + 5),
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
}

fn fixtureJob() !recursion.span_statement.JobContext {
    const initial = try recursion.span_statement.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest(1),
        digest(2),
    );
    const final = try recursion.span_statement.MachineState.init(
        4,
        [_]u32{0} ** 32,
        digest(3),
        digest(4),
    );
    const complete = try recursion.span_statement.CompleteExecution.init(
        recursion.protocol.PROTOCOL_ID_WORDS,
        digest(5),
        initial,
        final,
        digest(6),
        digest(7),
        8,
    );
    return recursion.span_statement.JobContext.init(complete, 210);
}

fn fixtureRef(kind: u32, schema: u16, seed: u32) artifact_mod.ArtifactRefV1 {
    return .{
        .kind = kind,
        .format_version = 1,
        .schema_version = schema,
        .byte_count = 17,
        .sha256 = sha(seed),
    };
}

fn sha(seed: u32) [32]u8 {
    var result: [32]u8 = undefined;
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, seed, .little);
    for (0..8) |index| @memcpy(result[index * 4 ..][0..4], &encoded);
    return result;
}

fn digest(seed: u32) [8]u32 {
    return [_]u32{seed + 1} ** 8;
}
