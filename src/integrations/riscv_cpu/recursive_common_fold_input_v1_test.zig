const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_common_fold_input_v1.zig");
const authority_mod = @import("recursive_common_wrapper_authority_v1.zig");
const manifest_mod = @import("recursive_common_wrapper_manifest_v1.zig");
const artifact_mod = @import("recursive_node_artifact_v1.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const recursion = frontend.recursion;
const Hasher = recursion.engine.Hasher;
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(Hasher);

test "common fold input retains two fresh captures and derives exact empty parent" {
    var fixture = try Fixture.init();
    var left_capture = CaptureFixture{};
    left_capture.init(&fixture.geometries[1]);
    var right_capture = CaptureFixture{};
    right_capture.init(&fixture.geometries[1]);
    const left = view(
        &fixture.children[0],
        &fixture.geometries[1],
        &left_capture.capture,
    );
    const right = view(
        &fixture.children[1],
        &fixture.geometries[1],
        &right_capture.capture,
    );
    var input = try subject.FreshFoldInputV1.init(
        left,
        right,
        try artifact_mod.TaskCoordinateV1.init(1, 105),
        &fixture.registry,
    );
    try input.validateAgainst(&fixture.registry);
    try std.testing.expectEqual(
        artifact_mod.NodeKindV1.empty,
        input.parent_node_kind,
    );
    try std.testing.expectEqual(
        manifest_mod.RegisteredChildCircuitV1.empty_leaf_wrapper,
        input.orderedPair().left,
    );
    try std.testing.expectEqual(
        manifest_mod.RegisteredChildCircuitV1.empty_leaf_wrapper,
        input.orderedPair().right,
    );
    try std.testing.expectEqual(
        input.parent.node_public.output_identity_sha256,
        input.outputNodePublic().output_identity_sha256,
    );
}

test "common fold input rejects alias order registry and sealed identity drift" {
    var fixture = try Fixture.init();
    var left_capture = CaptureFixture{};
    left_capture.init(&fixture.geometries[1]);
    var right_capture = CaptureFixture{};
    right_capture.init(&fixture.geometries[1]);
    const left = view(
        &fixture.children[0],
        &fixture.geometries[1],
        &left_capture.capture,
    );
    const right = view(
        &fixture.children[1],
        &fixture.geometries[1],
        &right_capture.capture,
    );
    const parent = try artifact_mod.TaskCoordinateV1.init(1, 105);
    try std.testing.expectError(
        error.AliasedCommonFoldChild,
        subject.FreshFoldInputV1.init(left, left, parent, &fixture.registry),
    );
    try std.testing.expectError(
        error.ChildCoordinateMismatch,
        subject.FreshFoldInputV1.init(right, left, parent, &fixture.registry),
    );

    var input = try subject.FreshFoldInputV1.init(
        left,
        right,
        parent,
        &fixture.registry,
    );
    input.identity_sha256[31] ^= 1;
    try std.testing.expectError(
        error.CommonFoldInputMismatch,
        input.validateAgainst(&fixture.registry),
    );
    input.identity_sha256[31] ^= 1;
    var wrong_registry = fixture.registry;
    wrong_registry.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCircuitRegistry,
        input.validateAgainst(&wrong_registry),
    );
}

const QUERY_COUNT: usize = 193;

const CaptureFixture = struct {
    commitments: [authority_mod.COMMITMENT_TREE_COUNT]Hasher.Hash = undefined,
    tree0_logs: [2]u32 = undefined,
    tree1_logs: [1]u32 = .{9},
    tree2_logs: [1]u32 = .{9},
    tree3_logs: [1]u32 = .{9},
    column_logs: [authority_mod.COMMITMENT_TREE_COUNT][]u32 = undefined,
    empty_sample_columns: [0][]CirclePointQM31 = .{},
    sampled_points: [authority_mod.COMMITMENT_TREE_COUNT][][]CirclePointQM31 =
        undefined,
    raw_queries: [QUERY_COUNT]usize = [_]usize{0} ** QUERY_COUNT,
    unique_queries: [1]usize = .{0},
    deep_answers: [QUERY_COUNT]QM31 = [_]QM31{QM31.zero()} ** QUERY_COUNT,
    trace_paths: [authority_mod.COMMITMENT_TREE_COUNT]MerklePathCapture = undefined,
    fri_layers: [0]FriLayerCapture = .{},
    last_layer: [1]QM31 = .{QM31.one()},
    capture: authority_mod.ProofCapture = undefined,

    fn init(
        self: *CaptureFixture,
        geometry: *const registry_mod.AuthenticatedGeometryV1,
    ) void {
        self.commitments = std.mem.zeroes(@TypeOf(self.commitments));
        for (&self.tree0_logs, geometry.preprocessed_column_log_sizes[0..2]) |
            *destination,
            base,
        | destination.* = base + geometry.pcs.fri_log_blowup_factor;
        self.column_logs = .{
            self.tree0_logs[0..],
            self.tree1_logs[0..],
            self.tree2_logs[0..],
            self.tree3_logs[0..],
        };
        for (&self.sampled_points) |*tree|
            tree.* = self.empty_sample_columns[0..];
        self.capture = .{
            .queries = .{
                .raw = self.raw_queries[0..],
                .unique = self.unique_queries[0..],
            },
            .commitments = self.commitments[0..],
            .column_log_sizes = self.column_logs[0..],
            .sampled_points = self.sampled_points[0..],
            .sampled_values = &.{},
            .queried_values = &.{},
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

const Fixture = struct {
    geometries: [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1,
    registry: registry_mod.RecursiveCircuitRegistryV1,
    children: [2]artifact_mod.RecursiveNodeArtifactV1,

    fn init() !Fixture {
        var geometries: [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1 = undefined;
        for (&geometries, 0..) |*geometry, ordinal|
            geometry.* = try fixtureGeometry(
                @enumFromInt(ordinal),
                @intCast(ordinal + 1),
            );
        var entries: [registry_mod.ROLE_COUNT]registry_mod.RegistryEntryV1 =
            undefined;
        for (&entries, &geometries) |*entry, *geometry|
            entry.* = try registry_mod.RegistryEntryV1.fromGeometry(geometry);
        const registry = try registry_mod.RecursiveCircuitRegistryV1.seal(
            entries,
        );
        const job = try fixtureJob();
        const left_statement = try recursion.span_statement.SpanStatement
            .emptyLeaf(job, 210);
        const right_statement = try recursion.span_statement.SpanStatement
            .emptyLeaf(job, 211);
        return .{
            .geometries = geometries,
            .registry = registry,
            .children = .{
                try fixtureArtifact(
                    210,
                    left_statement,
                    &registry,
                    &geometries[1],
                    11,
                ),
                try fixtureArtifact(
                    211,
                    right_statement,
                    &registry,
                    &geometries[1],
                    21,
                ),
            },
        };
    }
};

fn view(
    artifact: *const artifact_mod.RecursiveNodeArtifactV1,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    capture: *const authority_mod.ProofCapture,
) authority_mod.FreshWrapperViewV1 {
    return .{ .artifact = artifact, .geometry = geometry, .capture = capture };
}

fn fixtureGeometry(
    role: registry_mod.CircuitRoleV1,
    seed: u32,
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
        .output_abi = registry_mod.OutputAbiV1.nodePublic(),
        .proof_shape = try fixtureProofShape(),
        .authority_identity_sha256 = undefined,
    });
}

fn fixtureProofShape() !registry_mod.FixedProofShapeV3 {
    var logs = [_][registry_mod.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry_mod.MAX_TREE_COLUMN_COUNT,
    } ** registry_mod.FIXED_PROOF_TREE_COUNT;
    logs[0][0] = 9;
    logs[0][1] = 9;
    logs[1][0] = 9;
    logs[2][0] = 9;
    logs[3][0] = 9;
    var samples = [_][registry_mod.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry_mod.MAX_TREE_COLUMN_COUNT,
    } ** registry_mod.FIXED_PROOF_TREE_COUNT;
    samples[0][0] = 1;
    samples[0][1] = 1;
    samples[1][0] = 1;
    samples[2][0] = 1;
    samples[3][0] = 1;
    var folds = [_]u8{0} ** registry_mod.MAX_FRI_LAYER_COUNT;
    var paths = [_]u8{0} ** registry_mod.MAX_FRI_LAYER_COUNT;
    folds[0] = 16;
    folds[1] = 16;
    paths[0] = 9;
    paths[1] = 5;
    return registry_mod.FixedProofShapeV3.seal(.{
        .maximum_merkle_depth = 9,
        .claimed_sum_count = 36,
        .fri_layer_count = 2,
        .query_count = QUERY_COUNT,
        .maximum_fold_width = 16,
        .column_log_degree = 8,
        .sampled_value_count = 5,
        .queried_value_count = 5 * QUERY_COUNT,
        .trace_path_count = 4 * QUERY_COUNT,
        .trace_sibling_count = 36 * QUERY_COUNT,
        .fri_value_count = 32 * QUERY_COUNT,
        .fri_sibling_count = 14 * QUERY_COUNT,
        .last_layer_coefficient_count = 1,
        .tree_column_counts = .{ 2, 1, 1, 1 },
        .tree_column_log_sizes = logs,
        .tree_column_sample_counts = samples,
        .fri_layer_fold_widths = folds,
        .fri_layer_path_depths = paths,
        .table_layout_identity_sha256 = sha(101),
        .identity_sha256 = undefined,
    });
}

fn fixtureArtifact(
    index: u32,
    statement: recursion.span_statement.SpanStatement,
    registry: *const registry_mod.RecursiveCircuitRegistryV1,
    geometry: *const registry_mod.AuthenticatedGeometryV1,
    seed: u32,
) !artifact_mod.RecursiveNodeArtifactV1 {
    const words = try statement.canonicalWords();
    var canonical_words: [artifact_mod.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&canonical_words, words) |*destination, word|
        destination.* = word.toU32();
    const node_public = try artifact_mod.NodePublicV1.seal(.{
        .statement_words = canonical_words,
        .statement_identity_sha256 = statement_plan.statementSha256(&words),
        .node_authority_sha256 = sha(seed + 1),
        .subtree_sha256 = sha(seed + 2),
        .subtree_digest = digest(seed + 3),
        .output_identity_sha256 = undefined,
    });
    const entry = try registry.entry(.canonical_empty_field_v2);
    return artifact_mod.RecursiveNodeArtifactV1.seal(.{
        .stage_kind = .leaf_wrapper,
        .node_kind = .empty,
        .child_count = 1,
        .coordinate = try artifact_mod.TaskCoordinateV1.init(0, index),
        .node_public = node_public,
        .campaign_namespace_sha256 = sha(200),
        .circuit_identity_sha256 = entry.circuit_identity_sha256,
        .program_identity_sha256 = entry.program_identity_sha256,
        .profile_identity_sha256 = entry.profile_identity_sha256,
        .pcs_identity_sha256 = entry.pcs_identity_sha256,
        .padding_layout_identity_sha256 = entry.padding_layout_identity_sha256,
        .registry_identity_sha256 = registry.identity_sha256,
        .node_public_abi_sha256 = artifact_mod.nodePublicAbiIdentity(),
        .statement_identity_sha256 = node_public.statement_identity_sha256,
        .output_identity_sha256 = node_public.output_identity_sha256,
        .ordered_children = .{
            fixtureRef(14, seed + 4),
            artifact_mod.ArtifactRefV1.zero(),
        },
        .proof_ref = fixtureRef(8, seed + 5),
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
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

fn fixtureRef(kind: u32, seed: u32) artifact_mod.ArtifactRefV1 {
    return .{
        .kind = kind,
        .format_version = artifact_mod.ARTIFACT_REF_FORMAT_VERSION,
        .schema_version = 1,
        .byte_count = 17,
        .sha256 = sha(seed),
    };
}

fn sha(seed: u32) [32]u8 {
    var result: [32]u8 = undefined;
    for (0..8) |index|
        std.mem.writeInt(
            u32,
            result[index * 4 ..][0..4],
            seed + @as(u32, @intCast(index)),
            .little,
        );
    return result;
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}
