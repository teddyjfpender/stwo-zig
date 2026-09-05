//! Focused three-shape fixture for the ordinary Ethereum H1 V3 session.
//!
//! SegmentV2, the authenticated 12-placement H1 binary program, and the
//! frozen universal Empty program deliberately retain different capture
//! geometries. This test-only fixture proves that the append-only constructor
//! keeps those authorities separate and instantiates the H1 owner's exact
//! `recordCohort` callback without activating production publication.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const canonical_empty = frontend.recursion.canonical_empty_cohort_v3;
const h1_components =
    @import("recursive_temporal_ethereum_poseidon_h1_components_v1.zig");
const h1_graph =
    @import("recursive_temporal_secure_child_h1_graph_v1.zig");
const h1_manifest =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const v3_test_support = @import(
    "../../frontends/riscv/recursion/recursion_air_composition_circuit_v3_test_support.zig",
);

const recursion = frontend.recursion;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const protocol = recursion.protocol;
const segment_manifest = recursion.air.segment_outer_adapter_manifest_v2;
const span = recursion.span_statement;
const temporal = recursion.temporal_pair_node;
const universal_manifest = recursion.air.universal_manifest;
const verifier_types = stwo_core.verifier_types;
const QM31 = stwo_core.fields.qm31.QM31;

const FRI_LOG_BLOWUP: u32 = 1;
const COMPOSITION_COLUMN_COUNT: usize = 8;
const H1_LOG_SIZES = h1_manifest.LogSizes{
    11, 11, 9,
    7,  3,  4,
    4,  7,  3,
    4,  4,  8,
};

test "ordinary H1 session retains three shapes and exact cohort callback" {
    var fixture = try ThreeShapeFixture.init(std.testing.allocator);
    defer fixture.deinit();

    const session = try fixture.createSession(
        &fixture.h1_authority,
        fixture.segment_capture.view(),
        fixture.h1_capture.view(),
        fixture.empty_capture.view(),
    );
    defer session.deinit();

    const empty_layout = &session.authenticated_h1_empty_layout.?;
    try std.testing.expectEqual(
        capture_layout.ManifestFamily.segment_v2,
        session.segment_layout.manifest_family,
    );
    try std.testing.expectEqual(
        capture_layout.ManifestFamily.ethereum_poseidon_h1_v1,
        session.binary_layout.manifest_family,
    );
    try std.testing.expectEqual(
        capture_layout.ManifestFamily.universal_v1,
        empty_layout.manifest_family,
    );
    try std.testing.expectEqual(
        @as(u8, segment_manifest.COMPONENT_COUNT),
        session.segment_layout.component_count,
    );
    try std.testing.expectEqual(
        @as(u8, h1_manifest.COMPONENT_COUNT),
        session.binary_layout.component_count,
    );
    try std.testing.expectEqual(
        @as(u8, composition_v3.UNIVERSAL_PHYSICAL_CLAIM_COUNT),
        empty_layout.component_count,
    );
    try expectDifferentIdentity(
        &session.segment_layout.identity,
        &session.binary_layout.identity,
    );
    try expectDifferentIdentity(
        &session.binary_layout.identity,
        &empty_layout.identity,
    );
    try expectDifferentIdentity(
        &session.segment_layout.identity,
        &empty_layout.identity,
    );
    try std.testing.expectEqual(
        session.binary_layout.sampled_value_count,
        session.sample_input_authority.binary_sample_count,
    );
    try std.testing.expect(
        empty_layout.sampled_value_count <=
            session.sample_input_authority.max_sample_count,
    );

    // The fixture does not fabricate component witnesses. Corrupt the
    // pointer-free configuration so admission fails before any undefined
    // adapter can be read, while still instantiating the exact typed callback
    // through the generic session method.
    session.configuration.identity[0] ^= 1;
    var segment_components: v3_test_support.SegmentCohortComponents = undefined;
    var binary_components: h1_components.ComponentsV1 = undefined;
    var empty_components: v3_test_support.UniversalCohortComponents = undefined;
    try std.testing.expectError(
        error.ConfigurationIdentityMismatch,
        session.recordProgramsWithAuthenticatedH1(
            h1_manifest,
            &fixture.h1_authority,
            &segment_components,
            &binary_components,
            h1_graph.recordCohort,
            &empty_components,
        ),
    );
    try std.testing.expect(session.failed);
    try std.testing.expect(!h1_graph.PRODUCTION_ACTIVATION);
    assertH1CallbackType();
}

test "ordinary H1 and canonical Empty retain separate capture custody" {
    var fixture = try ThreeShapeFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const empty_program = try fixture.canonicalEmptyProgram();

    const session = try fixture.createCombinedSession(empty_program);
    defer session.deinit();
    const empty_binary_layout = &session.authenticated_h1_empty_layout.?;
    const canonical_layout = &session.canonical_empty_layout.?;
    try empty_program.validateAgainst(
        &fixture.universal_authority,
        empty_binary_layout,
        canonical_layout,
    );
    try std.testing.expectEqual(
        composition_v3.ManifestFamilyV3.ethereum_poseidon_h1_v1,
        session.configuration.program_roster
            .forKind(.binary_node).manifest_family,
    );
    try std.testing.expectEqual(
        composition_v3.ClaimPolicyV3.canonical_empty_provider,
        session.configuration.program_roster.forKind(.empty_leaf).claim_policy,
    );
    try std.testing.expectEqualDeep(
        empty_program.air_program_id,
        session.air_program_ids.empty_leaf,
    );
    try std.testing.expectEqualSlices(
        u8,
        &empty_program.binary_layout_identity,
        &empty_binary_layout.identity,
    );
    try std.testing.expectEqualSlices(
        u8,
        &empty_program.empty_layout_identity,
        &canonical_layout.identity,
    );
    try expectDifferentIdentity(
        &session.binary_layout.identity,
        &empty_binary_layout.identity,
    );

    // Instantiate the combined recorder handoff while rejecting before any
    // undefined test-only component storage is read.
    session.configuration.identity[0] ^= 1;
    var segment_components: v3_test_support.SegmentCohortComponents = undefined;
    var binary_components: h1_components.ComponentsV1 = undefined;
    var empty_cohort: canonical_empty.CohortV3 = undefined;
    try std.testing.expectError(
        error.ConfigurationIdentityMismatch,
        session.recordProgramsWithAuthenticatedH1AndCanonicalEmptyCatalog(
            h1_manifest,
            &fixture.h1_authority,
            &segment_components,
            &binary_components,
            h1_graph.recordCohort,
            &empty_cohort.owners,
            &empty_cohort.poseidon,
            &empty_cohort.range,
        ),
    );
    try std.testing.expect(session.failed);
}

test "ordinary H1 and canonical Empty reject detached program custody" {
    var fixture = try ThreeShapeFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var empty_program = try fixture.canonicalEmptyProgram();
    empty_program.binary_layout_identity[0] ^= 1;

    try fixture.expectCombinedCreateError(
        error.CanonicalEmptyProgramMismatch,
        empty_program,
    );
}

test "ordinary H1 session rejects provider sample and cross-shape mutations" {
    var fixture = try ThreeShapeFixture.init(std.testing.allocator);
    defer fixture.deinit();

    const provider = fixture.h1_authority.placements[
        h1_manifest.keyIndex(.poseidon2)
    ].?;
    const provider_column: usize = @intCast(provider.interaction_offset);
    const original_points = fixture.h1_capture.sampled_points[
        capture_layout.INTERACTION_TREE_INDEX
    ][provider_column];
    try std.testing.expectEqual(@as(usize, 2), original_points.len);
    fixture.h1_capture.sampled_points[
        capture_layout.INTERACTION_TREE_INDEX
    ][provider_column] = original_points[0..1];
    try fixture.expectCreateError(
        error.InvalidSampleGeometry,
        &fixture.h1_authority,
        fixture.segment_capture.view(),
        fixture.h1_capture.view(),
        fixture.empty_capture.view(),
    );
    fixture.h1_capture.sampled_points[
        capture_layout.INTERACTION_TREE_INDEX
    ][provider_column] = original_points;

    // Equal proof kinds do not make capture geometries interchangeable: H1
    // has twelve placements and the universal Empty shell has thirty-six.
    try fixture.expectCreateError(
        error.InvalidSampleGeometry,
        &fixture.h1_authority,
        fixture.segment_capture.view(),
        fixture.empty_capture.view(),
        fixture.h1_capture.view(),
    );
}

test "ordinary H1 session rejects Empty logs and H1 manifest custody drift" {
    var fixture = try ThreeShapeFixture.init(std.testing.allocator);
    defer fixture.deinit();

    const original_log = fixture.empty_capture.column_log_sizes[
        capture_layout.MAIN_TREE_INDEX
    ][0];
    fixture.empty_capture.column_log_sizes[
        capture_layout.MAIN_TREE_INDEX
    ][0] = original_log + 1;
    try fixture.expectCreateError(
        error.InvalidTraceLogGeometry,
        &fixture.h1_authority,
        fixture.segment_capture.view(),
        fixture.h1_capture.view(),
        fixture.empty_capture.view(),
    );
    fixture.empty_capture.column_log_sizes[
        capture_layout.MAIN_TREE_INDEX
    ][0] = original_log;

    var stale_manifest = fixture.h1_authority;
    stale_manifest.seal[0] ^= 1;
    try fixture.expectCreateError(
        error.ManifestSealMismatch,
        &stale_manifest,
        fixture.segment_capture.view(),
        fixture.h1_capture.view(),
        fixture.empty_capture.view(),
    );
}

const ThreeShapeFixture = struct {
    allocator: std.mem.Allocator,
    universal_authority: universal_manifest.Manifest,
    segment_authority: segment_manifest.Manifest,
    h1_authority: h1_manifest.Manifest,
    segment_capture: CaptureFixture,
    h1_capture: CaptureFixture,
    empty_capture: CaptureFixture,

    fn init(allocator: std.mem.Allocator) !ThreeShapeFixture {
        const log_sizes = v3_test_support.fixtureLogSizes();
        const universal_authority = try universal_manifest.build(log_sizes);
        const catalog = try v3_test_support.fixtureCatalog(log_sizes);
        const segment_authority = try segment_manifest.assemble(
            &catalog,
            v3_test_support.authorityIds(),
        );
        const h1_authority = try h1_manifest.build(
            H1_LOG_SIZES,
            sha(0x4831_0001),
        );
        var segment_capture = try CaptureFixture.init(
            allocator,
            &segment_authority,
            composition_v3.POSEIDON_ROSTER_ROW,
        );
        errdefer segment_capture.deinit();
        var h1_capture = try CaptureFixture.init(
            allocator,
            &h1_authority,
            h1_manifest.keyIndex(.poseidon2),
        );
        errdefer h1_capture.deinit();
        var empty_capture = try CaptureFixture.init(
            allocator,
            &universal_authority,
            composition_v3.POSEIDON_ROSTER_ROW,
        );
        errdefer empty_capture.deinit();
        return .{
            .allocator = allocator,
            .universal_authority = universal_authority,
            .segment_authority = segment_authority,
            .h1_authority = h1_authority,
            .segment_capture = segment_capture,
            .h1_capture = h1_capture,
            .empty_capture = empty_capture,
        };
    }

    fn deinit(self: *ThreeShapeFixture) void {
        self.empty_capture.deinit();
        self.h1_capture.deinit();
        self.segment_capture.deinit();
        self.* = undefined;
    }

    fn createSession(
        self: *ThreeShapeFixture,
        active_h1_manifest: *const h1_manifest.Manifest,
        segment_capture: CaptureFixture.View,
        h1_capture: CaptureFixture.View,
        empty_capture: CaptureFixture.View,
    ) !*composition_v3.HeterogeneousSessionV3 {
        return composition_v3.HeterogeneousSessionV3
            .createWithAuthenticatedH1(
            self.allocator,
            .{
                .universal = &self.universal_authority,
                .segment = &self.segment_authority,
            },
            .{
                .segment_leaf = v3_test_support.airProgramId(401),
                .binary_node = v3_test_support.airProgramId(501),
                .empty_leaf = v3_test_support.airProgramId(601),
            },
            active_h1_manifest,
            segment_capture,
            h1_capture,
            empty_capture,
        );
    }

    fn canonicalEmptyProgram(
        self: *ThreeShapeFixture,
    ) !composition_v3.CanonicalEmptyProgramV3 {
        var binary_layout = try capture_layout.CaptureLayoutV3.initBinary(
            self.allocator,
            &self.universal_authority,
            self.empty_capture.view(),
        );
        defer binary_layout.deinit();
        var empty_layout = try capture_layout.CanonicalEmptyCaptureLayoutV3.init(
            self.allocator,
            &self.universal_authority,
            &binary_layout,
        );
        defer empty_layout.deinit();
        const publication = try canonicalEmptyPublication();
        return canonical_empty.sealProgram(
            &self.universal_authority,
            &binary_layout,
            &empty_layout,
            &publication,
        );
    }

    fn createCombinedSession(
        self: *ThreeShapeFixture,
        empty_program: composition_v3.CanonicalEmptyProgramV3,
    ) !*composition_v3.HeterogeneousSessionV3 {
        return composition_v3.HeterogeneousSessionV3
            .createWithAuthenticatedH1AndCanonicalEmpty(
            self.allocator,
            .{
                .universal = &self.universal_authority,
                .segment = &self.segment_authority,
            },
            .{
                .segment_leaf = v3_test_support.airProgramId(401),
                .binary_node = v3_test_support.airProgramId(501),
                .empty_leaf = empty_program.air_program_id,
            },
            &self.h1_authority,
            self.segment_capture.view(),
            self.h1_capture.view(),
            self.empty_capture.view(),
            empty_program,
        );
    }

    fn expectCombinedCreateError(
        self: *ThreeShapeFixture,
        expected: anyerror,
        empty_program: composition_v3.CanonicalEmptyProgramV3,
    ) !void {
        const created = self.createCombinedSession(empty_program);
        if (created) |session| {
            session.deinit();
            return error.ExpectedH1SessionCreationFailure;
        } else |actual| {
            try std.testing.expectEqual(expected, actual);
        }
    }

    fn expectCreateError(
        self: *ThreeShapeFixture,
        expected: anyerror,
        active_h1_manifest: *const h1_manifest.Manifest,
        segment_capture: CaptureFixture.View,
        h1_capture: CaptureFixture.View,
        empty_capture: CaptureFixture.View,
    ) !void {
        const created = self.createSession(
            active_h1_manifest,
            segment_capture,
            h1_capture,
            empty_capture,
        );
        if (created) |session| {
            session.deinit();
            return error.ExpectedH1SessionCreationFailure;
        } else |actual| {
            try std.testing.expectEqual(expected, actual);
        }
    }
};

const CaptureFixture = struct {
    allocator: std.mem.Allocator,
    sampled_points: [][][]u8,
    column_log_sizes: [][]u32,
    sampled_values: []QM31,

    const View = struct {
        sampled_points: [][][]u8,
        column_log_sizes: [][]u32,
        sampled_values: []QM31,
    };

    fn init(
        allocator: std.mem.Allocator,
        manifest: anytype,
        poseidon_roster_row: usize,
    ) !CaptureFixture {
        const column_counts = [capture_layout.TREE_COUNT]usize{
            manifest.total_preprocessed_columns,
            manifest.total_main_columns,
            manifest.total_interaction_columns,
            COMPOSITION_COLUMN_COUNT,
        };
        const points = try allocator.alloc(
            [][]u8,
            capture_layout.TREE_COUNT,
        );
        errdefer allocator.free(points);
        const logs = try allocator.alloc([]u32, capture_layout.TREE_COUNT);
        errdefer allocator.free(logs);
        var initialized_trees: usize = 0;
        errdefer {
            for (0..initialized_trees) |tree| {
                for (points[tree]) |column| allocator.free(column);
                allocator.free(points[tree]);
                allocator.free(logs[tree]);
            }
        }

        const composition_log_size = try deriveCompositionLogSize(manifest);
        var sampled_value_count: usize = 0;
        for (column_counts, 0..) |column_count, tree| {
            points[tree] = try allocator.alloc([]u8, column_count);
            errdefer allocator.free(points[tree]);
            logs[tree] = try allocator.alloc(u32, column_count);
            errdefer allocator.free(logs[tree]);
            var initialized_columns: usize = 0;
            errdefer for (points[tree][0..initialized_columns]) |column|
                allocator.free(column);
            for (points[tree], 0..) |*column, column_index| {
                const sample_count = try sampleCount(
                    manifest,
                    poseidon_roster_row,
                    tree,
                    column_index,
                );
                column.* = try allocator.alloc(u8, sample_count);
                initialized_columns += 1;
                @memset(column.*, 0);
                sampled_value_count = try std.math.add(
                    usize,
                    sampled_value_count,
                    sample_count,
                );
            }
            for (logs[tree], 0..) |*log_size, column_index| {
                log_size.* = if (tree == capture_layout.COMPOSITION_TREE_INDEX)
                    composition_log_size -
                        verifier_types.COMPOSITION_LOG_SPLIT +
                        FRI_LOG_BLOWUP
                else
                    try traceColumnLog(manifest, tree, column_index) +
                        FRI_LOG_BLOWUP;
            }
            initialized_trees += 1;
        }
        const values = try allocator.alloc(QM31, sampled_value_count);
        @memset(values, QM31.zero());
        return .{
            .allocator = allocator,
            .sampled_points = points,
            .column_log_sizes = logs,
            .sampled_values = values,
        };
    }

    fn deinit(self: *CaptureFixture) void {
        self.allocator.free(self.sampled_values);
        for (self.sampled_points, self.column_log_sizes) |tree, logs| {
            for (tree) |column| self.allocator.free(column);
            self.allocator.free(tree);
            self.allocator.free(logs);
        }
        self.allocator.free(self.sampled_points);
        self.allocator.free(self.column_log_sizes);
        self.* = undefined;
    }

    fn view(self: *CaptureFixture) View {
        return .{
            .sampled_points = self.sampled_points,
            .column_log_sizes = self.column_log_sizes,
            .sampled_values = self.sampled_values,
        };
    }
};

fn sampleCount(
    manifest: anytype,
    poseidon_roster_row: usize,
    tree: usize,
    column: usize,
) !usize {
    if (tree != capture_layout.INTERACTION_TREE_INDEX) return 1;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = @intCast(placement.interaction_offset);
        const end = start + placement.geometry.interaction_columns;
        if (column < start or column >= end) continue;
        if (@as(usize, row) == poseidon_roster_row) return 2;
        return if (column >= end - stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE)
            2
        else
            1;
    }
    return error.InvalidSampleGeometry;
}

fn traceColumnLog(manifest: anytype, tree: usize, column: usize) !u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const range = switch (tree) {
            capture_layout.PREPROCESSED_TREE_INDEX => .{
                placement.preprocessed_offset,
                placement.geometry.preprocessed_columns,
            },
            capture_layout.MAIN_TREE_INDEX => .{
                placement.main_offset,
                placement.geometry.main_columns,
            },
            capture_layout.INTERACTION_TREE_INDEX => .{
                placement.interaction_offset,
                placement.geometry.interaction_columns,
            },
            else => return error.InvalidTraceLogGeometry,
        };
        const start: usize = range[0];
        const end = start + range[1];
        if (column >= start and column < end)
            return placement.geometry.log_size;
    }
    return error.InvalidTraceLogGeometry;
}

fn deriveCompositionLogSize(manifest: anytype) !u32 {
    var result: u32 = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        const quotient_blowup = @max(
            @as(u32, 1),
            std.math.log2_int_ceil(
                u32,
                geometry.protocol_constraint_degree - 1,
            ),
        );
        result = @max(
            result,
            try std.math.add(u32, geometry.log_size, quotient_blowup),
        );
    }
    return result;
}

fn expectDifferentIdentity(left: *const [32]u8, right: *const [32]u8) !void {
    try std.testing.expect(!std.mem.eql(u8, left, right));
}

fn assertH1CallbackType() void {
    const Callback = *const fn (
        *h1_graph.ProgramRecorder,
        *const h1_components.ComponentsV1,
    ) anyerror!composition_v3.segment_recorder_v3.ProgramResultV3;
    const callback: Callback = h1_graph.recordCohort;
    _ = callback;
}

fn canonicalEmptyPublication() !temporal.VerifiedChildV2 {
    const initial = try span.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest(11),
        digest(21),
    );
    const final = try span.MachineState.init(
        16,
        [_]u32{0} ** 32,
        digest(31),
        digest(41),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest(51),
            initial,
            final,
            digest(61),
            digest(71),
            32,
        ),
        3,
    );
    const statement = try span.SpanStatement.emptyLeaf(job, 3);
    const words = try statement.canonicalWords();
    const zero = [_]u32{0} ** 8;
    return .{
        .position = try temporal.positionForNextParent(statement),
        .kind = .empty_leaf,
        .scope = .protocol_padding,
        .proof_present = false,
        .roster_count = 0,
        .session_id = digest(81),
        .job_id = try temporal.jobId(&words),
        .recursive_parent_vk_id = digest(91),
        .verification_key_id = zero,
        .air_program_id = zero,
        .manifest_id = zero,
        .profile_id = zero,
        .statement_words = words,
        .proof_id = zero,
        .transcript_id = zero,
        .capture_id = zero,
        .verifier_receipt_id = zero,
        .claimed_sums_id = zero,
        .relation_replay_id = zero,
        .auxiliary_claim_seal_id = zero,
        .closure_receipt_id = zero,
        .lineage_id = zero,
        .closure_value = .{ 0, 0, 0, 0 },
    };
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn sha(seed: u32) [32]u8 {
    var result = [_]u8{0} ** 32;
    std.mem.writeInt(u32, result[0..4], seed, .little);
    result[4] = 1;
    return result;
}
