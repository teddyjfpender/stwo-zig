const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const subject = @import("recursion_air_composition_circuit_v3.zig");
const graph_mod = @import("air/composition_circuit.zig");
const recorder = @import("air/composition_graph_recorder.zig");
const control = @import("air/control.zig");
const control_relation = @import("air/control_relation.zig");
const direct = @import("air/direct_constraint_program.zig");
const universal = @import("air/universal_challenges.zig");
const universal_adapter_manifest = @import("air/universal_adapter_manifest.zig");
const segment_manifest = @import("air/segment_outer_adapter_manifest_v2.zig");
const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const row17_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary_manifest = @import("segment_leaf_outer_authority_v2.zig");
const provider_authority = @import("segment_publication_input_provider_authority_v2.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const segment_boundary_components =
    @import("air/segment_boundary_components_v2.zig");
const segment_provider_component =
    @import("air/segment_publication_input_provider_component_v2.zig");
const segment_core_components = @import("segment_core_outer_components_v2.zig");
const segment_public_components =
    @import("segment_public_outer_components_v2.zig");
const segment_range_authority = @import("segment_range_authority_v2.zig");
const segment_statement_components =
    @import("segment_statement_outer_components_v2.zig");
const segment_transcript_components =
    @import("segment_transcript_outer_components_v2.zig");
const binary_transcript_components =
    @import("binary_transcript_outer_source.zig");
const binary_statement_components =
    @import("outer_parent_statement_air_source.zig");
const binary_inactive_components =
    @import("binary_inactive_outer_source.zig");
const binary_fri_components = @import("binary_fri_outer_bundle.zig");
const capture_layout = subject.capture_layout_v3;
const segment_recorder = subject.segment_recorder_v3;

const FRI_LOG_BLOWUP: u32 = 1;
const COMPOSITION_COLUMN_COUNT: usize = 8;

// Shared fixtures and mutation helpers for this conformance suite.

pub fn claimsOfLength(comptime count: usize, seed: u32) [count]QM31 {
    var result: [count]QM31 = undefined;
    for (&result, 0..) |*value, index| value.* = felt(seed + @as(u32, @intCast(index)));
    return result;
}

pub fn felt(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

pub fn airProgramId(seed: u32) subject.AirProgramId {
    var result: subject.AirProgramId = undefined;
    for (&result, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return result;
}

pub fn fixtureLogSizes() universal_manifest.LogSizes {
    var result = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    result[0] = 5;
    result[1] = 6;
    result[5] = 7;
    result[11] = 8;
    result[12] = 5;
    result[13] = 4;
    result[14] = 4;
    result[15] = 6;
    result[16] = 5;
    result[17] = row17_witness_v2.TRACE_LOG_SIZE;
    result[@intFromEnum(universal_roster.Component.poseidon2)] = 11;
    result[@intFromEnum(universal_roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    return result;
}

pub fn fixtureCatalog(log_sizes: universal_manifest.LogSizes) !catalog_mod.Catalog {
    return catalog_mod.build(log_sizes, boundaryComponents(8));
}

pub fn boundaryComponents(
    statement_log_size: u8,
) [boundary_manifest.COMPONENT_COUNT]boundary_manifest.ComponentGeometryV2 {
    return .{
        .{
            .kind = .statement_source,
            .component_tag = boundary_manifest.STATEMENT_COMPONENT_TAG,
            .logical_rows = (@as(u32, 1) << @intCast(statement_log_size - 1)) + 1,
            .trace_log_size = statement_log_size,
            .trace_rows = @as(u32, 1) << @intCast(statement_log_size),
            .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = boundary_manifest.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = boundary_manifest.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = boundary_manifest.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = boundary_manifest.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
}

pub fn authorityIds() segment_manifest.AuthorityIds {
    return .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
        .provider_authority_sha_id = provider_authority.sourceAuthorityShaId(),
    };
}

pub fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

pub fn shaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

pub const UniversalCohortComponents = struct {
    non_fri: struct {
        transcript: binary_transcript_components.Components,
        statement: binary_statement_components.Components,
        inactive: binary_inactive_components.Components,
    },
    fri: binary_fri_components.Components,
};

pub const SegmentCohortComponents = struct {
    noncore: struct {
        transcript: segment_transcript_components.Components,
        statement: segment_statement_components.ComponentsV2,
        public: segment_public_components.Components,
        range: segment_range_authority.AdapterV2,
        boundary: segment_boundary_components.Components,
        verifier_input_provider: segment_provider_component.AdapterForManifest(
            segment_manifest,
        ),
    },
    core: segment_core_components.ComponentsV2,
};

pub fn expectUniversalOrchestrationCompiles(
    comptime ProgramRecorder: type,
    allocator: std.mem.Allocator,
    manifest: *const universal_adapter_manifest.Manifest,
    layout: *const capture_layout.CaptureLayoutV3,
) !void {
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(0, 128);
    try builder.activate();

    const samples = try allocator.alloc(
        recorder.Scalar,
        layout.sampled_value_count,
    );
    defer allocator.free(samples);
    @memset(samples, recorder.Scalar.zero());
    const claims = [_]recorder.Scalar{recorder.Scalar.zero()} **
        subject.COMPOSITION_CLAIM_INPUT_COUNT;
    var challenge_draws: [subject.RELATION_CHALLENGE_COUNT][2]recorder.Scalar =
        undefined;
    for (&challenge_draws) |*draw| draw.* = .{
        recorder.Scalar.zero(),
        recorder.Scalar.one(),
    };
    const challenges = try recorder.ChallengeSet.init(challenge_draws);
    var denominator_cache: recorder.DenominatorCache =
        .{null} ** stwo_core.circle.M31_CIRCLE_LOG_ORDER;
    var program = try ProgramRecorder.init(
        &builder,
        manifest,
        layout,
        samples,
        &claims,
        &challenges,
        recorder.Scalar.one(),
        recorder.pointFromSeed(recorder.Scalar.zero()),
        &denominator_cache,
    );

    // Compile every exact field/runtime pairing without dereferencing an
    // uninitialized adapter: the inactive builder is rejected at row zero.
    var cohort: UniversalCohortComponents = undefined;
    builder.deactivate();
    try std.testing.expectError(
        error.CircuitAlreadyFinished,
        program.recordCompleteUniversalCohort(&cohort),
    );
}

pub const CaptureFixture = struct {
    allocator: std.mem.Allocator,
    sampled_points: [][][]u8,
    column_log_sizes: [][]u32,
    sampled_values: []QM31,

    pub const View = struct {
        sampled_points: [][][]u8,
        column_log_sizes: [][]u32,
        sampled_values: []QM31,
    };

    pub fn init(allocator: std.mem.Allocator, manifest: anytype) !CaptureFixture {
        const column_counts = [capture_layout.TREE_COUNT]usize{
            manifest.total_preprocessed_columns,
            manifest.total_main_columns,
            manifest.total_interaction_columns,
            COMPOSITION_COLUMN_COUNT,
        };
        const points = try allocator.alloc([][]u8, capture_layout.TREE_COUNT);
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
        var sample_count: usize = 0;
        for (column_counts, 0..) |column_count, tree| {
            points[tree] = try allocator.alloc([]u8, column_count);
            logs[tree] = try allocator.alloc(u32, column_count);
            initialized_trees += 1;
            var initialized_columns: usize = 0;
            errdefer for (points[tree][0..initialized_columns]) |column|
                allocator.free(column);
            for (points[tree], 0..) |*column, index| {
                const sample_count_for_column =
                    if (tree == capture_layout.INTERACTION_TREE_INDEX)
                        interactionSamples(manifest, index)
                    else
                        1;
                column.* = try allocator.alloc(u8, sample_count_for_column);
                initialized_columns += 1;
                @memset(column.*, 0);
                sample_count += sample_count_for_column;
            }
            for (logs[tree], 0..) |*log_size, column| {
                log_size.* = if (tree == capture_layout.COMPOSITION_TREE_INDEX)
                    range_bridge.LOG_SIZE + FRI_LOG_BLOWUP
                else
                    traceColumnLog(manifest, tree, column);
            }
        }
        const values = try allocator.alloc(QM31, sample_count);
        @memset(values, QM31.zero());
        return .{
            .allocator = allocator,
            .sampled_points = points,
            .column_log_sizes = logs,
            .sampled_values = values,
        };
    }

    pub fn deinit(self: *CaptureFixture) void {
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

    pub fn view(self: *CaptureFixture) View {
        return .{
            .sampled_points = self.sampled_points,
            .column_log_sizes = self.column_log_sizes,
            .sampled_values = self.sampled_values,
        };
    }
};

pub fn interactionSamples(manifest: anytype, column: usize) usize {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = placement.interaction_offset;
        const end = start + placement.geometry.interaction_columns;
        if (column >= start and column < end) {
            if (row == subject.POSEIDON_ROSTER_ROW) return 2;
            return if (column >= end - 4) 2 else 1;
        }
    }
    unreachable;
}

pub fn traceColumnLog(manifest: anytype, tree: usize, column: usize) u32 {
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
            else => unreachable,
        };
        const start: usize = range[0];
        const end = start + range[1];
        if (column >= start and column < end)
            return placement.geometry.log_size + FRI_LOG_BLOWUP;
    }
    unreachable;
}
