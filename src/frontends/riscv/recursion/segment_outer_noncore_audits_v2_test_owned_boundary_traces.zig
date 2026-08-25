//! Focused shard of segment_outer_noncore_audits_v2_test.zig; import that suite facade.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const PcsConfig = stwo_core.pcs.PcsConfig;

pub const subject = @import("segment_outer_noncore_audits_v2.zig");
pub const transcript_components = @import("segment_transcript_outer_components_v2.zig");
pub const transcript_source = @import("segment_transcript_outer_source_v2.zig");
pub const statement_components = @import("segment_statement_outer_components_v2.zig");
pub const statement_source = @import("segment_statement_outer_source_v2.zig");
pub const public_components = @import("segment_public_outer_components_v2.zig");
pub const public_source = @import("segment_public_outer_source_v2.zig");
pub const public_support = @import("segment_public_outer_test_support.zig");
pub const boundary_authority = @import("segment_leaf_outer_authority_v2.zig");
pub const boundary_air = @import("segment_leaf_outer_air_v2.zig");
pub const input_provider_authority =
    @import("segment_publication_input_provider_authority_v2.zig");
pub const input_provider_air =
    @import("air/segment_publication_input_provider_v2.zig");
pub const input_provider_support =
    @import("segment_publication_input_provider_test_support.zig");
pub const range_authority = @import("segment_range_authority_v2.zig");
pub const shared_provider = @import("air/universal_shared_provider.zig");
pub const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
pub const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
pub const relation_interaction = @import("air/relation_interaction.zig");
pub const universal = @import("air/universal_challenges.zig");
pub const universal_roster = @import("air/universal_roster.zig");
pub const range_bridge = @import("air/range_check_8_8_bridge.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const schedule = @import("air/verifier_schedule.zig");
pub const fixed_profile = @import("fixed_profile.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const transcript = @import("transcript_program_v2.zig");
pub const native_relations = @import("../air/relation_challenges.zig");
pub const public_data_support = @import("../air/public_data_v2_test_support.zig");

pub const config = PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

pub fn buildManifest(
    transcript_prepared: *const transcript_source.PreparedV2,
    statement_prepared: *const statement_source.PreparedV2,
    public_prepared: *const public_source.PreparedV2,
    boundary_prepared: *const boundary_authority.PreparedNativeVerifierOuterAuthorityV2,
) !manifest_mod.Manifest {
    var log_sizes = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    for (transcript_prepared.manifest.log_sizes, 0..) |log_size, row|
        log_sizes[row] = log_size;
    log_sizes[10] = statement_components.ROW10_LOG_SIZE;
    log_sizes[11] = statement_prepared.manifest.trace_log_size;
    for (public_prepared.manifest.log_sizes, 0..) |log_size, index|
        log_sizes[public_components.FIRST_ROW + index] = log_size;
    log_sizes[@intFromEnum(universal_roster.Component.poseidon2)] = 11;
    log_sizes[@intFromEnum(universal_roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    const catalog = try catalog_mod.build(
        log_sizes,
        boundary_prepared.manifest.components,
    );
    return manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = transcript_prepared.manifest.identity,
        .statement_manifest_id = statement_prepared.manifest.identity,
        .public_manifest_id = public_prepared.manifest.identity,
        .boundary_manifest_id = boundary_prepared.manifest.identity,
        .boundary_authority_sha_id = boundary_prepared.manifest.authority_sha_id,
        .provider_authority_sha_id = input_provider_authority.sourceAuthorityShaId(),
    });
}

pub fn testPlan(allocator: std.mem.Allocator) !schedule.Plan {
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(
            .vm,
            native_relations.RELATION_COUNT,
            1,
            2,
            native_relations.RELATION_COUNT,
        ),
        .{
            .protocol_id = public_data_support.id("noncore-protocol"),
            .shape_id = public_data_support.id("noncore-shape"),
            .interaction_pow_bits = 0,
            .pcs_pow_bits = config.pow_bits,
            .query_count = @intCast(config.fri_config.n_queries),
            .table_count = 4,
            .claimed_sum_count = transcript.COMPONENT_CLAIM_COUNT,
            .sampled_value_count = 3,
            .tree_heights = .{ 5, 5, 5, 5 },
            .fri = try fixed_profile.FriSchedule.init(4, config.fri_config),
        },
    );
}

pub const OwnedStatementDestinations = struct {
    allocator: std.mem.Allocator,
    preprocessed_storage: []M31,
    main_storage: []M31,
    logical_rows: []statement_source.Air.Row,
    events: []statement_source.RelationEventV2,
    ranges: []statement_source.RangeRequestV2,
    preprocessed: [statement_source.Air.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [statement_source.Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: statement_source.ManifestV2,
    ) !OwnedStatementDestinations {
        const rows: usize = manifest.trace_row_count;
        const preprocessed_storage = try allocator.alloc(
            M31,
            rows * statement_source.Air.PREPROCESSED_COLUMN_COUNT,
        );
        errdefer allocator.free(preprocessed_storage);
        const main_storage = try allocator.alloc(
            M31,
            rows * statement_source.Air.PHYSICAL_MAIN_COLUMN_COUNT,
        );
        errdefer allocator.free(main_storage);
        const logical_rows = try allocator.alloc(
            statement_source.Air.Row,
            manifest.logical_row_count,
        );
        errdefer allocator.free(logical_rows);
        const events = try allocator.alloc(
            statement_source.RelationEventV2,
            manifest.relation_event_count,
        );
        errdefer allocator.free(events);
        const ranges = try allocator.alloc(
            statement_source.RangeRequestV2,
            manifest.range_request_count,
        );
        errdefer allocator.free(ranges);
        var preprocessed: [statement_source.Air.PREPROCESSED_COLUMN_COUNT][]M31 =
            undefined;
        for (&preprocessed, 0..) |*column, index| column.* =
            preprocessed_storage[index * rows ..][0..rows];
        var main: [statement_source.Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 =
            undefined;
        for (&main, 0..) |*column, index| column.* =
            main_storage[index * rows ..][0..rows];
        return .{
            .allocator = allocator,
            .preprocessed_storage = preprocessed_storage,
            .main_storage = main_storage,
            .logical_rows = logical_rows,
            .events = events,
            .ranges = ranges,
            .preprocessed = preprocessed,
            .main = main,
        };
    }

    pub fn deinit(self: *OwnedStatementDestinations) void {
        self.allocator.free(self.ranges);
        self.allocator.free(self.events);
        self.allocator.free(self.logical_rows);
        self.allocator.free(self.main_storage);
        self.allocator.free(self.preprocessed_storage);
        self.* = undefined;
    }

    pub fn destinations(self: *OwnedStatementDestinations) statement_source.DestinationsV2 {
        return .{
            .trace = .{ .preprocessed = self.preprocessed, .main = self.main },
            .logical_rows = self.logical_rows,
            .relation_events = self.events,
            .range_requests = self.ranges,
        };
    }
};

pub const OwnedBoundaryTraces = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    statement_preprocessed: [boundary_air.Statement.PREPROCESSED_COLUMN_COUNT][]M31,
    statement_main: [boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    statement_interaction: [boundary_air.Statement.INTERACTION_COLUMN_COUNT][]M31,
    public_preprocessed: [boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31,
    public_main: [boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    public_interaction: [boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const boundary_authority.OuterManifestV2,
    ) !OwnedBoundaryTraces {
        const statement_rows: usize = manifest.components[0].trace_rows;
        const public_rows: usize = manifest.components[1].trace_rows;
        const statement_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT +
            boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT +
            boundary_air.Statement.INTERACTION_COLUMN_COUNT;
        const public_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT +
            boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT +
            boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT;
        const statement_words = try std.math.mul(
            usize,
            statement_rows,
            statement_columns,
        );
        const public_words = try std.math.mul(
            usize,
            public_rows,
            public_columns,
        );
        const storage = try allocator.alloc(
            M31,
            try std.math.add(usize, statement_words, public_words),
        );
        var at: usize = 0;
        var statement_preprocessed: [boundary_air.Statement.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&statement_preprocessed) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_main: [boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&statement_main) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_interaction: [boundary_air.Statement.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&statement_interaction) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var public_preprocessed: [boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&public_preprocessed) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        var public_main: [boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&public_main) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        var public_interaction: [boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&public_interaction) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        std.debug.assert(at == storage.len);
        return .{
            .allocator = allocator,
            .storage = storage,
            .statement_preprocessed = statement_preprocessed,
            .statement_main = statement_main,
            .statement_interaction = statement_interaction,
            .public_preprocessed = public_preprocessed,
            .public_main = public_main,
            .public_interaction = public_interaction,
        };
    }

    pub fn deinit(self: *OwnedBoundaryTraces) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn traces(self: *OwnedBoundaryTraces) boundary_authority.TracesV2 {
        return .{
            .statement = .{
                .preprocessed = self.statement_preprocessed,
                .main = self.statement_main,
                .interaction = self.statement_interaction,
            },
            .public_logup = .{
                .preprocessed = self.public_preprocessed,
                .main = self.public_main,
                .interaction = self.public_interaction,
            },
        };
    }
};

pub const InputProviderTrace = struct {
    preprocessed: [input_provider_air.PREPROCESSED_COLUMN_COUNT][input_provider_authority.TRACE_ROW_COUNT]M31 = undefined,
    main: [input_provider_air.PHYSICAL_MAIN_COLUMN_COUNT][input_provider_authority.TRACE_ROW_COUNT]M31 = undefined,
    interaction: [input_provider_air.INTERACTION_COLUMN_COUNT][input_provider_authority.TRACE_ROW_COUNT]M31 = undefined,

    pub fn trace(self: *InputProviderTrace) input_provider_authority.TraceV2 {
        var preprocessed: [input_provider_air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&preprocessed, &self.preprocessed) |*destination, *source|
            destination.* = source;
        var main: [input_provider_air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 =
            undefined;
        for (&main, &self.main) |*destination, *source|
            destination.* = source;
        var interaction: [input_provider_air.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&interaction, &self.interaction) |*destination, *source|
            destination.* = source;
        return .{
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
        };
    }
};

pub const OwnedTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
    ) !OwnedTree {
        const column_count: usize = manifest.total_interaction_columns;
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        var initialized: usize = 0;
        errdefer for (columns[0..initialized]) |column| allocator.free(column);
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = placement.interaction_offset;
            const count: usize = placement.geometry.interaction_columns;
            const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..count]) |*column| {
                column.* = try allocator.alloc(M31, size);
                @memset(column.*, M31.zero());
                initialized += 1;
            }
        }
        if (initialized != column_count) return error.TestUnexpectedResult;
        return .{ .allocator = allocator, .columns = columns };
    }

    pub fn deinit(self: *OwnedTree) void {
        for (self.columns) |column| self.allocator.free(column);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

pub fn copyRangeTree2(
    tree: *OwnedTree,
    manifest: *const manifest_mod.Manifest,
    interaction: *const range_authority.ProviderInteractionV2,
) void {
    const placement = manifest.placements[35].?;
    for (interaction.columns(), 0..) |column, index|
        @memcpy(tree.columns[placement.interaction_offset + index], column);
}

pub fn copyBoundaryTree2(
    tree: *OwnedTree,
    manifest: *const manifest_mod.Manifest,
    traces: *const OwnedBoundaryTraces,
) void {
    const statement = manifest.placements[36].?;
    for (traces.statement_interaction, 0..) |column, index|
        @memcpy(tree.columns[statement.interaction_offset + index], column);
    const public = manifest.placements[37].?;
    for (traces.public_interaction, 0..) |column, index|
        @memcpy(tree.columns[public.interaction_offset + index], column);
}

pub fn copyInputProviderTree2(
    tree: *OwnedTree,
    manifest: *const manifest_mod.Manifest,
    traces: *const InputProviderTrace,
) void {
    const placement = manifest.placements[38].?;
    for (traces.interaction, 0..) |column, index|
        @memcpy(tree.columns[placement.interaction_offset + index], &column);
}

pub fn qm31(seed: usize) QM31 {
    return QM31.fromU32Unchecked(
        @intCast(seed),
        @intCast(seed + 1),
        @intCast(seed + 2),
        @intCast(seed + 3),
    );
}
