const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const PcsConfig = stwo_core.pcs.PcsConfig;
const public_data_v2 = @import("../air/public_data_v2.zig");
const support = @import("../air/public_data_v2_test_support.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const air_v2 = @import("segment_leaf_outer_air_v2.zig");
const source_v2 = @import("segment_leaf_authority_v2.zig");
const boundary_v2 = @import("segment_leaf_outer_authority_v2.zig");
const range_authority_v2 = @import("segment_range_authority_v2.zig");
const transcript_source_v2 = @import("segment_transcript_outer_source_v2.zig");
const transcript = @import("transcript_program_v2.zig");
const schedule = @import("air/verifier_schedule.zig");
const fixed_profile = @import("fixed_profile.zig");
const channel = @import("poseidon2_channel.zig");
const universal = @import("air/universal_challenges.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const manifest_v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
const catalog_v2 = @import("air/segment_outer_typed_catalog_v2.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const statement_components_v2 = @import("segment_statement_outer_components_v2.zig");
const subject = @import("segment_statement_outer_source_v2.zig");

const config = PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

const component_descs = [_]statement_v1.FamilyComponentDesc{.{
    .family = .base_alu_imm,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 10,
}};

const infra_descs = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 2,
}};

// Shared fixtures and mutation helpers for this conformance suite.

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    data: public_data_v2.PublicDataV2,
    plan: schedule.Plan,
    program: transcript.Program,
    trace_commitments: [4]channel.Digest,
    claimed_sums: [transcript.COMPONENT_CLAIM_COUNT]QM31,
    sampled_values: [3]QM31,
    fri_commitments: [4]channel.Digest,
    last_layer_coefficients: [1]QM31,
    execution: transcript.Execution,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        var source_fixture = try support.Fixture.init();
        const source = source_fixture.leftSource();
        const words = try support.encode(allocator, &source);
        errdefer allocator.free(words);
        const data = try public_data_v2.PublicDataV2.authenticate(words);
        var plan = try testPlan(allocator);
        errdefer plan.deinit();
        var program = try transcript.Program.init(
            allocator,
            &plan,
            config,
            &data,
            &component_descs,
            &infra_descs,
        );
        errdefer program.deinit();
        const trace_commitments = [_]channel.Digest{
            support.id("statement-spine-tree-0"),
            support.id("statement-spine-tree-1"),
            support.id("statement-spine-tree-2"),
            support.id("statement-spine-tree-3"),
        };
        var claimed_sums: [transcript.COMPONENT_CLAIM_COUNT]QM31 = undefined;
        for (&claimed_sums, 0..) |*value, index| value.* = qm31(index + 10);
        var sampled_values: [3]QM31 = undefined;
        for (&sampled_values, 0..) |*value, index| value.* = qm31(index + 100);
        const fri_commitments = [_]channel.Digest{
            support.id("statement-spine-fri-0"),
            support.id("statement-spine-fri-1"),
            support.id("statement-spine-fri-2"),
            support.id("statement-spine-fri-3"),
        };
        const last_layer_coefficients = [_]QM31{qm31(200)};
        const execution = try transcript.execute(allocator, &program, &data, .{
            .trace_commitments = &trace_commitments,
            .interaction_pow = 0,
            .claimed_sums = &claimed_sums,
            .sampled_values = &sampled_values,
            .fri_commitments = &fri_commitments,
            .last_layer_coefficients = &last_layer_coefficients,
            .pcs_pow = 0,
        });
        return .{
            .allocator = allocator,
            .words = words,
            .data = data,
            .plan = plan,
            .program = program,
            .trace_commitments = trace_commitments,
            .claimed_sums = claimed_sums,
            .sampled_values = sampled_values,
            .fri_commitments = fri_commitments,
            .last_layer_coefficients = last_layer_coefficients,
            .execution = execution,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.execution.deinit();
        self.program.deinit();
        self.plan.deinit();
        self.allocator.free(self.words);
        self.* = undefined;
    }
};

pub const OwnedDestinations = struct {
    allocator: std.mem.Allocator,
    preprocessed_storage: []M31,
    main_storage: []M31,
    logical_rows: []subject.Air.Row,
    events: []subject.RelationEventV2,
    ranges: []subject.RangeRequestV2,
    preprocessed: [subject.Air.PREPROCESSED_COLUMN_COUNT][]M31,
    main: [subject.Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: subject.ManifestV2,
    ) !OwnedDestinations {
        const rows: usize = manifest.trace_row_count;
        const preprocessed_storage = try allocator.alloc(
            M31,
            rows * subject.Air.PREPROCESSED_COLUMN_COUNT,
        );
        errdefer allocator.free(preprocessed_storage);
        const main_storage = try allocator.alloc(
            M31,
            rows * subject.Air.PHYSICAL_MAIN_COLUMN_COUNT,
        );
        errdefer allocator.free(main_storage);
        const logical_rows = try allocator.alloc(
            subject.Air.Row,
            manifest.logical_row_count,
        );
        errdefer allocator.free(logical_rows);
        const events = try allocator.alloc(
            subject.RelationEventV2,
            manifest.relation_event_count,
        );
        errdefer allocator.free(events);
        const ranges = try allocator.alloc(
            subject.RangeRequestV2,
            manifest.range_request_count,
        );
        errdefer allocator.free(ranges);
        var preprocessed: [subject.Air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&preprocessed, 0..) |*column, index| column.* =
            preprocessed_storage[index * rows ..][0..rows];
        var main: [subject.Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
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

    pub fn deinit(self: *OwnedDestinations) void {
        self.allocator.free(self.ranges);
        self.allocator.free(self.events);
        self.allocator.free(self.logical_rows);
        self.allocator.free(self.main_storage);
        self.allocator.free(self.preprocessed_storage);
        self.* = undefined;
    }

    pub fn destinations(self: *OwnedDestinations) subject.DestinationsV2 {
        return .{
            .trace = .{ .preprocessed = self.preprocessed, .main = self.main },
            .logical_rows = self.logical_rows,
            .relation_events = self.events,
            .range_requests = self.ranges,
        };
    }

    pub fn fillSentinel(self: *OwnedDestinations) void {
        @memset(std.mem.sliceAsBytes(self.preprocessed_storage), 0xa5);
        @memset(std.mem.sliceAsBytes(self.main_storage), 0xa5);
        @memset(std.mem.sliceAsBytes(self.logical_rows), 0xa5);
        @memset(std.mem.sliceAsBytes(self.events), 0xa5);
        @memset(std.mem.sliceAsBytes(self.ranges), 0xa5);
    }

    pub fn digest(self: *const OwnedDestinations) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(std.mem.sliceAsBytes(self.preprocessed_storage));
        hash.update(std.mem.sliceAsBytes(self.main_storage));
        hash.update(std.mem.sliceAsBytes(self.logical_rows));
        hash.update(std.mem.sliceAsBytes(self.events));
        hash.update(std.mem.sliceAsBytes(self.ranges));
        return hash.finalResult();
    }
};

pub const OwnedTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_v2.Manifest,
        tree: usize,
    ) !OwnedTree {
        try manifest.validate();
        const column_count: usize = switch (tree) {
            manifest_v2.PREPROCESSED_TREE_INDEX => @intCast(manifest.total_preprocessed_columns),
            manifest_v2.MAIN_TREE_INDEX => @intCast(manifest.total_main_columns),
            manifest_v2.INTERACTION_TREE_INDEX => @intCast(manifest.total_interaction_columns),
            else => return error.TestUnexpectedResult,
        };
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        var initialized: usize = 0;
        errdefer for (columns[0..initialized]) |column| allocator.free(column);
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = switch (tree) {
                manifest_v2.PREPROCESSED_TREE_INDEX => @intCast(placement.preprocessed_offset),
                manifest_v2.MAIN_TREE_INDEX => @intCast(placement.main_offset),
                manifest_v2.INTERACTION_TREE_INDEX => @intCast(placement.interaction_offset),
                else => unreachable,
            };
            const count: usize = switch (tree) {
                manifest_v2.PREPROCESSED_TREE_INDEX => @intCast(placement.geometry.preprocessed_columns),
                manifest_v2.MAIN_TREE_INDEX => @intCast(placement.geometry.main_columns),
                manifest_v2.INTERACTION_TREE_INDEX => @intCast(placement.geometry.interaction_columns),
                else => unreachable,
            };
            const size = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            for (columns[offset..][0..count]) |*column| {
                column.* = try allocator.alloc(M31, size);
                initialized += 1;
            }
        }
        try std.testing.expectEqual(column_count, initialized);
        return .{ .allocator = allocator, .columns = columns };
    }

    pub fn deinit(self: *OwnedTree) void {
        for (self.columns) |column| self.allocator.free(column);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn fillSentinel(self: *OwnedTree) void {
        for (self.columns) |column| @memset(column, M31.fromCanonical(0x1234));
    }

    pub fn digest(self: *const OwnedTree) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        for (self.columns) |column| for (column) |value| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, value.toU32(), .little);
            hash.update(&encoded);
        };
        return hash.finalResult();
    }
};

pub fn sourceTrace(storage: []M31, rows_value: u32) source_v2.TraceColumnsV2 {
    const rows: usize = rows_value;
    return .{
        .active = storage[0..rows],
        .scope = storage[rows .. 2 * rows],
        .index = storage[2 * rows .. 3 * rows],
        .value = storage[3 * rows .. 4 * rows],
    };
}

pub fn testPlan(allocator: std.mem.Allocator) !schedule.Plan {
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(
            .vm,
            relation_challenges.RELATION_COUNT,
            1,
            2,
            relation_challenges.RELATION_COUNT,
        ),
        .{
            .protocol_id = support.id("statement-spine-protocol"),
            .shape_id = support.id("statement-spine-shape"),
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

pub fn qm31(seed: usize) QM31 {
    return QM31.fromU32Unchecked(
        @intCast(seed),
        @intCast(seed + 1),
        @intCast(seed + 2),
        @intCast(seed + 3),
    );
}

pub fn counterDigest(values: []const M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (values) |value| {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, value.toU32(), .little);
        hash.update(&encoded);
    }
    return hash.finalResult();
}

pub fn providerManifest(statement_log_size: u32) !manifest_v2.Manifest {
    var log_sizes = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    log_sizes[@intFromEnum(universal_roster.Component.statement_semantics_input)] =
        statement_log_size;
    log_sizes[@intFromEnum(universal_roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    const catalog = try catalog_v2.build(
        log_sizes,
        providerBoundaryComponents(@intCast(statement_log_size)),
    );
    return manifest_v2.assemble(&catalog, .{
        .transcript_manifest_id = testDigest(11),
        .statement_manifest_id = testDigest(29),
        .public_manifest_id = testDigest(47),
        .boundary_manifest_id = testDigest(71),
        .boundary_authority_sha_id = testShaDigest(89),
    });
}

pub fn statementComponentManifest(
    prepared: *const subject.PreparedV2,
) !manifest_v2.Manifest {
    var log_sizes = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    log_sizes[@intFromEnum(universal_roster.Component.statement_semantics_input)] =
        prepared.manifest.trace_log_size;
    log_sizes[@intFromEnum(universal_roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    const catalog = try catalog_v2.build(
        log_sizes,
        providerBoundaryComponents(@intCast(prepared.manifest.trace_log_size)),
    );
    return manifest_v2.assemble(&catalog, .{
        .transcript_manifest_id = testDigest(11),
        .statement_manifest_id = prepared.manifest.identity,
        .public_manifest_id = testDigest(47),
        .boundary_manifest_id = testDigest(71),
        .boundary_authority_sha_id = testShaDigest(89),
    });
}

pub fn expectComponentColumnsZero(
    manifest: *const manifest_v2.Manifest,
    key: manifest_v2.ComponentKey,
    tree: usize,
    columns: []const []M31,
) !void {
    const placement = try manifest.placement(key);
    const offset: usize = switch (tree) {
        manifest_v2.PREPROCESSED_TREE_INDEX => @intCast(placement.preprocessed_offset),
        manifest_v2.MAIN_TREE_INDEX => @intCast(placement.main_offset),
        manifest_v2.INTERACTION_TREE_INDEX => @intCast(placement.interaction_offset),
        else => return error.TestUnexpectedResult,
    };
    const count: usize = switch (tree) {
        manifest_v2.PREPROCESSED_TREE_INDEX => @intCast(placement.geometry.preprocessed_columns),
        manifest_v2.MAIN_TREE_INDEX => @intCast(placement.geometry.main_columns),
        manifest_v2.INTERACTION_TREE_INDEX => @intCast(placement.geometry.interaction_columns),
        else => return error.TestUnexpectedResult,
    };
    for (columns[offset..][0..count]) |column|
        for (column) |value| try std.testing.expect(value.isZero());
}

pub fn providerBoundaryComponents(
    statement_log_size: u8,
) [boundary_v2.COMPONENT_COUNT]boundary_v2.ComponentGeometryV2 {
    return .{
        .{
            .kind = .statement_source,
            .component_tag = boundary_v2.STATEMENT_COMPONENT_TAG,
            .logical_rows = (@as(u32, 1) << @intCast(statement_log_size - 1)) + 1,
            .trace_log_size = statement_log_size,
            .trace_rows = @as(u32, 1) << @intCast(statement_log_size),
            .preprocessed_columns = air_v2.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = air_v2.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = air_v2.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = air_v2.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = air_v2.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = air_v2.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = boundary_v2.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = boundary_v2.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = boundary_v2.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = boundary_v2.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = air_v2.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = air_v2.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = air_v2.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = air_v2.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
}

pub fn testDigest(seed: u32) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

pub fn testShaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
