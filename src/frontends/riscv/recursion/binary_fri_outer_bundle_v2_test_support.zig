//! Independent acceptance tests for the binary-pair V2 rows-18--34 owner.
//!
//! This file intentionally does not share implementation helpers with
//! `binary_fri_outer_bundle.zig`.  It checks the public manifest and schedule
//! contracts from their respective authorities, then exercises the concrete
//! bundle through a separately owned test root. The honest pair fixture is
//! not the native SegmentV2 leaf: it produces 16,852 verifier calls, while the
//! separately owned native schedule profile records 294.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const bundle_mod = @import("binary_fri_outer_bundle.zig");
const fixture_mod = @import("binary_pair_test_fixture.zig");
const source_mod = @import("binary_fri_outer_source.zig");
const source_test_support = @import("binary_fri_outer_source_test.zig");
const schedule_mod = @import("segment_shared_poseidon_schedule_v2.zig");
const cohort_mod = @import("segment_outer_cohort_v2.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const row17_witness_v2 =
    @import("air/vm_public_logup_control_witness_v2.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const universal = @import("air/universal_challenges.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary_manifest = @import("segment_leaf_outer_authority_v2.zig");
const input_provider_authority =
    @import("segment_publication_input_provider_authority_v2.zig");

const BundleV2 = bundle_mod.BundleForManifest(
    fixture_mod.DIMENSIONS,
    manifest_mod,
);
const AdaptersV2 = bundle_mod.AdaptersForManifest(manifest_mod);
const PAIR_FIXTURE_CORE_CALL_COUNT: usize = 16_852;
const PAIR_FIXTURE_TOTAL_CALL_COUNT: usize = 17_751;
const PAIR_FIXTURE_PROVIDER_LOG_SIZE: u32 = 15;

// Shared fixtures and mutation helpers for this conformance suite.

pub fn prepareVerifierCoreCalls(
    allocator: std.mem.Allocator,
    source: *const source_mod.Source(fixture_mod.DIMENSIONS),
) ![]schedule_mod.Call {
    const Source = source_mod.Source(fixture_mod.DIMENSIONS);
    var fri_workspace = try Source.Workspace.init(allocator, source);
    defer fri_workspace.deinit();
    var fri_main = try OwnedRows.init(
        allocator,
        source.friLogSizes(),
        source_mod.MAIN_COLUMNS_PER_ROW,
    );
    defer fri_main.deinit();
    try source.fillFriMainInto(&fri_workspace, fri_main.columns);

    var merkle_workspace = try Source.MerkleWorkspace.init(allocator, source);
    defer merkle_workspace.deinit();
    try source.prepareMerkleWorkspace(&fri_workspace, &merkle_workspace);
    const calls = try source.merklePoseidonCalls(
        &fri_workspace,
        &merkle_workspace,
    );
    return allocator.dupe(schedule_mod.Call, calls);
}

pub const OwnedRows = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        log_sizes: anytype,
        column_counts: anytype,
    ) !OwnedRows {
        var column_count: usize = 0;
        var storage_count: usize = 0;
        for (log_sizes, column_counts) |log_size, count| {
            column_count = try std.math.add(usize, column_count, count);
            const rows = @as(usize, 1) << @intCast(log_size);
            storage_count = try std.math.add(
                usize,
                storage_count,
                try std.math.mul(usize, count, rows),
            );
        }
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        const storage = try allocator.alloc(M31, storage_count);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());

        var column_at: usize = 0;
        var storage_at: usize = 0;
        for (log_sizes, column_counts) |log_size, count| {
            const rows = @as(usize, 1) << @intCast(log_size);
            for (0..count) |_| {
                columns[column_at] = storage[storage_at..][0..rows];
                column_at += 1;
                storage_at += rows;
            }
        }
        std.debug.assert(column_at == columns.len);
        std.debug.assert(storage_at == storage.len);
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
    }

    pub fn deinit(self: *OwnedRows) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

pub const OwnedManifestTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !OwnedManifestTree {
        try manifest.validate();
        const total_columns: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
            manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
            manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
            else => return error.InvalidTreeIndex,
        };
        const columns = try allocator.alloc([]M31, total_columns);
        errdefer allocator.free(columns);

        var storage_count: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const count: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const rows = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            storage_count = try std.math.add(
                usize,
                storage_count,
                try std.math.mul(usize, count, rows),
            );
        }
        const storage = try allocator.alloc(M31, storage_count);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());

        var storage_at: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
                manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
                manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
                else => unreachable,
            };
            const count: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const rows = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[storage_at..][0..rows];
                storage_at += rows;
            }
        }
        std.debug.assert(storage_at == storage.len);
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
    }

    pub fn deinit(self: *OwnedManifestTree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn anyNonZero(self: *const OwnedManifestTree) bool {
        return self.nonZeroCount() != 0;
    }

    pub fn allZero(self: *const OwnedManifestTree) bool {
        return self.nonZeroCount() == 0;
    }

    pub fn nonZeroCount(self: *const OwnedManifestTree) usize {
        var count: usize = 0;
        for (self.storage) |value| count += @intFromBool(!value.isZero());
        return count;
    }
};

pub fn fixtureManifestForCore(
    component_logs: [bundle_mod.ROW_COUNT]u32,
) !manifest_mod.Manifest {
    var logs = fixtureLogSizes();
    inline for (component_logs, bundle_mod.FIRST_ROW..) |log_size, row|
        logs[row] = log_size;
    return fixtureManifest(logs);
}

pub fn expectSingleProviderSelector(
    tree: *const OwnedManifestTree,
    manifest: *const manifest_mod.Manifest,
) !void {
    const placement = try manifest.placement(.poseidon2);
    try std.testing.expectEqual(@as(u16, 1), placement.geometry.preprocessed_columns);
    const selector = tree.columns[placement.preprocessed_offset];
    var one_count: usize = 0;
    for (selector) |value| {
        try std.testing.expect(value.isZero() or value.eql(M31.one()));
        one_count += @intFromBool(value.eql(M31.one()));
    }
    try std.testing.expectEqual(@as(usize, 1), one_count);
}

pub fn expectExactProviderRows(
    tree: *const OwnedManifestTree,
    manifest: *const manifest_mod.Manifest,
    logical_call_count: usize,
) !void {
    const placement = try manifest.placement(.poseidon2);
    const active = tree.columns[placement.main_offset];
    var active_count: usize = 0;
    for (active) |value| {
        try std.testing.expect(value.isZero() or value.eql(M31.one()));
        active_count += @intFromBool(value.eql(M31.one()));
    }
    try std.testing.expectEqual(logical_call_count, active_count);
    try std.testing.expectEqual(
        @as(usize, 1) << @intCast(placement.geometry.log_size),
        active.len,
    );
}

pub fn expectCallSlicesEqual(
    expected: []const schedule_mod.Call,
    actual: []const schedule_mod.Call,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right|
        try std.testing.expectEqualDeep(left, right);
}

pub fn expectAllCoreDomainAudits(
    audits: bundle_mod.DomainAudits,
    claims: bundle_mod.Claims,
) !void {
    for (audits.typed_rows, claims.typed_rows) |audit, claim| {
        var total = QM31.zero();
        for (audit.values) |value| total = total.add(value);
        try std.testing.expect(total.eql(audit.total));
        try std.testing.expect(audit.total.eql(claim));
        try std.testing.expect(audit.logical_rows != 0);
        try std.testing.expect(audit.event_terms != 0);
    }
    try audits.poseidon2.validate(claims);
    try std.testing.expect(
        audits.poseidon2.total.eql(claims.poseidon2Total()),
    );
}

pub fn expectGeometry(
    manifest: *const manifest_mod.Manifest,
    key: manifest_mod.ComponentKey,
    expected: manifest_mod.Geometry,
) !void {
    const placement = try manifest.placement(key);
    try std.testing.expectEqualDeep(expected, placement.geometry);
}

pub fn fixtureManifest(
    logs: universal_manifest.LogSizes,
) !manifest_mod.Manifest {
    const catalog = try catalog_mod.build(logs, boundaryComponents(8));
    return manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
        .provider_authority_sha_id = input_provider_authority.sourceAuthorityShaId(),
    });
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
    result[34] = 11;
    result[35] = range_bridge.LOG_SIZE;
    return result;
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

pub fn fixtureCalls(
    allocator: std.mem.Allocator,
    count: usize,
) ![]schedule_mod.Call {
    const calls = try allocator.alloc(schedule_mod.Call, count);
    for (calls, 0..) |*call, index| {
        call.* = .{
            .input = [_]u32{0} ** 16,
            .io = true,
        };
        call.input[0] = @intCast(index);
    }
    return calls;
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

comptime {
    if (bundle_mod.ROW_COUNT != 17 or bundle_mod.FIRST_ROW != 18 or
        bundle_mod.LAST_ROW != 34 or
        cohort_mod.MEASURED_TRANSCRIPT_POSEIDON_CALLS != 885 or
        cohort_mod.MEASURED_AUTHORITY_POSEIDON_CALLS != 14 or
        cohort_mod.MEASURED_CORE_POSEIDON_CALLS != 294 or
        cohort_mod.MEASURED_TOTAL_POSEIDON_CALLS != 1_193 or
        schedule_mod.PROVIDER_INSTANCE_COUNT != 1 or
        schedule_mod.PROVIDER_COMPONENT_INDEX != 34 or
        bundle_mod.HOT_ALL_TREES_HEAP_ALLOCATIONS != 0 or
        bundle_mod.ROW34_REPLAYED_SCALAR_PERMUTATIONS != 0)
    {
        @compileError("Segment V2 core-owner acceptance contract drifted");
    }
}
