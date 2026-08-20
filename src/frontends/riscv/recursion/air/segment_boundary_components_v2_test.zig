const std = @import("std");
const stwo_core = @import("stwo_core");
const subject = @import("segment_boundary_components_v2.zig");
const manifest = @import("segment_outer_adapter_manifest_v2.zig");
const catalog = @import("segment_outer_typed_catalog_v2.zig");
const universal_manifest = @import("universal_manifest.zig");
const universal_roster = @import("universal_roster.zig");
const row17_witness_v2 =
    @import("vm_public_logup_control_witness_v2.zig");
const range_bridge = @import("range_check_8_8_bridge.zig");
const authority = @import("../segment_leaf_outer_authority_v2.zig");
const boundary_air = @import("../segment_leaf_outer_air_v2.zig");

const M31 = stwo_core.fields.m31.M31;

test "V2 boundary adapters occupy only appended manifest indices" {
    const statement = subject.StatementAdapter.manifestGeometry(
        .statement_source_v2,
        8,
    );
    const public_logup = subject.PublicLogUpAdapter.manifestGeometry(
        .public_logup_source_v2,
        6,
    );
    try std.testing.expectEqual(manifest.STATEMENT_SOURCE_INDEX, statement.roster_row);
    try std.testing.expectEqual(
        manifest.PUBLIC_LOGUP_SOURCE_INDEX,
        public_logup.roster_row,
    );
    try std.testing.expectEqual(@as(usize, 0), subject.HOT_HEAP_ALLOCATIONS);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
}

test "boundary Tree 0 1 and 2 source descriptors retain exact manifest geometry" {
    const statement_log_size: u8 = 8;
    const complete_manifest = try fixtureManifest(statement_log_size);
    const statement_rows: usize = @as(usize, 1) << statement_log_size;
    const public_rows: usize = authority.PUBLIC_LOGUP_TRACE_ROWS;

    var statement_preprocessed: [boundary_air.Statement.PREPROCESSED_COLUMN_COUNT][statement_rows]M31 = undefined;
    var statement_main: [boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT][statement_rows]M31 = undefined;
    var statement_interaction: [boundary_air.Statement.INTERACTION_COLUMN_COUNT][statement_rows]M31 = undefined;
    var public_preprocessed: [boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT][public_rows]M31 = undefined;
    var public_main: [boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][public_rows]M31 = undefined;
    var public_interaction: [boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT][public_rows]M31 = undefined;
    inline for (.{
        &statement_preprocessed,
        &statement_main,
        &statement_interaction,
        &public_preprocessed,
        &public_main,
        &public_interaction,
    }) |columns| for (columns) |*column| @memset(column, M31.one());

    const traces = authority.TracesV2{
        .statement = .{
            .preprocessed = columnSlices(&statement_preprocessed),
            .main = columnSlices(&statement_main),
            .interaction = columnSlices(&statement_interaction),
        },
        .public_logup = .{
            .preprocessed = columnSlices(&public_preprocessed),
            .main = columnSlices(&public_main),
            .interaction = columnSlices(&public_interaction),
        },
    };
    inline for (.{
        manifest.PREPROCESSED_TREE_INDEX,
        manifest.MAIN_TREE_INDEX,
        manifest.INTERACTION_TREE_INDEX,
    }) |tree_index| try expectExactTreeCopy(
        &complete_manifest,
        &traces,
        tree_index,
    );
}

fn expectExactTreeCopy(
    complete_manifest: *const manifest.Manifest,
    traces: *const authority.TracesV2,
    tree_index: usize,
) !void {
    const column_count: usize = switch (tree_index) {
        manifest.PREPROCESSED_TREE_INDEX => complete_manifest.total_preprocessed_columns,
        manifest.MAIN_TREE_INDEX => complete_manifest.total_main_columns,
        manifest.INTERACTION_TREE_INDEX => complete_manifest.total_interaction_columns,
        else => unreachable,
    };
    const destination = try std.testing.allocator.alloc([]M31, column_count);
    defer std.testing.allocator.free(destination);
    for (destination) |*column| column.* = @constCast((&[_]M31{})[0..]);

    const statement = try complete_manifest.placement(.statement_source_v2);
    const public_logup = try complete_manifest.placement(.public_logup_source_v2);
    const statement_sources: []const []M31 = switch (tree_index) {
        manifest.PREPROCESSED_TREE_INDEX => &traces.statement.preprocessed,
        manifest.MAIN_TREE_INDEX => &traces.statement.main,
        manifest.INTERACTION_TREE_INDEX => &traces.statement.interaction,
        else => unreachable,
    };
    const public_sources: []const []M31 = switch (tree_index) {
        manifest.PREPROCESSED_TREE_INDEX => &traces.public_logup.preprocessed,
        manifest.MAIN_TREE_INDEX => &traces.public_logup.main,
        manifest.INTERACTION_TREE_INDEX => &traces.public_logup.interaction,
        else => unreachable,
    };
    const statement_offset = treeOffset(statement, tree_index);
    const public_offset = treeOffset(public_logup, tree_index);
    const statement_rows = @as(usize, 1) << @intCast(statement.geometry.log_size);
    const public_rows = @as(usize, 1) << @intCast(public_logup.geometry.log_size);
    const target_word_count = statement_sources.len * statement_rows +
        public_sources.len * public_rows;
    const target_storage = try std.testing.allocator.alloc(M31, target_word_count);
    defer std.testing.allocator.free(target_storage);
    @memset(target_storage, M31.zero());
    var cursor: usize = 0;
    for (destination[statement_offset..][0..statement_sources.len]) |*column| {
        column.* = target_storage[cursor..][0..statement_rows];
        cursor += statement_rows;
    }
    for (destination[public_offset..][0..public_sources.len]) |*column| {
        column.* = target_storage[cursor..][0..public_rows];
        cursor += public_rows;
    }
    try std.testing.expectEqual(target_storage.len, cursor);

    // These are the exact invariants that failed when `sourceColumns`
    // returned descriptors borrowed from its expired by-value parameter.
    for (
        statement_sources,
        destination[statement_offset..][0..statement_sources.len],
    ) |source, target| {
        try std.testing.expectEqual(statement_rows, source.len);
        try std.testing.expectEqual(statement_rows, target.len);
    }
    for (
        public_sources,
        destination[public_offset..][0..public_sources.len],
    ) |source, target| {
        try std.testing.expectEqual(public_rows, source.len);
        try std.testing.expectEqual(public_rows, target.len);
    }

    try subject.fillTreeInto(
        complete_manifest,
        traces.*,
        tree_index,
        destination,
    );
    for (
        statement_sources,
        destination[statement_offset..][0..statement_sources.len],
    ) |source, target|
        try expectM31SlicesEqual(source, target);
    for (
        public_sources,
        destination[public_offset..][0..public_sources.len],
    ) |source, target|
        try expectM31SlicesEqual(source, target);
}

fn fixtureManifest(statement_log_size: u8) !manifest.Manifest {
    const logs = fixtureLogSizes();
    const typed_catalog = try catalog.build(
        logs,
        boundaryComponents(statement_log_size),
    );
    return manifest.assemble(&typed_catalog, .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
    });
}

fn fixtureLogSizes() universal_manifest.LogSizes {
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

fn boundaryComponents(
    statement_log_size: u8,
) [authority.COMPONENT_COUNT]authority.ComponentGeometryV2 {
    return .{
        .{
            .kind = .statement_source,
            .component_tag = authority.STATEMENT_COMPONENT_TAG,
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
            .component_tag = authority.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = authority.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = authority.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = authority.PUBLIC_LOGUP_TRACE_ROWS,
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

fn columnSlices(storage: anytype) [@typeInfo(@TypeOf(storage.*)).array.len][]M31 {
    var result: [@typeInfo(@TypeOf(storage.*)).array.len][]M31 = undefined;
    for (&result, storage) |*slice, *column| slice.* = column[0..];
    return result;
}

fn treeOffset(placement: manifest.Placement, tree_index: usize) usize {
    return switch (tree_index) {
        manifest.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest.MAIN_TREE_INDEX => placement.main_offset,
        manifest.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn expectM31SlicesEqual(left: []const M31, right: []const M31) !void {
    try std.testing.expectEqual(left.len, right.len);
    for (left, right) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));
}

fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
