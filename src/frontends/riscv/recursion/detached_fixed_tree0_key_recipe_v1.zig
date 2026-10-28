//! Proof-free reconstruction of detached leaf Tree0 families completed so far.
//! Inputs are admitted key geometry and protocol constants, never native
//! witness values, proof bytes, or producer receipts.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const framework = @import("air/framework_interaction.zig");
const range = @import("air/range_check_8_8_bridge.zig");
const statement = @import("segment_statement_outer_source_v2_contract.zig");
const statement_rows = @import("segment_statement_outer_source_v2_prepared_v2.zig");
const wire_layout = @import("segment_statement_v2_transcript_layout.zig");
const leaf_source = @import("segment_leaf_authority_v2.zig");
const provider_shape = @import("air/segment_publication_input_provider_shape_v2.zig");

/// The frozen statement-input adapter is explicitly inactive in SegmentV2.
/// Its physical Tree0 columns are present and must all be zero.
pub fn fillInactiveStatementInputRow(
    manifest: *const manifest_mod.Manifest,
    columns: *[@import("air/statement_input.zig").PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try manifest.validate();
    const placement = manifest.placements[10] orelse return error.InvalidFixedStatementGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size != @import("segment_statement_outer_components_v2.zig").ROW10_LOG_SIZE)
        return error.InvalidFixedStatementGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| {
        if (column.len != size) return error.InvalidFixedStatementGeometry;
        @memset(column, M31.zero());
    }
}

/// Boundary row 36 publishes the wire followed by the fixed-size context.
/// Only the values live in Tree 1; the Tree 0 selectors follow from the key's
/// admitted wire length and cannot be supplied by a proof or capture.
pub fn fillBoundaryStatementRow(
    manifest: *const manifest_mod.Manifest,
    wire_word_count: u32,
    columns: *[3][]M31,
) !void {
    try manifest.validate();
    const placement = manifest.placements[36] orelse return error.InvalidFixedBoundaryGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedBoundaryGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    const wire_words: usize = wire_word_count;
    const logical = std.math.add(usize, wire_words, leaf_source.CONTEXT_WORD_COUNT) catch
        return error.InvalidFixedBoundaryGeometry;
    if (logical > size or logical <= size / 2) return error.InvalidFixedBoundaryGeometry;
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedBoundaryGeometry;
    for (columns) |column| @memset(column, M31.zero());
    for (0..logical) |index| {
        const committed = framework.committedRow(index, placement.geometry.log_size);
        columns[0][committed] = M31.one();
        columns[1][committed] = M31.fromCanonical(if (index < wire_words)
            leaf_source.WIRE_SCOPE
        else
            leaf_source.CONTEXT_SCOPE);
        columns[2][committed] = M31.fromCanonical(@intCast(if (index < wire_words)
            index
        else
            index - wire_words));
    }
}

pub fn fillBoundaryPublicLogupRow(
    manifest: *const manifest_mod.Manifest,
    columns: *[2][]M31,
) !void {
    try manifest.validate();
    const placement = manifest.placements[37] orelse return error.InvalidFixedBoundaryGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedBoundaryGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    if (provider_shape.LUP2_WORD_COUNT > size or
        provider_shape.LUP2_WORD_COUNT <= size / 2)
        return error.InvalidFixedBoundaryGeometry;
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedBoundaryGeometry;
    for (columns) |column| @memset(column, M31.zero());
    for (0..provider_shape.LUP2_WORD_COUNT) |index| {
        const committed = framework.committedRow(index, placement.geometry.log_size);
        columns[0][committed] = M31.one();
        columns[1][committed] = M31.fromCanonical(@intCast(index));
    }
}

pub fn fillPublicationInputProviderRow(
    manifest: *const manifest_mod.Manifest,
    columns: *[4][]M31,
) !void {
    try manifest.validate();
    const placement = manifest.placements[38] orelse return error.InvalidFixedProviderGeometry;
    if (placement.geometry.preprocessed_columns != columns.len or
        placement.geometry.log_size != provider_shape.TRACE_LOG_SIZE)
        return error.InvalidFixedProviderGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedProviderGeometry;
    for (columns) |column| @memset(column, M31.zero());
    for (0..provider_shape.LUP2_WORD_COUNT) |index| {
        columns[0][index] = M31.one();
        columns[1][index] = M31.one();
        columns[2][index] = M31.fromCanonical(@intCast(index));
    }
}

pub fn fillStatementRow(
    manifest: *const manifest_mod.Manifest,
    retained_counts: [wire_layout.SECTIONS.len]u32,
    columns: *[statement.Air.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try manifest.validate();
    const layout = try wire_layout.Layout.init(retained_counts);
    const placement = manifest.placements[11] orelse return error.InvalidFixedStatementGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    const logical = statement.HEADER_LIMB_COUNT + layout.total_words +
        @import("segment_leaf_authority_v2.zig").CONTEXT_WORD_COUNT;
    if (placement.geometry.preprocessed_columns != columns.len or
        logical > size or logical <= size / 2)
        return error.InvalidFixedStatementGeometry;
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedStatementGeometry;
    for (columns) |column| @memset(column, M31.zero());
    for (0..logical) |index| {
        const values = (try statement_rows.preprocessingAt(&layout, index)).values();
        const committed = framework.committedRow(index, placement.geometry.log_size);
        for (columns, values) |column, value| column[committed] = value;
    }
}

pub fn fillPoseidonFirst(manifest: *const manifest_mod.Manifest, column: []M31) !void {
    try manifest.validate();
    const placement = manifest.placements[34] orelse return error.InvalidFixedProviderGeometry;
    if (placement.geometry.preprocessed_columns != 1 or
        column.len != @as(usize, 1) << @intCast(placement.geometry.log_size))
        return error.InvalidFixedProviderGeometry;
    @memset(column, M31.zero());
    column[framework.committedRow(0, placement.geometry.log_size)] = M31.one();
}

pub fn fillRangeTable(manifest: *const manifest_mod.Manifest, columns: *[3][]M31) !void {
    try manifest.validate();
    const placement = manifest.placements[35] orelse return error.InvalidFixedProviderGeometry;
    if (placement.geometry.preprocessed_columns != 3 or
        placement.geometry.log_size != range.LOG_SIZE)
        return error.InvalidFixedProviderGeometry;
    for (columns) |column| if (column.len != range.TABLE_SIZE)
        return error.InvalidFixedProviderGeometry;
    for (columns) |column| @memset(column, M31.zero());
    columns[0][0] = M31.one();
    for (0..range.TABLE_SIZE) |logical| {
        const row = range.committedRow(logical);
        columns[1][row] = M31.fromCanonical(@intCast(logical & 0xff));
        columns[2][row] = M31.fromCanonical(@intCast(logical >> 8));
    }
}

fn censusDigest(columns: []const []const M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, column.len, .little);
        hash.update(&bytes);
        for (column) |word| {
            var field: [4]u8 = undefined;
            std.mem.writeInt(u32, &field, word.toU32(), .little);
            hash.update(&field);
        }
    }
    return hash.finalResult();
}

test "Tree0 rows 11 34 and 35 regenerate from key geometry and match production census" {
    const allocator = std.testing.allocator;
    // A current manifest is generated by the same typed catalog used for
    // admitted keys; the pinned digests below come from an actual q193 leaf.
    const profile = @import("detached_segment_protocol_fixture_v1.zig");
    inline for (.{
        .{ .counts = [4]u32{ 16, 16, 0, 11 }, .digest = "6046533df3c32ae03a8caf2ee1d755a4c839b395cd7ba1aebc78d6f5dcdb48e3" },
        .{ .counts = [4]u32{ 16, 16, 16, 16 }, .digest = "c69c443febd342950920e43df0f81c5652c283bd0d3a3a10fef31e85767354d5" },
    }) |case| {
        const layout = try wire_layout.Layout.init(case.counts);
        const key = try profile.testing.keyWithPoseidonLog(layout.total_words, 1, 16);
        const size = @as(usize, 1) << @intCast(key.manifest.placements[11].?.geometry.log_size);
        var statement_columns: [statement.Air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&statement_columns) |*column| column.* = try allocator.alloc(M31, size);
        defer for (statement_columns) |column| allocator.free(column);
        try fillStatementRow(&key.manifest, case.counts, &statement_columns);
        var statement_view: [statement.Air.PREPROCESSED_COLUMN_COUNT][]const M31 = undefined;
        for (&statement_view, statement_columns) |*target, column| target.* = column;
        var expected_statement: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_statement, case.digest);
        try std.testing.expectEqual(expected_statement, censusDigest(&statement_view));
    }

    const key = try profile.testing.keyWithPoseidonLog(1000, 1, 16);

    const poseidon = try allocator.alloc(M31, @as(usize, 1) << 16);
    defer allocator.free(poseidon);
    try fillPoseidonFirst(&key.manifest, poseidon);
    const poseidon_columns: [1][]const M31 = .{poseidon};
    var expected_poseidon: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_poseidon, "f6f8b08ada99b6065fd82b4afeba5e12f21693318865788702e11861b619f9fb");
    try std.testing.expectEqual(expected_poseidon, censusDigest(&poseidon_columns));

    var range_columns: [3][]M31 = undefined;
    for (&range_columns) |*column| column.* = try allocator.alloc(M31, range.TABLE_SIZE);
    defer for (range_columns) |column| allocator.free(column);
    try fillRangeTable(&key.manifest, &range_columns);
    const range_view: [3][]const M31 = .{ range_columns[0], range_columns[1], range_columns[2] };
    var expected_range: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_range, "72447854d4ba84f6eed889db85f0ee0d6c5529d2d1e80420f6e35f06e1173ffa");
    try std.testing.expectEqual(expected_range, censusDigest(&range_view));
}

test "Tree0 boundary and input-provider rows regenerate without a proof" {
    const allocator = std.testing.allocator;
    const fixture = @import("detached_segment_protocol_fixture_v1.zig");
    const counts = [4]u32{ 16, 16, 0, 11 };
    const layout = try wire_layout.Layout.init(counts);
    const key = try fixture.testing.keyWithPoseidonLog(layout.total_words, 1, 16);

    const statement_size = @as(usize, 1) << @intCast(key.manifest.placements[36].?.geometry.log_size);
    var statement_columns: [3][]M31 = undefined;
    for (&statement_columns) |*column| column.* = try allocator.alloc(M31, statement_size);
    defer for (statement_columns) |column| allocator.free(column);
    try fillBoundaryStatementRow(&key.manifest, key.source_manifest.wire_word_count, &statement_columns);
    const statement_view: [3][]const M31 = .{ statement_columns[0], statement_columns[1], statement_columns[2] };
    var statement_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&statement_digest, "5b293baf5e2b462fc439b6be3767646198fedf1551ebad2de54f528c33d63dd0");
    try std.testing.expectEqual(statement_digest, censusDigest(&statement_view));

    const public_size = @as(usize, 1) << @intCast(key.manifest.placements[37].?.geometry.log_size);
    var public_columns: [2][]M31 = undefined;
    for (&public_columns) |*column| column.* = try allocator.alloc(M31, public_size);
    defer for (public_columns) |column| allocator.free(column);
    try fillBoundaryPublicLogupRow(&key.manifest, &public_columns);
    const public_view: [2][]const M31 = .{ public_columns[0], public_columns[1] };
    var public_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&public_digest, "c31f93a8fca7c0e971ba1e41d6391079624d4500ef601d89b1aa7750130aa1b7");
    try std.testing.expectEqual(public_digest, censusDigest(&public_view));

    const provider_size = @as(usize, 1) << @intCast(key.manifest.placements[38].?.geometry.log_size);
    var provider_columns: [4][]M31 = undefined;
    for (&provider_columns) |*column| column.* = try allocator.alloc(M31, provider_size);
    defer for (provider_columns) |column| allocator.free(column);
    try fillPublicationInputProviderRow(&key.manifest, &provider_columns);
    const provider_view: [4][]const M31 = .{
        provider_columns[0], provider_columns[1], provider_columns[2], provider_columns[3],
    };
    var provider_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&provider_digest, "9521e69b5d76b96992de73cbb1502770d0443681cce35799222f65b8bfa402c0");
    try std.testing.expectEqual(provider_digest, censusDigest(&provider_view));
}
