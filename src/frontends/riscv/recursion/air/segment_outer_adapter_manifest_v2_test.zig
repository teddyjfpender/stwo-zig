const std = @import("std");

const subject = @import("segment_outer_adapter_manifest_v2.zig");
const catalog_mod = @import("segment_outer_typed_catalog_v2.zig");
const universal_manifest = @import("universal_manifest.zig");
const universal_roster = @import("universal_roster.zig");
const typed_component = @import("universal_typed_component.zig");
const statement_v2 = @import("../segment_statement_outer_source_v2.zig");
const public_air_v2 = @import("segment_public_outer_air_v2.zig");
const row17_air_v2 = @import("vm_public_logup_control_v2.zig");
const row17_witness_v2 = @import("vm_public_logup_control_witness_v2.zig");
const boundary_air = @import("../segment_leaf_outer_air_v2.zig");
const boundary_manifest = @import("../segment_leaf_outer_authority_v2.zig");
const provider_air = @import("segment_publication_input_provider_v2.zig");
const provider_authority =
    @import("../segment_publication_input_provider_authority_v2.zig");
const range_bridge = @import("range_check_8_8_bridge.zig");
const shared_provider = @import("universal_shared_provider.zig");

const StatementRelation = struct {
    pub const Runtime = boundary_air.Statement.Runtime;
};

test "V2 catalog append-fixes all 39 rows without moving rows zero through 37" {
    const log_sizes = fixtureLogSizes();
    const universal = try universal_manifest.build(log_sizes);
    const catalog = try fixtureCatalog(log_sizes);
    const manifest = try subject.assemble(&catalog, authorityIds());
    try manifest.validate();

    try std.testing.expectEqual(
        @as(u8, subject.COMPONENT_COUNT),
        manifest.roster_count,
    );
    for (manifest.roster_rows, 0..) |row, ordinal| {
        try std.testing.expectEqual(@as(u8, @intCast(ordinal)), row);
        const placement = manifest.placements[row].?;
        try std.testing.expectEqual(row, placement.geometry.roster_row);
        try std.testing.expectEqual(row, placement.claimed_sum_index);
        if ((catalog_mod.V1_AUTHORITY_UNCHANGED_MASK & componentBit(row)) != 0) {
            try std.testing.expectEqualDeep(
                universal.placements[row].?.geometry,
                placement.geometry,
            );
        }
    }
    // The final provider log is sized from the combined authenticated call
    // stream (294 core + 885 transcript + 14 statement = 1,193), not from the
    // core-only prefix. Its AIR identity and column geometry remain V1-exact.
    try std.testing.expectEqual(
        @as(u32, 11),
        manifest.placements[@intFromEnum(universal_roster.Component.poseidon2)].?.geometry.log_size,
    );

    // V2 transcript rows retain the exact typed-program identities.
    for (0..10) |row| {
        try std.testing.expectEqualSlices(
            u8,
            &universal.placements[row].?.geometry.semantic_digest,
            &manifest.placements[row].?.geometry.semantic_digest,
        );
    }
    const statement_source = manifest.placements[subject.STATEMENT_SOURCE_INDEX].?;
    const public_source = manifest.placements[subject.PUBLIC_LOGUP_SOURCE_INDEX].?;
    const provider = manifest.placements[subject.VERIFIER_INPUT_PROVIDER_INDEX].?;
    try std.testing.expectEqual(
        subject.STATEMENT_SOURCE_INDEX,
        statement_source.claimed_sum_index,
    );
    try std.testing.expectEqual(
        subject.PUBLIC_LOGUP_SOURCE_INDEX,
        public_source.claimed_sum_index,
    );
    try std.testing.expectEqual(
        statement_source.preprocessed_offset +
            statement_source.geometry.preprocessed_columns,
        public_source.preprocessed_offset,
    );
    try std.testing.expectEqual(
        subject.VERIFIER_INPUT_PROVIDER_INDEX,
        provider.claimed_sum_index,
    );
    try std.testing.expectEqual(
        public_source.preprocessed_offset +
            public_source.geometry.preprocessed_columns,
        provider.preprocessed_offset,
    );
    try std.testing.expectEqual(
        public_source.main_offset + public_source.geometry.main_columns,
        provider.main_offset,
    );
    try std.testing.expectEqual(
        public_source.interaction_offset +
            public_source.geometry.interaction_columns,
        provider.interaction_offset,
    );
    try std.testing.expectEqual(
        public_source.constraint_offset +
            public_source.geometry.direct_constraints +
            public_source.geometry.interaction_batches,
        provider.constraint_offset,
    );
    try std.testing.expectEqual(
        provider_authority.TRACE_LOG_SIZE,
        provider.geometry.log_size,
    );
    try std.testing.expectEqual(
        provider_air.PREPROCESSED_COLUMN_COUNT,
        provider.geometry.preprocessed_columns,
    );
    try std.testing.expectEqual(
        provider_air.PHYSICAL_MAIN_COLUMN_COUNT,
        provider.geometry.main_columns,
    );
    try std.testing.expectEqual(
        provider_air.INTERACTION_COLUMN_COUNT,
        provider.geometry.interaction_columns,
    );
    try std.testing.expectEqualSlices(
        u8,
        &provider_air.SEMANTIC_DIGEST,
        &provider.geometry.semantic_digest,
    );
}

test "authority changed unchanged and appended masks are exact and disjoint" {
    const expected_changed = rangeMask(10, 18);
    const expected_unchanged = rangeMask(0, 10) | rangeMask(18, 36);
    const expected_appended = rangeMask(36, 38);
    const expected_provider = componentBit(38);
    try std.testing.expectEqual(
        expected_changed,
        catalog_mod.V2_AUTHORITY_CHANGED_MASK,
    );
    try std.testing.expectEqual(
        expected_unchanged,
        catalog_mod.V1_AUTHORITY_UNCHANGED_MASK,
    );
    try std.testing.expectEqual(
        expected_appended,
        catalog_mod.APPENDED_SOURCE_MASK,
    );
    try std.testing.expectEqual(
        expected_provider,
        catalog_mod.APPENDED_PROVIDER_MASK,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        expected_changed & expected_unchanged |
            expected_changed & expected_appended |
            expected_changed & expected_provider |
            expected_unchanged & expected_appended |
            expected_unchanged & expected_provider |
            expected_appended & expected_provider,
    );
    try std.testing.expectEqual(
        catalog_mod.ALL_COMPONENT_MASK,
        expected_changed | expected_unchanged | expected_appended |
            expected_provider,
    );

    const log_sizes = fixtureLogSizes();
    const universal = try universal_manifest.build(log_sizes);
    const catalog = try fixtureCatalog(log_sizes);
    // Row 10 is classified by its explicit V2 inactive table entry, never by
    // whether its current raw geometry happens to equal the frozen V1 row.
    try std.testing.expectEqual(
        catalog_mod.Activation.explicitly_inactive,
        catalog.entries[10].activation,
    );
    for (11..18) |row| {
        try std.testing.expect(!std.mem.eql(
            u8,
            &universal.placements[row].?.geometry.semantic_digest,
            &catalog.entries[row].geometry.semantic_digest,
        ));
    }
}

test "rows 10 through 17 consume their exact V2 typed authorities" {
    const catalog = try fixtureCatalog(fixtureLogSizes());
    try expectOverride(catalog.entries[10], statement_v2.COMPONENT_OVERRIDE_TABLE_V2[0]);
    try expectOverride(catalog.entries[11], statement_v2.COMPONENT_OVERRIDE_TABLE_V2[1]);
    inline for (public_air_v2.COMPONENT_OVERRIDE_TABLE_V2[0..5], 0..) |item, index|
        try expectOverride(catalog.entries[12 + index], item);

    const row17 = catalog.entries[17].geometry;
    try std.testing.expectEqual(row17_witness_v2.TRACE_LOG_SIZE, row17.log_size);
    try std.testing.expectEqual(
        row17_air_v2.PREPROCESSED_COLUMN_COUNT,
        row17.preprocessed_columns,
    );
    try std.testing.expectEqual(
        row17_air_v2.PHYSICAL_MAIN_COLUMN_COUNT,
        row17.main_columns,
    );
    try std.testing.expectEqual(
        row17_air_v2.INTERACTION_COLUMN_COUNT,
        row17.interaction_columns,
    );
    try std.testing.expectEqual(
        row17_air_v2.DIRECT_CONSTRAINT_COUNT,
        row17.direct_constraints,
    );
    try std.testing.expectEqual(
        row17_air_v2.INTERACTION_BATCH_COUNT,
        row17.interaction_batches,
    );
    try std.testing.expectEqualSlices(
        u8,
        &row17_air_v2.SEMANTIC_DIGEST,
        &row17.semantic_digest,
    );
}

test "catalog manifest ordering claims identities and geometry reject mutation" {
    const catalog = try fixtureCatalog(fixtureLogSizes());
    const manifest = try subject.assemble(&catalog, authorityIds());

    var bad_entry = catalog;
    bad_entry.entries[12].geometry.semantic_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCatalogGeometry,
        bad_entry.validate(),
    );

    var bad_row17 = catalog;
    bad_row17.entries[17].geometry.log_size -= 1;
    try std.testing.expectError(
        error.InvalidCatalogGeometry,
        bad_row17.validate(),
    );

    var bad_activation = catalog;
    bad_activation.entries[10].activation = .active_v2_override;
    try std.testing.expectError(
        error.InvalidCatalogEntry,
        bad_activation.validate(),
    );

    var bad_catalog_identity = catalog;
    bad_catalog_identity.identity[0] ^= 1;
    try std.testing.expectError(
        error.CatalogIdentityMismatch,
        bad_catalog_identity.validate(),
    );

    var bad_order = manifest;
    bad_order.roster_rows[38] = 37;
    try std.testing.expectError(error.RosterOrderMismatch, bad_order.validate());

    var bad_claim_index = manifest;
    bad_claim_index.placements[17].?.claimed_sum_index = 16;
    try std.testing.expectError(
        error.ManifestSealMismatch,
        bad_claim_index.validate(),
    );

    var bad_source_id = manifest;
    bad_source_id.public_manifest_id[0] += 1;
    try std.testing.expectError(
        error.ManifestSealMismatch,
        bad_source_id.validate(),
    );

    var bad_provider_id = manifest;
    bad_provider_id.provider_authority_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.ManifestSealMismatch,
        bad_provider_id.validate(),
    );

    var bad_provider_geometry = catalog;
    bad_provider_geometry.entries[38].geometry.log_size -= 1;
    try std.testing.expectError(
        error.InvalidCatalogGeometry,
        bad_provider_geometry.validate(),
    );

    var bad_manifest_catalog = manifest;
    bad_manifest_catalog.catalog_identity[0] ^= 1;
    try std.testing.expectError(
        error.CatalogIdentityMismatch,
        bad_manifest_catalog.validate(),
    );
}

test "generic typed adapter accepts the V2 manifest contract without a copy" {
    const Adapter = typed_component.ComponentForManifest(
        boundary_air.Statement,
        StatementRelation,
        subject,
    );
    const geometry = Adapter.manifestGeometry(.statement_source_v2, 8);
    try geometry.validateForComponentCount(subject.COMPONENT_COUNT);
    try std.testing.expectEqual(
        subject.STATEMENT_SOURCE_INDEX,
        geometry.roster_row,
    );
    try std.testing.expectEqual(
        boundary_air.Statement.INTERACTION_COLUMN_COUNT,
        geometry.interaction_columns,
    );
}

test "native provider adapters retain their exact V1 identities" {
    const Poseidon = shared_provider.Poseidon2AdapterForManifest(subject);
    const Range = shared_provider.RangeCheck8x8AdapterForManifest(subject);
    const poseidon = Poseidon.manifestGeometry(7);
    const range = Range.manifestGeometry();
    try poseidon.validateForComponentCount(subject.COMPONENT_COUNT);
    try range.validateForComponentCount(subject.COMPONENT_COUNT);
    try std.testing.expectEqual(
        @as(u8, @intFromEnum(universal_roster.Component.poseidon2)),
        poseidon.roster_row,
    );
    try std.testing.expectEqual(
        @as(u8, @intFromEnum(universal_roster.Component.range_check_8_8)),
        range.roster_row,
    );
    try std.testing.expectEqualSlices(
        u8,
        &shared_provider.POSEIDON_SOURCE_AUTHORITY_DIGEST,
        &poseidon.semantic_digest,
    );
    try std.testing.expectEqualSlices(
        u8,
        &range_bridge.BINDING_DIGEST,
        &range.semantic_digest,
    );
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

fn fixtureCatalog(
    log_sizes: universal_manifest.LogSizes,
) !catalog_mod.Catalog {
    return catalog_mod.build(log_sizes, boundaryComponents(8));
}

fn boundaryComponents(
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

fn authorityIds() subject.AuthorityIds {
    return .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
        .provider_authority_sha_id = provider_authority.sourceAuthorityShaId(),
    };
}

fn expectOverride(entry: catalog_mod.Entry, item: anytype) !void {
    try std.testing.expectEqual(item.component_index, entry.component_index);
    try std.testing.expectEqual(item.preprocessed_columns, entry.geometry.preprocessed_columns);
    try std.testing.expectEqual(item.main_columns, entry.geometry.main_columns);
    try std.testing.expectEqual(item.interaction_columns, entry.geometry.interaction_columns);
    try std.testing.expectEqual(item.direct_constraints, entry.geometry.direct_constraints);
    try std.testing.expectEqual(item.interaction_batches, entry.geometry.interaction_batches);
    try std.testing.expectEqual(item.protocol_constraint_degree, entry.geometry.protocol_constraint_degree);
    try std.testing.expectEqual(item.profiled_constraint_degree, entry.geometry.profiled_constraint_degree);
    try std.testing.expectEqualSlices(
        u8,
        &item.semantic_digest,
        &entry.geometry.semantic_digest,
    );
}

fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn rangeMask(comptime first: usize, comptime end: usize) u64 {
    var result: u64 = 0;
    inline for (first..end) |row| result |= componentBit(row);
    return result;
}

fn componentBit(row: anytype) u64 {
    return @as(u64, 1) << @intCast(row);
}
