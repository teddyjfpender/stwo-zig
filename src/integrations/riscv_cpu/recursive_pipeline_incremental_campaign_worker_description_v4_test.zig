const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const custody_mod =
    @import("recursive_pipeline_incremental_campaign_cold_description_v4.zig");
const description_mod =
    @import("recursive_pipeline_incremental_campaign_worker_description_v4.zig");
const receipt_mod =
    @import("recursive_pipeline_incremental_campaign_import_receipt_v4.zig");
const recipe_mod =
    @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const support = @import("ethereum_block_leaf_support.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");
const worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");

test "campaign worker description emits exact runtime-derived 2 3 and 5 leaf projections" {
    inline for (.{ @as(u32, 2), @as(u32, 3), @as(u32, 5) }) |count|
        try expectProjectionRoundtrip(count);
}

test "campaign worker description rejects row order count input and semantic drift" {
    const allocator = std.testing.allocator;
    const count: u32 = 3;
    var records: [count]table_mod.LeafRecordV4 = undefined;
    const table = try fixtureTable(count, &records);
    const custody = try fixtureCustody(allocator, &table);
    var description = try description_mod.mintAlloc(
        allocator,
        custody,
        &table,
    );
    defer description.deinit();
    const rows = @constCast(description.value.rows);

    std.mem.swap(description_mod.RowV4, &rows[0], &rows[1]);
    try expectInvalid(&description.value);
    std.mem.swap(description_mod.RowV4, &rows[0], &rows[1]);

    const full_rows = description.value.rows;
    description.value.rows = full_rows[0 .. full_rows.len - 1];
    try expectInvalid(&description.value);
    description.value.rows = full_rows;

    rows[0].recipe_ref.sha256[0] ^= 1;
    try expectInvalid(&description.value);
    rows[0].recipe_ref.sha256[0] ^= 1;

    rows[0].stage_inputs[0].blob.sha256[0] ^= 1;
    try expectInvalid(&description.value);
    rows[0].stage_inputs[0].blob.sha256[0] ^= 1;

    rows[0].local_task_identity_sha256[0] ^= 1;
    try expectInvalid(&description.value);
    rows[0].local_task_identity_sha256[0] ^= 1;

    rows[0].semantic_authorities.statement_identity_sha256[0] ^= 1;
    try expectInvalid(&description.value);
    rows[0].semantic_authorities.statement_identity_sha256[0] ^= 1;

    rows[0].campaign_namespace_sha256[0] ^= 1;
    try expectInvalid(&description.value);
    rows[0].campaign_namespace_sha256[0] ^= 1;

    description.value.campaign_namespace_sha256[0] ^= 1;
    try expectInvalid(&description.value);
    description.value.campaign_namespace_sha256[0] ^= 1;

    description.value.validation_receipt_identity_sha256[0] ^= 1;
    try expectInvalid(&description.value);
}

test "campaign worker description codec is canonical path-free and size-bounded" {
    const allocator = std.testing.allocator;
    const count: u32 = 5;
    var records: [count]table_mod.LeafRecordV4 = undefined;
    const table = try fixtureTable(count, &records);
    const custody = try fixtureCustody(allocator, &table);
    var description = try description_mod.mintAlloc(
        allocator,
        custody,
        &table,
    );
    defer description.deinit();
    const encoded = try description_mod.encodeCanonicalJsonAlloc(
        allocator,
        &description.value,
    );
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(u8, '\n'), encoded[encoded.len - 1]);
    try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '/') == null);
    try std.testing.expect(
        encoded.len <= description_mod.FIXED_CANONICAL_JSON_BYTE_COUNT +
            count * description_mod.MAX_ROW_CANONICAL_JSON_BYTE_COUNT,
    );

    var decoded = try description_mod.decodeCanonicalJsonAlloc(
        allocator,
        encoded,
    );
    defer decoded.deinit();
    try decoded.value.validateAgainstTable(allocator, &table);
    const reencoded = try description_mod.encodeCanonicalJsonAlloc(
        allocator,
        &decoded.value,
    );
    defer allocator.free(reencoded);
    try std.testing.expectEqualStrings(encoded, reencoded);

    const mutation = try allocator.dupe(u8, encoded);
    defer allocator.free(mutation);
    const digest_hex = std.fmt.bytesToHex(
        description.value.validation_receipt_identity_sha256,
        .lower,
    );
    const digest_at = std.mem.lastIndexOf(u8, mutation, &digest_hex) orelse
        return error.TestExpectedEqual;
    mutation[digest_at] = if (mutation[digest_at] == '0') '1' else '0';
    try std.testing.expectError(
        error.InvalidIncrementalCampaignWorkerDescriptionV4,
        description_mod.decodeCanonicalJsonAlloc(allocator, mutation),
    );
}

fn expectProjectionRoundtrip(comptime count: u32) !void {
    const allocator = std.testing.allocator;
    var records: [count]table_mod.LeafRecordV4 = undefined;
    const table = try fixtureTable(count, &records);
    const custody = try fixtureCustody(allocator, &table);
    var description = try description_mod.mintAlloc(
        allocator,
        custody,
        &table,
    );
    defer description.deinit();
    try std.testing.expectEqual(
        @as(usize, count),
        description.value.rows.len,
    );
    try std.testing.expect(!artifact_store.encoding.isZeroDigest(
        description.value.campaign_namespace_sha256,
    ));
    const topology = try table_mod.TopologyV4.derive(count);
    try std.testing.expectEqualDeep(topology, description.value.custody.topology);
    for (description.value.rows, table.records) |row, record| {
        try std.testing.expectEqual(record.segment_index, row.segment_index);
        try std.testing.expect(artifact_store.BlobRefV1.eql(
            record.recipe,
            row.recipe_ref,
        ));
        try std.testing.expectEqualDeep(record.stage_inputs, row.stage_inputs);
        const projection = try worker.semanticProjection(
            row.segment_index,
            count,
            &row.stage_inputs,
            description.value.campaign_namespace_sha256,
        );
        try std.testing.expectEqualDeep(
            description.value.campaign_namespace_sha256,
            row.campaign_namespace_sha256,
        );
        try std.testing.expectEqualDeep(
            description.value.campaign_namespace_sha256,
            projection.campaign_namespace_sha256,
        );
        try std.testing.expectEqualDeep(
            projection.local_task_identity_sha256,
            row.local_task_identity_sha256,
        );
        try std.testing.expectEqualDeep(
            projection.authorities,
            row.semantic_authorities,
        );
    }
}

fn expectInvalid(value: *const description_mod.DescriptionV4) !void {
    try std.testing.expectError(
        error.InvalidIncrementalCampaignWorkerDescriptionV4,
        value.validate(),
    );
}

fn fixtureTable(
    comptime count: u32,
    records: *[count]table_mod.LeafRecordV4,
) !table_mod.CampaignTableV4 {
    const globals = try fixtureGlobals();
    for (records, 0..) |*record, ordinal|
        record.* = try fixtureRecord(globals, @intCast(ordinal), count);
    return table_mod.CampaignTableV4.seal(.{
        .segment_count = count,
        .globals = globals,
        .records = records,
        .content_sha256 = undefined,
    });
}

fn fixtureCustody(
    allocator: std.mem.Allocator,
    table: *const table_mod.CampaignTableV4,
) !custody_mod.DescriptionV4 {
    const encoded = try table_mod.encodeAlloc(allocator, table);
    defer allocator.free(encoded);
    const reference = try artifact_store.BlobRefV1.create(
        table_mod.ARTIFACT_KIND,
        table_mod.CAS_SCHEMA_VERSION,
        @intCast(encoded.len),
        artifact_store.digestBytes(encoded),
    );
    const receipt = try receipt_mod.ReceiptV4.seal(.{
        .segment_count = table.segment_count,
        .table_ref = reference,
        .content_sha256 = undefined,
    });
    return custody_mod.DescriptionV4.mint(
        &receipt,
        reference,
        table.segment_count,
    );
}

fn fixtureRecord(
    globals: table_mod.GlobalRefsV4,
    segment_index: u32,
    segment_count: u32,
) !table_mod.LeafRecordV4 {
    const statement = try exactRef(
        .statement,
        1,
        support.source_wire.encoded_size,
        @intCast(20 + segment_index),
    );
    const compact = try ref(
        .capture_transport,
        1,
        @intCast(30 + segment_index),
    );
    const boundary = try ref(
        .capture_transport,
        4,
        @intCast(40 + segment_index),
    );
    const public_reference = try exactRef(
        .capture_transport,
        wire_publication.CAS_REFERENCE_SCHEMA_VERSION,
        wire_publication.reference_byte_count,
        @intCast(50 + segment_index),
    );
    const journal = try ref(.journal, 1, @intCast(60 + segment_index));
    const recipe = try recipe_mod.RecipeV4.seal(.{
        .segment_index = segment_index,
        .segment_count = segment_count,
        .statement = statement,
        .program = globals.program,
        .compact_witness = compact,
        .boundary_v4 = boundary,
        .public_wire_reference_v4 = public_reference,
        .journal_record = journal,
        .raw_input = globals.raw_input,
        .expected_output = globals.expected_output,
        .boundary_manifest_v4 = globals.capture_manifest,
        .public_wire_manifest_v4 = globals.public_wire_manifest,
        .content_sha256 = undefined,
    });
    const recipe_bytes = try recipe_mod.encode(&recipe);
    const recipe_ref = try artifact_store.BlobRefV1.create(
        .capture_transport,
        recipe_mod.SCHEMA_VERSION,
        recipe_bytes.len,
        artifact_store.digestBytes(&recipe_bytes),
    );
    const result = table_mod.LeafRecordV4{
        .segment_index = segment_index,
        .recipe = recipe_ref,
        .stage_inputs = .{
            input(.statement, 0, statement),
            input(.program, 0, globals.program),
            input(.profile, 0, recipe_ref),
            input(.witness, 0, compact),
            input(.capture, 0, boundary),
            input(.capture, 1, public_reference),
            input(.journal, 0, journal),
        },
    };
    try result.validate(@intCast(segment_index), globals);
    return result;
}

fn fixtureGlobals() !table_mod.GlobalRefsV4 {
    return .{
        .capture_manifest = try ref(.capture_transport, 4, 1),
        .public_wire_manifest = try ref(
            .capture_transport,
            wire_publication.CAS_MANIFEST_SCHEMA_VERSION,
            2,
        ),
        .compact_manifest = try ref(
            .capture_transport,
            table_mod.COMPACT_MANIFEST_CAS_SCHEMA_VERSION,
            3,
        ),
        .execution_profile_receipt = try ref(.profile_receipt, 1, 4),
        .materialization_result = try ref(
            .source,
            table_mod.MATERIALIZATION_CAS_SCHEMA_VERSION,
            5,
        ),
        .source_request = try ref(.source, 1, 6),
        .execution_journal = try ref(
            .journal,
            table_mod.FULL_JOURNAL_CAS_SCHEMA_VERSION,
            7,
        ),
        .program = try ref(.program, 1, 8),
        .raw_input = try ref(.raw, 1, 9),
        .expected_output = try ref(.raw, 1, 10),
    };
}

fn input(
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    blob: artifact_store.BlobRefV1,
) artifact_store.InputRefV1 {
    return .{ .role = role, .ordinal = ordinal, .blob = blob };
}

fn ref(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    seed: u8,
) !artifact_store.BlobRefV1 {
    return exactRef(kind, schema_version, @as(u64, seed) + 1, seed);
}

fn exactRef(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    byte_count: u64,
    seed: u8,
) !artifact_store.BlobRefV1 {
    var digest = [_]u8{seed} ** 32;
    digest[31] +%= 1;
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        byte_count,
        digest,
    );
}
