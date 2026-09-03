const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const importer = @import("recursive_pipeline_incremental_campaign_importer_v4.zig");
const recipe_mod = @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const table_mod = @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const synthetic_count: u32 = 2;

test "two-leaf campaign table roundtrips exact path-free Stage101 refs" {
    try expectStructuralRoundtrip(synthetic_count);
}

test "three and five leaf campaign tables derive exact binary topology" {
    inline for (.{ @as(u32, 3), @as(u32, 5) }) |count|
        try expectStructuralRoundtrip(count);
}

fn expectStructuralRoundtrip(comptime count: u32) !void {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();

    const globals = try fixtureGlobals();
    var records: [count]table_mod.LeafRecordV4 = undefined;
    for (&records, 0..) |*record, ordinal|
        record.* = try fixtureRecord(
            &store,
            globals,
            @intCast(ordinal),
            count,
        );
    const table = try table_mod.CampaignTableV4.seal(.{
        .segment_count = count,
        .globals = globals,
        .records = &records,
        .content_sha256 = undefined,
    });
    const topology = try table.topology();
    const expected_padded = try std.math.ceilPowerOfTwo(u32, count);
    try std.testing.expectEqual(count, topology.leaf_count);
    try std.testing.expectEqual(expected_padded, topology.padded_leaf_count);
    try std.testing.expectEqual(expected_padded - count, topology.empty_leaf_count);
    try std.testing.expectEqual(expected_padded - 1, topology.fold_count);
    const encoded = try table_mod.encodeAlloc(allocator, &table);
    defer allocator.free(encoded);
    try std.testing.expectEqual(
        try table_mod.encodedByteCount(count),
        encoded.len,
    );
    comptime {
        if (@hasField(table_mod.LeafRecordV4, "path") or
            @hasField(table_mod.GlobalRefsV4, "path"))
        {
            @compileError("campaign table gained filesystem path authority");
        }
    }

    var decoded = try table_mod.decodeAlloc(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqualDeep(table.content_sha256, decoded.value.content_sha256);
    for (records, decoded.value.records) |expected, actual|
        try std.testing.expectEqualDeep(expected, actual);
    try table_mod.coldValidateRecipeBindings(&store, &decoded.value);
    var count_mutation = try allocator.dupe(u8, encoded);
    defer allocator.free(count_mutation);
    const count_bytes: *[4]u8 = @ptrCast(count_mutation[20..24].ptr);
    std.mem.writeInt(u32, count_bytes, count + 1, .little);
    try std.testing.expectError(
        error.IncrementalCampaignTableCodecMismatchV4,
        table_mod.decodeAlloc(allocator, count_mutation),
    );
}

test "two-leaf campaign table rejects order role codec and manifest substitution" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();

    const globals = try fixtureGlobals();
    var records: [synthetic_count]table_mod.LeafRecordV4 = undefined;
    for (&records, 0..) |*record, ordinal|
        record.* = try fixtureRecord(
            &store,
            globals,
            @intCast(ordinal),
            synthetic_count,
        );

    var mutation = records;
    std.mem.swap(
        table_mod.LeafRecordV4,
        &mutation[0],
        &mutation[1],
    );
    try expectInvalid(
        error.InvalidIncrementalCampaignTableV4,
        globals,
        &mutation,
    );

    mutation = records;
    mutation[0].stage_inputs[5].role = .witness;
    try expectInvalid(
        error.IncrementalCampaignTableInputMismatchV4,
        globals,
        &mutation,
    );

    mutation = records;
    mutation[0].stage_inputs[4].blob.schema_version = 3;
    try expectInvalid(
        error.IncrementalCampaignTableInputMismatchV4,
        globals,
        &mutation,
    );

    var substituted = globals;
    substituted.capture_manifest = try ref(.capture_transport, 4, 91);
    const resealed = try table_mod.CampaignTableV4.seal(.{
        .segment_count = synthetic_count,
        .globals = substituted,
        .records = &records,
        .content_sha256 = undefined,
    });
    try std.testing.expectError(
        error.IncrementalCampaignTableRecipeMismatchV4,
        table_mod.coldValidateRecipeBindings(&store, &resealed),
    );

    var count_mismatch = records;
    count_mismatch[0] = try fixtureRecord(&store, globals, 0, 3);
    const count_mismatch_table = try table_mod.CampaignTableV4.seal(.{
        .segment_count = synthetic_count,
        .globals = globals,
        .records = &count_mismatch,
        .content_sha256 = undefined,
    });
    try std.testing.expectError(
        error.IncrementalCampaignTableRecipeMismatchV4,
        table_mod.coldValidateRecipeBindings(&store, &count_mismatch_table),
    );
}

test "two-leaf journal payload extraction retains canonical payload bytes" {
    const allocator = std.testing.allocator;
    const first = "{\"segment_index\":0,\"value\":17}";
    const second = "{\"segment_index\":1,\"value\":19}";
    const first_digest = digest(first);
    const second_digest = digest(second);
    const first_hex = std.fmt.bytesToHex(first_digest, .lower);
    const second_hex = std.fmt.bytesToHex(second_digest, .lower);
    const journal = try std.fmt.allocPrint(
        allocator,
        "{{\"header\":1}}\n" ++
            "{{\"payload\":{s},\"content_sha256\":\"{s}\"}}\n" ++
            "{{\"payload\":{s},\"content_sha256\":\"{s}\"}}\n" ++
            "{{\"summary\":1}}\n",
        .{ first, &first_hex, second, &second_hex },
    );
    defer allocator.free(journal);
    const expected = [_][32]u8{ first_digest, second_digest };
    var payloads = try importer.extractJournalPayloadsAlloc(
        allocator,
        journal,
        &expected,
    );
    defer payloads.deinit();
    try std.testing.expectEqualStrings(first, payloads.values[0]);
    try std.testing.expectEqualStrings(second, payloads.values[1]);

    const reversed = [_][32]u8{ second_digest, first_digest };
    try std.testing.expectError(
        error.IncrementalCampaignImportJournalMismatchV4,
        importer.extractJournalPayloadsAlloc(allocator, journal, &reversed),
    );
    try std.testing.expectError(
        error.IncrementalCampaignImportJournalMismatchV4,
        importer.extractJournalPayloadsAlloc(
            allocator,
            journal[0 .. journal.len - 1],
            &expected,
        ),
    );
}

fn expectInvalid(
    expected: anyerror,
    globals: table_mod.GlobalRefsV4,
    records: []const table_mod.LeafRecordV4,
) !void {
    try std.testing.expectError(
        expected,
        table_mod.CampaignTableV4.seal(.{
            .segment_count = synthetic_count,
            .globals = globals,
            .records = records,
            .content_sha256 = undefined,
        }),
    );
}

fn fixtureRecord(
    store: *artifact_store.Store,
    globals: table_mod.GlobalRefsV4,
    segment_index: u32,
    segment_count: u32,
) !table_mod.LeafRecordV4 {
    const statement = try ref(.statement, 1, @intCast(20 + segment_index));
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
    const recipe_ref = try store.putBytes(
        .capture_transport,
        recipe_mod.SCHEMA_VERSION,
        &recipe_bytes,
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
    const byte_count: u64 = if (kind == .statement)
        @as(
            u64,
            @intCast(
                @import("ethereum_block_leaf_support.zig").source_wire.encoded_size,
            ),
        )
    else
        @as(u64, seed) + 1;
    return exactRef(kind, schema_version, byte_count, seed);
}

fn exactRef(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    byte_count: u64,
    seed: u8,
) !artifact_store.BlobRefV1 {
    var value = [_]u8{seed} ** 32;
    value[31] +%= 1;
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        byte_count,
        value,
    );
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
