const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const command =
    @import("recursive_pipeline_incremental_campaign_import_command_v4.zig");
const ethereum_policy =
    @import("recursive_pipeline_incremental_campaign_ethereum_policy_v4.zig");
const receipt_mod =
    @import("recursive_pipeline_incremental_campaign_import_receipt_v4.zig");
const table =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");

test "campaign import receipt is canonical and path-free" {
    const segment_count: u32 = 5;
    const table_ref = try artifact_store.BlobRefV1.create(
        table.ARTIFACT_KIND,
        table.CAS_SCHEMA_VERSION,
        @intCast(try table.encodedByteCount(segment_count)),
        [_]u8{0x7b} ** 32,
    );
    const receipt = try receipt_mod.ReceiptV4.seal(.{
        .segment_count = segment_count,
        .table_ref = table_ref,
        .content_sha256 = undefined,
    });
    const encoded = try receipt_mod.encode(&receipt);
    try std.testing.expectEqual(
        receipt_mod.ENCODED_BYTE_COUNT,
        encoded.len,
    );
    try std.testing.expectEqual(@as(usize, 100), encoded.len);
    try std.testing.expect(
        std.mem.indexOf(u8, &encoded, "/publication") == null,
    );

    const decoded = try receipt_mod.decode(&encoded);
    try std.testing.expect(artifact_store.BlobRefV1.eql(
        decoded.table_ref,
        table_ref,
    ));
    try std.testing.expectEqual(
        segment_count,
        decoded.segment_count,
    );
    const topology = try decoded.topology();
    try std.testing.expectEqual(@as(u32, 8), topology.padded_leaf_count);
    try std.testing.expectEqual(@as(u32, 3), topology.empty_leaf_count);
    try std.testing.expectEqual(@as(u32, 7), topology.fold_count);

    var reserved_mutation = encoded;
    reserved_mutation[12] = 1;
    try std.testing.expectError(
        error.IncrementalCampaignImportReceiptCodecMismatchV4,
        receipt_mod.decode(&reserved_mutation),
    );
    var custody_mutation = encoded;
    custody_mutation[custody_mutation.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalCampaignImportReceiptV4,
        receipt_mod.decode(&custody_mutation),
    );
}

// Legacy focused-filter wording is retained until the shared build inventory
// can be migrated; the tested authority is fixture-only and gates no import.
test "canonical Ethereum profile retains exact 210-count admission policy" {
    try std.testing.expectEqual(
        @as(u32, 210),
        ethereum_policy.CURRENT_CONFORMANCE_SEGMENT_COUNT,
    );
    try ethereum_policy.requireCurrentConformanceFixture(
        ethereum_policy.CURRENT_CONFORMANCE_SEGMENT_COUNT,
    );
    try std.testing.expectError(
        error.IncrementalEthereumCampaignConformanceFixtureMismatchV4,
        ethereum_policy.requireCurrentConformanceFixture(5),
    );
    try std.testing.expect(command.GENERIC_CAMPAIGN_COUNTS);
}

test "campaign import command resolves exact options and rejects drift" {
    const arguments = [_][]const u8{
        "--retained-materialization-result", "/campaign-authority/result.json",
        "--publication-root",                "/sealed-publication",
        "--artifact-store-root",             "/shared-zig-cas",
        "--table-receipt-out",               "/controller-handoff/table.ref",
    };
    const parsed = try command.OptionsV4.parse(&arguments);
    var resolved = try parsed.resolve(std.testing.allocator);
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "/campaign-authority/result.json",
        resolved.retained_materialization_result,
    );
    try std.testing.expectEqualStrings(
        "/sealed-publication",
        resolved.publication_root,
    );
    try std.testing.expectEqualStrings(
        "/shared-zig-cas",
        resolved.artifact_store_root,
    );
    try std.testing.expectEqualStrings(
        "/controller-handoff/table.ref",
        resolved.table_receipt_out,
    );
    try std.testing.expect(command.RECOVERY_AWARE_IMPORT);
    try std.testing.expect(command.RECEIPT_SEALED_LAST);

    var duplicate = arguments;
    duplicate[2] = "--retained-materialization-result";
    try std.testing.expectError(
        error.DuplicateArgument,
        command.OptionsV4.parse(&duplicate),
    );
    var unknown = arguments;
    unknown[6] = "--receipt";
    try std.testing.expectError(
        error.InvalidArguments,
        command.OptionsV4.parse(&unknown),
    );
}

test "campaign import command rejects publication CAS and receipt overlap" {
    try command.validateResolvedCustodyPaths(
        "/authority/result.json",
        "/sealed-publication",
        "/shared-cas",
        "/handoff/table.ref",
    );
    try std.testing.expectError(
        error.IncrementalCampaignImportCommandPathMismatchV4,
        command.validateResolvedCustodyPaths(
            "/authority/result.json",
            "/sealed-publication",
            "/sealed-publication/cas",
            "/handoff/table.ref",
        ),
    );
    try std.testing.expectError(
        error.IncrementalCampaignImportCommandPathMismatchV4,
        command.validateResolvedCustodyPaths(
            "/sealed-publication/authority/result.json",
            "/sealed-publication",
            "/shared-cas",
            "/handoff/table.ref",
        ),
    );
    try std.testing.expectError(
        error.IncrementalCampaignImportCommandPathMismatchV4,
        command.validateResolvedCustodyPaths(
            "/authority/result.json",
            "/sealed-publication",
            "/shared-cas",
            "/shared-cas/table.ref",
        ),
    );
    try std.testing.expectError(
        error.IncrementalCampaignImportCommandPathMismatchV4,
        command.validateResolvedCustodyPaths(
            "/authority/result.json",
            "/sealed-publication",
            "/shared-cas",
            "/authority/result.json",
        ),
    );
}
