const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const cold_describe =
    @import("recursive_pipeline_incremental_campaign_cold_describe_v4.zig");
const command =
    @import("recursive_pipeline_incremental_campaign_cold_describe_command_v4.zig");
const description_mod =
    @import("recursive_pipeline_incremental_campaign_cold_description_v4.zig");
const receipt_mod =
    @import("recursive_pipeline_incremental_campaign_import_receipt_v4.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");

test "cold campaign description is canonical path-free and topology-bound" {
    const receipt = try fixtureReceipt(5, 0xab);
    const description = try description_mod.DescriptionV4.mint(
        &receipt,
        receipt.table_ref,
        receipt.segment_count,
    );
    const encoded = try description_mod.encodeCanonicalJsonAlloc(
        std.testing.allocator,
        &description,
    );
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqual(@as(u8, '\n'), encoded[encoded.len - 1]);
    try std.testing.expect(
        std.mem.indexOf(u8, encoded, "/publication") == null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, encoded, "/artifact-store") == null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, encoded, "\"authenticated_segment_count\":5") !=
            null,
    );

    const decoded = try description_mod.decodeCanonicalJson(
        std.testing.allocator,
        encoded,
    );
    try std.testing.expect(std.meta.eql(description, decoded));
    try std.testing.expectEqual(@as(u32, 8), decoded.topology.padded_leaf_count);
    try std.testing.expectEqual(@as(u32, 3), decoded.topology.empty_leaf_count);
    try std.testing.expectEqual(@as(u32, 7), decoded.topology.fold_count);
}

test "cold campaign description rejects receipt table and topology mutations" {
    const receipt = try fixtureReceipt(3, 0x41);
    const description = try description_mod.DescriptionV4.mint(
        &receipt,
        receipt.table_ref,
        receipt.segment_count,
    );

    var topology_mutation = description;
    topology_mutation.topology.empty_leaf_count = 0;
    try std.testing.expectError(
        error.InvalidIncrementalCampaignColdDescriptionV4,
        topology_mutation.validate(),
    );
    var table_mutation = description;
    table_mutation.table_ref.sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalCampaignColdDescriptionV4,
        table_mutation.validate(),
    );
    const unrelated = try fixtureReceipt(3, 0x42);
    try std.testing.expectError(
        error.InvalidIncrementalCampaignColdDescriptionV4,
        description_mod.DescriptionV4.mint(
            &receipt,
            unrelated.table_ref,
            receipt.segment_count,
        ),
    );
    try std.testing.expectError(
        error.InvalidIncrementalCampaignColdDescriptionV4,
        description_mod.DescriptionV4.mint(
            &receipt,
            receipt.table_ref,
            5,
        ),
    );

    const encoded = try description_mod.encodeCanonicalJsonAlloc(
        std.testing.allocator,
        &description,
    );
    defer std.testing.allocator.free(encoded);
    const mutated = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(mutated);
    const digest_at = std.mem.indexOf(u8, mutated, "41414141") orelse
        return error.TestExpectedEqual;
    mutated[digest_at] = 'A';
    try std.testing.expectError(
        error.IncrementalCampaignColdDescriptionCodecMismatchV4,
        description_mod.decodeCanonicalJson(std.testing.allocator, mutated),
    );
}

test "cold describe command accepts only receipt and Zig CAS inputs" {
    const arguments = [_][]const u8{
        "--campaign-import-receipt",
        "/controller/stwcir04.json",
        "--artifact-store-root",
        "/zig-cas",
    };
    const parsed = try command.OptionsV4.parse(&arguments);
    var resolved = try parsed.resolve(std.testing.allocator);
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "/controller/stwcir04.json",
        resolved.campaign_import_receipt,
    );
    try std.testing.expectEqualStrings(
        "/zig-cas",
        resolved.artifact_store_root,
    );
    try std.testing.expect(!command.PRODUCTION_ACTIVE);

    var duplicate = arguments;
    duplicate[2] = "--campaign-import-receipt";
    try std.testing.expectError(
        error.DuplicateArgument,
        command.OptionsV4.parse(&duplicate),
    );
    const extra = [_][]const u8{
        "--campaign-import-receipt",
        "/controller/stwcir04.json",
        "--artifact-store-root",
        "/zig-cas",
        "--table",
        "/caller/table",
    };
    try std.testing.expectError(
        error.InvalidArguments,
        command.OptionsV4.parse(&extra),
    );
    const overlap = command.OptionsV4{
        .campaign_import_receipt = "/zig-cas/receipt",
        .artifact_store_root = "/zig-cas",
    };
    try std.testing.expectError(
        error.IncrementalCampaignColdDescribePathMismatchV4,
        overlap.resolve(std.testing.allocator),
    );

    // Compile-time inventory: the production bridge takes the concrete Store
    // and therefore cannot substitute a caller-provided validation callback.
    const owner: *const fn (
        std.mem.Allocator,
        *artifact_store.Store,
        []const u8,
    ) anyerror!cold_describe.DescriptionV4 = &cold_describe.coldDescribe;
    _ = owner;
}

test "cold describe rejects noncanonical STWCIR04 before CAS access" {
    var bytes: [receipt_mod.ENCODED_BYTE_COUNT]u8 = [_]u8{0} **
        receipt_mod.ENCODED_BYTE_COUNT;
    bytes[0] = 'X';
    var unopened_store: artifact_store.Store = undefined;
    try std.testing.expectError(
        error.IncrementalCampaignImportReceiptCodecMismatchV4,
        cold_describe.coldDescribe(
            std.testing.allocator,
            &unopened_store,
            &bytes,
        ),
    );
}

fn fixtureReceipt(
    segment_count: u32,
    seed: u8,
) !receipt_mod.ReceiptV4 {
    const reference = try artifact_store.BlobRefV1.create(
        table_mod.ARTIFACT_KIND,
        table_mod.CAS_SCHEMA_VERSION,
        @intCast(try table_mod.encodedByteCount(segment_count)),
        [_]u8{seed} ** 32,
    );
    return receipt_mod.ReceiptV4.seal(.{
        .segment_count = segment_count,
        .table_ref = reference,
        .content_sha256 = undefined,
    });
}
