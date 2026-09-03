//! Cold STWCIR04 -> controller description boundary.
//!
//! Opening a BlobRef only proves CAS custody.  This owner deliberately runs
//! the complete STWCIT04 validator before minting any controller-visible
//! metadata; no digest or table presence grants admission.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const description_mod =
    @import("recursive_pipeline_incremental_campaign_cold_description_v4.zig");
const importer =
    @import("recursive_pipeline_incremental_campaign_importer_v4.zig");
const receipt_mod =
    @import("recursive_pipeline_incremental_campaign_import_receipt_v4.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const worker_description =
    @import("recursive_pipeline_incremental_campaign_worker_description_v4.zig");

pub const DescriptionV4 = description_mod.DescriptionV4;

pub fn coldDescribe(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    receipt_bytes: []const u8,
) !DescriptionV4 {
    const receipt = try receipt_mod.decode(receipt_bytes);
    var table_blob = try store.openBlob(
        receipt.table_ref,
        table_mod.ARTIFACT_KIND,
        table_mod.CAS_SCHEMA_VERSION,
        receipt.table_ref.byte_count,
    );
    defer table_blob.deinit(store.allocator);
    if (!artifact_store.BlobRefV1.eql(
        table_blob.ref,
        receipt.table_ref,
    )) return error.IncrementalCampaignColdDescriptionTableMismatchV4;

    // This transitively reopens both final manifests, every RecipeV4, and all
    // seven Stage101 inputs.  Keep it before every description projection.
    try importer.coldValidateCampaignTable(
        allocator,
        store,
        table_blob.bytes,
    );
    const header = try table_mod.decodeHeader(table_blob.bytes);
    if (header.segment_count != receipt.segment_count)
        return error.IncrementalCampaignColdDescriptionCountMismatchV4;
    return description_mod.DescriptionV4.mint(
        &receipt,
        table_blob.ref,
        header.segment_count,
    );
}

pub fn coldDescribeCanonicalJsonAlloc(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    receipt_bytes: []const u8,
) ![]u8 {
    const description = try coldDescribe(allocator, store, receipt_bytes);
    return description_mod.encodeCanonicalJsonAlloc(
        allocator,
        &description,
    );
}

/// Emits the complete path-free Stage101 planner projection only after the
/// table and every transitive campaign input have been cold validated by Zig.
/// The returned JSON is controller metadata; the worker still reopens and
/// revalidates every referenced object before producing a live capability.
pub fn coldDescribeWorkerCanonicalJsonAlloc(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    receipt_bytes: []const u8,
) ![]u8 {
    const receipt = try receipt_mod.decode(receipt_bytes);
    var table_blob = try store.openBlob(
        receipt.table_ref,
        table_mod.ARTIFACT_KIND,
        table_mod.CAS_SCHEMA_VERSION,
        receipt.table_ref.byte_count,
    );
    defer table_blob.deinit(store.allocator);
    if (!artifact_store.BlobRefV1.eql(table_blob.ref, receipt.table_ref))
        return error.IncrementalCampaignColdDescriptionTableMismatchV4;

    try importer.coldValidateCampaignTable(
        allocator,
        store,
        table_blob.bytes,
    );
    var table = try table_mod.decodeAllocAgainstAuthenticatedCount(
        allocator,
        table_blob.bytes,
        receipt.segment_count,
    );
    defer table.deinit();
    const custody = try description_mod.DescriptionV4.mint(
        &receipt,
        table_blob.ref,
        table.value.segment_count,
    );
    var description = try worker_description.mintAlloc(
        allocator,
        custody,
        &table.value,
    );
    defer description.deinit();
    return worker_description.encodeCanonicalJsonAlloc(
        allocator,
        &description.value,
    );
}
