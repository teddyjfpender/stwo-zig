//! Heap-stable owner for the live Stage-102 receipt prefix.
//!
//! JSON request/response arenas may be destroyed immediately after `init`:
//! opaque lease selectors and dependency StageManifest refs are copied into
//! this owner. Node, key, and ordered-input pointers are borrowed only from
//! the immutable sealed Stage-102 session already held by the driver. This
//! owner never closes a lease; it must be destroyed before its active worker.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const REQUEST_ARENA_POINTERS_RETAINED = false;
pub const IMMUTABLE_SESSION_POINTERS_REQUIRED = true;
pub const LIVE_WORKER_MUST_OUTLIVE_OWNER = true;
pub const LEASE_CLOSE_OWNERSHIP = false;

pub const Error = error{
    CampaignFinalLiveRole0ReceiptMismatchV2,
};

pub const ColdPublicationV2 = struct {
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    lease_id: []const u8,

    pub fn validate(self: ColdPublicationV2) !void {
        if (self.lease_id.len == 0)
            return error.CampaignFinalLiveRole0ReceiptMismatchV2;
        try campaign_cas.validate(self.output_ref, .recursion_node);
        try campaign_cas.validate(self.stage_manifest_ref, .stage_manifest);
    }
};

pub fn OwnerFor(comptime Binder: type) type {
    assertBinder(Binder);
    const Frontier = Binder.FrontierV4;

    return struct {
        allocator: std.mem.Allocator,
        binder: Binder,
        frontier: *const Frontier.OwnedFrontierV4,
        lease_ids: [][]u8,
        dependency_refs: [][1]artifact_store.BlobRefV1,
        receipts: []driver_mod.CommittedStageV2,

        const Self = @This();

        pub fn init(
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            binder: Binder,
            frontier: *const Frontier.OwnedFrontierV4,
            publications: []const ColdPublicationV2,
        ) !*Self {
            const session = binder.driver.session;
            const rows = frontier.orderedRows();
            if (publications.len != session.entries.len or
                publications.len != rows.len or
                frontier.policy != session.policy)
            {
                return error.CampaignFinalLiveRole0ReceiptMismatchV2;
            }

            const self = try owner_allocator.create(Self);
            errdefer owner_allocator.destroy(self);
            const lease_ids = try owner_allocator.alloc(
                []u8,
                publications.len,
            );
            errdefer owner_allocator.free(lease_ids);
            var initialized_lease_ids: usize = 0;
            errdefer for (lease_ids[0..initialized_lease_ids]) |value|
                owner_allocator.free(value);
            const dependency_refs = try owner_allocator.alloc(
                [1]artifact_store.BlobRefV1,
                publications.len,
            );
            errdefer owner_allocator.free(dependency_refs);
            const receipts = try owner_allocator.alloc(
                driver_mod.CommittedStageV2,
                publications.len,
            );
            errdefer owner_allocator.free(receipts);

            for (publications, session.entries, rows, 0..) |
                publication,
                *entry,
                row,
                index,
            | {
                try publication.validate();
                if (row.coordinate != @as(u32, @intCast(index)) or
                    !artifact_store.BlobRefV1.eql(
                        publication.output_ref,
                        entry.output_ref,
                    ) or !artifact_store.BlobRefV1.eql(
                    publication.output_ref,
                    row.publication.output_ref,
                ) or !artifact_store.BlobRefV1.eql(
                    publication.stage_manifest_ref,
                    entry.admission.stage_manifest_ref,
                ) or !artifact_store.BlobRefV1.eql(
                    publication.stage_manifest_ref,
                    row.publication.stage_manifest_ref,
                )) return error.CampaignFinalLiveRole0ReceiptMismatchV2;
                for (lease_ids[0..initialized_lease_ids]) |earlier| {
                    if (std.mem.eql(u8, earlier, publication.lease_id))
                        return error.CampaignFinalLiveRole0ReceiptMismatchV2;
                }
                try binder.worker.validateRetainedLeaseIdentity(
                    publication.lease_id,
                    entry.admission.node.node_id,
                    publication.output_ref,
                    publication.stage_manifest_ref,
                );
                lease_ids[index] = try owner_allocator.dupe(
                    u8,
                    publication.lease_id,
                );
                initialized_lease_ids += 1;
                dependency_refs[index] = .{
                    entry.admission.dependency_stage_manifest_ref,
                };
                receipts[index] = .{
                    .node = entry.admission.node,
                    .semantic = entry.admission.semantic,
                    .execution = entry.admission.execution,
                    .ordered_inputs = entry.admission.ordered_inputs,
                    .output_ref = entry.output_ref,
                    .stage_manifest_ref = entry.admission.stage_manifest_ref,
                    .dependency_stage_manifest_refs = &dependency_refs[index],
                    .lease_id = lease_ids[index],
                };
            }

            self.* = .{
                .allocator = owner_allocator,
                .binder = binder,
                .frontier = frontier,
                .lease_ids = lease_ids,
                .dependency_refs = dependency_refs,
                .receipts = receipts,
            };
            try self.validate(scratch_allocator);
            return self;
        }

        pub fn validate(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            const session = self.binder.driver.session;
            const rows = self.frontier.orderedRows();
            if (self.receipts.len != session.entries.len or
                self.receipts.len != rows.len or
                self.lease_ids.len != self.receipts.len or
                self.dependency_refs.len != self.receipts.len or
                self.frontier.policy != session.policy)
            {
                return error.CampaignFinalLiveRole0ReceiptMismatchV2;
            }
            for (
                self.receipts,
                self.lease_ids,
                self.dependency_refs,
                session.entries,
                rows,
                0..,
            ) |receipt, lease_id, *dependencies, *entry, row, index| {
                if (receipt.node != entry.admission.node or
                    receipt.semantic != entry.admission.semantic or
                    receipt.execution != entry.admission.execution or
                    receipt.ordered_inputs.ptr !=
                        entry.admission.ordered_inputs.ptr or
                    receipt.lease_id.ptr != lease_id.ptr or
                    receipt.lease_id.len != lease_id.len or
                    receipt.dependency_stage_manifest_refs.ptr !=
                        dependencies[0..].ptr or
                    receipt.dependency_stage_manifest_refs.len != 1 or
                    row.coordinate != @as(u32, @intCast(index)) or
                    !artifact_store.BlobRefV1.eql(
                        receipt.output_ref,
                        entry.output_ref,
                    ) or !artifact_store.BlobRefV1.eql(
                    receipt.stage_manifest_ref,
                    entry.admission.stage_manifest_ref,
                ) or !artifact_store.BlobRefV1.eql(
                    dependencies[0],
                    entry.admission.dependency_stage_manifest_ref,
                )) return error.CampaignFinalLiveRole0ReceiptMismatchV2;
            }
            _ = try self.binder.bindRole0Frontier(
                scratch_allocator,
                self.frontier,
                self.receipts,
            );
        }

        pub fn committedReceipts(
            self: *const Self,
        ) []const driver_mod.CommittedStageV2 {
            return self.receipts;
        }

        pub fn boundRole0Frontier(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !Binder.BoundRole0FrontierV2 {
            try self.validate(scratch_allocator);
            return self.binder.bindRole0Frontier(
                scratch_allocator,
                self.frontier,
                self.receipts,
            );
        }

        pub fn deinit(self: *Self) void {
            for (self.lease_ids) |value| self.allocator.free(value);
            self.allocator.free(self.receipts);
            self.allocator.free(self.dependency_refs);
            self.allocator.free(self.lease_ids);
            const allocator = self.allocator;
            self.* = undefined;
            allocator.destroy(self);
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertBinder(comptime Binder: type) void {
    inline for (.{
        "WorkerV1",
        "DriverV2",
        "FrontierV4",
        "BoundRole0FrontierV2",
        "bindRole0Frontier",
    }) |name| if (!@hasDecl(Binder, name))
        @compileError("live role0 receipt owner binder missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("live role0 receipt owner gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        REQUEST_ARENA_POINTERS_RETAINED or
        !IMMUTABLE_SESSION_POINTERS_REQUIRED or
        !LIVE_WORKER_MUST_OUTLIVE_OWNER or LEASE_CLOSE_OWNERSHIP)
    {
        @compileError("campaign final live role0 receipt owner drifted");
    }
}
