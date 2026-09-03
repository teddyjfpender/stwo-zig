//! Process-local binder from a live worker lease to a Stage-104 child view.
//!
//! The generic worker never releases its raw payload. Its adapter validates
//! that payload against the final campaign and returns only a role-neutral
//! fold projection. This short-lived view pins that projection to the exact
//! node/output/StageManifest/selector tuple used by the next description.
//! The caller must hold an exclusive worker borrow until the description and
//! build request have consumed the view.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const real_worker = @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const consumers = @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SERIALIZABLE_LIVE_LEASE_SELECTOR = false;
pub const RAW_LEASE_PAYLOAD_EXPOSED = false;
pub const EXCLUSIVE_WORKER_BORROW_REQUIRED = true;
pub const PROJECTION_POINTER_IDENTITY_REQUIRED = true;

pub const Error = error{
    CampaignFinalLiveFoldChildMismatchV2,
};

pub const RetainedLeaseReceiptV2 = struct {
    node: *const protocol.Node,
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    lease_id: []const u8,

    pub fn validate(self: RetainedLeaseReceiptV2) !void {
        self.output_ref.validate() catch
            return error.CampaignFinalLiveFoldChildMismatchV2;
        self.stage_manifest_ref.validate() catch
            return error.CampaignFinalLiveFoldChildMismatchV2;
        if (self.lease_id.len == 0 or self.node.output_kind != .recursion_node or
            self.node.output_schema_version != campaign_artifact.SCHEMA_VERSION or
            self.output_ref.kind != .recursion_node or
            self.output_ref.schema_version != campaign_artifact.SCHEMA_VERSION or
            self.output_ref.byte_count != campaign_artifact.ENCODED_BYTE_COUNT or
            self.stage_manifest_ref.kind != .stage_manifest or
            self.stage_manifest_ref.schema_version !=
                support.stage_manifest_schema_version or
            self.stage_manifest_ref.byte_count == 0)
        {
            return error.CampaignFinalLiveFoldChildMismatchV2;
        }
    }
};

pub fn BinderFor(comptime Worker: type) type {
    assertWorker(Worker);
    const Projection = Worker.AdapterV1.RetainedLeaseProjection;
    assertProjection(Projection);

    return struct {
        pub const WorkerV1 = Worker;
        pub const RetainedLeaseProjection = Projection;

        worker: *Worker,

        const Self = @This();

        pub const BorrowedChildV2 = struct {
            binder: *const Self,
            receipt: *const RetainedLeaseReceiptV2,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            projection: Projection,

            pub fn validate(self: BorrowedChildV2) !void {
                try self.receipt.validate();
                try self.final_remint.validateAgainstCampaign(
                    self.final_remint.shape.campaign_namespace_sha256,
                );
                const current = try self.binder.worker.projectRetainedLease(
                    Projection,
                    self.receipt.lease_id,
                    self.receipt.node.node_id,
                    self.receipt.output_ref,
                    self.receipt.stage_manifest_ref,
                    self.final_remint,
                );
                try current.validateAgainstFinal(self.final_remint);
                if (self.projection.authority != self.final_remint or
                    current.authority != self.final_remint or
                    self.projection.node_artifact != current.node_artifact)
                {
                    return error.CampaignFinalLiveFoldChildMismatchV2;
                }
                try self.projection.validateAgainstFinal(self.final_remint);
                const artifact = current.node_artifact;
                const expected_ref = try node_store.toSharedRef(
                    try campaign_artifact.artifactRef(
                        self.final_remint.shape,
                        artifact,
                    ),
                );
                if (!artifact_store.BlobRefV1.eql(
                    expected_ref,
                    self.receipt.output_ref,
                )) return error.CampaignFinalLiveFoldChildMismatchV2;
                try validateStage(self.receipt.node.*, artifact);
            }

            pub fn node(self: BorrowedChildV2) *const protocol.Node {
                return self.receipt.node;
            }

            pub fn outputRef(
                self: BorrowedChildV2,
            ) artifact_store.BlobRefV1 {
                return self.receipt.output_ref;
            }

            pub fn stageManifestRef(
                self: BorrowedChildV2,
            ) artifact_store.BlobRefV1 {
                return self.receipt.stage_manifest_ref;
            }

            pub fn nodeArtifact(
                self: BorrowedChildV2,
            ) *const campaign_artifact.Artifact {
                return self.projection.node_artifact;
            }

            pub fn liveLeaseSelector(self: BorrowedChildV2) []const u8 {
                return self.receipt.lease_id;
            }

            comptime {
                rejectCodec(BorrowedChildV2);
            }
        };

        pub fn init(worker: *Worker) Self {
            return .{ .worker = worker };
        }

        pub fn bind(
            self: *const Self,
            receipt: *const RetainedLeaseReceiptV2,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
        ) !BorrowedChildV2 {
            try receipt.validate();
            const result = BorrowedChildV2{
                .binder = self,
                .receipt = receipt,
                .final_remint = final_remint,
                .projection = try self.worker.projectRetainedLease(
                    Projection,
                    receipt.lease_id,
                    receipt.node.node_id,
                    receipt.output_ref,
                    receipt.stage_manifest_ref,
                    final_remint,
                ),
            };
            try result.validate();
            return result;
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn validateStage(
    node: protocol.Node,
    artifact: *const campaign_artifact.Artifact,
) !void {
    if (node.stage_kind == .prove and
        node.stage_schema_version == real_worker.STAGE_SCHEMA_VERSION and
        std.mem.eql(u8, node.adapter, real_worker.adapter_name))
    {
        if (artifact.stage_kind != .leaf_wrapper or
            artifact.node_kind != .real)
        {
            return error.CampaignFinalLiveFoldChildMismatchV2;
        }
        return;
    }
    if (node.stage_kind == .prove and
        node.stage_schema_version == consumers.STAGE103_SCHEMA_VERSION and
        std.mem.eql(u8, node.adapter, consumers.stage103_adapter_name))
    {
        if (artifact.stage_kind != .leaf_wrapper or
            artifact.node_kind != .empty)
        {
            return error.CampaignFinalLiveFoldChildMismatchV2;
        }
        return;
    }
    if (node.stage_kind == .fold and
        node.stage_schema_version == consumers.STAGE104_SCHEMA_VERSION and
        std.mem.eql(u8, node.adapter, consumers.stage104_adapter_name))
    {
        if (artifact.stage_kind != .fold and artifact.stage_kind != .root)
            return error.CampaignFinalLiveFoldChildMismatchV2;
        return;
    }
    return error.CampaignFinalLiveFoldChildMismatchV2;
}

fn assertWorker(comptime Worker: type) void {
    inline for (.{ "AdapterV1", "projectRetainedLease" }) |name|
        if (!@hasDecl(Worker, name))
            @compileError("live fold child worker missing " ++ name);
    inline for (.{ "RetainedLeaseProjection", "projectRetainedLease" }) |name|
        if (!@hasDecl(Worker.AdapterV1, name))
            @compileError("live fold child adapter missing " ++ name);
}

fn assertProjection(comptime Projection: type) void {
    if (!@hasDecl(Projection, "validateAgainstFinal"))
        @compileError("live fold child projection lacks final validation");
    inline for (.{ "authority", "node_artifact" }) |name|
        if (!@hasField(Projection, name))
            @compileError("live fold child projection missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("live fold child gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        SERIALIZABLE_LIVE_LEASE_SELECTOR or RAW_LEASE_PAYLOAD_EXPOSED or
        !EXCLUSIVE_WORKER_BORROW_REQUIRED or
        !PROJECTION_POINTER_IDENTITY_REQUIRED)
    {
        @compileError("campaign final live fold child binder drifted");
    }
}
