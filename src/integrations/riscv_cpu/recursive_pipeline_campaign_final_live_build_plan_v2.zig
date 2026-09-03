//! Nonserializable Stage-104 build plan over two live child receipts.
//!
//! The canonical controller description intentionally omits opaque lease
//! selectors. This process-local companion binds the selectors back to the
//! exact ordered child nodes, CAS refs, and StageManifests immediately before
//! a generic worker build request is emitted. It owns no child and cannot
//! mint, close, replace, encode, or decode a verifier capability.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const description_mod =
    @import("recursive_pipeline_campaign_final_description_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SERIALIZABLE_LIVE_LEASE_SELECTOR = false;
pub const EXACT_LEFT_RIGHT_ORDER_REQUIRED = true;
pub const CHILD_LEASE_CLOSE_OWNERSHIP = false;

pub const Error = error{
    CampaignFinalLiveBuildPlanMismatchV2,
};

pub fn PlanFor(
    comptime LeftBoundChild: type,
    comptime RightBoundChild: type,
) type {
    assertBoundChild(LeftBoundChild);
    assertBoundChild(RightBoundChild);

    return struct {
        pub const StageDescriptionV2 =
            description_mod.OwnedStageDescriptionV2;

        description: *const description_mod.OwnedStageDescriptionV2,
        left: *const LeftBoundChild,
        right: *const RightBoundChild,
        lease_ids: [2][]const u8,

        const Self = @This();

        pub fn init(
            scratch_allocator: std.mem.Allocator,
            description: *const description_mod.OwnedStageDescriptionV2,
            left: *const LeftBoundChild,
            right: *const RightBoundChild,
        ) !Self {
            const result = Self{
                .description = description,
                .left = left,
                .right = right,
                .lease_ids = .{
                    left.liveLeaseSelector(),
                    right.liveLeaseSelector(),
                },
            };
            try result.validate(scratch_allocator);
            return result;
        }

        pub fn validate(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            try self.left.validate();
            try self.right.validate();
            try self.description.validate(scratch_allocator);
            const node = self.description.node;
            const inputs = self.description.ordered_inputs;
            const manifests = self.description.dependency_stage_manifest_refs;
            const left_lease = self.left.liveLeaseSelector();
            const right_lease = self.right.liveLeaseSelector();
            if (node.stage_kind != .fold or node.dependencies.len != 2 or
                inputs.len != 2 or manifests.len != 2 or
                left_lease.len == 0 or right_lease.len == 0 or
                std.mem.eql(u8, left_lease, right_lease) or
                self.lease_ids[0].ptr != left_lease.ptr or
                self.lease_ids[0].len != left_lease.len or
                self.lease_ids[1].ptr != right_lease.ptr or
                self.lease_ids[1].len != right_lease.len or
                self.left.node() == self.right.node() or
                !std.mem.eql(
                    u8,
                    node.dependencies[0].node_id,
                    self.left.node().node_id,
                ) or !std.mem.eql(
                u8,
                node.dependencies[1].node_id,
                self.right.node().node_id,
            ) or node.dependencies[0].role !=
                @intFromEnum(artifact_store.InputRoleV1.child_left) or
                node.dependencies[0].ordinal != 0 or
                node.dependencies[1].role !=
                    @intFromEnum(artifact_store.InputRoleV1.child_right) or
                node.dependencies[1].ordinal != 0 or
                inputs[0].role != .child_left or inputs[0].ordinal != 0 or
                inputs[1].role != .child_right or inputs[1].ordinal != 0 or
                !artifact_store.BlobRefV1.eql(
                    inputs[0].blob,
                    self.left.outputRef(),
                ) or !artifact_store.BlobRefV1.eql(
                inputs[1].blob,
                self.right.outputRef(),
            ) or !artifact_store.BlobRefV1.eql(
                manifests[0],
                self.left.stageManifestRef(),
            ) or !artifact_store.BlobRefV1.eql(
                manifests[1],
                self.right.stageManifestRef(),
            ) or self.left.nodeArtifact() == self.right.nodeArtifact()) {
                return error.CampaignFinalLiveBuildPlanMismatchV2;
            }
        }

        pub fn stageDescription(
            self: *const Self,
        ) *const description_mod.OwnedStageDescriptionV2 {
            return self.description;
        }

        pub fn dependencyLeaseIds(
            self: *const Self,
        ) []const []const u8 {
            return &self.lease_ids;
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertBoundChild(comptime BoundChild: type) void {
    inline for (.{
        "validate",
        "node",
        "outputRef",
        "stageManifestRef",
        "nodeArtifact",
        "liveLeaseSelector",
    }) |name| if (!@hasDecl(BoundChild, name))
        @compileError("campaign live build child missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign live build plan gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        SERIALIZABLE_LIVE_LEASE_SELECTOR or
        !EXACT_LEFT_RIGHT_ORDER_REQUIRED or CHILD_LEASE_CLOSE_OWNERSHIP)
    {
        @compileError("campaign final live build plan contract drifted");
    }
}
