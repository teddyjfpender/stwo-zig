//! Exact process-local handoff from one live worker publication to the final
//! campaign driver's existing `CommittedStageV2` view.
//!
//! The description owns all durable Node/key/input metadata, the build owner
//! pins the output BlobRef, and the retained cold owner pins the seal-last
//! StageManifest plus opaque selector. This adapter borrows all three, checks
//! their pointer/value closure while the lease is live, then field-projects
//! the driver's non-owning view. It never owns, closes, encodes, or exposes a
//! verifier payload.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SERIALIZABLE_LIVE_LEASE_SELECTOR = false;
pub const LIVE_LEASE_REQUIRED_AT_PROJECTION = true;
pub const LEASE_CLOSE_OWNERSHIP = false;
pub const EXACT_DESCRIPTION_PUBLICATION_CLOSURE = true;

pub const Error = error{
    CampaignFinalLiveCommittedStageMismatchV2,
};

pub fn AdapterFor(comptime Executor: type) type {
    assertExecutor(Executor);
    return struct {
        pub const ExecutorV2 = Executor;
        pub const StageDescriptionV2 = Executor.StageDescriptionV2;
        pub const BuiltPublicationV2 = Executor.OwnedBuiltPublicationV2;
        pub const RetainedPublicationV2 = Executor.OwnedRetainedParentV2;

        description: *const StageDescriptionV2,
        built: *const BuiltPublicationV2,
        retained: *const RetainedPublicationV2,

        const Self = @This();

        pub fn init(
            scratch_allocator: std.mem.Allocator,
            description: *const StageDescriptionV2,
            built: *const BuiltPublicationV2,
            retained: *const RetainedPublicationV2,
        ) !Self {
            const result = Self{
                .description = description,
                .built = built,
                .retained = retained,
            };
            try result.validate(scratch_allocator);
            return result;
        }

        pub fn validate(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            try self.description.validate(scratch_allocator);
            try self.built.validate(scratch_allocator);
            try self.retained.validate();
            if (self.built.description != self.description or
                self.retained.description != self.description or
                self.built.executor != self.retained.executor or
                !artifact_store.BlobRefV1.eql(
                    self.built.output_ref,
                    self.retained.output_ref,
                ) or self.retained.lease_id.len == 0)
            {
                return error.CampaignFinalLiveCommittedStageMismatchV2;
            }
        }

        /// The returned value borrows all slices and pointers. The three
        /// owners and the immutable worker/session metadata must outlive its
        /// use by the final driver.
        pub fn committed(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !driver_mod.CommittedStageV2 {
            try self.validate(scratch_allocator);
            return .{
                .node = &self.description.node,
                .semantic = &self.description.semantic,
                .execution = &self.description.execution,
                .ordered_inputs = self.description.ordered_inputs,
                .output_ref = self.built.output_ref,
                .stage_manifest_ref = self.retained.stage_manifest_ref,
                .dependency_stage_manifest_refs = self.description
                    .dependency_stage_manifest_refs,
                .lease_id = self.retained.lease_id,
            };
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertExecutor(comptime Executor: type) void {
    inline for (.{
        "StageDescriptionV2",
        "OwnedBuiltPublicationV2",
        "OwnedRetainedParentV2",
    }) |name| if (!@hasDecl(Executor, name))
        @compileError("live committed-stage executor missing " ++ name);
    inline for (.{ "description", "output_ref", "executor" }) |name|
        if (!@hasField(Executor.OwnedBuiltPublicationV2, name))
            @compileError("live committed-stage build missing " ++ name);
    inline for (.{
        "description",
        "output_ref",
        "stage_manifest_ref",
        "lease_id",
        "executor",
    }) |name| if (!@hasField(Executor.OwnedRetainedParentV2, name))
        @compileError("live committed-stage cold owner missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("live committed-stage adapter gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        SERIALIZABLE_LIVE_LEASE_SELECTOR or
        !LIVE_LEASE_REQUIRED_AT_PROJECTION or LEASE_CLOSE_OWNERSHIP or
        !EXACT_DESCRIPTION_PUBLICATION_CLOSURE)
    {
        @compileError("campaign final live committed-stage contract drifted");
    }
}
