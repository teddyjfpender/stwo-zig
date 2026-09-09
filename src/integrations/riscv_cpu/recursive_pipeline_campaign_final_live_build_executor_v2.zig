//! Process-local execution of one Stage-104 live build plan.
//!
//! The controller description contains durable node/key/ref authority while
//! `LiveBuildPlan` restores the two opaque child lease selectors immediately
//! before dispatch. This module serializes only the frozen worker request,
//! verifies its exact response, and cold-opens the published parent into one
//! new typed lease. It never observes a lease payload or proof bytes.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const storage = @import("recursive_pipeline_worker_storage_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SERIALIZABLE_LIVE_LEASE_SELECTOR = false;
pub const EXACT_ORDERED_LEASE_CONSUMPTION_REQUIRED = true;
pub const PARENT_LEASE_PAYLOAD_EXPOSED = false;
pub const LEASE_CLOSE_OWNERSHIP = false;

pub const Error = error{
    CampaignFinalLiveBuildResponseMismatchV2,
    CampaignFinalLiveColdOpenMismatchV2,
    CampaignFinalLiveKeyPublicationMismatchV2,
};

pub const BuildPathsV2 = struct {
    output_path: []const u8,
    profile_receipt_path: []const u8,
    candidate_ref_path: []const u8,

    pub fn validate(self: BuildPathsV2) !void {
        try support.validateDistinctPaths(
            self.output_path,
            self.profile_receipt_path,
            self.candidate_ref_path,
        );
    }
};

pub fn ExecutorFor(
    comptime Worker: type,
    comptime LiveBuildPlan: type,
) type {
    assertWorker(Worker);
    assertLiveBuildPlan(LiveBuildPlan);

    return struct {
        pub const WorkerV1 = Worker;
        pub const LiveBuildPlanV2 = LiveBuildPlan;
        pub const StageDescriptionV2 = LiveBuildPlan.StageDescriptionV2;

        worker: *Worker,

        const Self = @This();

        pub const OwnedBuiltPublicationV2 = struct {
            allocator: std.mem.Allocator,
            executor: *Self,
            description: *const StageDescriptionV2,
            output_ref: artifact_store.BlobRefV1,
            output_path: []u8,
            profile_receipt_path: []u8,
            candidate_ref_path: []u8,

            pub fn validate(
                self: *const OwnedBuiltPublicationV2,
                scratch: std.mem.Allocator,
            ) !void {
                try self.description.validate(scratch);
                try (BuildPathsV2{
                    .output_path = self.output_path,
                    .profile_receipt_path = self.profile_receipt_path,
                    .candidate_ref_path = self.candidate_ref_path,
                }).validate();
                if (self.output_ref.kind !=
                    self.description.node.output_kind or
                    self.output_ref.schema_version !=
                        self.description.node.output_schema_version)
                {
                    return error.CampaignFinalLiveBuildResponseMismatchV2;
                }
                try storage.exactOpenRef(
                    scratch,
                    &self.executor.worker.store,
                    self.output_ref,
                    null,
                );
            }

            pub fn deinit(self: *OwnedBuiltPublicationV2) void {
                const allocator = self.allocator;
                allocator.free(self.candidate_ref_path);
                allocator.free(self.profile_receipt_path);
                allocator.free(self.output_path);
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(OwnedBuiltPublicationV2);
            }
        };

        /// Owns only a stable copy of the opaque selector. The worker owns
        /// the typed payload and is responsible for its eventual close.
        pub const OwnedRetainedParentV2 = struct {
            allocator: std.mem.Allocator,
            executor: *Self,
            description: *const StageDescriptionV2,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            lease_id: []u8,

            pub fn validate(self: *const OwnedRetainedParentV2) !void {
                if (self.lease_id.len == 0 or
                    self.stage_manifest_ref.kind != .stage_manifest or
                    self.stage_manifest_ref.schema_version !=
                        support.stage_manifest_schema_version)
                {
                    return error.CampaignFinalLiveColdOpenMismatchV2;
                }
                try self.executor.worker.validateRetainedLeaseIdentity(
                    self.lease_id,
                    self.description.node.node_id,
                    self.output_ref,
                    self.stage_manifest_ref,
                );
            }

            pub fn liveLeaseSelector(
                self: *const OwnedRetainedParentV2,
            ) []const u8 {
                return self.lease_id;
            }

            pub fn deinit(self: *OwnedRetainedParentV2) void {
                const allocator = self.allocator;
                allocator.free(self.lease_id);
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(OwnedRetainedParentV2);
            }
        };

        pub fn init(worker: *Worker) Self {
            return .{ .worker = worker };
        }

        /// A worker failure leaves both child leases live. A successful
        /// response is accepted only if it reports those two selectors in
        /// the exact request order; the worker has then consumed both.
        pub fn build(
            self: *Self,
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            plan: *const LiveBuildPlan,
            paths: BuildPathsV2,
        ) !*OwnedBuiltPublicationV2 {
            try plan.validate(scratch_allocator);
            return self.buildDescription(
                owner_allocator,
                scratch_allocator,
                plan.stageDescription(),
                plan.dependencyLeaseIds(),
                paths,
            );
        }

        /// Stage-103 has one authenticated direct CAS input and deliberately
        /// no dependency lease. This entry retains the exact worker build
        /// wire while making the empty dependency set explicit at the type
        /// boundary; it cannot be used for a node with dependencies.
        pub fn buildWithoutDependencies(
            self: *Self,
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            description: *const StageDescriptionV2,
            paths: BuildPathsV2,
        ) !*OwnedBuiltPublicationV2 {
            try description.validate(scratch_allocator);
            if (description.node.dependencies.len != 0 or
                description.dependency_stage_manifest_refs.len != 0)
            {
                return error.CampaignFinalLiveBuildResponseMismatchV2;
            }
            return self.buildDescription(
                owner_allocator,
                scratch_allocator,
                description,
                &.{},
                paths,
            );
        }

        fn buildDescription(
            self: *Self,
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            description: *const StageDescriptionV2,
            requested_leases: []const []const u8,
            paths: BuildPathsV2,
        ) !*OwnedBuiltPublicationV2 {
            try paths.validate();
            try description.validate(scratch_allocator);
            try self.publishKeys(scratch_allocator, description);

            var arena_state = std.heap.ArenaAllocator.init(scratch_allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var payload = protocol.jsonObject(arena);
            try protocol.put(
                &payload,
                "node",
                try protocol.nodeValue(arena, description.node),
            );
            try protocol.put(
                &payload,
                "ordered_inputs",
                try protocol.inputRefsValue(
                    arena,
                    description.ordered_inputs,
                ),
            );
            try protocol.put(
                &payload,
                "semantic_key",
                try protocol.semanticProjection(arena, description.semantic),
            );
            try protocol.put(
                &payload,
                "execution_key",
                try protocol.executionProjection(
                    arena,
                    description.execution,
                ),
            );
            try protocol.put(
                &payload,
                "dependency_lease_ids",
                try support.stringsValue(arena, requested_leases),
            );
            var input_paths = protocol.array(arena);
            for (description.ordered_inputs) |input| {
                const object_path = try storage.objectPathAlloc(
                    arena,
                    &self.worker.store,
                    input.blob,
                );
                try protocol.append(
                    &input_paths,
                    protocol.string(object_path),
                );
            }
            try protocol.put(&payload, "input_object_paths", input_paths);
            try protocol.put(
                &payload,
                "output_path",
                protocol.string(paths.output_path),
            );
            try protocol.put(
                &payload,
                "profile_receipt_path",
                protocol.string(paths.profile_receipt_path),
            );
            try protocol.put(
                &payload,
                "candidate_ref_path",
                protocol.string(paths.candidate_ref_path),
            );

            const response = try self.worker.handle(arena, .{
                .sequence = 0,
                .action = .build,
                .payload = payload,
            });
            const object = try protocol.objectValue(response);
            try protocol.exactKeys(object, &.{
                "output_path",
                "output_ref",
                "profile_receipt_path",
                "candidate_ref_path",
                "consumed_lease_ids",
            });
            try expectString(
                object,
                "output_path",
                paths.output_path,
                error.CampaignFinalLiveBuildResponseMismatchV2,
            );
            try expectString(
                object,
                "profile_receipt_path",
                paths.profile_receipt_path,
                error.CampaignFinalLiveBuildResponseMismatchV2,
            );
            try expectString(
                object,
                "candidate_ref_path",
                paths.candidate_ref_path,
                error.CampaignFinalLiveBuildResponseMismatchV2,
            );
            const consumed = try support.stringArray(
                arena,
                object.get("consumed_lease_ids") orelse
                    return error.CampaignFinalLiveBuildResponseMismatchV2,
            );
            if (!stringsEqual(consumed, requested_leases))
                return error.CampaignFinalLiveBuildResponseMismatchV2;
            const output_ref = try protocol.parseBlobRef(
                object.get("output_ref") orelse
                    return error.CampaignFinalLiveBuildResponseMismatchV2,
            );
            if (output_ref.kind != description.node.output_kind or
                output_ref.schema_version !=
                    description.node.output_schema_version)
            {
                return error.CampaignFinalLiveBuildResponseMismatchV2;
            }
            try storage.exactOpenRef(
                scratch_allocator,
                &self.worker.store,
                output_ref,
                null,
            );

            const owned = try owner_allocator.create(
                OwnedBuiltPublicationV2,
            );
            errdefer owner_allocator.destroy(owned);
            const output_path = try owner_allocator.dupe(
                u8,
                paths.output_path,
            );
            errdefer owner_allocator.free(output_path);
            const profile_path = try owner_allocator.dupe(
                u8,
                paths.profile_receipt_path,
            );
            errdefer owner_allocator.free(profile_path);
            const candidate_path = try owner_allocator.dupe(
                u8,
                paths.candidate_ref_path,
            );
            errdefer owner_allocator.free(candidate_path);
            owned.* = .{
                .allocator = owner_allocator,
                .executor = self,
                .description = description,
                .output_ref = output_ref,
                .output_path = output_path,
                .profile_receipt_path = profile_path,
                .candidate_ref_path = candidate_path,
            };
            return owned;
        }

        /// Cold verification owns StageManifest publication. The returned
        /// selector is copied out of the request arena while the verifier's
        /// typed parent payload remains retained only inside the worker.
        pub fn coldOpenAndRetain(
            self: *Self,
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            built: *const OwnedBuiltPublicationV2,
            validator_version: u32,
            mode: []const u8,
        ) !*OwnedRetainedParentV2 {
            if (built.executor != self or validator_version == 0)
                return error.CampaignFinalLiveColdOpenMismatchV2;
            try support.validateMode(mode);
            try built.validate(scratch_allocator);
            const description = built.description;

            var arena_state = std.heap.ArenaAllocator.init(scratch_allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var payload = protocol.jsonObject(arena);
            try protocol.put(
                &payload,
                "node",
                try protocol.nodeValue(arena, description.node),
            );
            try protocol.put(
                &payload,
                "ordered_inputs",
                try protocol.inputRefsValue(
                    arena,
                    description.ordered_inputs,
                ),
            );
            try protocol.put(
                &payload,
                "semantic_key",
                try protocol.semanticProjection(arena, description.semantic),
            );
            try protocol.put(
                &payload,
                "execution_key",
                try protocol.executionProjection(
                    arena,
                    description.execution,
                ),
            );
            try protocol.put(
                &payload,
                "output_ref",
                try protocol.blobRefValue(arena, built.output_ref),
            );
            try protocol.put(
                &payload,
                "output_path",
                protocol.string(try storage.objectPathAlloc(
                    arena,
                    &self.worker.store,
                    built.output_ref,
                )),
            );
            try protocol.put(
                &payload,
                "dependency_stage_manifest_refs",
                try blobRefsValue(
                    arena,
                    description.dependency_stage_manifest_refs,
                ),
            );
            try protocol.put(&payload, "stage_manifest_ref", .null);
            try protocol.put(
                &payload,
                "validator_version",
                protocol.integer(validator_version),
            );
            try protocol.put(&payload, "mode", protocol.string(mode));

            const response = try self.worker.handle(arena, .{
                .sequence = 1,
                .action = .cold_open,
                .payload = payload,
            });
            const object = try protocol.objectValue(response);
            try protocol.exactKeys(object, &.{
                "validation_receipt",
                "lease_id",
                "stage_manifest_ref",
            });
            const lease_id = try protocol.stringField(object, "lease_id");
            if (lease_id.len == 0)
                return error.CampaignFinalLiveColdOpenMismatchV2;
            var retained = true;
            errdefer if (retained)
                self.closeLease(arena, lease_id) catch {};
            const receipt = try protocol.objectValue(
                object.get("validation_receipt") orelse
                    return error.CampaignFinalLiveColdOpenMismatchV2,
            );
            try protocol.validateSeal(arena, receipt);
            const manifest_ref = try protocol.parseBlobRef(
                object.get("stage_manifest_ref") orelse
                    return error.CampaignFinalLiveColdOpenMismatchV2,
            );
            try self.worker.validateRetainedLeaseIdentity(
                lease_id,
                description.node.node_id,
                built.output_ref,
                manifest_ref,
            );

            const owned = try owner_allocator.create(
                OwnedRetainedParentV2,
            );
            errdefer owner_allocator.destroy(owned);
            const lease_copy = try owner_allocator.dupe(u8, lease_id);
            errdefer owner_allocator.free(lease_copy);
            owned.* = .{
                .allocator = owner_allocator,
                .executor = self,
                .description = description,
                .output_ref = built.output_ref,
                .stage_manifest_ref = manifest_ref,
                .lease_id = lease_copy,
            };
            try owned.validate();
            retained = false;
            return owned;
        }

        pub fn closeRetainedParent(
            self: *Self,
            scratch_allocator: std.mem.Allocator,
            parent: *const OwnedRetainedParentV2,
        ) !void {
            if (parent.executor != self)
                return error.CampaignFinalLiveColdOpenMismatchV2;
            try parent.validate();
            var arena_state = std.heap.ArenaAllocator.init(scratch_allocator);
            defer arena_state.deinit();
            try self.closeLease(arena_state.allocator(), parent.lease_id);
        }

        fn publishKeys(
            self: *Self,
            allocator: std.mem.Allocator,
            description: *const StageDescriptionV2,
        ) !void {
            const semantic_bytes = try description.semantic
                .canonicalBytesAlloc(allocator);
            defer allocator.free(semantic_bytes);
            const execution_bytes = try description.execution.canonicalBytes();
            const semantic_ref = try self.worker.store.putBytes(
                .semantic_key,
                artifact_store.types.format_version_v1,
                semantic_bytes,
            );
            const execution_ref = try self.worker.store.putBytes(
                .execution_key,
                artifact_store.types.format_version_v1,
                &execution_bytes,
            );
            if (!std.mem.eql(
                u8,
                &semantic_ref.sha256,
                &description.semantic.identity,
            ) or !std.mem.eql(
                u8,
                &execution_ref.sha256,
                &description.execution.identity,
            )) return error.CampaignFinalLiveKeyPublicationMismatchV2;
        }

        fn closeLease(
            self: *Self,
            allocator: std.mem.Allocator,
            lease_id: []const u8,
        ) !void {
            var payload = protocol.jsonObject(allocator);
            try protocol.put(
                &payload,
                "lease_id",
                protocol.string(lease_id),
            );
            _ = try self.worker.handle(allocator, .{
                .sequence = 2,
                .action = .close_lease,
                .payload = payload,
            });
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn blobRefsValue(
    allocator: std.mem.Allocator,
    values: []const artifact_store.BlobRefV1,
) !protocol.Json {
    var result = protocol.array(allocator);
    for (values) |value|
        try protocol.append(
            &result,
            try protocol.blobRefValue(allocator, value),
        );
    return result;
}

fn expectString(
    object: std.json.ObjectMap,
    name: []const u8,
    expected: []const u8,
    mismatch: anyerror,
) !void {
    if (!std.mem.eql(
        u8,
        try protocol.stringField(object, name),
        expected,
    )) return mismatch;
}

fn stringsEqual(
    left: []const []const u8,
    right: []const []const u8,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

fn assertWorker(comptime Worker: type) void {
    inline for (.{ "handle", "validateRetainedLeaseIdentity" }) |name|
        if (!@hasDecl(Worker, name))
            @compileError("campaign live build executor worker missing " ++ name);
    if (!@hasField(Worker, "store"))
        @compileError("campaign live build executor worker lacks Zig CAS");
}

fn assertLiveBuildPlan(comptime LiveBuildPlan: type) void {
    inline for (.{
        "StageDescriptionV2",
        "validate",
        "stageDescription",
        "dependencyLeaseIds",
    }) |name| if (!@hasDecl(LiveBuildPlan, name))
        @compileError("campaign live build executor plan missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign live build executor gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        SERIALIZABLE_LIVE_LEASE_SELECTOR or
        !EXACT_ORDERED_LEASE_CONSUMPTION_REQUIRED or
        PARENT_LEASE_PAYLOAD_EXPOSED or LEASE_CLOSE_OWNERSHIP)
    {
        @compileError("campaign final live build executor contract drifted");
    }
}
