//! Persistent typed recursive-pipeline worker.
//!
//! The controller sees only canonical JSON projections and typed CAS refs.
//! Proof bytes, live verifier state, and opaque leases remain inside Zig.
//! Adapters receive the Zig store directly so a proof-bearing stage can
//! publish/reopen nested proof blobs without returning those bytes or paths to
//! Python. `coldOpenLease` must remint its payload from those durable refs;
//! the worker never constructs a capability from the envelope digest alone.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const storage = @import("recursive_pipeline_worker_storage_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const build_dispatch = @import("recursive_pipeline_worker_build_dispatch_v1.zig");

const maximum_small_artifact_bytes: usize = 16 * 1024 * 1024;

pub const LIVE_LEASE_IDENTITY_VALIDATION = true;
pub const LIVE_LEASE_PAYLOAD_IS_OPAQUE = true;
pub const LIVE_LEASE_VALIDATED_PROJECTION = true;

fn maximumOutputBytes(comptime Adapter: type) usize {
    if (@hasDecl(Adapter, "maximum_output_bytes")) {
        if (Adapter.maximum_output_bytes == 0)
            @compileError("worker adapter maximum_output_bytes must be nonzero");
        return Adapter.maximum_output_bytes;
    }
    return maximum_small_artifact_bytes;
}

fn Lease(comptime Adapter: type) type {
    return struct {
        node_id: []u8,
        output_ref: artifact_store.BlobRefV1,
        stage_manifest_ref: artifact_store.BlobRefV1,
        /// Adapter-owned, verifier-minted process-local state. This value is
        /// never encoded in JSON, a StageManifest, or the CAS. A restarted
        /// worker must remint it through `coldOpenLease`.
        payload: Adapter.LeasePayload,

        const Self = @This();

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            Adapter.deinitLeasePayload(&self.payload, allocator);
            allocator.free(self.node_id);
            self.* = undefined;
        }
    };
}

pub fn Worker(comptime Adapter: type) type {
    assertAdapterLeaseContract(Adapter);
    const LeaseValue = Lease(Adapter);
    return struct {
        const Self = @This();

        pub const AdapterV1 = Adapter;

        allocator: std.mem.Allocator,
        store: artifact_store.Store,
        leases: std.StringHashMap(LeaseValue),
        lease_salt: u64,
        next_lease: u64 = 1,
        next_candidate: u64 = 1,
        failure_phase: []const u8 = "idle",
        failure_ref: ?artifact_store.BlobRefV1 = null,

        pub fn init(
            allocator: std.mem.Allocator,
            store_root: []const u8,
        ) !Self {
            return .{
                .allocator = allocator,
                .store = try artifact_store.Store.openOrCreate(
                    allocator,
                    store_root,
                    false,
                ),
                .leases = std.StringHashMap(LeaseValue).init(allocator),
                .lease_salt = std.crypto.random.int(u64),
            };
        }

        pub fn deinit(self: *Self) void {
            var iterator = self.leases.iterator();
            while (iterator.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.leases.deinit();
            self.store.deinit();
            self.* = undefined;
        }

        /// Confirms that an opaque process-local selector still names the
        /// exact typed lease retained by this worker. The verifier payload is
        /// deliberately neither returned nor projected into a durable form.
        pub fn validateRetainedLeaseIdentity(
            self: *Self,
            lease_id: []const u8,
            node_id: []const u8,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
        ) !void {
            const lease = self.leases.getPtr(lease_id) orelse
                return error.UnknownWorkerLease;
            if (!std.mem.eql(u8, lease.node_id, node_id) or
                !artifact_store.BlobRefV1.eql(lease.output_ref, output_ref) or
                !artifact_store.BlobRefV1.eql(
                    lease.stage_manifest_ref,
                    stage_manifest_ref,
                )) return error.WorkerLeaseIdentityMismatch;
        }

        /// Produces only an adapter-defined, validated process-local view.
        /// The raw lease payload remains private to the worker. Callers must
        /// hold an exclusive worker borrow while using any pointer contained
        /// by the projection because inserting another lease may move map
        /// storage.
        pub fn projectRetainedLease(
            self: *Self,
            comptime Projection: type,
            lease_id: []const u8,
            node_id: []const u8,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            authority: anytype,
        ) !Projection {
            if (comptime !@hasDecl(Adapter, "RetainedLeaseProjection") or
                !@hasDecl(Adapter, "projectRetainedLease"))
            {
                @compileError(
                    "worker adapter lacks a retained-lease projection",
                );
            }
            if (comptime Adapter.RetainedLeaseProjection != Projection)
                @compileError("worker retained-lease projection type drifted");
            try self.validateRetainedLeaseIdentity(
                lease_id,
                node_id,
                output_ref,
                stage_manifest_ref,
            );
            const lease = self.leases.getPtr(lease_id) orelse
                return error.UnknownWorkerLease;
            return Adapter.projectRetainedLease(
                &lease.payload,
                authority,
            );
        }

        pub fn handle(
            self: *Self,
            allocator: std.mem.Allocator,
            request: protocol.Request,
        ) !protocol.Json {
            self.setFailureContext(request.action.wireName(), null);
            return switch (request.action) {
                .describe => self.describe(allocator, request.payload),
                .derive => self.derive(allocator, request.payload),
                .build => self.build(allocator, request.payload),
                .cold_open => self.coldOpen(allocator, request.payload),
                .close_lease => self.closeLease(allocator, request.payload),
                .shutdown => support.shutdownPayload(allocator, request.payload),
            };
        }

        /// Exact-body entry used only by genuine cryptographic gates while an
        /// adapter's release boolean remains false. Parsing, key reopening,
        /// CAS publication, StageManifest sealing, dependency consumption,
        /// and lease custody are the same bodies as `handle`.
        pub fn handleForGenuineGate(
            self: *Self,
            allocator: std.mem.Allocator,
            request: protocol.Request,
        ) !protocol.Json {
            self.setFailureContext(request.action.wireName(), null);
            return switch (request.action) {
                .describe => self.describe(allocator, request.payload),
                .derive => self.derive(allocator, request.payload),
                .build => self.buildImpl(allocator, request.payload, true),
                .cold_open => self.coldOpenImpl(
                    allocator,
                    request.payload,
                    true,
                ),
                .close_lease => self.closeLease(allocator, request.payload),
                .shutdown => support.shutdownPayload(allocator, request.payload),
            };
        }

        fn describe(
            _: *Self,
            allocator: std.mem.Allocator,
            payload: protocol.Json,
        ) !protocol.Json {
            const object = try protocol.objectValue(payload);
            try protocol.exactKeys(
                object,
                &.{ "stage_kind", "stage_schema_version" },
            );
            const description = try Adapter.describe(
                @enumFromInt(try protocol.positiveField(
                    u32,
                    object,
                    "stage_kind",
                )),
                try protocol.positiveField(
                    u16,
                    object,
                    "stage_schema_version",
                ),
            );
            var result = protocol.jsonObject(allocator);
            try protocol.put(
                &result,
                "description",
                try protocol.descriptionValue(allocator, description),
            );
            return result;
        }

        fn derive(
            self: *Self,
            allocator: std.mem.Allocator,
            payload: protocol.Json,
        ) !protocol.Json {
            const object = try protocol.objectValue(payload);
            try protocol.exactKeys(object, &.{
                "campaign_namespace_sha256",
                "node",
                "ordered_inputs",
                "execution_authorities",
            });
            const node = try protocol.parseNode(
                allocator,
                object.get("node") orelse return error.MissingWorkerField,
            );
            const inputs = try protocol.parseInputRefs(
                allocator,
                object.get("ordered_inputs") orelse
                    return error.MissingWorkerField,
            );
            try support.requireAdapter(Adapter, node);
            try support.validateNodeInputs(node, inputs);
            const semantic = try support.createSemanticKey(
                allocator,
                node,
                inputs,
                try protocol.digestField(
                    object,
                    "campaign_namespace_sha256",
                    true,
                ),
            );
            const authorities = try protocol.parseExecutionAuthorities(
                object.get("execution_authorities") orelse
                    return error.MissingWorkerField,
            );
            const execution = try artifact_store.ExecutionKeyV1.create(
                authorities.fields(semantic.identity),
            );
            self.setFailureContext("derive.key_publication", null);
            const semantic_bytes = try semantic.canonicalBytesAlloc(allocator);
            const execution_bytes = try execution.canonicalBytes();
            const semantic_ref = try self.store.putBytes(
                .semantic_key,
                1,
                semantic_bytes,
            );
            const execution_ref = try self.store.putBytes(
                .execution_key,
                1,
                &execution_bytes,
            );
            if (!std.mem.eql(u8, &semantic_ref.sha256, &semantic.identity) or
                !std.mem.eql(u8, &execution_ref.sha256, &execution.identity))
            {
                return error.WorkerKeyPublicationMismatch;
            }
            var result = protocol.jsonObject(allocator);
            try protocol.put(
                &result,
                "semantic_key_hex",
                protocol.string(try support.bytesHexAlloc(allocator, semantic_bytes)),
            );
            try protocol.put(
                &result,
                "execution_key_hex",
                protocol.string(try support.bytesHexAlloc(allocator, &execution_bytes)),
            );
            try protocol.put(
                &result,
                "semantic_projection",
                try protocol.semanticProjection(allocator, semantic),
            );
            try protocol.put(
                &result,
                "execution_projection",
                try protocol.executionProjection(allocator, execution),
            );
            return result;
        }

        fn build(
            self: *Self,
            allocator: std.mem.Allocator,
            payload: protocol.Json,
        ) !protocol.Json {
            return self.buildImpl(allocator, payload, false);
        }

        fn buildImpl(
            self: *Self,
            allocator: std.mem.Allocator,
            payload: protocol.Json,
            comptime genuine_gate: bool,
        ) !protocol.Json {
            const object = try protocol.objectValue(payload);
            try protocol.exactKeys(object, &.{
                "node",
                "ordered_inputs",
                "semantic_key",
                "execution_key",
                "dependency_lease_ids",
                "input_object_paths",
                "output_path",
                "profile_receipt_path",
                "candidate_ref_path",
            });
            const node = try protocol.parseNode(
                allocator,
                object.get("node") orelse return error.MissingWorkerField,
            );
            const inputs = try protocol.parseInputRefs(
                allocator,
                object.get("ordered_inputs") orelse
                    return error.MissingWorkerField,
            );
            const semantic = try protocol.parseSemanticKey(
                allocator,
                object.get("semantic_key") orelse
                    return error.MissingWorkerField,
            );
            const execution = try protocol.parseExecutionKey(
                object.get("execution_key") orelse
                    return error.MissingWorkerField,
            );
            try support.requireAdapter(Adapter, node);
            if (comptime genuine_gate) {
                requireGenuineGateAdapter(Adapter);
            } else if (comptime !Adapter.available) {
                return Adapter.unavailable();
            }
            try support.validateKeys(
                allocator,
                node,
                inputs,
                semantic,
                execution,
            );
            self.setFailureContext("build.key_reopen", null);
            try self.reopenKeys(allocator, semantic, execution);
            const lease_ids = try support.stringArray(
                allocator,
                object.get("dependency_lease_ids") orelse
                    return error.MissingWorkerField,
            );
            const dependency_payloads = try allocator.alloc(
                *const Adapter.LeasePayload,
                lease_ids.len,
            );
            defer allocator.free(dependency_payloads);
            try self.validateDependencyLeases(
                node,
                inputs,
                lease_ids,
                dependency_payloads,
            );
            const input_paths = try support.stringArray(
                allocator,
                object.get("input_object_paths") orelse
                    return error.MissingWorkerField,
            );
            if (input_paths.len != inputs.len)
                return error.WorkerInputObjectPathMismatch;
            for (inputs, input_paths) |input, path| {
                self.setFailureContext("build.input_cold_open", input.blob);
                try storage.exactOpenRef(
                    allocator,
                    &self.store,
                    input.blob,
                    path,
                );
            }
            const output_path = try protocol.stringField(object, "output_path");
            const profile_path = try protocol.stringField(
                object,
                "profile_receipt_path",
            );
            const candidate_ref_path = try protocol.stringField(
                object,
                "candidate_ref_path",
            );
            try support.validateDistinctPaths(
                output_path,
                profile_path,
                candidate_ref_path,
            );
            const candidate_ordinal = self.next_candidate;
            const next_candidate = std.math.add(
                u64,
                candidate_ordinal,
                1,
            ) catch return error.WorkerCandidateOrdinalExhausted;
            self.setFailureContext("build.output_construct", null);
            const output_bytes = if (comptime genuine_gate)
                try build_dispatch.buildForGenuineGate(
                    Adapter,
                    allocator,
                    &self.store,
                    node,
                    semantic,
                    execution,
                    inputs,
                    candidate_ordinal,
                    dependency_payloads,
                )
            else
                try build_dispatch.build(
                    Adapter,
                    allocator,
                    &self.store,
                    node,
                    semantic,
                    execution,
                    inputs,
                    candidate_ordinal,
                    dependency_payloads,
                );
            self.setFailureContext("build.output_publish", null);
            try storage.writeExclusive(allocator, output_path, output_bytes);
            self.setFailureContext("build.output_ingest", null);
            const output_ref = try storage.ingestTypedPath(
                &self.store,
                output_path,
                node.output_kind,
                node.output_schema_version,
            );
            self.setFailureContext("build.profile_construct", output_ref);
            const profile = try Adapter.profileValue(
                allocator,
                node,
                semantic,
                execution,
                candidate_ordinal,
            );
            self.setFailureContext("build.profile_publish", output_ref);
            const profile_bytes = try protocol.canonicalAlloc(
                allocator,
                profile,
                false,
            );
            try storage.writeExclusive(allocator, profile_path, profile_bytes);
            var candidate_ref = protocol.jsonObject(allocator);
            try protocol.put(
                &candidate_ref,
                "schema",
                protocol.string(protocol.candidate_ref_schema),
            );
            try protocol.put(
                &candidate_ref,
                "output_ref",
                try protocol.blobRefValue(allocator, output_ref),
            );
            try protocol.sealObject(allocator, &candidate_ref);
            const candidate_ref_bytes = try protocol.canonicalAlloc(
                allocator,
                candidate_ref,
                false,
            );
            try storage.writeExclusive(
                allocator,
                candidate_ref_path,
                candidate_ref_bytes,
            );
            self.setFailureContext("build.lease_commit", output_ref);
            try self.consumeLeases(lease_ids);
            self.next_candidate = next_candidate;

            var result = protocol.jsonObject(allocator);
            try protocol.put(
                &result,
                "output_path",
                protocol.string(output_path),
            );
            try protocol.put(
                &result,
                "output_ref",
                try protocol.blobRefValue(allocator, output_ref),
            );
            try protocol.put(
                &result,
                "profile_receipt_path",
                protocol.string(profile_path),
            );
            try protocol.put(
                &result,
                "candidate_ref_path",
                protocol.string(candidate_ref_path),
            );
            try protocol.put(
                &result,
                "consumed_lease_ids",
                try support.stringsValue(allocator, lease_ids),
            );
            return result;
        }

        fn coldOpen(
            self: *Self,
            allocator: std.mem.Allocator,
            payload: protocol.Json,
        ) !protocol.Json {
            return self.coldOpenImpl(allocator, payload, false);
        }

        fn coldOpenImpl(
            self: *Self,
            allocator: std.mem.Allocator,
            payload: protocol.Json,
            comptime genuine_gate: bool,
        ) !protocol.Json {
            const object = try protocol.objectValue(payload);
            try protocol.exactKeys(object, &.{
                "node",
                "ordered_inputs",
                "semantic_key",
                "execution_key",
                "output_ref",
                "output_path",
                "dependency_stage_manifest_refs",
                "stage_manifest_ref",
                "validator_version",
                "mode",
            });
            const node = try protocol.parseNode(
                allocator,
                object.get("node") orelse return error.MissingWorkerField,
            );
            const inputs = try protocol.parseInputRefs(
                allocator,
                object.get("ordered_inputs") orelse
                    return error.MissingWorkerField,
            );
            const semantic = try protocol.parseSemanticKey(
                allocator,
                object.get("semantic_key") orelse
                    return error.MissingWorkerField,
            );
            const execution = try protocol.parseExecutionKey(
                object.get("execution_key") orelse
                    return error.MissingWorkerField,
            );
            try support.requireAdapter(Adapter, node);
            if (comptime genuine_gate) {
                requireGenuineGateAdapter(Adapter);
            } else if (comptime !Adapter.available) {
                return Adapter.unavailable();
            }
            try support.validateKeys(
                allocator,
                node,
                inputs,
                semantic,
                execution,
            );
            self.setFailureContext("cold_open.key_reopen", null);
            try self.reopenKeys(allocator, semantic, execution);
            const output_ref = try protocol.parseBlobRef(
                object.get("output_ref") orelse return error.MissingWorkerField,
            );
            if (output_ref.kind != node.output_kind or
                output_ref.schema_version != node.output_schema_version)
            {
                return error.WorkerOutputCodecMismatch;
            }
            self.setFailureContext("cold_open.output", output_ref);
            try storage.exactOpenRef(
                allocator,
                &self.store,
                output_ref,
                try protocol.stringField(object, "output_path"),
            );
            const dependency_refs = try support.parseBlobRefArray(
                allocator,
                object.get("dependency_stage_manifest_refs") orelse
                    return error.MissingWorkerField,
            );
            const supplied_manifest = object.get("stage_manifest_ref") orelse
                return error.MissingWorkerField;
            if (dependency_refs.len != 0) {
                self.setFailureContext("cold_open.dependencies", null);
                try support.validateDependencyManifests(
                    allocator,
                    &self.store,
                    node,
                    dependency_refs,
                );
            } else if (supplied_manifest == .null and
                node.dependencies.len != 0)
            {
                return error.WorkerDependencyManifestMismatch;
            }
            self.setFailureContext("cold_open.output_read", output_ref);
            const output_bytes = try storage.readSmallRefAlloc(
                allocator,
                &self.store,
                output_ref,
                maximumOutputBytes(Adapter),
            );
            defer self.store.allocator.free(output_bytes);
            self.setFailureContext("cold_open.output_semantics", output_ref);
            var lease_payload = if (comptime genuine_gate)
                try Adapter.coldOpenLeaseForGenuineGate(
                    allocator,
                    &self.store,
                    output_bytes,
                    node,
                    semantic,
                    inputs,
                )
            else
                try Adapter.coldOpenLease(
                    allocator,
                    &self.store,
                    output_bytes,
                    node,
                    semantic,
                    inputs,
                );
            var lease_payload_owned = true;
            defer if (lease_payload_owned)
                Adapter.deinitLeasePayload(&lease_payload, allocator);
            const mode = try protocol.stringField(object, "mode");
            try support.validateMode(mode);
            const validator_version = try protocol.positiveField(
                u32,
                object,
                "validator_version",
            );
            self.setFailureContext("cold_open.stage_manifest", output_ref);
            const manifest_ref = try self.resolveStageManifest(
                allocator,
                supplied_manifest,
                node,
                inputs,
                semantic,
                execution,
                output_ref,
                dependency_refs,
                mode,
            );
            if (comptime genuine_gate) {
                self.setFailureContext(
                    "cold_open.admission_adopt",
                    output_ref,
                );
                try Adapter.adoptColdPublicationForGenuineGate(
                    allocator,
                    node,
                    semantic,
                    execution,
                    inputs,
                    output_ref,
                    manifest_ref,
                    dependency_refs,
                );
            } else if (comptime @hasDecl(Adapter, "adoptColdPublication")) {
                self.setFailureContext(
                    "cold_open.admission_adopt",
                    output_ref,
                );
                try Adapter.adoptColdPublication(
                    allocator,
                    node,
                    semantic,
                    execution,
                    inputs,
                    output_ref,
                    manifest_ref,
                    dependency_refs,
                );
            }
            const lease_id = try self.retainLease(
                node.node_id,
                output_ref,
                manifest_ref,
                lease_payload,
            );
            lease_payload_owned = false;
            errdefer self.discardLease(lease_id) catch {};
            self.setFailureContext("cold_open.validation_receipt", output_ref);
            const receipt = try Adapter.validationValue(
                allocator,
                node,
                semantic,
                output_ref,
                validator_version,
                mode,
            );
            var result = protocol.jsonObject(allocator);
            try protocol.put(&result, "validation_receipt", receipt);
            try protocol.put(
                &result,
                "lease_id",
                protocol.string(lease_id),
            );
            try protocol.put(
                &result,
                "stage_manifest_ref",
                try protocol.blobRefValue(allocator, manifest_ref),
            );
            return result;
        }

        pub fn failureContext(
            self: *const Self,
        ) struct { phase: []const u8, ref: ?artifact_store.BlobRefV1 } {
            return .{ .phase = self.failure_phase, .ref = self.failure_ref };
        }

        fn setFailureContext(
            self: *Self,
            phase: []const u8,
            ref: ?artifact_store.BlobRefV1,
        ) void {
            self.failure_phase = phase;
            self.failure_ref = ref;
        }

        fn closeLease(
            self: *Self,
            allocator: std.mem.Allocator,
            payload: protocol.Json,
        ) !protocol.Json {
            const object = try protocol.objectValue(payload);
            try protocol.exactKeys(object, &.{"lease_id"});
            try self.discardLease(try protocol.stringField(object, "lease_id"));
            return protocol.jsonObject(allocator);
        }

        fn reopenKeys(
            self: *Self,
            allocator: std.mem.Allocator,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
        ) !void {
            const semantic_bytes = try semantic.canonicalBytesAlloc(allocator);
            const execution_bytes = try execution.canonicalBytes();
            const semantic_ref = try artifact_store.BlobRefV1.create(
                .semantic_key,
                1,
                @intCast(semantic_bytes.len),
                semantic.identity,
            );
            const execution_ref = try artifact_store.BlobRefV1.create(
                .execution_key,
                1,
                execution_bytes.len,
                execution.identity,
            );
            try storage.exactOpenRef(
                allocator,
                &self.store,
                semantic_ref,
                null,
            );
            try storage.exactOpenRef(
                allocator,
                &self.store,
                execution_ref,
                null,
            );
        }

        fn validateDependencyLeases(
            self: *Self,
            node: protocol.Node,
            inputs: []const artifact_store.InputRefV1,
            lease_ids: []const []const u8,
            destination: []*const Adapter.LeasePayload,
        ) !void {
            if (lease_ids.len != node.dependencies.len or
                destination.len != lease_ids.len)
            {
                return error.WorkerDependencyLeaseMismatch;
            }
            for (lease_ids, 0..) |lease_id, index| {
                for (lease_ids[0..index]) |previous| {
                    if (std.mem.eql(u8, lease_id, previous))
                        return error.WorkerDependencyLeaseMismatch;
                }
                const lease = self.leases.getPtr(lease_id) orelse
                    return error.UnknownWorkerLease;
                const dependency = node.dependencies[index];
                const input = support.findInput(
                    inputs,
                    dependency.role,
                    dependency.ordinal,
                ) orelse
                    return error.WorkerDependencyLeaseMismatch;
                if (!std.mem.eql(u8, lease.node_id, dependency.node_id) or
                    !artifact_store.BlobRefV1.eql(lease.output_ref, input.blob))
                {
                    return error.WorkerDependencyLeaseMismatch;
                }
                destination[index] = &lease.payload;
            }
        }

        fn consumeLeases(self: *Self, lease_ids: []const []const u8) !void {
            for (lease_ids) |lease_id| {
                if (!self.leases.contains(lease_id))
                    return error.UnknownWorkerLease;
            }
            for (lease_ids) |lease_id| {
                const removed = self.leases.fetchRemove(lease_id) orelse
                    unreachable;
                self.allocator.free(removed.key);
                var lease = removed.value;
                lease.deinit(self.allocator);
            }
        }

        fn retainLease(
            self: *Self,
            node_id: []const u8,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            payload: Adapter.LeasePayload,
        ) ![]const u8 {
            const lease_id = try std.fmt.allocPrint(
                self.allocator,
                "lease-{x:0>16}-{x:0>16}",
                .{ self.lease_salt, self.next_lease },
            );
            errdefer self.allocator.free(lease_id);
            self.next_lease +%= 1;
            const node_copy = try self.allocator.dupe(u8, node_id);
            errdefer self.allocator.free(node_copy);
            try self.leases.putNoClobber(lease_id, .{
                .node_id = node_copy,
                .output_ref = output_ref,
                .stage_manifest_ref = stage_manifest_ref,
                .payload = payload,
            });
            return lease_id;
        }

        fn discardLease(self: *Self, lease_id: []const u8) !void {
            const removed = self.leases.fetchRemove(lease_id) orelse
                return error.UnknownWorkerLease;
            self.allocator.free(removed.key);
            var lease = removed.value;
            lease.deinit(self.allocator);
        }

        fn resolveStageManifest(
            self: *Self,
            allocator: std.mem.Allocator,
            supplied: protocol.Json,
            node: protocol.Node,
            inputs: []const artifact_store.InputRefV1,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            output_ref: artifact_store.BlobRefV1,
            dependencies: []const artifact_store.BlobRefV1,
            mode: []const u8,
        ) !artifact_store.BlobRefV1 {
            if (supplied == .null) {
                // StageManifestV1 is a borrowed view. Keep its single output
                // storage in this caller through canonical encoding instead
                // of returning a slice into a helper's expired stack frame.
                const ordered_outputs = [_]artifact_store.BlobRefV1{output_ref};
                const expected = try support.createStageManifest(
                    allocator,
                    node,
                    inputs,
                    semantic,
                    execution,
                    &ordered_outputs,
                    dependencies,
                );
                const bytes = try expected.canonicalBytesAlloc(allocator);
                const published = try self.store.putBytes(
                    .stage_manifest,
                    support.stage_manifest_schema_version,
                    bytes,
                );
                if (!std.mem.eql(u8, &published.sha256, &expected.identity))
                    return error.WorkerStageManifestMismatch;
                return published;
            }
            const observed = try protocol.parseBlobRef(supplied);
            try support.validateExistingStageManifest(
                allocator,
                &self.store,
                observed,
                node,
                inputs,
                semantic,
                execution,
                output_ref,
                dependencies,
                mode,
            );
            return observed;
        }
    };
}

fn assertAdapterLeaseContract(comptime Adapter: type) void {
    inline for (.{
        "LeasePayload",
        "buildOutputWithLeases",
        "coldOpenLease",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(Adapter, name))
        @compileError("recursive worker adapter missing lease contract: " ++ name);
}

fn requireGenuineGateAdapter(comptime Adapter: type) void {
    inline for (.{
        "buildOutputWithExecutionAndLeasesForGenuineGate",
        "coldOpenLeaseForGenuineGate",
        "adoptColdPublicationForGenuineGate",
    }) |name| if (!@hasDecl(Adapter, name))
        @compileError("genuine-gate worker adapter missing contract: " ++ name);
}

test "lease consumption is atomic and process local" {
    const mock = @import("recursive_pipeline_worker_mock_v1.zig");
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var worker = try Worker(mock.Adapter).init(allocator, root);
    defer worker.deinit();
    const output_ref = try artifact_store.BlobRefV1.create(
        .recursion_node,
        1,
        1,
        artifact_store.digestBytes("output"),
    );
    const manifest_ref = try artifact_store.BlobRefV1.create(
        .stage_manifest,
        1,
        1,
        artifact_store.digestBytes("manifest"),
    );
    const lease = try worker.retainLease(
        "leaf/000",
        output_ref,
        manifest_ref,
        mock.Adapter.testingLeasePayload(),
    );
    try std.testing.expectEqual(@as(usize, 1), worker.leases.count());
    try std.testing.expectError(
        error.UnknownWorkerLease,
        worker.consumeLeases(&.{ lease, "unknown-lease" }),
    );
    try std.testing.expectEqual(@as(usize, 1), worker.leases.count());
    try worker.consumeLeases(&.{lease});
    try std.testing.expectEqual(@as(usize, 0), worker.leases.count());
}

test "typed lease payload survives errors and releases exactly once" {
    const LeaseLifecycleTestAdapter = @import(
        "recursive_pipeline_worker_lease_test_support_v1.zig",
    ).Adapter;
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var worker = try Worker(LeaseLifecycleTestAdapter).init(allocator, root);
    defer worker.deinit();
    const output_ref = try artifact_store.BlobRefV1.create(
        .recursion_node,
        1,
        1,
        artifact_store.digestBytes("typed-output"),
    );
    const manifest_ref = try artifact_store.BlobRefV1.create(
        .stage_manifest,
        1,
        1,
        artifact_store.digestBytes("typed-manifest"),
    );
    var releases: usize = 0;
    const lease = try worker.retainLease(
        "leaf/typed",
        output_ref,
        manifest_ref,
        .{
            .allocation = try allocator.dupe(u8, "verifier-owned-capture"),
            .releases = &releases,
        },
    );
    try std.testing.expectError(
        error.UnknownWorkerLease,
        worker.consumeLeases(&.{ lease, "missing-typed-lease" }),
    );
    try std.testing.expectEqual(@as(usize, 0), releases);
    try std.testing.expectEqual(@as(usize, 1), worker.leases.count());
    try worker.consumeLeases(&.{lease});
    try std.testing.expectEqual(@as(usize, 1), releases);
    try std.testing.expectEqual(@as(usize, 0), worker.leases.count());
}
