//! Verifier-owned Stage-101 frontier for one authenticated V4 campaign.
//!
//! Construction starts from an exact STWCIT04 BlobRef, repeats the complete
//! transitive campaign-table validation, then deep-owns every published
//! Stage-101 node/key projection. Each seal-last StageManifest is replayed
//! against its exact seven-input row before the proof is independently cold
//! opened into the production native-leaf lease type. Neither the table ref,
//! proof ref, manifest, nor a digest can mint a live capability on its own.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const importer =
    @import("recursive_pipeline_incremental_campaign_importer_v4.zig");
const namespace_mod =
    @import("recursive_pipeline_campaign_namespace_v1.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const native_worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const fresh_input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const role0_authority =
    @import("recursive_pipeline_worker_campaign_real_leaf_authority_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const GENUINE_FIXTURE_LEAF_COUNT: u32 = 3;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const TABLE_REF_ALONE_IS_ADMISSION = false;
pub const PROOF_REF_ALONE_IS_ADMISSION = false;
pub const EVERY_LEAF_INDEPENDENTLY_COLD_OPENED = true;
pub const RUNTIME_CAMPAIGN_COUNT = true;

pub const Error = error{
    AuthenticatedStage101CampaignMismatchV4,
    AuthenticatedStage101PublicationMismatchV4,
    AuthenticatedStage101TableReferenceMismatchV4,
};

/// Borrowed publication supplied by the seal-last Stage-101 worker epoch.
/// `open` deep-copies all pointer-bearing fields before retaining anything.
pub const PublishedStage101V4 = struct {
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    output_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
};

pub fn Types(comptime Engine: type) type {
    const NativeAdapter = native_worker.AdapterForEngine(Engine);
    const NativeLease = NativeAdapter.LeasePayload;
    const FreshInput = fresh_input_mod.FreshInputV4(Engine);

    return struct {
        pub const EngineV4 = Engine;
        pub const NativeLeaseV4 = NativeLease;
        pub const PublicationV4 = PublishedStage101V4;

        const Family = @This();

        /// Heap-stable, nonserializable authority. The Store is borrowed and
        /// must outlive this owner. Everything originating in the worker
        /// request arena is deep-owned here.
        pub const OwnedCampaignV4 = struct {
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            table_ref: artifact_store.BlobRefV1,
            table: table_mod.OwnedCampaignTableV4,
            campaign_namespace_sha256: artifact_store.Digest,
            entries: []*OwnedEntryV4,

            const Self = @This();

            pub fn open(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                table_ref: artifact_store.BlobRefV1,
                publications: []const PublishedStage101V4,
            ) !*Self {
                try validateTableRef(table_ref, null);
                var table_blob = try store.openBlob(
                    table_ref,
                    table_mod.ARTIFACT_KIND,
                    table_mod.CAS_SCHEMA_VERSION,
                    table_ref.byte_count,
                );
                defer table_blob.deinit(store.allocator);
                if (!artifact_store.BlobRefV1.eql(table_blob.ref, table_ref))
                    return error.AuthenticatedStage101TableReferenceMismatchV4;

                // This is the independent trust boundary: both manifests,
                // every recipe, and all seven direct/nested refs are reopened.
                try importer.coldValidateCampaignTable(
                    allocator,
                    store,
                    table_blob.bytes,
                );
                var table = try table_mod.decodeAlloc(
                    allocator,
                    table_blob.bytes,
                );
                var table_owned = true;
                defer if (table_owned) table.deinit();
                try validateTableRef(table_ref, table.value.segment_count);
                if (publications.len != table.value.records.len)
                    return error.AuthenticatedStage101CampaignMismatchV4;
                const namespace = try namespace_mod.fromValidatedTable(
                    &table.value,
                );

                const entries = try allocator.alloc(
                    *OwnedEntryV4,
                    publications.len,
                );
                var entries_owned = true;
                var entry_count: usize = 0;
                errdefer if (entries_owned) {
                    var index = entry_count;
                    while (index != 0) {
                        index -= 1;
                        entries[index].deinit();
                    }
                    allocator.free(entries);
                };
                for (publications, 0..) |publication, index| {
                    entries[index] = try OwnedEntryV4.open(
                        allocator,
                        store,
                        &table.value,
                        namespace,
                        index,
                        publication,
                    );
                    entry_count += 1;
                }
                const self = try allocator.create(Self);
                var self_initialized = false;
                errdefer if (!self_initialized) allocator.destroy(self);
                self.* = .{
                    .allocator = allocator,
                    .store = store,
                    .table_ref = table_ref,
                    .table = table,
                    .campaign_namespace_sha256 = namespace,
                    .entries = entries,
                };
                self_initialized = true;
                table_owned = false;
                entries_owned = false;
                errdefer self.deinit();
                try self.validate();
                return self;
            }

            /// Fixture-only cardinality guard. The underlying owner remains
            /// runtime-count generic and derives its count from STWCIT04.
            pub fn openThreeLeafFixture(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                table_ref: artifact_store.BlobRefV1,
                publications: []const PublishedStage101V4,
            ) !*Self {
                const result = try open(
                    allocator,
                    store,
                    table_ref,
                    publications,
                );
                errdefer result.deinit();
                if (result.table.value.segment_count !=
                    GENUINE_FIXTURE_LEAF_COUNT)
                {
                    return error.AuthenticatedStage101CampaignMismatchV4;
                }
                return result;
            }

            pub fn deinit(self: *Self) void {
                const allocator = self.allocator;
                var index = self.entries.len;
                while (index != 0) {
                    index -= 1;
                    self.entries[index].deinit();
                }
                allocator.free(self.entries);
                self.table.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            pub fn validate(self: *const Self) !void {
                try self.table.value.validate();
                try validateTableRef(
                    self.table_ref,
                    self.table.value.segment_count,
                );
                const encoded = try table_mod.encodeAlloc(
                    self.allocator,
                    &self.table.value,
                );
                defer self.allocator.free(encoded);
                const canonical_digest = artifact_store.digestBytes(encoded);
                const expected_namespace = try namespace_mod
                    .fromValidatedTable(&self.table.value);
                if (self.entries.len != self.table.value.records.len or
                    self.table_ref.byte_count !=
                        @as(u64, @intCast(encoded.len)) or
                    !std.mem.eql(
                        u8,
                        &self.table_ref.sha256,
                        &canonical_digest,
                    ) or !std.mem.eql(
                    u8,
                    &self.campaign_namespace_sha256,
                    &expected_namespace,
                )) return error.AuthenticatedStage101CampaignMismatchV4;
                for (self.entries, 0..) |entry, index| {
                    try entry.validate(
                        self.allocator,
                        self.store,
                        &self.table.value,
                        self.campaign_namespace_sha256,
                        index,
                    );
                }
            }

            pub fn campaignTable(self: *const Self) *const table_mod.CampaignTableV4 {
                return &self.table.value;
            }

            pub fn leafCount(self: *const Self) usize {
                return self.entries.len;
            }

            /// Revalidated borrowed Stage-101 publication for a downstream
            /// Stage-102 request owner. Pointer-bearing Node/Semantic fields
            /// remain owned by `self` and die before `deinit`; no durable ref
            /// or copied digest can mint this view independently.
            pub fn publicationAt(
                self: *const Self,
                scratch_allocator: std.mem.Allocator,
                index: usize,
            ) !PublishedStage101V4 {
                if (index >= self.entries.len)
                    return error.AuthenticatedStage101CampaignMismatchV4;
                const entry = self.entries[index];
                try entry.validate(
                    scratch_allocator,
                    self.store,
                    &self.table.value,
                    self.campaign_namespace_sha256,
                    index,
                );
                return entry.publication();
            }

            pub fn retainedLeaseAt(
                self: *const Self,
                index: usize,
            ) !*const NativeLease {
                if (index >= self.entries.len)
                    return error.AuthenticatedStage101CampaignMismatchV4;
                try self.entries[index].lease.validate();
                return &self.entries[index].lease;
            }

            pub fn retainedFreshInputAt(
                self: *const Self,
                index: usize,
            ) !*const FreshInput {
                return &(try self.retainedLeaseAt(index)).fresh;
            }

            /// Independent replay for a Stage-102 build/cold boundary. The
            /// retained dependency lease is never moved or reused as output.
            pub fn coldOpenLeaseAt(
                self: *const Self,
                allocator: std.mem.Allocator,
                index: usize,
            ) !NativeLease {
                if (index >= self.entries.len)
                    return error.AuthenticatedStage101CampaignMismatchV4;
                const entry = self.entries[index];
                try entry.validate(
                    self.allocator,
                    self.store,
                    &self.table.value,
                    self.campaign_namespace_sha256,
                    index,
                );
                var proof = try self.store.openBlob(
                    entry.output_ref,
                    .proof_artifact,
                    native_worker.OUTPUT_SCHEMA_VERSION,
                    native_worker.MAXIMUM_OUTPUT_BYTES,
                );
                defer proof.deinit(self.store.allocator);
                return NativeAdapter.coldOpenLease(
                    allocator,
                    self.store,
                    proof.bytes,
                    entry.node,
                    entry.semantic.value,
                    &self.table.value.records[index].stage_inputs,
                );
            }

            /// Streaming campaign-geometry opener. Ownership of the returned
            /// FreshInput belongs to the caller; no retained lease is moved.
            pub fn openFreshInput(
                self: *const Self,
                allocator: std.mem.Allocator,
                index: usize,
            ) !FreshInput {
                var lease = try self.coldOpenLeaseAt(allocator, index);
                const result = lease.fresh;
                lease.fresh = undefined;
                return result;
            }

            /// Binds later Stage-102 task identities to these exact native
            /// admissions. Wrapper identities are not predicted here.
            pub fn fillStage101Admissions(
                self: *const Self,
                wrapper_task_identities: []const artifact_store.Digest,
                destination: []role0_authority.Stage101AdmissionV4,
            ) !void {
                try self.validate();
                if (wrapper_task_identities.len != self.entries.len or
                    destination.len != self.entries.len)
                {
                    return error.AuthenticatedStage101CampaignMismatchV4;
                }
                for (self.entries, wrapper_task_identities, 0..) |
                    entry,
                    wrapper_identity,
                    index,
                | {
                    for (wrapper_task_identities[0..index]) |earlier| {
                        if (std.mem.eql(u8, &earlier, &wrapper_identity))
                            return error.AuthenticatedStage101CampaignMismatchV4;
                    }
                    destination[index] = .{
                        .wrapper_local_task_identity_sha256 = wrapper_identity,
                        .node = entry.node,
                        .semantic = &entry.semantic.value,
                    };
                    try destination[index].validateAgainstRow(
                        self.allocator,
                        &self.table.value,
                        index,
                        self.campaign_namespace_sha256,
                    );
                }
            }

            comptime {
                rejectCodec(Self);
            }
        };

        const OwnedEntryV4 = struct {
            allocator: std.mem.Allocator,
            node_id: []u8,
            adapter: []u8,
            dependencies: []protocol.Dependency,
            external_inputs: []artifact_store.InputRefV1,
            semantic_options: std.json.Parsed(protocol.Json),
            node: protocol.Node,
            semantic: artifact_store.OwnedSemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            lease: NativeLease,

            fn open(
                allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                table: *const table_mod.CampaignTableV4,
                namespace: artifact_store.Digest,
                index: usize,
                source_publication: PublishedStage101V4,
            ) !*OwnedEntryV4 {
                const self = try clone(allocator, source_publication);
                var self_owned = true;
                defer if (self_owned) self.deinitBeforeLease();
                try validatePublicationEnvelope(
                    allocator,
                    table,
                    namespace,
                    index,
                    self.publication(),
                );
                try support.validateExistingStageManifest(
                    allocator,
                    store,
                    self.stage_manifest_ref,
                    self.node,
                    &table.records[index].stage_inputs,
                    self.semantic.value,
                    self.execution,
                    self.output_ref,
                    &.{},
                    "root",
                );
                var proof = try store.openBlob(
                    self.output_ref,
                    .proof_artifact,
                    native_worker.OUTPUT_SCHEMA_VERSION,
                    native_worker.MAXIMUM_OUTPUT_BYTES,
                );
                defer proof.deinit(store.allocator);
                self.lease = try NativeAdapter.coldOpenLease(
                    allocator,
                    store,
                    proof.bytes,
                    self.node,
                    self.semantic.value,
                    &table.records[index].stage_inputs,
                );
                self_owned = false;
                errdefer self.deinit();
                try self.lease.validate();
                return self;
            }

            fn clone(
                allocator: std.mem.Allocator,
                source: PublishedStage101V4,
            ) !*OwnedEntryV4 {
                const node_id = try allocator.dupe(u8, source.node.node_id);
                errdefer allocator.free(node_id);
                const adapter = try allocator.dupe(u8, source.node.adapter);
                errdefer allocator.free(adapter);
                const dependencies = try allocator.alloc(
                    protocol.Dependency,
                    source.node.dependencies.len,
                );
                var dependency_count: usize = 0;
                errdefer {
                    for (dependencies[0..dependency_count]) |dependency|
                        allocator.free(dependency.node_id);
                    allocator.free(dependencies);
                }
                for (source.node.dependencies, dependencies) |
                    source_dependency,
                    *destination,
                | {
                    destination.* = .{
                        .node_id = try allocator.dupe(
                            u8,
                            source_dependency.node_id,
                        ),
                        .role = source_dependency.role,
                        .ordinal = source_dependency.ordinal,
                    };
                    dependency_count += 1;
                }
                const external_inputs = try allocator.dupe(
                    artifact_store.InputRefV1,
                    source.node.external_inputs,
                );
                errdefer allocator.free(external_inputs);
                const options_bytes = try protocol.canonicalAlloc(
                    allocator,
                    source.node.semantic_options,
                    false,
                );
                defer allocator.free(options_bytes);
                var semantic_options = try std.json.parseFromSlice(
                    protocol.Json,
                    allocator,
                    options_bytes,
                    .{ .parse_numbers = true },
                );
                errdefer semantic_options.deinit();
                const semantic_bytes = try source.semantic
                    .canonicalBytesAlloc(allocator);
                defer allocator.free(semantic_bytes);
                var semantic = try artifact_store.decodeSemanticKeyAlloc(
                    allocator,
                    semantic_bytes,
                );
                errdefer semantic.deinit(allocator);
                const self = try allocator.create(OwnedEntryV4);
                self.* = .{
                    .allocator = allocator,
                    .node_id = node_id,
                    .adapter = adapter,
                    .dependencies = dependencies,
                    .external_inputs = external_inputs,
                    .semantic_options = semantic_options,
                    .node = undefined,
                    .semantic = semantic,
                    .execution = source.execution,
                    .output_ref = source.output_ref,
                    .stage_manifest_ref = source.stage_manifest_ref,
                    .lease = undefined,
                };
                self.node = .{
                    .node_id = self.node_id,
                    .stage_kind = source.node.stage_kind,
                    .stage_schema_version = source.node.stage_schema_version,
                    .adapter = self.adapter,
                    .dependencies = self.dependencies,
                    .external_inputs = self.external_inputs,
                    .local_task_identity_sha256 = source.node.local_task_identity_sha256,
                    .semantic_authorities = source.node.semantic_authorities,
                    .semantic_options = self.semantic_options.value,
                    .cpu_tokens = source.node.cpu_tokens,
                    .rss_tokens = source.node.rss_tokens,
                    .output_kind = source.node.output_kind,
                    .output_schema_version = source.node.output_schema_version,
                };
                return self;
            }

            fn validate(
                self: *const OwnedEntryV4,
                scratch_allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                table: *const table_mod.CampaignTableV4,
                namespace: artifact_store.Digest,
                index: usize,
            ) !void {
                try validatePublicationEnvelope(
                    scratch_allocator,
                    table,
                    namespace,
                    index,
                    self.publication(),
                );
                try support.validateExistingStageManifest(
                    scratch_allocator,
                    store,
                    self.stage_manifest_ref,
                    self.node,
                    &table.records[index].stage_inputs,
                    self.semantic.value,
                    self.execution,
                    self.output_ref,
                    &.{},
                    "root",
                );
                try self.lease.validate();
                if (!std.mem.eql(
                    u8,
                    &self.lease.semantic_key_identity,
                    &self.semantic.value.identity,
                )) return error.AuthenticatedStage101PublicationMismatchV4;
            }

            fn publication(self: *const OwnedEntryV4) PublishedStage101V4 {
                return .{
                    .node = self.node,
                    .semantic = self.semantic.value,
                    .execution = self.execution,
                    .output_ref = self.output_ref,
                    .stage_manifest_ref = self.stage_manifest_ref,
                };
            }

            fn deinit(self: *OwnedEntryV4) void {
                self.lease.deinit();
                self.deinitBeforeLease();
            }

            fn deinitBeforeLease(self: *OwnedEntryV4) void {
                const allocator = self.allocator;
                self.semantic.deinit(allocator);
                self.semantic_options.deinit();
                allocator.free(self.external_inputs);
                for (self.dependencies) |dependency|
                    allocator.free(dependency.node_id);
                allocator.free(self.dependencies);
                allocator.free(self.adapter);
                allocator.free(self.node_id);
                allocator.destroy(self);
            }
        };

        comptime {
            if (Family.NativeLeaseV4 != NativeAdapter.LeasePayload)
                @compileError("authenticated Stage101 lease type drifted");
        }
    };
}

fn validatePublicationEnvelope(
    allocator: std.mem.Allocator,
    table: *const table_mod.CampaignTableV4,
    namespace: artifact_store.Digest,
    index: usize,
    publication: PublishedStage101V4,
) !void {
    table.validate() catch
        return error.AuthenticatedStage101PublicationMismatchV4;
    if (index >= table.records.len)
        return error.AuthenticatedStage101PublicationMismatchV4;
    const row = table.records[index];
    const expected = native_worker.semanticProjection(
        row.segment_index,
        table.segment_count,
        &row.stage_inputs,
        namespace,
    ) catch return error.AuthenticatedStage101PublicationMismatchV4;
    publication.semantic.validate(allocator) catch
        return error.AuthenticatedStage101PublicationMismatchV4;
    publication.execution.validate() catch
        return error.AuthenticatedStage101PublicationMismatchV4;
    support.validateKeys(
        allocator,
        publication.node,
        &row.stage_inputs,
        publication.semantic,
        publication.execution,
    ) catch return error.AuthenticatedStage101PublicationMismatchV4;
    const fields = publication.semantic.fields;
    if (publication.node.node_id.len == 0 or
        publication.node.stage_kind != .prove or
        publication.node.stage_schema_version !=
            native_worker.STAGE_SCHEMA_VERSION or
        publication.node.dependencies.len != 0 or
        publication.node.external_inputs.len != table_mod.STAGE_INPUT_COUNT or
        publication.node.output_kind != .proof_artifact or
        publication.node.output_schema_version !=
            native_worker.OUTPUT_SCHEMA_VERSION or
        !native_worker.Adapter.acceptsNodeAdapter(publication.node.adapter) or
        publication.node.cpu_tokens == 0 or publication.node.rss_tokens == 0 or
        !std.mem.eql(
            u8,
            &publication.node.local_task_identity_sha256,
            &expected.local_task_identity_sha256,
        ) or !std.meta.eql(
        publication.node.semantic_authorities,
        expected.authorities,
    ) or !std.mem.eql(
        u8,
        &fields.campaign_namespace,
        &namespace,
    ) or !std.mem.eql(
        u8,
        &fields.local_task_identity,
        &expected.local_task_identity_sha256,
    ) or !semanticAuthoritiesEqual(fields, expected.authorities) or
        fields.stage_kind != .prove or
        fields.stage_schema_version != native_worker.STAGE_SCHEMA_VERSION or
        fields.ordered_inputs.len != table_mod.STAGE_INPUT_COUNT)
    {
        return error.AuthenticatedStage101PublicationMismatchV4;
    }
    for (
        publication.node.external_inputs,
        fields.ordered_inputs,
        row.stage_inputs,
    ) |node_input, key_input, expected_input| {
        if (!std.meta.eql(node_input, expected_input) or
            !std.meta.eql(key_input, expected_input))
        {
            return error.AuthenticatedStage101PublicationMismatchV4;
        }
    }
    const options = protocol.objectValue(
        publication.node.semantic_options,
    ) catch return error.AuthenticatedStage101PublicationMismatchV4;
    protocol.exactKeys(options, &.{}) catch
        return error.AuthenticatedStage101PublicationMismatchV4;
    try validateProofRef(publication.output_ref);
    try validateManifestRef(publication.stage_manifest_ref);
}

fn validateTableRef(
    reference: artifact_store.BlobRefV1,
    expected_count: ?u32,
) !void {
    reference.validate() catch
        return error.AuthenticatedStage101TableReferenceMismatchV4;
    const maximum = table_mod.encodedByteCount(
        table_mod.MAX_SEGMENT_COUNT,
    ) catch unreachable;
    const minimum = table_mod.encodedByteCount(
        table_mod.MIN_SEGMENT_COUNT,
    ) catch unreachable;
    const expected_bytes: ?u64 = if (expected_count) |count|
        std.math.cast(
            u64,
            table_mod.encodedByteCount(count) catch
                return error.AuthenticatedStage101TableReferenceMismatchV4,
        ) orelse return error.AuthenticatedStage101TableReferenceMismatchV4
    else
        null;
    if (reference.kind != table_mod.ARTIFACT_KIND or
        reference.format_version != artifact_store.types.format_version_v1 or
        reference.schema_version != table_mod.CAS_SCHEMA_VERSION or
        reference.byte_count < @as(u64, @intCast(minimum)) or
        reference.byte_count > @as(u64, @intCast(maximum)) or
        (expected_bytes != null and reference.byte_count != expected_bytes.?))
    {
        return error.AuthenticatedStage101TableReferenceMismatchV4;
    }
}

fn validateProofRef(reference: artifact_store.BlobRefV1) !void {
    reference.validate() catch
        return error.AuthenticatedStage101PublicationMismatchV4;
    if (reference.kind != .proof_artifact or
        reference.format_version != artifact_store.types.format_version_v1 or
        reference.schema_version != native_worker.OUTPUT_SCHEMA_VERSION or
        reference.byte_count == 0 or
        reference.byte_count >
            @as(u64, @intCast(native_worker.MAXIMUM_OUTPUT_BYTES)))
    {
        return error.AuthenticatedStage101PublicationMismatchV4;
    }
}

fn validateManifestRef(reference: artifact_store.BlobRefV1) !void {
    reference.validate() catch
        return error.AuthenticatedStage101PublicationMismatchV4;
    if (reference.kind != .stage_manifest or
        reference.format_version != artifact_store.types.format_version_v1 or
        reference.schema_version != support.stage_manifest_schema_version or
        reference.byte_count == 0)
    {
        return error.AuthenticatedStage101PublicationMismatchV4;
    }
}

fn semanticAuthoritiesEqual(
    fields: artifact_store.SemanticKeyFieldsV1,
    expected: protocol.SemanticAuthorities,
) bool {
    return std.mem.eql(
        u8,
        &fields.protocol_identity,
        &expected.protocol_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.program_identity,
        &expected.program_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.profile_identity,
        &expected.profile_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.pcs_identity,
        &expected.pcs_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.security_identity,
        &expected.security_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.statement_identity,
        &expected.statement_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.provider_identity,
        &expected.provider_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.layout_identity,
        &expected.layout_identity_sha256,
    ) and std.mem.eql(
        u8,
        &fields.registry_identity,
        &expected.registry_identity_sha256,
    );
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "serialize", "deserialize" }) |name| {
        if (@hasDecl(T, name))
            @compileError("authenticated Stage101 capability gained codec " ++ name);
    }
}

pub const testing = struct {
    pub const validatePublicationEnvelopeV4 = validatePublicationEnvelope;
    pub const validateTableRefV4 = validateTableRef;
};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        GENUINE_FIXTURE_LEAF_COUNT != 3 or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        TABLE_REF_ALONE_IS_ADMISSION or PROOF_REF_ALONE_IS_ADMISSION or
        !EVERY_LEAF_INDEPENDENTLY_COLD_OPENED or !RUNTIME_CAMPAIGN_COUNT)
    {
        @compileError("authenticated Stage101 campaign owner drifted");
    }
}
