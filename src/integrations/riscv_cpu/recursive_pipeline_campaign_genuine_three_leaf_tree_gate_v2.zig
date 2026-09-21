//! Gate-only final 3 -> 4 campaign tree over production cold-proof owners.
//!
//! This owner starts after the genuine padding transaction has minted one
//! FinalRemint and after the exact Stage-102 inventory has been sealed and
//! installed. It publishes the campaign-empty Stage-103 source, proves and
//! independently cold-opens its role-1 wrapper, then proves the three role-2
//! parents bottom-up. Every proof and node is written to the real CAS before
//! its StageManifest is sealed. The final Driver validates the complete
//! frontier and root from those durable transports.
//!
//! The process-local selectors below exist only to exercise the Driver in a
//! coordinated genuine gate. They are not Worker lease identities and cannot
//! activate a route. Production admission still requires the separate live
//! Worker receipt binder.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store = @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const empty_source =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const role1_child =
    @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const description_mod =
    @import("recursive_pipeline_campaign_final_description_v2.zig");
const target_native =
    @import("recursive_pipeline_campaign_target_native_q193_pairs_v2.zig");
const driver_mod = @import("recursive_pipeline_campaign_final_driver_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_Q193_GATE_GREEN = false;
pub const GENUINE_GATE_ONLY = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const LIVE_WORKER_LEASE_ADMISSION = false;
pub const PROOF_AND_NODE_PRECEDE_STAGE_MANIFEST = true;
pub const EVERY_PROOF_IS_FRESHLY_COLD_OPENED = true;
pub const EXECUTION_POLICY_HAS_NO_SERIAL_FALLBACK = true;

const REAL_LEAF_COUNT: usize = 3;
const PADDED_LEAF_COUNT: usize = 4;
const FIRST_PARENT_COUNT: usize = 2;
const ROOT_COUNT: usize = 1;
const CHILD_COUNT: usize = 2;
const SELECTOR_BYTE_COUNT: usize = 96;

pub const Error = error{
    GenuineThreeLeafTreeGateIdentityMismatchV2,
    GenuineThreeLeafTreeGateOwnershipMismatchV2,
    GenuineThreeLeafTreeGatePublicationMismatchV2,
    GenuineThreeLeafTreeGateTopologyMismatchV2,
};

/// `FinalFixture` is the exact three-leaf FinalRemint owner, `Lifecycle` is
/// Mill's installed immutable Stage-102 session, and `FinalWorker` supplies
/// the recursive production lease family. No nominal role is erased.
pub fn Types(
    comptime FinalFixture: type,
    comptime Lifecycle: type,
    comptime FinalWorker: type,
    comptime TargetNative: type,
    comptime Driver: type,
) type {
    assertTypes(FinalFixture, Lifecycle, FinalWorker, TargetNative);

    const FinalOwner = FinalFixture.OwnedFinalV2;
    const FinalSessionOwner = Lifecycle.OwnedFinalSessionV4;
    const ImmutableSession = Lifecycle.ImmutableSessionV4;
    const Role0View = Lifecycle.BorrowedRole0FinalV4;
    const Role0Lease = Lifecycle.Role0LeaseV4;
    const Role1Lease = role1_child.OwnedLeaseV2;
    const Role2Types = FinalWorker.Role2TypesV2;
    const DependencyLease = Role2Types.DependencyLease;
    const CommonLeaseHandle = Role2Types.CommonLeaseHandleV2;
    const Role2Lease = TargetNative.ProductionLeasePayloadV2;
    const StageDescription = description_mod.OwnedStageDescriptionV2;
    return struct {
        const SelfTypes = @This();

        pub const FinalOwnerV2 = FinalOwner;
        pub const FinalSessionOwnerV4 = FinalSessionOwner;
        pub const ImmutableSessionV4 = ImmutableSession;
        pub const Role0LeaseV4 = Role0Lease;
        pub const Role1LeaseV2 = Role1Lease;
        pub const Role2LeaseV2 = Role2Lease;
        pub const DependencyLeaseV2 = DependencyLease;
        pub const FinalDriverV2 = Driver;

        /// One exact typed child plus its durable worker description fields.
        /// The selector is generated from the authenticated role/coordinate
        /// and has no codec or admission meaning outside this gate owner.
        pub const BoundChildV2 = struct {
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            dependency: DependencyLease,
            node_ptr: *const protocol.Node,
            semantic_ptr: *const artifact_store.SemanticKeyV1,
            execution_ptr: *const artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_manifest_refs: [CHILD_COUNT]artifact_store.BlobRefV1,
            dependency_manifest_count: u8,
            artifact_ptr: *const campaign_artifact.Artifact,
            selector_bytes: [SELECTOR_BYTE_COUNT]u8,
            selector_len: u8,

            pub fn fromRole0(
                final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
                view: Role0View,
            ) !BoundChildV2 {
                try view.validate();
                if (view.final_remint != final_remint)
                    return error.GenuineThreeLeafTreeGateIdentityMismatchV2;
                const manifests = [_]artifact_store.BlobRefV1{
                    view.admission.dependency_stage_manifest_ref,
                };
                return init(
                    final_remint,
                    DependencyLease.fromReal(view.lease),
                    view.admission.node,
                    view.admission.semantic,
                    view.admission.execution,
                    view.admission.ordered_inputs[0..],
                    view.output_ref,
                    view.admission.stage_manifest_ref,
                    &manifests,
                    view.lease.nodeArtifact(),
                );
            }

            pub fn fromRole1(owner: *const OwnedRole1V2) !BoundChildV2 {
                return init(
                    owner.final_remint,
                    DependencyLease.fromEmpty(&owner.lease),
                    &owner.description.node,
                    &owner.description.semantic,
                    &owner.description.execution,
                    owner.description.ordered_inputs,
                    owner.sealed.node_ref,
                    owner.sealed.stage_manifest_ref,
                    owner.description.dependency_stage_manifest_refs,
                    owner.lease.nodeArtifact(),
                );
            }

            pub fn fromRole2(owner: *const OwnedRole2V2) !BoundChildV2 {
                return init(
                    owner.final_remint,
                    DependencyLease.fromCommon(&owner.common_handle),
                    &owner.description.node,
                    &owner.description.semantic,
                    &owner.description.execution,
                    owner.description.ordered_inputs,
                    owner.sealed.node_ref,
                    owner.sealed.stage_manifest_ref,
                    owner.description.dependency_stage_manifest_refs,
                    owner.lease.nodeArtifact(),
                );
            }

            fn init(
                final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
                dependency: DependencyLease,
                node_ptr: *const protocol.Node,
                semantic_ptr: *const artifact_store.SemanticKeyV1,
                execution_ptr: *const artifact_store.ExecutionKeyV1,
                ordered_inputs: []const artifact_store.InputRefV1,
                output_ref: artifact_store.BlobRefV1,
                stage_manifest_ref: artifact_store.BlobRefV1,
                dependency_manifest_refs: []const artifact_store.BlobRefV1,
                artifact_ptr: *const campaign_artifact.Artifact,
            ) !BoundChildV2 {
                if (dependency_manifest_refs.len > CHILD_COUNT)
                    return error.GenuineThreeLeafTreeGatePublicationMismatchV2;
                var result = BoundChildV2{
                    .final_remint = final_remint,
                    .dependency = dependency,
                    .node_ptr = node_ptr,
                    .semantic_ptr = semantic_ptr,
                    .execution_ptr = execution_ptr,
                    .ordered_inputs = ordered_inputs,
                    .output_ref = output_ref,
                    .stage_manifest_ref = stage_manifest_ref,
                    .dependency_manifest_refs = @splat(
                        std.mem.zeroes(artifact_store.BlobRefV1),
                    ),
                    .dependency_manifest_count = @intCast(
                        dependency_manifest_refs.len,
                    ),
                    .artifact_ptr = artifact_ptr,
                    .selector_bytes = @splat(0),
                    .selector_len = 0,
                };
                for (dependency_manifest_refs, 0..) |value, index|
                    result.dependency_manifest_refs[index] = value;
                const selector = try std.fmt.bufPrint(
                    &result.selector_bytes,
                    "genuine-gate/{d}/{d}/{d}",
                    .{
                        @intFromEnum(dependency.role()),
                        artifact_ptr.coordinate.height,
                        artifact_ptr.coordinate.index,
                    },
                );
                result.selector_len = @intCast(selector.len);
                try result.validate();
                return result;
            }

            pub fn validate(self: *const BoundChildV2) !void {
                try self.final_remint.validateAgainstCampaign(
                    self.artifact_ptr.campaign_namespace_sha256,
                );
                try self.dependency.validateAgainst(self.final_remint);
                const projection = try self.dependency.foldProjection(
                    self.final_remint,
                );
                const expected_ref = try node_store.toSharedRef(
                    try campaign_artifact.artifactRef(
                        self.final_remint.shape,
                        self.artifact_ptr,
                    ),
                );
                try campaign_cas.validate(self.output_ref, .recursion_node);
                try campaign_cas.validate(
                    self.stage_manifest_ref,
                    .stage_manifest,
                );
                const dependency_count: usize = @intCast(
                    self.dependency_manifest_count,
                );
                if (dependency_count > CHILD_COUNT or
                    dependency_count != self.node_ptr.dependencies.len or
                    projection.authority != self.final_remint or
                    projection.node_artifact != self.artifact_ptr or
                    projection.role != self.dependency.role() or
                    !artifact_store.BlobRefV1.eql(
                        self.output_ref,
                        expected_ref,
                    ))
                {
                    return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;
                }
                for (self.dependencyManifestRefs()) |manifest|
                    try campaign_cas.validate(manifest, .stage_manifest);
                const zero = std.mem.zeroes(artifact_store.BlobRefV1);
                for (self.dependency_manifest_refs[dependency_count..]) |ref|
                    if (!std.meta.eql(ref, zero))
                        return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;

                var expected_storage: [SELECTOR_BYTE_COUNT]u8 = @splat(0);
                const expected = try std.fmt.bufPrint(
                    &expected_storage,
                    "genuine-gate/{d}/{d}/{d}",
                    .{
                        @intFromEnum(self.dependency.role()),
                        self.artifact_ptr.coordinate.height,
                        self.artifact_ptr.coordinate.index,
                    },
                );
                if (!std.mem.eql(u8, self.liveLeaseSelector(), expected))
                    return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;
            }

            pub fn node(self: *const BoundChildV2) *const protocol.Node {
                return self.node_ptr;
            }

            pub fn outputRef(
                self: *const BoundChildV2,
            ) artifact_store.BlobRefV1 {
                return self.output_ref;
            }

            pub fn stageManifestRef(
                self: *const BoundChildV2,
            ) artifact_store.BlobRefV1 {
                return self.stage_manifest_ref;
            }

            pub fn nodeArtifact(
                self: *const BoundChildV2,
            ) *const campaign_artifact.Artifact {
                return self.artifact_ptr;
            }

            pub fn liveLeaseSelector(
                self: *const BoundChildV2,
            ) []const u8 {
                return self.selector_bytes[0..self.selector_len];
            }

            pub fn dependencyManifestRefs(
                self: *const BoundChildV2,
            ) []const artifact_store.BlobRefV1 {
                return self.dependency_manifest_refs[0..self.dependency_manifest_count];
            }

            pub fn receipt(
                self: *const BoundChildV2,
            ) driver_mod.CommittedStageV2 {
                return .{
                    .node = self.node_ptr,
                    .semantic = self.semantic_ptr,
                    .execution = self.execution_ptr,
                    .ordered_inputs = self.ordered_inputs,
                    .output_ref = self.output_ref,
                    .stage_manifest_ref = self.stage_manifest_ref,
                    .dependency_stage_manifest_refs = self.dependencyManifestRefs(),
                    .lease_id = self.liveLeaseSelector(),
                };
            }

            comptime {
                rejectCodec(BoundChildV2);
            }
        };

        pub const OwnedRole1V2 = struct {
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            source_ref: artifact_store.BlobRefV1,
            description: *StageDescription,
            proof_bytes: []u8,
            lease: Role1Lease,
            candidate: target_native.GatePublicationV2,
            sealed: target_native.SealedGatePublicationV2,
            bound: BoundChildV2,

            pub fn init(
                allocator: std.mem.Allocator,
                scratch: std.mem.Allocator,
                store: *artifact_store.Store,
                final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
                policy: *const @import("recursive_pipeline_worker_execution_policy_v2.zig").PolicyV2,
                execution_authorities: protocol.ExecutionAuthorities,
                source: *const empty_source.ColdInputV2,
            ) anyerror!*OwnedRole1V2 {
                const source_bytes = try source.source.encodeCanonical(
                    &source.shape,
                );
                const source_ref = try store.putBytes(
                    .source,
                    empty_source.SCHEMA_VERSION,
                    &source_bytes,
                );
                const description = try description_mod.describeStage103(
                    allocator,
                    final_remint,
                    policy,
                    execution_authorities,
                    source_ref,
                    source,
                );
                var description_owned = true;
                defer if (description_owned) description.deinit();

                const proof_bytes = blk: {
                    var proved = try target_native.proveRole1ForGenuineGate(
                        allocator,
                        scratch,
                        description,
                        source,
                    );
                    defer proved.deinit();
                    break :blk try proved.proof.encodeArtifactAlloc(allocator);
                };
                var proof_bytes_owned = true;
                defer if (proof_bytes_owned) allocator.free(proof_bytes);

                var lease = try target_native.coldOpenRole1ForGenuineGate(
                    allocator,
                    scratch,
                    description,
                    source,
                    proof_bytes,
                );
                var lease_owned = true;
                defer if (lease_owned) lease.deinit();

                const self = try allocator.create(OwnedRole1V2);
                errdefer allocator.destroy(self);
                self.allocator = allocator;
                self.store = store;
                self.final_remint = final_remint;
                self.source_ref = source_ref;
                self.description = description;
                self.proof_bytes = proof_bytes;
                self.lease = lease;
                self.candidate = try target_native
                    .role1PublicationForGenuineGate(
                    scratch,
                    description,
                    source,
                    &self.lease,
                    proof_bytes,
                );
                self.sealed = try target_native.SealedGatePublicationV2
                    .publishSealLast(
                    scratch,
                    store,
                    &self.candidate,
                    &.{},
                );
                self.bound = try BoundChildV2.fromRole1(self);
                try self.validate(scratch);
                description_owned = false;
                proof_bytes_owned = false;
                lease_owned = false;
                return self;
            }

            pub fn validate(
                self: *const OwnedRole1V2,
                scratch: std.mem.Allocator,
            ) !void {
                try self.description.validate(scratch);
                try self.lease.validateForCampaign(self.final_remint);
                try self.candidate.validate(scratch);
                try self.sealed.validate(scratch);
                try self.bound.validate();
                if (self.description.final_remint != self.final_remint or
                    self.candidate.description != self.description or
                    self.candidate.proof_bytes.ptr != self.proof_bytes.ptr or
                    self.sealed.store != self.store or
                    self.sealed.candidate != &self.candidate or
                    self.bound.artifact_ptr != self.lease.nodeArtifact() or
                    !artifact_store.BlobRefV1.eql(
                        self.source_ref,
                        self.description.ordered_inputs[0].blob,
                    ) or !artifact_store.BlobRefV1.eql(
                    self.bound.output_ref,
                    self.sealed.node_ref,
                )) return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;
                const receipt = self.bound.receipt();
                try validateReceipt(&receipt, &self.bound);
            }

            pub fn deinit(self: *OwnedRole1V2) void {
                const allocator = self.allocator;
                self.lease.deinit();
                allocator.free(self.proof_bytes);
                self.description.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(OwnedRole1V2);
            }
        };

        pub const OwnedRole2V2 = struct {
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            description: *StageDescription,
            proof_bytes: []u8,
            lease: Role2Lease,
            common_handle: CommonLeaseHandle,
            candidate: target_native.GatePublicationV2,
            sealed: target_native.SealedGatePublicationV2,
            bound: BoundChildV2,

            pub fn init(
                allocator: std.mem.Allocator,
                scratch: std.mem.Allocator,
                store: *artifact_store.Store,
                final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
                policy: *const @import("recursive_pipeline_worker_execution_policy_v2.zig").PolicyV2,
                execution_authorities: protocol.ExecutionAuthorities,
                left: *const BoundChildV2,
                right: *const BoundChildV2,
            ) anyerror!*OwnedRole2V2 {
                try left.validate();
                try right.validate();
                if (left.final_remint != final_remint or
                    right.final_remint != final_remint)
                {
                    return error.GenuineThreeLeafTreeGateIdentityMismatchV2;
                }
                const Describer = description_mod.DescriberFor(
                    BoundChildV2,
                    BoundChildV2,
                );
                const description = try Describer.describeStage104(
                    allocator,
                    final_remint,
                    policy,
                    execution_authorities,
                    left,
                    right,
                );
                var description_owned = true;
                defer if (description_owned) description.deinit();
                const prepared = try TargetNative.PreparedRole2PairV2.init(
                    allocator,
                    scratch,
                    description,
                    left.dependency,
                    right.dependency,
                );
                defer prepared.deinit();

                const retained = blk: {
                    var proved = try TargetNative
                        .proveRole2TransitiveForGenuineGate(
                        allocator,
                        scratch,
                        store,
                        prepared,
                    );
                    defer proved.deinit();
                    const proof_bytes = try allocator.dupe(
                        u8,
                        proved.proofBytes(),
                    );
                    errdefer allocator.free(proof_bytes);
                    const node_bytes = try campaign_artifact.encodeCanonical(
                        final_remint.shape,
                        proved.nodeArtifact(),
                    );
                    break :blk .{
                        .proof_bytes = proof_bytes,
                        .node_bytes = node_bytes,
                    };
                };
                var proof_bytes_owned = true;
                defer if (proof_bytes_owned)
                    allocator.free(retained.proof_bytes);

                var lease = try TargetNative
                    .coldOpenRole2TransitiveForGenuineGate(
                    allocator,
                    scratch,
                    store,
                    prepared,
                    retained.proof_bytes,
                    &retained.node_bytes,
                );
                var lease_owned = true;
                defer if (lease_owned) lease.deinit();

                const self = try allocator.create(OwnedRole2V2);
                errdefer allocator.destroy(self);
                self.allocator = allocator;
                self.store = store;
                self.final_remint = final_remint;
                self.description = description;
                self.proof_bytes = retained.proof_bytes;
                self.lease = lease;
                self.common_handle = try CommonLeaseHandle.borrow(&self.lease);
                var handle_owned = true;
                defer if (handle_owned) self.common_handle.deinit();
                self.candidate = try target_native.GatePublicationV2.init(
                    scratch,
                    description,
                    self.proof_bytes,
                    self.lease.nodeArtifact().*,
                );
                self.sealed = try target_native.SealedGatePublicationV2
                    .publishSealLast(
                    scratch,
                    store,
                    &self.candidate,
                    description.dependency_stage_manifest_refs,
                );
                self.bound = try BoundChildV2.fromRole2(self);
                try self.validate(scratch);
                description_owned = false;
                proof_bytes_owned = false;
                lease_owned = false;
                handle_owned = false;
                return self;
            }

            pub fn validate(
                self: *const OwnedRole2V2,
                scratch: std.mem.Allocator,
            ) !void {
                try self.description.validate(scratch);
                try self.lease.validateForCampaign(self.final_remint);
                try self.common_handle.validateForCampaign(
                    self.final_remint,
                );
                try self.candidate.validate(scratch);
                try self.sealed.validate(scratch);
                try self.bound.validate();
                if (self.description.final_remint != self.final_remint or
                    self.candidate.description != self.description or
                    self.candidate.proof_bytes.ptr != self.proof_bytes.ptr or
                    self.sealed.store != self.store or
                    self.sealed.candidate != &self.candidate or
                    self.common_handle.owns_owner or
                    self.bound.artifact_ptr != self.lease.nodeArtifact() or
                    !artifact_store.BlobRefV1.eql(
                        self.bound.output_ref,
                        self.sealed.node_ref,
                    )) return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;
                const receipt = self.bound.receipt();
                try validateReceipt(&receipt, &self.bound);
            }

            pub fn deinit(self: *OwnedRole2V2) void {
                const allocator = self.allocator;
                self.common_handle.deinit();
                self.lease.deinit();
                allocator.free(self.proof_bytes);
                self.description.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            comptime {
                rejectCodec(OwnedRole2V2);
            }
        };

        /// Heap-stable complete gate. `final` and `lifecycle` are borrowed;
        /// they must outlive this owner so role-0 lease and authority pointers
        /// remain exact for every descendant proof.
        pub const OwnedTreeV2 = struct {
            allocator: std.mem.Allocator,
            final: *const FinalOwner,
            lifecycle: *FinalSessionOwner,
            session: *const ImmutableSession,
            store: *artifact_store.Store,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            execution_authorities: protocol.ExecutionAuthorities,
            role0_views: [REAL_LEAF_COUNT]Role0View,
            role0_children: [REAL_LEAF_COUNT]BoundChildV2,
            role1: ?*OwnedRole1V2,
            first_parents: [FIRST_PARENT_COUNT]?*OwnedRole2V2,
            root: ?*OwnedRole2V2,
            leaf_receipts: [PADDED_LEAF_COUNT]driver_mod.CommittedStageV2,
            first_parent_receipts: [FIRST_PARENT_COUNT]driver_mod.CommittedStageV2,
            root_receipts: [ROOT_COUNT]driver_mod.CommittedStageV2,

            pub fn proveAndSealForGenuineGate(
                allocator: std.mem.Allocator,
                scratch: std.mem.Allocator,
                final: *const FinalOwner,
                lifecycle: *FinalSessionOwner,
                execution_authorities: protocol.ExecutionAuthorities,
            ) anyerror!*OwnedTreeV2 {
                try final.validate();
                try lifecycle.validate(scratch);
                const session = try lifecycle.immutableSession();
                const final_remint = final.genuine.authority();
                try validateFinalSession(
                    scratch,
                    final,
                    session,
                    final_remint,
                );

                const self = try allocator.create(OwnedTreeV2);
                self.* = .{
                    .allocator = allocator,
                    .final = final,
                    .lifecycle = lifecycle,
                    .session = session,
                    .store = session.store,
                    .final_remint = final_remint,
                    .execution_authorities = execution_authorities,
                    .role0_views = undefined,
                    .role0_children = undefined,
                    .role1 = null,
                    .first_parents = @splat(null),
                    .root = null,
                    .leaf_receipts = undefined,
                    .first_parent_receipts = undefined,
                    .root_receipts = undefined,
                };
                errdefer self.deinit();

                for (session.entries, 0..) |entry, index| {
                    self.role0_views[index] = try lifecycle
                        .role0ForOutputForGenuineGate(entry.output_ref);
                    self.role0_children[index] = try BoundChildV2.fromRole0(
                        final_remint,
                        self.role0_views[index],
                    );
                }

                self.role1 = try OwnedRole1V2.init(
                    allocator,
                    scratch,
                    session.store,
                    final_remint,
                    session.policy,
                    execution_authorities,
                    &final.campaign.empty_source,
                );
                self.first_parents[0] = try OwnedRole2V2.init(
                    allocator,
                    scratch,
                    session.store,
                    final_remint,
                    session.policy,
                    execution_authorities,
                    &self.role0_children[0],
                    &self.role0_children[1],
                );
                self.first_parents[1] = try OwnedRole2V2.init(
                    allocator,
                    scratch,
                    session.store,
                    final_remint,
                    session.policy,
                    execution_authorities,
                    &self.role0_children[2],
                    &self.role1.?.bound,
                );
                self.root = try OwnedRole2V2.init(
                    allocator,
                    scratch,
                    session.store,
                    final_remint,
                    session.policy,
                    execution_authorities,
                    &self.first_parents[0].?.bound,
                    &self.first_parents[1].?.bound,
                );
                self.refreshReceipts();
                try self.validate(scratch);
                return self;
            }

            pub fn validate(
                self: *const OwnedTreeV2,
                scratch: std.mem.Allocator,
            ) !void {
                try self.final.validate();
                try self.lifecycle.validate(scratch);
                try validateFinalSession(
                    scratch,
                    self.final,
                    self.session,
                    self.final_remint,
                );
                const installed = try self.lifecycle.immutableSession();
                if (installed != self.session or
                    self.store != self.session.store or
                    self.role1 == null or self.root == null)
                {
                    return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;
                }
                for (self.first_parents) |parent|
                    if (parent == null)
                        return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;

                for (self.role0_views, &self.role0_children, 0..) |
                    view,
                    *child,
                    index,
                | {
                    try view.validate();
                    try child.validate();
                    if (view.session != self.session or
                        view.admission !=
                            &self.session.entries[index].admission or
                        child.dependency.role() !=
                            .ethereum_incremental_leaf_wrapper_v4)
                    {
                        return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;
                    }
                    try validateReceipt(
                        &self.leaf_receipts[index],
                        child,
                    );
                }
                try self.role1.?.validate(scratch);
                try validateReceipt(
                    &self.leaf_receipts[REAL_LEAF_COUNT],
                    &self.role1.?.bound,
                );
                for (self.first_parents, 0..) |parent, index| {
                    try parent.?.validate(scratch);
                    try validateReceipt(
                        &self.first_parent_receipts[index],
                        &parent.?.bound,
                    );
                }
                try self.root.?.validate(scratch);
                try validateReceipt(
                    &self.root_receipts[0],
                    &self.root.?.bound,
                );

                const driver = try Driver.init(scratch, self.session);
                try driver.validateLeafFrontier(
                    scratch,
                    &self.leaf_receipts,
                );
                try driver.validateLevel(
                    scratch,
                    1,
                    &self.leaf_receipts,
                    &self.first_parent_receipts,
                );
                try driver.validateLevel(
                    scratch,
                    self.final_remint.shape.root_height,
                    &self.first_parent_receipts,
                    &self.root_receipts,
                );
                const levels = [_][]const driver_mod.CommittedStageV2{
                    &self.leaf_receipts,
                    &self.first_parent_receipts,
                    &self.root_receipts,
                };
                const root_receipt = try driver.validateComplete(
                    scratch,
                    &levels,
                );
                if (root_receipt != &self.root_receipts[0] or
                    self.root.?.lease.nodeArtifact().stage_kind != .root or
                    !artifact_store.BlobRefV1.eql(
                        root_receipt.output_ref,
                        self.root.?.sealed.node_ref,
                    )) return error.GenuineThreeLeafTreeGateTopologyMismatchV2;
            }

            pub fn rootOutputRef(
                self: *const OwnedTreeV2,
            ) artifact_store.BlobRefV1 {
                return self.root.?.sealed.node_ref;
            }

            pub fn rootStageManifestRef(
                self: *const OwnedTreeV2,
            ) artifact_store.BlobRefV1 {
                return self.root.?.sealed.stage_manifest_ref;
            }

            pub fn deinit(self: *OwnedTreeV2) void {
                const allocator = self.allocator;
                if (self.root) |root| root.deinit();
                var index = self.first_parents.len;
                while (index != 0) {
                    index -= 1;
                    if (self.first_parents[index]) |parent| parent.deinit();
                }
                if (self.role1) |role1| role1.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            fn refreshReceipts(self: *OwnedTreeV2) void {
                for (&self.role0_children, 0..) |*child, index|
                    self.leaf_receipts[index] = child.receipt();
                self.leaf_receipts[REAL_LEAF_COUNT] =
                    self.role1.?.bound.receipt();
                for (self.first_parents, 0..) |parent, index|
                    self.first_parent_receipts[index] =
                        parent.?.bound.receipt();
                self.root_receipts[0] = self.root.?.bound.receipt();
            }

            comptime {
                rejectCodec(OwnedTreeV2);
            }
        };

        fn validateFinalSession(
            scratch: std.mem.Allocator,
            final: *const FinalOwner,
            session: *const ImmutableSession,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
        ) !void {
            try final.validate();
            try session.validate(scratch);
            try final_remint.validateAgainstCampaign(
                final_remint.shape.campaign_namespace_sha256,
            );
            if (session.entries.len != REAL_LEAF_COUNT or
                final_remint.shape.real_leaf_count !=
                    @as(u32, @intCast(REAL_LEAF_COUNT)) or
                final_remint.shape.padded_leaf_count !=
                    @as(u32, @intCast(PADDED_LEAF_COUNT)) or
                final_remint.shape.root_height != 2 or
                try final_remint.shape.nodeCount(0) !=
                    @as(u32, @intCast(PADDED_LEAF_COUNT)) or
                try final_remint.shape.nodeCount(1) !=
                    @as(u32, @intCast(FIRST_PARENT_COUNT)) or
                try final_remint.shape.nodeCount(2) !=
                    @as(u32, @intCast(ROOT_COUNT)) or
                session.authority.final_remint != final_remint or
                session.authority.padding_target != &final.genuine.target or
                session.authority.active_sources != &final.active_sources or
                final_remint.shape != &final.genuine.target.shape or
                !std.meta.eql(final.campaign.shape, final_remint.shape.*))
            {
                return error.GenuineThreeLeafTreeGateIdentityMismatchV2;
            }
        }

        fn validateReceipt(
            receipt: *const driver_mod.CommittedStageV2,
            child: *const BoundChildV2,
        ) !void {
            const expected = child.receipt();
            if (receipt.node != expected.node or
                receipt.semantic != expected.semantic or
                receipt.execution != expected.execution or
                receipt.ordered_inputs.ptr != expected.ordered_inputs.ptr or
                receipt.ordered_inputs.len != expected.ordered_inputs.len or
                receipt.dependency_stage_manifest_refs.ptr !=
                    expected.dependency_stage_manifest_refs.ptr or
                receipt.dependency_stage_manifest_refs.len !=
                    expected.dependency_stage_manifest_refs.len or
                receipt.lease_id.ptr != expected.lease_id.ptr or
                receipt.lease_id.len != expected.lease_id.len or
                !artifact_store.BlobRefV1.eql(
                    receipt.output_ref,
                    expected.output_ref,
                ) or !artifact_store.BlobRefV1.eql(
                receipt.stage_manifest_ref,
                expected.stage_manifest_ref,
            )) return error.GenuineThreeLeafTreeGateOwnershipMismatchV2;
        }

        comptime {
            if (Role2Lease != FinalWorker.Role2TypesV2.ProofFamily.LeasePayload or
                DependencyLease != FinalWorker.Role2TypesV2.DependencyLease or
                Role0Lease != FinalWorker.Role0InventoryOpenerV4.LeasePayload or
                TargetNative.DependencyLeaseV2 != DependencyLease)
            {
                @compileError("genuine three-leaf tree custody types drifted");
            }
            _ = SelfTypes;
        }
    };
}

fn assertTypes(
    comptime FinalFixture: type,
    comptime Lifecycle: type,
    comptime FinalWorker: type,
    comptime TargetNative: type,
) void {
    inline for (.{
        "OwnedFinalV2",
        "ActiveSourcesV2",
        "Role0AuthorityV4",
    }) |name| if (!@hasDecl(FinalFixture, name))
        @compileError("genuine final fixture missing " ++ name);
    inline for (.{
        "OwnedFinalSessionV4",
        "ImmutableSessionV4",
        "BorrowedRole0FinalV4",
        "Role0LeaseV4",
    }) |name| if (!@hasDecl(Lifecycle, name))
        @compileError("genuine Stage102 lifecycle missing " ++ name);
    inline for (.{ "Role2TypesV2", "Role0InventoryOpenerV4" }) |name|
        if (!@hasDecl(FinalWorker, name))
            @compileError("genuine final worker missing " ++ name);
    inline for (.{
        "DependencyLeaseV2",
        "ProductionLeasePayloadV2",
        "PreparedRole2PairV2",
        "proveRole2TransitiveForGenuineGate",
        "coldOpenRole2TransitiveForGenuineGate",
    }) |name| if (!@hasDecl(TargetNative, name))
        @compileError("target-native q193 family missing " ++ name);
    if (FinalFixture.Role0AuthorityV4 != Lifecycle.AuthorityV4 or
        Lifecycle.Role0LeaseV4 !=
            FinalWorker.Role0InventoryOpenerV4.LeasePayload)
    {
        @compileError("genuine final/session role0 authority drifted");
    }
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("genuine gate-only owner gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        GENUINE_Q193_GATE_GREEN or !GENUINE_GATE_ONLY or
        SERIALIZABLE_FRESH_CAPABILITY or LIVE_WORKER_LEASE_ADMISSION or
        !PROOF_AND_NODE_PRECEDE_STAGE_MANIFEST or
        !EVERY_PROOF_IS_FRESHLY_COLD_OPENED or
        !EXECUTION_POLICY_HAS_NO_SERIAL_FALLBACK or
        @intFromEnum(registry_mod.CircuitRoleV1
            .ethereum_incremental_leaf_wrapper_v4) != 0 or
        @intFromEnum(registry_mod.CircuitRoleV1
            .canonical_empty_field_v2) != 1 or
        @intFromEnum(registry_mod.CircuitRoleV1
            .common_fold_field_v2) != 2)
    {
        @compileError("genuine three-leaf tree gate contract drifted");
    }
}
