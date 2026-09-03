//! Process-local Stage-101/102 worker-to-final-campaign lifecycle.
//!
//! The mutable inventory provider is installed only while its worker exists.
//! Quiescing destroys that worker and every lease before `sealComplete` may
//! move the builder into an immutable session.  A separate install transition
//! then exposes role-0 outputs solely through the existing authenticated
//! inventory opener.  Durable refs select rows; they never mint a verifier
//! capability or geometry.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const builder_mod =
    @import("recursive_pipeline_worker_campaign_stage102_inventory_builder_v4.zig");
const provider_mod =
    @import("recursive_pipeline_worker_campaign_session_provider_v4.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const real_backend =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");
const real_composite =
    @import("recursive_pipeline_worker_campaign_real_leaf_composite_v4.zig");
const real_opener =
    @import("recursive_pipeline_worker_campaign_real_leaf_inventory_opener_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const WORKER_AND_LEASES_QUIESCED_BEFORE_SEAL = true;
pub const IMMUTABLE_SESSION_INSTALLED_AFTER_SEAL = true;
pub const ROLE0_OPEN_USES_EXISTING_INVENTORY_OPENER = true;
pub const GENUINE_GATE_BYPASSES_RELEASE_BOOLEANS_ONLY = true;

pub const Error = error{
    CampaignStage102FinalLifecycleMismatchV4,
    CampaignStage102FinalLifecycleUnavailableV4,
};

/// Production specialization.  Its `begin` path stays unavailable until the
/// existing two-stage adapter and transitive role-0 opener gates are enabled;
/// merely instantiating this type cannot activate a route.
pub fn CampaignSupervisorFor(
    comptime Engine: type,
    comptime ActiveSources: type,
    comptime PolicyProvider: type,
) type {
    const Backend = real_backend.BackendFor(
        Engine,
        ActiveSources,
        PolicyProvider,
    );
    const Assembly = struct {
        pub const AuthorityV4 = Backend.AuthorityV4;

        pub fn AdapterFor(comptime Provider: type) type {
            return real_composite.CampaignAdapterFor(
                Engine,
                ActiveSources,
                Provider,
                PolicyProvider,
            );
        }

        pub fn Role0OpenerFor(comptime Provider: type) type {
            return real_opener.OpenerFor(Backend, Provider);
        }
    };
    return SupervisorFor(Assembly);
}

/// `Assembly` supplies the exact authority and provider-parameterized worker
/// adapter/opener pair.  The generic form exists for cheap lifecycle tests;
/// production uses `CampaignSupervisorFor` above.
pub fn SupervisorFor(comptime Assembly: type) type {
    assertAssembly(Assembly);
    const Authority = Assembly.AuthorityV4;
    const Builder = builder_mod.BuilderFor(Authority);
    const ImmutableSession = Builder.ImmutableSessionV4;
    const BuildProvider = provider_mod.ProviderFor(Builder);
    const ReplayProvider = provider_mod.ProviderFor(ImmutableSession);
    const BuildAdapter = Assembly.AdapterFor(BuildProvider);
    const BuildWorker = worker_mod.Worker(BuildAdapter);
    const Role0Opener = Assembly.Role0OpenerFor(ReplayProvider);
    const Role0Lease = Role0Opener.LeasePayload;
    const Admission = builder_mod.Admission;

    assertGenuineGateBuildAdapter(BuildAdapter);
    assertRole0Opener(Role0Opener);
    assertRole0Lease(Role0Lease);

    return struct {
        pub const AuthorityV4 = Authority;
        pub const BuilderV4 = Builder;
        pub const ImmutableSessionV4 = ImmutableSession;
        pub const BuildProviderV4 = BuildProvider;
        pub const ReplayProviderV4 = ReplayProvider;
        pub const BuildAdapterV4 = BuildAdapter;
        pub const BuildWorkerV4 = BuildWorker;
        pub const Role0OpenerV4 = Role0Opener;
        pub const Role0LeaseV4 = Role0Lease;
        pub const PolicyV2 = builder_mod.Policy;
        pub const available = BuildAdapter.available and Role0Opener.available;

        const Types = @This();

        pub const OwnedBuildingV4 = struct {
            allocator: std.mem.Allocator,
            store_root: []u8,
            builder: Builder,
            installed: BuildProvider.InstalledV4,
            worker: BuildWorker,

            pub fn init(
                owner_allocator: std.mem.Allocator,
                scratch_allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                store_root: []const u8,
                authority: *const Authority,
                policy: *const builder_mod.Policy,
            ) !*OwnedBuildingV4 {
                return initValidated(
                    owner_allocator,
                    scratch_allocator,
                    store,
                    store_root,
                    authority,
                    policy,
                    false,
                );
            }

            pub fn initForGenuineGate(
                owner_allocator: std.mem.Allocator,
                scratch_allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                store_root: []const u8,
                authority: *const Authority,
                policy: *const builder_mod.Policy,
            ) !*OwnedBuildingV4 {
                return initValidated(
                    owner_allocator,
                    scratch_allocator,
                    store,
                    store_root,
                    authority,
                    policy,
                    true,
                );
            }

            fn initValidated(
                owner_allocator: std.mem.Allocator,
                scratch_allocator: std.mem.Allocator,
                store: *artifact_store.Store,
                store_root: []const u8,
                authority: *const Authority,
                policy: *const builder_mod.Policy,
                comptime genuine_gate: bool,
            ) !*OwnedBuildingV4 {
                if (comptime !genuine_gate and !Types.available)
                    return error.CampaignStage102FinalLifecycleUnavailableV4;
                const self = try owner_allocator.create(OwnedBuildingV4);
                errdefer owner_allocator.destroy(self);
                self.allocator = owner_allocator;
                self.store_root = try owner_allocator.dupe(u8, store_root);
                errdefer owner_allocator.free(self.store_root);
                self.builder = try Builder.init(
                    owner_allocator,
                    scratch_allocator,
                    store,
                    authority,
                    policy,
                );
                errdefer self.builder.deinit();
                self.installed = try BuildProvider.install(
                    scratch_allocator,
                    &self.builder,
                );
                errdefer self.installed.deinit();
                self.worker = try BuildWorker.init(
                    owner_allocator,
                    self.store_root,
                );
                return self;
            }

            pub fn handle(
                self: *OwnedBuildingV4,
                allocator: std.mem.Allocator,
                request: protocol.Request,
            ) !protocol.Json {
                return self.handleValidated(allocator, request, false);
            }

            /// Gate-only framed entry. All request/key/CAS/manifest/lease work
            /// stays in the generic Worker; only its release check is skipped.
            pub fn handleForGenuineGate(
                self: *OwnedBuildingV4,
                allocator: std.mem.Allocator,
                request: protocol.Request,
            ) !protocol.Json {
                return self.handleValidated(allocator, request, true);
            }

            /// Exact Stage-101/102 proof-build step for the genuine gate.
            pub fn buildForGenuineGate(
                self: *OwnedBuildingV4,
                allocator: std.mem.Allocator,
                request: protocol.Request,
            ) !protocol.Json {
                if (request.action != .build)
                    return error.CampaignStage102FinalLifecycleMismatchV4;
                return self.handleValidated(allocator, request, true);
            }

            /// Exact cold-open, seal-last publication-adoption, and retained
            /// lease step for a just-built Stage-101/102 output.
            pub fn adoptForGenuineGate(
                self: *OwnedBuildingV4,
                allocator: std.mem.Allocator,
                request: protocol.Request,
            ) !protocol.Json {
                if (request.action != .cold_open)
                    return error.CampaignStage102FinalLifecycleMismatchV4;
                return self.handleValidated(allocator, request, true);
            }

            fn handleValidated(
                self: *OwnedBuildingV4,
                allocator: std.mem.Allocator,
                request: protocol.Request,
                comptime genuine_gate: bool,
            ) !protocol.Json {
                try self.validateInstalled(allocator);
                return if (comptime genuine_gate)
                    self.worker.handleForGenuineGate(allocator, request)
                else
                    self.worker.handle(allocator, request);
            }

            /// Restricted escape hatch for the framed-loop owner.  The
            /// pointer is valid only until `quiesce`; it cannot outlive this
            /// heap-stable build owner.
            pub fn workerView(self: *OwnedBuildingV4) *BuildWorker {
                return &self.worker;
            }

            pub fn builderView(self: *const OwnedBuildingV4) *const Builder {
                return &self.builder;
            }

            pub fn validateInstalled(
                self: *const OwnedBuildingV4,
                allocator: std.mem.Allocator,
            ) !void {
                try self.installed.validate(allocator);
                try self.builder.validate(allocator);
            }

            /// Infallibly ends the mutable provider/worker epoch after the
            /// quiesced owner itself has been allocated. `Worker.deinit`
            /// destroys every still-retained lease before provider removal.
            pub fn quiesce(
                self: *OwnedBuildingV4,
            ) !*OwnedQuiescedV4 {
                const allocator = self.allocator;
                const result = try allocator.create(OwnedQuiescedV4);
                self.worker.deinit();
                self.installed.deinit();
                result.* = .{
                    .allocator = allocator,
                    .store_root = self.store_root,
                    .builder = self.builder,
                };
                self.* = undefined;
                allocator.destroy(self);
                return result;
            }

            pub fn quiesceForGenuineGate(
                self: *OwnedBuildingV4,
            ) !*OwnedQuiescedV4 {
                return self.quiesce();
            }

            pub fn deinit(self: *OwnedBuildingV4) void {
                const allocator = self.allocator;
                self.worker.deinit();
                self.installed.deinit();
                self.builder.deinit();
                allocator.free(self.store_root);
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        /// No provider or worker is installed in this state.  An incomplete
        /// `sealComplete` leaves this owner unchanged and it may be resumed.
        pub const OwnedQuiescedV4 = struct {
            allocator: std.mem.Allocator,
            store_root: []u8,
            builder: Builder,

            pub fn resumeBuilding(
                self: *OwnedQuiescedV4,
                scratch_allocator: std.mem.Allocator,
            ) !*OwnedBuildingV4 {
                const allocator = self.allocator;
                const result = try allocator.create(OwnedBuildingV4);
                errdefer allocator.destroy(result);
                result.allocator = allocator;
                result.store_root = self.store_root;
                result.builder = self.builder;
                result.installed = try BuildProvider.install(
                    scratch_allocator,
                    &result.builder,
                );
                errdefer result.installed.deinit();
                result.worker = try BuildWorker.init(
                    allocator,
                    result.store_root,
                );
                self.* = undefined;
                allocator.destroy(self);
                return result;
            }

            pub fn resumeBuildingForGenuineGate(
                self: *OwnedQuiescedV4,
                scratch_allocator: std.mem.Allocator,
            ) !*OwnedBuildingV4 {
                return self.resumeBuilding(scratch_allocator);
            }

            pub fn sealComplete(
                self: *OwnedQuiescedV4,
                scratch_allocator: std.mem.Allocator,
            ) !*OwnedSealedV4 {
                const allocator = self.allocator;
                const result = try allocator.create(OwnedSealedV4);
                errdefer allocator.destroy(result);
                const sealed = try self.builder.sealComplete(
                    scratch_allocator,
                );
                result.* = .{
                    .allocator = allocator,
                    .store_root = self.store_root,
                    .sealed = sealed,
                };
                self.* = undefined;
                allocator.destroy(self);
                return result;
            }

            pub fn sealCompleteForGenuineGate(
                self: *OwnedQuiescedV4,
                scratch_allocator: std.mem.Allocator,
            ) !*OwnedSealedV4 {
                return self.sealComplete(scratch_allocator);
            }

            pub fn deinit(self: *OwnedQuiescedV4) void {
                const allocator = self.allocator;
                self.builder.deinit();
                allocator.free(self.store_root);
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        /// Complete immutable inventory, not yet installed in the provider.
        pub const OwnedSealedV4 = struct {
            allocator: std.mem.Allocator,
            store_root: []u8,
            sealed: Builder.OwnedSealedSessionV4,

            pub fn installImmutable(
                self: *OwnedSealedV4,
                scratch_allocator: std.mem.Allocator,
            ) !*OwnedFinalSessionV4 {
                const allocator = self.allocator;
                const session = try self.sealed.sessionView();
                const slots = try allocator.alloc(
                    ?*Role0Lease,
                    session.entries.len,
                );
                errdefer allocator.free(slots);
                @memset(slots, null);
                const result = try allocator.create(OwnedFinalSessionV4);
                errdefer allocator.destroy(result);
                const installed = try ReplayProvider.install(
                    scratch_allocator,
                    session,
                );
                result.* = .{
                    .allocator = allocator,
                    .store_root = self.store_root,
                    .sealed = self.sealed,
                    .installed = installed,
                    .role0_slots = slots,
                };
                self.* = undefined;
                allocator.destroy(self);
                return result;
            }

            pub fn installImmutableForGenuineGate(
                self: *OwnedSealedV4,
                scratch_allocator: std.mem.Allocator,
            ) !*OwnedFinalSessionV4 {
                return self.installImmutable(scratch_allocator);
            }

            pub fn deinit(self: *OwnedSealedV4) void {
                const allocator = self.allocator;
                self.sealed.deinit();
                allocator.free(self.store_root);
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        pub const BorrowedRole0FinalV4 = struct {
            session: *const ImmutableSession,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            output_ref: artifact_store.BlobRefV1,
            admission: *const Admission,
            lease: *const Role0Lease,
            geometry: *const registry_mod.AuthenticatedGeometryV1,

            pub fn validate(self: BorrowedRole0FinalV4) !void {
                try self.final_remint.validateAgainstCampaign(
                    self.final_remint.shape.campaign_namespace_sha256,
                );
                const retained = try self.session.stage102AdmissionForOutput(
                    self.final_remint.shape.campaign_namespace_sha256,
                    self.output_ref,
                );
                try self.lease.validateForCampaign(self.final_remint);
                const expected_geometry = try self.final_remint.geometryForRole(
                    .ethereum_incremental_leaf_wrapper_v4,
                );
                const node = self.lease.nodeArtifact();
                const expected_ref = try node_store.toSharedRef(
                    try campaign_artifact.artifactRef(
                        self.final_remint.shape,
                        node,
                    ),
                );
                const projection = try self.lease.campaignFoldProjection(
                    self.final_remint,
                );
                try projection.validateAgainstFinal(self.final_remint);
                if (retained != self.admission or
                    expected_geometry != self.geometry or
                    self.lease.geometryForPaddingTarget() != self.geometry or
                    projection.authority != self.final_remint or
                    projection.geometry != self.geometry or
                    projection.node_artifact != node or
                    !artifact_store.BlobRefV1.eql(
                        expected_ref,
                        self.output_ref,
                    ))
                {
                    return error.CampaignStage102FinalLifecycleMismatchV4;
                }
            }
        };

        /// Installed immutable session plus heap-stable cold role-0 leases.
        /// Returned borrows die before `deinit`, which destroys every lease,
        /// uninstalls the provider, and only then releases sealed inventory.
        pub const OwnedFinalSessionV4 = struct {
            allocator: std.mem.Allocator,
            store_root: []u8,
            sealed: Builder.OwnedSealedSessionV4,
            installed: ReplayProvider.InstalledV4,
            mutex: std.Thread.Mutex = .{},
            role0_slots: []?*Role0Lease,

            pub fn validate(
                self: *OwnedFinalSessionV4,
                scratch_allocator: std.mem.Allocator,
            ) !void {
                try self.installed.validate(scratch_allocator);
                try self.sealed.validate(scratch_allocator);
                const session = try self.sealed.sessionView();
                if (self.role0_slots.len != session.entries.len)
                    return error.CampaignStage102FinalLifecycleMismatchV4;
                for (self.role0_slots, 0..) |maybe_lease, index| {
                    const lease = maybe_lease orelse continue;
                    const view = try role0View(self, session, index, lease);
                    try view.validate();
                }
            }

            pub fn immutableSession(
                self: *const OwnedFinalSessionV4,
            ) !*const ImmutableSession {
                return self.sealed.sessionView();
            }

            pub fn role0ForOutput(
                self: *OwnedFinalSessionV4,
                output_ref: artifact_store.BlobRefV1,
            ) !BorrowedRole0FinalV4 {
                if (comptime !Role0Opener.available)
                    return error.CampaignStage102FinalLifecycleUnavailableV4;
                return role0ForOutputValidated(self, false, output_ref);
            }

            /// Genuine-gate sibling of `role0ForOutput`. The immutable
            /// session, CAS transport, admission, and retained lease owner are
            /// identical to production. Only the still-false release boolean
            /// is skipped so the transitive q193 evidence can be produced.
            pub fn role0ForOutputForGenuineGate(
                self: *OwnedFinalSessionV4,
                output_ref: artifact_store.BlobRefV1,
            ) !BorrowedRole0FinalV4 {
                return role0ForOutputValidated(self, true, output_ref);
            }

            fn role0ForOutputValidated(
                self: *OwnedFinalSessionV4,
                comptime genuine_gate: bool,
                output_ref: artifact_store.BlobRefV1,
            ) !BorrowedRole0FinalV4 {
                self.mutex.lock();
                defer self.mutex.unlock();
                const session = try self.sealed.sessionView();
                const index = try outputIndex(session, output_ref);
                if (self.role0_slots[index] == null) {
                    const final_remint = session.authority.final_remint;
                    const artifact = try campaign_store
                        .coldOpenRecursiveNodeTransport(
                        session.store,
                        final_remint.shape,
                        output_ref,
                    );
                    const lease = try self.allocator.create(Role0Lease);
                    errdefer self.allocator.destroy(lease);
                    lease.* = if (comptime genuine_gate)
                        try Role0Opener.coldOpenNodeForGenuineGate(
                            self.allocator,
                            session.store,
                            final_remint,
                            output_ref,
                            &artifact,
                        )
                    else
                        try Role0Opener.coldOpenNode(
                            self.allocator,
                            session.store,
                            final_remint,
                            output_ref,
                            &artifact,
                        );
                    errdefer lease.deinit();
                    const opened_view = try role0View(
                        self,
                        session,
                        index,
                        lease,
                    );
                    try opened_view.validate();
                    self.role0_slots[index] = lease;
                    return opened_view;
                }
                const view = try role0View(
                    self,
                    session,
                    index,
                    self.role0_slots[index].?,
                );
                try view.validate();
                return view;
            }

            pub fn deinit(self: *OwnedFinalSessionV4) void {
                const allocator = self.allocator;
                var index = self.role0_slots.len;
                while (index != 0) {
                    index -= 1;
                    if (self.role0_slots[index]) |lease| {
                        lease.deinit();
                        allocator.destroy(lease);
                    }
                }
                allocator.free(self.role0_slots);
                self.installed.deinit();
                self.sealed.deinit();
                allocator.free(self.store_root);
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        pub fn begin(
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            store_root: []const u8,
            authority: *const Authority,
            policy: *const builder_mod.Policy,
        ) !*OwnedBuildingV4 {
            return OwnedBuildingV4.init(
                owner_allocator,
                scratch_allocator,
                store,
                store_root,
                authority,
                policy,
            );
        }

        /// Constructs the same mutable lifecycle owner as `begin`, bypassing
        /// only the still-false composite/opener release booleans. The result
        /// remains mutable and provider-installed; callers must build/adopt,
        /// quiesce, seal, and install before an immutable Session is exposed.
        pub fn beginForGenuineGate(
            owner_allocator: std.mem.Allocator,
            scratch_allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            store_root: []const u8,
            authority: *const Authority,
            policy: *const builder_mod.Policy,
        ) !*OwnedBuildingV4 {
            return OwnedBuildingV4.initForGenuineGate(
                owner_allocator,
                scratch_allocator,
                store,
                store_root,
                authority,
                policy,
            );
        }

        fn outputIndex(
            session: *const ImmutableSession,
            output_ref: artifact_store.BlobRefV1,
        ) !usize {
            for (session.entries, 0..) |entry, index| {
                if (artifact_store.BlobRefV1.eql(
                    entry.output_ref,
                    output_ref,
                )) return index;
            }
            return error.CampaignStage102FinalLifecycleMismatchV4;
        }

        fn role0View(
            _: *const OwnedFinalSessionV4,
            session: *const ImmutableSession,
            index: usize,
            lease: *const Role0Lease,
        ) !BorrowedRole0FinalV4 {
            if (index >= session.entries.len)
                return error.CampaignStage102FinalLifecycleMismatchV4;
            const output_ref = session.entries[index].output_ref;
            const final_remint = session.authority.final_remint;
            return .{
                .session = session,
                .final_remint = final_remint,
                .output_ref = output_ref,
                .admission = &session.entries[index].admission,
                .lease = lease,
                .geometry = try final_remint.geometryForRole(
                    .ethereum_incremental_leaf_wrapper_v4,
                ),
            };
        }

        comptime {
            rejectCodec(OwnedBuildingV4);
            rejectCodec(OwnedQuiescedV4);
            rejectCodec(OwnedSealedV4);
            rejectCodec(OwnedFinalSessionV4);
            rejectCodec(BorrowedRole0FinalV4);
        }
    };
}

fn assertAssembly(comptime Assembly: type) void {
    inline for (.{ "AuthorityV4", "AdapterFor", "Role0OpenerFor" }) |name|
        if (!@hasDecl(Assembly, name))
            @compileError("campaign Stage102 lifecycle assembly missing " ++ name);
}

fn assertRole0Opener(comptime Opener: type) void {
    inline for (.{
        "available",
        "LeasePayload",
        "coldOpenNode",
        "coldOpenNodeForGenuineGate",
    }) |name|
        if (!@hasDecl(Opener, name))
            @compileError("campaign Stage102 lifecycle opener missing " ++ name);
}

fn assertGenuineGateBuildAdapter(comptime Adapter: type) void {
    inline for (.{
        "buildOutputWithExecutionAndLeasesForGenuineGate",
        "coldOpenLeaseForGenuineGate",
        "adoptColdPublicationForGenuineGate",
    }) |name| if (!@hasDecl(Adapter, name))
        @compileError("campaign Stage102 lifecycle gate adapter missing " ++ name);
}

fn assertRole0Lease(comptime Lease: type) void {
    inline for (.{
        "deinit",
        "validateForCampaign",
        "geometryForPaddingTarget",
        "nodeArtifact",
        "campaignFoldProjection",
    }) |name| if (!@hasDecl(Lease, name))
        @compileError("campaign Stage102 lifecycle lease missing " ++ name);
    rejectCodec(Lease);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign Stage102 lifecycle capability gained a codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or
        !WORKER_AND_LEASES_QUIESCED_BEFORE_SEAL or
        !IMMUTABLE_SESSION_INSTALLED_AFTER_SEAL or
        !ROLE0_OPEN_USES_EXISTING_INVENTORY_OPENER or
        !GENUINE_GATE_BYPASSES_RELEASE_BOOLEANS_ONLY)
    {
        @compileError("campaign Stage102 final lifecycle contract drifted");
    }
}
