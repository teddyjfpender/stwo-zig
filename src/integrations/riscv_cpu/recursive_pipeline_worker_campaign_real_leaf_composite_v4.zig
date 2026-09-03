//! Unrouteable two-stage worker composition for campaign role-0 leaves.
//!
//! Stage 101 owns a fresh native proof lease. Stage 102 borrows exactly that
//! tagged lease, receives the complete sealed ExecutionKey, and returns a
//! distinct verifier-owned campaign fold lease. The generic worker remains
//! the sole owner of lease consumption and seal-last StageManifest custody.
//! This composition intentionally omits Stages 103/104 and cannot activate a
//! production route before the final three-role remint gate.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const fold_projection =
    @import("recursive_pipeline_campaign_fold_projection_v2.zig");
const native_execution =
    @import("recursive_pipeline_worker_native_leaf_execution_v4.zig");
const real_stage =
    @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const real_backend =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");

pub const adapter_name = "campaign_real_leaf_two_stage_v4";
pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const NATIVE_STAGE_SCHEMA_VERSION: u16 = 101;
pub const WRAPPER_STAGE_SCHEMA_VERSION: u16 = 102;

pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const EXECUTION_KEY_FORWARDED = true;
pub const BUILD_BORROWS_NATIVE_LEASE = true;
pub const BUILD_FAILURE_RETAINS_NATIVE_LEASE = true;

pub const Error = error{
    CampaignRealLeafCompositeUnavailableV4,
    CampaignRealLeafCompositeStageMismatchV4,
    CampaignRealLeafCompositeLeaseMismatchV4,
    CampaignRealLeafCompositeExecutionMismatchV4,
};

pub const StageCodeV4 = enum(u16) {
    native_leaf_v4 = NATIVE_STAGE_SCHEMA_VERSION,
    real_wrapper_v4 = WRAPPER_STAGE_SCHEMA_VERSION,
};

pub fn LeasePayloadFor(
    comptime NativeLease: type,
    comptime RealLease: type,
) type {
    assertNativeLease(NativeLease);
    assertRealLease(RealLease);
    return union(StageCodeV4) {
        const Self = @This();

        native_leaf_v4: NativeLease,
        real_wrapper_v4: RealLease,

        pub fn stageCode(self: *const Self) StageCodeV4 {
            return std.meta.activeTag(self.*);
        }

        pub fn validate(self: *const Self) !void {
            switch (self.*) {
                inline else => |*payload| try payload.validate(),
            }
        }

        pub fn campaignFoldProjection(
            self: *const Self,
            authority: *const final_mod.CampaignFinalRemintAuthorityV2,
        ) !fold_projection.ProjectionV2 {
            return switch (self.*) {
                .native_leaf_v4 => error.CampaignRealLeafCompositeLeaseMismatchV4,
                .real_wrapper_v4 => |*payload| payload.campaignFoldProjection(authority),
            };
        }

        pub fn deinit(self: *Self) void {
            switch (self.*) {
                inline else => |*payload| payload.deinit(),
            }
            self.* = undefined;
        }
    };
}

/// `NativeAdapter` is the exact Stage-101 adapter specialization used to mint
/// the dependency. `RealAdapter.DependencyLease` must be nominally identical
/// to its lease type; no anyopaque bridge or payload cast is accepted.
pub fn AdapterFor(
    comptime NativeAdapter: type,
    comptime RealAdapter: type,
) type {
    assertNativeAdapter(NativeAdapter);
    assertRealAdapter(RealAdapter);
    if (NativeAdapter.LeasePayload != RealAdapter.DependencyLease)
        @compileError("campaign Stage102 dependency is not the Stage101 lease");

    const Lease = LeasePayloadFor(
        NativeAdapter.LeasePayload,
        RealAdapter.LeasePayload,
    );

    return struct {
        pub const available = false;
        pub const production = PRODUCTION_ACTIVATION;
        pub const routes_cryptographically_implemented =
            NativeAdapter.available and RealAdapter.available;
        pub const LeasePayload = Lease;

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return NativeAdapter.acceptsNodeAdapter(value) or
                RealAdapter.acceptsNodeAdapter(value);
        }

        pub fn unavailable() error{CampaignRealLeafCompositeUnavailableV4} {
            return error.CampaignRealLeafCompositeUnavailableV4;
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            return switch (try parseStage(stage_kind, stage_schema_version)) {
                .native_leaf_v4 => NativeAdapter.describe(
                    stage_kind,
                    stage_schema_version,
                ),
                .real_wrapper_v4 => RealAdapter.describe(
                    stage_kind,
                    stage_schema_version,
                ),
            };
        }

        /// The persistent worker must select the execution-aware callback.
        pub fn buildOutputWithLeases(
            _: std.mem.Allocator,
            _: *artifact_store.Store,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
            _: []const *const LeasePayload,
        ) ![]u8 {
            return error.CampaignRealLeafCompositeExecutionMismatchV4;
        }

        pub fn buildOutputWithExecutionAndLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            return buildOutputWithExecutionAndLeasesValidated(
                allocator,
                store,
                node,
                semantic,
                execution,
                ordered_inputs,
                candidate_ordinal,
                dependency_leases,
                false,
            );
        }

        /// Genuine-gate sibling returning the same production output. Stage
        /// 101 already has no inner release guard; Stage 102 invokes its exact
        /// q193 body while the composite route remains unavailable.
        pub fn buildOutputWithExecutionAndLeasesForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            return buildOutputWithExecutionAndLeasesValidated(
                allocator,
                store,
                node,
                semantic,
                execution,
                ordered_inputs,
                candidate_ordinal,
                dependency_leases,
                true,
            );
        }

        fn buildOutputWithExecutionAndLeasesValidated(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const LeasePayload,
            comptime genuine_gate: bool,
        ) ![]u8 {
            const stage = try validateNode(node);
            try validateExecutionBinding(allocator, semantic, execution);
            return switch (stage) {
                .native_leaf_v4 => blk: {
                    if (dependency_leases.len != 0)
                        return error.CampaignRealLeafCompositeLeaseMismatchV4;
                    break :blk NativeAdapter
                        .buildOutputWithExecutionAndLeases(
                        allocator,
                        store,
                        node,
                        semantic,
                        execution,
                        ordered_inputs,
                        candidate_ordinal,
                        &.{},
                    );
                },
                .real_wrapper_v4 => blk: {
                    const native = try nativeDependency(dependency_leases);
                    break :blk if (comptime genuine_gate)
                        RealAdapter
                            .buildOutputWithExecutionAndLeasesForGenuineGate(
                            allocator,
                            store,
                            node,
                            semantic,
                            execution,
                            ordered_inputs,
                            candidate_ordinal,
                            &native,
                        )
                    else
                        RealAdapter.buildOutputWithExecutionAndLeases(
                            allocator,
                            store,
                            node,
                            semantic,
                            execution,
                            ordered_inputs,
                            candidate_ordinal,
                            &native,
                        );
                },
            };
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            return switch (try validateNode(node)) {
                .native_leaf_v4 => NativeAdapter.profileValue(
                    allocator,
                    node,
                    semantic,
                    execution,
                    candidate_ordinal,
                ),
                .real_wrapper_v4 => RealAdapter.profileValue(
                    allocator,
                    node,
                    semantic,
                    execution,
                    candidate_ordinal,
                ),
            };
        }

        pub fn validateOutput(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            return validateOutputValidated(
                allocator,
                bytes,
                node,
                semantic,
                ordered_inputs,
                false,
            );
        }

        pub fn validateOutputForGenuineGate(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            return validateOutputValidated(
                allocator,
                bytes,
                node,
                semantic,
                ordered_inputs,
                true,
            );
        }

        fn validateOutputValidated(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            comptime genuine_gate: bool,
        ) !void {
            return switch (try validateNode(node)) {
                .native_leaf_v4 => NativeAdapter.validateOutput(
                    allocator,
                    bytes,
                    node,
                    semantic,
                    ordered_inputs,
                ),
                .real_wrapper_v4 => if (comptime genuine_gate)
                    RealAdapter.validateOutputForGenuineGate(
                        allocator,
                        bytes,
                        node,
                        semantic,
                        ordered_inputs,
                    )
                else
                    RealAdapter.validateOutput(
                        allocator,
                        bytes,
                        node,
                        semantic,
                        ordered_inputs,
                    ),
            };
        }

        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            return coldOpenLeaseValidated(
                allocator,
                store,
                bytes,
                node,
                semantic,
                ordered_inputs,
                false,
            );
        }

        pub fn coldOpenLeaseForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            return coldOpenLeaseValidated(
                allocator,
                store,
                bytes,
                node,
                semantic,
                ordered_inputs,
                true,
            );
        }

        fn coldOpenLeaseValidated(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            comptime genuine_gate: bool,
        ) !LeasePayload {
            return switch (try validateNode(node)) {
                .native_leaf_v4 => .{
                    .native_leaf_v4 = try NativeAdapter.coldOpenLease(
                        allocator,
                        store,
                        bytes,
                        node,
                        semantic,
                        ordered_inputs,
                    ),
                },
                .real_wrapper_v4 => .{
                    .real_wrapper_v4 = if (comptime genuine_gate)
                        try RealAdapter.coldOpenLeaseForGenuineGate(
                            allocator,
                            store,
                            bytes,
                            node,
                            semantic,
                            ordered_inputs,
                        )
                    else
                        try RealAdapter.coldOpenLease(
                            allocator,
                            store,
                            bytes,
                            node,
                            semantic,
                            ordered_inputs,
                        ),
                },
            };
        }

        pub fn validationValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            output_ref: artifact_store.BlobRefV1,
            validator_version: u32,
            mode: []const u8,
        ) !protocol.Json {
            return switch (try validateNode(node)) {
                .native_leaf_v4 => NativeAdapter.validationValue(
                    allocator,
                    node,
                    semantic,
                    output_ref,
                    validator_version,
                    mode,
                ),
                .real_wrapper_v4 => RealAdapter.validationValue(
                    allocator,
                    node,
                    semantic,
                    output_ref,
                    validator_version,
                    mode,
                ),
            };
        }

        pub fn adoptColdPublication(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
        ) !void {
            try validateExecutionBinding(allocator, semantic, execution);
            return switch (try validateNode(node)) {
                .native_leaf_v4 => if (comptime @hasDecl(
                    NativeAdapter,
                    "adoptColdPublication",
                )) NativeAdapter.adoptColdPublication(
                    allocator,
                    node,
                    semantic,
                    execution,
                    ordered_inputs,
                    output_ref,
                    stage_manifest_ref,
                    dependency_stage_manifest_refs,
                ) else {},
                .real_wrapper_v4 => if (comptime @hasDecl(
                    RealAdapter,
                    "adoptColdPublication",
                )) RealAdapter.adoptColdPublication(
                    allocator,
                    node,
                    semantic,
                    execution,
                    ordered_inputs,
                    output_ref,
                    stage_manifest_ref,
                    dependency_stage_manifest_refs,
                ) else {},
            };
        }

        /// Adoption itself has no release guard. The explicit gate name keeps
        /// the generic Worker from falling back to an optional callback while
        /// preserving the identical provider mutation and validation body.
        pub fn adoptColdPublicationForGenuineGate(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
        ) !void {
            return adoptColdPublication(
                allocator,
                node,
                semantic,
                execution,
                ordered_inputs,
                output_ref,
                stage_manifest_ref,
                dependency_stage_manifest_refs,
            );
        }

        pub fn deinitLeasePayload(
            payload: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            payload.deinit();
        }

        fn nativeDependency(
            dependencies: []const *const LeasePayload,
        ) ![1]*const NativeAdapter.LeasePayload {
            if (dependencies.len != 1)
                return error.CampaignRealLeafCompositeLeaseMismatchV4;
            const payload = switch (dependencies[0].*) {
                .native_leaf_v4 => |*value| value,
                .real_wrapper_v4 => return error.CampaignRealLeafCompositeLeaseMismatchV4,
            };
            return .{payload};
        }
    };
}

/// Concrete campaign composition factory. One sealed execution-policy
/// provider is shared by both proof layers, so Stage 101 and Stage 102 cannot
/// silently select different worker/RSS authorities for the same worker
/// process. `AuthorityProvider` remains process-local and owns the runtime
/// campaign/final-remint custody required by the role-0 backend.
pub fn CampaignAdapterFor(
    comptime Engine: type,
    comptime ActiveSources: type,
    comptime AuthorityProvider: type,
    comptime PolicyProvider: type,
) type {
    const Native = native_execution.AdapterFor(Engine, PolicyProvider);
    const Backend = real_backend.BackendFor(
        Engine,
        ActiveSources,
        PolicyProvider,
    );
    assertCampaignProvider(AuthorityProvider, Backend.AuthorityV4);
    const Real = real_stage.Stage102For(AuthorityProvider, Backend);
    return AdapterFor(Native, Real);
}

/// Instantiates the frozen six-action persistent worker around the exact
/// two-stage adapter specialization. This is only a type boundary: no CLI
/// route is selected, and the process-local providers must already own their
/// campaign/execution authorities before a future route can be activated.
pub fn CampaignWorkerFor(
    comptime Engine: type,
    comptime ActiveSources: type,
    comptime AuthorityProvider: type,
    comptime PolicyProvider: type,
) type {
    const Adapter = CampaignAdapterFor(
        Engine,
        ActiveSources,
        AuthorityProvider,
        PolicyProvider,
    );
    if (Adapter.available or PRODUCTION_ACTIVATION or ROUTER_ACTIVATION)
        @compileError("campaign Stage101/102 worker route activated early");
    return worker_mod.Worker(Adapter);
}

fn parseStage(
    stage_kind: artifact_store.StageKindV1,
    stage_schema_version: u16,
) !StageCodeV4 {
    const result = std.meta.intToEnum(
        StageCodeV4,
        stage_schema_version,
    ) catch return error.CampaignRealLeafCompositeStageMismatchV4;
    const expected_kind: artifact_store.StageKindV1 = switch (result) {
        .native_leaf_v4, .real_wrapper_v4 => .prove,
    };
    if (stage_kind != expected_kind)
        return error.CampaignRealLeafCompositeStageMismatchV4;
    return result;
}

fn validateNode(node: protocol.Node) !StageCodeV4 {
    const stage = try parseStage(node.stage_kind, node.stage_schema_version);
    const expected_dependencies: usize = switch (stage) {
        .native_leaf_v4 => 0,
        .real_wrapper_v4 => 1,
    };
    const expected_output: artifact_store.ArtifactKindV1 = switch (stage) {
        .native_leaf_v4 => .proof_artifact,
        .real_wrapper_v4 => .recursion_node,
    };
    const expected_schema: u16 = switch (stage) {
        .native_leaf_v4 => 1,
        .real_wrapper_v4 => 2,
    };
    if (node.dependencies.len != expected_dependencies or
        node.output_kind != expected_output or
        node.output_schema_version != expected_schema)
    {
        return error.CampaignRealLeafCompositeStageMismatchV4;
    }
    return stage;
}

fn validateExecutionBinding(
    allocator: std.mem.Allocator,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
) !void {
    try semantic.validate(allocator);
    try execution.validate();
    if (!std.mem.eql(
        u8,
        &execution.fields.semantic_key_identity,
        &semantic.identity,
    )) return error.CampaignRealLeafCompositeExecutionMismatchV4;
}

fn assertNativeLease(comptime Lease: type) void {
    inline for (.{ "validate", "deinit" }) |name| if (!@hasDecl(Lease, name))
        @compileError("campaign native lease missing " ++ name);
    rejectCodec(Lease);
}

fn assertCampaignProvider(comptime Provider: type, comptime Authority: type) void {
    if (!@hasDecl(Provider, "AuthorityV4"))
        @compileError("campaign Stage102 provider has no nominal authority");
    if (Provider.AuthorityV4 != Authority)
        @compileError("campaign Stage102 provider authority specialization drifted");
    if (!@hasDecl(Provider, "adoptStage102ColdPublication"))
        @compileError("campaign Stage102 provider cannot retain cold admission");
}

fn assertRealLease(comptime Lease: type) void {
    inline for (.{ "validate", "campaignFoldProjection", "deinit" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign role0 lease missing " ++ name);
    rejectCodec(Lease);
}

fn assertNativeAdapter(comptime Adapter: type) void {
    assertAdapterCommon(Adapter);
    if (!@hasDecl(Adapter, "buildOutputWithExecutionAndLeases"))
        @compileError("campaign Stage101 adapter does not consume ExecutionKey");
}

fn assertRealAdapter(comptime Adapter: type) void {
    assertAdapterCommon(Adapter);
    inline for (.{
        "DependencyLease",
        "buildOutputWithExecutionAndLeases",
        "buildOutputWithExecutionAndLeasesForGenuineGate",
        "validateOutputForGenuineGate",
        "coldOpenLeaseForGenuineGate",
    }) |name| if (!@hasDecl(Adapter, name))
        @compileError("campaign Stage102 adapter missing " ++ name);
}

fn assertAdapterCommon(comptime Adapter: type) void {
    inline for (.{
        "available",
        "LeasePayload",
        "acceptsNodeAdapter",
        "describe",
        "buildOutputWithLeases",
        "profileValue",
        "validateOutput",
        "coldOpenLease",
        "validationValue",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(Adapter, name))
        @compileError("campaign two-stage adapter missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign live lease gained durable codec");
}

pub const testing = struct {
    pub const validateExecutionBindingV4 = validateExecutionBinding;
};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        NATIVE_STAGE_SCHEMA_VERSION != 101 or
        WRAPPER_STAGE_SCHEMA_VERSION != 102 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !EXECUTION_KEY_FORWARDED or
        !BUILD_BORROWS_NATIVE_LEASE or !BUILD_FAILURE_RETAINS_NATIVE_LEASE)
    {
        @compileError("campaign real-leaf two-stage composition drifted");
    }
}
