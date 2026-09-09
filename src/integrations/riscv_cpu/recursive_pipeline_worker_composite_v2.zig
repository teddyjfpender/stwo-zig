//! Static composite adapter contract for recursive stages 101--104.
//!
//! The persistent worker owns one process-local tagged lease type across the
//! four production stage codes. Durable output bytes remain typed CAS blobs;
//! a lease is never encoded, placed in a manifest, or reconstructed from a
//! digest. Dependency leases are borrowed by `buildOutputWithLeases` and stay
//! owned by the worker until every outer output has been durably published.
//!
//! The native-leaf and canonical-empty stages have concrete routes in this
//! checkpoint. Real-wrapper and common-fold routes remain explicit,
//! uninhabited admission branches until their role-specific cold verifiers
//! freeze. This module is deliberately not selected by the worker router.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const canonical_empty =
    @import("recursive_pipeline_worker_canonical_empty_v2.zig");
const native_leaf = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const child_capability =
    @import("recursive_common_fold_child_capability_v2.zig");
const common_child = @import("recursive_common_fold_child_v2.zig");
const node_artifact = @import("recursive_node_artifact_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const full_leaf_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");

pub const adapter_name = "recursive_composite_v2";
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;

pub const NATIVE_LEAF_STAGE_SCHEMA_VERSION: u16 = 101;
pub const REAL_WRAPPER_STAGE_SCHEMA_VERSION: u16 =
    node_store.REAL_WRAPPER_STAGE_SCHEMA_VERSION;
pub const EMPTY_WRAPPER_STAGE_SCHEMA_VERSION: u16 =
    node_store.EMPTY_WRAPPER_STAGE_SCHEMA_VERSION;
pub const COMMON_FOLD_STAGE_SCHEMA_VERSION: u16 =
    node_store.COMMON_FOLD_STAGE_SCHEMA_VERSION;

pub const CAS_FORMAT_VERSION: u16 =
    artifact_store.types.format_version_v1;
pub const PROOF_CAS_SCHEMA_VERSION: u16 = 1;
pub const RECURSION_NODE_CAS_SCHEMA_VERSION: u16 =
    node_artifact.SCHEMA_VERSION;
pub const STAGE_MANIFEST_CAS_SCHEMA_VERSION: u16 =
    node_store.STAGE_MANIFEST_SCHEMA_VERSION;

pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const DURABLE_LEASE_CODEC_AVAILABLE = false;
pub const DEPENDENCIES_BORROWED_DURING_BUILD = true;
pub const BUILD_FAILURE_RETAINS_DEPENDENCY_LEASES = true;
pub const SUCCESS_CONSUMES_AFTER_OUTER_PUBLICATION = true;

pub const Error = error{
    CompositeRecursiveStageUnavailable,
    InvalidCompositeRecursiveLease,
    InvalidCompositeRecursiveStage,
    NativeLeafStage101Unavailable,
    RealWrapperStage102Unavailable,
    CommonFoldStage104Unavailable,
};

pub const StageCodeV2 = enum(u16) {
    native_leaf_v4 = NATIVE_LEAF_STAGE_SCHEMA_VERSION,
    real_wrapper_v4 = REAL_WRAPPER_STAGE_SCHEMA_VERSION,
    canonical_empty_v2 = EMPTY_WRAPPER_STAGE_SCHEMA_VERSION,
    common_fold_v2 = COMMON_FOLD_STAGE_SCHEMA_VERSION,
};

pub const StageContractV2 = struct {
    code: StageCodeV2,
    stage_kind: artifact_store.StageKindV1,
    output_kind: artifact_store.ArtifactKindV1,
    output_format_version: u16 = CAS_FORMAT_VERSION,
    output_schema_version: u16,
    embedded_artifact_schema_version: u16,
    fixed_output_byte_count: ?u64,
    dependency_lease_count: u8,
    produces_process_local_lease: bool = true,
    route_available: bool,

    pub fn description(self: StageContractV2) protocol.StageDescription {
        return .{
            .stage_kind = self.stage_kind,
            .stage_schema_version = @intFromEnum(self.code),
            .output_kind = self.output_kind,
            .output_schema_version = self.output_schema_version,
            .minimum_cpu_tokens = 1,
            .minimum_rss_tokens = 1,
            .root_cold_open_transitive = true,
        };
    }
};

/// Durable stage/CAS allocation. This is descriptive authority only; route
/// availability is checked separately and no value here mints a live lease.
pub fn stageContract(code: StageCodeV2) StageContractV2 {
    return switch (code) {
        .native_leaf_v4 => .{
            .code = code,
            .stage_kind = .prove,
            .output_kind = .proof_artifact,
            .output_schema_version = PROOF_CAS_SCHEMA_VERSION,
            .embedded_artifact_schema_version = full_leaf_artifact.SCHEMA_VERSION,
            .fixed_output_byte_count = null,
            .dependency_lease_count = 0,
            .route_available = native_leaf.Adapter.available,
        },
        .real_wrapper_v4 => .{
            .code = code,
            .stage_kind = .prove,
            .output_kind = .recursion_node,
            .output_schema_version = RECURSION_NODE_CAS_SCHEMA_VERSION,
            .embedded_artifact_schema_version = node_artifact.SCHEMA_VERSION,
            .fixed_output_byte_count = node_artifact.ENCODED_BYTE_COUNT,
            .dependency_lease_count = 1,
            .route_available = false,
        },
        .canonical_empty_v2 => .{
            .code = code,
            .stage_kind = .prove,
            .output_kind = .recursion_node,
            .output_schema_version = RECURSION_NODE_CAS_SCHEMA_VERSION,
            .embedded_artifact_schema_version = node_artifact.SCHEMA_VERSION,
            .fixed_output_byte_count = node_artifact.ENCODED_BYTE_COUNT,
            .dependency_lease_count = 0,
            .route_available = canonical_empty.Adapter.available,
        },
        .common_fold_v2 => .{
            .code = code,
            .stage_kind = .fold,
            .output_kind = .recursion_node,
            .output_schema_version = RECURSION_NODE_CAS_SCHEMA_VERSION,
            .embedded_artifact_schema_version = node_artifact.SCHEMA_VERSION,
            .fixed_output_byte_count = node_artifact.ENCODED_BYTE_COUNT,
            .dependency_lease_count = 2,
            .route_available = false,
        },
    };
}

/// Explicit non-authority used until the stage-101 cold verifier owner is
/// bound into the persistent-worker route.
pub const UnavailableNativeLeafLeaseV2 = struct {
    pub fn validate(_: *const UnavailableNativeLeafLeaseV2) !void {
        return error.NativeLeafStage101Unavailable;
    }

    pub fn deinit(_: *UnavailableNativeLeafLeaseV2) void {}
};

/// Explicit role-0 non-authority. It cannot be projected as a fold child.
pub const UnavailableRealWrapperLeaseV2 = struct {
    pub const FoldChild = child_capability.UnavailableRealLeafChildV2;

    pub fn validate(_: *const UnavailableRealWrapperLeaseV2) !void {
        return error.RealWrapperStage102Unavailable;
    }

    pub fn requireFoldChild(
        _: *const UnavailableRealWrapperLeaseV2,
    ) !FoldChild {
        return error.RealWrapperStage102Unavailable;
    }

    pub fn deinit(_: *UnavailableRealWrapperLeaseV2) void {}
};

/// Explicit non-authority until exact capture-derived q193 dimensions select
/// the common-fold backend. The child type is reserved, but no value can be
/// minted from durable bytes through this placeholder.
pub const UnavailableCommonFoldLeaseV2 = struct {
    pub const FoldChild = common_child.FreshFoldChildV2;

    pub fn validate(_: *const UnavailableCommonFoldLeaseV2) !void {
        return error.CommonFoldStage104Unavailable;
    }

    pub fn requireFoldChild(
        _: *const UnavailableCommonFoldLeaseV2,
    ) !FoldChild {
        return error.CommonFoldStage104Unavailable;
    }

    pub fn deinit(_: *UnavailableCommonFoldLeaseV2) void {}
};

/// One worker-owned payload type across all four stages. The generic boundary
/// permits future role-specific owners without changing the stable stage tags
/// or accepting a nominal cast between their verifier capabilities.
pub fn LeasePayloadFor(
    comptime NativeLease: type,
    comptime RealLease: type,
    comptime CommonLease: type,
) type {
    assertNativeLeaseContract(NativeLease);
    assertFoldLeaseContract(RealLease);
    assertFoldLeaseContract(CommonLease);
    const TaggedFoldChild = child_capability.TaggedFoldChildV2(
        RealLease.FoldChild,
        canonical_empty.FreshFoldChildV2,
        CommonLease.FoldChild,
    );

    return union(StageCodeV2) {
        const Self = @This();

        native_leaf_v4: NativeLease,
        real_wrapper_v4: RealLease,
        canonical_empty_v2: canonical_empty.LeasePayloadV2,
        common_fold_v2: CommonLease,

        pub const FoldChildCapability = TaggedFoldChild;

        pub fn stageCode(self: *const Self) StageCodeV2 {
            return std.meta.activeTag(self.*);
        }

        pub fn validate(self: *const Self) !void {
            switch (self.*) {
                inline else => |*payload| try payload.validate(),
            }
        }

        /// Returns only a borrowed neutral projection. The temporary nominal
        /// child value is never retained or serialized; all pointers in the
        /// projection continue to borrow the lease-owned cold verifier state.
        pub fn foldProjection(
            self: *const Self,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !child_capability.ProjectionV2 {
            return switch (self.*) {
                .native_leaf_v4 => error.InvalidCompositeRecursiveLease,
                .real_wrapper_v4 => |*payload| blk: {
                    const child = try payload.requireFoldChild();
                    const tagged = try TaggedFoldChild.fromReal(
                        &child,
                        registry,
                    );
                    break :blk try tagged.projection(registry);
                },
                .canonical_empty_v2 => |*payload| blk: {
                    const child = try payload.requireFoldChild();
                    const tagged = try TaggedFoldChild.fromCanonical(
                        &child,
                        registry,
                    );
                    break :blk try tagged.projection(registry);
                },
                .common_fold_v2 => |*payload| blk: {
                    const child = try payload.requireFoldChild();
                    const tagged = try TaggedFoldChild.fromCommon(
                        &child,
                        registry,
                    );
                    break :blk try tagged.projection(registry);
                },
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

pub const LeasePayloadV2 = LeasePayloadFor(
    native_leaf.Adapter.LeasePayload,
    UnavailableRealWrapperLeaseV2,
    UnavailableCommonFoldLeaseV2,
);

/// Validates only dependency ownership topology. It deliberately neither
/// consumes nor deinitializes a lease: the persistent worker performs the
/// all-or-none consumption after output/profile/candidate-ref publication.
pub fn validateDependencyLeaseShape(
    comptime Lease: type,
    code: StageCodeV2,
    dependencies: []const *const Lease,
) !void {
    if (dependencies.len != stageContract(code).dependency_lease_count)
        return error.InvalidCompositeRecursiveLease;
    switch (code) {
        .native_leaf_v4, .canonical_empty_v2 => {},
        .real_wrapper_v4 => if (dependencies[0].stageCode() != .native_leaf_v4) return error.InvalidCompositeRecursiveLease,
        .common_fold_v2 => for (dependencies) |dependency| switch (dependency.stageCode()) {
            .real_wrapper_v4,
            .canonical_empty_v2,
            .common_fold_v2,
            => {},
            .native_leaf_v4 => return error.InvalidCompositeRecursiveLease,
        },
    }
}

/// Worker-shaped static adapter. Stages 101 and 103 delegate to implemented
/// routes. The type is deliberately unavailable to the router until every
/// required stage has a role-specific cold verifier and live lease owner.
pub const Adapter = struct {
    pub const name = adapter_name;
    pub const production = PRODUCTION_ACTIVATION;
    pub const available = false;
    pub const LeasePayload = LeasePayloadV2;

    pub fn acceptsNodeAdapter(value: []const u8) bool {
        return std.mem.eql(u8, value, adapter_name) or
            std.mem.eql(u8, value, "zig-worker-v1");
    }

    pub fn describe(
        stage_kind: artifact_store.StageKindV1,
        stage_schema_version: u16,
    ) !protocol.StageDescription {
        const code = try parseStage(stage_kind, stage_schema_version);
        return switch (code) {
            .native_leaf_v4 => native_leaf.Adapter.describe(
                stage_kind,
                stage_schema_version,
            ),
            .canonical_empty_v2 => canonical_empty.Adapter.describe(
                stage_kind,
                stage_schema_version,
            ),
            .real_wrapper_v4,
            .common_fold_v2,
            => error.CompositeRecursiveStageUnavailable,
        };
    }

    pub fn unavailable() error{CompositeRecursiveStageUnavailable} {
        return error.CompositeRecursiveStageUnavailable;
    }

    pub fn buildOutput(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
    ) ![]u8 {
        return error.CompositeRecursiveStageUnavailable;
    }

    pub fn buildOutputWithLeases(
        allocator: std.mem.Allocator,
        store: *artifact_store.Store,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
        candidate_ordinal: u64,
        dependency_leases: []const *const LeasePayload,
    ) ![]u8 {
        const code = try validateNodeContract(node);
        try validateDependencyLeaseShape(LeasePayload, code, dependency_leases);
        return switch (code) {
            .native_leaf_v4 => native_leaf.Adapter.buildOutputWithLeases(
                allocator,
                store,
                node,
                semantic,
                ordered_inputs,
                candidate_ordinal,
                &.{},
            ),
            .canonical_empty_v2 => canonical_empty.Adapter.buildOutputWithLeases(
                allocator,
                store,
                node,
                semantic,
                ordered_inputs,
                candidate_ordinal,
                &.{},
            ),
            .real_wrapper_v4,
            .common_fold_v2,
            => error.CompositeRecursiveStageUnavailable,
        };
    }

    pub fn profileValue(
        allocator: std.mem.Allocator,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        execution: artifact_store.ExecutionKeyV1,
        candidate_ordinal: u64,
    ) !protocol.Json {
        return switch (try validateNodeContract(node)) {
            .native_leaf_v4 => native_leaf.Adapter.profileValue(
                allocator,
                node,
                semantic,
                execution,
                candidate_ordinal,
            ),
            .canonical_empty_v2 => canonical_empty.Adapter.profileValue(
                allocator,
                node,
                semantic,
                execution,
                candidate_ordinal,
            ),
            .real_wrapper_v4,
            .common_fold_v2,
            => error.CompositeRecursiveStageUnavailable,
        };
    }

    pub fn validateOutput(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
    ) !void {
        return switch (try validateNodeContract(node)) {
            .native_leaf_v4 => native_leaf.Adapter.validateOutput(
                allocator,
                bytes,
                node,
                semantic,
                ordered_inputs,
            ),
            .canonical_empty_v2 => canonical_empty.Adapter.validateOutput(
                allocator,
                bytes,
                node,
                semantic,
                ordered_inputs,
            ),
            .real_wrapper_v4,
            .common_fold_v2,
            => error.CompositeRecursiveStageUnavailable,
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
        return switch (try validateNodeContract(node)) {
            .native_leaf_v4 => .{
                .native_leaf_v4 = try native_leaf.Adapter.coldOpenLease(
                    allocator,
                    store,
                    bytes,
                    node,
                    semantic,
                    ordered_inputs,
                ),
            },
            .canonical_empty_v2 => .{
                .canonical_empty_v2 = try canonical_empty.Adapter.coldOpenLease(
                    allocator,
                    store,
                    bytes,
                    node,
                    semantic,
                    ordered_inputs,
                ),
            },
            .real_wrapper_v4,
            .common_fold_v2,
            => error.CompositeRecursiveStageUnavailable,
        };
    }

    pub fn deinitLeasePayload(
        payload: *LeasePayload,
        _: std.mem.Allocator,
    ) void {
        payload.deinit();
    }

    pub fn validationValue(
        allocator: std.mem.Allocator,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        output_ref: artifact_store.BlobRefV1,
        validator_version: u32,
        mode: []const u8,
    ) !protocol.Json {
        return switch (try validateNodeContract(node)) {
            .native_leaf_v4 => native_leaf.Adapter.validationValue(
                allocator,
                node,
                semantic,
                output_ref,
                validator_version,
                mode,
            ),
            .canonical_empty_v2 => canonical_empty.Adapter.validationValue(
                allocator,
                node,
                semantic,
                output_ref,
                validator_version,
                mode,
            ),
            .real_wrapper_v4,
            .common_fold_v2,
            => error.CompositeRecursiveStageUnavailable,
        };
    }
};

fn parseStage(
    stage_kind: artifact_store.StageKindV1,
    stage_schema_version: u16,
) !StageCodeV2 {
    const code = std.meta.intToEnum(
        StageCodeV2,
        stage_schema_version,
    ) catch return error.InvalidCompositeRecursiveStage;
    if (stageContract(code).stage_kind != stage_kind)
        return error.InvalidCompositeRecursiveStage;
    return code;
}

fn validateNodeContract(node: protocol.Node) !StageCodeV2 {
    const code = try parseStage(node.stage_kind, node.stage_schema_version);
    const contract = stageContract(code);
    if (node.output_kind != contract.output_kind or
        node.output_schema_version != contract.output_schema_version or
        node.dependencies.len != contract.dependency_lease_count)
    {
        return error.InvalidCompositeRecursiveStage;
    }
    return code;
}

fn assertNativeLeaseContract(comptime Lease: type) void {
    inline for (.{ "validate", "deinit" }) |name| if (!@hasDecl(Lease, name))
        @compileError("native lease is missing declaration: " ++ name);
}

fn assertFoldLeaseContract(comptime Lease: type) void {
    inline for (.{ "FoldChild", "validate", "requireFoldChild", "deinit" }) |name| {
        if (!@hasDecl(Lease, name))
            @compileError("fold lease is missing declaration: " ++ name);
    }
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        NATIVE_LEAF_STAGE_SCHEMA_VERSION != 101 or
        REAL_WRAPPER_STAGE_SCHEMA_VERSION != 102 or
        EMPTY_WRAPPER_STAGE_SCHEMA_VERSION != 103 or
        COMMON_FOLD_STAGE_SCHEMA_VERSION != 104 or
        CAS_FORMAT_VERSION != 1 or
        PROOF_CAS_SCHEMA_VERSION != 1 or
        RECURSION_NODE_CAS_SCHEMA_VERSION != 2 or
        STAGE_MANIFEST_CAS_SCHEMA_VERSION != 1 or
        node_artifact.ENCODED_BYTE_COUNT != 2380 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        DURABLE_LEASE_CODEC_AVAILABLE or
        !DEPENDENCIES_BORROWED_DURING_BUILD or
        !BUILD_FAILURE_RETAINS_DEPENDENCY_LEASES or
        !SUCCESS_CONSUMES_AFTER_OUTER_PUBLICATION)
    {
        @compileError("composite recursive worker contract drifted");
    }
}
