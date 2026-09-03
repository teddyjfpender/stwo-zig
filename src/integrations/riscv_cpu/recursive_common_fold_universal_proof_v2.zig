//! Fail-closed q193 transaction boundary for the field-native common fold.
//!
//! This module specifies the only acceptable backend contract without
//! pretending that another recursive circuit's engine/session is the common
//! fold. A backend must prove, independently cold-open, and only then return
//! an owner whose nonserializable fold-child view borrows that cold result.
//! The durable envelope is always kind 10/schema 2.

const std = @import("std");

const cohort_mod =
    @import("recursive_common_fold_universal_cohort_v2.zig");
const secure_proof = @import("recursive_common_fold_secure_proof_v2.zig");
const common_authority = @import("recursive_common_wrapper_authority_v2.zig");
const node_mod = @import("recursive_node_artifact_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const FRI_QUERY_COUNT: u32 = 193;
pub const OUTPUT_KIND: u32 = node_mod.RECURSIVE_NODE_ARTIFACT_KIND;
pub const OUTPUT_SCHEMA_VERSION: u16 = node_mod.SCHEMA_VERSION;
pub const COMMON_FOLD_ROLE =
    registry_mod.CircuitRoleV1.common_fold_field_v2;

pub const PRODUCTION_ACTIVATION = false;
pub const Q193_BACKEND_AVAILABLE =
    cohort_mod.ALL_SCHEMA4_ROLE_BRANCHES_AVAILABLE and
    cohort_mod.FIXED_WIRE_SOURCE_AVAILABLE and
    cohort_mod.COMPLETE_POSEIDON_PROVIDER_TRACE_AVAILABLE and
    cohort_mod.GLOBAL_RELATION_CLOSURE_AVAILABLE;
pub const COMMON_FOLD_SESSION_AVAILABLE = true;
pub const COLD_GRAPH_REMINT_AVAILABLE = Q193_BACKEND_AVAILABLE;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Error = cohort_mod.Error || node_mod.Error || registry_mod.Error ||
    error{
        CommonFoldColdGraphMismatch,
        CommonFoldColdQ193VerifierUnavailable,
        CommonFoldDurableOutputMismatch,
        CommonFoldProofBackendContractMismatch,
    };

pub const ReadinessV2 = struct {
    registry_role: registry_mod.CircuitRoleV1 = COMMON_FOLD_ROLE,
    universal_component_count: u16 = 36,
    poseidon_call_count: u16 = 116,
    fri_query_count: u16 = FRI_QUERY_COUNT,
    fixed_wire_source_available: bool =
        cohort_mod.FIXED_WIRE_SOURCE_AVAILABLE,
    complete_poseidon_provider_trace_available: bool =
        cohort_mod.COMPLETE_POSEIDON_PROVIDER_TRACE_AVAILABLE,
    global_relation_closure_available: bool =
        cohort_mod.GLOBAL_RELATION_CLOSURE_AVAILABLE,
    common_fold_session_available: bool = COMMON_FOLD_SESSION_AVAILABLE,
    q193_backend_available: bool = Q193_BACKEND_AVAILABLE,
    cold_graph_remint_available: bool = COLD_GRAPH_REMINT_AVAILABLE,
    production_activation: bool = PRODUCTION_ACTIVATION,
};

pub fn currentReadiness() ReadinessV2 {
    return .{};
}

/// Exact native q193 transaction selected by the cold-derived fixed proof
/// dimensions. The generic contract remains public for isolated test
/// backends, while this is the only current production-shaped implementation.
pub fn SecureTransactionV2(
    comptime dimensions: @import("stwo_riscv_frontend").recursion.fixed_wire.Dimensions,
) type {
    return TransactionV2(secure_proof.BackendV2(dimensions));
}

/// Generic transaction used only after a common-fold-specific backend lands.
/// Merely declaring a type with the right method names grants no authority:
/// every returned owner is revalidated against the live cohort, exact schema-2
/// node, registered common-fold geometry, and freshly rerecorded graph.
pub fn TransactionV2(comptime Backend: type) type {
    assertBackendContract(Backend);
    return struct {
        pub const OwnedColdProof = Backend.OwnedColdProof;
        pub const ExecutionOptions = Backend.ExecutionOptions;

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            cohort: *const cohort_mod.CohortV2,
            execution: ExecutionOptions,
        ) !OwnedColdProof {
            try cohort.validate();
            var result = try Backend.proveAndColdVerify(
                allocator,
                cohort,
                execution,
            );
            errdefer result.deinit();
            try validateColdOwner(&result, cohort);
            return result;
        }

        /// `node_bytes` and `proof_bytes` are both retained transport. The
        /// backend must decode them canonically and rerun q193 before it can
        /// construct `OwnedColdProof`; this wrapper then checks the reminted
        /// nonserializable graph/lease boundary a second time.
        pub fn coldOpen(
            allocator: std.mem.Allocator,
            cohort: *const cohort_mod.CohortV2,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !OwnedColdProof {
            try cohort.validate();
            if (proof_bytes.len == 0 or
                node_bytes.len != node_mod.ENCODED_BYTE_COUNT)
            {
                return error.CommonFoldDurableOutputMismatch;
            }
            var result = try Backend.coldOpen(
                allocator,
                cohort,
                proof_bytes,
                node_bytes,
            );
            errdefer result.deinit();
            try validateColdOwner(&result, cohort);
            const canonical = try result.nodeArtifact().encodeCanonical();
            if (!std.mem.eql(u8, node_bytes, &canonical) or
                !std.mem.eql(u8, proof_bytes, result.proofBytes()))
            {
                return error.CommonFoldDurableOutputMismatch;
            }
            return result;
        }

        fn validateColdOwner(
            cold: *const OwnedColdProof,
            cohort: *const cohort_mod.CohortV2,
        ) !void {
            try cold.validateAgainst(cohort);
            const node = cold.nodeArtifact();
            try validateDurableOutput(node, cohort);
            if (cold.proofBytes().len == 0)
                return error.CommonFoldDurableOutputMismatch;
            const child = try cold.requireFoldChild();
            try child.validateBorrowed();
            const tagged = try cohort_mod.FreshFoldChildV2.fromCommon(
                &child,
                &cohort.geometry.registry,
            );
            const projection = try tagged.projection(&cohort.geometry.registry);
            if (projection.wrapper.artifact != node or
                projection.wrapper.geometry !=
                    cohort.geometry.commonFoldGeometry() or
                !std.meta.eql(
                    try projection.wrapper.reference(),
                    try node.artifactRef(),
                )) return error.CommonFoldColdGraphMismatch;
        }
    };
}

pub fn validateDurableOutput(
    node: *const node_mod.RecursiveNodeArtifactV2,
    cohort: *const cohort_mod.CohortV2,
) !void {
    try cohort.validate();
    try node.validate();
    const expected_stage: node_mod.StageKindV1 =
        if (cohort.input.parent_coordinate.height ==
        @import("recursive_node_artifact_v1.zig").ROOT_HEIGHT)
            .root
        else
            .fold;
    if (node.stage_kind != expected_stage or node.child_count != 2 or
        !std.meta.eql(node.coordinate, cohort.input.parent_coordinate) or
        !std.meta.eql(node.node_public, cohort.public_schedule.parent) or
        !std.mem.eql(
            u8,
            &node.campaign_namespace_sha256,
            &cohort.input.campaign_namespace_sha256,
        ) or !std.mem.eql(
        u8,
        &node.registry_identity_sha256,
        &cohort.geometry.registry.identity_sha256,
    ) or !std.meta.eql(
        node.ordered_children,
        cohort.input.child_refs,
    ) or node.proof_ref.kind != common_authority.PROOF_ARTIFACT_KIND or
        node.proof_ref.byte_count == 0)
    {
        return error.CommonFoldDurableOutputMismatch;
    }
    const geometry = cohort.geometry.commonFoldGeometry();
    const entry = try cohort.geometry.registry.entry(COMMON_FOLD_ROLE);
    if (!std.mem.eql(
        u8,
        &node.circuit_identity_sha256,
        &entry.circuit_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &node.program_identity_sha256,
        &entry.program_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &node.profile_identity_sha256,
        &entry.profile_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &node.pcs_identity_sha256,
        &entry.pcs_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &node.padding_layout_identity_sha256,
        &entry.padding_layout_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &node.proof_shape_identity_sha256,
        &geometry.proof_shape.identity_sha256,
    ) or !std.meta.eql(node.preprocessed_root, entry.preprocessed_root)) {
        return error.CommonFoldDurableOutputMismatch;
    }
    try cohort.geometry.registry.admitV2(node, geometry);
    const ref = try node.artifactRef();
    if (ref.kind != OUTPUT_KIND or ref.schema_version != OUTPUT_SCHEMA_VERSION or
        ref.byte_count != node_mod.ENCODED_BYTE_COUNT)
    {
        return error.CommonFoldDurableOutputMismatch;
    }
}

/// Explicit current fail-closed path. No caller can obtain a fresh fold child
/// from a digest, a schema-2 node, or a proof byte slice alone.
pub fn requireCurrentColdBackend() Error!void {
    if (comptime !Q193_BACKEND_AVAILABLE)
        return error.CommonFoldColdQ193VerifierUnavailable;
}

fn assertBackendContract(comptime Backend: type) void {
    inline for (.{
        "OwnedColdProof",
        "ExecutionOptions",
        "proveAndColdVerify",
        "coldOpen",
    }) |name| if (!@hasDecl(Backend, name))
        @compileError("common-fold backend missing declaration: " ++ name);
    const Cold = Backend.OwnedColdProof;
    inline for (.{
        "deinit",
        "validateAgainst",
        "nodeArtifact",
        "proofBytes",
        "requireFoldChild",
    }) |name| if (!@hasDecl(Cold, name))
        @compileError("common-fold cold owner missing declaration: " ++ name);
    inline for (.{
        "fri_query_count",
        "output_kind",
        "output_schema_version",
        "common_fold_role",
        "cold_verification_before_remint",
        "serializable_fresh_capability",
        "production_activation",
    }) |name| if (!@hasDecl(Backend, name))
        @compileError("common-fold backend missing protocol constant: " ++ name);
    if (Backend.fri_query_count != FRI_QUERY_COUNT or
        Backend.output_kind != OUTPUT_KIND or
        Backend.output_schema_version != OUTPUT_SCHEMA_VERSION or
        Backend.common_fold_role != COMMON_FOLD_ROLE or
        !Backend.cold_verification_before_remint or
        Backend.serializable_fresh_capability or
        Backend.production_activation)
    {
        @compileError("common-fold backend protocol contract mismatch");
    }
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        FRI_QUERY_COUNT != 193 or OUTPUT_KIND != 10 or
        OUTPUT_SCHEMA_VERSION != 2 or PRODUCTION_ACTIVATION or
        !COMMON_FOLD_SESSION_AVAILABLE or
        COLD_GRAPH_REMINT_AVAILABLE != Q193_BACKEND_AVAILABLE or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("common-fold proof transaction contract drifted");
    }
}
