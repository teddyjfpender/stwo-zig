//! Role-0 recursive-proof and cold-capability facade.
//!
//! A stage-101 native proof and its exact recursive sources are necessary but
//! not sufficient for a common wrapper proof. The types below require the
//! genuine 36-row q193 transaction, canonical decode, independent cold verify,
//! capture-derived geometry, and verifier-rerecorded graph before a role-
//! neutral child can exist. Availability flags remain false until that full
//! transaction passes its dedicated mutation gate.

const std = @import("std");

const capture_mod =
    @import("recursive_common_ethereum_incremental_leaf_composition_capture_v4.zig");
const core_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_core.zig");
const child_capability =
    @import("recursive_common_fold_child_capability_v2.zig");
const cohort_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const evidence_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_evidence_v4.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROLE = registry_mod.CircuitRoleV4
    .ethereum_incremental_leaf_wrapper_v4;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const PRODUCTION_ACTIVATION = false;
pub const WRAPPER_PROOF_AVAILABLE = false;
pub const COLD_WRAPPER_CAPTURE_AVAILABLE = false;
pub const FOLD_CHILD_PROJECTION_AVAILABLE = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Error = error{
    EthereumIncrementalUniversalProofUnavailableV4,
    EthereumIncrementalUniversalProofShellMismatchV4,
};

/// Pointer-free readiness receipt. It carries no proof, capture, claim, graph,
/// or freshness authority; the false proof/cold flags are lifted only after a
/// genuine gate, never because the implementation type compiled.
pub const ReadinessV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    role: registry_mod.CircuitRoleV4 = ROLE,
    source_authority_available: bool =
        cohort_mod.SOURCE_AUTHORITY_AVAILABLE,
    row_materializers_available: bool =
        cohort_mod.UNIVERSAL_ROW_MATERIALIZERS_AVAILABLE,
    claim_closure_available: bool =
        cohort_mod.UNIVERSAL_CLAIM_CLOSURE_AVAILABLE,
    proof_gate_available: bool =
        cohort_mod.UNIVERSAL_PROOF_GATE_AVAILABLE,
    cold_capture_available: bool = COLD_WRAPPER_CAPTURE_AVAILABLE,

    pub fn validate(self: ReadinessV4) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.role != ROLE or
            !self.source_authority_available or
            !self.row_materializers_available or
            !self.claim_closure_available or self.proof_gate_available or
            self.cold_capture_available)
        {
            return error.EthereumIncrementalUniversalProofShellMismatchV4;
        }
    }

    pub fn requireProof(self: ReadinessV4) Error!void {
        try self.validate();
        return error.EthereumIncrementalUniversalProofUnavailableV4;
    }
};

pub fn readiness() ReadinessV4 {
    const result = ReadinessV4{};
    result.validate() catch unreachable;
    return result;
}

/// Concrete q193 implementation family. The materialized Stage-102 source and
/// its runtime campaign authority must outlive every returned proof/capability.
pub fn Types(comptime Engine: type) type {
    const Core = core_mod.Types(Engine);
    const EvidenceTypes = evidence_mod.Types(Engine);
    const Evidence = EvidenceTypes.EvidenceV4;
    return struct {
        pub const CoreV4 = Core;
        pub const OwnedColdProofV4 = Core.OwnedColdProofV4;
        pub const ProveResultV4 = Core.ProveResultV4;
        pub const Ingress = Core.Ingress;
        pub const Graph = Core.Graph;
        pub const EvidenceV4 = Evidence;
        pub const ColdCompositionCaptureV4 =
            EvidenceTypes.ColdCompositionCaptureV4;
        pub const FreshAdmissionV4 = EvidenceTypes.FreshAdmissionV4;
        pub const FreshFoldChildV4 =
            freshFoldChildType(Evidence);

        pub const proveAndColdVerify = Core.proveAndColdVerify;
        pub const proveAndColdVerifyPreFinal =
            Core.proveAndColdVerifyPreFinal;
        pub const coldOpen = Core.coldOpen;
        pub const coldOpenPreFinal = Core.coldOpenPreFinal;
    };
}

fn freshFoldChildType(comptime ColdOwner: type) type {
    return FreshFoldChildV4(ColdOwner);
}

/// Role-specific adapter accepted by the tagged neutral child boundary. It is
/// constructible only from a concrete cold owner that supplies an actual
/// wrapper capture and verifier-rerecorded graph.
pub fn FreshFoldChildV4(comptime ColdOwner: type) type {
    const Capture = capture_mod.ColdCompositionCaptureV4(ColdOwner);
    return struct {
        cold: Capture,
        wrapper: @TypeOf(@as(Capture, undefined).wrapper),
        ingress: ColdOwner.Ingress,
        graph: ColdOwner.Graph,
        query_words: @TypeOf(@as(ColdOwner.Ingress, undefined).query_words),
        query_log_size: u32,
        final_transcript_digest: @TypeOf(
            @as(ColdOwner.Ingress, undefined).final_transcript_digest,
        ),
        final_transcript_draw_count: u32,
        query_words_identity_sha256: @TypeOf(
            @as(ColdOwner.Ingress, undefined).query_words_identity_sha256,
        ),

        const Self = @This();

        pub fn init(
            owner: *const ColdOwner,
            registry: *const registry_mod.RecursiveCircuitRegistryV1,
        ) !Self {
            const cold = try Capture.init(owner, registry);
            const result = Self{
                .cold = cold,
                .wrapper = cold.wrapper,
                .ingress = cold.ingress,
                .graph = cold.graph,
                .query_words = cold.ingress.query_words,
                .query_log_size = cold.ingress.query_log_size,
                .final_transcript_digest = cold.ingress.final_transcript_digest,
                .final_transcript_draw_count = cold.ingress.final_transcript_draw_count,
                .query_words_identity_sha256 = cold.ingress.query_words_identity_sha256,
            };
            try result.validateBorrowed();
            return result;
        }

        pub fn validateBorrowed(self: Self) !void {
            try self.cold.validateBorrowed();
            if (self.wrapper.artifact != self.cold.wrapper.artifact or
                self.wrapper.geometry != self.cold.wrapper.geometry or
                self.wrapper.capture != self.cold.wrapper.capture or
                self.ingress.node_public != self.cold.ingress.node_public or
                self.ingress.claims != self.cold.ingress.claims or
                self.ingress.capture != self.cold.ingress.capture or
                self.graph.capture_identity_sha256 !=
                    self.cold.graph.capture_identity_sha256 or
                self.query_words != self.ingress.query_words or
                self.query_words != self.graph.query_words or
                self.query_log_size != self.ingress.query_log_size or
                self.query_log_size != self.graph.query_log_size or
                self.final_transcript_digest !=
                    self.ingress.final_transcript_digest or
                self.final_transcript_digest !=
                    self.graph.final_transcript_digest or
                self.final_transcript_draw_count !=
                    self.ingress.final_transcript_draw_count or
                self.final_transcript_draw_count !=
                    self.graph.final_transcript_draw_count or
                self.query_words_identity_sha256 !=
                    self.ingress.query_words_identity_sha256 or
                self.query_words_identity_sha256 !=
                    self.graph.query_words_identity_sha256)
            {
                return error.EthereumIncrementalUniversalProofShellMismatchV4;
            }
        }
    };
}

/// Exact tagged child type consumed by the common fold. The real branch is
/// typed now, but no value can exist until `ColdOwner` completes a genuine
/// role-0 prove -> decode -> cold-verify -> graph-rerecord transaction.
pub fn TaggedFoldChildV4(
    comptime ColdOwner: type,
    comptime EmptyChild: type,
    comptime CommonChild: type,
) type {
    return child_capability.TaggedFoldChildV2(
        FreshFoldChildV4(ColdOwner),
        EmptyChild,
        CommonChild,
    );
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        @intFromEnum(ROLE) != 0 or COMPONENT_COUNT != 36 or
        PRODUCTION_ACTIVATION or WRAPPER_PROOF_AVAILABLE or
        COLD_WRAPPER_CAPTURE_AVAILABLE or
        FOLD_CHILD_PROJECTION_AVAILABLE or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("Ethereum incremental universal proof V4 drifted");
    }
    _ = std;
}
