//! Live verifier admission for field-native common recursive wrappers.
//!
//! Durable schema-2 artifacts are transport only. A view exists only while a
//! role-specific cold verifier owns the exact expanded PCS capture which
//! remints the registry geometry and fixed proof-wire authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_node_artifact_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const recursion = frontend.recursion;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const COMMITMENT_TREE_COUNT: usize = 4;
pub const PROOF_ARTIFACT_KIND: u32 = 8;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
pub const Registry = registry_mod.RecursiveCircuitRegistryV1;
pub const Geometry = registry_mod.AuthenticatedGeometryV1;
pub const RecursiveNodeArtifact = artifact_mod.RecursiveNodeArtifactV2;
pub const NodePublic = artifact_mod.NodePublicV2;

pub const Error = registry_mod.Error || error{
    ChildCoordinateMismatch,
    EvidenceContractIncomplete,
    FreshWrapperCaptureMismatch,
    FreshWrapperEvidenceMismatch,
    FreshWrapperRoleMismatch,
    InvalidCommonFoldOutput,
    InvalidRecursiveProofReference,
};

pub const FreshWrapperViewV2 = struct {
    artifact: *const RecursiveNodeArtifact,
    geometry: *const Geometry,
    capture: *const ProofCapture,

    pub fn validateAgainst(
        self: FreshWrapperViewV2,
        registry: *const Registry,
    ) !void {
        try registry.admitV2(self.artifact, self.geometry);
        if (self.artifact.proof_ref.kind != PROOF_ARTIFACT_KIND)
            return error.InvalidRecursiveProofReference;
        const artifact_role = try registry_mod.roleForArtifactV2(self.artifact);
        if (artifact_role != self.geometry.role)
            return error.FreshWrapperRoleMismatch;
        try validateCaptureShape(self.capture, self.geometry);
    }

    pub fn role(self: FreshWrapperViewV2) !registry_mod.CircuitRoleV1 {
        return registry_mod.roleForArtifactV2(self.artifact);
    }

    pub fn reference(self: FreshWrapperViewV2) !artifact_mod.ArtifactRefV1 {
        return self.artifact.artifactRef();
    }

    pub fn nodePublic(self: FreshWrapperViewV2) *const NodePublic {
        return &self.artifact.node_public;
    }
};

/// `Evidence` owns the decoded proof, fresh verifier result, capture, geometry,
/// and schema-2 artifact. It must expose the five declarations checked below.
pub fn OwnedFreshWrapperAdmissionV2(comptime Evidence: type) type {
    assertEvidenceContract(Evidence);
    return struct {
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        evidence: Evidence,
        registry: Registry,

        const Self = @This();

        pub fn initOwned(evidence: Evidence, registry: Registry) !Self {
            var owned_evidence = evidence;
            errdefer owned_evidence.deinit();
            var result = Self{
                .evidence = owned_evidence,
                .registry = registry,
            };
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.evidence.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION)
            {
                return error.FreshWrapperEvidenceMismatch;
            }
            try self.registry.validate();
            try self.evidence.validateFresh(&self.registry);
            try self.view().validateAgainst(&self.registry);
        }

        pub fn view(self: *const Self) FreshWrapperViewV2 {
            return .{
                .artifact = self.evidence.artifact(),
                .geometry = self.evidence.geometry(),
                .capture = self.evidence.proofCapture(),
            };
        }
    };
}

pub const ParentNodePublicDerivationV2 = struct {
    node_public: NodePublic,

    pub fn validateAgainst(
        self: *const ParentNodePublicDerivationV2,
        left: FreshWrapperViewV2,
        right: FreshWrapperViewV2,
        parent: artifact_mod.TaskCoordinateV1,
        registry: *const Registry,
    ) !void {
        const expected = try deriveParentNodePublic(left, right, parent, registry);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidCommonFoldOutput;
    }
};

pub fn deriveParentNodePublic(
    left: FreshWrapperViewV2,
    right: FreshWrapperViewV2,
    parent: artifact_mod.TaskCoordinateV1,
    registry: *const Registry,
) !ParentNodePublicDerivationV2 {
    try left.validateAgainst(registry);
    try right.validateAgainst(registry);
    try validateOrderedChildren(left.artifact, right.artifact, parent);
    return .{
        .node_public = try NodePublic.initParent(
            left.nodePublic(),
            right.nodePublic(),
            parent,
        ),
    };
}

pub fn deriveParentNodePublicFromFields(
    left: *const NodePublic,
    right: *const NodePublic,
    parent: artifact_mod.TaskCoordinateV1,
) !ParentNodePublicDerivationV2 {
    return .{ .node_public = try NodePublic.initParent(left, right, parent) };
}

fn validateOrderedChildren(
    left: *const RecursiveNodeArtifact,
    right: *const RecursiveNodeArtifact,
    parent: artifact_mod.TaskCoordinateV1,
) !void {
    try parent.validate();
    if (parent.height == 0 or left.coordinate.height + 1 != parent.height or
        right.coordinate.height != left.coordinate.height or
        left.coordinate.index != parent.index * 2 or
        right.coordinate.index != left.coordinate.index + 1 or
        !std.mem.eql(
            u8,
            &left.campaign_namespace_sha256,
            &right.campaign_namespace_sha256,
        )) return error.ChildCoordinateMismatch;
}

fn validateCaptureShape(
    capture: *const ProofCapture,
    geometry: *const Geometry,
) !void {
    const derived = registry_mod.sealProofShapeFromCapture(
        capture,
        geometry.component_count,
        geometry.proof_shape.column_log_degree,
        geometry.proof_shape.table_layout_identity_sha256,
    ) catch return error.FreshWrapperCaptureMismatch;
    if (!std.meta.eql(derived, geometry.proof_shape))
        return error.FreshWrapperCaptureMismatch;
}

fn assertEvidenceContract(comptime Evidence: type) void {
    inline for (.{
        "deinit",
        "validateFresh",
        "artifact",
        "geometry",
        "proofCapture",
    }) |name| if (!@hasDecl(Evidence, name))
        @compileError("field wrapper Evidence missing declaration: " ++ name);
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 2 or
        COMMITMENT_TREE_COUNT != 4 or PRODUCTION_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or PROOF_ARTIFACT_KIND != 8 or
        artifact_mod.SCHEMA_VERSION != 2)
    {
        @compileError("field-native common wrapper authority drifted");
    }
}
