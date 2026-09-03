//! Typed recursive-circuit trust list and authenticated padding-parity gate.
//!
//! `PaddingParityV1` never manufactures rows or accepts caller-authored
//! padding.  Each circuit supplies a sealed geometry authority; the gate first
//! verifies that authority against the registry, computes the pointwise target
//! component sizes, and then requires every already-authenticated padded shape
//! to equal that target.  Circuit hashes may differ, but PCS, trace,
//! all four commitment-tree layouts, fixed proof-wire dimensions, and the
//! NodePublic ABI may not.

const std = @import("std");
const builtin = @import("builtin");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const artifact_v2_mod = @import("recursive_node_artifact_v2.zig");
const field_public_mod = @import("recursive_field_node_public_v2.zig");
const proof_shape_mod = @import("recursive_fixed_proof_shape_v3.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
// Schema 2 raised the preprocessed-column ceiling to fit the 570-column
// universal manifest. Schema 3 additionally authenticated the entire fixed
// recursive proof wire. Schema 4 replaces the migration-era omitted-leaf and
// temporal-parent role labels with the exact production circuits. Ordinals
// remain stable, but schema-3 registries are intentionally not admissible as
// schema-4 authority.
pub const SCHEMA_VERSION: u16 = 4;
pub const PRODUCTION_ACTIVATION = false;
pub const ROLE_COUNT: usize = 3;
pub const MAX_COMPONENT_COUNT: usize = 64;
pub const MAX_PREPROCESSED_COLUMN_COUNT: usize = 1024;
pub const NO_LIFTING_LOG_SIZE: u32 = std.math.maxInt(u32);

const PCS_IDENTITY_DOMAIN =
    "stwo-zig/recursive-circuit-pcs/v1\x00";
const OUTPUT_ABI_IDENTITY_DOMAIN =
    "stwo-zig/recursive-circuit-output-abi/v1\x00";
const GEOMETRY_IDENTITY_DOMAIN =
    "stwo-zig/recursive-circuit-authenticated-geometry/v4\x00";
const REGISTRY_ENTRY_DOMAIN =
    "stwo-zig/recursive-circuit-registry-entry/v4\x00";
const REGISTRY_IDENTITY_DOMAIN =
    "stwo-zig/recursive-circuit-registry/v4\x00";
const PARITY_IDENTITY_DOMAIN =
    "stwo-zig/recursive-padding-parity/v4\x00";

pub const Error = artifact_mod.Error || artifact_v2_mod.Error ||
    proof_shape_mod.Error || error{
    CircuitNotRegistered,
    FixedProofWireShapeMismatch,
    DuplicateCircuitRole,
    InvalidCircuitGeometry,
    InvalidCircuitRegistry,
    InvalidOutputAbi,
    InvalidPcsConfig,
    MissingAuthenticatedPadding,
    PaddingComponentCountMismatch,
    PaddingComponentTargetMismatch,
    PaddingLayoutMismatch,
    PcsConfigMismatch,
    PreprocessedColumnLayoutMismatch,
    RegistryArtifactMismatch,
    TraceLogSizeMismatch,
};

pub const FixedProofShapeV3 = proof_shape_mod.AuthorityV3;
pub const sealProofShapeFromCapture = proof_shape_mod.sealFromCapture;
pub const FIXED_PROOF_TREE_COUNT: usize = proof_shape_mod.TREE_COUNT;
pub const MAX_TREE_COLUMN_COUNT: usize =
    proof_shape_mod.MAX_TREE_COLUMN_COUNT;
pub const MAX_FRI_LAYER_COUNT: usize =
    proof_shape_mod.MAX_FRI_LAYER_COUNT;

pub const CircuitRoleV4 = enum(u8) {
    ethereum_incremental_leaf_wrapper_v4 = 0,
    canonical_empty_field_v2 = 1,
    common_fold_field_v2 = 2,
};

/// Compatibility alias for APIs whose container types predate the schema-4
/// registry. The enum tags themselves are exclusively the production roles.
pub const CircuitRoleV1 = CircuitRoleV4;

pub const PcsConfigV1 = struct {
    interaction_pow_bits: u32,
    pcs_pow_bits: u32,
    fri_log_blowup_factor: u32,
    fri_query_count: u32,
    fri_fold_step: u32,
    fri_log_last_layer_degree_bound: u32,
    lifting_log_size: u32 = NO_LIFTING_LOG_SIZE,
    identity_sha256: [32]u8,

    pub fn seal(value: PcsConfigV1) Error!PcsConfigV1 {
        var result = value;
        result.identity_sha256 = pcsIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn secureTemporalParent() PcsConfigV1 {
        return seal(.{
            .interaction_pow_bits = 10,
            .pcs_pow_bits = 16,
            .fri_log_blowup_factor = 1,
            .fri_query_count = 193,
            .fri_fold_step = 4,
            .fri_log_last_layer_degree_bound = 0,
            .identity_sha256 = undefined,
        }) catch unreachable;
    }

    pub fn validate(self: *const PcsConfigV1) Error!void {
        if (self.fri_log_blowup_factor == 0 or
            self.fri_query_count == 0 or self.fri_fold_step == 0 or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &pcsIdentity(self),
            ))
        {
            return error.InvalidPcsConfig;
        }
    }
};

pub const OutputAbiV1 = struct {
    format_version: u16 = artifact_mod.FORMAT_VERSION,
    schema_version: u16 = artifact_mod.SCHEMA_VERSION,
    statement_word_count: u32 = artifact_mod.STATEMENT_WORD_COUNT,
    digest_word_count: u32 = artifact_mod.DIGEST_WORD_COUNT,
    encoded_byte_count: u32 = artifact_mod.NODE_PUBLIC_BYTE_COUNT,
    node_public_abi_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn nodePublic() OutputAbiV1 {
        var result = OutputAbiV1{
            .node_public_abi_sha256 = artifact_mod.nodePublicAbiIdentity(),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = outputAbiIdentity(&result);
        return result;
    }

    /// Production recursive circuits use the field-native V2 payload. SHA
    /// receipts remain outside the AIR and therefore outside this output ABI.
    pub fn fieldNodePublicV2() OutputAbiV1 {
        var result = OutputAbiV1{
            .format_version = @intCast(field_public_mod.FORMAT_VERSION),
            .schema_version = @intCast(field_public_mod.SCHEMA_VERSION),
            .statement_word_count = field_public_mod.STATEMENT_WORD_COUNT,
            .digest_word_count = field_public_mod.DIGEST_WORD_COUNT,
            .encoded_byte_count = field_public_mod.ENCODED_BYTE_COUNT,
            .node_public_abi_sha256 = field_public_mod.abiIdentitySha256(),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = outputAbiIdentity(&result);
        return result;
    }

    pub fn validate(self: *const OutputAbiV1) Error!void {
        if (!std.meta.eql(self.*, nodePublic()) and
            !std.meta.eql(self.*, fieldNodePublicV2()))
        {
            return error.InvalidOutputAbi;
        }
    }
};

/// Pointer-free geometry emitted only after a kind-specific native cold-open
/// has reconstructed and authenticated the circuit layout.
pub const AuthenticatedGeometryV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    role: CircuitRoleV1,
    authenticated_padding: bool,
    component_count: u16,
    preprocessed_column_count: u16,
    trace_log_size: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    active_component_log_sizes: [MAX_COMPONENT_COUNT]u8,
    padded_component_log_sizes: [MAX_COMPONENT_COUNT]u8,
    preprocessed_column_log_sizes: [MAX_PREPROCESSED_COLUMN_COUNT]u8,
    circuit_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    padding_layout_identity_sha256: [32]u8,
    preprocessed_root: [artifact_mod.DIGEST_WORD_COUNT]u32,
    pcs: PcsConfigV1,
    output_abi: OutputAbiV1,
    proof_shape: FixedProofShapeV3,
    authority_identity_sha256: [32]u8,

    pub fn seal(value: AuthenticatedGeometryV1) Error!AuthenticatedGeometryV1 {
        var result = value;
        result.authority_identity_sha256 = geometryIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const AuthenticatedGeometryV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !self.authenticated_padding or
            self.component_count == 0 or
            self.component_count > MAX_COMPONENT_COUNT or
            self.preprocessed_column_count == 0 or
            self.preprocessed_column_count > MAX_PREPROCESSED_COLUMN_COUNT or
            self.trace_log_size == 0 or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            std.mem.allEqual(u8, &self.circuit_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.program_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.profile_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.padding_layout_identity_sha256, 0) or
            allWordsZero(self.preprocessed_root))
        {
            return error.InvalidCircuitGeometry;
        }
        try self.pcs.validate();
        try self.output_abi.validate();
        try self.proof_shape.validateAgainstPcs(
            self.pcs.fri_log_blowup_factor,
            self.pcs.fri_query_count,
            self.pcs.fri_fold_step,
            self.pcs.fri_log_last_layer_degree_bound,
        );
        if (self.proof_shape.claimed_sum_count != self.component_count or
            self.proof_shape.tree_column_counts[0] !=
                self.preprocessed_column_count)
        {
            return error.InvalidCircuitGeometry;
        }
        // VerifiedProofCapture stores FRI-extended logs. Registry preprocessing
        // geometry remains in base trace-log units, so the relation is exact
        // base + blowup rather than byte equality.
        for (
            self.proof_shape.tree_column_log_sizes[0][0..self.preprocessed_column_count],
            self.preprocessed_column_log_sizes[0..self.preprocessed_column_count],
        ) |captured, base| {
            const expected = std.math.add(
                u32,
                base,
                self.pcs.fri_log_blowup_factor,
            ) catch return error.InvalidCircuitGeometry;
            if (captured != expected) return error.InvalidCircuitGeometry;
        }
        for (0..self.component_count) |index| {
            const active = self.active_component_log_sizes[index];
            const padded = self.padded_component_log_sizes[index];
            if (active == 0 or padded < active or padded > self.trace_log_size)
                return error.InvalidCircuitGeometry;
        }
        if (!std.mem.allEqual(
            u8,
            self.active_component_log_sizes[self.component_count..],
            0,
        ) or !std.mem.allEqual(
            u8,
            self.padded_component_log_sizes[self.component_count..],
            0,
        ) or !std.mem.allEqual(
            u8,
            self.preprocessed_column_log_sizes[self.preprocessed_column_count..],
            0,
        )) return error.InvalidCircuitGeometry;
        for (self.preprocessed_column_log_sizes[0..self.preprocessed_column_count]) |log_size| {
            if (log_size == 0 or log_size > self.trace_log_size)
                return error.InvalidCircuitGeometry;
        }
        if (!std.mem.eql(
            u8,
            &self.authority_identity_sha256,
            &geometryIdentity(self),
        )) return error.InvalidCircuitGeometry;
    }
};

pub const RegistryEntryV1 = struct {
    role: CircuitRoleV1,
    circuit_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    profile_identity_sha256: [32]u8,
    pcs_identity_sha256: [32]u8,
    padding_layout_identity_sha256: [32]u8,
    node_public_abi_sha256: [32]u8,
    preprocessed_root: [artifact_mod.DIGEST_WORD_COUNT]u32,
    geometry_authority_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn fromGeometry(value: *const AuthenticatedGeometryV1) Error!RegistryEntryV1 {
        try value.validate();
        var result = RegistryEntryV1{
            .role = value.role,
            .circuit_identity_sha256 = value.circuit_identity_sha256,
            .program_identity_sha256 = value.program_identity_sha256,
            .profile_identity_sha256 = value.profile_identity_sha256,
            .pcs_identity_sha256 = value.pcs.identity_sha256,
            .padding_layout_identity_sha256 = value.padding_layout_identity_sha256,
            .node_public_abi_sha256 = value.output_abi.node_public_abi_sha256,
            .preprocessed_root = value.preprocessed_root,
            .geometry_authority_identity_sha256 = value.authority_identity_sha256,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = registryEntryIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const RegistryEntryV1) Error!void {
        inline for (.{
            self.circuit_identity_sha256,
            self.program_identity_sha256,
            self.profile_identity_sha256,
            self.pcs_identity_sha256,
            self.padding_layout_identity_sha256,
            self.node_public_abi_sha256,
            self.geometry_authority_identity_sha256,
        }) |identity| {
            if (std.mem.allEqual(u8, &identity, 0))
                return error.InvalidCircuitRegistry;
        }
        const legacy_abi = artifact_mod.nodePublicAbiIdentity();
        const field_abi = field_public_mod.abiIdentitySha256();
        if (allWordsZero(self.preprocessed_root) or
            (!std.mem.eql(
                u8,
                &self.node_public_abi_sha256,
                &legacy_abi,
            ) and !std.mem.eql(
                u8,
                &self.node_public_abi_sha256,
                &field_abi,
            )) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &registryEntryIdentity(self),
        )) return error.InvalidCircuitRegistry;
    }
};

pub const RecursiveCircuitRegistryV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    entry_count: u8 = ROLE_COUNT,
    entries: [ROLE_COUNT]RegistryEntryV1,
    identity_sha256: [32]u8,

    pub fn seal(entries: [ROLE_COUNT]RegistryEntryV1) Error!RecursiveCircuitRegistryV1 {
        var result = RecursiveCircuitRegistryV1{
            .entries = entries,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = registryIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const RecursiveCircuitRegistryV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.entry_count != ROLE_COUNT)
        {
            return error.InvalidCircuitRegistry;
        }
        for (&self.entries, 0..) |*registered_entry, ordinal| {
            try registered_entry.validate();
            if (@intFromEnum(registered_entry.role) != ordinal)
                return error.DuplicateCircuitRole;
        }
        if (!std.mem.eql(
            u8,
            &self.identity_sha256,
            &registryIdentity(self),
        )) return error.InvalidCircuitRegistry;
    }

    pub fn entry(self: *const RecursiveCircuitRegistryV1, role: CircuitRoleV1) Error!*const RegistryEntryV1 {
        try self.validate();
        const result = &self.entries[@intFromEnum(role)];
        if (result.role != role) return error.CircuitNotRegistered;
        return result;
    }

    /// Registry admission is structural.  It cannot replace kind-specific
    /// proof cold-open, which must have minted `geometry` first.
    pub fn admit(
        self: *const RecursiveCircuitRegistryV1,
        artifact: *const artifact_mod.RecursiveNodeArtifactV1,
        geometry: *const AuthenticatedGeometryV1,
    ) Error!void {
        try self.validate();
        try artifact.validate();
        try geometry.validate();
        const role = try roleForArtifact(artifact);
        if (geometry.role != role) return error.RegistryArtifactMismatch;
        const registered = try self.entry(role);
        if (!std.mem.eql(
            u8,
            &artifact.registry_identity_sha256,
            &self.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.circuit_identity_sha256,
            &registered.circuit_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.program_identity_sha256,
            &registered.program_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.profile_identity_sha256,
            &registered.profile_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.pcs_identity_sha256,
            &registered.pcs_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.padding_layout_identity_sha256,
            &registered.padding_layout_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.node_public_abi_sha256,
            &registered.node_public_abi_sha256,
        ) or !std.mem.eql(
            u8,
            &geometry.authority_identity_sha256,
            &registered.geometry_authority_identity_sha256,
        ) or !std.meta.eql(
            artifact.preprocessed_root,
            registered.preprocessed_root,
        ) or !std.meta.eql(
            geometry.preprocessed_root,
            registered.preprocessed_root,
        )) return error.RegistryArtifactMismatch;
    }

    /// Schema-2 admission for the field-native recursive public ABI. The
    /// caller must still be a kind-specific cold verifier retaining the live
    /// PCS capture which minted `geometry`.
    pub fn admitV2(
        self: *const RecursiveCircuitRegistryV1,
        artifact: *const artifact_v2_mod.RecursiveNodeArtifactV2,
        geometry: *const AuthenticatedGeometryV1,
    ) Error!void {
        try self.validate();
        try artifact.validate();
        try geometry.validate();
        const role = try roleForArtifactV2(artifact);
        if (geometry.role != role or !std.meta.eql(
            geometry.output_abi,
            OutputAbiV1.fieldNodePublicV2(),
        )) return error.RegistryArtifactMismatch;
        const registered = try self.entry(role);
        if (!std.mem.eql(
            u8,
            &artifact.registry_identity_sha256,
            &self.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.circuit_identity_sha256,
            &registered.circuit_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.program_identity_sha256,
            &registered.program_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.profile_identity_sha256,
            &registered.profile_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.pcs_identity_sha256,
            &registered.pcs_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.padding_layout_identity_sha256,
            &registered.padding_layout_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.node_public_abi_sha256,
            &registered.node_public_abi_sha256,
        ) or !std.mem.eql(
            u8,
            &artifact.proof_shape_identity_sha256,
            &geometry.proof_shape.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &geometry.authority_identity_sha256,
            &registered.geometry_authority_identity_sha256,
        ) or !std.meta.eql(
            artifact.preprocessed_root,
            registered.preprocessed_root,
        ) or !std.meta.eql(
            geometry.preprocessed_root,
            registered.preprocessed_root,
        )) return error.RegistryArtifactMismatch;
    }
};

pub const PaddingParityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    role_count: u8 = ROLE_COUNT,
    registry_identity_sha256: [32]u8,
    component_count: u16,
    preprocessed_column_count: u16,
    trace_log_size: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    target_component_log_sizes: [MAX_COMPONENT_COUNT]u8,
    preprocessed_column_log_sizes: [MAX_PREPROCESSED_COLUMN_COUNT]u8,
    proof_shape_identity_sha256: [32]u8,
    pcs_identity_sha256: [32]u8,
    output_abi_identity_sha256: [32]u8,
    padding_layout_identity_sha256: [32]u8,
    geometry_authority_identities: [ROLE_COUNT][32]u8,
    identity_sha256: [32]u8,

    pub fn derive(
        registry: *const RecursiveCircuitRegistryV1,
        geometries: [ROLE_COUNT]AuthenticatedGeometryV1,
    ) Error!PaddingParityV1 {
        return deriveCheckedCore(registry, geometries);
    }

    pub fn validate(
        self: *const PaddingParityV1,
        registry: *const RecursiveCircuitRegistryV1,
        geometries: *const [ROLE_COUNT]AuthenticatedGeometryV1,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or self.role_count != ROLE_COUNT or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(
                u8,
                &self.registry_identity_sha256,
                &registry.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &parityIdentity(self),
        )) return error.InvalidCircuitGeometry;
        const expected = try deriveCheckedCore(registry, geometries.*);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidCircuitGeometry;
    }
};

/// Exact source-shape diagnostic for the three production circuits. A native
/// V4 Ethereum proof is not itself the recursive leaf wrapper; each role must
/// provide a cold-derived universal-36 geometry before parity can be minted.
pub const CurrentShapeDiagnosticV1 = struct {
    universal_component_count: u16 = 36,
    ethereum_incremental_leaf_wrapper_geometry_authenticated: bool = false,
    canonical_empty_field_geometry_authenticated: bool = false,
    common_fold_field_geometry_authenticated: bool = false,
    parity_authority_available: bool = false,
    first_gap: GapV1 = .missing_ethereum_incremental_leaf_wrapper_geometry,
};

pub const GapV1 = enum(u8) {
    missing_ethereum_incremental_leaf_wrapper_geometry = 1,
    missing_canonical_empty_field_geometry = 2,
    missing_common_fold_field_geometry = 3,
    component_count_mismatch = 4,
};

pub fn currentShapeDiagnostic() CurrentShapeDiagnosticV1 {
    return .{};
}

/// Test-only attacker model: recompute the projection seal after mutating its
/// visible fields.  Replay must still reject against the immutable registry
/// and independently authenticated geometries.
pub const testing = if (builtin.is_test) struct {
    pub fn resealParity(
        value: PaddingParityV1,
    ) PaddingParityV1 {
        var result = value;
        result.identity_sha256 = parityIdentity(&result);
        return result;
    }
} else struct {};

fn deriveCheckedCore(
    registry: *const RecursiveCircuitRegistryV1,
    geometries: [ROLE_COUNT]AuthenticatedGeometryV1,
) Error!PaddingParityV1 {
    try registry.validate();
    for (&geometries, 0..) |*geometry, ordinal| {
        try geometry.validate();
        if (@intFromEnum(geometry.role) != ordinal)
            return error.DuplicateCircuitRole;
        const registered = try registry.entry(geometry.role);
        if (!std.mem.eql(
            u8,
            &registered.geometry_authority_identity_sha256,
            &geometry.authority_identity_sha256,
        ) or !std.meta.eql(
            registered.preprocessed_root,
            geometry.preprocessed_root,
        )) return error.CircuitNotRegistered;
    }

    const first = &geometries[0];
    var target = [_]u8{0} ** MAX_COMPONENT_COUNT;
    for (0..first.component_count) |component_index| {
        for (geometries) |geometry| {
            if (geometry.component_count != first.component_count)
                return error.PaddingComponentCountMismatch;
            target[component_index] = @max(
                target[component_index],
                geometry.active_component_log_sizes[component_index],
            );
        }
    }
    for (geometries) |geometry| {
        if (geometry.component_count != first.component_count)
            return error.PaddingComponentCountMismatch;
        if (!std.mem.eql(
            u8,
            geometry.padded_component_log_sizes[0..first.component_count],
            target[0..first.component_count],
        )) return error.PaddingComponentTargetMismatch;
        if (!std.mem.eql(
            u8,
            &geometry.padding_layout_identity_sha256,
            &first.padding_layout_identity_sha256,
        )) return error.PaddingLayoutMismatch;
        if (geometry.trace_log_size != first.trace_log_size)
            return error.TraceLogSizeMismatch;
        if (!std.meta.eql(geometry.pcs, first.pcs))
            return error.PcsConfigMismatch;
        if (!std.meta.eql(geometry.output_abi, first.output_abi))
            return error.InvalidOutputAbi;
        if (geometry.preprocessed_column_count !=
            first.preprocessed_column_count or !std.mem.eql(
            u8,
            geometry.preprocessed_column_log_sizes[0..geometry.preprocessed_column_count],
            first.preprocessed_column_log_sizes[0..first.preprocessed_column_count],
        )) return error.PreprocessedColumnLayoutMismatch;
        if (!std.meta.eql(geometry.proof_shape, first.proof_shape))
            return error.FixedProofWireShapeMismatch;
    }
    var result = PaddingParityV1{
        .registry_identity_sha256 = registry.identity_sha256,
        .component_count = first.component_count,
        .preprocessed_column_count = first.preprocessed_column_count,
        .trace_log_size = first.trace_log_size,
        .target_component_log_sizes = target,
        .preprocessed_column_log_sizes = first.preprocessed_column_log_sizes,
        .proof_shape_identity_sha256 = first.proof_shape.identity_sha256,
        .pcs_identity_sha256 = first.pcs.identity_sha256,
        .output_abi_identity_sha256 = first.output_abi.identity_sha256,
        .padding_layout_identity_sha256 = first.padding_layout_identity_sha256,
        .geometry_authority_identities = .{
            geometries[0].authority_identity_sha256,
            geometries[1].authority_identity_sha256,
            geometries[2].authority_identity_sha256,
        },
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = parityIdentity(&result);
    return result;
}

pub fn roleForArtifact(
    artifact: *const artifact_mod.RecursiveNodeArtifactV1,
) Error!CircuitRoleV1 {
    try artifact.validate();
    return switch (artifact.stage_kind) {
        .leaf_wrapper => switch (artifact.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.RegistryArtifactMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

pub fn roleForArtifactV2(
    artifact: *const artifact_v2_mod.RecursiveNodeArtifactV2,
) Error!CircuitRoleV1 {
    try artifact.validate();
    return switch (artifact.stage_kind) {
        .leaf_wrapper => switch (artifact.node_kind) {
            .real => .ethereum_incremental_leaf_wrapper_v4,
            .empty => .canonical_empty_field_v2,
            .mixed => error.RegistryArtifactMismatch,
        },
        .fold, .root => .common_fold_field_v2,
    };
}

fn pcsIdentity(value: *const PcsConfigV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PCS_IDENTITY_DOMAIN);
    inline for (.{
        value.interaction_pow_bits,
        value.pcs_pow_bits,
        value.fri_log_blowup_factor,
        value.fri_query_count,
        value.fri_fold_step,
        value.fri_log_last_layer_degree_bound,
        value.lifting_log_size,
    }) |field| hashInt(&hash, u32, field);
    return hash.finalResult();
}

fn outputAbiIdentity(value: *const OutputAbiV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(OUTPUT_ABI_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.statement_word_count);
    hashInt(&hash, u32, value.digest_word_count);
    hashInt(&hash, u32, value.encoded_byte_count);
    hash.update(&value.node_public_abi_sha256);
    return hash.finalResult();
}

fn geometryIdentity(value: *const AuthenticatedGeometryV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(GEOMETRY_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.role));
    hashInt(&hash, u8, @intFromBool(value.authenticated_padding));
    hashInt(&hash, u16, value.component_count);
    hashInt(&hash, u16, value.preprocessed_column_count);
    hashInt(&hash, u8, value.trace_log_size);
    hash.update(&value.reserved);
    hash.update(&value.active_component_log_sizes);
    hash.update(&value.padded_component_log_sizes);
    hash.update(&value.preprocessed_column_log_sizes);
    hash.update(&value.circuit_identity_sha256);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.profile_identity_sha256);
    hash.update(&value.padding_layout_identity_sha256);
    for (value.preprocessed_root) |word| hashInt(&hash, u32, word);
    hash.update(&value.pcs.identity_sha256);
    hash.update(&value.output_abi.identity_sha256);
    hash.update(&value.proof_shape.identity_sha256);
    return hash.finalResult();
}

fn registryEntryIdentity(value: *const RegistryEntryV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(REGISTRY_ENTRY_DOMAIN);
    hashInt(&hash, u8, @intFromEnum(value.role));
    inline for (.{
        value.circuit_identity_sha256,
        value.program_identity_sha256,
        value.profile_identity_sha256,
        value.pcs_identity_sha256,
        value.padding_layout_identity_sha256,
        value.node_public_abi_sha256,
        value.geometry_authority_identity_sha256,
    }) |identity| hash.update(&identity);
    for (value.preprocessed_root) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn registryIdentity(value: *const RecursiveCircuitRegistryV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(REGISTRY_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, value.entry_count);
    for (value.entries) |entry| hash.update(&entry.identity_sha256);
    return hash.finalResult();
}

fn parityIdentity(value: *const PaddingParityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PARITY_IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, value.role_count);
    hash.update(&value.registry_identity_sha256);
    hashInt(&hash, u16, value.component_count);
    hashInt(&hash, u16, value.preprocessed_column_count);
    hashInt(&hash, u8, value.trace_log_size);
    hash.update(&value.reserved);
    hash.update(&value.target_component_log_sizes);
    hash.update(&value.preprocessed_column_log_sizes);
    hash.update(&value.proof_shape_identity_sha256);
    hash.update(&value.pcs_identity_sha256);
    hash.update(&value.output_abi_identity_sha256);
    hash.update(&value.padding_layout_identity_sha256);
    for (value.geometry_authority_identities) |identity| hash.update(&identity);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn allWordsZero(words: [artifact_mod.DIGEST_WORD_COUNT]u32) bool {
    var aggregate: u32 = 0;
    for (words) |word| aggregate |= word;
    return aggregate == 0;
}

comptime {
    if (SCHEMA_VERSION != 4 or ROLE_COUNT != 3 or
        MAX_COMPONENT_COUNT < 36 or
        MAX_PREPROCESSED_COLUMN_COUNT != 1024 or
        PRODUCTION_ACTIVATION)
    {
        @compileError("recursive circuit registry V1 constants drifted");
    }
}
