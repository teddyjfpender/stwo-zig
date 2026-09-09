//! Typed authority for one full Ethereum + incremental-memory V4 leaf.
//!
//! This profile is minted only from a coldly reconstructed STWIMT04 boundary,
//! the exact authenticated SegmentV2 statement, and the canonical fourteen-
//! component Ethereum statement. It reuses the frozen q193/base-geometry
//! types from the native V3 profile, but never relabels its STWIMT03 policy.
//! The appended bridge is placed strictly after all Ethereum components.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const base_profile = @import("ethereum_incremental_native_leaf_profile_v3.zig");
pub const field_transcript = @import("ethereum_incremental_field_transcript_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const statement_v2 = frontend.air.statement_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const incremental_public = frontend.air.incremental_public_logup_v4;
const transition_v1 = frontend.air.memory_commitment.incremental_transition_v1;
const bridge = frontend.prover_mod.incremental_bridge_external_v3;
const witness_v3 = frontend.prover_mod.incremental_commitment_witness_v3;
const ethereum_wire = frontend.prover_mod.guest_precompile
    .ethereum_proof_artifact_wire;

pub const FixedProgramDescriptorV1 = frontend.air.program.fixed_table_v1.DescriptorV1;
pub const CircuitProfileV1 = frontend.prover_mod.ethereum_circuit_profile_v1.CircuitProfileV1;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 2;
pub const ClaimAdmissionV4 = enum(u16) {
    legacy_aggregate_v2 = SCHEMA_VERSION,
    selected_detailed_v3 = 3,
    field_authority_v4 = field_transcript.SCHEMA_VERSION,
    fixed_program_narrow_v5 = 5,
};
pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const FRESH_VERIFICATION_AVAILABLE = false;
pub const SCHEMA = "stwo.ethereum.incremental-full-leaf-profile.v4";

const IDENTITY_DOMAIN =
    "stwo.ethereum.incremental-full-leaf-profile.v4\x00";
const PRE_TREE0_DOMAIN_WORDS = [3]u32{
    0x5749_5453, // STIW
    0x3446_4c45, // ELF4
    FORMAT_VERSION,
};
const POST_TREE1_DOMAIN_WORDS = [3]u32{
    0x5749_5453, // STIW
    0x3446_5242, // BRF4
    FORMAT_VERSION,
};

pub const AuthorityV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_active: bool = PRODUCTION_ACTIVE,
    proof_admissible: bool = PROOF_ADMISSIBLE,
    fresh_verification_available: bool = FRESH_VERIFICATION_AVAILABLE,
    reserved: u8 = 0,
    statement_family: boundary_v4.StatementFamilyV4 = .segment_full_state_v4,
    boundary_policy: boundary_v4.BoundaryPolicyV4 =
        .full_state_split_public_input_exit,
    coordinate: boundary_v4.CoordinateV4,
    segment_public_wire_id: public_data_v2.Digest,
    continuation_roots: boundary_v4.FullStateRootsV4,
    boundary_artifact_content_sha256: [32]u8,
    base_geometry: base_profile.BaseGeometryV3,
    ethereum: ethereum_statement.Statement,
    ethereum_identity_sha256: [32]u8,
    public_boundary_identity_sha256: [32]u8,
    bridge_geometry: bridge.GeometryV3,
    protocol: base_profile.ProtocolAuthorityV3,
    identity_sha256: [32]u8,
    fixed_program: ?FixedProgramDescriptorV1 = null,

    pub fn circuitProfile(self: *const AuthorityV4) CircuitProfileV1 {
        return if (self.schema_version == 5) .fixed_program_narrow_v1 else .legacy_v4;
    }

    pub fn usesFieldTranscript(self: *const AuthorityV4) bool {
        return self.schema_version == 4 or self.schema_version == 5;
    }

    pub fn claimAdmission(self: *const AuthorityV4) !ClaimAdmissionV4 {
        return std.meta.intToEnum(ClaimAdmissionV4, self.schema_version) catch
            return error.InvalidIncrementalEthereumLeafAuthorityV4;
    }

    /// Schema 2 remains a legacy aggregate-only transcript. Schema 3 adds the
    /// selected physical base claims at one shared, pre-Tree-2 position.
    /// Schema 4 retains those claims and uses field-level profile frames.
    pub fn mixSelectedBaseClaims(
        self: *const AuthorityV4,
        allocator: std.mem.Allocator,
        channel: anytype,
        core: *const frontend.air.statement.RiscVStatement,
        manifest: *const frontend.air.lookup_physical_manifest_v2.Manifest,
        authenticated: *const frontend.air.lookup_physical_manifest_v2.AuthenticatedStatement,
        claim: *const frontend.air.statement.RiscVInteractionClaim,
    ) !void {
        switch (try self.claimAdmission()) {
            .legacy_aggregate_v2 => {},
            .selected_detailed_v3, .field_authority_v4, .fixed_program_narrow_v5 => {
                const selected = try frontend.prover_mod.guest_precompile
                    .ethereum_transcript.SelectedBaseClaimsV3.init(core, manifest, authenticated, claim);
                try selected.mix(allocator, channel);
            },
        }
    }

    /// The extension claim sequence must precede this single final-claims
    /// operation. Prover hooks, native verification and recursive replay share
    /// this boundary so detailed-base admission cannot drift from the bridge.
    pub fn mixFinalClaims(
        self: *const AuthorityV4,
        allocator: std.mem.Allocator,
        channel: anytype,
        core_statement: *const frontend.air.statement.RiscVStatement,
        manifest: *const frontend.air.lookup_physical_manifest_v2.Manifest,
        authenticated: *const frontend.air.lookup_physical_manifest_v2.AuthenticatedStatement,
        base_claim: *const frontend.air.statement.RiscVInteractionClaim,
        bridge_claim: stwo_core.fields.qm31.QM31,
    ) !void {
        try self.mixSelectedBaseClaims(allocator, channel, core_statement, manifest, authenticated, base_claim);
        bridge.mixClaim(channel, bridge_claim);
    }

    pub fn validateAgainstStatement(
        self: *const AuthorityV4,
        native: *const statement_v2.RiscVStatementV2,
        ethereum: *const ethereum_statement.Statement,
        role_aware_public: *const public_data.PublicData,
    ) !void {
        _ = try self.claimAdmission();
        if (self.circuitProfile() == .fixed_program_narrow_v1) {
            if (native.core.n_infra == 0) return error.InvalidIncrementalEthereumLeafAuthorityV4;
            const fixed = self.fixed_program orelse return error.EthereumFixedProgramAdmissionRequired;
            try fixed.validate();
            const metadata = try native.public_data.metadata();
            if (fixed.row_count != native.core.infra_descs[0].n_rows or metadata.program[0] != fixed.compatibility_root or !std.mem.allEqual(u32, metadata.program[1..], 0)) return error.EthereumFixedProgramAdmissionMismatch;
        } else if (self.fixed_program != null) return error.EthereumFixedProgramProfileMismatch;
        if (self.format_version != FORMAT_VERSION or
            self.production_active or self.proof_admissible or
            self.fresh_verification_available or self.reserved != 0 or
            self.statement_family != .segment_full_state_v4 or
            self.boundary_policy != .full_state_split_public_input_exit or
            self.coordinate.segment_count == 0 or
            self.coordinate.segment_index >= self.coordinate.segment_count or
            self.continuation_roots.entry >= m31.Modulus or
            self.continuation_roots.exit >= m31.Modulus or
            allZero(self.boundary_artifact_content_sha256))
        {
            return error.InvalidIncrementalEthereumLeafAuthorityV4;
        }
        try requireFieldDigest(self.segment_public_wire_id);
        try native.validate();
        try ethereum.validateV2WithCircuitProfileV1(native, self.circuitProfile());
        try incremental_public.validateSharedAuthority(
            &native.public_data,
            role_aware_public,
        );
        try self.protocol.validate();
        if (self.circuitProfile() == .legacy_v4) {
            try self.base_geometry.validateAgainstWithRetirementSupplementV2(native, self.protocol.pcs, retirementSupplement(ethereum));
        } else {
            const expected = try base_profile.BaseGeometryV3.deriveWithCircuitProfileV1(native, self.protocol.pcs, retirementSupplement(ethereum), self.circuitProfile());
            if (!std.meta.eql(expected, self.base_geometry)) return error.IncrementalNativeLeafBaseGeometryMismatch;
        }
        if (!std.meta.eql(native.public_data.wireId(), self.segment_public_wire_id) or
            !std.meta.eql(self.ethereum, ethereum.*) or
            !std.mem.eql(
                u8,
                &self.ethereum_identity_sha256,
                &try ethereumIdentity(ethereum),
            ) or !std.mem.eql(
            u8,
            &self.public_boundary_identity_sha256,
            &incremental_public.publicBoundaryIdentity(
                &native.public_data,
                role_aware_public,
            ),
        )) {
            return error.IncrementalEthereumLeafStatementMismatchV4;
        }
        var prefix = try prefixColumns(native, ethereum, &self.base_geometry, self.circuitProfile());
        if (self.fixed_program != null) prefix.preprocessed = try add(prefix.preprocessed, frontend.air.program.fixed_table_v1.COLUMN_COUNT);
        try self.bridge_geometry.validateAfterPrefix(prefix);
        if (!std.mem.eql(u8, &self.identity_sha256, &identity(self)))
            return error.InvalidIncrementalEthereumLeafAuthorityV4;
    }

    pub fn validateAgainstInputs(
        self: *const AuthorityV4,
        allocator: std.mem.Allocator,
        artifact: *const artifact_v4.OwnedArtifactV4,
        segment_public_wire: *const public_data_v2.PublicDataV2,
        public_authority: boundary_v4.SegmentPublicAuthorityV4,
        native: *const statement_v2.RiscVStatementV2,
        ethereum: *const ethereum_statement.Statement,
        limits: artifact_v4.Limits,
    ) !void {
        var expected = try mint(
            allocator,
            artifact,
            segment_public_wire,
            public_authority,
            native,
            ethereum,
            limits,
        );
        selectClaimAdmission(&expected, try self.claimAdmission());
        if (!std.meta.eql(self.*, expected))
            return error.IncrementalEthereumLeafInputMismatchV4;
    }

    pub fn validateAgainstInputsWithProgramV1(self: *const AuthorityV4, allocator: std.mem.Allocator, artifact: *const artifact_v4.OwnedArtifactV4, segment_public_wire: *const public_data_v2.PublicDataV2, public_authority: boundary_v4.SegmentPublicAuthorityV4, native: *const statement_v2.RiscVStatementV2, ethereum: *const ethereum_statement.Statement, limits: artifact_v4.Limits, program: *const @import("ethereum_fixed_program_admission_v1.zig").OwnedV1) !void {
        try program.validateDescriptor(self.fixed_program orelse return error.EthereumFixedProgramAdmissionRequired);
        var cold = try artifact_v4.coldReconstruct(allocator, artifact, segment_public_wire, public_authority, limits);
        defer cold.deinit();
        try requireSamePublicWire(segment_public_wire, &native.public_data);
        var boundary = try deriveBoundaryWitness(allocator, artifact, public_authority, &cold);
        defer boundary.deinit();
        const expected = try mintFromColdReconstructionWithFixedProgramV1(native, ethereum, public_authority, artifact, &cold, &boundary, program);
        if (!std.meta.eql(self.*, expected)) return error.IncrementalEthereumLeafInputMismatchV4;
    }

    pub fn pcsConfig(self: *const AuthorityV4) !stwo_core.pcs.PcsConfig {
        try self.protocol.validate();
        return self.protocol.pcs.config();
    }

    /// Exact order before Tree 0: q193 PCS, canonical V2 public statement,
    /// authenticated physical lookup, full V4 authority, Ethereum statement,
    /// role-aware IO identity, and relocated bridge geometry.
    pub fn mixPreTree0(
        self: *const AuthorityV4,
        native: *const statement_v2.RiscVStatementV2,
        role_aware_public: *const public_data.PublicData,
        channel: anytype,
    ) !void {
        try self.validateAgainstStatement(
            native,
            &self.ethereum,
            role_aware_public,
        );
        if (self.usesFieldTranscript())
            return field_transcript.mixPreTree0(self, native, role_aware_public, channel);
        (try self.protocol.pcs.config()).mixInto(channel);
        try statement_v2.mixIntoNativeTranscript(&native.public_data, channel);
        self.base_geometry.lookup_activation.mixInto(channel);
        channel.mixU32s(&.{ PRE_TREE0_DOMAIN_WORDS[0], PRE_TREE0_DOMAIN_WORDS[1], FORMAT_VERSION, self.schema_version });
        channel.mixU32s(&.{
            self.format_version,
            self.schema_version,
            @intFromEnum(self.statement_family),
            @intFromEnum(self.boundary_policy),
            self.coordinate.segment_index,
            self.coordinate.segment_count,
            self.continuation_roots.entry,
            self.continuation_roots.exit,
            self.base_geometry.component_count,
            self.base_geometry.infrastructure_count,
            self.base_geometry.maximum_column_log_size,
        });
        channel.mixU32s(&self.segment_public_wire_id);
        mixSha256(channel, self.boundary_artifact_content_sha256);
        channel.mixU32s(&self.base_geometry.compatibility_tree_columns);
        channel.mixU32s(&self.base_geometry.physical_tree_columns);
        channel.mixU32s(&self.base_geometry.statement_authority_id);
        mixSha256(channel, self.base_geometry.identity_sha256);
        channel.mixU32s(&self.protocol.profile_words);
        channel.mixU32s(&self.protocol.protocol_id);
        mixSha256(channel, self.protocol.proof_security_identity_sha256);
        channel.mixU32s(&.{
            self.protocol.pcs.pow_bits,
            self.protocol.pcs.log_blowup_factor,
            self.protocol.pcs.query_count,
            self.protocol.pcs.fold_step,
            self.protocol.pcs.log_last_layer_degree_bound,
            self.protocol.pcs.lifting_mode,
            self.protocol.pcs.configured_security_bits,
        });
        mixSha256(channel, self.protocol.pcs.identity_sha256);
        mixSha256(channel, self.protocol.identity_sha256);
        try self.ethereum.mixIntoV2WithCircuitProfileV1(native, channel, self.circuitProfile());
        mixSha256(channel, self.ethereum_identity_sha256);
        mixSha256(channel, self.public_boundary_identity_sha256);
        const completion = role_aware_public.completion orelse
            return error.MissingCompletion;
        channel.mixU32s(&.{
            @intFromEnum(completion.kind),
            completion.address,
            completion.value,
            completion.clock,
        });
        self.bridge_geometry.mixFieldAuthority(channel);
        mixSha256(channel, self.identity_sha256);
    }

    /// Base main/shards, all fourteen Ethereum descriptors, then one bridge
    /// descriptor before the shared interaction relation draw.
    pub fn mixPostTree1(
        self: *const AuthorityV4,
        native: *const statement_v2.RiscVStatementV2,
        role_aware_public: *const public_data.PublicData,
        channel: anytype,
    ) !void {
        try self.validateAgainstStatement(
            native,
            &self.ethereum,
            role_aware_public,
        );
        if (self.usesFieldTranscript())
            return field_transcript.mixPostTree1(self, native, channel);
        const main_claim = native.core.canonicalMainClaim();
        main_claim.mixInto(channel);
        native.core.mixShardManifest(channel);
        try self.ethereum.mixIntoV2WithCircuitProfileV1(native, channel, self.circuitProfile());
        channel.mixU32s(&.{ POST_TREE1_DOMAIN_WORDS[0], POST_TREE1_DOMAIN_WORDS[1], FORMAT_VERSION, self.schema_version });
        self.bridge_geometry.mixFieldAuthority(channel);
        mixSha256(channel, self.identity_sha256);
    }
};

pub fn mint(
    allocator: std.mem.Allocator,
    artifact: *const artifact_v4.OwnedArtifactV4,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    native: *const statement_v2.RiscVStatementV2,
    ethereum: *const ethereum_statement.Statement,
    limits: artifact_v4.Limits,
) !AuthorityV4 {
    var cold = try artifact_v4.coldReconstruct(
        allocator,
        artifact,
        segment_public_wire,
        public_authority,
        limits,
    );
    defer cold.deinit();
    try requireSamePublicWire(segment_public_wire, &native.public_data);
    try incremental_public.validateSharedAuthority(
        segment_public_wire,
        public_authority.public_data,
    );
    var boundary = try deriveBoundaryWitness(
        allocator,
        artifact,
        public_authority,
        &cold,
    );
    defer boundary.deinit();
    return mintFromColdReconstruction(
        native,
        ethereum,
        public_authority,
        artifact,
        &cold,
        &boundary,
    );
}

/// Process-local fast path for a producer that will move the same boundary
/// into `FullWitnessV3` immediately after profile minting. Cold transport and
/// the complete boundary witness remain mandatory; no digest-only overload
/// exists.
pub fn mintFromColdReconstruction(
    native: *const statement_v2.RiscVStatementV2,
    ethereum: *const ethereum_statement.Statement,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    artifact: *const artifact_v4.OwnedArtifactV4,
    cold: *const artifact_v4.ColdReconstructionV4,
    boundary: *const witness_v3.BoundaryWitnessV3,
) !AuthorityV4 {
    return mintFromColdReconstructionWithFixedDescriptor(native, ethereum, public_authority, artifact, cold, boundary, null);
}

pub fn mintFromColdReconstructionWithFixedProgramV1(
    native: *const statement_v2.RiscVStatementV2,
    ethereum: *const ethereum_statement.Statement,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    artifact: *const artifact_v4.OwnedArtifactV4,
    cold: *const artifact_v4.ColdReconstructionV4,
    boundary: *const witness_v3.BoundaryWitnessV3,
    program: *const @import("ethereum_fixed_program_admission_v1.zig").OwnedV1,
) !AuthorityV4 {
    try program.validateDescriptor(program.descriptor());
    return mintFromColdReconstructionWithFixedDescriptor(native, ethereum, public_authority, artifact, cold, boundary, program.descriptor());
}

fn mintFromColdReconstructionWithFixedDescriptor(
    native: *const statement_v2.RiscVStatementV2,
    ethereum: *const ethereum_statement.Statement,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    artifact: *const artifact_v4.OwnedArtifactV4,
    cold: *const artifact_v4.ColdReconstructionV4,
    boundary: *const witness_v3.BoundaryWitnessV3,
    fixed_program: ?FixedProgramDescriptorV1,
) !AuthorityV4 {
    try native.public_data.validate();
    try incremental_public.validateSharedAuthority(
        &native.public_data,
        public_authority.public_data,
    );
    const roots = boundary.roots();
    const expected_boundary_rows = std.math.mul(
        usize,
        cold.transitions.len,
        2,
    ) catch return error.IncrementalEthereumLeafGeometryOverflowV4;
    if (!std.meta.eql(native.public_data.wireId(), cold.segment_public_wire_id) or
        !std.meta.eql(cold.coordinate, artifact.coordinate) or
        !std.meta.eql(cold.segment_public_wire_id, artifact.segment_public_wire_id) or
        !std.mem.eql(
            u8,
            &cold.artifact_content_sha256,
            &artifact.content_sha256,
        ) or roots.entry != artifact.continuation_roots.entry or
        roots.exit != artifact.continuation_roots.exit or
        expected_boundary_rows != boundary.rows().len)
    {
        return error.IncrementalEthereumLeafInventoryMismatchV4;
    }
    const circuit_profile: CircuitProfileV1 = if (fixed_program != null) .fixed_program_narrow_v1 else .legacy_v4;
    try ethereum.validateV2WithCircuitProfileV1(native, circuit_profile);
    const protocol = base_profile.ProtocolAuthorityV3.canonical();
    const base_geometry = if (fixed_program != null)
        try base_profile.BaseGeometryV3.deriveWithCircuitProfileV1(native, protocol.pcs, retirementSupplement(ethereum), .fixed_program_narrow_v1)
    else
        try base_profile.BaseGeometryV3.deriveWithRetirementSupplementV2(native, protocol.pcs, retirementSupplement(ethereum));
    const n_rows = std.math.cast(u32, boundary.bridgeRows().len) orelse
        return error.IncrementalEthereumLeafGeometryOverflowV4;
    var prefix = try prefixColumns(native, ethereum, &base_geometry, circuit_profile);
    if (fixed_program != null) prefix.preprocessed = try add(prefix.preprocessed, frontend.air.program.fixed_table_v1.COLUMN_COUNT);
    const bridge_geometry = try bridge.GeometryV3.canonicalAfterPrefix(
        n_rows,
        prefix,
    );
    var result = AuthorityV4{
        .schema_version = if (fixed_program != null) 5 else SCHEMA_VERSION,
        .fixed_program = fixed_program,
        .coordinate = cold.coordinate,
        .segment_public_wire_id = cold.segment_public_wire_id,
        .continuation_roots = artifact.continuation_roots,
        .boundary_artifact_content_sha256 = cold.artifact_content_sha256,
        .base_geometry = base_geometry,
        .ethereum = ethereum.*,
        .ethereum_identity_sha256 = try ethereumIdentity(ethereum),
        .public_boundary_identity_sha256 = incremental_public
            .publicBoundaryIdentity(
            &native.public_data,
            public_authority.public_data,
        ),
        .bridge_geometry = bridge_geometry,
        .protocol = protocol,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = identity(&result);
    try result.validateAgainstStatement(
        native,
        ethereum,
        public_authority.public_data,
    );
    return result;
}

/// Explicit new-producer admission. Existing constructors retain schema 2;
/// decoding old bytes can never opt a legacy proof into the new transcript.
pub fn mintFromColdReconstructionWithAdmission(
    native: *const statement_v2.RiscVStatementV2,
    ethereum: *const ethereum_statement.Statement,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    artifact: *const artifact_v4.OwnedArtifactV4,
    cold: *const artifact_v4.ColdReconstructionV4,
    boundary: *const witness_v3.BoundaryWitnessV3,
    admission: ClaimAdmissionV4,
) !AuthorityV4 {
    if (admission == .fixed_program_narrow_v5) return error.EthereumFixedProgramAdmissionRequired;
    var result = try mintFromColdReconstruction(native, ethereum, public_authority, artifact, cold, boundary);
    selectClaimAdmission(&result, admission);
    try result.validateAgainstStatement(native, ethereum, public_authority.public_data);
    return result;
}

fn selectClaimAdmission(value: *AuthorityV4, admission: ClaimAdmissionV4) void {
    value.schema_version = @intFromEnum(admission);
    value.identity_sha256 = identity(value);
}

pub fn deriveBoundaryWitness(
    allocator: std.mem.Allocator,
    artifact: *const artifact_v4.OwnedArtifactV4,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    cold: *const artifact_v4.ColdReconstructionV4,
) !witness_v3.BoundaryWitnessV3 {
    const touched_source = artifact.transition_v2.authority.touched_words;
    const frontier_source = artifact.transition_v2.authority.frontier_nodes;
    if (cold.transitions.len != touched_source.len)
        return error.IncrementalEthereumLeafInventoryMismatchV4;
    const touched = try allocator.alloc(transition_v1.TouchedWord, touched_source.len);
    defer allocator.free(touched);
    for (touched, touched_source) |*destination, source| destination.* = .{
        .address = source.address,
        .old_word = source.old_word,
        .new_word = source.new_word,
        .final_clock = source.final_clock,
    };
    const frontier = try allocator.alloc(
        transition_v1.FrontierNode,
        frontier_source.len,
    );
    defer allocator.free(frontier);
    for (frontier, frontier_source) |*destination, source| destination.* = .{
        .depth = source.depth,
        .index = source.index,
        .value = source.value,
    };
    const row_count = std.math.mul(usize, cold.transitions.len, 2) catch
        return error.IncrementalEthereumLeafGeometryOverflowV4;
    const rows = try allocator.alloc(boundary_v4.BoundaryRowContractV4, row_count);
    defer allocator.free(rows);
    try boundary_v4.writeBoundaryRows(public_authority, cold.transitions, rows);
    const policy = try allocator.alloc(witness_v3.RowPolicyV3, cold.transitions.len);
    defer allocator.free(policy);
    for (policy, 0..) |*destination, index| destination.* = .{
        .entry_clock = rows[index * 2].clock,
        .entry_memory = mapMultiplicity(rows[index * 2].memory_multiplicity),
        .exit_memory = mapMultiplicity(rows[index * 2 + 1].memory_multiplicity),
    };
    return witness_v3.buildBoundary(
        allocator,
        touched,
        frontier,
        policy,
        .{
            .entry = artifact.continuation_roots.entry,
            .exit = artifact.continuation_roots.exit,
        },
    );
}

fn prefixColumns(
    native: *const statement_v2.RiscVStatementV2,
    ethereum: *const ethereum_statement.Statement,
    base: *const base_profile.BaseGeometryV3,
    circuit_profile: CircuitProfileV1,
) !bridge.PrefixColumnsV3 {
    try ethereum.validateV2WithCircuitProfileV1(native, circuit_profile);
    var result = bridge.PrefixColumnsV3{
        .preprocessed = base.physical_tree_columns[0],
        .main = base.physical_tree_columns[1],
        .interaction = base.physical_tree_columns[2],
    };
    for (ethereum.components) |descriptor| {
        result.preprocessed = try add(
            result.preprocessed,
            descriptor.preprocessed_columns,
        );
        result.main = try add(result.main, descriptor.main_columns);
        result.interaction = try add(
            result.interaction,
            descriptor.interaction_columns,
        );
    }
    try result.validate();
    return result;
}

fn ethereumIdentity(value: *const ethereum_statement.Statement) ![32]u8 {
    var encoded: [ethereum_wire.extension_encoded_size]u8 = undefined;
    var stream = std.io.fixedBufferStream(&encoded);
    try ethereum_wire.encodeExtension(stream.writer(), value);
    if (stream.pos != encoded.len)
        return error.InvalidIncrementalEthereumStatementEncodingV4;
    var result: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&encoded, &result, .{});
    return result;
}

fn identity(value: *const AuthorityV4) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_active));
    hashInt(&hash, u8, @intFromBool(value.proof_admissible));
    hashInt(&hash, u8, @intFromBool(value.fresh_verification_available));
    hashInt(&hash, u8, value.reserved);
    hashInt(&hash, u32, @intFromEnum(value.statement_family));
    hashInt(&hash, u32, @intFromEnum(value.boundary_policy));
    hashInt(&hash, u32, value.coordinate.segment_index);
    hashInt(&hash, u32, value.coordinate.segment_count);
    hashFieldDigest(&hash, value.segment_public_wire_id);
    hashInt(&hash, u32, value.continuation_roots.entry);
    hashInt(&hash, u32, value.continuation_roots.exit);
    hash.update(&value.boundary_artifact_content_sha256);
    hash.update(&value.base_geometry.identity_sha256);
    hash.update(&value.ethereum_identity_sha256);
    hash.update(&value.public_boundary_identity_sha256);
    hash.update(&value.bridge_geometry.identity_sha256);
    hash.update(&value.protocol.identity_sha256);
    if (value.fixed_program) |fixed| {
        const words = fixed.canonicalWords() catch unreachable;
        for (words) |word| hashInt(&hash, u32, word);
    }
    return hash.finalResult();
}

fn requireSamePublicWire(
    left: *const public_data_v2.PublicDataV2,
    right: *const public_data_v2.PublicDataV2,
) !void {
    try left.validate();
    try right.validate();
    if (!std.meta.eql(left.wireId(), right.wireId()) or
        left.words().len != right.words().len)
    {
        return error.IncrementalEthereumLeafPublicWireMismatchV4;
    }
    for (left.words(), right.words()) |actual, expected|
        if (!actual.eql(expected))
            return error.IncrementalEthereumLeafPublicWireMismatchV4;
}

fn mapMultiplicity(
    value: boundary_v4.MemoryMultiplicityV4,
) witness_v3.MemoryMultiplicityV3 {
    return switch (value) {
        .entry => .entry,
        .none => .none,
        .exit => .exit,
    };
}

fn add(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.IncrementalEthereumLeafGeometryOverflowV4;
}

fn retirementSupplement(
    ethereum: *const ethereum_statement.Statement,
) base_profile.RetirementSupplementV2 {
    if (ethereum.counts.external_retirements == 0) return .{
        .rows = 0,
        .extra_memory_terms = 0,
        .expected_memory_relation_terms = 0,
    };
    return .{
        .rows = ethereum.counts.external_retirements,
        .extra_memory_terms = ethereum.admission.extra_memory_terms,
        .expected_memory_relation_terms = ethereum.admission.memory_relation_terms,
    };
}

fn mixSha256(channel: anytype, value: [32]u8) void {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(
        u16,
        value[index * 2 ..][0..2],
        .little,
    );
    channel.mixU32s(&words);
}

fn hashFieldDigest(hash: *Sha256, value: public_data_v2.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn requireFieldDigest(value: public_data_v2.Digest) !void {
    for (value) |word| if (word >= m31.Modulus)
        return error.InvalidIncrementalEthereumLeafAuthorityV4;
}

fn allZero(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn authorityIdentity(value: *const AuthorityV4) [32]u8 {
        return identity(value);
    }
};

test "Ethereum full leaf claim admission versions have fixed identities" {
    // Identity-only fixture: no capability is minted from these placeholder
    // fields. The full proof test exercises validated profile admission.
    var value: AuthorityV4 = undefined;
    value.fixed_program = null;
    value.format_version = FORMAT_VERSION;
    value.schema_version = SCHEMA_VERSION;
    value.production_active = false;
    value.proof_admissible = false;
    value.fresh_verification_available = false;
    value.reserved = 0;
    value.statement_family = .segment_full_state_v4;
    value.boundary_policy = .full_state_split_public_input_exit;
    value.coordinate = .{ .segment_index = 0, .segment_count = 1 };
    value.segment_public_wire_id = .{0} ** 8;
    value.continuation_roots = .{ .entry = 0, .exit = 0 };
    value.boundary_artifact_content_sha256 = .{0} ** 32;
    value.base_geometry.identity_sha256 = .{0} ** 32;
    value.ethereum_identity_sha256 = .{0} ** 32;
    value.public_boundary_identity_sha256 = .{0} ** 32;
    value.bridge_geometry.identity_sha256 = .{0} ** 32;
    value.protocol.identity_sha256 = .{0} ** 32;
    try std.testing.expectEqual(ClaimAdmissionV4.legacy_aggregate_v2, try value.claimAdmission());
    try std.testing.expectEqualStrings(
        "48c887984963c589308ad73cf0b0672881808dd52d9a5ec6805cc194be63ea8c",
        &std.fmt.bytesToHex(identity(&value), .lower),
    );
    selectClaimAdmission(&value, .selected_detailed_v3);
    try std.testing.expectEqual(ClaimAdmissionV4.selected_detailed_v3, try value.claimAdmission());
    try std.testing.expectEqualStrings(
        "e5c3d73d05e840b48e5048a56af98cadbfcb3215ab344448c0bda208de0869ba",
        &std.fmt.bytesToHex(value.identity_sha256, .lower),
    );
    selectClaimAdmission(&value, .field_authority_v4);
    try std.testing.expectEqual(ClaimAdmissionV4.field_authority_v4, try value.claimAdmission());
    try std.testing.expectEqualStrings(
        "597f90f420ff5b1e3abc5ddafb6a24747a62315943dd7431e60072a582f2e839",
        &std.fmt.bytesToHex(value.identity_sha256, .lower),
    );
    value.schema_version = 6;
    try std.testing.expectError(error.InvalidIncrementalEthereumLeafAuthorityV4, value.claimAdmission());
}

comptime {
    if (PRODUCTION_ACTIVE or PROOF_ADMISSIBLE or
        FRESH_VERIFICATION_AVAILABLE or bridge.COMPONENT_COUNT != 1)
    {
        @compileError("incremental Ethereum full-leaf V4 activated or drifted");
    }
    if (frontend.recursion.protocol.FRI_QUERY_COUNT != 193)
        @compileError("incremental Ethereum full-leaf V4 q193 drifted");
    _ = M31;
}
