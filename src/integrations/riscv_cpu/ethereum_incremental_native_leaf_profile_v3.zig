//! Typed statement/profile authority for one incremental-memory native leaf.
//!
//! The authority is minted only after STWIMT03 has been coldly reconstructed
//! against its SegmentV2 public wire and role authority.  It then replays the
//! transition into the frontend V3 boundary witness, derives exactly one
//! appended bridge component, and binds the authenticated physical-V2 base
//! lookup layout.  No caller supplies a row count, placement, role bit, tree
//! width, PCS choice, or transcript identity.
//!
//! This value is pointer-free so a cold verifier may retain it beside an
//! actual PCS capture.  It never contains (or substitutes for) a fresh
//! verifier capability.  Proof orchestration and production activation remain
//! deliberately outside this module.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_v3 = @import("ethereum_incremental_boundary_artifact_v3.zig");
const boundary_v3 = @import("ethereum_incremental_boundary_authority_v3.zig");
const proof_security_mod =
    @import("recursive_temporal_proof_security_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const statement = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const public_data_v2 = frontend.air.public_data_v2;
const lookup_physical = frontend.air.lookup_physical_manifest_v2;
const transition_v1 =
    frontend.air.memory_commitment.incremental_transition_v1;
const commitment_v3 = frontend.prover_mod.incremental_commitment_witness_v3;
const bridge_external = frontend.prover_mod.incremental_bridge_external_v3;
const proof_ingress = frontend.recursion.proof_ingress;
const recursion_protocol = frontend.recursion.protocol;

pub const RetirementSupplementV2 = proof_ingress.RetirementSupplementV2;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVE = false;
pub const PROOF_ADMISSIBLE = false;
pub const FRESH_VERIFICATION_AVAILABLE = false;
pub const SCHEMA = "stwo.ethereum.incremental-native-leaf-profile.v3";

pub const PRE_TREE0_DOMAIN_WORDS = [4]u32{
    0x5749_5453, // STIW
    0x3350_4c4e, // NLP3
    FORMAT_VERSION,
    SCHEMA_VERSION,
};
pub const POST_TREE1_DOMAIN_WORDS = [4]u32{
    0x5749_5453, // STIW
    0x3347_5242, // BRG3
    FORMAT_VERSION,
    1,
};

const AUTHORITY_ID_DOMAIN =
    "stwo.ethereum.incremental-native-leaf-profile.v3\x00";
const BASE_GEOMETRY_ID_DOMAIN =
    "stwo.ethereum.incremental-native-leaf-base-geometry.v3\x00";
const PCS_ID_DOMAIN =
    "stwo.ethereum.incremental-native-leaf-pcs.v3\x00";
const PROTOCOL_ID_DOMAIN =
    "stwo.ethereum.incremental-native-leaf-protocol.v3\x00";
const VALIDATION_MAX_PROOF_BYTES: usize = 1;

pub const PcsAuthorityV3 = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    query_count: u32,
    fold_step: u32,
    log_last_layer_degree_bound: u32,
    lifting_mode: u32,
    configured_security_bits: u32,
    identity_sha256: [32]u8,

    pub fn canonical() PcsAuthorityV3 {
        const pcs_config = recursion_protocol.PCS_CONFIG;
        var result = PcsAuthorityV3{
            .pow_bits = pcs_config.pow_bits,
            .log_blowup_factor = pcs_config.fri_config.log_blowup_factor,
            .query_count = @intCast(pcs_config.fri_config.n_queries),
            .fold_step = pcs_config.fri_config.fold_step,
            .log_last_layer_degree_bound = pcs_config.fri_config.log_last_layer_degree_bound,
            .lifting_mode = recursion_protocol.PCS_LIFTING_MODE_NONE,
            .configured_security_bits = pcs_config.securityBits(),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = pcsIdentity(&result);
        return result;
    }

    pub fn validate(self: *const PcsAuthorityV3) !void {
        if (!std.meta.eql(self.*, canonical()))
            return error.InvalidIncrementalNativeLeafPcs;
    }

    pub fn config(self: *const PcsAuthorityV3) !stwo_core.pcs.PcsConfig {
        try self.validate();
        return recursion_protocol.PCS_CONFIG;
    }
};

/// Exact q193 Poseidon2-M31 protocol authority.  `profile_words` is the full
/// field-level profile preimage; none of the SHA identities can replace it.
pub const ProtocolAuthorityV3 = struct {
    profile_words: [recursion_protocol.PROFILE_WORD_COUNT]u32,
    protocol_id: recursion_protocol.Digest,
    proof_security_identity_sha256: [32]u8,
    pcs: PcsAuthorityV3,
    identity_sha256: [32]u8,

    pub fn canonical() ProtocolAuthorityV3 {
        const profile = recursion_protocol.Profile{};
        const security = proof_security_mod.ProofSecurityV1
            .segmentV2Poseidon2();
        var result = ProtocolAuthorityV3{
            .profile_words = profile.words(),
            .protocol_id = recursion_protocol.protocolId(),
            .proof_security_identity_sha256 = security.identity,
            .pcs = PcsAuthorityV3.canonical(),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = protocolIdentity(&result);
        return result;
    }

    pub fn validate(self: *const ProtocolAuthorityV3) !void {
        try (recursion_protocol.Profile{}).validate();
        const security = proof_security_mod.ProofSecurityV1
            .segmentV2Poseidon2();
        try security.validate();
        try self.pcs.validate();
        if (!std.meta.eql(self.*, canonical()))
            return error.InvalidIncrementalNativeLeafProtocol;
    }
};

/// Compact projection of the exact base statement.  The complete statement
/// remains a required input to every validator: identities alone never admit
/// geometry.  The physical lookup activation is retained value-for-value so
/// Tree 2 is sized from the selected V2 columns, not compatibility widths.
pub const BaseGeometryV3 = struct {
    component_count: u32,
    infrastructure_count: u32,
    compatibility_tree_columns: [4]u32,
    physical_tree_columns: [4]u32,
    maximum_column_log_size: u32,
    statement_authority_id: public_data_v2.Digest,
    lookup_activation: lookup_physical.AuthenticatedStatement,
    identity_sha256: [32]u8,

    pub fn derive(
        base: *const statement_v2.RiscVStatementV2,
        pcs: PcsAuthorityV3,
    ) !BaseGeometryV3 {
        const config = try pcs.config();
        const shape = try proof_ingress.preflightShapeV2ForVerifierConfig(
            base,
            config,
            VALIDATION_MAX_PROOF_BYTES,
        );
        return deriveFromValidatedShape(
            base,
            shape.tree_columns,
            shape.max_column_log_size,
        );
    }

    /// Joined extensions authenticate their heterogeneous retirement rows
    /// before deriving the unchanged base-tree geometry. This sibling cannot
    /// be reached with a digest or row count alone: the exact memory relation
    /// total is revalidated by proof ingress first.
    pub fn deriveWithRetirementSupplementV2(
        base: *const statement_v2.RiscVStatementV2,
        pcs: PcsAuthorityV3,
        supplement: RetirementSupplementV2,
    ) !BaseGeometryV3 {
        const config = try pcs.config();
        const shape = try proof_ingress
            .preflightShapeV2WithRetirementSupplementV2ForVerifierConfig(
            base,
            supplement,
            config,
            VALIDATION_MAX_PROOF_BYTES,
        );
        return deriveFromValidatedShape(
            base,
            shape.tree_columns,
            shape.max_column_log_size,
        );
    }

    fn deriveFromValidatedShape(
        base: *const statement_v2.RiscVStatementV2,
        tree_columns: [4]u32,
        maximum_column_log_size: u32,
    ) !BaseGeometryV3 {
        const manifest = lookup_physical.Manifest.native();
        try manifest.validate();
        const activation = try lookup_physical.AuthenticatedStatement.init(
            &base.core,
            &manifest,
        );
        const physical_interaction = try activation.totalInteractionColumns(
            &base.core,
            &manifest,
        );
        var result = BaseGeometryV3{
            .component_count = base.core.n_components,
            .infrastructure_count = base.core.n_infra,
            .compatibility_tree_columns = tree_columns,
            .physical_tree_columns = .{
                base.core.nPreprocessedColumns(),
                base.core.nMainColumns(),
                std.math.cast(u32, physical_interaction) orelse
                    return error.IncrementalNativeLeafGeometryOverflow,
                tree_columns[3],
            },
            .maximum_column_log_size = maximum_column_log_size,
            .statement_authority_id = base.authority_id,
            .lookup_activation = activation,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = baseGeometryIdentity(&result, &base.core);
        return result;
    }

    pub fn validateAgainst(
        self: *const BaseGeometryV3,
        base: *const statement_v2.RiscVStatementV2,
        pcs: PcsAuthorityV3,
    ) !void {
        const expected = try derive(base, pcs);
        if (!std.meta.eql(self.*, expected))
            return error.IncrementalNativeLeafBaseGeometryMismatch;
    }

    pub fn validateAgainstWithRetirementSupplementV2(
        self: *const BaseGeometryV3,
        base: *const statement_v2.RiscVStatementV2,
        pcs: PcsAuthorityV3,
        supplement: RetirementSupplementV2,
    ) !void {
        const expected = try deriveWithRetirementSupplementV2(
            base,
            pcs,
            supplement,
        );
        if (!std.meta.eql(self.*, expected))
            return error.IncrementalNativeLeafBaseGeometryMismatch;
    }
};

pub const AuthorityV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_active: bool = PRODUCTION_ACTIVE,
    proof_admissible: bool = PROOF_ADMISSIBLE,
    fresh_verification_available: bool = FRESH_VERIFICATION_AVAILABLE,
    reserved: u8 = 0,
    statement_family: boundary_v3.StatementFamilyV3 = .segment_full_state_v3,
    boundary_policy: boundary_v3.BoundaryPolicyV3 =
        .full_state_split_memory_multiplicity,
    coordinate: boundary_v3.CoordinateV3,
    segment_public_wire_id: public_data_v2.Digest,
    continuation_roots: boundary_v3.FullStateRootsV3,
    boundary_artifact_content_sha256: [32]u8,
    base_geometry: BaseGeometryV3,
    bridge_geometry: bridge_external.GeometryV3,
    protocol: ProtocolAuthorityV3,
    identity_sha256: [32]u8,

    /// Revalidate all pointer-free fields against the complete typed base
    /// statement.  This deliberately cannot re-admit STWIMT03; callers needing
    /// artifact custody must use `validateAgainstInputs`.
    pub fn validateAgainstStatement(
        self: *const AuthorityV3,
        base: *const statement_v2.RiscVStatementV2,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_active or self.proof_admissible or
            self.fresh_verification_available or self.reserved != 0 or
            self.statement_family != .segment_full_state_v3 or
            self.boundary_policy != .full_state_split_memory_multiplicity or
            self.coordinate.segment_count == 0 or
            self.coordinate.segment_index >= self.coordinate.segment_count or
            self.continuation_roots.entry >= m31.Modulus or
            self.continuation_roots.exit >= m31.Modulus or
            allZero(self.boundary_artifact_content_sha256))
        {
            return error.InvalidIncrementalNativeLeafAuthority;
        }
        try requireFieldDigest(self.segment_public_wire_id);
        try self.protocol.validate();
        try self.base_geometry.validateAgainst(base, self.protocol.pcs);
        try self.bridge_geometry.validate(
            &base.core,
            self.base_geometry.physical_tree_columns[2],
        );
        const expected_preprocessed = std.math.add(
            u32,
            self.base_geometry.physical_tree_columns[0],
            @as(u32, @intCast(bridge_external.PREPROCESSED_COLUMNS)),
        ) catch return error.IncrementalNativeLeafGeometryOverflow;
        const expected_main = std.math.add(
            u32,
            self.base_geometry.physical_tree_columns[1],
            @as(u32, @intCast(bridge_external.MAIN_COLUMNS)),
        ) catch return error.IncrementalNativeLeafGeometryOverflow;
        const expected_interaction = std.math.add(
            u32,
            self.base_geometry.physical_tree_columns[2],
            @as(u32, @intCast(bridge_external.INTERACTION_COLUMNS)),
        ) catch return error.IncrementalNativeLeafGeometryOverflow;
        if (self.bridge_geometry.total_preprocessed_columns !=
            expected_preprocessed or
            self.bridge_geometry.total_main_columns !=
                expected_main or
            self.bridge_geometry.total_interaction_columns !=
                expected_interaction or
            !std.meta.eql(base.public_data.wireId(), self.segment_public_wire_id) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &computeAuthorityIdentity(self),
            ))
        {
            return error.InvalidIncrementalNativeLeafAuthority;
        }
    }

    /// Remint from every cold authority and compare the complete value.  This
    /// is the only readmission path for a retained profile.
    pub fn validateAgainstInputs(
        self: *const AuthorityV3,
        allocator: std.mem.Allocator,
        artifact: *const artifact_v3.OwnedArtifactV3,
        segment_public_wire: *const public_data_v2.PublicDataV2,
        public_authority: boundary_v3.SegmentPublicAuthorityV3,
        base_statement: *const statement_v2.RiscVStatementV2,
        limits: artifact_v3.Limits,
    ) !void {
        const expected = try mint(
            allocator,
            artifact,
            segment_public_wire,
            public_authority,
            base_statement,
            limits,
        );
        if (!std.meta.eql(self.*, expected))
            return error.IncrementalNativeLeafInputMismatch;
    }

    /// Exact pre-Tree-0 order:
    /// q193 PCS, canonical V2 public wire, authenticated physical lookup, then
    /// every profile field.  SHA identities are included as typed u16 limbs;
    /// validators still require the underlying fields and statement.
    pub fn mixPreTree0(
        self: *const AuthorityV3,
        base: *const statement_v2.RiscVStatementV2,
        channel: anytype,
    ) !void {
        try self.validateAgainstStatement(base);
        (try self.protocol.pcs.config()).mixInto(channel);
        try statement_v2.mixIntoNativeTranscript(&base.public_data, channel);
        self.base_geometry.lookup_activation.mixInto(channel);
        channel.mixU32s(&PRE_TREE0_DOMAIN_WORDS);
        channel.mixU32s(&.{
            self.format_version,
            self.schema_version,
            @intFromEnum(self.statement_family),
            @intFromEnum(self.boundary_policy),
            self.coordinate.segment_index,
            self.coordinate.segment_count,
            self.continuation_roots.entry,
            self.continuation_roots.exit,
            @intFromBool(self.production_active),
            @intFromBool(self.proof_admissible),
            @intFromBool(self.fresh_verification_available),
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
        self.bridge_geometry.mixFieldAuthority(channel);
    }

    /// Preserve the base main-claim/shard ordering, then append exactly one
    /// bridge descriptor before the shared interaction challenge is drawn.
    pub fn mixPostTree1(
        self: *const AuthorityV3,
        base: *const statement_v2.RiscVStatementV2,
        channel: anytype,
    ) !void {
        try self.validateAgainstStatement(base);
        const main_claim = base.core.canonicalMainClaim();
        main_claim.mixInto(channel);
        base.core.mixShardManifest(channel);
        channel.mixU32s(&POST_TREE1_DOMAIN_WORDS);
        self.bridge_geometry.mixFieldAuthority(channel);
    }

    pub fn totalTreeColumns(self: *const AuthorityV3) [4]u32 {
        return .{
            self.bridge_geometry.total_preprocessed_columns,
            self.bridge_geometry.total_main_columns,
            self.bridge_geometry.total_interaction_columns,
            self.base_geometry.physical_tree_columns[3],
        };
    }

    pub fn maximumColumnLogSize(self: *const AuthorityV3) u32 {
        return @max(
            self.base_geometry.maximum_column_log_size,
            self.bridge_geometry.log_size,
        );
    }
};

pub fn mint(
    allocator: std.mem.Allocator,
    artifact: *const artifact_v3.OwnedArtifactV3,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v3.SegmentPublicAuthorityV3,
    base_statement: *const statement_v2.RiscVStatementV2,
    limits: artifact_v3.Limits,
) !AuthorityV3 {
    var cold = try artifact_v3.coldReconstruct(
        allocator,
        artifact,
        segment_public_wire,
        public_authority,
        limits,
    );
    defer cold.deinit();
    try requireSamePublicWire(segment_public_wire, &base_statement.public_data);

    const protocol = ProtocolAuthorityV3.canonical();
    const base_geometry = try BaseGeometryV3.derive(
        base_statement,
        protocol.pcs,
    );
    var witness = try deriveBoundaryWitness(
        allocator,
        artifact,
        public_authority,
        &cold,
    );
    defer witness.deinit();
    const bridge_rows = witness.bridgeRows();
    const n_rows = std.math.cast(u32, bridge_rows.len) orelse
        return error.IncrementalNativeLeafGeometryOverflow;
    const bridge_geometry = try bridge_external.GeometryV3.canonical(
        &base_statement.core,
        n_rows,
        base_geometry.physical_tree_columns[2],
    );
    var result = AuthorityV3{
        .coordinate = cold.coordinate,
        .segment_public_wire_id = cold.segment_public_wire_id,
        .continuation_roots = artifact.continuation_roots,
        .boundary_artifact_content_sha256 = cold.artifact_content_sha256,
        .base_geometry = base_geometry,
        .bridge_geometry = bridge_geometry,
        .protocol = protocol,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = computeAuthorityIdentity(&result);
    try result.validateAgainstStatement(base_statement);
    return result;
}

fn deriveBoundaryWitness(
    allocator: std.mem.Allocator,
    artifact: *const artifact_v3.OwnedArtifactV3,
    public_authority: boundary_v3.SegmentPublicAuthorityV3,
    cold: *const artifact_v3.ColdReconstructionV3,
) !commitment_v3.BoundaryWitnessV3 {
    const touched_source = artifact.transition_v2.authority.touched_words;
    const frontier_source = artifact.transition_v2.authority.frontier_nodes;
    if (cold.transitions.len != touched_source.len)
        return error.IncrementalNativeLeafInventoryMismatch;

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
        return error.IncrementalNativeLeafGeometryOverflow;
    const rows = try allocator.alloc(boundary_v3.BoundaryRowContractV3, row_count);
    defer allocator.free(rows);
    try boundary_v3.writeBoundaryRows(public_authority, cold.transitions, rows);
    const policy = try allocator.alloc(commitment_v3.RowPolicyV3, cold.transitions.len);
    defer allocator.free(policy);
    for (policy, 0..) |*destination, index| destination.* = .{
        .entry_clock = rows[2 * index].clock,
        .entry_memory = mapMultiplicity(rows[2 * index].memory_multiplicity),
        .exit_memory = mapMultiplicity(rows[2 * index + 1].memory_multiplicity),
    };
    return commitment_v3.buildBoundary(
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

fn mapMultiplicity(
    value: boundary_v3.MemoryMultiplicityV3,
) commitment_v3.MemoryMultiplicityV3 {
    return switch (value) {
        .entry => .entry,
        .none => .none,
        .exit => .exit,
    };
}

fn requireSamePublicWire(
    left: *const public_data_v2.PublicDataV2,
    right: *const public_data_v2.PublicDataV2,
) !void {
    try left.validate();
    try right.validate();
    if (!std.meta.eql(left.wireId(), right.wireId()) or
        left.words().len != right.words().len or
        !m31SlicesEqual(left.words(), right.words()))
    {
        return error.IncrementalNativeLeafPublicWireMismatch;
    }
}

fn m31SlicesEqual(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |actual, expected|
        if (!actual.eql(expected)) return false;
    return true;
}

fn baseGeometryIdentity(
    value: *const BaseGeometryV3,
    core: *const statement.RiscVStatement,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(BASE_GEOMETRY_ID_DOMAIN);
    hashInt(&hash, u32, value.component_count);
    hashInt(&hash, u32, value.infrastructure_count);
    for (value.compatibility_tree_columns) |field| hashInt(&hash, u32, field);
    for (value.physical_tree_columns) |field| hashInt(&hash, u32, field);
    hashInt(&hash, u32, value.maximum_column_log_size);
    hashFieldDigest(&hash, value.statement_authority_id);
    hash.update(&value.lookup_activation.manifest_identity);
    hash.update(&value.lookup_activation.statement_identity);
    hash.update(&value.lookup_activation.activation_identity);
    hashInt(&hash, u32, value.lookup_activation.component_count);
    hashInt(&hash, u32, value.lookup_activation.opcode_main_columns);
    hashInt(&hash, u32, value.lookup_activation.opcode_interaction_columns);
    hashInt(&hash, u32, value.lookup_activation.detailed_claim_count);
    for (core.component_descs[0..core.n_components]) |descriptor| {
        hashInt(&hash, u32, @intFromEnum(descriptor.family));
        hashInt(&hash, u32, descriptor.log_size);
        hashInt(&hash, u32, descriptor.n_rows);
        hashInt(&hash, u32, descriptor.n_columns);
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        hashInt(&hash, u32, @intFromEnum(descriptor.kind));
        hashInt(&hash, u32, descriptor.log_size);
        hashInt(&hash, u32, descriptor.n_rows);
        hashInt(&hash, u32, descriptor.n_columns);
    }
    return hash.finalResult();
}

fn pcsIdentity(value: *const PcsAuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PCS_ID_DOMAIN);
    inline for (.{
        value.pow_bits,
        value.log_blowup_factor,
        value.query_count,
        value.fold_step,
        value.log_last_layer_degree_bound,
        value.lifting_mode,
        value.configured_security_bits,
    }) |field| hashInt(&hash, u32, field);
    return hash.finalResult();
}

fn protocolIdentity(value: *const ProtocolAuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PROTOCOL_ID_DOMAIN);
    for (value.profile_words) |word| hashInt(&hash, u32, word);
    hashFieldDigest(&hash, value.protocol_id);
    hash.update(&value.proof_security_identity_sha256);
    hash.update(&value.pcs.identity_sha256);
    return hash.finalResult();
}

fn computeAuthorityIdentity(value: *const AuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_ID_DOMAIN);
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
    hash.update(&value.bridge_geometry.identity_sha256);
    hash.update(&value.protocol.identity_sha256);
    return hash.finalResult();
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
        return error.InvalidIncrementalNativeLeafAuthority;
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
    /// Mutation tests may reseal a pointer-free projection, but cold input
    /// readmission still has to remint the complete authority independently.
    pub fn authorityIdentity(value: *const AuthorityV3) [32]u8 {
        return computeAuthorityIdentity(value);
    }
};

comptime {
    if (PRODUCTION_ACTIVE or PROOF_ADMISSIBLE or
        FRESH_VERIFICATION_AVAILABLE or bridge_external.COMPONENT_COUNT != 1)
    {
        @compileError("incremental native leaf V3 profile activated or drifted");
    }
    if (recursion_protocol.INTERACTION_POW_BITS != 10 or
        recursion_protocol.PCS_POW_BITS != 16 or
        recursion_protocol.FRI_QUERY_COUNT != 193 or
        recursion_protocol.FRI_FOLD_STEP != 4)
    {
        @compileError("incremental native leaf V3 q193 protocol drifted");
    }
    _ = QM31;
}
