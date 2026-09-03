//! Cold-decodable postcard envelope for the nonproduction candidate leaf.
//!
//! SHA-256 fields protect transport framing only. Fresh STARK verification,
//! candidate component closure, and provider closure remain the sole proof
//! authorities and are deliberately absent from this decoder's verdict.

const std = @import("std");
const core = @import("stwo_core");
const pcs = core.pcs;
const qm31 = core.fields.qm31;
const verifier_types = core.verifier_types;
const postcard = @import("interop_postcard");

const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const base_types = @import("../types.zig");
const base_wire = @import("proof_artifact_wire.zig");
const statement_wire = @import("ethereum_segment_artifact_statement_wire.zig");
const native_artifact = @import("ethereum_segment_proof_artifact.zig");
const candidate_admission = @import("ethereum_candidate_leaf_admission_v1.zig");
const candidate_integration = @import("ethereum_candidate_leaf_integration_v1.zig");
const candidate_profile = @import("ethereum_candidate_leaf_profile_v1.zig");
const candidate_tree = @import("ethereum_candidate_leaf_tree_v1.zig");
const candidate_wire = @import("ethereum_candidate_leaf_artifact_wire_v1.zig");

pub const production_active = false;
pub const format_version: u16 = 1;
pub const magic = [8]u8{ 'S', 'T', 'W', 'G', 'C', 'L', 'F', '1' };
pub const header_size: usize = 40;
pub const identity_size: usize = 76;
pub const Limits = base_wire.Limits;

pub fn EncodeInput(comptime Engine: type) type {
    return struct {
        pcs_config: pcs.PcsConfig,
        security_identity_sha256: [32]u8,
        full_statement: *const statement_v2.RiscVStatementV2,
        projected_statement: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        global: *const global_v3.MetadataV3,
        profile: *const candidate_profile.Profile,
        base_claim: *const base_types.RiscVInteractionClaim,
        interaction_claims: *const candidate_tree.InteractionClaims,
        proof: *const base_types.ProofForEngine(Engine),
    };
}

pub fn Decoded(comptime Engine: type) type {
    return struct {
        pcs_config: pcs.PcsConfig,
        security_identity_sha256: [32]u8,
        full_statement: statement_v2.RiscVStatementV2,
        projected_statement: statement_v2.RiscVStatementV2,
        extension: ethereum_statement.Statement,
        global: global_v3.MetadataV3,
        profile: candidate_profile.Profile,
        base_claim: *base_types.RiscVInteractionClaim,
        interaction_claims: candidate_tree.InteractionClaims,
        proof: base_types.ProofForEngine(Engine),
        full_words: []core.fields.m31.M31,
        projected_words: []core.fields.m31.M31,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.releaseMetadata(allocator);
        }

        pub fn deinitAfterProofMoved(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            self.releaseMetadata(allocator);
        }

        fn releaseMetadata(self: *Self, allocator: std.mem.Allocator) void {
            allocator.destroy(self.base_claim);
            allocator.free(self.projected_words);
            allocator.free(self.full_words);
            self.* = undefined;
        }
    };
}

pub fn encodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    input: EncodeInput(Engine),
    limits: Limits,
) ![]u8 {
    try limits.validate();
    try validateInput(Engine, allocator, input, limits);

    var statement_section: std.ArrayList(u8) = .empty;
    defer statement_section.deinit(allocator);
    try encodeStatements(
        allocator,
        statement_section.writer(allocator),
        input.full_statement,
        input.projected_statement,
        limits.max_artifact_bytes,
    );

    var metadata_section: std.ArrayList(u8) = .empty;
    defer metadata_section.deinit(allocator);
    try candidate_wire.encodeMetadata(metadata_section.writer(allocator), .{
        .ethereum = input.extension.*,
        .global = input.global.*,
        .profile = input.profile.*,
    });

    var claim_section: std.ArrayList(u8) = .empty;
    defer claim_section.deinit(allocator);
    try candidate_wire.encodeClaims(
        allocator,
        claim_section.writer(allocator),
        input.projected_statement,
        input.extension,
        input.base_claim,
        &input.interaction_claims.ethereum,
        input.interaction_claims.candidate,
    );

    var proof_section: std.ArrayList(u8) = .empty;
    defer proof_section.deinit(allocator);
    try postcard.serializeProof(
        base_types.HasherForEngine(Engine),
        proof_section.writer(allocator),
        input.proof.*,
    );
    if (proof_section.items.len == 0 or
        proof_section.items.len > limits.max_proof_bytes)
    {
        return error.ProofResourceLimitExceeded;
    }
    try postcard.proof_preflight.validate(
        proof_section.items,
        try proofPreflightShape(
            Engine,
            allocator,
            input.pcs_config,
            input.projected_statement,
            input.extension,
            input.profile,
            limits,
        ),
    );

    var identity_section: [identity_size]u8 = undefined;
    try encodeIdentity(
        &identity_section,
        input.pcs_config,
        input.security_identity_sha256,
        statement_section.items,
        metadata_section.items,
        claim_section.items,
    );
    const lengths = [_]usize{
        statement_section.items.len,
        metadata_section.items.len,
        identity_section.len,
        claim_section.items.len,
        proof_section.items.len,
    };
    var total = header_size;
    for (lengths) |length| total = std.math.add(usize, total, length) catch
        return error.ArtifactResourceLimitExceeded;
    if (total > limits.max_artifact_bytes or total > std.math.maxInt(u64))
        return error.ArtifactResourceLimitExceeded;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.ensureTotalCapacityPrecise(allocator, total);
    try encodeHeader(output.writer(allocator), @intCast(total), lengths);
    try output.appendSlice(allocator, statement_section.items);
    try output.appendSlice(allocator, metadata_section.items);
    try output.appendSlice(allocator, &identity_section);
    try output.appendSlice(allocator, claim_section.items);
    try output.appendSlice(allocator, proof_section.items);
    if (output.items.len != total) return error.InvalidArtifactLength;
    return output.toOwnedSlice(allocator);
}

pub fn decodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_pcs_config: pcs.PcsConfig,
    expected_security_identity_sha256: [32]u8,
    limits: Limits,
) !Decoded(Engine) {
    try limits.validate();
    if (bytes.len > limits.max_artifact_bytes)
        return error.ArtifactResourceLimitExceeded;
    const frame = try Frame.parse(bytes);
    if (frame.total_bytes != bytes.len) return error.InvalidArtifactLength;

    var statements = try decodeStatements(
        allocator,
        frame.statement,
        limits.max_artifact_bytes,
    );
    var statements_owned = true;
    errdefer if (statements_owned) statements.deinit(allocator);
    const metadata = try candidate_wire.decodeMetadata(frame.metadata);
    try validateCandidateMetadata(
        &statements.full.value,
        &statements.projected.value,
        &metadata.ethereum,
        &metadata.global,
        &metadata.profile,
    );
    try validateProjectedProfile(
        &statements.projected.value,
        &metadata.ethereum,
        &metadata.profile,
    );
    const identity = try decodeAndValidateIdentity(
        frame.identity,
        expected_pcs_config,
        expected_security_identity_sha256,
        frame.statement,
        frame.metadata,
        frame.claim,
    );
    var claims = try candidate_wire.decodeClaims(
        allocator,
        frame.claim,
        &statements.projected.value,
        &metadata.ethereum,
        &metadata.profile,
    );
    var claims_owned = true;
    errdefer if (claims_owned) claims.deinit(allocator);

    const shape = try proofPreflightShape(
        Engine,
        allocator,
        expected_pcs_config,
        &statements.projected.value,
        &metadata.ethereum,
        &metadata.profile,
        limits,
    );
    try postcard.proof_preflight.validate(frame.proof, shape);
    var proof_stream = std.io.fixedBufferStream(frame.proof);
    var proof = try postcard.deserializeProof(
        base_types.HasherForEngine(Engine),
        allocator,
        proof_stream.reader(),
    );
    errdefer proof.deinit(allocator);
    if (proof_stream.pos != frame.proof.len) return error.TrailingProofBytes;
    if (!pcsConfigsEqual(
        expected_pcs_config,
        proof.commitment_scheme_proof.config,
    )) return error.PcsConfigMismatch;

    statements_owned = false;
    claims_owned = false;
    return .{
        .pcs_config = expected_pcs_config,
        .security_identity_sha256 = identity.security_identity_sha256,
        .full_statement = statements.full.value,
        .projected_statement = statements.projected.value,
        .extension = metadata.ethereum,
        .global = metadata.global,
        .profile = metadata.profile,
        .base_claim = claims.base,
        .interaction_claims = .{
            .ethereum = claims.ethereum,
            .candidate = claims.candidate,
        },
        .proof = proof,
        .full_words = statements.full.canonical_words,
        .projected_words = statements.projected.canonical_words,
    };
}

pub fn proofPreflightShape(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    config: pcs.PcsConfig,
    projected: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    profile: *const candidate_profile.Profile,
    limits: Limits,
) !postcard.proof_preflight.Shape {
    try limits.validate();
    try projected.validate();
    try validateProjectedProfile(projected, extension, profile);
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &projected.core,
        &manifest,
    );
    var logs = try candidate_tree.logSizes(
        allocator,
        &projected.core,
        extension,
        &manifest,
        &authenticated,
        profile,
    );
    defer logs.deinit(allocator);
    const composition_columns = verifier_types.compositionColumnCount(
        candidate_profile.composition_log_split,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidProofShape;
    const hash_size = @sizeOf(base_types.HasherForEngine(Engine).Hash);
    if (hash_size == 0 or hash_size % @sizeOf(u32) != 0)
        return error.InvalidProofShape;
    return .{
        .config = .{
            .pow_bits = config.pow_bits,
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .n_queries = config.fri_config.n_queries,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .fold_step = config.fri_config.fold_step,
            .lifting_log_size = config.lifting_log_size,
        },
        .tree_columns = .{
            try checkedU32(logs.tree0.len),
            try checkedU32(logs.tree1.len),
            try checkedU32(logs.tree2.len),
            try checkedU32(composition_columns),
        },
        .max_column_log_size = maxLogSize(&.{
            logs.tree0,
            logs.tree1,
            logs.tree2,
        }),
        .sample_width_limits = .{ 2, 6, 2, 1 },
        .hash_size = @intCast(hash_size),
        .hash_encoding = .canonical_m31_words,
        .max_wire_bytes = limits.max_proof_bytes,
    };
}

fn validateInput(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    input: EncodeInput(Engine),
    limits: Limits,
) !void {
    if (std.mem.allEqual(u8, &input.security_identity_sha256, 0))
        return error.InvalidSecurityIdentity;
    if (!pcsConfigsEqual(
        input.pcs_config,
        input.proof.commitment_scheme_proof.config,
    )) return error.PcsConfigMismatch;
    if (input.proof.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidProofShape;
    try validateCandidateMetadata(
        input.full_statement,
        input.projected_statement,
        input.extension,
        input.global,
        input.profile,
    );
    try input.projected_statement.validate();
    try validateProjectedProfile(
        input.projected_statement,
        input.extension,
        input.profile,
    );
    _ = try input.base_claim.canonical(&input.projected_statement.core);
    try input.interaction_claims.validate(input.extension, input.profile);
    _ = try proofPreflightShape(
        Engine,
        allocator,
        input.pcs_config,
        input.projected_statement,
        input.extension,
        input.profile,
        limits,
    );
}

/// Validates the full native retirement authority without conflating it with
/// the provider-projected component geometry. The transported profile owns
/// the candidate authority and exact dynamic counts; a full-core sibling is
/// deterministically reconstructed for preprojection admission, while the
/// transported projected profile remains independently checked below.
fn validateCandidateMetadata(
    full: *const statement_v2.RiscVStatementV2,
    projected: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    global: *const global_v3.MetadataV3,
    profile: *const candidate_profile.Profile,
) !void {
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &full.core,
        &manifest,
    );
    const base_interaction_columns = std.math.cast(
        u32,
        try authenticated.totalInteractionColumns(&full.core, &manifest),
    ) orelse return error.EthereumCandidateLeafGeometryOverflow;
    const full_profile = try candidate_profile.Profile.create(
        &full.core,
        extension,
        base_interaction_columns,
        profile.authority,
        profile.bulk_memcpy_call_count,
        profile.bulk_memcpy_word_row_count,
        profile.stack_swap_call_count,
    );
    _ = try candidate_admission.validateV2(
        full,
        extension,
        base_interaction_columns,
        &full_profile,
        .proof,
    );
    try native_artifact.validateGlobalMetadataMapping(full, global);
    try projected.validate();
}

fn validateProjectedProfile(
    projected: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    profile: *const candidate_profile.Profile,
) !void {
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &projected.core,
        &manifest,
    );
    const base_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(&projected.core, &manifest),
    );
    try profile.validate(&projected.core, extension, base_columns);
}

const OwnedStatements = struct {
    full: statement_wire.Owned,
    projected: statement_wire.Owned,

    fn deinit(self: *OwnedStatements, allocator: std.mem.Allocator) void {
        self.projected.deinit(allocator);
        self.full.deinit(allocator);
        self.* = undefined;
    }
};

fn encodeStatements(
    allocator: std.mem.Allocator,
    writer: anytype,
    full: *const statement_v2.RiscVStatementV2,
    projected: *const statement_v2.RiscVStatementV2,
    max_section_bytes: usize,
) !void {
    var full_bytes: std.ArrayList(u8) = .empty;
    defer full_bytes.deinit(allocator);
    try statement_wire.encode(
        full_bytes.writer(allocator),
        full,
        max_section_bytes,
    );
    var projected_bytes: std.ArrayList(u8) = .empty;
    defer projected_bytes.deinit(allocator);
    try statement_wire.encode(
        projected_bytes.writer(allocator),
        projected,
        max_section_bytes,
    );
    if (full_bytes.items.len > std.math.maxInt(u32) or
        projected_bytes.items.len > std.math.maxInt(u32))
    {
        return error.StatementResourceLimitExceeded;
    }
    try base_wire.writeInt(writer, u16, format_version);
    try base_wire.writeInt(writer, u32, @intCast(full_bytes.items.len));
    try writer.writeAll(full_bytes.items);
    try base_wire.writeInt(writer, u32, @intCast(projected_bytes.items.len));
    try writer.writeAll(projected_bytes.items);
}

fn decodeStatements(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_section_bytes: usize,
) !OwnedStatements {
    var cursor = base_wire.Cursor.init(bytes);
    if (try cursor.readInt(u16) != format_version)
        return error.UnsupportedArtifactVersion;
    const full_len = try cursor.readCount();
    var full = try statement_wire.decode(
        allocator,
        try cursor.take(full_len),
        max_section_bytes,
    );
    errdefer full.deinit(allocator);
    const projected_len = try cursor.readCount();
    var projected = try statement_wire.decode(
        allocator,
        try cursor.take(projected_len),
        max_section_bytes,
    );
    errdefer projected.deinit(allocator);
    try cursor.requireDone();
    return .{ .full = full, .projected = projected };
}

const Identity = struct {
    security_identity_sha256: [32]u8,
    metadata_sha256: [32]u8,
};

fn encodeIdentity(
    output: *[identity_size]u8,
    config: pcs.PcsConfig,
    security: [32]u8,
    statement: []const u8,
    metadata: []const u8,
    claim: []const u8,
) !void {
    var stream = std.io.fixedBufferStream(output);
    const writer = stream.writer();
    try writer.writeAll(&magic);
    try base_wire.writeInt(writer, u16, format_version);
    try base_wire.writeInt(writer, u16, 1);
    try writer.writeAll(&security);
    try writer.writeAll(&metadataIdentity(
        config,
        security,
        statement,
        metadata,
        claim,
    ));
    if (stream.pos != output.len) return error.InvalidIdentityLength;
}

fn decodeAndValidateIdentity(
    bytes: []const u8,
    config: pcs.PcsConfig,
    expected_security: [32]u8,
    statement: []const u8,
    metadata: []const u8,
    claim: []const u8,
) !Identity {
    if (bytes.len != identity_size) return error.InvalidIdentityLength;
    var cursor = base_wire.Cursor.init(bytes);
    if (!std.mem.eql(u8, try cursor.take(magic.len), &magic))
        return error.InvalidIdentityMagic;
    if (try cursor.readInt(u16) != format_version or
        try cursor.readInt(u16) != 1)
    {
        return error.UnsupportedIdentityVersion;
    }
    var result: Identity = undefined;
    try cursor.readExact(&result.security_identity_sha256);
    try cursor.readExact(&result.metadata_sha256);
    try cursor.requireDone();
    if (!std.mem.eql(
        u8,
        &result.security_identity_sha256,
        &expected_security,
    ) or !std.mem.eql(
        u8,
        &result.metadata_sha256,
        &metadataIdentity(
            config,
            expected_security,
            statement,
            metadata,
            claim,
        ),
    )) return error.InvalidArtifactIdentity;
    return result;
}

fn metadataIdentity(
    config: pcs.PcsConfig,
    security: [32]u8,
    statement: []const u8,
    metadata: []const u8,
    claim: []const u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-leaf-artifact.v1\x00");
    hash.update(&security);
    hashInt(&hash, u32, config.pow_bits);
    hashInt(&hash, u32, config.fri_config.log_blowup_factor);
    hashInt(&hash, u64, config.fri_config.n_queries);
    hashInt(&hash, u32, config.fri_config.log_last_layer_degree_bound);
    hashInt(&hash, u32, config.fri_config.fold_step);
    hashInt(&hash, u32, config.lifting_log_size orelse std.math.maxInt(u32));
    hash.update(statement);
    hash.update(metadata);
    hash.update(claim);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn encodeHeader(
    writer: anytype,
    total: u64,
    lengths: [5]usize,
) !void {
    try writer.writeAll(&magic);
    try base_wire.writeInt(writer, u16, format_version);
    try base_wire.writeInt(writer, u16, header_size);
    try base_wire.writeInt(writer, u64, total);
    for (lengths) |length| {
        if (length == 0 or length > std.math.maxInt(u32))
            return error.ArtifactResourceLimitExceeded;
        try base_wire.writeInt(writer, u32, @intCast(length));
    }
    if (8 + 2 + 2 + 8 + 5 * 4 != header_size)
        return error.InvalidHeaderLength;
}

const Frame = struct {
    total_bytes: u64,
    statement: []const u8,
    metadata: []const u8,
    identity: []const u8,
    claim: []const u8,
    proof: []const u8,

    fn parse(bytes: []const u8) !Frame {
        if (bytes.len < header_size) return error.EndOfStream;
        var cursor = base_wire.Cursor.init(bytes[0..header_size]);
        if (!std.mem.eql(u8, try cursor.take(magic.len), &magic))
            return error.InvalidArtifactMagic;
        if (try cursor.readInt(u16) != format_version)
            return error.UnsupportedArtifactVersion;
        if (try cursor.readInt(u16) != header_size)
            return error.InvalidHeaderLength;
        const total = try cursor.readInt(u64);
        var lengths: [5]usize = undefined;
        for (&lengths) |*length| {
            length.* = try cursor.readCount();
            if (length.* == 0) return error.InvalidSectionLength;
        }
        try cursor.requireDone();
        var payload = base_wire.Cursor.init(bytes[header_size..]);
        const statement = try payload.take(lengths[0]);
        const metadata = try payload.take(lengths[1]);
        const identity = try payload.take(lengths[2]);
        const claim = try payload.take(lengths[3]);
        const proof = try payload.take(lengths[4]);
        try payload.requireDone();
        return .{
            .total_bytes = total,
            .statement = statement,
            .metadata = metadata,
            .identity = identity,
            .claim = claim,
            .proof = proof,
        };
    }
};

fn checkedU32(value: usize) !u32 {
    return std.math.cast(u32, value) orelse return error.InvalidProofShape;
}

fn maxLogSize(trees: []const []const u32) u32 {
    var result: u32 = 0;
    for (trees) |tree| {
        for (tree) |value| result = @max(result, value);
    }
    return result;
}

fn pcsConfigsEqual(a: pcs.PcsConfig, b: pcs.PcsConfig) bool {
    return a.pow_bits == b.pow_bits and
        a.fri_config.log_blowup_factor == b.fri_config.log_blowup_factor and
        a.fri_config.n_queries == b.fri_config.n_queries and
        a.fri_config.log_last_layer_degree_bound ==
            b.fri_config.log_last_layer_degree_bound and
        a.fri_config.fold_step == b.fri_config.fold_step and
        a.lifting_log_size == b.lifting_log_size;
}

comptime {
    if (production_active or candidate_profile.production_active or
        candidate_integration.production_active)
    {
        @compileError("candidate Ethereum leaf proof artifact became active");
    }
}
