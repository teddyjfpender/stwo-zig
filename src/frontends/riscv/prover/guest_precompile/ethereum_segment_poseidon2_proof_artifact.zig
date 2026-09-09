//! Append-only `STWGPF01` v4 Poseidon2-M31 Ethereum SegmentV3 envelope.
//!
//! Version 3 remains the byte-exact native Blake2s product. Version 4 fixes
//! the recursion protocol PCS and Poseidon2 suite in verifier code, retains the
//! complete dynamic base-plus-fourteen-component proof, and carries no
//! prover-selected recursive program or verification-key identity.

const std = @import("std");
const core = @import("stwo_core");
const qm31 = core.fields.qm31;
const verifier_types = core.verifier_types;
const postcard = @import("interop_postcard");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const proof_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const protocol = @import("../../recursion/protocol.zig");
const recursive_engine = @import("../../recursion/engine.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const base_types = @import("../types.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
const ethereum_types = @import("ethereum_types.zig");
const framing = @import("proof_artifact_header.zig");
const base_wire = @import("proof_artifact_wire.zig");
const claim_wire = @import("ethereum_proof_artifact_wire.zig");
const statement_wire = @import("ethereum_segment_artifact_statement_wire.zig");
const metadata_wire = @import("ethereum_segment_artifact_metadata_wire.zig");
const native_artifact = @import("ethereum_segment_proof_artifact.zig");
const native_wire = @import("ethereum_segment_proof_artifact_wire.zig");
const wire = @import("ethereum_segment_poseidon2_proof_artifact_wire.zig");

pub const Limits = base_wire.Limits;
pub const magic = framing.magic;
pub const format_version: u16 = wire.artifact_format_version;
pub const header_size = framing.header_size;
pub const PreflightDiagnostic = postcard.proof_preflight.Diagnostic;
pub const EncodePhase = enum {
    limits,
    pcs_policy,
    proof_config,
    security_identity,
    metadata,
    extension_claim,
    base_claim,
    shape_limits,
    shape_pcs_policy,
    shape_statement,
    shape_admission,
    shape_lookup,
    shape_tree0,
    shape_tree1,
    shape_tree2,
    shape_composition,
    shape_count_cast,
    shape_unknown,
    hash_width,
    statement_section,
    extension_section,
    identity_section,
    claim_section,
    proof_serialization,
    proof_resource_limit,
    canonical_preflight,
};

pub const EncodeDiagnostic = struct {
    phase: EncodePhase,
    cause: anyerror,
    preflight: ?PreflightDiagnostic = null,
};
pub const HeaderOffset = framing.Offset;
pub const ExtensionOffset = struct {
    pub const metadata_clock_frame = native_wire.extension_encoded_size -
        metadata_wire.encoded_size + metadata_wire.clock_frame_offset;
};
pub const pcs_config = protocol.PCS_CONFIG;
pub const Proof = recursive_engine.Proof;

pub const EncodeInput = struct {
    security_identity_sha256: [32]u8,
    statement: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    global: *const global_v3.MetadataV3,
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    proof: *const Proof,
};

pub const Decoded = struct {
    statement: statement_v2.RiscVStatementV2,
    extension: ethereum_statement.Statement,
    global: global_v3.MetadataV3,
    identity: wire.Identity,
    base_claim: *base_types.RiscVInteractionClaim,
    extension_claim: ethereum_types.ExtensionClaim,
    proof: Proof,
    canonical_words: []core.fields.m31.M31,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        self.releaseMetadata(allocator);
    }

    pub fn deinitAfterProofMoved(self: *Decoded, allocator: std.mem.Allocator) void {
        self.releaseMetadata(allocator);
    }

    fn releaseMetadata(self: *Decoded, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base_claim);
        allocator.free(self.canonical_words);
        self.* = undefined;
    }
};

pub fn encodeAlloc(allocator: std.mem.Allocator, input: EncodeInput) ![]u8 {
    return encodeAllocWithLimits(allocator, input, .{});
}

pub fn encodeAllocWithLimits(
    allocator: std.mem.Allocator,
    input: EncodeInput,
    limits: Limits,
) ![]u8 {
    return encodeAllocWithLimitsInternal(allocator, input, limits, null);
}

/// Product-only localization for a failed canonical proof preflight.
///
/// The proof bytes and admission result are identical to
/// `encodeAllocWithLimits`; only the first structural mismatch is retained.
pub fn encodeAllocWithLimitsDiagnosed(
    allocator: std.mem.Allocator,
    input: EncodeInput,
    limits: Limits,
    diagnostic: *?EncodeDiagnostic,
) ![]u8 {
    diagnostic.* = null;
    return encodeAllocWithLimitsInternal(allocator, input, limits, diagnostic);
}

fn encodeAllocWithLimitsInternal(
    allocator: std.mem.Allocator,
    input: EncodeInput,
    limits: Limits,
    diagnostic: ?*?EncodeDiagnostic,
) ![]u8 {
    limits.validate() catch |err|
        return encodeFailure(diagnostic, .limits, err, null);
    if (limits.max_artifact_bytes < header_size)
        return encodeFailure(
            diagnostic,
            .limits,
            error.InvalidResourceLimits,
            null,
        );
    framing.validatePcsConfig(pcs_config, limits) catch |err|
        return encodeFailure(diagnostic, .pcs_policy, err, null);
    if (!framing.pcsConfigsEqual(
        pcs_config,
        input.proof.commitment_scheme_proof.config,
    )) return encodeFailure(
        diagnostic,
        .proof_config,
        error.PcsConfigMismatch,
        null,
    );
    if (std.mem.allEqual(u8, &input.security_identity_sha256, 0))
        return encodeFailure(
            diagnostic,
            .security_identity,
            error.InvalidSecurityIdentity,
            null,
        );
    native_artifact.validateMetadata(
        input.statement,
        input.extension,
        input.global,
    ) catch |err| return encodeFailure(diagnostic, .metadata, err, null);
    input.extension_claim.validate(input.extension) catch |err|
        return encodeFailure(diagnostic, .extension_claim, err, null);
    _ = input.base_claim.canonical(&input.statement.core) catch |err|
        return encodeFailure(diagnostic, .base_claim, err, null);
    const shape = try proofPreflightShapeInternal(
        allocator,
        input.statement,
        input.extension,
        limits,
        diagnostic,
    );

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    output.appendNTimes(allocator, 0, header_size) catch |err|
        return encodeFailure(diagnostic, .statement_section, err, null);
    const writer = output.writer(allocator);

    const statement_start = output.items.len;
    statement_wire.encode(
        writer,
        input.statement,
        limits.max_artifact_bytes,
    ) catch |err| return encodeFailure(
        diagnostic,
        .statement_section,
        err,
        null,
    );
    const statement_length = sectionLength(
        output.items.len,
        statement_start,
    ) catch |err| return encodeFailure(
        diagnostic,
        .statement_section,
        err,
        null,
    );

    const extension_start = output.items.len;
    native_wire.encodeExtension(writer, .{
        .ethereum = input.extension.*,
        .global = input.global.*,
    }) catch |err| return encodeFailure(
        diagnostic,
        .extension_section,
        err,
        null,
    );
    const extension_length = sectionLength(
        output.items.len,
        extension_start,
    ) catch |err| return encodeFailure(
        diagnostic,
        .extension_section,
        err,
        null,
    );
    if (extension_length != native_wire.extension_encoded_size)
        return encodeFailure(
            diagnostic,
            .extension_section,
            error.InvalidExtensionLength,
            null,
        );

    const identity_start = output.items.len;
    const identity = wire.Identity.canonical(
        allocator,
        pcs_config,
        input.security_identity_sha256,
        input.statement,
        input.extension,
        input.global,
        output.items[statement_start..extension_start],
        output.items[extension_start..identity_start],
    ) catch |err| return encodeFailure(
        diagnostic,
        .identity_section,
        err,
        null,
    );
    identity.encode(writer) catch |err|
        return encodeFailure(diagnostic, .identity_section, err, null);
    const identity_length = sectionLength(
        output.items.len,
        identity_start,
    ) catch |err| return encodeFailure(
        diagnostic,
        .identity_section,
        err,
        null,
    );
    if (identity_length != wire.identity_encoded_size)
        return encodeFailure(
            diagnostic,
            .identity_section,
            error.InvalidIdentityLength,
            null,
        );

    const claim_start = output.items.len;
    claim_wire.encodeClaim(
        writer,
        &input.statement.core,
        input.extension,
        input.base_claim,
        input.extension_claim,
    ) catch |err| return encodeFailure(
        diagnostic,
        .claim_section,
        err,
        null,
    );
    const claim_length = sectionLength(
        output.items.len,
        claim_start,
    ) catch |err| return encodeFailure(
        diagnostic,
        .claim_section,
        err,
        null,
    );

    const proof_start = output.items.len;
    postcard.serializeProof(
        recursive_engine.Hasher,
        writer,
        input.proof.*,
    ) catch |err| return encodeFailure(
        diagnostic,
        .proof_serialization,
        err,
        null,
    );
    const proof_length = sectionLength(
        output.items.len,
        proof_start,
    ) catch |err| return encodeFailure(
        diagnostic,
        .proof_serialization,
        err,
        null,
    );
    if (proof_length == 0 or proof_length > limits.max_proof_bytes)
        return encodeFailure(
            diagnostic,
            .proof_resource_limit,
            error.ProofResourceLimitExceeded,
            null,
        );
    var preflight_diagnostic: ?PreflightDiagnostic = null;
    postcard.proof_preflight.validateWithDiagnostic(
        output.items[proof_start..],
        shape,
        &preflight_diagnostic,
    ) catch |err| return encodeFailure(
        diagnostic,
        .canonical_preflight,
        err,
        preflight_diagnostic,
    );
    if (output.items.len > limits.max_artifact_bytes)
        return error.ArtifactResourceLimitExceeded;

    const header = framing.Header{
        .format_version = format_version,
        .total_bytes = @intCast(output.items.len),
        .pcs_config = pcs_config,
        .statement_length = @intCast(statement_length),
        .extension_length = @intCast(extension_length),
        .identity_length = @intCast(identity_length),
        .claim_length = @intCast(claim_length),
        .proof_length = @intCast(proof_length),
    };
    var stream = std.io.fixedBufferStream(output.items[0..header_size]);
    try header.encode(stream.writer());
    if (stream.getWritten().len != header_size) return error.InvalidHeaderLength;
    return output.toOwnedSlice(allocator);
}

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_security_identity_sha256: [32]u8,
    limits: Limits,
) !Decoded {
    try limits.validate();
    if (limits.max_artifact_bytes < header_size)
        return error.InvalidResourceLimits;
    if (std.mem.allEqual(u8, &expected_security_identity_sha256, 0))
        return error.InvalidSecurityIdentity;
    const frame = try Frame.parse(bytes, limits);
    if (!framing.pcsConfigsEqual(pcs_config, frame.header.pcs_config))
        return error.PcsConfigMismatch;

    var owned_statement = try statement_wire.decode(
        allocator,
        frame.statement,
        limits.max_artifact_bytes,
    );
    var statement_owned = true;
    errdefer if (statement_owned) owned_statement.deinit(allocator);
    const extension = try native_wire.decodeExtension(frame.extension);
    try native_artifact.validateMetadata(
        &owned_statement.value,
        &extension.ethereum,
        &extension.global,
    );
    const identity = try wire.Identity.decode(frame.identity);
    try identity.validateAgainst(
        allocator,
        pcs_config,
        expected_security_identity_sha256,
        &owned_statement.value,
        &extension.ethereum,
        &extension.global,
        frame.statement,
        frame.extension,
    );

    var claim = try claim_wire.decodeClaim(
        allocator,
        frame.claim,
        &owned_statement.value.core,
        &extension.ethereum,
    );
    var claim_owned = true;
    errdefer if (claim_owned) claim.deinit(allocator);

    const shape = try proofPreflightShape(
        allocator,
        &owned_statement.value,
        &extension.ethereum,
        limits,
    );
    try postcard.proof_preflight.validate(frame.proof, shape);
    var proof_stream = std.io.fixedBufferStream(frame.proof);
    var proof = try postcard.deserializeProof(
        recursive_engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    errdefer proof.deinit(allocator);
    if (proof_stream.pos != frame.proof.len) return error.TrailingProofBytes;
    if (!framing.pcsConfigsEqual(
        pcs_config,
        proof.commitment_scheme_proof.config,
    )) return error.PcsConfigMismatch;

    claim_owned = false;
    statement_owned = false;
    return .{
        .statement = owned_statement.value,
        .extension = extension.ethereum,
        .global = extension.global,
        .identity = identity,
        .base_claim = claim.base,
        .extension_claim = claim.extension,
        .proof = proof,
        .canonical_words = owned_statement.canonical_words,
    };
}

pub fn proofPreflightShape(
    allocator: std.mem.Allocator,
    statement: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    limits: Limits,
) !postcard.proof_preflight.Shape {
    return proofPreflightShapeInternal(
        allocator,
        statement,
        extension,
        limits,
        null,
    );
}

fn proofPreflightShapeInternal(
    allocator: std.mem.Allocator,
    statement: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    limits: Limits,
    diagnostic: ?*?EncodeDiagnostic,
) !postcard.proof_preflight.Shape {
    var shape = native_artifact.proofPreflightShape(
        allocator,
        pcs_config,
        statement,
        extension,
        limits,
    ) catch |err| return encodeFailure(
        diagnostic,
        diagnoseShapeFailure(allocator, statement, extension, limits),
        err,
        null,
    );
    if (shape.hash_size != @sizeOf(recursive_engine.Hasher.Hash))
        return encodeFailure(
            diagnostic,
            .hash_width,
            error.InvalidProofShape,
            null,
        );
    // The native geometry constructor intentionally defaults to the Blake
    // postcard wire, where Merkle hashes are fixed raw-byte arrays. Poseidon
    // hashes are arrays of M31 values and postcard encodes every limb as a
    // canonical varint, so v4 must walk those words rather than skip 32 bytes.
    shape.hash_encoding = .canonical_m31_words;
    return shape;
}

fn diagnoseShapeFailure(
    allocator: std.mem.Allocator,
    statement: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    limits: Limits,
) EncodePhase {
    limits.validate() catch return .shape_limits;
    framing.validatePcsConfig(pcs_config, limits) catch
        return .shape_pcs_policy;
    statement.validate() catch return .shape_statement;
    proof_admission.validateV2(statement, extension, .proof) catch
        return .shape_admission;

    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = lookup_physical_v2.AuthenticatedStatement.init(
        &statement.core,
        &manifest,
    ) catch return .shape_lookup;
    const tree0 = ethereum_preprocessed.logSizes(
        allocator,
        &statement.core,
        extension,
    ) catch return .shape_tree0;
    defer allocator.free(tree0);
    const tree1 = ethereum_main.logSizes(
        allocator,
        &statement.core,
        extension,
    ) catch return .shape_tree1;
    defer allocator.free(tree1);
    const tree2 = ethereum_interaction.logSizesAuthenticatedLookupV2(
        allocator,
        &statement.core,
        extension,
        &manifest,
        &authenticated,
    ) catch return .shape_tree2;
    defer allocator.free(tree2);

    const composition_columns = verifier_types.compositionColumnCount(
        verifier_types.COMPOSITION_LOG_SPLIT,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return .shape_composition;
    if (std.math.cast(u32, tree0.len) == null or
        std.math.cast(u32, tree1.len) == null or
        std.math.cast(u32, tree2.len) == null or
        std.math.cast(u32, composition_columns) == null)
    {
        return .shape_count_cast;
    }
    return .shape_unknown;
}

fn encodeFailure(
    diagnostic: ?*?EncodeDiagnostic,
    phase: EncodePhase,
    cause: anyerror,
    preflight: ?PreflightDiagnostic,
) anyerror {
    if (diagnostic) |output| {
        if (output.* == null) {
            output.* = .{
                .phase = phase,
                .cause = cause,
                .preflight = preflight,
            };
        }
    }
    return cause;
}

const Frame = struct {
    header: framing.Header,
    statement: []const u8,
    extension: []const u8,
    identity: []const u8,
    claim: []const u8,
    proof: []const u8,

    fn parse(bytes: []const u8, limits: Limits) !Frame {
        if (bytes.len > limits.max_artifact_bytes)
            return error.ArtifactResourceLimitExceeded;
        const header = try framing.Header.decodeForVersion(
            bytes,
            format_version,
            limits,
        );
        if (header.total_bytes != bytes.len) return error.InvalidArtifactLength;
        if (header.statement_length == 0 or header.claim_length == 0 or
            header.proof_length == 0 or
            header.extension_length != native_wire.extension_encoded_size or
            header.identity_length != wire.identity_encoded_size)
        {
            return error.InvalidSectionLength;
        }
        if (header.proof_length > limits.max_proof_bytes)
            return error.ProofResourceLimitExceeded;
        var cursor = base_wire.Cursor.init(bytes);
        cursor.position = header_size;
        const statement = try cursor.take(header.statement_length);
        const extension = try cursor.take(header.extension_length);
        const identity = try cursor.take(header.identity_length);
        const claim = try cursor.take(header.claim_length);
        const proof = try cursor.take(header.proof_length);
        try cursor.requireDone();
        return .{
            .header = header,
            .statement = statement,
            .extension = extension,
            .identity = identity,
            .claim = claim,
            .proof = proof,
        };
    }
};

fn sectionLength(end: usize, start: usize) !usize {
    if (end < start) return error.InvalidArtifactLength;
    const length = end - start;
    if (length > std.math.maxInt(u32)) return error.ArtifactResourceLimitExceeded;
    return length;
}

test "Poseidon v4 encode diagnostic retains every typed phase and first mismatch" {
    inline for (std.meta.fields(EncodePhase)) |field| {
        const phase: EncodePhase = @enumFromInt(field.value);
        var diagnostic: ?EncodeDiagnostic = null;
        _ = encodeFailure(
            &diagnostic,
            phase,
            error.InvalidProofShape,
            null,
        );
        _ = encodeFailure(
            &diagnostic,
            .shape_unknown,
            error.InvalidPreflightShape,
            null,
        );
        const retained = diagnostic orelse return error.MissingDiagnostic;
        try std.testing.expectEqual(phase, retained.phase);
        try std.testing.expectEqual(error.InvalidProofShape, retained.cause);
        try std.testing.expect(retained.preflight == null);
    }

    const preflight = PreflightDiagnostic{
        .stage = .queried_column_count,
        .tree = 2,
        .index = null,
        .offset = 144,
        .actual = 17,
        .expected = 18,
    };
    var diagnostic: ?EncodeDiagnostic = null;
    _ = encodeFailure(
        &diagnostic,
        .canonical_preflight,
        error.InvalidProofShape,
        preflight,
    );
    try std.testing.expectEqualDeep(
        preflight,
        diagnostic.?.preflight.?,
    );
}

comptime {
    if (HeaderOffset.proof_length + @sizeOf(u32) != header_size or
        ExtensionOffset.metadata_clock_frame + @sizeOf(u16) >
            native_wire.extension_encoded_size or
        format_version != 4 or @sizeOf(recursive_engine.Hasher.Hash) != 32)
    {
        @compileError("Poseidon2 Ethereum SegmentV3 artifact authority drifted");
    }
}
