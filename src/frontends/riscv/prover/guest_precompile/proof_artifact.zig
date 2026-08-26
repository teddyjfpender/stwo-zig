//! Versioned, fresh-process proof envelope for the Poseidon2 guest profile.
//!
//! The outer protocol uses fixed-width little-endian metadata and five exact
//! sections.  The proof section is the repository's canonical Stark-V
//! postcard encoding; its configuration is repeated in the fixed header so an
//! allocation-free exact-shape preflight can run before the ordinary decoder
//! allocates.  Preflight then requires the embedded proof configuration to be
//! byte-for-value equal to that independent header.
//!
//! Structural decoding is not a security-profile decision.  A product that
//! requires one PCS profile should use `decodeAllocForConfig`, not accept the
//! artifact-selected configuration merely because it is well formed.

const std = @import("std");
const core = @import("stwo_core");
const fri = core.fri;
const pcs = core.pcs;
const qm31 = core.fields.qm31;
const verifier_types = core.verifier_types;
const postcard = @import("interop_postcard");
const proof_admission = @import("../../air/guest_precompile/proof_admission.zig");
const artifact_identity = @import("../../air/guest_precompile/artifact_identity.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const base_statement = @import("../../air/statement.zig");
const base_types = @import("../types.zig");
const profile_types = @import("types.zig");
const wire = @import("proof_artifact_wire.zig");

pub const Limits = wire.Limits;
pub const magic = [8]u8{ 'S', 'T', 'W', 'G', 'P', 'F', '0', '1' };
pub const format_version: u16 = 1;
pub const header_size: usize = 80;
pub const postcard_proof_encoding_v1: u16 = 1;
pub const blake2s_merkle_hasher_v1: u16 = 1;

/// Stable offsets for cheap routing, diagnostics, and mutation tests.  Users
/// should still call the decoder; reading one field is not envelope admission.
pub const HeaderOffset = struct {
    pub const version: usize = 8;
    pub const declared_header_size: usize = 10;
    pub const flags: usize = 12;
    pub const total_bytes: usize = 16;
    pub const proof_encoding: usize = 24;
    pub const hasher: usize = 26;
    pub const pow_bits: usize = 28;
    pub const log_blowup_factor: usize = 32;
    pub const n_queries: usize = 36;
    pub const log_last_layer_degree_bound: usize = 44;
    pub const fold_step: usize = 48;
    pub const lifting_tag: usize = 52;
    pub const lifting_value: usize = 56;
    pub const statement_length: usize = 60;
    pub const extension_length: usize = 64;
    pub const identity_length: usize = 68;
    pub const claim_length: usize = 72;
    pub const proof_length: usize = 76;
};

pub const EncodeInput = struct {
    pcs_config: pcs.PcsConfig,
    statement: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,
    interaction_claim: *const profile_types.InteractionClaim,
    proof: *const base_types.Proof,
};

/// All inputs accepted by `guest_precompile.verifier`, with explicit ownership
/// for the proof, detailed claim box, and public-I/O slices.
pub const Decoded = struct {
    pcs_config: pcs.PcsConfig,
    statement: base_statement.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,
    interaction_claim: *profile_types.InteractionClaim,
    proof: base_types.Proof,
    input_words: []u32,
    output_words: []@import("../../air/public_data.zig").OutputWord,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        self.releaseMetadata(allocator);
    }

    /// Release the envelope after the verifier has consumed the shallow proof
    /// value on either its success or failure path.
    pub fn deinitAfterProofMoved(self: *Decoded, allocator: std.mem.Allocator) void {
        self.releaseMetadata(allocator);
    }

    fn releaseMetadata(self: *Decoded, allocator: std.mem.Allocator) void {
        self.interaction_claim.destroy(allocator);
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        self.* = undefined;
    }
};

pub fn encodeAlloc(
    allocator: std.mem.Allocator,
    input: EncodeInput,
) ![]u8 {
    return encodeAllocWithLimits(allocator, input, .{});
}

pub fn encodeAllocWithLimits(
    allocator: std.mem.Allocator,
    input: EncodeInput,
    limits: Limits,
) ![]u8 {
    try limits.validate();
    if (limits.max_artifact_bytes < header_size)
        return error.InvalidResourceLimits;
    try validatePcsConfig(input.pcs_config, limits);
    if (!pcsConfigsEqual(
        input.pcs_config,
        input.proof.commitment_scheme_proof.config,
    )) return error.PcsConfigMismatch;
    try proof_admission.validate(
        input.statement,
        input.extension,
        input.artifact,
        .proof,
    );
    try input.interaction_claim.validate(input.statement, input.extension);
    const shape = try proofPreflightShape(
        input.pcs_config,
        input.statement,
        input.extension,
        limits,
    );

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.appendNTimes(allocator, 0, header_size);
    const writer = output.writer(allocator);

    const statement_start = output.items.len;
    try wire.encodeStatement(writer, input.statement, limits);
    const statement_length = try sectionLength(output.items.len, statement_start);

    const extension_start = output.items.len;
    try wire.encodeExtension(writer, input.extension);
    const extension_length = try sectionLength(output.items.len, extension_start);
    if (extension_length != wire.extension_encoded_size)
        return error.InvalidExtensionLength;

    const identity_start = output.items.len;
    const identity_bytes = input.artifact.encode();
    try writer.writeAll(&identity_bytes);
    const identity_length = try sectionLength(output.items.len, identity_start);
    if (identity_length != artifact_identity.encoded_size)
        return error.InvalidIdentityLength;

    const claim_start = output.items.len;
    try wire.encodeClaim(writer, input.statement, input.interaction_claim);
    const claim_length = try sectionLength(output.items.len, claim_start);

    const proof_start = output.items.len;
    try postcard.serializeProof(base_types.Hasher, writer, input.proof.*);
    const proof_length = try sectionLength(output.items.len, proof_start);
    if (proof_length == 0 or proof_length > limits.max_proof_bytes)
        return error.ProofResourceLimitExceeded;
    try postcard.proof_preflight.validate(output.items[proof_start..], shape);

    if (output.items.len > limits.max_artifact_bytes)
        return error.ArtifactResourceLimitExceeded;
    const header = Header{
        .total_bytes = @intCast(output.items.len),
        .pcs_config = input.pcs_config,
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
) !Decoded {
    return decodeAllocWithLimits(allocator, bytes, .{});
}

pub fn decodeAllocWithLimits(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !Decoded {
    return decodeInternal(allocator, bytes, limits, null);
}

/// Decode while requiring the product-selected PCS profile exactly.  This is
/// the release-facing entry point; the comparison occurs before any payload
/// allocation.
pub fn decodeAllocForConfig(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: pcs.PcsConfig,
    limits: Limits,
) !Decoded {
    return decodeInternal(allocator, bytes, limits, expected);
}

fn decodeInternal(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
    expected_config: ?pcs.PcsConfig,
) !Decoded {
    try limits.validate();
    if (limits.max_artifact_bytes < header_size)
        return error.InvalidResourceLimits;
    const frame = try Frame.parse(bytes, limits);
    if (expected_config) |expected| {
        if (!pcsConfigsEqual(expected, frame.header.pcs_config))
            return error.PcsConfigMismatch;
    }

    var owned_statement = try wire.decodeStatement(
        allocator,
        frame.statement,
        limits,
    );
    var statement_owned = true;
    errdefer if (statement_owned) owned_statement.deinit(allocator);
    const extension = try wire.decodeExtension(frame.extension);
    const artifact = try artifact_identity.Identity.decode(frame.identity);
    try proof_admission.validate(
        &owned_statement.value,
        &extension,
        artifact,
        .proof,
    );

    const claim = try wire.decodeClaim(
        allocator,
        frame.claim,
        &owned_statement.value,
        &extension,
    );
    var claim_owned = true;
    errdefer if (claim_owned) claim.destroy(allocator);

    const shape = try proofPreflightShape(
        frame.header.pcs_config,
        &owned_statement.value,
        &extension,
        limits,
    );
    try postcard.proof_preflight.validate(frame.proof, shape);
    var proof_stream = std.io.fixedBufferStream(frame.proof);
    var proof = try postcard.deserializeProof(
        base_types.Hasher,
        allocator,
        proof_stream.reader(),
    );
    errdefer proof.deinit(allocator);
    if (proof_stream.pos != frame.proof.len) return error.TrailingProofBytes;
    if (!pcsConfigsEqual(
        frame.header.pcs_config,
        proof.commitment_scheme_proof.config,
    )) return error.PcsConfigMismatch;

    claim_owned = false;
    statement_owned = false;
    return .{
        .pcs_config = frame.header.pcs_config,
        .statement = owned_statement.value,
        .extension = extension,
        .artifact = artifact,
        .interaction_claim = claim,
        .proof = proof,
        .input_words = owned_statement.input_words,
        .output_words = owned_statement.output_words,
    };
}

/// Reconstruct the exact postcard proof shape from independently admitted
/// statement geometry.  No vector proportional to a column count is allocated.
pub fn proofPreflightShape(
    config: pcs.PcsConfig,
    statement: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    limits: Limits,
) !postcard.proof_preflight.Shape {
    try limits.validate();
    try validatePcsConfig(config, limits);
    if (statement.n_components > base_statement.MAX_COMPONENTS or
        statement.n_infra > base_statement.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidProofShape;
    }
    _ = try proof_admission.canonical(statement, extension, .proof);

    var tree0: u64 = 0;
    var tree1: u64 = 0;
    var tree2: u64 = 0;
    var max_log_size: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        tree0 = try checkedAdd(tree0, 2);
        tree1 = try checkedAdd(tree1, descriptor.n_columns);
        tree2 = try checkedAdd(
            tree2,
            @import("../../air/lookups/opcode_interaction.zig").nColumns(
                descriptor.family,
            ),
        );
        max_log_size = @max(max_log_size, descriptor.log_size);
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        tree0 = try checkedAdd(
            tree0,
            base_statement.nPreprocessedColumnsForInfra(descriptor.kind),
        );
        tree1 = try checkedAdd(tree1, descriptor.n_columns);
        tree2 = try checkedAdd(
            tree2,
            base_statement.nInteractionColsForInfra(descriptor.kind),
        );
        max_log_size = @max(max_log_size, descriptor.log_size);
    }
    for (extension.components) |descriptor| {
        tree0 = try checkedAdd(tree0, descriptor.preprocessed_columns);
        tree1 = try checkedAdd(tree1, descriptor.main_columns);
        tree2 = try checkedAdd(tree2, descriptor.interaction_columns);
        max_log_size = @max(max_log_size, descriptor.log_size);
    }
    const composition_columns = verifier_types.compositionColumnCount(
        verifier_types.COMPOSITION_LOG_SPLIT,
        qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.InvalidProofShape;

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
            try checkedU32(tree0),
            try checkedU32(tree1),
            try checkedU32(tree2),
            std.math.cast(u32, composition_columns) orelse
                return error.InvalidProofShape,
        },
        .max_column_log_size = max_log_size,
        .hash_size = @sizeOf(base_types.Hasher.Hash),
        .max_wire_bytes = limits.max_proof_bytes,
    };
}

pub fn pcsConfigsEqual(expected: pcs.PcsConfig, actual: pcs.PcsConfig) bool {
    return expected.pow_bits == actual.pow_bits and
        expected.fri_config.log_blowup_factor == actual.fri_config.log_blowup_factor and
        expected.fri_config.log_last_layer_degree_bound == actual.fri_config.log_last_layer_degree_bound and
        expected.fri_config.n_queries == actual.fri_config.n_queries and
        expected.fri_config.fold_step == actual.fri_config.fold_step and
        expected.lifting_log_size == actual.lifting_log_size;
}

const Header = struct {
    total_bytes: u64,
    pcs_config: pcs.PcsConfig,
    statement_length: u32,
    extension_length: u32,
    identity_length: u32,
    claim_length: u32,
    proof_length: u32,

    fn encode(self: Header, writer: anytype) !void {
        try writer.writeAll(&magic);
        try wire.writeInt(writer, u16, format_version);
        try wire.writeInt(writer, u16, header_size);
        try wire.writeInt(writer, u32, 0);
        try wire.writeInt(writer, u64, self.total_bytes);
        try wire.writeInt(writer, u16, postcard_proof_encoding_v1);
        try wire.writeInt(writer, u16, blake2s_merkle_hasher_v1);
        try wire.writeInt(writer, u32, self.pcs_config.pow_bits);
        try wire.writeInt(
            writer,
            u32,
            self.pcs_config.fri_config.log_blowup_factor,
        );
        try wire.writeInt(
            writer,
            u64,
            self.pcs_config.fri_config.n_queries,
        );
        try wire.writeInt(
            writer,
            u32,
            self.pcs_config.fri_config.log_last_layer_degree_bound,
        );
        try wire.writeInt(writer, u32, self.pcs_config.fri_config.fold_step);
        if (self.pcs_config.lifting_log_size) |value| {
            try writer.writeByte(1);
            try writer.writeAll(&.{ 0, 0, 0 });
            try wire.writeInt(writer, u32, value);
        } else {
            try writer.writeByte(0);
            try writer.writeAll(&.{ 0, 0, 0 });
            try wire.writeInt(writer, u32, 0);
        }
        try wire.writeInt(writer, u32, self.statement_length);
        try wire.writeInt(writer, u32, self.extension_length);
        try wire.writeInt(writer, u32, self.identity_length);
        try wire.writeInt(writer, u32, self.claim_length);
        try wire.writeInt(writer, u32, self.proof_length);
    }

    fn decode(bytes: []const u8, limits: Limits) !Header {
        if (bytes.len < header_size) return error.EndOfStream;
        var cursor = wire.Cursor.init(bytes[0..header_size]);
        if (!std.mem.eql(u8, try cursor.take(magic.len), &magic))
            return error.InvalidArtifactMagic;
        if (try cursor.readInt(u16) != format_version)
            return error.UnsupportedArtifactVersion;
        if (try cursor.readInt(u16) != header_size)
            return error.InvalidHeaderLength;
        if (try cursor.readInt(u32) != 0) return error.UnsupportedArtifactFlags;
        const total_bytes = try cursor.readInt(u64);
        if (try cursor.readInt(u16) != postcard_proof_encoding_v1)
            return error.UnsupportedProofEncoding;
        if (try cursor.readInt(u16) != blake2s_merkle_hasher_v1)
            return error.UnsupportedProofHasher;

        const pow_bits = try cursor.readInt(u32);
        const log_blowup_factor = try cursor.readInt(u32);
        const n_queries_u64 = try cursor.readInt(u64);
        if (n_queries_u64 == 0 or n_queries_u64 > limits.max_queries or
            n_queries_u64 > std.math.maxInt(usize))
        {
            return error.ProofResourceLimitExceeded;
        }
        const log_last_layer_degree_bound = try cursor.readInt(u32);
        const fold_step = try cursor.readInt(u32);
        const lifting_tag = try cursor.readByte();
        for (0..3) |_| if (try cursor.readByte() != 0)
            return error.NonCanonicalHeader;
        const lifting_value = try cursor.readInt(u32);
        const lifting_log_size: ?u32 = switch (lifting_tag) {
            0 => if (lifting_value == 0) null else return error.NonCanonicalHeader,
            1 => lifting_value,
            else => return error.InvalidOptionTag,
        };
        var fri_config = try fri.FriConfig.init(
            log_last_layer_degree_bound,
            log_blowup_factor,
            @intCast(n_queries_u64),
        );
        fri_config.fold_step = fold_step;
        const config = pcs.PcsConfig{
            .pow_bits = pow_bits,
            .fri_config = fri_config,
            .lifting_log_size = lifting_log_size,
        };
        try validatePcsConfig(config, limits);

        const result = Header{
            .total_bytes = total_bytes,
            .pcs_config = config,
            .statement_length = try cursor.readInt(u32),
            .extension_length = try cursor.readInt(u32),
            .identity_length = try cursor.readInt(u32),
            .claim_length = try cursor.readInt(u32),
            .proof_length = try cursor.readInt(u32),
        };
        try cursor.requireDone();
        return result;
    }
};

const Frame = struct {
    header: Header,
    statement: []const u8,
    extension: []const u8,
    identity: []const u8,
    claim: []const u8,
    proof: []const u8,

    fn parse(bytes: []const u8, limits: Limits) !Frame {
        if (bytes.len > limits.max_artifact_bytes)
            return error.ArtifactResourceLimitExceeded;
        const header = try Header.decode(bytes, limits);
        if (header.total_bytes != bytes.len) return error.InvalidArtifactLength;
        if (header.statement_length == 0 or header.claim_length == 0 or
            header.proof_length == 0)
        {
            return error.InvalidSectionLength;
        }
        if (header.extension_length != wire.extension_encoded_size or
            header.identity_length != artifact_identity.encoded_size)
        {
            return error.InvalidSectionLength;
        }
        if (header.proof_length > limits.max_proof_bytes)
            return error.ProofResourceLimitExceeded;

        var cursor = wire.Cursor.init(bytes);
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

fn validatePcsConfig(config: pcs.PcsConfig, limits: Limits) !void {
    if (config.pow_bits > limits.max_pow_bits or
        config.fri_config.n_queries == 0 or
        config.fri_config.n_queries > limits.max_queries or
        config.fri_config.fold_step == 0 or
        config.fri_config.fold_step > 16 or
        (config.lifting_log_size != null and config.lifting_log_size.? > 30))
    {
        return error.InvalidPcsConfig;
    }
    _ = try fri.FriConfig.init(
        config.fri_config.log_last_layer_degree_bound,
        config.fri_config.log_blowup_factor,
        config.fri_config.n_queries,
    );
}

fn checkedAdd(left: u64, right: anytype) !u64 {
    return std.math.add(u64, left, std.math.cast(u64, right) orelse
        return error.InvalidProofShape) catch return error.InvalidProofShape;
}

fn checkedU32(value: u64) !u32 {
    return std.math.cast(u32, value) orelse error.InvalidProofShape;
}

fn sectionLength(end: usize, start: usize) !usize {
    if (end < start) return error.InvalidArtifactLength;
    const length = end - start;
    if (length > std.math.maxInt(u32)) return error.ArtifactResourceLimitExceeded;
    return length;
}

comptime {
    if (HeaderOffset.proof_length + @sizeOf(u32) != header_size)
        @compileError("guest proof-artifact header layout drifted");
    if (verifier_types.COMPOSITION_LOG_SPLIT != 1)
        @compileError("guest proof wire must version a composition split change");
}
