//! Append-only `STWGPF01` v2 envelope for joined Ethereum leaf proofs.
//!
//! V1 remains the Poseidon2 profile format. This decoder requires V2 before
//! allocating and binds the base statement, all fourteen extension slots,
//! every detailed claim, and the canonical postcard proof shape.

const std = @import("std");
const core = @import("stwo_core");
const pcs = core.pcs;
const qm31 = core.fields.qm31;
const verifier_types = core.verifier_types;
const postcard = @import("interop_postcard");
const proof_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const base_statement = @import("../../air/statement.zig");
const base_types = @import("../types.zig");
const ethereum_types = @import("ethereum_types.zig");
const framing = @import("proof_artifact_header.zig");
const base_wire = @import("proof_artifact_wire.zig");
const wire = @import("ethereum_proof_artifact_wire.zig");

pub const Limits = base_wire.Limits;
pub const magic = framing.magic;
pub const format_version: u16 = wire.artifact_format_version;
pub const header_size = framing.header_size;
pub const HeaderOffset = framing.Offset;
const sample_width_limits = [4]u32{ 2, 6, 2, 1 };

pub const EncodeInput = struct {
    pcs_config: pcs.PcsConfig,
    statement: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base_claim: *const base_statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    proof: *const base_types.Proof,
};

pub const Decoded = struct {
    pcs_config: pcs.PcsConfig,
    statement: base_statement.RiscVStatement,
    extension: ethereum_statement.Statement,
    identity: wire.Identity,
    base_claim: *base_statement.RiscVInteractionClaim,
    extension_claim: ethereum_types.ExtensionClaim,
    proof: base_types.Proof,
    input_words: []u32,
    output_words: []@import("../../air/public_data.zig").OutputWord,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        self.releaseMetadata(allocator);
    }

    pub fn deinitAfterProofMoved(self: *Decoded, allocator: std.mem.Allocator) void {
        self.releaseMetadata(allocator);
    }

    fn releaseMetadata(self: *Decoded, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base_claim);
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
    try framing.validatePcsConfig(input.pcs_config, limits);
    if (!framing.pcsConfigsEqual(
        input.pcs_config,
        input.proof.commitment_scheme_proof.config,
    )) return error.PcsConfigMismatch;
    try proof_admission.validate(input.statement, input.extension, .proof);
    try input.extension_claim.validate(input.extension);
    _ = try input.base_claim.canonical(input.statement);
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
    try base_wire.encodeStatement(writer, input.statement, limits);
    const statement_length = try sectionLength(output.items.len, statement_start);

    const extension_start = output.items.len;
    try wire.encodeExtension(writer, input.extension);
    const extension_length = try sectionLength(output.items.len, extension_start);
    if (extension_length != wire.extension_encoded_size)
        return error.InvalidExtensionLength;

    const identity_start = output.items.len;
    const identity = wire.Identity.canonical(
        output.items[statement_start..extension_start],
        output.items[extension_start..identity_start],
    );
    try identity.encode(writer);
    const identity_length = try sectionLength(output.items.len, identity_start);
    if (identity_length != wire.identity_encoded_size)
        return error.InvalidIdentityLength;

    const claim_start = output.items.len;
    try wire.encodeClaim(
        writer,
        input.statement,
        input.extension,
        input.base_claim,
        input.extension_claim,
    );
    const claim_length = try sectionLength(output.items.len, claim_start);

    const proof_start = output.items.len;
    try postcard.serializeProof(base_types.Hasher, writer, input.proof.*);
    const proof_length = try sectionLength(output.items.len, proof_start);
    if (proof_length == 0 or proof_length > limits.max_proof_bytes)
        return error.ProofResourceLimitExceeded;
    try postcard.proof_preflight.validate(output.items[proof_start..], shape);
    if (output.items.len > limits.max_artifact_bytes)
        return error.ArtifactResourceLimitExceeded;

    const header = framing.Header{
        .format_version = format_version,
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

pub fn decodeAllocForConfig(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: pcs.PcsConfig,
    limits: Limits,
) !Decoded {
    try limits.validate();
    if (limits.max_artifact_bytes < header_size)
        return error.InvalidResourceLimits;
    const frame = try Frame.parse(bytes, limits);
    if (!framing.pcsConfigsEqual(expected, frame.header.pcs_config))
        return error.PcsConfigMismatch;

    var owned_statement = try base_wire.decodeStatement(
        allocator,
        frame.statement,
        limits,
    );
    var statement_owned = true;
    errdefer if (statement_owned) owned_statement.deinit(allocator);
    const extension = try wire.decodeExtension(frame.extension);
    try proof_admission.validate(&owned_statement.value, &extension, .proof);
    const identity = try wire.Identity.decode(frame.identity);
    try identity.validate(frame.statement, frame.extension);

    var claim = try wire.decodeClaim(
        allocator,
        frame.claim,
        &owned_statement.value,
        &extension,
    );
    var claim_owned = true;
    errdefer if (claim_owned) claim.deinit(allocator);

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
    if (!framing.pcsConfigsEqual(
        frame.header.pcs_config,
        proof.commitment_scheme_proof.config,
    )) return error.PcsConfigMismatch;

    claim_owned = false;
    statement_owned = false;
    return .{
        .pcs_config = frame.header.pcs_config,
        .statement = owned_statement.value,
        .extension = extension,
        .identity = identity,
        .base_claim = claim.base,
        .extension_claim = claim.extension,
        .proof = proof,
        .input_words = owned_statement.input_words,
        .output_words = owned_statement.output_words,
    };
}

pub fn proofPreflightShape(
    config: pcs.PcsConfig,
    statement: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    limits: Limits,
) !postcard.proof_preflight.Shape {
    try limits.validate();
    try framing.validatePcsConfig(config, limits);
    if (statement.n_components > base_statement.MAX_COMPONENTS or
        statement.n_infra > base_statement.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidProofShape;
    }
    try proof_admission.validate(statement, extension, .proof);

    var tree0: u64 = 0;
    var tree1: u64 = 0;
    var tree2: u64 = 0;
    var max_log_size: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        tree0 = try checkedAdd(tree0, 2);
        tree1 = try checkedAdd(tree1, descriptor.n_columns);
        tree2 = try checkedAdd(tree2, @import("../../air/lookups/opcode_interaction.zig").nColumns(descriptor.family));
        max_log_size = @max(max_log_size, descriptor.log_size);
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        tree0 = try checkedAdd(tree0, base_statement.nPreprocessedColumnsForInfra(descriptor.kind));
        tree1 = try checkedAdd(tree1, descriptor.n_columns);
        tree2 = try checkedAdd(tree2, base_statement.nInteractionColsForInfra(descriptor.kind));
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
        .sample_width_limits = sample_width_limits,
        .hash_size = @sizeOf(base_types.Hasher.Hash),
        .max_wire_bytes = limits.max_proof_bytes,
    };
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
            header.extension_length != wire.extension_encoded_size or
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
    if (HeaderOffset.proof_length + @sizeOf(u32) != header_size or
        verifier_types.COMPOSITION_LOG_SPLIT != 1)
    {
        @compileError("Ethereum proof-artifact framing authority drifted");
    }
}
