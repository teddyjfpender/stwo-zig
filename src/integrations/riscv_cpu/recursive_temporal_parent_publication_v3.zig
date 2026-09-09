const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const suffix_mod = @import("recursive_temporal_parent_suffix_v3.zig");
const child_transcript = @import("recursive_temporal_child_transcript_authority_v1.zig");

const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const FORMAT_VERSION: u16 = 3;
const PUBLICATION_SCHEMA_VERSION: u16 = 1;
const PRODUCTION_ACTIVATION = false;

pub const VerifiedPublicationV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = PUBLICATION_SCHEMA_VERSION,
    statement_version: u32 = frontend.air.public_data_v2.STATEMENT_TRANSCRIPT_VERSION,
    outer_stark_verified: bool = true,
    complete_temporal_parent: bool = true,
    production_activation: bool = PRODUCTION_ACTIVATION,
    padding: [5]u8 = [_]u8{0} ** 5,
    canonical_proof_byte_count: u32,
    proof_id: channel.Digest,
    canonical_proof_sha_id: [32]u8,
    capture_id: channel.Digest,
    transcript_id: channel.Digest,
    transcript_authority: child_transcript.DescriptorV1 =
        .temporalParentV3(),
    transcript_context_sha_id: [32]u8,
    statement_words: recursion.span_statement.StatementWords,
    pair_authority_id: channel.Digest,
    context: suffix_mod.ContextReceiptV3,
    manifest_sha_id: [32]u8,
    claims_sha_id: [32]u8,
    generated_interactions_sha_id: [32]u8,
    audit_sha_id: [32]u8,
    cohort_authority_sha_id: [32]u8,
    closure_receipt_sha_id: [32]u8,
    publication_sha_id: [32]u8,

    pub fn validate(self: *const VerifiedPublicationV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != PUBLICATION_SCHEMA_VERSION or
            self.statement_version !=
                frontend.air.public_data_v2.STATEMENT_TRANSCRIPT_VERSION or
            !self.outer_stark_verified or !self.complete_temporal_parent or
            self.production_activation or self.canonical_proof_byte_count == 0 or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.InvalidPublication;
        }
        try self.context.validate();
        try self.transcript_authority.validate();
        const statement = recursion.span_statement.SpanStatement
            .fromCanonicalWords(&self.statement_words) catch
            return error.InvalidPublication;
        self.transcript_authority.validateForChildHeight(
            statement.slots.height,
        ) catch return error.InvalidPublication;
        try requireSha(self.transcript_context_sha_id);
        if (self.transcript_authority.isLegacyParent() and !std.mem.eql(
            u8,
            &self.transcript_context_sha_id,
            &self.context.identity,
        )) return error.InvalidPublication;
        if (self.statement_version != self.context.statement_version or
            statement.slots.height != self.context.parent_height or
            statement.slots.nodeIndex() != self.context.parent_node_index or
            !std.meta.eql(
                temporalStatementId(&self.statement_words),
                self.context.parent_statement_id,
            ) or !std.meta.eql(
            self.pair_authority_id,
            self.context.pair_authority_id,
        )) return error.InvalidPublication;
        try requireNativeDigest(self.proof_id);
        try requireNativeDigest(self.capture_id);
        try requireNativeDigest(self.transcript_id);
        try requireNativeDigest(self.pair_authority_id);
        inline for (.{
            self.canonical_proof_sha_id,
            self.manifest_sha_id,
            self.claims_sha_id,
            self.generated_interactions_sha_id,
            self.audit_sha_id,
            self.cohort_authority_sha_id,
            self.closure_receipt_sha_id,
            self.publication_sha_id,
        }) |value| try requireSha(value);
        for (self.statement_words) |word|
            if (word.toU32() >= m31.Modulus)
                return error.InvalidPublication;
        if (!std.mem.eql(
            u8,
            &self.publication_sha_id,
            &identity(self),
        )) return error.InvalidPublication;
    }
};

pub fn identity(value: *const VerifiedPublicationV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-parent-publication/v1\x00");
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.statement_version);
    hashInt(&hash, u8, @intFromBool(value.outer_stark_verified));
    hashInt(&hash, u8, @intFromBool(value.complete_temporal_parent));
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.padding);
    hashInt(&hash, u32, value.canonical_proof_byte_count);
    hashNative(&hash, value.proof_id);
    hash.update(&value.canonical_proof_sha_id);
    hashNative(&hash, value.capture_id);
    hashNative(&hash, value.transcript_id);
    if (!value.transcript_authority.isLegacyParent())
        hashTranscriptAuthority(&hash, value.transcript_authority);
    if (!value.transcript_authority.isLegacyParent())
        hash.update(&value.transcript_context_sha_id);
    for (value.statement_words) |word| hashInt(&hash, u32, word.toU32());
    hashNative(&hash, value.pair_authority_id);
    hash.update(&value.context.identity);
    hash.update(&value.manifest_sha_id);
    hash.update(&value.claims_sha_id);
    hash.update(&value.generated_interactions_sha_id);
    hash.update(&value.audit_sha_id);
    hash.update(&value.cohort_authority_sha_id);
    hash.update(&value.closure_receipt_sha_id);
    return hash.finalResult();
}

/// Exercises cross-field publication bindings with fully resealed hostile
/// values. The verifier-only mint remains the authority; these checks ensure
/// a downstream structural validation cannot accept internally inconsistent
/// temporal context even when its SHA seals are recomputed.
pub fn validateMutationFleetForTest(
    publication: VerifiedPublicationV1,
) !void {
    var forged = publication;
    forged.context.pair_authority_id[0] ^= 1;
    suffix_mod.context_test_support.reseal(&forged.context);
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    forged = publication;
    forged.context.parent_statement_id[0] ^= 1;
    suffix_mod.context_test_support.reseal(&forged.context);
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    forged = publication;
    forged.context.statement_version +%= 1;
    suffix_mod.context_test_support.reseal(&forged.context);
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    forged = publication;
    forged.transcript_authority.domain +%= 1;
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    forged = publication;
    forged.transcript_authority.cohort_format_version +%= 1;
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    forged = publication;
    forged.transcript_authority.cohort_schema_version +%= 1;
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    forged = publication;
    forged.transcript_authority.schema_version +%= 1;
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    forged = publication;
    forged.transcript_authority = switch (publication.transcript_authority.kind) {
        .temporal_parent_v3 => .recursiveNodeV1(),
        .recursive_node_v1 => .temporalParentV3(),
        .empty_parent_v1 => .temporalParentV3(),
    };
    forged.publication_sha_id = identity(&forged);
    try expectPublicationRejected(&forged);

    if (publication.transcript_authority.isLegacyParent()) {
        forged = publication;
        forged.transcript_context_sha_id[0] ^= 1;
        forged.publication_sha_id = identity(&forged);
        try expectPublicationRejected(&forged);
    }
}

fn expectPublicationRejected(
    publication: *const VerifiedPublicationV1,
) !void {
    publication.validate() catch return;
    return error.AdversarialMutationAccepted;
}

fn temporalStatementId(
    words: *const recursion.span_statement.StatementWords,
) channel.Digest {
    var canonical: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
        undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return recursion.protocol.statementId(&canonical);
}

fn requireNativeDigest(value: channel.Digest) !void {
    var any = false;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidPublication;
        any = any or word != 0;
    }
    if (!any) return error.InvalidPublication;
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0)) return error.InvalidPublication;
}

fn hashNative(hash: anytype, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashTranscriptAuthority(
    hash: anytype,
    value: child_transcript.DescriptorV1,
) void {
    hash.update("stwo-zig/typed-air/temporal-child-transcript-authority/v1\x00");
    hashInt(hash, u16, value.format_version);
    hashInt(hash, u16, value.schema_version);
    hashInt(hash, u8, @intFromEnum(value.kind));
    hash.update(&value.padding);
    hashInt(hash, u32, value.domain);
    hashInt(hash, u16, value.cohort_format_version);
    hashInt(hash, u16, value.cohort_schema_version);
    hashInt(hash, u16, value.component_count);
    hashInt(hash, u16, value.reserved);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
