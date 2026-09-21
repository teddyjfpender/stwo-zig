//! Fail-closed compiler for the Ethereum leaf's global/local recursion bridge.
//!
//! This value is not a recursive proof and its SHA-256 is transport custody
//! only. The compiler runs on the direct fresh-verifier transaction, reopens
//! the exact SegmentV2 capture and NodePublicAuthorityV2, and retains every
//! field element in the MetadataV3 and VerifiedLinkV3 Poseidon preimages.
//! Production promotion stays unavailable until a recursive AIR consumes
//! those preimages, joins the local receipt identifiers to the verified child,
//! and binds its own freshly verified preprocessed commitment.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const leaf_support = @import("ethereum_block_leaf_support.zig");
const node_public_mod =
    @import("recursive_temporal_node_public_authority_v2.zig");
const provider_mod =
    @import("recursive_temporal_incremental_provider_authority_v1.zig");

const recursion = frontend.recursion;
const source_wire = leaf_support.source_wire;
const global_v3 = recursion.segment_leaf_local_authority_v3;
const link_v3 = recursion.segment_leaf_local_verified_link_v3;
const projection_v3 = recursion.segment_leaf_local_projection_v3;
const span = recursion.span_statement;
const program_v2 = recursion.ethereum_vm_composition_program_v2;
const channel = recursion.poseidon2_channel;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const TRANSCRIPT_CLAIM_COUNT: usize =
    program_v2.TRANSCRIPT_CLAIM_COUNT;
pub const PRODUCTION_RECURSIVE_ACTIVATION = false;

const COMPILER_DOMAIN =
    "stwo-zig/typed-air/ethereum-leaf-bridge-compiler/v1\x00";

comptime {
    if (TRANSCRIPT_CLAIM_COUNT != 42 or
        global_v3.METADATA_IDENTITY_WORDS != 608 or
        link_v3.IDENTITY_WORDS != 50)
    {
        @compileError("Ethereum leaf bridge algebraic geometry drifted");
    }
}

pub const CompilerInputV1 = struct {
    /// Owned capability returned by the successful fresh Poseidon verifier.
    verified: *const leaf_support.VerifiedPoseidonV4,
    source: *const source_wire.Source,
    node_public: *const node_public_mod.EthereumLeafAuthorityV2,
    provider: provider_mod.CompilerInputV1,
};

/// Pointer-free, exact algebraic projection prepared for a future wrapper AIR.
/// `compiler_sha256` detects transport corruption; it is never substituted for
/// the missing in-circuit MetadataV3/VerifiedLinkV3 constraints.
pub const CompiledBridgeV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    metadata: global_v3.MetadataV3,
    metadata_words: global_v3.IdentityWords,
    metadata_identity: channel.Digest,
    verified_link: link_v3.VerifiedLinkV3,
    verified_link_words: link_v3.IdentityWords,
    global_statement_words: span.StatementWords,
    local_statement_words: span.StatementWords,
    transcript_claimed_sums: [TRANSCRIPT_CLAIM_COUNT]QM31,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    protocol_profile_sha256: [32]u8,
    preprocessed_commitment_root: channel.Digest,
    proof_capture_sha256: [32]u8,
    capture_identity: [32]u8,
    program_instance_sha256: [32]u8,
    source_authority_sha256: [32]u8,
    node_public_authority_sha256: [32]u8,
    node_public_subtree_digest: channel.Digest,
    provider_compiler_authority_sha256: [32]u8,
    compiler_sha256: [32]u8,

    pub fn validate(self: *const CompiledBridgeV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidEthereumLeafBridge;
        }
        try self.metadata.validate();
        try self.verified_link.validateHeader();
        const metadata_words = try self.metadata.identityWords();
        const link_words = try self.verified_link.identityWords();
        const expected_local = try projection_v3.localStatementFromMetadata(
            &self.metadata,
        );
        const expected_local_words = try expected_local.canonicalWords();
        if (!std.meta.eql(self.metadata_words, metadata_words) or
            !std.meta.eql(self.metadata_identity, try self.metadata.identity()) or
            !std.meta.eql(self.verified_link_words, link_words) or
            !std.meta.eql(self.metadata_identity, self.verified_link.global_metadata_id) or
            !std.meta.eql(self.verified_link.identity, hashLinkWords(&link_words)) or
            !std.meta.eql(
                self.global_statement_words,
                self.metadata.base_statement_words,
            ) or !std.meta.eql(self.local_statement_words, expected_local_words))
        {
            return error.InvalidEthereumLeafBridge;
        }
        try validateLinkAgainstMetadata(&self.verified_link, &self.metadata);
        _ = try span.SpanStatement.fromCanonicalWords(
            &self.global_statement_words,
        );
        _ = try span.SpanStatement.fromCanonicalWords(
            &self.local_statement_words,
        );
        for (self.transcript_claimed_sums) |value|
            for (value.toM31Array()) |word|
                if (word.toU32() >= core.fields.m31.Modulus)
                    return error.InvalidEthereumLeafBridge;
        inline for (.{
            self.air_program_identity,
            self.verifier_program_authority,
            self.protocol_profile_sha256,
            self.proof_capture_sha256,
            self.capture_identity,
            self.program_instance_sha256,
            self.source_authority_sha256,
            self.node_public_authority_sha256,
            self.provider_compiler_authority_sha256,
            self.compiler_sha256,
        }) |identity_value| try requireSha(identity_value);
        try requireDigest(self.preprocessed_commitment_root);
        try requireDigest(self.node_public_subtree_digest);
        if (!std.mem.eql(
            u8,
            &self.compiler_sha256,
            &compilerIdentity(self),
        )) return error.InvalidEthereumLeafBridge;
    }

    /// Cold re-admission always reconstructs from the fresh-verifier-owned
    /// capture and the complete provider authority; self-sealed transport is
    /// not sufficient.
    pub fn validateAgainst(
        self: *const CompiledBridgeV1,
        input: CompilerInputV1,
    ) !void {
        try self.validate();
        const expected = try compileUnchecked(input);
        if (!std.meta.eql(self.*, expected))
            return error.EthereumLeafBridgeMismatch;
    }

    /// Explicit terminal guard. The next implementation must replace this
    /// error with a freshly verified wrapper AIR receipt, never a SHA check.
    pub fn requireProductionRecursiveAuthority(
        self: *const CompiledBridgeV1,
    ) !void {
        try self.validate();
        if (!PRODUCTION_RECURSIVE_ACTIVATION)
            return error.EthereumLeafLinkAirUnavailable;
    }
};

/// The only public compiler entry consumes the transaction-local verifier
/// capability. It does not mint a parent envelope or verified recursive node.
pub fn compileFromFreshVerifier(
    input: CompilerInputV1,
) !CompiledBridgeV1 {
    const result = try compileUnchecked(input);
    try result.validateAgainst(input);
    return result;
}

fn compileUnchecked(input: CompilerInputV1) !CompiledBridgeV1 {
    try input.verified.validateAgainst(input.source);
    try input.node_public.validateAgainstProvider(input.provider);
    const capture = &input.verified.capture;
    if (!std.meta.eql(input.node_public.descriptor, input.verified.leaf_descriptor) or
        !std.meta.eql(input.node_public.metadata, input.source.metadata) or
        !std.meta.eql(input.node_public.metadata, capture.global_metadata))
    {
        return error.EthereumLeafBridgeMismatch;
    }
    try capture.verified_link.validateAgainst(
        &input.node_public.metadata,
        &capture.base.public_data.data,
        &capture.base.receipt,
    );
    const local_view = try recursion.segment_statement_v2
        .authenticateCanonicalWire(capture.base.public_data.data.words());
    const local_statement = try local_view.statement.base();
    const expected_local = try projection_v3.localStatementFromMetadata(
        &input.node_public.metadata,
    );
    if (!std.meta.eql(local_statement, expected_local) or
        capture.base.receipt.segment_index !=
            input.node_public.metadata.segment_index or
        capture.base.receipt.segment_count !=
            input.node_public.metadata.segment_count or
        capture.base.receipt.global_cycle_start != 0 or
        capture.base.receipt.global_cycle_end !=
            input.node_public.metadata.local_cycle_count)
    {
        return error.EthereumLeafBridgeMismatch;
    }
    const program = &input.verified.verifier_program.program;
    if (program.input_profile.transcript_claimed_sum_count !=
        TRANSCRIPT_CLAIM_COUNT)
    {
        return error.EthereumLeafBridgeMismatch;
    }
    var transcript_claimed_sums: [TRANSCRIPT_CLAIM_COUNT]QM31 = undefined;
    const base_claim_count = capture.base.vm_air.canonical_claims.len;
    if (base_claim_count + capture.extension_context.components.len !=
        transcript_claimed_sums.len)
    {
        return error.EthereumLeafBridgeMismatch;
    }
    @memcpy(
        transcript_claimed_sums[0..base_claim_count],
        &capture.base.vm_air.canonical_claims,
    );
    for (
        capture.extension_context.components,
        transcript_claimed_sums[base_claim_count..],
    ) |component, *destination| destination.* = component.component_sum;

    const metadata_words = try input.node_public.metadata.identityWords();
    const link_words = try capture.verified_link.identityWords();
    const descriptor = &input.node_public.descriptor;
    var result = CompiledBridgeV1{
        .metadata = input.node_public.metadata,
        .metadata_words = metadata_words,
        .metadata_identity = try input.node_public.metadata.identity(),
        .verified_link = capture.verified_link,
        .verified_link_words = link_words,
        .global_statement_words = input.node_public.metadata.base_statement_words,
        .local_statement_words = try local_statement.canonicalWords(),
        .transcript_claimed_sums = transcript_claimed_sums,
        .air_program_identity = descriptor.program.air_program_identity,
        .verifier_program_authority = descriptor.program.verifier_program_authority,
        .protocol_profile_sha256 = descriptor.program.protocol_profile_sha256,
        .preprocessed_commitment_root = descriptor.program.preprocessed_commitment_root,
        .proof_capture_sha256 = descriptor.program.proof_capture_sha256,
        .capture_identity = descriptor.program.capture_identity,
        .program_instance_sha256 = descriptor.program.instance_sha256,
        .source_authority_sha256 = descriptor.source_authority_sha256,
        .node_public_authority_sha256 = input.node_public.authority_sha256,
        .node_public_subtree_digest = input.node_public.subtree_digest,
        .provider_compiler_authority_sha256 = input.node_public.provider.compiler_authority_sha256,
        .compiler_sha256 = undefined,
    };
    result.compiler_sha256 = compilerIdentity(&result);
    try result.validate();
    return result;
}

fn validateLinkAgainstMetadata(
    link: *const link_v3.VerifiedLinkV3,
    metadata: *const global_v3.MetadataV3,
) !void {
    if (link.segment_index != metadata.segment_index or
        link.segment_count != metadata.segment_count or
        link.global_cycle_start != metadata.global_cycle_start or
        link.global_cycle_end != metadata.global_cycle_end or
        link.local_cycle_count != metadata.local_cycle_count or
        link.entry_continuation_root != metadata.entry.continuation_root or
        link.exit_continuation_root != metadata.exit.continuation_root)
    {
        return error.InvalidEthereumLeafBridge;
    }
}

fn hashLinkWords(words: *const link_v3.IdentityWords) channel.Digest {
    return channel.hashCanonicalWords(words, link_v3.IDENTITY_DOMAIN);
}

fn compilerIdentity(value: *const CompiledBridgeV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(COMPILER_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashM31Slice(&hash, &value.metadata_words);
    hashDigest(&hash, value.metadata_identity);
    hashM31Slice(&hash, &value.verified_link_words);
    hashDigest(&hash, value.verified_link.identity);
    hashM31Slice(&hash, &value.global_statement_words);
    hashM31Slice(&hash, &value.local_statement_words);
    for (value.transcript_claimed_sums) |claim|
        hashM31Slice(&hash, &claim.toM31Array());
    inline for (.{
        value.air_program_identity,
        value.verifier_program_authority,
        value.protocol_profile_sha256,
    }) |identity_value| hash.update(&identity_value);
    hashDigest(&hash, value.preprocessed_commitment_root);
    inline for (.{
        value.proof_capture_sha256,
        value.capture_identity,
        value.program_instance_sha256,
        value.source_authority_sha256,
        value.node_public_authority_sha256,
    }) |identity_value| hash.update(&identity_value);
    hashDigest(&hash, value.node_public_subtree_digest);
    hash.update(&value.provider_compiler_authority_sha256);
    return hash.finalResult();
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidEthereumLeafBridge;
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= core.fields.m31.Modulus)
            return error.InvalidEthereumLeafBridge;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidEthereumLeafBridge;
}

fn hashM31Slice(hash: *Sha256, words: []const M31) void {
    for (words) |word| hashInt(hash, u32, word.toU32());
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
