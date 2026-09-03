//! Append-only public sidecar for dynamic recursive Ethereum nodes.
//!
//! The frozen 412-word `SpanStatement` remains the execution statement.  It
//! does not contain leaf-local clock/snapshot custody or the dynamically
//! compiled verifier-program identity, so it cannot by itself authorize the
//! selected Ethereum recursion path.  This module keeps that missing public
//! authority in a distinct canonical transport:
//!
//! * a leaf retains the complete MetadataV3 and verifier-minted leaf
//!   descriptor (including VerifiedLinkV3 and the exact preprocessed root),
//!   plus the separately compiled incremental-provider shard authority;
//! * a parent compiler authority binds the ordered child authority/subtree
//!   digests, folded Span statement, verifier program, protocol profile, and
//!   exact preprocessed commitment root.
//!
//! Decoding or compiling either record is not proof acceptance.  Production
//! parent publication stays disabled until a fresh wrapper/parent verifier
//! binds the corresponding proof instance to these values.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const ethereum_leaf =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const provider_mod =
    @import("recursive_temporal_incremental_provider_authority_v1.zig");
const metadata_wire =
    @import("recursive_temporal_node_public_metadata_v2.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const global_v3 = recursion.segment_leaf_local_authority_v3;
const span = recursion.span_statement;
const M31 = core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const METADATA_ENCODED_BYTE_COUNT: usize = metadata_wire.ENCODED_BYTE_COUNT;
pub const LEAF_FIELD_PREIMAGE_BYTE_COUNT: usize = 5424;
pub const PARENT_FIELD_PREIMAGE_BYTE_COUNT: usize = 2008;
pub const LEAF_ENCODED_BYTE_COUNT: usize = 5584;
pub const PARENT_ENCODED_BYTE_COUNT: usize = 2104;
pub const PRODUCTION_PARENT_PUBLICATION = false;

const LINK_DOMAIN =
    "stwo-zig/typed-air/recursive-node-public-link/v2\x00";
const LEAF_SUBTREE_DOMAIN =
    "stwo-zig/typed-air/recursive-node-public-leaf-subtree/v2\x00";
const LEAF_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-node-public-leaf-authority/v2\x00";
const PARENT_SUBTREE_DOMAIN =
    "stwo-zig/typed-air/recursive-node-public-parent-subtree/v2\x00";
const PARENT_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-node-public-parent-authority/v2\x00";
pub const LEAF_SUBTREE_DIGEST_DOMAIN: u32 = 0x4e50_4c32; // "NPL2"
pub const PARENT_SUBTREE_DIGEST_DOMAIN: u32 = 0x4e50_5032; // "NPP2"

pub const KindV2 = enum(u8) {
    ethereum_leaf = 1,
    binary_parent = 2,
};

pub const NodeReferenceV2 = struct {
    height: u8,
    statement_words: span.StatementWords,
    authority_sha256: [32]u8,
    subtree_sha256: [32]u8,
    subtree_digest: channel.Digest,

    pub fn validate(self: *const NodeReferenceV2) !void {
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        );
        if (statement.slots.height != self.height)
            return error.InvalidNodePublicReference;
        try requireSha(self.authority_sha256);
        try requireSha(self.subtree_sha256);
        try requireDigest(self.subtree_digest);
    }
};

/// Full h0 public authority. `descriptor` carries the complete VerifiedLinkV3
/// and fresh-verifier ProgramV2/Tree0 custody; `metadata` retains every field
/// whose native identity was referenced by that link. `provider` binds the
/// entry/exit continuation roots and a possibly multi-shard touched-address
/// transition manifest without requiring a monolithic memory provider.
pub const EthereumLeafAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV2 = .ethereum_leaf,
    height: u8 = 0,
    reserved: u16 = 0,
    descriptor: ethereum_leaf.DescriptorV1,
    metadata: global_v3.MetadataV3,
    provider: provider_mod.ProviderCompilerAuthorityV1,
    metadata_sha256: [32]u8,
    verified_link_sha256: [32]u8,
    subtree_digest: channel.Digest,
    subtree_sha256: [32]u8,
    authority_sha256: [32]u8,

    /// This projection may be called only on the existing fresh-verifier
    /// success edge which minted `descriptor` from the same metadata/link.
    pub fn initFromFreshVerifier(
        descriptor: ethereum_leaf.DescriptorV1,
        metadata: global_v3.MetadataV3,
        provider_input: provider_mod.CompilerInputV1,
    ) !EthereumLeafAuthorityV2 {
        var result = EthereumLeafAuthorityV2{
            .descriptor = descriptor,
            .metadata = metadata,
            .provider = try provider_mod.ProviderCompilerAuthorityV1.compile(
                provider_input,
            ),
            .metadata_sha256 = try metadata_wire.identitySha256(&metadata),
            .verified_link_sha256 = verifiedLinkSha256(
                &descriptor.verified_link,
            ),
            .subtree_digest = undefined,
            .subtree_sha256 = undefined,
            .authority_sha256 = undefined,
        };
        result.subtree_digest = try leafSubtreeDigest(&result);
        result.subtree_sha256 = leafSubtreeIdentity(&result);
        result.authority_sha256 = leafAuthorityIdentity(&result);
        try result.validate();
        try result.provider.validateAgainst(provider_input);
        return result;
    }

    pub fn validate(self: *const EthereumLeafAuthorityV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.kind != .ethereum_leaf or self.height != 0 or
            self.reserved != 0)
        {
            return error.InvalidNodePublicLeaf;
        }
        try self.descriptor.validate();
        try self.metadata.validate();
        try self.provider.validate();
        const metadata_id = try self.metadata.identity();
        if (!std.meta.eql(
            self.descriptor.statement_words,
            self.metadata.base_statement_words,
        ) or !std.meta.eql(
            self.descriptor.global_metadata_id,
            metadata_id,
        ) or !std.meta.eql(
            self.descriptor.verified_link.global_metadata_id,
            metadata_id,
        ) or self.provider.entry_continuation_root !=
            self.metadata.entry.continuation_root or
            self.provider.exit_continuation_root !=
                self.metadata.exit.continuation_root or
            !std.mem.eql(
                u8,
                &self.provider.core_proof_artifact_sha256,
                &self.descriptor.proof_artifact_sha256,
            ) or !std.mem.eql(
            u8,
            &self.provider.core_proof_capture_sha256,
            &self.descriptor.program.proof_capture_sha256,
        ) or !std.mem.eql(
            u8,
            &self.provider.core_capture_identity,
            &self.descriptor.program.capture_identity,
        )) {
            return error.InvalidNodePublicLeaf;
        }
        try validateLinkAgainstMetadata(
            &self.descriptor.verified_link,
            &self.metadata,
        );
        inline for (.{
            self.metadata_sha256,
            self.verified_link_sha256,
            self.subtree_sha256,
            self.authority_sha256,
        }) |value| try requireSha(value);
        try requireDigest(self.subtree_digest);
        const expected_metadata_sha256 = try metadata_wire.identitySha256(
            &self.metadata,
        );
        if (!std.mem.eql(
            u8,
            &self.metadata_sha256,
            &expected_metadata_sha256,
        ) or !std.mem.eql(
            u8,
            &self.verified_link_sha256,
            &verifiedLinkSha256(&self.descriptor.verified_link),
        ) or !std.meta.eql(
            self.subtree_digest,
            try leafSubtreeDigest(self),
        ) or !std.mem.eql(
            u8,
            &self.subtree_sha256,
            &leafSubtreeIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.authority_sha256,
            &leafAuthorityIdentity(self),
        )) return error.InvalidNodePublicLeaf;
    }

    /// Cold re-admission reopens the exact residency plan, provider call plan,
    /// ordered shard proof/claim artifacts, and same-challenge cancellation.
    pub fn validateAgainstProvider(
        self: *const EthereumLeafAuthorityV2,
        provider_input: provider_mod.CompilerInputV1,
    ) !void {
        try self.validate();
        try self.provider.validateAgainst(provider_input);
    }

    pub fn reference(self: *const EthereumLeafAuthorityV2) !NodeReferenceV2 {
        try self.validate();
        return .{
            .height = 0,
            .statement_words = self.descriptor.statement_words,
            .authority_sha256 = self.authority_sha256,
            .subtree_sha256 = self.subtree_sha256,
            .subtree_digest = self.subtree_digest,
        };
    }

    pub fn encodeCanonical(
        self: *const EthereumLeafAuthorityV2,
    ) ![LEAF_ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [LEAF_ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writer.u16Value(self.format_version);
        writer.u16Value(self.schema_version);
        writer.u8Value(@intFromEnum(self.kind));
        writer.u8Value(self.height);
        writer.u16Value(self.reserved);
        const descriptor_bytes = try self.descriptor.encodeCanonical();
        writer.bytesValue(&descriptor_bytes);
        const metadata_bytes = try metadata_wire.encode(&self.metadata);
        writer.bytesValue(&metadata_bytes);
        const provider_bytes = try self.provider.encodeCanonical();
        writer.bytesValue(&provider_bytes);
        inline for (.{
            self.metadata_sha256,
            self.verified_link_sha256,
        }) |value| writer.sha(value);
        writer.digest(self.subtree_digest);
        writer.sha(self.subtree_sha256);
        writer.sha(self.authority_sha256);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !EthereumLeafAuthorityV2 {
        if (bytes.len != LEAF_ENCODED_BYTE_COUNT)
            return error.InvalidNodePublicLeaf;
        var reader = Reader{ .bytes = bytes };
        const result = EthereumLeafAuthorityV2{
            .format_version = reader.u16Value(),
            .schema_version = reader.u16Value(),
            .kind = std.meta.intToEnum(KindV2, reader.u8Value()) catch
                return error.InvalidNodePublicLeaf,
            .height = reader.u8Value(),
            .reserved = reader.u16Value(),
            .descriptor = try ethereum_leaf.DescriptorV1.decodeCanonical(
                reader.take(ethereum_leaf.ENCODED_BYTE_COUNT),
            ),
            .metadata = try metadata_wire.decode(
                reader.take(METADATA_ENCODED_BYTE_COUNT),
            ),
            .provider = try provider_mod.ProviderCompilerAuthorityV1
                .decodeCanonical(reader.take(provider_mod.ENCODED_BYTE_COUNT)),
            .metadata_sha256 = reader.sha(),
            .verified_link_sha256 = reader.sha(),
            .subtree_digest = reader.digest(),
            .subtree_sha256 = reader.sha(),
            .authority_sha256 = reader.sha(),
        };
        if (reader.at != bytes.len) return error.InvalidNodePublicLeaf;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidNodePublicLeaf;
        return result;
    }
};

pub const ParentCompilerInputV2 = struct {
    left: NodeReferenceV2,
    right: NodeReferenceV2,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    protocol_profile_sha256: [32]u8,
    preprocessed_commitment_root: channel.Digest,
};

/// Proof-independent parent public compiler authority. It is intentionally not
/// a verified parent receipt and cannot be promoted while
/// `PRODUCTION_PARENT_PUBLICATION` is false.
pub const ParentCompilerAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV2 = .binary_parent,
    height: u8,
    reserved: u16 = 0,
    statement_words: span.StatementWords,
    statement_sha256: [32]u8,
    child_authority_sha256: [2][32]u8,
    child_subtree_sha256: [2][32]u8,
    child_subtree_digest: [2]channel.Digest,
    air_program_identity: [32]u8,
    verifier_program_authority: [32]u8,
    protocol_profile_sha256: [32]u8,
    preprocessed_commitment_root: channel.Digest,
    subtree_digest: channel.Digest,
    subtree_sha256: [32]u8,
    compiler_authority_sha256: [32]u8,

    pub fn compile(input: ParentCompilerInputV2) !ParentCompilerAuthorityV2 {
        try input.left.validate();
        try input.right.validate();
        if (input.left.height != input.right.height)
            return error.InvalidNodePublicParent;
        const left = try span.SpanStatement.fromCanonicalWords(
            &input.left.statement_words,
        );
        const right = try span.SpanStatement.fromCanonicalWords(
            &input.right.statement_words,
        );
        const parent = try span.SpanStatement.fold(left, right);
        const parent_words = try parent.canonicalWords();
        var result = ParentCompilerAuthorityV2{
            .height = parent.slots.height,
            .statement_words = parent_words,
            .statement_sha256 = statement_plan.statementSha256(&parent_words),
            .child_authority_sha256 = .{
                input.left.authority_sha256,
                input.right.authority_sha256,
            },
            .child_subtree_sha256 = .{
                input.left.subtree_sha256,
                input.right.subtree_sha256,
            },
            .child_subtree_digest = .{
                input.left.subtree_digest,
                input.right.subtree_digest,
            },
            .air_program_identity = input.air_program_identity,
            .verifier_program_authority = input.verifier_program_authority,
            .protocol_profile_sha256 = input.protocol_profile_sha256,
            .preprocessed_commitment_root = input.preprocessed_commitment_root,
            .subtree_digest = undefined,
            .subtree_sha256 = undefined,
            .compiler_authority_sha256 = undefined,
        };
        result.subtree_digest = parentSubtreeDigest(&result);
        result.subtree_sha256 = parentSubtreeIdentity(&result);
        result.compiler_authority_sha256 = parentAuthorityIdentity(&result);
        try result.validateAgainst(input);
        return result;
    }

    pub fn validate(self: *const ParentCompilerAuthorityV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.kind != .binary_parent or self.height == 0 or
            self.reserved != 0)
        {
            return error.InvalidNodePublicParent;
        }
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        );
        if (statement.slots.height != self.height or !std.mem.eql(
            u8,
            &self.statement_sha256,
            &statement_plan.statementSha256(&self.statement_words),
        )) return error.InvalidNodePublicParent;
        inline for (.{
            self.child_authority_sha256[0],
            self.child_authority_sha256[1],
            self.child_subtree_sha256[0],
            self.child_subtree_sha256[1],
            self.air_program_identity,
            self.verifier_program_authority,
            self.protocol_profile_sha256,
            self.subtree_sha256,
            self.compiler_authority_sha256,
        }) |value| try requireSha(value);
        try requireDigest(self.child_subtree_digest[0]);
        try requireDigest(self.child_subtree_digest[1]);
        try requireDigest(self.subtree_digest);
        try requireDigest(self.preprocessed_commitment_root);
        if (!std.meta.eql(
            self.subtree_digest,
            parentSubtreeDigest(self),
        ) or !std.mem.eql(
            u8,
            &self.subtree_sha256,
            &parentSubtreeIdentity(self),
        ) or !std.mem.eql(
            u8,
            &self.compiler_authority_sha256,
            &parentAuthorityIdentity(self),
        )) return error.InvalidNodePublicParent;
    }

    /// Cold reconstruction from trusted child and compiler authorities. A
    /// self-consistent decoded record is never sufficient admission.
    pub fn validateAgainst(
        self: *const ParentCompilerAuthorityV2,
        input: ParentCompilerInputV2,
    ) !void {
        try self.validate();
        const expected = try compileUnchecked(input);
        if (!std.meta.eql(self.*, expected))
            return error.NodePublicParentMismatch;
    }

    pub fn reference(self: *const ParentCompilerAuthorityV2) !NodeReferenceV2 {
        try self.validate();
        return .{
            .height = self.height,
            .statement_words = self.statement_words,
            .authority_sha256 = self.compiler_authority_sha256,
            .subtree_sha256 = self.subtree_sha256,
            .subtree_digest = self.subtree_digest,
        };
    }

    pub fn requireProductionPublication(
        self: *const ParentCompilerAuthorityV2,
    ) !void {
        try self.validate();
        if (!PRODUCTION_PARENT_PUBLICATION)
            return error.VerifiedParentPublicationUnavailable;
    }

    pub fn encodeCanonical(
        self: *const ParentCompilerAuthorityV2,
    ) ![PARENT_ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [PARENT_ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writer.u16Value(self.format_version);
        writer.u16Value(self.schema_version);
        writer.u8Value(@intFromEnum(self.kind));
        writer.u8Value(self.height);
        writer.u16Value(self.reserved);
        for (self.statement_words) |word| writer.u32Value(word.toU32());
        writer.sha(self.statement_sha256);
        for (self.child_authority_sha256) |value| writer.sha(value);
        for (self.child_subtree_sha256) |value| writer.sha(value);
        for (self.child_subtree_digest) |value| writer.digest(value);
        writer.sha(self.air_program_identity);
        writer.sha(self.verifier_program_authority);
        writer.sha(self.protocol_profile_sha256);
        writer.digest(self.preprocessed_commitment_root);
        writer.digest(self.subtree_digest);
        writer.sha(self.subtree_sha256);
        writer.sha(self.compiler_authority_sha256);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !ParentCompilerAuthorityV2 {
        if (bytes.len != PARENT_ENCODED_BYTE_COUNT)
            return error.InvalidNodePublicParent;
        var reader = Reader{ .bytes = bytes };
        var result = ParentCompilerAuthorityV2{
            .format_version = reader.u16Value(),
            .schema_version = reader.u16Value(),
            .kind = std.meta.intToEnum(KindV2, reader.u8Value()) catch
                return error.InvalidNodePublicParent,
            .height = reader.u8Value(),
            .reserved = reader.u16Value(),
            .statement_words = undefined,
            .statement_sha256 = undefined,
            .child_authority_sha256 = undefined,
            .child_subtree_sha256 = undefined,
            .child_subtree_digest = undefined,
            .air_program_identity = undefined,
            .verifier_program_authority = undefined,
            .protocol_profile_sha256 = undefined,
            .preprocessed_commitment_root = undefined,
            .subtree_digest = undefined,
            .subtree_sha256 = undefined,
            .compiler_authority_sha256 = undefined,
        };
        for (&result.statement_words) |*word|
            word.* = try reader.m31Value();
        result.statement_sha256 = reader.sha();
        for (&result.child_authority_sha256) |*value| value.* = reader.sha();
        for (&result.child_subtree_sha256) |*value| value.* = reader.sha();
        for (&result.child_subtree_digest) |*value| value.* = reader.digest();
        result.air_program_identity = reader.sha();
        result.verifier_program_authority = reader.sha();
        result.protocol_profile_sha256 = reader.sha();
        result.preprocessed_commitment_root = reader.digest();
        result.subtree_digest = reader.digest();
        result.subtree_sha256 = reader.sha();
        result.compiler_authority_sha256 = reader.sha();
        if (reader.at != bytes.len) return error.InvalidNodePublicParent;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidNodePublicParent;
        return result;
    }
};

fn compileUnchecked(input: ParentCompilerInputV2) !ParentCompilerAuthorityV2 {
    try input.left.validate();
    try input.right.validate();
    const left = try span.SpanStatement.fromCanonicalWords(
        &input.left.statement_words,
    );
    const right = try span.SpanStatement.fromCanonicalWords(
        &input.right.statement_words,
    );
    const parent = try span.SpanStatement.fold(left, right);
    const words = try parent.canonicalWords();
    var result = ParentCompilerAuthorityV2{
        .height = parent.slots.height,
        .statement_words = words,
        .statement_sha256 = statement_plan.statementSha256(&words),
        .child_authority_sha256 = .{
            input.left.authority_sha256,
            input.right.authority_sha256,
        },
        .child_subtree_sha256 = .{
            input.left.subtree_sha256,
            input.right.subtree_sha256,
        },
        .child_subtree_digest = .{
            input.left.subtree_digest,
            input.right.subtree_digest,
        },
        .air_program_identity = input.air_program_identity,
        .verifier_program_authority = input.verifier_program_authority,
        .protocol_profile_sha256 = input.protocol_profile_sha256,
        .preprocessed_commitment_root = input.preprocessed_commitment_root,
        .subtree_digest = undefined,
        .subtree_sha256 = undefined,
        .compiler_authority_sha256 = undefined,
    };
    result.subtree_digest = parentSubtreeDigest(&result);
    result.subtree_sha256 = parentSubtreeIdentity(&result);
    result.compiler_authority_sha256 = parentAuthorityIdentity(&result);
    try result.validate();
    return result;
}

fn validateLinkAgainstMetadata(
    link: *const recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3,
    metadata: *const global_v3.MetadataV3,
) !void {
    try link.validateHeader();
    if (!std.meta.eql(link.global_metadata_id, try metadata.identity()) or
        link.segment_index != metadata.segment_index or
        link.segment_count != metadata.segment_count or
        link.global_cycle_start != metadata.global_cycle_start or
        link.global_cycle_end != metadata.global_cycle_end or
        link.local_cycle_count != metadata.local_cycle_count or
        link.entry_continuation_root != metadata.entry.continuation_root or
        link.exit_continuation_root != metadata.exit.continuation_root)
    {
        return error.InvalidNodePublicLeaf;
    }
}

fn verifiedLinkSha256(
    link: *const recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LINK_DOMAIN);
    hashInt(&hash, u16, link.format_version);
    hashInt(&hash, u16, link.schema_version);
    inline for (.{
        link.global_metadata_id,
        link.local_authority_id,
        link.local_wire_id,
        link.local_receipt_id,
    }) |value| hashDigest(&hash, value);
    hashInt(&hash, u32, link.segment_index);
    hashInt(&hash, u32, link.segment_count);
    hashInt(&hash, u64, link.global_cycle_start);
    hashInt(&hash, u64, link.global_cycle_end);
    hashInt(&hash, u32, link.local_cycle_count);
    hashInt(&hash, u32, link.entry_continuation_root);
    hashInt(&hash, u32, link.exit_continuation_root);
    hashDigest(&hash, link.identity);
    return hash.finalResult();
}

fn leafSubtreeIdentity(value: *const EthereumLeafAuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LEAF_SUBTREE_DOMAIN);
    hash.update(&value.descriptor.subtree_sha256);
    hash.update(&value.descriptor.descriptor_sha256);
    hash.update(&value.metadata_sha256);
    hash.update(&value.verified_link_sha256);
    hash.update(&value.provider.compiler_authority_sha256);
    hashDigest(&hash, value.provider.shard_manifest_digest);
    hashDigest(&hash, value.provider.aggregate_cancellation_digest);
    hashDigest(&hash, value.subtree_digest);
    hash.update(&value.descriptor.program.verifier_program_authority);
    hashDigest(&hash, value.descriptor.program.preprocessed_commitment_root);
    return hash.finalResult();
}

fn leafAuthorityIdentity(value: *const EthereumLeafAuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LEAF_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u8, value.height);
    hash.update(&value.descriptor.descriptor_sha256);
    hash.update(&value.metadata_sha256);
    hash.update(&value.verified_link_sha256);
    hash.update(&value.provider.compiler_authority_sha256);
    hashDigest(&hash, value.subtree_digest);
    hash.update(&value.subtree_sha256);
    return hash.finalResult();
}

fn parentSubtreeIdentity(value: *const ParentCompilerAuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PARENT_SUBTREE_DOMAIN);
    hash.update(&value.child_authority_sha256[0]);
    hash.update(&value.child_subtree_sha256[0]);
    hashDigest(&hash, value.child_subtree_digest[0]);
    hash.update(&value.child_authority_sha256[1]);
    hash.update(&value.child_subtree_sha256[1]);
    hashDigest(&hash, value.child_subtree_digest[1]);
    hash.update(&value.statement_sha256);
    hash.update(&value.air_program_identity);
    hash.update(&value.verifier_program_authority);
    hash.update(&value.protocol_profile_sha256);
    hashDigest(&hash, value.preprocessed_commitment_root);
    hashDigest(&hash, value.subtree_digest);
    return hash.finalResult();
}

fn parentAuthorityIdentity(value: *const ParentCompilerAuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PARENT_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u8, value.height);
    hash.update(&value.statement_sha256);
    hashDigest(&hash, value.subtree_digest);
    hash.update(&value.subtree_sha256);
    return hash.finalResult();
}

fn leafSubtreeDigest(
    value: *const EthereumLeafAuthorityV2,
) !channel.Digest {
    var bytes: [LEAF_FIELD_PREIMAGE_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromEnum(value.kind));
    writer.u8Value(value.height);
    writer.u16Value(value.reserved);
    const descriptor_bytes = try value.descriptor.encodeCanonical();
    writer.bytesValue(&descriptor_bytes);
    const metadata_bytes = try metadata_wire.encode(&value.metadata);
    writer.bytesValue(&metadata_bytes);
    const provider_bytes = try value.provider.encodeCanonical();
    writer.bytesValue(&provider_bytes);
    std.debug.assert(writer.at == bytes.len);
    return channel.hashBytes(&bytes, LEAF_SUBTREE_DIGEST_DOMAIN);
}

fn parentSubtreeDigest(value: *const ParentCompilerAuthorityV2) channel.Digest {
    var bytes: [PARENT_FIELD_PREIMAGE_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromEnum(value.kind));
    writer.u8Value(value.height);
    writer.u16Value(value.reserved);
    for (value.statement_words) |word| writer.u32Value(word.toU32());
    writer.sha(value.statement_sha256);
    for (value.child_authority_sha256) |item| writer.sha(item);
    for (value.child_subtree_sha256) |item| writer.sha(item);
    for (value.child_subtree_digest) |item| writer.digest(item);
    writer.sha(value.air_program_identity);
    writer.sha(value.verifier_program_authority);
    writer.sha(value.protocol_profile_sha256);
    writer.digest(value.preprocessed_commitment_root);
    std.debug.assert(writer.at == bytes.len);
    return channel.hashBytes(&bytes, PARENT_SUBTREE_DIGEST_DOMAIN);
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidNodePublicIdentity;
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= core.fields.m31.Modulus)
            return error.InvalidNodePublicIdentity;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidNodePublicIdentity;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }

    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }

    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }

    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }

    fn sha(self: *Writer, value: [32]u8) void {
        self.bytesValue(&value);
    }

    fn digest(self: *Writer, value: channel.Digest) void {
        for (value) |word| self.u32Value(word);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) []const u8 {
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }

    fn u8Value(self: *Reader) u8 {
        return self.take(1)[0];
    }

    fn u16Value(self: *Reader) u16 {
        return std.mem.readInt(u16, self.take(2)[0..2], .little);
    }

    fn u32Value(self: *Reader) u32 {
        return std.mem.readInt(u32, self.take(4)[0..4], .little);
    }

    fn u64Value(self: *Reader) u64 {
        return std.mem.readInt(u64, self.take(8)[0..8], .little);
    }

    fn m31Value(self: *Reader) !M31 {
        const value = self.u32Value();
        if (value >= core.fields.m31.Modulus)
            return error.InvalidNodePublicIdentity;
        return M31.fromCanonical(value);
    }

    fn sha(self: *Reader) [32]u8 {
        return self.take(32)[0..32].*;
    }

    fn digest(self: *Reader) channel.Digest {
        var result: channel.Digest = undefined;
        for (&result) |*word| word.* = self.u32Value();
        return result;
    }
};

comptime {
    if (SCHEMA_VERSION != 2 or METADATA_ENCODED_BYTE_COUNT != 2112 or
        LEAF_FIELD_PREIMAGE_BYTE_COUNT != 5424 or
        PARENT_FIELD_PREIMAGE_BYTE_COUNT != 2008 or
        LEAF_ENCODED_BYTE_COUNT != 5584 or
        PARENT_ENCODED_BYTE_COUNT != 2104)
    {
        @compileError("recursive node public V2 transport geometry drifted");
    }
}
