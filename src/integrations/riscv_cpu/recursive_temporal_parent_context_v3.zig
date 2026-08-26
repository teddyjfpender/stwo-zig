const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const binary_outer = @import("recursive_binary_outer.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");

const recursion = frontend.recursion;
const m31 = @import("stwo_core").fields.m31;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const CONTEXT_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-context-receipt/v3\x00";
pub const Digest = temporal_nonfri.Digest;

pub const ContextReceiptV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    statement_version: u32,
    parent_height: u8,
    padding: [1]u8 = .{0},
    parent_node_index: u64,
    session_id: Digest,
    parent_vk_id: Digest,
    parent_statement_id: Digest,
    pair_context_id: Digest,
    pair_authority_id: Digest,
    adjacency_id: Digest,
    child_lineage_ids: [CHILD_COUNT]Digest,
    child_publication_ids: [CHILD_COUNT]Digest,
    identity: [32]u8,

    pub fn init(
        artifacts: *const binary_outer.TemporalParentArtifactViewV1,
    ) !ContextReceiptV3 {
        try artifacts.validate();
        for (artifacts.children) |child| {
            try child.publication.validate();
            if (child.publication.statement_version !=
                segment_publication.STATEMENT_VERSION)
            {
                return error.ContextAuthorityMismatch;
            }
            _ = try recursion.span_statement.SpanStatement.fromCanonicalWords(
                &child.publication.statement_words,
            );
        }
        const pair = artifacts.pair;
        const authenticated = try pair.authenticatePrepared();
        const authority = &pair.prepared_root.authority_snapshot;
        var result = ContextReceiptV3{
            .statement_version = segment_publication.STATEMENT_VERSION,
            .parent_height = authenticated.pair.parent_height,
            .parent_node_index = authenticated.pair.parent_node_index,
            .session_id = authenticated.pair.session_id,
            .parent_vk_id = authenticated.pair.aggregator_vk_id,
            .parent_statement_id = authenticated.pair.parent_statement_id,
            .pair_context_id = authenticated.pair.context_id,
            .pair_authority_id = pair.authority_id,
            .adjacency_id = pair.adjacency_id,
            .child_lineage_ids = .{
                authority.children[0].lineage_id,
                authority.children[1].lineage_id,
            },
            .child_publication_ids = .{
                artifacts.children[0].publication.publication_id,
                artifacts.children[1].publication.publication_id,
            },
            .identity = undefined,
        };
        result.identity = contextIdentity(&result);
        try result.validateAgainst(artifacts);
        return result;
    }

    pub fn validate(self: *const ContextReceiptV3) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.statement_version == 0 or self.parent_height == 0 or
            !std.mem.allEqual(u8, &self.padding, 0) or
            !std.mem.eql(u8, &self.identity, &contextIdentity(self)))
        {
            return error.ContextAuthorityMismatch;
        }
        inline for (.{
            self.session_id,
            self.parent_vk_id,
            self.parent_statement_id,
            self.pair_context_id,
            self.pair_authority_id,
            self.adjacency_id,
        }) |value| try requireDigest(value);
        for (self.child_lineage_ids) |value| try requireDigest(value);
        for (self.child_publication_ids) |value| try requireDigest(value);
    }

    pub fn validateAgainst(
        self: *const ContextReceiptV3,
        artifacts: *const binary_outer.TemporalParentArtifactViewV1,
    ) !void {
        try self.validate();
        try artifacts.validate();
        const pair = artifacts.pair;
        const authenticated = try pair.authenticatePrepared();
        const authority = &pair.prepared_root.authority_snapshot;
        for (artifacts.children) |child| {
            try child.publication.validate();
            if (child.publication.statement_version != self.statement_version or
                child.publication.statement_version !=
                    segment_publication.STATEMENT_VERSION)
            {
                return error.ContextAuthorityMismatch;
            }
            _ = try recursion.span_statement.SpanStatement.fromCanonicalWords(
                &child.publication.statement_words,
            );
        }
        if (self.statement_version != segment_publication.STATEMENT_VERSION or
            self.parent_height != authenticated.pair.parent_height or
            self.parent_node_index != authenticated.pair.parent_node_index or
            !std.meta.eql(self.session_id, authenticated.pair.session_id) or
            !std.meta.eql(self.parent_vk_id, authenticated.pair.aggregator_vk_id) or
            !std.meta.eql(
                self.parent_statement_id,
                authenticated.pair.parent_statement_id,
            ) or !std.meta.eql(
            self.pair_context_id,
            authenticated.pair.context_id,
        ) or !std.meta.eql(self.pair_authority_id, pair.authority_id) or
            !std.meta.eql(self.adjacency_id, pair.adjacency_id) or
            !std.meta.eql(self.child_lineage_ids, [CHILD_COUNT]Digest{
                authority.children[0].lineage_id,
                authority.children[1].lineage_id,
            }) or !std.meta.eql(
            self.child_publication_ids,
            [CHILD_COUNT]Digest{
                artifacts.children[0].publication.publication_id,
                artifacts.children[1].publication.publication_id,
            },
        )) return error.ContextAuthorityMismatch;
    }
};

/// Mutation-only access for adversarial verifier tests. Production builds
/// expose no constructor which can reseal caller-authored temporal context;
/// the live constructor above remains rooted in the two verified child
/// publications and their prepared pair.
pub const test_support = if (@import("builtin").is_test) struct {
    pub fn reseal(value: *ContextReceiptV3) void {
        value.identity = contextIdentity(value);
    }
} else struct {};

/// Compile-time source and bundle family for one exact admitted outer-proof
fn contextIdentity(value: *const ContextReceiptV3) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTEXT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.statement_version);
    hashInt(&hash, u8, value.parent_height);
    hashInt(&hash, u64, value.parent_node_index);
    inline for (.{
        value.session_id,
        value.parent_vk_id,
        value.parent_statement_id,
        value.pair_context_id,
        value.pair_authority_id,
        value.adjacency_id,
    }) |digest| hashDigest(&hash, digest);
    for (value.child_lineage_ids) |digest| hashDigest(&hash, digest);
    for (value.child_publication_ids) |digest| hashDigest(&hash, digest);
    return hash.finalResult();
}

fn requireDigest(value: Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= m31.Modulus) return error.ContextAuthorityMismatch;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.ContextAuthorityMismatch;
}

fn hashDigest(hash: anytype, value: anytype) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
