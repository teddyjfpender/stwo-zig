//! External verifier-input boundary for the height-2 temporal root.
//!
//! Row 10 consumes both verified parent statements and row 18 consumes the
//! recorder-authenticated Poseidon partial claims. This owner seals those two
//! sources before challenges and evaluates exactly the same tuples afterward.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const level2 = @import("recursive_temporal_parent_pair_authority_v1.zig");
const suffix_mod = @import("recursive_temporal_level2_suffix_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const statement_air = recursion.air.statement_input;
const statement_witness = recursion.air.statement_input_witness;
const universal = recursion.air.universal_challenges;
const rows_source = recursion.binary_fri_outer_source;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const GENERIC_SCHEMA_VERSION: u16 = 2;
pub const CHILD_COUNT: usize = 2;
pub const VERIFIER_INPUT_DOMAIN_INDEX: u8 = 25;
pub const STATEMENT_WORD_COUNT: usize = statement_air.CANONICAL_WORD_COUNT;
pub const STATEMENT_TUPLE_COUNT: u32 = CHILD_COUNT * STATEMENT_WORD_COUNT;
pub const INACTIVE_CLAIM_ITEM_COUNT: u32 = 3;
pub const RECORDER_TUPLE_COUNT: u32 =
    CHILD_COUNT * (INACTIVE_CLAIM_ITEM_COUNT + 2) * 4;

pub const ContextReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    parent_height: u8,
    padding: [3]u8 = .{ 0, 0, 0 },
    parent_node_index: u64,
    pair_authority_id: level2.Digest,
    pair_context_id: level2.Digest,
    pair_node_id: level2.Digest,
    pair_record_id: level2.Digest,
    child_publication_ids: [CHILD_COUNT]level2.Digest,
    identity: [32]u8,

    pub fn init(pair: *const level2.PreparedLevel2PairV1) !ContextReceiptV1 {
        try pair.validate();
        const root = pair.prepared_root.result.pair;
        var result = ContextReceiptV1{
            .schema_version = contextSchema(root.parent_height),
            .parent_height = root.parent_height,
            .parent_node_index = root.parent_node_index,
            .pair_authority_id = pair.authority_id,
            .pair_context_id = root.context_id,
            .pair_node_id = root.node_id,
            .pair_record_id = root.record_id,
            .child_publication_ids = pair.child_publication_ids,
            .identity = undefined,
        };
        result.identity = contextIdentity(&result);
        try result.validateAgainst(pair);
        return result;
    }

    pub fn validate(self: *const ContextReceiptV1) !void {
        if (self.format_version != FORMAT_VERSION or
            (self.schema_version != SCHEMA_VERSION and
                self.schema_version != GENERIC_SCHEMA_VERSION) or
            self.parent_height < level2.FIRST_MULTI_LEVEL_HEIGHT or
            self.schema_version != contextSchema(self.parent_height) or
            !std.mem.allEqual(u8, &self.padding, 0) or
            !std.mem.eql(u8, &self.identity, &contextIdentity(self)))
        {
            return error.ContextAuthorityMismatch;
        }
    }

    pub fn validateAgainst(
        self: *const ContextReceiptV1,
        pair: *const level2.PreparedLevel2PairV1,
    ) !void {
        try self.validate();
        try pair.validate();
        const root = pair.prepared_root.result.pair;
        if (self.parent_height != root.parent_height or
            self.parent_node_index != root.parent_node_index or
            !std.meta.eql(self.pair_authority_id, pair.authority_id) or
            !std.meta.eql(self.pair_context_id, root.context_id) or
            !std.meta.eql(self.pair_node_id, root.node_id) or
            !std.meta.eql(self.pair_record_id, root.record_id) or
            !std.meta.eql(self.child_publication_ids, pair.child_publication_ids))
        {
            return error.ContextAuthorityMismatch;
        }
    }
};

fn contextSchema(parent_height: u8) u16 {
    return if (parent_height == level2.FIRST_MULTI_LEVEL_HEIGHT)
        SCHEMA_VERSION
    else
        GENERIC_SCHEMA_VERSION;
}

pub const AuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    context: ContextReceiptV1,
    statement_boundary: rows_source.PublicBoundaryDescriptor,
    recorder_boundary: rows_source.AuthenticatedRecorderVerifierInputBoundaryDescriptor,
    identity: [32]u8,

    pub fn init(
        pair: *const level2.PreparedLevel2PairV1,
        source: *const suffix_mod.SourceV1,
    ) !AuthorityV1 {
        const context = try ContextReceiptV1.init(pair);
        const statement = try foldStatementBoundary(pair, null);
        const recorder_boundary = try source
            .authenticatedRecorderVerifierInputBoundaryDescriptor();
        var result = AuthorityV1{
            .context = context,
            .statement_boundary = statement.descriptor,
            .recorder_boundary = recorder_boundary,
            .identity = undefined,
        };
        result.identity = authorityIdentity(&result);
        try result.validateAgainst(pair, source);
        return result;
    }

    pub fn validate(self: *const AuthorityV1) !void {
        try self.context.validate();
        try self.recorder_boundary.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.statement_boundary.tuple_count != STATEMENT_TUPLE_COUNT or
            self.recorder_boundary.boundary.tuple_count != RECORDER_TUPLE_COUNT or
            !std.meta.eql(
                self.recorder_boundary.inactive_claim_item_counts,
                [_]u32{INACTIVE_CLAIM_ITEM_COUNT} ** CHILD_COUNT,
            ) or
            !std.mem.eql(u8, &self.identity, &authorityIdentity(self)))
        {
            return error.VerifierInputAuthorityMismatch;
        }
    }

    pub fn validateAgainst(
        self: *const AuthorityV1,
        pair: *const level2.PreparedLevel2PairV1,
        source: *const suffix_mod.SourceV1,
    ) !void {
        try self.validate();
        try self.context.validateAgainst(pair);
        const statement = try foldStatementBoundary(pair, null);
        const recorder = try source
            .authenticatedRecorderVerifierInputBoundaryDescriptor();
        if (!std.meta.eql(self.statement_boundary, statement.descriptor) or
            !std.meta.eql(self.recorder_boundary, recorder))
        {
            return error.VerifierInputAuthorityMismatch;
        }
    }

    pub fn boundaryEvidence(
        self: *const AuthorityV1,
        pair: *const level2.PreparedLevel2PairV1,
        source: *const suffix_mod.SourceV1,
        relations: *const universal.UniversalRelations,
    ) !rows_source.PublicBoundaryEvidence {
        try self.validateAgainst(pair, source);
        const challenge = try relations.getExact(
            .recursion_verifier_input_word,
        );
        const statement = try foldStatementBoundary(pair, challenge);
        const recorder = try source
            .authenticatedRecorderVerifierInputBoundaryEvidence(relations);
        if (!std.meta.eql(statement.descriptor, self.statement_boundary) or
            !std.meta.eql(recorder.descriptor, self.recorder_boundary))
        {
            return error.VerifierInputAuthorityMismatch;
        }
        const tuple_count = std.math.add(
            u32,
            statement.descriptor.tuple_count,
            recorder.descriptor.boundary.tuple_count,
        ) catch return error.ArithmeticOverflow;
        return .{
            .source_authority_id = combinedIdentity(
                "source",
                self,
                tuple_count,
            ),
            .snapshot_id = combinedIdentity("snapshot", self, tuple_count),
            .tuple_provenance_id = combinedIdentity(
                "tuples",
                self,
                tuple_count,
            ),
            .tuple_count = tuple_count,
            .claimed_sum = statement.claimed_sum.add(recorder.claimed_sum),
        };
    }
};

const StatementBoundaryFold = struct {
    descriptor: rows_source.PublicBoundaryDescriptor,
    claimed_sum: QM31,
};

fn foldStatementBoundary(
    pair: *const level2.PreparedLevel2PairV1,
    challenge: ?*const universal.Elements,
) !StatementBoundaryFold {
    try pair.validate();
    const source_id = statementSourceIdentity();
    const snapshot_id = statementSnapshotIdentity(pair);
    var provenance = std.crypto.hash.sha2.Sha256.init(.{});
    provenance.update(
        "stwo-zig/typed-air/recursive-temporal-level2-statement-tuples/v1\x00",
    );
    provenance.update(&source_id);
    provenance.update(&snapshot_id);
    hashInt(&provenance, u8, VERIFIER_INPUT_DOMAIN_INDEX);
    var count: u32 = 0;
    var claim = QM31.zero();
    for (pair.prepared_root.authority_snapshot.children, 0..) |child, index| {
        const verifier_id: u32 = if (index == 0)
            statement_witness.LEFT_RECURSION_VERIFIER_ID
        else
            statement_witness.RIGHT_RECURSION_VERIFIER_ID;
        for (child.statement_words, 0..) |word, word_index| {
            const tuple = [_]QM31{
                QM31.fromBase(M31.fromCanonical(verifier_id)),
                QM31.fromBase(M31.fromCanonical(statement_air.STATEMENT_INPUT_KIND)),
                QM31.fromBase(M31.fromCanonical(statement_air.STATEMENT_INPUT_ITEM)),
                QM31.fromBase(M31.fromCanonical(@intCast(word_index))),
                QM31.fromBase(word),
            };
            if (challenge) |active| {
                const denominator = try active.combineSecure(&tuple);
                claim = claim.add(denominator.inv() catch
                    return error.ZeroDenominator);
            }
            count += 1;
            hashInt(&provenance, u32, verifier_id);
            hashInt(
                &provenance,
                u32,
                @as(u32, @intCast(word_index)),
            );
            hashInt(&provenance, u32, word.toU32());
        }
    }
    if (count != STATEMENT_TUPLE_COUNT) return error.InvalidTupleCount;
    hashInt(&provenance, u32, count);
    return .{
        .descriptor = .{
            .source_authority_id = source_id,
            .snapshot_id = snapshot_id,
            .tuple_provenance_id = provenance.finalResult(),
            .tuple_count = count,
        },
        .claimed_sum = claim,
    };
}

fn contextIdentity(value: *const ContextReceiptV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-level2-context/v1\x00");
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.parent_height);
    hashInt(&hash, u64, value.parent_node_index);
    hashNative(&hash, value.pair_authority_id);
    hashNative(&hash, value.pair_context_id);
    hashNative(&hash, value.pair_node_id);
    hashNative(&hash, value.pair_record_id);
    for (value.child_publication_ids) |item| hashNative(&hash, item);
    return hash.finalResult();
}

fn authorityIdentity(value: *const AuthorityV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/typed-air/recursive-temporal-level2-verifier-input/v1\x00",
    );
    hash.update(&value.context.identity);
    hashDescriptor(&hash, value.statement_boundary);
    hashDescriptor(&hash, value.recorder_boundary.boundary);
    for (value.recorder_boundary.capture_sample_counts) |item|
        hashInt(&hash, u32, item);
    for (value.recorder_boundary.recorder_sample_counts) |item|
        hashInt(&hash, u32, item);
    for (value.recorder_boundary.zero_padding_item_counts) |item|
        hashInt(&hash, u32, item);
    for (value.recorder_boundary.inactive_claim_item_counts) |item|
        hashInt(&hash, u32, item);
    for (value.recorder_boundary.poseidon_partial_claim_ranges) |range| {
        hashInt(&hash, u32, range.start);
        hashInt(&hash, u32, range.end);
    }
    return hash.finalResult();
}

fn statementSourceIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/typed-air/recursive-temporal-level2-statement-source/v1\x00",
    );
    hash.update(&statement_air.SEMANTIC_DIGEST);
    hash.update(&statement_witness.BINDING_DIGEST);
    hashInt(&hash, u32, STATEMENT_WORD_COUNT);
    return hash.finalResult();
}

fn statementSnapshotIdentity(
    pair: *const level2.PreparedLevel2PairV1,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/typed-air/recursive-temporal-level2-statement-snapshot/v1\x00",
    );
    hashNative(&hash, pair.authority_id);
    for (pair.prepared_root.authority_snapshot.children) |child|
        for (child.statement_words) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn combinedIdentity(
    comptime label: []const u8,
    value: *const AuthorityV1,
    tuple_count: u32,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(
        "stwo-zig/typed-air/recursive-temporal-level2-combined-boundary/v1\x00",
    );
    hash.update(label);
    hash.update(&value.identity);
    hashInt(&hash, u32, tuple_count);
    return hash.finalResult();
}

fn hashDescriptor(
    hash: anytype,
    value: rows_source.PublicBoundaryDescriptor,
) void {
    hash.update(&value.source_authority_id);
    hash.update(&value.snapshot_id);
    hash.update(&value.tuple_provenance_id);
    hashInt(hash, u32, value.tuple_count);
}

fn hashNative(hash: anytype, value: level2.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
