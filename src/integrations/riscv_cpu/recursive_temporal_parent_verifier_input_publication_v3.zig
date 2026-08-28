//! Authenticated public verifier-input source for one temporal parent.
//!
//! Domain 25 has exactly two genuinely external tuple multisets in the
//! temporal 2-to-1 cohort:
//!
//! * row 10 consumes both verifier-authenticated 412-word child statements;
//! * row 18 consumes only the recorder-authenticated fixed-zero sample padding
//!   and the two sealed Poseidon partial claims for each child.
//!
//! Internal publishers, including row 18's public-wire input, are excluded and
//! close through their ordinary typed interactions.  This module prepares a
//! challenge-independent source authority during cold cohort construction and
//! evaluates exactly those retained tuple sources after the universal relation
//! draw.  It never observes, negates, or otherwise depends on a closure
//! residual.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const prefix_runtime = @import("recursive_temporal_parent_prefix_runtime.zig");
const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const suffix_mod = @import("recursive_temporal_parent_suffix_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const statement_air = recursion.air.statement_input;
const statement_witness = recursion.air.statement_input_witness;
const universal = recursion.air.universal_challenges;
const rows_source = recursion.binary_fri_outer_source;

pub const Digest = pair_authority.Digest;
pub const RecorderSource = suffix_mod.SegmentV2.SourceV3;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const VERIFIER_INPUT_DOMAIN_INDEX: u8 = 25;
pub const STATEMENT_WORD_COUNT: usize = statement_air.CANONICAL_WORD_COUNT;
pub const STATEMENT_TUPLE_COUNT: u32 = CHILD_COUNT * STATEMENT_WORD_COUNT;
pub const CHILD_CAPTURE_SAMPLE_COUNT: u32 = 2_245;
pub const RECORDER_PROFILE_SAMPLE_COUNT: u32 = 2_330;
pub const ZERO_PADDING_ITEM_COUNT: u32 =
    RECORDER_PROFILE_SAMPLE_COUNT - CHILD_CAPTURE_SAMPLE_COUNT;
pub const POSEIDON_PARTIAL_CLAIM_START: u32 = 39;
pub const POSEIDON_PARTIAL_CLAIM_END: u32 = 41;
pub const RECORDER_TUPLE_COUNT: u32 = 696;
pub const TOTAL_TUPLE_COUNT: u32 =
    STATEMENT_TUPLE_COUNT + RECORDER_TUPLE_COUNT;
pub const HOT_AUDIT_HEAP_ALLOCATIONS: usize = 0;
pub const RESIDUAL_DERIVATION_PASSES: usize = 0;
pub const INTERNAL_PUBLIC_WIRE_INCLUDED = false;

pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/temporal-parent-verifier-input-source/v3\x00";
pub const STATEMENT_SOURCE_DOMAIN =
    "stwo-zig/typed-air/temporal-parent-statement-input-source/v3\x00";
pub const STATEMENT_SNAPSHOT_DOMAIN =
    "stwo-zig/typed-air/temporal-parent-statement-input-snapshot/v3\x00";
pub const STATEMENT_TUPLE_DOMAIN =
    "stwo-zig/typed-air/temporal-parent-statement-input-tuples/v3\x00";
pub const COMBINED_SNAPSHOT_DOMAIN =
    "stwo-zig/typed-air/temporal-parent-verifier-input-snapshot/v3\x00";
pub const COMBINED_TUPLE_DOMAIN =
    "stwo-zig/typed-air/temporal-parent-verifier-input-tuples/v3\x00";

pub const Error = error{
    ArithmeticOverflow,
    AuthorityIdentityMismatch,
    AuthorityMismatch,
    ChildIdentityMismatch,
    DuplicateChild,
    InvalidDigest,
    InvalidTupleCount,
    InvalidTupleProvenance,
    SourceMismatch,
    ZeroDenominator,
};

/// Pointer-free, challenge-independent authority prepared from the exact pair
/// and recorder sources retained by the cohort.  The two descriptors identify
/// separate domain-25 multisets; combining their counts or claims before this
/// authority check is intentionally impossible.
pub const AuthorityV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    child_count: u8 = CHILD_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },
    pair_authority_id: Digest,
    pair_context_id: Digest,
    pair_node_id: Digest,
    pair_record_id: Digest,
    child_publication_ids: [CHILD_COUNT]Digest,
    child_capture_ids: [CHILD_COUNT]Digest,
    statement_boundary: rows_source.PublicBoundaryDescriptor,
    recorder_boundary: rows_source.AuthenticatedRecorderVerifierInputBoundaryDescriptor,
    identity: [32]u8,

    /// Cold construction: performs full external-artifact and source
    /// authentication before retaining a pointer-free authority.
    pub fn init(
        inputs: prefix_runtime.RuntimeInputsV1,
        recorder: *const RecorderSource,
    ) !AuthorityV3 {
        const facts = try deriveFacts(inputs, recorder);
        return fromFacts(facts);
    }

    pub fn validate(self: *const AuthorityV3) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.child_count != CHILD_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.statement_boundary.tuple_count != STATEMENT_TUPLE_COUNT or
            self.recorder_boundary.boundary.tuple_count != RECORDER_TUPLE_COUNT)
        {
            return error.InvalidTupleCount;
        }
        inline for (.{
            self.pair_authority_id,
            self.pair_context_id,
            self.pair_node_id,
            self.pair_record_id,
        }) |value| try requireNativeDigest(value);
        for (self.child_publication_ids) |value| try requireNativeDigest(value);
        for (self.child_capture_ids) |value| try requireNativeDigest(value);
        if (std.meta.eql(
            self.child_publication_ids[0],
            self.child_publication_ids[1],
        ) or std.meta.eql(
            self.child_capture_ids[0],
            self.child_capture_ids[1],
        )) return error.DuplicateChild;
        try validateDescriptor(self.statement_boundary);
        try validateRecorderDescriptor(self.recorder_boundary);
        if (!std.mem.eql(u8, &self.identity, &authorityIdentity(self)))
            return error.AuthorityIdentityMismatch;
    }

    /// Re-authenticates the external sources and rejects a stale, reordered,
    /// or coherently resealed authority.  No heap allocation occurs.
    pub fn validateAgainst(
        self: *const AuthorityV3,
        inputs: prefix_runtime.RuntimeInputsV1,
        recorder: *const RecorderSource,
    ) !void {
        const facts = try deriveFacts(inputs, recorder);
        try self.validateAgainstFacts(facts);
    }

    /// Allocation-free post-challenge evaluation of exactly 1,520 source
    /// tuples.  Both evidence values are re-derived from their authenticated
    /// sources and matched against the cold authority before claims combine.
    pub fn boundaryEvidence(
        self: *const AuthorityV3,
        inputs: prefix_runtime.RuntimeInputsV1,
        recorder: *const RecorderSource,
        relations: *const universal.UniversalRelations,
    ) !rows_source.PublicBoundaryEvidence {
        _ = try inputs.validate();
        const statement = try foldStatementBoundary(inputs, try relations.getExact(
            .recursion_verifier_input_word,
        ));
        const recorder_evidence = try recorder
            .authenticatedRecorderVerifierInputBoundaryEvidence(relations);
        const facts = try factsFromValidatedInputs(
            inputs,
            statement.descriptor,
            recorder_evidence.descriptor,
        );
        try self.validateAgainstFacts(facts);
        if (statement.descriptor.tuple_count != STATEMENT_TUPLE_COUNT or
            recorder_evidence.descriptor.boundary.tuple_count !=
                RECORDER_TUPLE_COUNT)
        {
            return error.InvalidTupleCount;
        }

        const tuple_count = std.math.add(
            u32,
            statement.descriptor.tuple_count,
            recorder_evidence.descriptor.boundary.tuple_count,
        ) catch return error.ArithmeticOverflow;
        if (tuple_count != TOTAL_TUPLE_COUNT)
            return error.InvalidTupleCount;
        return .{
            .source_authority_id = combinedSourceAuthorityId(self),
            .snapshot_id = combinedSnapshotId(self),
            .tuple_provenance_id = combinedTupleProvenanceId(self),
            .tuple_count = tuple_count,
            .claimed_sum = statement.claimed_sum.add(
                recorder_evidence.claimed_sum,
            ),
        };
    }

    fn validateAgainstFacts(
        self: *const AuthorityV3,
        facts: SourceFactsV3,
    ) Error!void {
        try self.validate();
        const expected = fromFacts(facts) catch |err| return err;
        if (!std.meta.eql(self.*, expected)) return error.AuthorityMismatch;
    }
};

const SourceFactsV3 = struct {
    pair_authority_id: Digest,
    pair_context_id: Digest,
    pair_node_id: Digest,
    pair_record_id: Digest,
    child_publication_ids: [CHILD_COUNT]Digest,
    child_capture_ids: [CHILD_COUNT]Digest,
    statement_boundary: rows_source.PublicBoundaryDescriptor,
    recorder_boundary: rows_source.AuthenticatedRecorderVerifierInputBoundaryDescriptor,
};

const StatementBoundaryFold = struct {
    descriptor: rows_source.PublicBoundaryDescriptor,
    claimed_sum: QM31,
};

fn deriveFacts(
    inputs: prefix_runtime.RuntimeInputsV1,
    recorder: *const RecorderSource,
) !SourceFactsV3 {
    _ = try inputs.validate();
    const statement = try foldStatementBoundary(inputs, null);
    const recorder_boundary = try recorder
        .authenticatedRecorderVerifierInputBoundaryDescriptor();
    return factsFromValidatedInputs(
        inputs,
        statement.descriptor,
        recorder_boundary,
    );
}

fn factsFromValidatedInputs(
    inputs: prefix_runtime.RuntimeInputsV1,
    statement_boundary: rows_source.PublicBoundaryDescriptor,
    recorder_boundary: rows_source.AuthenticatedRecorderVerifierInputBoundaryDescriptor,
) !SourceFactsV3 {
    const pair = inputs.artifacts.pair;
    const authenticated = try pair.authenticatePrepared();
    const authority = &pair.prepared_root.authority_snapshot;
    var publication_ids: [CHILD_COUNT]Digest = undefined;
    var capture_ids: [CHILD_COUNT]Digest = undefined;
    for (
        inputs.artifacts.children,
        authority.children,
        0..,
    ) |artifact, child, child_index| {
        if (!std.meta.eql(
            artifact.publication.statement_words,
            child.statement_words,
        ) or !std.meta.eql(
            artifact.publication.capture_id,
            child.capture_id,
        )) return error.ChildIdentityMismatch;
        publication_ids[child_index] = artifact.publication.publication_id;
        capture_ids[child_index] = artifact.publication.capture_id;
    }
    if (std.meta.eql(publication_ids[0], publication_ids[1]) or
        std.meta.eql(capture_ids[0], capture_ids[1]))
    {
        return error.DuplicateChild;
    }
    return .{
        .pair_authority_id = pair.authority_id,
        .pair_context_id = authenticated.pair.context_id,
        .pair_node_id = authenticated.pair.node_id,
        .pair_record_id = authenticated.pair.record_id,
        .child_publication_ids = publication_ids,
        .child_capture_ids = capture_ids,
        .statement_boundary = statement_boundary,
        .recorder_boundary = recorder_boundary,
    };
}

fn foldStatementBoundary(
    inputs: prefix_runtime.RuntimeInputsV1,
    challenge: ?*const universal.Elements,
) !StatementBoundaryFold {
    const pair = inputs.artifacts.pair;
    const authority = &pair.prepared_root.authority_snapshot;
    const source_authority_id = statementSourceAuthorityId();
    const snapshot_id = try statementSnapshotId(inputs);
    var provenance = std.crypto.hash.sha2.Sha256.init(.{});
    provenance.update(STATEMENT_TUPLE_DOMAIN);
    provenance.update(&source_authority_id);
    provenance.update(&snapshot_id);
    hashInt(
        &provenance,
        u8,
        VERIFIER_INPUT_DOMAIN_INDEX,
    );

    var tuple_count: u32 = 0;
    var claim = QM31.zero();
    for (authority.children, 0..) |child, child_index| {
        const verifier_id: u32 = switch (child_index) {
            0 => statement_witness.LEFT_RECURSION_VERIFIER_ID,
            1 => statement_witness.RIGHT_RECURSION_VERIFIER_ID,
            else => unreachable,
        };
        for (child.statement_words, 0..) |word, word_index| {
            const tuple = [_]QM31{
                QM31.fromBase(M31.fromCanonical(verifier_id)),
                QM31.fromBase(M31.fromCanonical(
                    statement_air.STATEMENT_INPUT_KIND,
                )),
                QM31.fromBase(M31.fromCanonical(
                    statement_air.STATEMENT_INPUT_ITEM,
                )),
                QM31.fromBase(M31.fromCanonical(@intCast(word_index))),
                QM31.fromBase(word),
            };
            if (challenge) |active_challenge| {
                const denominator = try active_challenge.combineSecure(&tuple);
                claim = claim.add(denominator.inv() catch
                    return error.ZeroDenominator);
            }
            tuple_count = std.math.add(u32, tuple_count, 1) catch
                return error.ArithmeticOverflow;
            hashInt(&provenance, u32, verifier_id);
            hashInt(&provenance, u32, statement_air.STATEMENT_INPUT_KIND);
            hashInt(&provenance, u32, statement_air.STATEMENT_INPUT_ITEM);
            hashInt(&provenance, u32, @as(u32, @intCast(word_index)));
            hashInt(&provenance, u32, word.toU32());
        }
    }
    if (tuple_count != STATEMENT_TUPLE_COUNT)
        return error.InvalidTupleCount;
    hashInt(&provenance, u32, tuple_count);
    return .{
        .descriptor = .{
            .source_authority_id = source_authority_id,
            .snapshot_id = snapshot_id,
            .tuple_provenance_id = provenance.finalResult(),
            .tuple_count = tuple_count,
        },
        .claimed_sum = claim,
    };
}

fn statementSourceAuthorityId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(STATEMENT_SOURCE_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&statement_air.SEMANTIC_DIGEST);
    hash.update(&statement_witness.BINDING_DIGEST);
    hashInt(&hash, u32, @intCast(STATEMENT_WORD_COUNT));
    hashInt(&hash, u32, statement_witness.LEFT_RECURSION_VERIFIER_ID);
    hashInt(&hash, u32, statement_witness.RIGHT_RECURSION_VERIFIER_ID);
    hashInt(&hash, u32, statement_air.STATEMENT_INPUT_KIND);
    hashInt(&hash, u32, statement_air.STATEMENT_INPUT_ITEM);
    return hash.finalResult();
}

fn statementSnapshotId(inputs: prefix_runtime.RuntimeInputsV1) ![32]u8 {
    const pair = inputs.artifacts.pair;
    const authenticated = try pair.authenticatePrepared();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(STATEMENT_SNAPSHOT_DOMAIN);
    hashDigest(&hash, pair.authority_id);
    hashDigest(&hash, authenticated.pair.context_id);
    hashDigest(&hash, authenticated.pair.node_id);
    hashDigest(&hash, authenticated.pair.record_id);
    for (
        inputs.artifacts.children,
        pair.prepared_root.authority_snapshot.children,
    ) |artifact, child| {
        hashDigest(&hash, artifact.publication.publication_id);
        hashDigest(&hash, artifact.publication.capture_id);
        hashDigest(&hash, artifact.publication.statement_id);
        for (child.statement_words) |word|
            hashInt(&hash, u32, word.toU32());
    }
    return hash.finalResult();
}

fn fromFacts(facts: SourceFactsV3) Error!AuthorityV3 {
    var result = AuthorityV3{
        .pair_authority_id = facts.pair_authority_id,
        .pair_context_id = facts.pair_context_id,
        .pair_node_id = facts.pair_node_id,
        .pair_record_id = facts.pair_record_id,
        .child_publication_ids = facts.child_publication_ids,
        .child_capture_ids = facts.child_capture_ids,
        .statement_boundary = facts.statement_boundary,
        .recorder_boundary = facts.recorder_boundary,
        .identity = undefined,
    };
    result.identity = authorityIdentity(&result);
    try result.validate();
    return result;
}

fn authorityIdentity(value: *const AuthorityV3) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SOURCE_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.child_count);
    hash.update(&value.padding);
    hashDigest(&hash, value.pair_authority_id);
    hashDigest(&hash, value.pair_context_id);
    hashDigest(&hash, value.pair_node_id);
    hashDigest(&hash, value.pair_record_id);
    for (value.child_publication_ids) |item| hashDigest(&hash, item);
    for (value.child_capture_ids) |item| hashDigest(&hash, item);
    hashDescriptor(&hash, value.statement_boundary);
    hashRecorderDescriptor(&hash, value.recorder_boundary);
    return hash.finalResult();
}

fn combinedSourceAuthorityId(value: *const AuthorityV3) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SOURCE_AUTHORITY_DOMAIN);
    hash.update(&value.identity);
    hash.update(&value.statement_boundary.source_authority_id);
    hash.update(&value.recorder_boundary.boundary.source_authority_id);
    hashInt(&hash, u32, TOTAL_TUPLE_COUNT);
    return hash.finalResult();
}

fn combinedSnapshotId(value: *const AuthorityV3) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COMBINED_SNAPSHOT_DOMAIN);
    hash.update(&value.identity);
    hashDigest(&hash, value.pair_authority_id);
    hashDigest(&hash, value.pair_context_id);
    hashDigest(&hash, value.pair_node_id);
    hashDigest(&hash, value.pair_record_id);
    for (value.child_publication_ids) |item| hashDigest(&hash, item);
    for (value.child_capture_ids) |item| hashDigest(&hash, item);
    hash.update(&value.statement_boundary.snapshot_id);
    hash.update(&value.recorder_boundary.boundary.snapshot_id);
    return hash.finalResult();
}

fn combinedTupleProvenanceId(value: *const AuthorityV3) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COMBINED_TUPLE_DOMAIN);
    hashInt(
        &hash,
        u8,
        VERIFIER_INPUT_DOMAIN_INDEX,
    );
    for (
        value.child_publication_ids,
        value.child_capture_ids,
    ) |publication_id, capture_id| {
        hashDigest(&hash, publication_id);
        hashDigest(&hash, capture_id);
    }
    hashInt(&hash, u8, 0);
    hashInt(&hash, u32, value.statement_boundary.tuple_count);
    hash.update(&value.statement_boundary.tuple_provenance_id);
    hashInt(&hash, u8, 1);
    hashInt(&hash, u32, value.recorder_boundary.boundary.tuple_count);
    hash.update(&value.recorder_boundary.boundary.tuple_provenance_id);
    hashInt(&hash, u32, TOTAL_TUPLE_COUNT);
    return hash.finalResult();
}

fn validateDescriptor(value: rows_source.PublicBoundaryDescriptor) Error!void {
    try requireShaDigest(value.source_authority_id);
    try requireShaDigest(value.snapshot_id);
    try requireShaDigest(value.tuple_provenance_id);
    if (value.tuple_count == 0) return error.InvalidTupleCount;
}

fn validateRecorderDescriptor(
    value: rows_source.AuthenticatedRecorderVerifierInputBoundaryDescriptor,
) Error!void {
    value.validate() catch |err| switch (err) {
        error.ArithmeticOverflow => return error.ArithmeticOverflow,
        else => return error.InvalidTupleCount,
    };
    try validateDescriptor(value.boundary);
    const expected_capture_counts =
        [_]u32{CHILD_CAPTURE_SAMPLE_COUNT} ** CHILD_COUNT;
    const expected_recorder_counts =
        [_]u32{RECORDER_PROFILE_SAMPLE_COUNT} ** CHILD_COUNT;
    const expected_padding_counts =
        [_]u32{ZERO_PADDING_ITEM_COUNT} ** CHILD_COUNT;
    const expected_inactive_claim_counts = [_]u32{0} ** CHILD_COUNT;
    const expected_partial_ranges =
        [_]rows_source.PublicBoundaryIndexRange{.{
            .start = POSEIDON_PARTIAL_CLAIM_START,
            .end = POSEIDON_PARTIAL_CLAIM_END,
        }} ** CHILD_COUNT;
    if (!std.meta.eql(value.capture_sample_counts, expected_capture_counts) or
        !std.meta.eql(value.recorder_sample_counts, expected_recorder_counts) or
        !std.meta.eql(value.zero_padding_item_counts, expected_padding_counts) or
        !std.meta.eql(
            value.inactive_claim_item_counts,
            expected_inactive_claim_counts,
        ) or
        !std.meta.eql(
            value.poseidon_partial_claim_ranges,
            expected_partial_ranges,
        ))
    {
        return error.InvalidTupleCount;
    }
}

fn requireShaDigest(value: [32]u8) Error!void {
    if (std.mem.allEqual(u8, &value, 0)) return error.InvalidDigest;
}

fn requireNativeDigest(value: Digest) Error!void {
    var nonzero = false;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidDigest;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidDigest;
}

fn hashDescriptor(hash: anytype, value: rows_source.PublicBoundaryDescriptor) void {
    hash.update(&value.source_authority_id);
    hash.update(&value.snapshot_id);
    hash.update(&value.tuple_provenance_id);
    hashInt(hash, u32, value.tuple_count);
}

fn hashRecorderDescriptor(
    hash: anytype,
    value: rows_source.AuthenticatedRecorderVerifierInputBoundaryDescriptor,
) void {
    hashDescriptor(hash, value.boundary);
    for (
        value.capture_sample_counts,
        value.recorder_sample_counts,
        value.zero_padding_item_counts,
        value.inactive_claim_item_counts,
        value.poseidon_partial_claim_ranges,
    ) |capture_count, recorder_count, padding_count, inactive_count, partial_range| {
        hashInt(hash, u32, capture_count);
        hashInt(hash, u32, recorder_count);
        hashInt(hash, u32, padding_count);
        hashInt(hash, u32, inactive_count);
        hashInt(hash, u32, partial_range.start);
        hashInt(hash, u32, partial_range.end);
    }
}

fn hashDigest(hash: anytype, value: Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn testDigest(seed: u32) Digest {
    var result: Digest = undefined;
    for (&result, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn testSha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn testFacts() SourceFactsV3 {
    return .{
        .pair_authority_id = testDigest(10),
        .pair_context_id = testDigest(30),
        .pair_node_id = testDigest(50),
        .pair_record_id = testDigest(70),
        .child_publication_ids = .{ testDigest(100), testDigest(120) },
        .child_capture_ids = .{ testDigest(140), testDigest(160) },
        .statement_boundary = .{
            .source_authority_id = testSha(1),
            .snapshot_id = testSha(2),
            .tuple_provenance_id = testSha(3),
            .tuple_count = STATEMENT_TUPLE_COUNT,
        },
        .recorder_boundary = .{
            .boundary = .{
                .source_authority_id = testSha(4),
                .snapshot_id = testSha(5),
                .tuple_provenance_id = testSha(6),
                .tuple_count = RECORDER_TUPLE_COUNT,
            },
            .capture_sample_counts = [_]u32{CHILD_CAPTURE_SAMPLE_COUNT} ** CHILD_COUNT,
            .recorder_sample_counts = [_]u32{RECORDER_PROFILE_SAMPLE_COUNT} ** CHILD_COUNT,
            .zero_padding_item_counts = [_]u32{ZERO_PADDING_ITEM_COUNT} ** CHILD_COUNT,
            .inactive_claim_item_counts = [_]u32{0} ** CHILD_COUNT,
            .poseidon_partial_claim_ranges = [_]rows_source.PublicBoundaryIndexRange{.{
                .start = POSEIDON_PARTIAL_CLAIM_START,
                .end = POSEIDON_PARTIAL_CLAIM_END,
            }} ** CHILD_COUNT,
        },
    };
}

test "temporal verifier-input authority rejects child swaps after resealing" {
    const facts = testFacts();
    var mutated = try fromFacts(facts);
    std.mem.swap(
        Digest,
        &mutated.child_publication_ids[0],
        &mutated.child_publication_ids[1],
    );
    std.mem.swap(
        Digest,
        &mutated.child_capture_ids[0],
        &mutated.child_capture_ids[1],
    );
    mutated.identity = authorityIdentity(&mutated);
    try mutated.validate();
    try std.testing.expectError(
        error.AuthorityMismatch,
        mutated.validateAgainstFacts(facts),
    );
}

test "temporal verifier-input authority rejects identity and provenance mutations" {
    const facts = testFacts();

    var pair_mutation = try fromFacts(facts);
    pair_mutation.pair_authority_id[0] += 1;
    pair_mutation.identity = authorityIdentity(&pair_mutation);
    try std.testing.expectError(
        error.AuthorityMismatch,
        pair_mutation.validateAgainstFacts(facts),
    );

    var provenance_mutation = try fromFacts(facts);
    provenance_mutation.recorder_boundary.boundary
        .tuple_provenance_id[0] ^= 1;
    provenance_mutation.identity = authorityIdentity(&provenance_mutation);
    try std.testing.expectError(
        error.AuthorityMismatch,
        provenance_mutation.validateAgainstFacts(facts),
    );

    var profile_digest_mutation = try fromFacts(facts);
    profile_digest_mutation.recorder_boundary.boundary
        .source_authority_id[0] ^= 1;
    profile_digest_mutation.identity = authorityIdentity(
        &profile_digest_mutation,
    );
    try profile_digest_mutation.validate();
    try std.testing.expectError(
        error.AuthorityMismatch,
        profile_digest_mutation.validateAgainstFacts(facts),
    );
}

test "temporal verifier-input authority pins both exact tuple counts" {
    const facts = testFacts();
    var mutated = try fromFacts(facts);
    mutated.recorder_boundary.boundary.tuple_count -= 1;
    mutated.identity = authorityIdentity(&mutated);
    try std.testing.expectError(error.InvalidTupleCount, mutated.validate());
    try std.testing.expectEqual(@as(u32, 824), STATEMENT_TUPLE_COUNT);
    try std.testing.expectEqual(@as(u32, 696), RECORDER_TUPLE_COUNT);
    try std.testing.expectEqual(@as(u32, 1_520), TOTAL_TUPLE_COUNT);
}

test "temporal verifier-input authority rejects off-by-one recorder geometry" {
    const facts = testFacts();

    var sample_mutation = try fromFacts(facts);
    sample_mutation.recorder_boundary.capture_sample_counts[0] -= 1;
    sample_mutation.recorder_boundary.zero_padding_item_counts[0] += 1;
    sample_mutation.identity = authorityIdentity(&sample_mutation);
    try std.testing.expectError(
        error.InvalidTupleCount,
        sample_mutation.validate(),
    );

    var profile_mutation = try fromFacts(facts);
    profile_mutation.recorder_boundary.recorder_sample_counts[1] += 1;
    profile_mutation.recorder_boundary.zero_padding_item_counts[1] += 1;
    profile_mutation.recorder_boundary.boundary.tuple_count += 4;
    profile_mutation.identity = authorityIdentity(&profile_mutation);
    try std.testing.expectError(
        error.InvalidTupleCount,
        profile_mutation.validate(),
    );

    var range_mutation = try fromFacts(facts);
    range_mutation.recorder_boundary.poseidon_partial_claim_ranges[0]
        .start -= 1;
    range_mutation.recorder_boundary.poseidon_partial_claim_ranges[0]
        .end -= 1;
    range_mutation.identity = authorityIdentity(&range_mutation);
    try std.testing.expectError(
        error.InvalidTupleCount,
        range_mutation.validate(),
    );
}

comptime {
    if (FORMAT_VERSION != 3 or SCHEMA_VERSION != 1 or CHILD_COUNT != 2 or
        STATEMENT_WORD_COUNT != 412 or STATEMENT_TUPLE_COUNT != 824 or
        CHILD_CAPTURE_SAMPLE_COUNT != 2_245 or
        RECORDER_PROFILE_SAMPLE_COUNT != 2_330 or
        ZERO_PADDING_ITEM_COUNT != 85 or
        POSEIDON_PARTIAL_CLAIM_START != 39 or
        POSEIDON_PARTIAL_CLAIM_END != 41 or
        RECORDER_TUPLE_COUNT != 696 or TOTAL_TUPLE_COUNT != 1_520 or
        HOT_AUDIT_HEAP_ALLOCATIONS != 0 or RESIDUAL_DERIVATION_PASSES != 0 or
        INTERNAL_PUBLIC_WIRE_INCLUDED)
    {
        @compileError("temporal verifier-input publication ABI drifted");
    }
}
