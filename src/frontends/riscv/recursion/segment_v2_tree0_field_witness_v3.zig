//! Verifier-owned Tree0 bridge between a base SegmentV2 capture and the
//! transcript frame that absorbed its preprocessed commitment.
//!
//! Native and transcript values are sourced independently from the successful
//! verifier preparation. Exact lookup closure matches their eight limbs; the
//! transcript-frame lookup remains for the V3 wrapper cohort to prove.

const std = @import("std");
const core = @import("stwo_core");
const air = @import("air/segment_v2_tree0_field_link_v3.zig");
const transcript = @import("transcript_program_v2.zig");
const channel = @import("poseidon2_channel.zig");
const universal = @import("air/universal_challenges.zig");
const relation = @import("../air/lang/relation.zig");
const interaction = @import("air/relation_interaction.zig");

const M31 = core.fields.m31.M31;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const TRACE_SIZE: usize = 16;
pub const LOG_SIZE: u32 = 4;
pub const ROOT_DOMAIN = relation.Domain.recursion_verifier_input_word;
pub const ROOT_DOMAIN_MASK: u64 = @as(u64, 1) << @intFromEnum(ROOT_DOMAIN);
pub const Interaction = air.Runtime.Interaction;

pub const WitnessV3 = struct {
    native_root: channel.Digest,
    transcript_root: channel.Digest,
    transcript_hash_id: u32,
    rows: [TRACE_SIZE]air.Row,

    pub fn initFromPrepared(allocator: std.mem.Allocator, prepared: anytype) !WitnessV3 {
        try prepared.validate();
        return fromValidated(allocator, prepared);
    }

    pub fn validateAgainst(self: *const WitnessV3, allocator: std.mem.Allocator, prepared: anytype) !void {
        try prepared.validate();
        const expected = try fromValidated(allocator, prepared);
        if (!std.meta.eql(self.native_root, expected.native_root) or
            !std.meta.eql(self.transcript_root, expected.transcript_root) or
            self.transcript_hash_id != expected.transcript_hash_id)
            return error.Tree0FieldWitnessMismatch;
        for (self.rows, expected.rows) |actual, wanted| {
            for (actual, wanted) |a, b| if (!a.eql(b))
                return error.Tree0FieldWitnessMismatch;
        }
    }

    /// The verifier's challenge bundle determines this component's interaction
    /// columns. Full 47-domain closure is deferred to the wrapper proof.
    pub fn generateInteraction(
        self: *const WitnessV3,
        allocator: std.mem.Allocator,
        relations: *const universal.UniversalRelations,
    ) !Interaction {
        var definition = try air.build(allocator);
        defer definition.deinit();
        const plan = try air.authenticate(&definition);
        var actual = try plan.generateInteraction(
            allocator,
            &definition.arena,
            try air.computeSemanticDigest(allocator),
            definition.events,
            &self.rows,
            LOG_SIZE,
            relations,
        );
        errdefer actual.deinit(allocator);
        try verifyExactNativeTranscriptLookup(allocator, &self.rows);
        return actual;
    }
};

fn fromValidated(allocator: std.mem.Allocator, prepared: anytype) !WitnessV3 {
    const roots = prepared.capture.proof.commitments;
    const mirrored = prepared.captured_fri.trace_roots;
    if (roots.len == 0 or mirrored.len == 0 or
        !std.meta.eql(roots[0], mirrored[0]))
        return error.Tree0FieldRootMismatch;
    const native_root: channel.Digest = roots[0];
    for (native_root) |word| if (word >= core.fields.m31.Modulus)
        return error.Tree0FieldRootMismatch;

    var first_hash_id: ?u32 = null;
    for (prepared.transcript_program.instructions, 0..) |instruction, index| {
        if (instruction.kind != .trace_commitment or instruction.args[0] != 0)
            continue;
        if (first_hash_id != null or index >= prepared.transcript_execution.operations.len)
            return error.Tree0TranscriptFrameMismatch;
        first_hash_id = prepared.transcript_execution.operations[index].first_hash_id;
    }
    const hash_id = first_hash_id orelse return error.Tree0TranscriptFrameMismatch;
    if (hash_id >= prepared.transcript_execution.hash_frames.len)
        return error.Tree0TranscriptFrameMismatch;
    const frame = prepared.transcript_execution.hash_frames[hash_id];
    if (frame.words.len != 2 * transcript.RATE)
        return error.Tree0TranscriptFrameMismatch;
    var transcript_root: channel.Digest = undefined;
    var rows = [_]air.Row{[_]M31{M31.zero()} ** air.LOGICAL_INPUT_COUNT} ** TRACE_SIZE;
    for (0..air.TREE0_WORD_COUNT) |limb| {
        const word = frame.words[transcript.RATE + limb];
        transcript_root[limb] = word.toU32();
        rows[limb] = air.logicalRow(
            M31.fromCanonical(native_root[limb]),
            word,
            1,
            @intCast(limb),
            hash_id,
            @intCast(transcript.RATE + limb),
        );
    }
    try verifyExactNativeTranscriptLookup(allocator, &rows);
    return .{
        .native_root = native_root,
        .transcript_root = transcript_root,
        .transcript_hash_id = hash_id,
        .rows = rows,
    };
}

/// One exact verifier-input tuple per root limb must cancel between the native emitter and
/// transcript consumer. The frame-word consumes must additionally be closed
/// by the transcript-word component in the eventual wrapper transaction.
pub fn verifyExactNativeTranscriptLookup(
    allocator: std.mem.Allocator,
    rows: *const [TRACE_SIZE]air.Row,
) !void {
    var definition = try air.build(allocator);
    defer definition.deinit();
    const plan = try air.authenticate(&definition);
    var ledger = interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(&ledger, 0, rows, ROOT_DOMAIN_MASK);
    const report = ledger.classify();
    if (report.unmatched_by_domain[@intFromEnum(ROOT_DOMAIN)] != 0 or
        report.contribution_count != 2 * air.TREE0_WORD_COUNT)
        return error.Tree0NativeTranscriptLookupMismatch;
}

test "Tree0 typed AIR accepts fixed root row and rejects nonzero padding" {
    const support = @import("air/test_support.zig");
    const lang = @import("../air/lang/mod.zig");
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    const digest = try air.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualStrings(air.SEMANTIC_DIGEST_HEX, &std.fmt.bytesToHex(digest, .lower));
    _ = try air.authenticate(&definition);
    const row = air.logicalRow(M31.fromCanonical(7), M31.fromCanonical(7), 1, 3, 12, 11);
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.arena.constraintsView()) |constraint|
        try std.testing.expect(values[lang.types.idIndex(constraint.root)].isZero());
    var bad = air.logicalRow(M31.zero(), M31.zero(), 0, 0, 0, 0);
    bad[0] = M31.one();
    const mutated = try support.evaluateArena(std.testing.allocator, &definition.arena, &bad);
    defer std.testing.allocator.free(mutated);
    var rejected = false;
    for (definition.arena.constraintsView()) |constraint|
        rejected = rejected or !mutated[lang.types.idIndex(constraint.root)].isZero();
    try std.testing.expect(rejected);
}

test "Tree0 exact lookup rejects a changed transcript limb" {
    var rows = [_]air.Row{[_]M31{M31.zero()} ** air.LOGICAL_INPUT_COUNT} ** TRACE_SIZE;
    for (0..air.TREE0_WORD_COUNT) |limb| {
        const word = M31.fromCanonical(@intCast(limb + 1));
        rows[limb] = air.logicalRow(word, word, 1, @intCast(limb), 12, @intCast(8 + limb));
    }
    try verifyExactNativeTranscriptLookup(std.testing.allocator, &rows);
    const relations = universal.UniversalRelations.dummy();
    const witness = WitnessV3{
        .native_root = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .transcript_root = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .transcript_hash_id = 12,
        .rows = rows,
    };
    var lookup = try witness.generateInteraction(std.testing.allocator, &relations);
    defer lookup.deinit(std.testing.allocator);
    rows[3][1] = rows[3][1].add(M31.one());
    try std.testing.expectError(
        error.Tree0NativeTranscriptLookupMismatch,
        verifyExactNativeTranscriptLookup(std.testing.allocator, &rows),
    );
}
