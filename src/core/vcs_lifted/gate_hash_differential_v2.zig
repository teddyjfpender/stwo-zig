//! Cross-path byte qualification for the unselected S31NAT9F candidate.
//!
//! This is a deliberately small, fixed-shape proof fixture, not a PCS proof.
//! Its producer uses native Merkle builders and the low-level framed channel;
//! its consumer decodes proof bytes, verifies Merkle paths, and follows the
//! separate typed Gate event plan. Neither side calls the other's replay code.
const std = @import("std");
const m31 = @import("../fields/m31.zig");
const framed = @import("../channel/framed_bcs_v2.zig");
const events = @import("../channel/paired_gate_event_plan_v2.zig");
const source = @import("blake2s_personalized_source_v2.zig");
const line = @import("blake2s_personalized_line_v2.zig");

const Digest = [32]u8;
const Wire = extern struct {
    source_roots: [4]Digest,
    source_values_le: [4][4]u8,
    source_siblings: [4]Digest,
    line_roots: [2]Digest,
    line_rows_le: [2][16]u8,
    line_siblings: [2]Digest,
    interaction_nonce_le: [8]u8,
    fri_nonce_le: [8]u8,
};

const Receipt = struct {
    digest: Digest,
    next_event: u64,
    lookup: [8]u32,
    gamma: [4]u32,
    oods: [4]u32,
    lambda: [4]u32,
    alphas: [2][4]u32,
    queries: [8]u32,
    pow_prefixes: [2]Digest,
    pow_trials: [2]Digest,
};

const Fixture = struct { wire: Wire, receipt: Receipt };

/// Test-only byte oracle using the standard library BLAKE2s implementation.
/// It does not call the candidate channel's frame constructor.
fn oracleFrame(role: framed.Role, event: u64, parts: []const []const u8) Digest {
    var length: u64 = 0;
    for (parts) |part| length += @intCast(part.len);
    var hash = std.crypto.hash.blake2.Blake2s256.init(.{});
    hash.update("S31BCS2");
    hash.update(&.{@intFromEnum(role)});
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, length, .little);
    hash.update(&word);
    std.mem.writeInt(u64, &word, event, .little);
    hash.update(&word);
    for (parts) |part| hash.update(part);
    var digest: Digest = undefined;
    hash.final(&digest);
    return digest;
}

fn checkPowOracle(before: Digest, barrier: framed.PowBarrier, nonce_le: [8]u8) !void {
    var difficulty_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &difficulty_le, barrier.difficulty, .little);
    const prefix = oracleFrame(.pow_prefix, barrier.prefix_event, &.{ &before, &difficulty_le });
    try std.testing.expectEqualDeep(prefix, barrier.prefix);
    const trial = oracleFrame(.pow_trial, barrier.trial_event, &.{ &prefix, &nonce_le });
    try std.testing.expectEqualDeep(trial, barrier.trialHash(std.mem.readInt(u64, &nonce_le, .little)));
}

fn statement() framed.StatementBinding {
    // Nonzero test-only statement digests. A selected verifier must derive
    // them from a sealed key and checked geometry, not this fixture.
    var descriptors: [4]Digest = undefined;
    for (&descriptors, 0..) |*digest, i| @memset(digest, @intCast(0x40 + i));
    return .{
        .key_digest = [_]u8{0x11} ** 32,
        .circuit_digest = [_]u8{0x22} ** 32,
        .fri_config_digest = [_]u8{0x33} ** 32,
        .source_tree_descriptors = descriptors,
        .line_profile_digest = [_]u8{0x55} ** 32,
    };
}

fn putU32(out: *[4]u8, word: u32) void {
    std.mem.writeInt(u32, out, word, .little);
}

fn putRow(out: *[16]u8, row: [4]u32) void {
    for (row, 0..) |word, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .little);
}

fn getRow(input: [16]u8) [4]u32 {
    var row: [4]u32 = undefined;
    for (&row, 0..) |*word, i| word.* = std.mem.readInt(u32, input[i * 4 ..][0..4], .little);
    return row;
}

fn producerSourceLeaf(word: u32) Digest {
    var hash = source.SourceMerkleHasherV2.defaultWithInitialState();
    hash.updateLeaf(&.{m31.M31.fromCanonical(word)});
    return hash.finalize();
}

fn producerLineLeaf(row: [4]u32) Digest {
    var values: [4]m31.M31 = undefined;
    for (&values, row) |*value, word| value.* = m31.M31.fromCanonical(word);
    var hash = line.LineMerkleHasherV2.defaultWithInitialState();
    hash.updateLeaf(&values);
    return hash.finalize();
}

fn producerDraw(channel: *framed.FramedBcsChannelV2) ![8]u32 {
    try channel.beginChallengeDraw();
    const words = try channel.drawChallengeQM31Limbs();
    try channel.endChallengeDraw();
    return words;
}

fn producerPow(channel: *framed.FramedBcsChannelV2, difficulty: u32, nonce_bytes: *[8]u8) !struct { Digest, Digest } {
    const before = channel.digest;
    const barrier = try channel.beginPow(difficulty);
    var nonce: u64 = 0;
    while (!barrier.accepts(nonce)) : (nonce += 1) {}
    std.mem.writeInt(u64, nonce_bytes, nonce, .little);
    try checkPowOracle(before, barrier, nonce_bytes.*);
    const trial = barrier.trialHash(nonce);
    try channel.acceptPowNonce(nonce);
    const absorbed = oracleFrame(.nonce_absorb, barrier.trial_event + 1, &.{ &before, nonce_bytes });
    try std.testing.expectEqualDeep(absorbed, channel.digest);
    return .{ barrier.prefix, trial };
}

fn produce() !Fixture {
    var wire: Wire = undefined;
    for (0..4) |i| {
        const first: u32 = @intCast(2 * i + 1);
        const left = producerSourceLeaf(first);
        const right = producerSourceLeaf(first + 1);
        wire.source_roots[i] = source.SourceMerkleHasherV2.hashChildren(.{ .left = left, .right = right });
        putU32(&wire.source_values_le[i], first);
        wire.source_siblings[i] = right;
    }
    const left_rows = [2][4]u32{ .{ 1, 2, 3, 4 }, .{ 9, 10, 11, 12 } };
    const right_rows = [2][4]u32{ .{ 5, 6, 7, 8 }, .{ 13, 14, 15, 16 } };
    for (0..2) |i| {
        const left = producerLineLeaf(left_rows[i]);
        const right = producerLineLeaf(right_rows[i]);
        wire.line_roots[i] = line.LineMerkleHasherV2.hashChildren(.{ .left = left, .right = right });
        putRow(&wire.line_rows_le[i], left_rows[i]);
        wire.line_siblings[i] = right;
    }

    const zeros4 = [_]u32{0} ** 4;
    const zeros32 = [_]u32{0} ** 32;
    var channel = framed.FramedBcsChannelV2.init(statement());
    const encoded_statement = statement().encode();
    try std.testing.expectEqualDeep(
        oracleFrame(.statement, 0, &.{&encoded_statement}),
        channel.digest,
    );
    const initial = channel.digest;
    try channel.mixRoot(wire.source_roots[0]);
    try std.testing.expectEqualDeep(
        oracleFrame(.root_absorb, 1, &.{ &initial, &wire.source_roots[0] }),
        channel.digest,
    );
    try channel.mixRoot([_]u8{0x91} ** 32);
    const before_public = channel.digest;
    try channel.mixField(&zeros32);
    const public_bytes = [_]u8{0} ** 128;
    try std.testing.expectEqualDeep(
        oracleFrame(.field_absorb, 3, &.{ &before_public, &public_bytes }),
        channel.digest,
    );
    try channel.mixRoot(wire.source_roots[1]);
    const interaction_pow = try producerPow(&channel, 3, &wire.interaction_nonce_le);
    const lookup = try producerDraw(&channel);
    try channel.mixField(&zeros4);
    try channel.mixRoot(wire.source_roots[2]);
    const gamma = (try producerDraw(&channel))[0..4].*;
    try channel.mixRoot(wire.source_roots[3]);
    const oods = (try producerDraw(&channel))[0..4].*;
    try channel.mixField(&zeros4);
    const lambda = (try producerDraw(&channel))[0..4].*;
    const alpha0 = (try producerDraw(&channel))[0..4].*;
    try channel.mixRoot(wire.line_roots[0]);
    try channel.mixRoot(wire.line_roots[1]);
    const alpha1 = (try producerDraw(&channel))[0..4].*;
    try channel.mixField(&zeros4);
    try channel.mixField(&zeros4);
    const fri_pow = try producerPow(&channel, 4, &wire.fri_nonce_le);
    var query_draw = try channel.beginQueries();
    const query_words = try query_draw.drawRawU32sChecked();
    return .{ .wire = wire, .receipt = .{
        .digest = channel.digest,
        .next_event = channel.next_event,
        .lookup = lookup,
        .gamma = gamma,
        .oods = oods,
        .lambda = lambda,
        .alphas = .{ alpha0, alpha1 },
        .queries = query_words,
        .pow_prefixes = .{ interaction_pow[0], fri_pow[0] },
        .pow_trials = .{ interaction_pow[1], fri_pow[1] },
    } };
}

/// Separate verifier-side source leaf encoding through the standard BLAKE2s
/// implementation; the producer uses SourceMerkleHasherV2's native backend.
fn verifierSourceLeaf(word: u32) !Digest {
    if (word >= m31.Modulus) return error.NonCanonicalSourceWord;
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    var digest: Digest = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&bytes, &digest, .{ .context = source.leaf_context });
    return digest;
}

fn consume(bytes: []const u8) !Receipt {
    if (bytes.len != @sizeOf(Wire)) return error.InvalidWireLength;
    var wire: Wire = undefined;
    @memcpy(std.mem.asBytes(&wire), bytes);
    for (0..4) |i| {
        const word = std.mem.readInt(u32, &wire.source_values_le[i], .little);
        const leaf = try verifierSourceLeaf(word);
        const rebuilt = source.SourceMerkleHasherV2.hashChildren(.{ .left = leaf, .right = wire.source_siblings[i] });
        if (!std.mem.eql(u8, &rebuilt, &wire.source_roots[i])) return error.InvalidSourceOpening;
    }
    for (0..2) |i| {
        const row = getRow(wire.line_rows_le[i]);
        if (!(try line.verifyPath(wire.line_roots[i], &row, 0, 1, &.{wire.line_siblings[i]})))
            return error.InvalidLineOpening;
    }

    const zeros4 = [_]u32{0} ** 4;
    const zeros32 = [_]u32{0} ** 32;
    var plan = try events.PairedGateEventPlanV2.init(statement(), &.{ 2, 1 });
    try plan.mixFixedRoot(wire.source_roots[0]);
    try plan.mixCircuitIdentity([_]u8{0x91} ** 32);
    try plan.mixPublicValues(&zeros32);
    try plan.mixMainRoot(wire.source_roots[1]);
    const interaction_pow = try plan.beginInteractionPow(3);
    const interaction_nonce = std.mem.readInt(u64, &wire.interaction_nonce_le, .little);
    const interaction_trial = interaction_pow.trialHash(interaction_nonce);
    try plan.acceptInteractionNonce(interaction_nonce);
    const lookup = try plan.drawLookupPair();
    try plan.mixInteractionClaim(&zeros4);
    try plan.mixInteractionRoot(wire.source_roots[2]);
    const gamma = try plan.drawCompositionGamma();
    try plan.mixCompositionRoot(wire.source_roots[3]);
    const oods = try plan.drawOodsSeed();
    try plan.mixSampledValues(&zeros4);
    const lambda = try plan.drawBatchLambda();
    const alpha0 = try plan.drawFoldAlpha();
    try plan.mixOriginalLineRoot(wire.line_roots[0]);
    try plan.mixOwnQuotientLineRoot(wire.line_roots[1]);
    const alpha1 = try plan.drawFoldAlpha();
    try plan.mixOriginalTerminalCoefficients(&zeros4);
    try plan.mixOwnQuotientTerminalCoefficients(&zeros4);
    const fri_pow = try plan.beginFriPow(4);
    const fri_nonce = std.mem.readInt(u64, &wire.fri_nonce_le, .little);
    const fri_trial = fri_pow.trialHash(fri_nonce);
    try plan.acceptFriNonce(fri_nonce);
    var query_draw = try plan.beginQueries();
    const query_words = try query_draw.drawRawU32sChecked();
    if (plan.stage != .complete) return error.IncompleteTranscript;
    return .{
        .digest = plan.channel.digest,
        .next_event = plan.channel.next_event,
        .lookup = lookup,
        .gamma = gamma,
        .oods = oods,
        .lambda = lambda,
        .alphas = .{ alpha0, alpha1 },
        .queries = query_words,
        .pow_prefixes = .{ interaction_pow.prefix, fri_pow.prefix },
        .pow_trials = .{ interaction_trial, fri_trial },
    };
}

test "candidate producer bytes authenticate and match separate verifier transcript" {
    const fixture = try produce();
    const expected = fixture.receipt;
    const actual = try consume(std.mem.asBytes(&fixture.wire));
    try std.testing.expectEqualDeep(expected, actual);
    try std.testing.expectEqual(@as(u64, 26), actual.next_event);
    try std.testing.expectEqual(@as(usize, 448), @sizeOf(Wire));
}

test "candidate consumer rejects malformed bytes, role swaps, and both bad PoW nonces" {
    const fixture = try produce();
    const original = std.mem.asBytes(&fixture.wire);
    try std.testing.expectError(error.InvalidWireLength, consume(original[0 .. original.len - 1]));
    var changed = fixture.wire;
    changed.source_values_le[0][0] ^= 1;
    try std.testing.expectError(error.InvalidSourceOpening, consume(std.mem.asBytes(&changed)));
    changed = fixture.wire;
    std.mem.writeInt(u32, &changed.source_values_le[0], m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalSourceWord, consume(std.mem.asBytes(&changed)));
    changed = fixture.wire;
    changed.line_roots[0] = fixture.wire.source_roots[0];
    try std.testing.expectError(error.InvalidLineOpening, consume(std.mem.asBytes(&changed)));
    changed = fixture.wire;
    changed.line_siblings[0] = fixture.wire.line_siblings[1];
    try std.testing.expectError(error.InvalidLineOpening, consume(std.mem.asBytes(&changed)));
    changed = fixture.wire;
    std.mem.writeInt(u32, changed.line_rows_le[0][0..4], m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalRow, consume(std.mem.asBytes(&changed)));

    // Find guaranteed failing nonce mutations rather than assuming nonce+1
    // fails a low-difficulty predicate by chance.
    inline for (.{ "interaction_nonce_le", "fri_nonce_le" }) |name| {
        var rejected = false;
        for (0..100) |candidate| {
            changed = fixture.wire;
            std.mem.writeInt(u64, &@field(changed, name), @intCast(candidate), .little);
            if (consume(std.mem.asBytes(&changed))) |_| {} else |err| {
                if (err == error.InvalidNonce) {
                    rejected = true;
                    break;
                }
                return err;
            }
        }
        try std.testing.expect(rejected);
    }
}
