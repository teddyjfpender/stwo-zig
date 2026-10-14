//! Unselected S31NAT9F hash suite for the proposed paired Gate protocol.
//!
//! The transcript and the two Merkle tree classes must travel together. A
//! producer using a plain source root or a line root under the source context
//! cannot reproduce this verifier's path checks or challenges. This module
//! fixes that type-level roster and tests a complete small event replay; it
//! does not install a proof selector or justify a BCS/ROM reduction for the
//! five BLAKE2s parameter/message domains.
const std = @import("std");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const framed = @import("../channel/framed_bcs_v2.zig");
const events = @import("../channel/paired_gate_event_plan_v2.zig");
const source = @import("blake2s_personalized_source_v2.zig");
const line = @import("blake2s_personalized_line_v2.zig");

test {
    _ = @import("gate_hash_differential_v2.zig");
}

pub const proof_magic = framed.reserved_proof_magic;
pub const Statement = framed.StatementBinding;
pub const Transcript = events.PairedGateEventPlanV2;
pub const SourceMerkleHasher = source.SourceMerkleHasherV2;
pub const LineMerkleHasher = line.LineMerkleHasherV2;
pub const Digest32 = framed.Digest32;

/// Source/line personalization is an *effective hash parameter*, rather than
/// bytes prepended to each message. The framed transcript uses BLAKE2s's
/// default personalization and a role/length/event message frame. No
/// selected verifier may replace one member of this roster independently.
pub const merkle_contexts = [4][8]u8{
    source.leaf_context,
    source.parent_context,
    line.leaf_context,
    line.parent_context,
};

comptime {
    if (!std.mem.eql(u8, proof_magic, "S31NAT9F"))
        @compileError("candidate Gate proof selector changed");
    if (!std.mem.eql(u8, framed.domain, "S31BCS2"))
        @compileError("candidate Gate transcript frame changed");
    for (merkle_contexts, 0..) |context, i| {
        if (std.mem.eql(u8, &context, &([_]u8{0} ** 8)))
            @compileError("Merkle role reuses unpersonalized transcript state");
        for (merkle_contexts[0..i]) |earlier| {
            if (std.mem.eql(u8, &context, &earlier))
                @compileError("candidate Gate Merkle roles share personalization");
        }
    }
}

const TwoLeafTree = struct {
    root: Digest32,
    leaves: [2]Digest32,
};

fn sourceTree(first: u32, second: u32) TwoLeafTree {
    var left = SourceMerkleHasher.defaultWithInitialState();
    left.updateLeaf(&.{m31.M31.fromCanonical(first)});
    var right = SourceMerkleHasher.defaultWithInitialState();
    right.updateLeaf(&.{m31.M31.fromCanonical(second)});
    const leaves = [2]Digest32{ left.finalize(), right.finalize() };
    return .{
        .root = SourceMerkleHasher.hashChildren(.{ .left = leaves[0], .right = leaves[1] }),
        .leaves = leaves,
    };
}

fn sourceOpeningMatches(tree: TwoLeafTree, value: u32, sibling: Digest32) bool {
    if (value >= m31.Modulus) return false;
    var leaf = SourceMerkleHasher.defaultWithInitialState();
    leaf.updateLeaf(&.{m31.M31.fromCanonical(value)});
    const rebuilt = SourceMerkleHasher.hashChildren(.{ .left = leaf.finalize(), .right = sibling });
    return std.mem.eql(u8, &rebuilt, &tree.root);
}

fn lineTree(first: [4]u32, second: [4]u32) !TwoLeafTree {
    const leaves = [2]Digest32{
        try line.hashCanonicalRow(&first),
        try line.hashCanonicalRow(&second),
    };
    return .{
        .root = LineMerkleHasher.hashChildren(.{ .left = leaves[0], .right = leaves[1] }),
        .leaves = leaves,
    };
}

const ReplayReceipt = struct {
    digest: Digest32,
    event: u64,
    lookup_pair: [8]u32,
    composition_gamma: [4]u32,
    oods_seed: [4]u32,
    batch_lambda: [4]u32,
    fold_alpha: [2][4]u32,
    query_words: [8]u32,
};

/// Synthetic one-line-pair transcript. This is a byte agreement control, not
/// an accepted AIR/PCS proof. Difficulty zero keeps the test independent of
/// grinding time while still executing both accepted nonce barriers.
fn replay(plan: *Transcript, source_roots: [4]Digest32, line_roots: [2]Digest32) !ReplayReceipt {
    const zeros = [_]u32{0} ** 4;
    const public_values = [_]u32{0} ** 32;
    try plan.mixFixedRoot(source_roots[0]);
    try plan.mixCircuitIdentity([_]u8{0x91} ** 32);
    try plan.mixPublicValues(&public_values);
    try plan.mixMainRoot(source_roots[1]);
    _ = try plan.beginInteractionPow(0);
    try plan.acceptInteractionNonce(0);
    const lookup = try plan.drawLookupPair();
    try plan.mixInteractionClaim(&zeros);
    try plan.mixInteractionRoot(source_roots[2]);
    const gamma = try plan.drawCompositionGamma();
    try plan.mixCompositionRoot(source_roots[3]);
    const oods = try plan.drawOodsSeed();
    try plan.mixSampledValues(&zeros);
    const lambda = try plan.drawBatchLambda();
    const alpha0 = try plan.drawFoldAlpha();
    try plan.mixOriginalLineRoot(line_roots[0]);
    try plan.mixOwnQuotientLineRoot(line_roots[1]);
    const alpha1 = try plan.drawFoldAlpha();
    try plan.mixOriginalTerminalCoefficients(&zeros);
    try plan.mixOwnQuotientTerminalCoefficients(&zeros);
    _ = try plan.beginFriPow(0);
    try plan.acceptFriNonce(0);
    var queries = try plan.beginQueries();
    const words = try queries.drawRawU32sChecked();
    return .{
        .digest = plan.channel.digest,
        .event = plan.channel.next_event,
        .lookup_pair = lookup,
        .composition_gamma = gamma,
        .oods_seed = oods,
        .batch_lambda = lambda,
        .fold_alpha = .{ alpha0, alpha1 },
        .query_words = words,
    };
}

test "candidate Gate hash suite gives producer and verifier identical bytes" {
    const roots = [4]TwoLeafTree{
        sourceTree(1, 2), sourceTree(3, 4), sourceTree(5, 6), sourceTree(7, 8),
    };
    const source_roots = [4]Digest32{ roots[0].root, roots[1].root, roots[2].root, roots[3].root };
    const original = try lineTree(.{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 });
    const quotient = try lineTree(.{ 9, 10, 11, 12 }, .{ 13, 14, 15, 16 });
    const line_roots = [2]Digest32{ original.root, quotient.root };

    // Independently generated with Python hashlib.blake2s(person=...). These
    // pin parameter-block personalization, row endian, and parent order.
    var expected_source: Digest32 = undefined;
    _ = try std.fmt.hexToBytes(&expected_source, "dd821c8622ef8c147bf3987bc6f8d3d34446e9e806fd4e69b7ea6e40cae36f36");
    try std.testing.expectEqualDeep(expected_source, roots[0].root);
    var expected_line: Digest32 = undefined;
    _ = try std.fmt.hexToBytes(&expected_line, "286778eeb8cf7c75aab208b1815c8464a3627406f4f3f261a27ea760a38d7e3b");
    try std.testing.expectEqualDeep(expected_line, original.root);

    // The producer builds leaves and roots; the verifier authenticates each
    // root under the profile's own Merkle role before replaying its events.
    for (roots, 0..) |tree, i| {
        try std.testing.expect(sourceOpeningMatches(tree, @intCast(2 * i + 1), tree.leaves[1]));
        try std.testing.expect(!sourceOpeningMatches(tree, @intCast(2 * i + 2), tree.leaves[1]));
    }
    try std.testing.expect(try line.verifyPath(original.root, &.{ 1, 2, 3, 4 }, 0, 1, &.{original.leaves[1]}));
    try std.testing.expect(try line.verifyPath(quotient.root, &.{ 9, 10, 11, 12 }, 0, 1, &.{quotient.leaves[1]}));
    try std.testing.expect(!(try line.verifyPath(original.root, &.{ 9, 10, 11, 12 }, 0, 1, &.{original.leaves[1]})));
    try std.testing.expect(!(try line.verifyPath(quotient.root, &.{ 9, 10, 11, 12 }, 0, 1, &.{original.leaves[1]})));

    // Legacy plain source roots have different bytes and cannot be reused.
    const plain = @import("blake2_merkle.zig").Blake2sPlainMerkleHasher;
    var plain_leaf = plain.defaultWithInitialState();
    plain_leaf.updateLeaf(&.{m31.M31.fromCanonical(1)});
    const plain_hash = plain_leaf.finalize();
    try std.testing.expect(!std.mem.eql(u8, &roots[0].leaves[0], &plain_hash));

    const zero = [_]u8{0} ** 32;
    const statement = Statement{
        .key_digest = zero,
        .circuit_digest = zero,
        .fri_config_digest = zero,
        .source_tree_descriptors = [_]Digest32{zero} ** 4,
        .line_profile_digest = zero,
    };
    var producer = try Transcript.init(statement, &.{ 2, 1 });
    var verifier = try Transcript.init(statement, &.{ 2, 1 });
    const produced = try replay(&producer, source_roots, line_roots);
    const verified = try replay(&verifier, source_roots, line_roots);
    try std.testing.expectEqualDeep(produced, verified);
    try std.testing.expectEqual(events.Stage.complete, verifier.stage);

    var wrong_roots = source_roots;
    wrong_roots[2][0] ^= 1;
    var wrong_plan = try Transcript.init(statement, &.{ 2, 1 });
    const wrong = try replay(&wrong_plan, wrong_roots, line_roots);
    try std.testing.expect(!std.mem.eql(u8, &verified.digest, &wrong.digest));
    try std.testing.expect(!std.mem.eql(u32, &verified.batch_lambda, &wrong.batch_lambda));
}

test "candidate roles separate legacy equal-input root field and leaf parent cases" {
    const zero = [_]u8{0} ** 32;

    // The raw profile hashes digest||root and digest||two QM31 values with
    // identical BLAKE2s input bytes when all three happen to be zero.
    const Raw = @import("channel_profile.zig").proving_5a7c5ed.Blake2sMerkleChannel;
    var raw_root = Raw.Channel{};
    Raw.mixRoot(&raw_root, zero);
    var raw_field = Raw.Channel{};
    raw_field.mixFelts(&.{ qm31.QM31.zero(), qm31.QM31.zero() });
    try std.testing.expectEqualDeep(raw_root.digestBytes(), raw_field.digestBytes());

    // A 16-word source leaf is also 64 zero bytes, just like a parent made
    // from two zero child hashes, in the raw plain Merkle profile.
    const plain = @import("blake2_merkle.zig").Blake2sPlainMerkleHasher;
    const zero_words = [_]m31.M31{m31.M31.zero()} ** 16;
    var raw_leaf = plain.defaultWithInitialState();
    raw_leaf.updateLeaf(&zero_words);
    const plain_leaf = raw_leaf.finalize();
    const plain_parent = plain.hashChildren(.{ .left = zero, .right = zero });
    try std.testing.expectEqualDeep(plain_leaf, plain_parent);

    // The versioned hash suite gives each of those roles a distinct frame or
    // BLAKE2s personalization parameter. These are byte-profile checks, not
    // a collision-resistance or independent-random-oracle proof.
    const root_frame = framed.hashRoot(zero, 1, zero);
    const field_frame = try framed.hashField(zero, 1, &([_]u32{0} ** 8));
    try std.testing.expect(!std.mem.eql(u8, &root_frame, &field_frame));
    var source_leaf = SourceMerkleHasher.defaultWithInitialState();
    source_leaf.updateLeaf(&zero_words);
    const personalized_leaf = source_leaf.finalize();
    const personalized_parent = SourceMerkleHasher.hashChildren(.{ .left = zero, .right = zero });
    try std.testing.expect(!std.mem.eql(u8, &personalized_leaf, &personalized_parent));
    try std.testing.expect(!std.mem.eql(u8, &personalized_parent, &plain_parent));
}
