//! Native verifier for the isolated direct SHA feed plus committed word LogUp.
//! All eight incoming, terminal, and output words remain verifier-owned.
const std = @import("std");
const core = @import("stwo_core");
const cpu = @import("stwo_circuit_cpu_integration");
const prover = @import("stwo_prover_engine");
const postcard = @import("interop_postcard");
const feed = @import("../air/sha_feed_direct_air.zig");
const word = @import("../air/sha_feed_direct_word_logup.zig");
const bus = @import("../air/sha_direct_word_bus.zig");
const feed_native = @import("sha_feed_direct_native_verifier.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
pub const max_proof_bytes: usize = 1 << 20;

pub fn mixStatement(channel: *MC.Channel, statement: feed.Statement, pcs: core.pcs.config_v2.PcsConfigV2, call_id: u32) void {
    feed_native.mixStatement(channel, statement, pcs);
    channel.mixU64(0x5333_3153_4841_5746);
    channel.mixU64(call_id);
    var digest: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(@embedFile("../air/sha_feed_direct_word_logup.zig"));
    hasher.update(@embedFile("../air/sha_direct_word_bus.zig"));
    hasher.final(&digest);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*slot, i| slot.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}

/// The public-boundary test statement is excluded from the private fixed-key
/// transcript. The isolated test verifier still receives it to check a claim.
pub fn mixPrivateStatement(channel: *MC.Channel, pcs: core.pcs.config_v2.PcsConfigV2, call_id: u32) void {
    const zero_state = [_]u32{0} ** 8;
    mixStatement(channel, .{ .initial = zero_state, .terminal = zero_state, .output = zero_state }, pcs, call_id);
    channel.mixU64(0x5333_3153_4841_4650);
}

fn addTerm(sum: *QM31, elements: bus.Elements, call_id: u32, address: u32, value: u32, sign: i8) !void {
    const id = M31.fromCanonical(call_id);
    const addr = M31.fromCanonical(address);
    const low = M31.fromCanonical(value & 0xffff);
    const high = M31.fromCanonical(value >> 16);
    const inverse = try elements.denominator(M31, bus.tuple(M31, id, addr, low, high)).inv();
    sum.* = sum.add(if (sign < 0) inverse.neg() else inverse);
}

/// Independently computes the feed component's exact signed claim from its
/// verifier-owned boundaries. The joined private proof must instead close
/// this claim against committed caller/round claims.
pub fn expectedClaim(statement: feed.Statement, call_id: u32, elements: bus.Elements) !QM31 {
    if (call_id == 0 or call_id >= core.fields.m31.Modulus) return error.InvalidShaCallId;
    var sum = QM31.zero();
    for (statement.initial, 0..) |value, i| try addTerm(&sum, elements, call_id, @intCast(i), value, -1);
    for (statement.terminal, 0..) |value, i| try addTerm(&sum, elements, call_id, bus.terminal_base + @as(u32, @intCast(i)), value, -1);
    for (statement.output, 0..) |value, i| try addTerm(&sum, elements, call_id, @as(u32, @intCast(24 + i)), value, 1);
    return sum;
}

/// Derive the verifier's expected fixed-column commitment from all public
/// boundary words and PCS settings. The prover cannot choose this root.
pub fn expectedFixedRoot(allocator: std.mem.Allocator, statement: feed.Statement, pcs: core.pcs.config_v2.PcsConfigV2, call_id: u32) ![32]u8 {
    var fixed = try feed.writeFixed(allocator, statement);
    defer fixed.deinit();
    const owned = try allocator.alloc(prover.pcs.ColumnEvaluation, fixed.values.len);
    var ready: usize = 0;
    errdefer {
        for (owned[0..ready]) |column| allocator.free(column.values);
        allocator.free(owned);
    }
    for (fixed.values, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(M31, source.values) };
        ready += 1;
    }
    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs, call_id);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try Engine.commit(&scheme, allocator, owned, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    return scheme.trees.items[0].commitment.root();
}

pub fn expectedPrivateFixedRoot(allocator: std.mem.Allocator, pcs: core.pcs.config_v2.PcsConfigV2, call_id: u32) ![32]u8 {
    var fixed = try feed.writeFixedPrivate(allocator);
    defer fixed.deinit();
    const owned = try allocator.alloc(prover.pcs.ColumnEvaluation, fixed.values.len);
    var ready: usize = 0;
    errdefer {
        for (owned[0..ready]) |column| allocator.free(column.values);
        allocator.free(owned);
    }
    for (fixed.values, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(M31, source.values) };
        ready += 1;
    }
    var channel = MC.Channel{};
    mixPrivateStatement(&channel, pcs, call_id);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try Engine.commit(&scheme, allocator, owned, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    return scheme.trees.items[0].commitment.root();
}

pub fn verifyBytes(
    allocator: std.mem.Allocator,
    statement: feed.Statement,
    pcs: core.pcs.config_v2.PcsConfigV2,
    call_id: u32,
    fixed_root: [32]u8,
    proof_bytes: []const u8,
) !void {
    if (proof_bytes.len > max_proof_bytes) return error.ShaFeedWordProofTooLarge;
    const expected_root = try expectedFixedRoot(allocator, statement, pcs, call_id);
    if (!std.mem.eql(u8, &fixed_root, &expected_root)) return error.WrongShaFeedWordFixedRoot;
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidShaFeedWordProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs))) return error.InvalidShaFeedWordProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaFeedWordFixedRoot;

    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs, call_id);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, fixed_root, &([_]u32{feed.log_size} ** feed.fixed_width), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{feed.log_size} ** feed.main_width), &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    const claim = try expectedClaim(statement, call_id, elements);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{claim});
    try verifier.commit(allocator, roots[2], &([_]u32{feed.log_size} ** word.interaction_width), &channel);
    const feed_component = feed.Component{};
    const word_component = word.Component{ .call_id = call_id, .elements = elements, .claimed_sum = claim };
    const handles = [_]core.air.components.Component{ feed_component.asVerifierComponent(), word_component.asVerifierComponent() };
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}

/// Functional test of private fixed/main geometry. The external statement is
/// supplied only to independently compute the isolated claim; a joined proof
/// must instead authenticate it through the global word-bus closure.
pub fn verifyPrivateBytes(
    allocator: std.mem.Allocator,
    statement: feed.Statement,
    pcs: core.pcs.config_v2.PcsConfigV2,
    call_id: u32,
    proof_bytes: []const u8,
) !void {
    if (proof_bytes.len > max_proof_bytes) return error.ShaFeedWordProofTooLarge;
    const fixed_root = try expectedPrivateFixedRoot(allocator, pcs, call_id);
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidShaFeedWordProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs))) return error.InvalidShaFeedWordProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaFeedWordFixedRoot;
    var channel = MC.Channel{};
    mixPrivateStatement(&channel, pcs, call_id);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, fixed_root, &([_]u32{feed.log_size} ** feed.fixed_width), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{feed.log_size} ** feed.main_width), &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    const claim = try expectedClaim(statement, call_id, elements);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{claim});
    try verifier.commit(allocator, roots[2], &([_]u32{feed.log_size} ** word.interaction_width), &channel);
    const feed_component = feed.Component{ .private_mode = true };
    const word_component = word.Component{ .call_id = call_id, .elements = elements, .claimed_sum = claim };
    const handles = [_]core.air.components.Component{ feed_component.asVerifierComponent(), word_component.asVerifierComponent() };
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}
