//! Native verifier for the isolated direct SHA round plus committed word LogUp.
//! The schedule and initial state remain verifier-owned in this test profile.
const std = @import("std");
const core = @import("stwo_core");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const sha = @import("s31_sha_provider").compression;
const round = @import("../air/sha_round_shift_air.zig");
const word = @import("../air/sha_round_shift_word_logup.zig");
const bus = @import("../air/sha_round_shift_word_bus.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
pub const max_proof_bytes: usize = 1 << 20;

pub fn mixStatement(channel: *MC.Channel, statement: round.Statement, pcs: core.pcs.config_v2.PcsConfigV2, call_id: u32) void {
    channel.mixU64(0x5333_3153_4841_5352);
    var air_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(@embedFile("../air/sha_round_shift_air.zig"), &air_digest, .{});
    var air_words: [8]u32 = undefined;
    for (&air_words, 0..) |*slot, i| slot.* = std.mem.readInt(u32, air_digest[4 * i ..][0..4], .little);
    channel.mixU32s(&air_words);
    pcs.fri_config.mixInto(channel);
    channel.mixU32s(&statement.initial);
    channel.mixU32s(&statement.final);
    channel.mixU32s(&statement.schedule);
    channel.mixU64(call_id);
    var digest: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(@embedFile("../air/sha_round_shift_word_logup.zig"));
    hasher.update(@embedFile("../air/sha_round_shift_word_bus.zig"));
    hasher.final(&digest);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*slot, i| slot.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}

fn addTerm(sum: *QM31, elements: bus.Elements, call_id: u32, address: u32, value: u32, sign: i8) !void {
    const id = M31.fromCanonical(call_id);
    const addr = M31.fromCanonical(address);
    const low = M31.fromCanonical(value & 0xffff);
    const high = M31.fromCanonical(value >> 16);
    const inverse = try elements.denominator(M31, bus.tuple(M31, id, addr, low, high)).inv();
    sum.* = sum.add(if (sign < 0) inverse.neg() else inverse);
}

/// Independently computes the round component's exact signed claim from its
/// verifier-owned schedule and initial state. The joined private proof must
/// instead close this claim against committed schedule/caller/feed claims.
pub fn expectedClaim(statement: round.Statement, call_id: u32, elements: bus.Elements) !QM31 {
    if (call_id == 0 or call_id >= core.fields.m31.Modulus) return error.InvalidShaCallId;
    var sum = QM31.zero();
    for (statement.initial, 0..) |value, i| try addTerm(&sum, elements, call_id, @intCast(i), value, -1);
    var state = statement.initial;
    for (statement.schedule, 0..) |value, t| {
        try addTerm(&sum, elements, call_id, bus.schedule_base + @as(u32, @intCast(t)), value, -1);
        state = sha.round(state, value, sha.round_constants[t]);
    }
    if (!std.meta.eql(state, statement.final)) return error.InvalidShaShiftTerminal;
    for (state, 0..) |value, i| try addTerm(&sum, elements, call_id, bus.terminal_base + @as(u32, @intCast(i)), value, 1);
    return sum;
}

pub fn verifyBytes(
    allocator: std.mem.Allocator,
    statement: round.Statement,
    pcs: core.pcs.config_v2.PcsConfigV2,
    call_id: u32,
    fixed_root: [32]u8,
    proof_bytes: []const u8,
) !void {
    return verifyBytesMode(allocator, statement, pcs, call_id, fixed_root, proof_bytes, true);
}

/// The isolated private-mode harness receives the schedule and boundary
/// state from its test statement. In the full joined proof the word claims
/// close against the schedule, caller, and feed components instead.
pub fn verifyBytesMode(
    allocator: std.mem.Allocator,
    statement: round.Statement,
    pcs: core.pcs.config_v2.PcsConfigV2,
    call_id: u32,
    fixed_root: [32]u8,
    proof_bytes: []const u8,
    private_mode: bool,
) !void {
    _ = private_mode;
    if (proof_bytes.len > max_proof_bytes) return error.ShaShiftWordProofTooLarge;
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidShaShiftWordProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs))) return error.InvalidShaShiftWordProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaShiftWordFixedRoot;

    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs, call_id);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, fixed_root, &([_]u32{round.log_size} ** round.fixed_width), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{round.log_size} ** round.main_width), &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    const claim = try expectedClaim(statement, call_id, elements);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{claim});
    try verifier.commit(allocator, roots[2], &([_]u32{round.log_size} ** word.interaction_width), &channel);
    const round_component = round.Component{ .statement = statement };
    const word_component = word.Component{ .call_id = call_id, .elements = elements, .claimed_sum = claim };
    const handles = [_]core.air.components.Component{ round_component.asVerifierComponent(), word_component.asVerifierComponent() };
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}
