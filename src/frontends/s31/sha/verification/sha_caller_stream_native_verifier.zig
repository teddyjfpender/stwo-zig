//! Native verifier for the isolated 80-row SHA256d caller AIR.
//! Acceptance proves only caller equations. A joint Gate/word lookup proof is
//! required to authenticate the private circuit-to-chip boundary.
const std = @import("std");
const core = @import("stwo_core");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const air = @import("../air/sha_caller_stream_air.zig");

const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
pub const max_proof_bytes: usize = 1 << 20;

pub fn mixStatement(channel: *MC.Channel, statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) void {
    channel.mixU64(0x5333_3143_414c_4c32);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(@embedFile("../air/sha_caller_stream_air.zig"));
    hasher.update(@embedFile("../air/sha_caller_stream_equations.zig"));
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    pcs.fri_config.mixInto(channel);
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, statement.digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    channel.mixU32s(&statement.config.gate_addresses);
    channel.mixU32s(&.{statement.config.first_call_id});
}

/// The serialization envelope carries the statement's initial transcript
/// digest so a wrong public digest or namespace is rejected before PCS work.
/// The same statement is also mixed into the proof transcript below.
pub fn statementTag(statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) [32]u8 {
    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    return channel.digestBytes();
}

pub fn verifyBytes(
    allocator: std.mem.Allocator,
    statement: air.Statement,
    pcs: core.pcs.config_v2.PcsConfigV2,
    fixed_root: [32]u8,
    envelope: []const u8,
) !void {
    try statement.validate();
    if (envelope.len < 32 or envelope.len > max_proof_bytes + 32) return error.ShaCallerProofTooLarge;
    const tag = statementTag(statement, pcs);
    if (!std.mem.eql(u8, envelope[0..32], &tag)) return error.WrongShaCallerStatementTag;
    const proof_bytes = envelope[32..];
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 3)
        return error.InvalidShaCallerProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidShaCallerProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaCallerFixedRoot;

    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, fixed_root, &([_]u32{air.log_size} ** air.fixed_width), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{air.log_size} ** air.main_width), &channel);
    const component = air.Component{ .statement = statement };
    const handles = [_]core.air.components.Component{component.asVerifierComponent()};
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}
