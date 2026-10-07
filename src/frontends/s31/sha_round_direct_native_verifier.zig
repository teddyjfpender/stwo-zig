//! Standalone native verifier for the isolated SHA round AIR test profile.
//! The caller supplies a verifier-pinned fixed-column commitment root derived
//! from the statement schedule and canonical SHA K constants.
const std = @import("std");
const core = @import("stwo_core");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const air = @import("sha_round_direct_air.zig");

const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
pub const max_proof_bytes: usize = 1 << 20;

pub fn mixStatement(channel: *MC.Channel, statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) void {
    channel.mixU64(0x5333_3153_4841_5231);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(@embedFile("sha_round_direct_air.zig"), &digest, .{});
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    pcs.fri_config.mixInto(channel);
    channel.mixU32s(&statement.initial);
    channel.mixU32s(&statement.final);
    channel.mixU32s(&statement.schedule);
}

pub fn verifyBytes(
    allocator: std.mem.Allocator,
    statement: air.Statement,
    pcs: core.pcs.config_v2.PcsConfigV2,
    fixed_root: [32]u8,
    proof_bytes: []const u8,
) !void {
    if (proof_bytes.len > max_proof_bytes) return error.ShaRoundProofTooLarge;
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 3)
        return error.InvalidShaRoundProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidShaRoundProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaRoundFixedRoot;

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
