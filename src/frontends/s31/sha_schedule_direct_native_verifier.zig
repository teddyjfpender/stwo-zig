//! Native verifier for the isolated, verifier-pinned SHA schedule AIR.
//! The fixed commitment root must be independently derived from first_words.
const std = @import("std");
const core = @import("stwo_core");
const cpu = @import("stwo_circuit_cpu_integration");
const prover = @import("stwo_prover_engine");
const postcard = @import("interop_postcard");
const air = @import("sha_schedule_direct_air.zig");

const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const M31 = core.fields.m31.M31;
const Engine = cpu.prove.Internal.Engine;
pub const max_proof_bytes: usize = 1 << 20;

pub fn mixStatement(channel: *MC.Channel, statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) void {
    channel.mixU64(0x5333_3153_4841_5331);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(@embedFile("sha_schedule_direct_air.zig"), &digest, .{});
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    std.crypto.hash.sha2.Sha256.hash(@embedFile("sha_schedule_direct_equations.zig"), &digest, .{});
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    pcs.fri_config.mixInto(channel);
    channel.mixU32s(&statement.first_words);
}

/// Private schedule mode has no public message words. The extra domain tag
/// prevents a public-boundary proof from being interpreted as a private one.
pub fn mixPrivateStatement(channel: *MC.Channel, pcs: core.pcs.config_v2.PcsConfigV2) void {
    mixStatement(channel, .{ .first_words = [_]u32{0} ** 16 }, pcs);
    channel.mixU64(0x5333_3153_4841_5350);
}

/// Derive the fixed root from the exact public statement and PCS config.
/// A verifier must never accept a prover-selected fixed-column commitment.
pub fn expectedFixedRoot(allocator: std.mem.Allocator, statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    var fixed = try air.writeFixed(allocator, statement);
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
    mixStatement(&channel, statement, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try Engine.commit(&scheme, allocator, owned, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    return scheme.trees.items[0].commitment.root();
}

/// The private fixed root contains selectors and row indices only. It is the
/// same for every private block and must be derived by the relying verifier.
pub fn expectedPrivateFixedRoot(allocator: std.mem.Allocator, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    var fixed = try air.writeFixedPrivate(allocator);
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
    mixPrivateStatement(&channel, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try Engine.commit(&scheme, allocator, owned, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    return scheme.trees.items[0].commitment.root();
}

pub fn verifyBytes(allocator: std.mem.Allocator, statement: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2, fixed_root: [32]u8, proof_bytes: []const u8) !void {
    if (proof_bytes.len > max_proof_bytes) return error.ShaScheduleProofTooLarge;
    const expected_root = try expectedFixedRoot(allocator, statement, pcs);
    if (!std.mem.eql(u8, &fixed_root, &expected_root)) return error.WrongShaScheduleFixedRoot;
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 3)
        return error.InvalidShaScheduleProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidShaScheduleProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaScheduleFixedRoot;
    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, fixed_root, &([_]u32{air.log_size} ** air.fixed_width), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{air.log_size} ** air.main_width), &channel);
    const component = air.Component{};
    const handles = [_]core.air.components.Component{component.asVerifierComponent()};
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}

/// This verifies schedule arithmetic and topology with private first words.
/// On its own it proves no claim about which block was scheduled; the joined
/// SHA word bus must authenticate all 16 consumed block words.
pub fn verifyPrivateBytes(allocator: std.mem.Allocator, pcs: core.pcs.config_v2.PcsConfigV2, proof_bytes: []const u8) !void {
    if (proof_bytes.len > max_proof_bytes) return error.ShaScheduleProofTooLarge;
    const fixed_root = try expectedPrivateFixedRoot(allocator, pcs);
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 3)
        return error.InvalidShaScheduleProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs)))
        return error.InvalidShaScheduleProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaScheduleFixedRoot;
    var channel = MC.Channel{};
    mixPrivateStatement(&channel, pcs);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, fixed_root, &([_]u32{air.log_size} ** air.fixed_width), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{air.log_size} ** air.main_width), &channel);
    const component = air.Component{ .boundary_mode = .private_input };
    const handles = [_]core.air.components.Component{component.asVerifierComponent()};
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}
