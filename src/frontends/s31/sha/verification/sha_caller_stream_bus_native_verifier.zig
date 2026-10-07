//! Native verifier for one proof containing caller equations and both caller
//! lookup accumulators over the same committed private main trace. Its two
//! public claims remain open until circuit and SHA components close them.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const caller = @import("../air/sha_caller_stream_air.zig");
const bus_component = @import("../air/sha_caller_stream_bus.zig");
const word_bus = @import("../air/sha_direct_word_bus.zig");
const caller_native = @import("sha_caller_stream_native_verifier.zig");

const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
pub const max_proof_bytes: usize = 1 << 20;

pub const Claims = struct {
    gate: QM31,
    word: QM31,
};

pub fn mixStatement(channel: *MC.Channel, statement: caller.Statement, pcs: core.pcs.config_v2.PcsConfigV2) void {
    caller_native.mixStatement(channel, statement, pcs);
    channel.mixU64(0x5333_3143_4142_5553);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(@embedFile("../air/sha_caller_stream_bus.zig"));
    hasher.update(@embedFile("../air/sha_direct_word_bus.zig"));
    channel.mixU64(@import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*value, i| value.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}

pub fn statementTag(statement: caller.Statement, pcs: core.pcs.config_v2.PcsConfigV2, claims: Claims) [32]u8 {
    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{ claims.gate, claims.word });
    return channel.digestBytes();
}

fn commitCanonical(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const prover.pcs.ColumnEvaluation, channel: *MC.Channel) !void {
    const owned = try allocator.alloc(prover.pcs.ColumnEvaluation, columns.len);
    var ready: usize = 0;
    errdefer {
        for (owned[0..ready]) |column| allocator.free(column.values);
        allocator.free(owned);
    }
    for (columns, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(core.fields.m31.M31, source.values) };
        ready += 1;
    }
    try Engine.commit(scheme, allocator, owned, null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

/// Recomputed solely from the public digest and namespace. The fixed tree
/// includes both the caller's role/padding columns and all 11 bus metadata
/// columns, so no prover-selected row role or event address is trusted.
pub fn canonicalFixedRoot(allocator: std.mem.Allocator, statement: caller.Statement, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    var caller_fixed = try caller.writeFixed(allocator, statement);
    defer caller_fixed.deinit();
    var bus_fixed = try bus_component.writeFixed(allocator, statement.config);
    defer bus_fixed.deinit();
    const columns = try allocator.alloc(prover.pcs.ColumnEvaluation, caller.fixed_width + bus_component.fixed_width);
    defer allocator.free(columns);
    @memcpy(columns[0..caller.fixed_width], caller_fixed.values);
    @memcpy(columns[caller.fixed_width..], bus_fixed.values);
    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try commitCanonical(&scheme, allocator, columns, &channel);
    return scheme.trees.items[0].commitment.root();
}

pub fn verifyBytes(allocator: std.mem.Allocator, statement: caller.Statement, pcs: core.pcs.config_v2.PcsConfigV2, trusted_fixed_root: [32]u8, claims: Claims, envelope: []const u8) !void {
    try statement.validate();
    if (envelope.len < 32 or envelope.len > max_proof_bytes + 32) return error.ShaCallerBusProofTooLarge;
    const tag = statementTag(statement, pcs, claims);
    if (!std.mem.eql(u8, envelope[0..32], &tag)) return error.WrongShaCallerBusStatementTag;
    const canonical_root = try canonicalFixedRoot(allocator, statement, pcs);
    if (!std.mem.eql(u8, &trusted_fixed_root, &canonical_root)) return error.NoncanonicalShaCallerBusFixedRoot;
    const proof_bytes = envelope[32..];
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidShaCallerBusProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs))) return error.InvalidShaCallerBusProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &trusted_fixed_root, &roots[0])) return error.WrongShaCallerBusFixedRoot;

    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, trusted_fixed_root, &([_]u32{caller.log_size} ** (caller.fixed_width + bus_component.fixed_width)), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{caller.log_size} ** caller.main_width), &channel);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const gate_elements = word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha);
    const word_elements = word_bus.Elements.init(word_challenge.z, word_challenge.alpha);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{ claims.gate, claims.word });
    try verifier.commit(allocator, roots[2], &([_]u32{caller.log_size} ** bus_component.interaction_width), &channel);
    const caller_component = caller.Component{ .statement = statement };
    const bus = bus_component.Component{
        .config = statement.config,
        .fixed_offset = caller.fixed_width,
        .gate_elements = gate_elements,
        .word_elements = word_elements,
        .gate_claimed_sum = claims.gate,
        .word_claimed_sum = claims.word,
    };
    const handles = [_]core.air.components.Component{ caller_component.asVerifierComponent(), bus.asVerifierComponent() };
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}
