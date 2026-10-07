//! Native verifier for the isolated three-call fused SHA schedule/round AIR.
//! All boundary words are public in this test harness. The eventual joined
//! Bitcoin proof must close them against the caller and feed-forward chips.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const air = @import("../air/sha_fused_air.zig");
const word = @import("../air/sha_fused_word_logup.zig");
const bus = @import("../air/sha_fused_word_bus.zig");
const sha = @import("s31_sha_provider").compression;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;
pub const max_proof_bytes: usize = 1 << 22;

pub fn mixStatement(channel: *MC.Channel, statements: air.Statements, first_call_id: u32, pcs: core.pcs.config_v2.PcsConfigV2) void {
    channel.mixU64(0x5333_3146_5553_3031);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(@embedFile("../air/sha_fused_air.zig"));
    hasher.update(@embedFile("../air/sha_fused_word_logup.zig"));
    hasher.update(@embedFile("../air/sha_fused_word_bus.zig"));
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*slot, i| slot.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    pcs.fri_config.mixInto(channel);
    channel.mixU32s(&.{first_call_id});
    for (statements) |statement| {
        channel.mixU32s(&statement.initial);
        channel.mixU32s(&statement.final);
        channel.mixU32s(&statement.schedule);
    }
}

fn cloneColumns(allocator: std.mem.Allocator, columns: []const Column) ![]Column {
    const owned = try allocator.alloc(Column, columns.len);
    var ready: usize = 0;
    errdefer {
        for (owned[0..ready]) |column| allocator.free(column.values);
        allocator.free(owned);
    }
    for (columns, owned) |source, *target| {
        target.* = .{ .log_size = source.log_size, .values = try allocator.dupe(M31, source.values) };
        ready += 1;
    }
    return owned;
}
fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *MC.Channel) !void {
    try Engine.commit(scheme, allocator, try cloneColumns(allocator, columns), null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

pub fn canonicalFixedRoot(allocator: std.mem.Allocator, statements: air.Statements, first_call_id: u32, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    var fixed = try air.writeFixed(allocator, first_call_id);
    defer fixed.deinit();
    var channel = MC.Channel{};
    mixStatement(&channel, statements, first_call_id, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try commit(&scheme, allocator, fixed.values, &channel);
    return scheme.trees.items[0].commitment.root();
}

fn addTerm(sum: *QM31, elements: bus.Elements, id: u32, address: u32, value: u32, sign: i8) !void {
    const tuple = bus.tuple(M31, M31.fromCanonical(id), M31.fromCanonical(address), M31.fromCanonical(value & 0xffff), M31.fromCanonical(value >> 16));
    const inverse = try elements.denominator(M31, tuple).inv();
    sum.* = sum.add(if (sign < 0) inverse.neg() else inverse);
}

pub fn expectedClaim(statements: air.Statements, first_call_id: u32, elements: bus.Elements) !QM31 {
    if (first_call_id == 0 or first_call_id > core.fields.m31.Modulus - air.call_count) return error.InvalidShaCallId;
    var sum = QM31.zero();
    for (statements, 0..) |statement, call| {
        const id = first_call_id + @as(u32, @intCast(call));
        for (statement.initial, 0..) |value, i| try addTerm(&sum, elements, id, @intCast(i), value, -1);
        for (statement.schedule[0..16], 0..) |value, i| try addTerm(&sum, elements, id, @intCast(8 + i), value, -1);
        var state = statement.initial;
        for (statement.schedule, 0..) |value, t| state = sha.round(state, value, sha.round_constants[t]);
        if (!std.meta.eql(state, statement.final)) return error.InvalidShaFusedTerminal;
        for (statement.final, 0..) |value, i| try addTerm(&sum, elements, id, bus.terminal_base + @as(u32, @intCast(i)), value, 1);
    }
    return sum;
}

pub fn verifyBytes(allocator: std.mem.Allocator, statements: air.Statements, first_call_id: u32, pcs: core.pcs.config_v2.PcsConfigV2, bytes: []const u8) !void {
    if (bytes.len > max_proof_bytes) return error.ShaFusedProofTooLarge;
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != bytes.len or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidShaFusedProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs))) return error.InvalidShaFusedProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    const fixed_root = try canonicalFixedRoot(allocator, statements, first_call_id, pcs);
    if (!std.mem.eql(u8, &fixed_root, &roots[0])) return error.WrongShaFusedFixedRoot;
    var channel = MC.Channel{};
    mixStatement(&channel, statements, first_call_id, pcs);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    try verifier.commit(allocator, fixed_root, &([_]u32{air.log_size} ** air.fixed_width), &channel);
    try verifier.commit(allocator, roots[1], &([_]u32{air.log_size} ** air.main_width), &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    const claim = try expectedClaim(statements, first_call_id, elements);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{claim});
    try verifier.commit(allocator, roots[2], &([_]u32{air.log_size} ** word.interaction_width), &channel);
    const air_component = air.Component{};
    const word_component = word.Component{ .elements = elements, .claimed_sum = claim };
    const handles = [_]core.air.components.Component{ air_component.asVerifierComponent(), word_component.asVerifierComponent() };
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
}
