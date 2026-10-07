//! Native verifier for one private-header, three-call direct SHA256d STARK.
//! Only the digest, call namespace, Gate addresses and lookup claims enter
//! the public statement. The word claims must close to zero. The Gate claim
//! remains open for a circuit component in the eventual same-proof profile.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const postcard = @import("interop_postcard");
const profile = @import("../config/sha_shift_private_join_profile.zig");
const caller = @import("../air/sha_caller_stream_air.zig");
const caller_bus = @import("../air/sha_caller_stream_bus.zig");
const schedule = @import("../air/sha_schedule_direct_air.zig");
const schedule_bus = @import("../air/sha_schedule_direct_word_logup.zig");
const round = @import("../air/sha_round_shift_air.zig");
const round_bus = @import("../air/sha_round_shift_word_logup.zig");
const feed = @import("../air/sha_feed_direct_air.zig");
const feed_bus = @import("../air/sha_feed_direct_word_logup.zig");
const word_bus = @import("../air/sha_direct_word_bus.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

pub const max_proof_bytes: usize = 1 << 24;
pub const magic = "S31SPR03";
pub const claim_bytes: usize = (1 + profile.word_claim_count) * 16;
pub const envelope_prefix_bytes: usize = magic.len + claim_bytes + 32;

pub const Verified = struct {
    gate_claim: QM31,
    fixed_root: [32]u8,
    main_root: [32]u8,
};

pub fn mixStatement(channel: *MC.Channel, statement: profile.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2) void {
    channel.mixU64(0x5333_3150_5249_5633);
    const digest = profile.semanticDigest();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    pcs.fri_config.mixInto(channel);
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, statement.digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    channel.mixU32s(&statement.config.gate_addresses);
    channel.mixU32s(&.{statement.config.first_call_id});
}

fn claimWords(claims: profile.Claims) [4 * (1 + profile.word_claim_count)]u32 {
    var values: [4 * (1 + profile.word_claim_count)]u32 = undefined;
    const all = [_]QM31{claims.gate} ++ claims.word;
    for (all, 0..) |claim, i| {
        const limbs = claim.toM31Array();
        for (limbs, 0..) |limb, j| values[4 * i + j] = limb.toU32();
    }
    return values;
}

pub fn statementTag(statement: profile.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2, claims: profile.Claims) [32]u8 {
    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    const words = claimWords(claims);
    channel.mixU32s(&words);
    return channel.digestBytes();
}

pub fn appendEnvelopePrefix(allocator: std.mem.Allocator, bytes: *std.ArrayList(u8), statement: profile.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2, claims: profile.Claims) !void {
    try bytes.appendSlice(allocator, magic);
    const words = claimWords(claims);
    for (words) |value| {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, value, .little);
        try bytes.appendSlice(allocator, &encoded);
    }
    const tag = statementTag(statement, pcs, claims);
    try bytes.appendSlice(allocator, &tag);
}

pub fn decodeClaims(envelope: []const u8) !profile.Claims {
    if (envelope.len < envelope_prefix_bytes or !std.mem.eql(u8, envelope[0..magic.len], magic)) return error.InvalidShaPrivateJoinEnvelope;
    var all: [1 + profile.word_claim_count]QM31 = undefined;
    for (&all, 0..) |*claim, i| {
        var limbs: [4]M31 = undefined;
        for (&limbs, 0..) |*limb, j| {
            const at = magic.len + 16 * i + 4 * j;
            const encoded = std.mem.readInt(u32, envelope[at..][0..4], .little);
            if (encoded >= core.fields.m31.Modulus) return error.NoncanonicalShaPrivateJoinClaim;
            limb.* = M31.fromCanonical(encoded);
        }
        claim.* = QM31.fromM31Array(limbs);
    }
    var result: profile.Claims = undefined;
    result.gate = all[0];
    @memcpy(&result.word, all[1..]);
    try result.validate();
    return result;
}

pub fn fixedLogSizes() [profile.Layout.init(.{}).total_fixed]u32 {
    const layout = comptime profile.Layout.init(.{});
    var sizes: [layout.total_fixed]u32 = undefined;
    @memset(&sizes, caller.log_size);
    for (layout.feed_fixed) |at| @memset(sizes[at..][0..feed.fixed_width], feed.log_size);
    return sizes;
}
pub fn mainLogSizes() [profile.Layout.init(.{}).total_main]u32 {
    const layout = comptime profile.Layout.init(.{});
    var sizes: [layout.total_main]u32 = undefined;
    @memset(&sizes, caller.log_size);
    for (layout.feed_main) |at| @memset(sizes[at..][0..feed.main_width], feed.log_size);
    return sizes;
}
pub fn interactionLogSizes() [profile.Layout.init(.{}).total_interaction]u32 {
    const layout = comptime profile.Layout.init(.{});
    var sizes: [layout.total_interaction]u32 = undefined;
    @memset(&sizes, caller.log_size);
    for (layout.feed_interaction) |at| @memset(sizes[at..][0..feed_bus.interaction_width], feed.log_size);
    return sizes;
}

fn commitCanonical(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *MC.Channel) !void {
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
    try Engine.commit(scheme, allocator, owned, null, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
}

/// The verifier independently commits precisely the public digest/role
/// columns, SHA K constants, canonical selectors and row indices. No header,
/// W, state, terminal or output value is used here.
pub fn canonicalFixedRoot(allocator: std.mem.Allocator, statement: profile.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    try statement.validate();
    const layout = profile.Layout.init(.{});
    var caller_fixed = try caller.writeFixed(allocator, statement);
    defer caller_fixed.deinit();
    var bus_fixed = try caller_bus.writeFixed(allocator, statement.config);
    defer bus_fixed.deinit();
    var schedule_fixed: [profile.call_count]schedule.Columns = undefined;
    var round_fixed: [profile.call_count]round.Columns = undefined;
    var feed_fixed: [profile.call_count]feed.Columns = undefined;
    var ns: usize = 0;
    var nr: usize = 0;
    var nf: usize = 0;
    defer {
        for (schedule_fixed[0..ns]) |*value| value.deinit();
        for (round_fixed[0..nr]) |*value| value.deinit();
        for (feed_fixed[0..nf]) |*value| value.deinit();
    }
    for (0..profile.call_count) |i| {
        schedule_fixed[i] = try schedule.writeFixedPrivate(allocator);
        ns += 1;
        round_fixed[i] = try round.writeFixedPrivate(allocator);
        nr += 1;
        feed_fixed[i] = try feed.writeFixedPrivate(allocator);
        nf += 1;
    }
    const columns = try allocator.alloc(Column, layout.total_fixed);
    defer allocator.free(columns);
    @memcpy(columns[layout.caller_fixed..][0..caller.fixed_width], caller_fixed.values);
    @memcpy(columns[layout.caller_bus_fixed..][0..caller_bus.fixed_width], bus_fixed.values);
    for (0..profile.call_count) |i| {
        @memcpy(columns[layout.schedule_fixed[i]..][0..schedule.fixed_width], schedule_fixed[i].values);
        @memcpy(columns[layout.round_fixed[i]..][0..round.fixed_width], round_fixed[i].values);
        @memcpy(columns[layout.feed_fixed[i]..][0..feed.fixed_width], feed_fixed[i].values);
    }
    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try commitCanonical(&scheme, allocator, columns, &channel);
    return scheme.trees.items[0].commitment.root();
}

pub fn verifyBytes(allocator: std.mem.Allocator, statement: profile.PublicStatement, pcs: core.pcs.config_v2.PcsConfigV2, envelope: []const u8) !Verified {
    try statement.validate();
    if (envelope.len < envelope_prefix_bytes or envelope.len > envelope_prefix_bytes + max_proof_bytes) return error.ShaPrivateJoinProofTooLarge;
    const claims = try decodeClaims(envelope);
    const tag = statementTag(statement, pcs, claims);
    if (!std.mem.eql(u8, envelope[magic.len + claim_bytes ..][0..32], &tag)) return error.WrongShaPrivateJoinStatementTag;
    const fixed_root = try canonicalFixedRoot(allocator, statement, pcs);
    const proof_bytes = envelope[envelope_prefix_bytes..];
    const decode_memory = try allocator.alloc(u8, max_proof_bytes);
    defer allocator.free(decode_memory);
    var bounded = std.heap.FixedBufferAllocator.init(decode_memory);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(H, bounded.allocator(), stream.reader());
    defer proof.deinit(bounded.allocator());
    if (stream.pos != proof_bytes.len or proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidShaPrivateJoinProofShape;
    if (!std.meta.eql(proof.commitment_scheme_proof.config, core.protocol_revision.Revision.proving_5a7c5ed.legacyView(pcs))) return error.InvalidShaPrivateJoinProofConfig;
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &roots[0], &fixed_root)) return error.WrongShaPrivateJoinFixedRoot;

    var channel = MC.Channel{};
    mixStatement(&channel, statement, pcs);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(allocator, pcs);
    defer verifier.deinit(allocator);
    const fixed_logs = fixedLogSizes();
    const main_logs = mainLogSizes();
    const interaction_logs = interactionLogSizes();
    try verifier.commit(allocator, fixed_root, &fixed_logs, &channel);
    try verifier.commit(allocator, roots[1], &main_logs, &channel);
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const gate_elements = word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha);
    const word_elements = word_bus.Elements.init(word_challenge.z, word_challenge.alpha);
    const claim_array = [_]QM31{claims.gate} ++ claims.word;
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &claim_array);
    try verifier.commit(allocator, roots[2], &interaction_logs, &channel);
    const layout = profile.Layout.init(.{});
    var components = profile.Components.init(statement, claims, gate_elements, word_elements, layout);
    const handles = components.verifierHandles();
    var capture: core.verifier.ProofCapture(H) = undefined;
    try core.verifier.verifyBorrowedExWithProofCapture(H, MC, allocator, &handles, &channel, &verifier, &proof, true, &capture);
    defer capture.deinit(allocator);
    return .{ .gate_claim = claims.gate, .fixed_root = fixed_root, .main_root = roots[1] };
}
