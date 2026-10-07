//! In-circuit Fiat-Shamir prefix for S31FCF01. These helpers mirror the
//! native profile and claim encoding; they do not verify an STARK proof.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const profile = @import("../config/sha_fused_fold_profile.zig");
const direct = @import("../config/sha_fused_private_join_profile.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const Var = circuit.builder.Var;
const Context = circuit.builder.Context;
const Channel = circuit.stark_verifier.channel.Channel;
const U32 = circuit.builder.wrappers.U32Wrapper(Var);

fn mixWords(comptime V: type, ctx: *Context(V), channel: *Channel, words: []const u32) !void {
    const wrapped = try ctx.scratch().alloc(U32, words.len);
    for (wrapped, words) |*slot, word| slot.* = try circuit.builder.wrappers.constU32(V, ctx, word);
    try channel.mixU32s(V, ctx, wrapped);
}

fn mixDigestBytes(comptime V: type, ctx: *Context(V), channel: *Channel, digest: [32]u8) !void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    try mixWords(V, ctx, channel, &words);
}

/// Replays `sha_fused_fold_profile.mixProfile` under circuit constraints.
/// `key` is a trusted verifier constant, never supplied by proof bytes.
pub fn mixProfile(comptime V: type, ctx: *Context(V), channel: *Channel, key: profile.Key) !void {
    try channel.mixU64(V, ctx, 0x5333_3146_4346_3031);
    try mixDigestBytes(V, ctx, channel, key.source_digest);
    try mixDigestBytes(V, ctx, channel, direct.semanticDigest());
    try mixDigestBytes(V, ctx, channel, profile.circuitAirDigest());
    try mixWords(V, ctx, channel, &.{ key.n_vars, direct.component_count, profile.component_count, profile.claim_count });
    const logs = key.circuit_logs.toArray();
    try mixWords(V, ctx, channel, &logs);
    try mixWords(V, ctx, channel, &key.statement.config.gate_addresses);
    try mixWords(V, ctx, channel, &.{key.statement.config.first_call_id});
    const fri = key.pcs.fri_config;
    try mixWords(V, ctx, channel, &.{
        fri.pow_bits,                          fri.log_blowup_factor,
        fri.log_last_layer_degree_bound,       fri.n_queries,
        fri.fold_step,                         key.pcs.trace_lifting_log_size,
        key.pcs.preprocessed_lifting_log_size,
    });
    try channel.mixChannelSalt(V, ctx, 0);
    const fri_values = [_]Var{
        try ctx.constant(QM31.fromU32Unchecked(fri.pow_bits, fri.log_blowup_factor, fri.n_queries, fri.log_last_layer_degree_bound)),
        try ctx.constant(QM31.fromU32Unchecked(fri.fold_step, 0, 0, 0)),
    };
    try channel.mixFelts(V, ctx, &fri_values);
}

pub fn mixRoot(comptime V: type, ctx: *Context(V), channel: *Channel, root: [32]u8) !void {
    const value = try circuit.builder.blake.constantHash(V, ctx, circuit.builder.blake.hashValueFromDigest(QM31, root));
    try channel.mixCommitment(V, ctx, value);
}

/// The native joined proof mixes its key identity as a root, then its eight
/// QM31 public outputs as field elements rather than raw output bytes.
pub fn mixPublicClaim(comptime V: type, ctx: *Context(V), channel: *Channel, key: profile.Key, outputs: []const Var) !void {
    if (outputs.len != 8) return error.InvalidFusedFoldPublicOutputCount;
    try mixRoot(V, ctx, channel, key.identity());
    try channel.mixFelts(V, ctx, outputs);
}

pub const LookupPairs = struct { gate: [2]Var, word: [2]Var };

/// The Gate and SHA word buses use distinct Fiat-Shamir challenges.
pub fn drawLookupPairs(comptime V: type, ctx: *Context(V), channel: *Channel) !LookupPairs {
    return .{
        .gate = try channel.drawLookupElements(V, ctx),
        .word = try channel.drawLookupElements(V, ctx),
    };
}

/// The native joined statement checks two independent closures: public
/// circuit output Gate uses plus the 11 circuit claims and caller Gate claim,
/// and the five SHA word-bus claims. Combining those sums into one equality
/// would allow an invalid Gate balance to cancel an invalid word balance.
pub fn constrainJoinedClosure(comptime V: type, ctx: *Context(V), public_gate_sum: Var, claims: []const Var) !void {
    if (claims.len != profile.claim_count) return error.InvalidFusedFoldClaimCount;
    var gate_sum = public_gate_sum;
    for (claims[0 .. profile.circuit_components + 1]) |claim| gate_sum = try ctx.add(gate_sum, claim);
    try ctx.eq(gate_sum, ctx.zero());
    var word_sum = ctx.zero();
    for (claims[profile.circuit_components + 1 ..]) |claim| word_sum = try ctx.add(word_sum, claim);
    try ctx.eq(word_sum, ctx.zero());
}

/// Test the in-circuit prefix against a native accepted joined proof. This
/// checks exact transcript bytes, the production PoW nonce, and both lookup
/// draws. It is a parity test, not a recursive STARK verifier.
pub fn expectAcceptedProofPrefix(
    key: profile.Key,
    outputs: []const QM31,
    roots: []const [32]u8,
    nonce: u64,
    claims: []const QM31,
) !void {
    if (outputs.len != 8 or roots.len != 4 or claims.len != profile.claim_count)
        return error.InvalidFusedFoldProofShape;
    if (!std.mem.eql(u8, &roots[0], &key.fixed_root))
        return error.WrongFusedFoldFixedRoot;
    const allocator = std.heap.page_allocator;
    var ctx = try Context(QM31).init(allocator, 0);
    defer ctx.deinit();
    var in_circuit = Channel.init(QM31, &ctx);
    var native = profile.MC.Channel{};
    try mixProfile(QM31, &ctx, &in_circuit, key);
    profile.mixProfile(&native, key);
    try expectNativeDigest(&ctx, in_circuit, native);

    try mixRoot(QM31, &ctx, &in_circuit, roots[0]);
    profile.MC.mixRoot(&native, roots[0]);
    try expectNativeDigest(&ctx, in_circuit, native);

    var output_vars: [8]Var = undefined;
    for (outputs, &output_vars) |value, *wire| wire.* = try ctx.newVar(value);
    try mixPublicClaim(QM31, &ctx, &in_circuit, key, &output_vars);
    profile.MC.mixRoot(&native, key.identity());
    native.mixFelts(outputs);
    try expectNativeDigest(&ctx, in_circuit, native);

    try mixRoot(QM31, &ctx, &in_circuit, roots[1]);
    profile.MC.mixRoot(&native, roots[1]);
    try expectNativeDigest(&ctx, in_circuit, native);

    const nonce_var = try ctx.newVar(QM31.fromU32Unchecked(@truncate(nonce), @truncate(nonce >> 32), 0, 0));
    try std.testing.expect(native.verifyPowNonce(circuit.common.component_list.INTERACTION_POW_BITS, nonce));
    try in_circuit.pow(QM31, &ctx, circuit.common.component_list.INTERACTION_POW_BITS, nonce_var);
    native.mixU64(nonce);
    try expectNativeDigest(&ctx, in_circuit, native);

    const drawn = try drawLookupPairs(QM31, &ctx, &in_circuit);
    const gate = try core.channel.lookup_transcript.drawLookupElements(allocator, &native);
    const word = try core.channel.lookup_transcript.drawLookupElements(allocator, &native);
    try std.testing.expect(ctx.get(drawn.gate[0]).eql(gate.z));
    try std.testing.expect(ctx.get(drawn.gate[1]).eql(gate.alpha));
    try std.testing.expect(ctx.get(drawn.word[0]).eql(word.z));
    try std.testing.expect(ctx.get(drawn.word[1]).eql(word.alpha));
    try expectNativeDigest(&ctx, in_circuit, native);

    const claim_vars = try allocator.alloc(Var, claims.len);
    defer allocator.free(claim_vars);
    for (claims, claim_vars) |value, *wire| wire.* = try ctx.newVar(value);
    try in_circuit.mixFelts(QM31, &ctx, claim_vars);
    core.channel.lookup_transcript.mixInteractionClaim(&native, claims);
    try expectNativeDigest(&ctx, in_circuit, native);

    try mixRoot(QM31, &ctx, &in_circuit, roots[2]);
    profile.MC.mixRoot(&native, roots[2]);
    try expectNativeDigest(&ctx, in_circuit, native);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

fn testKey() !profile.Key {
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = @intCast(100 + i);
    const layout = try profile.pp.ColumnLayout.fromComponentSizes(.{
        .eq = 32768,
        .qm31_ops = 2097152,
        .m31_to_u32 = 262144,
        .triple_xor = 131072,
        .blake_g_gate = 2097152,
    });
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    var key = profile.Key{
        .source_digest = profile.trustedFoldSourceDigest(),
        .statement = .{ .digest_visibility = .private, .config = .{ .gate_addresses = addresses, .first_call_id = 1 } },
        .n_vars = 5_606_320,
        .circuit_logs = try profile.component_list.circuitComponentLogSizes(&layout),
        .circuit_layout = layout,
        .pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, layout.traceLogSize()),
        .fixed_root = @splat(0x42),
        .digest = undefined,
    };
    key.digest = profile.keyDigest(key);
    try key.validate();
    return key;
}

fn expectNativeDigest(ctx: *const Context(QM31), in_circuit: Channel, native: profile.MC.Channel) !void {
    const expected = circuit.builder.blake.reducedHashValueFromDigest(native.digestBytes());
    try std.testing.expect(ctx.get(in_circuit.digest.low).eql(expected.low));
    try std.testing.expect(ctx.get(in_circuit.digest.high).eql(expected.high));
}

test "joined fold profile and claim transcript matches native at every boundary" {
    const allocator = std.testing.allocator;
    const key = try testKey();
    var ctx = try Context(QM31).init(allocator, 0);
    defer ctx.deinit();
    var in_circuit = Channel.init(QM31, &ctx);
    var native = profile.MC.Channel{};
    try mixProfile(QM31, &ctx, &in_circuit, key);
    profile.mixProfile(&native, key);
    try expectNativeDigest(&ctx, in_circuit, native);

    try mixRoot(QM31, &ctx, &in_circuit, key.fixed_root);
    profile.MC.mixRoot(&native, key.fixed_root);
    try expectNativeDigest(&ctx, in_circuit, native);

    const public_words = [_]u32{ 0, 1, 65535, 65536, 123456789, 0x8000_0000, 0xffff_fffe, 0xffff_ffff };
    var outputs: [8]QM31 = undefined;
    var output_vars: [8]Var = undefined;
    for (public_words, &outputs, &output_vars) |word, *output, *wire| {
        output.* = circuit.builder.ivalue.packU32(QM31, word);
        wire.* = try ctx.constant(output.*);
    }
    try mixPublicClaim(QM31, &ctx, &in_circuit, key, &output_vars);
    profile.MC.mixRoot(&native, key.identity());
    native.mixFelts(&outputs);
    try expectNativeDigest(&ctx, in_circuit, native);

    const main_root: [32]u8 = @splat(0x7a);
    try mixRoot(QM31, &ctx, &in_circuit, main_root);
    profile.MC.mixRoot(&native, main_root);
    try expectNativeDigest(&ctx, in_circuit, native);

    // Mix a fixed nonce without asserting it satisfies PoW. The channel's
    // PoW constraint is covered by channel_test; this tests encoding/order.
    const nonce: u64 = 0x1122_3344_5566_7788;
    try in_circuit.mixU64(QM31, &ctx, nonce);
    native.mixU64(nonce);
    const drawn = try drawLookupPairs(QM31, &ctx, &in_circuit);
    const gate = try core.channel.lookup_transcript.drawLookupElements(allocator, &native);
    const word = try core.channel.lookup_transcript.drawLookupElements(allocator, &native);
    try std.testing.expect(ctx.get(drawn.gate[0]).eql(gate.z));
    try std.testing.expect(ctx.get(drawn.gate[1]).eql(gate.alpha));
    try std.testing.expect(ctx.get(drawn.word[0]).eql(word.z));
    try std.testing.expect(ctx.get(drawn.word[1]).eql(word.alpha));
    try expectNativeDigest(&ctx, in_circuit, native);

    var claims: [profile.claim_count]QM31 = undefined;
    var claim_vars: [profile.claim_count]Var = undefined;
    for (&claims, &claim_vars, 0..) |*claim, *wire, i| {
        claim.* = QM31.fromBase(M31.fromCanonical(@intCast(i + 17)));
        wire.* = try ctx.constant(claim.*);
    }
    try in_circuit.mixFelts(QM31, &ctx, &claim_vars);
    core.channel.lookup_transcript.mixInteractionClaim(&native, &claims);
    try expectNativeDigest(&ctx, in_circuit, native);

    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "joined closure enforces Gate and SHA word sums separately" {
    for ([_]struct { change_gate: bool, change_word: bool, valid: bool }{
        .{ .change_gate = false, .change_word = false, .valid = true },
        .{ .change_gate = true, .change_word = false, .valid = false },
        .{ .change_gate = false, .change_word = true, .valid = false },
        .{ .change_gate = true, .change_word = true, .valid = false },
    }) |case| {
        var ctx = try Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const five = QM31.fromBase(M31.fromCanonical(5));
        const three = QM31.fromBase(M31.fromCanonical(3));
        var values: [profile.claim_count]QM31 = @splat(QM31.zero());
        values[profile.circuit_components] = if (case.change_gate) five.neg().add(QM31.one()) else five.neg();
        values[profile.circuit_components + 1] = three;
        values[profile.circuit_components + 2] = if (case.change_word) three.neg().add(QM31.one()) else three.neg();
        var wires: [profile.claim_count]Var = undefined;
        for (values, &wires) |value, *wire| wire.* = try ctx.newVar(value);
        const public_gate_sum = try ctx.newVar(five);
        try constrainJoinedClosure(QM31, &ctx, public_gate_sum, &wires);
        try ctx.finalize(false);
        try std.testing.expectEqual(case.valid, try ctx.isCircuitValid());
    }
}
