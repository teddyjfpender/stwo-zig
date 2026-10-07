//! Native functional proof of a direct SHA feed and its committed word LogUp.
//! All eight incoming, terminal, and output words are verifier-owned here.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const sha = @import("s31_sha_provider").compression;
const feed = @import("sha_feed_direct_air.zig");
const word = @import("sha_feed_direct_word_logup.zig");
const bus = @import("sha_direct_word_bus.zig");
const native = @import("sha_feed_direct_word_native_verifier.zig");
const postcard = @import("interop_postcard");

const M31 = core.fields.m31.M31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn commit(scheme: *Engine.Scheme, allocator: std.mem.Allocator, columns: []const Column, channel: *MC.Channel) !void {
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

fn exercise(allocator: std.mem.Allocator, statement: feed.Statement, mutate_interaction: bool) !void {
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, feed.log_size);
    const call_id: u32 = 17;
    var fixed = try feed.writeFixed(allocator, statement);
    defer fixed.deinit();
    var main = try feed.writeMain(allocator, statement);
    defer main.deinit();
    var channel = MC.Channel{};
    native.mixStatement(&channel, statement, pcs, call_id);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    const fixed_root = scheme.trees.items[0].commitment.root();
    try std.testing.expectEqualDeep(try native.expectedFixedRoot(allocator, statement, pcs, call_id), fixed_root);
    try commit(&scheme, allocator, main.values, &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    var interaction = try word.writeInteraction(allocator, fixed.values, main.values, call_id, elements);
    defer interaction.deinit();
    const expected = try native.expectedClaim(statement, call_id, elements);
    try std.testing.expect(interaction.claimed_sum.eql(expected));
    const feed_component = feed.Component{};
    const word_component = word.Component{ .call_id = call_id, .elements = elements, .claimed_sum = expected };
    if (mutate_interaction) {
        const at = feed.storageIndex(0);
        @constCast(interaction.columns[0].values)[at] = interaction.columns[0].values[at].add(M31.one());
        try std.testing.expectError(error.InvalidShaFeedWordConstraint, word.validateCommittedTrace(&word_component, fixed.values, main.values, interaction.columns));
    } else {
        try word.validateCommittedTrace(&word_component, fixed.values, main.values, interaction.columns);
    }
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{expected});
    try commit(&scheme, allocator, interaction.columns, &channel);
    const handles = [_]prover.air.component_prover.ComponentProver{ feed_component.asProverComponent(), word_component.asProverComponent() };
    var timer = try std.time.Timer.start();
    scheme_owned = false;
    var proof = Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true }) catch |err| {
        if (mutate_interaction and err == error.ConstraintsNotSatisfied) return;
        return err;
    };
    defer proof.deinit(allocator);
    if (mutate_interaction) return error.MutatedFeedWordTraceProved;
    const prove_ns = timer.read();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.proof);
    timer.reset();
    try native.verifyBytes(allocator, statement, pcs, call_id, fixed_root, bytes.items);
    const verify_ns = timer.read();
    std.debug.print("S31_SHA_FEED_WORD verified=true rows={d} fixed={d} main={d} interaction={d} constraints={d}+{d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{
        feed.rows,                     feed.fixed_width,               feed.main_width, word.interaction_width, feed.n_constraints, word.n_constraints,
        prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, bytes.items.len,
    });
    if (native.verifyBytes(allocator, statement, pcs, call_id + 1, fixed_root, bytes.items)) |_| return error.AlteredShaCallIdAccepted else |_| {}
    var changed = statement;
    changed.initial[0] ^= 1;
    if (native.verifyBytes(allocator, changed, pcs, call_id, fixed_root, bytes.items)) |_| return error.AlteredShaIncomingAccepted else |_| {}
    changed = statement;
    changed.terminal[1] ^= 1;
    if (native.verifyBytes(allocator, changed, pcs, call_id, fixed_root, bytes.items)) |_| return error.AlteredShaTerminalAccepted else |_| {}
    changed = statement;
    changed.output[7] ^= 1;
    if (native.verifyBytes(allocator, changed, pcs, call_id, fixed_root, bytes.items)) |_| return error.AlteredShaOutputAccepted else |_| {}
    if (native.verifyBytes(allocator, statement, pcs, call_id, fixed_root, bytes.items[0 .. bytes.items.len - 1])) |_| return error.TruncatedShaFeedWordProofAccepted else |_| {}
}

fn exercisePrivate(allocator: std.mem.Allocator, statement: feed.Statement) !void {
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, feed.log_size);
    const call_id: u32 = 17;
    var fixed = try feed.writeFixedPrivate(allocator);
    defer fixed.deinit();
    var main = try feed.writeMain(allocator, statement);
    defer main.deinit();
    try feed.validateCommittedTraceMode(fixed.values, main.values, true);
    try std.testing.expectError(error.InvalidShaFeedConstraint, feed.validateCommittedTrace(fixed.values, main.values));
    var channel = MC.Channel{};
    native.mixPrivateStatement(&channel, pcs, call_id);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    const fixed_root = scheme.trees.items[0].commitment.root();
    try std.testing.expectEqualDeep(try native.expectedPrivateFixedRoot(allocator, pcs, call_id), fixed_root);
    try commit(&scheme, allocator, main.values, &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    var interaction = try word.writeInteraction(allocator, fixed.values, main.values, call_id, elements);
    defer interaction.deinit();
    const expected = try native.expectedClaim(statement, call_id, elements);
    try std.testing.expect(interaction.claimed_sum.eql(expected));
    const feed_component = feed.Component{ .private_mode = true };
    const word_component = word.Component{ .call_id = call_id, .elements = elements, .claimed_sum = expected };
    try word.validateCommittedTrace(&word_component, fixed.values, main.values, interaction.columns);
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{expected});
    try commit(&scheme, allocator, interaction.columns, &channel);
    const handles = [_]prover.air.component_prover.ComponentProver{ feed_component.asProverComponent(), word_component.asProverComponent() };
    scheme_owned = false;
    var proof = try Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true });
    defer proof.deinit(allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.proof);
    try native.verifyPrivateBytes(allocator, statement, pcs, call_id, bytes.items);
    const public_root = try native.expectedFixedRoot(allocator, statement, pcs, call_id);
    try std.testing.expect(!std.mem.eql(u8, &fixed_root, &public_root));
    try std.testing.expectError(error.WrongShaFeedWordFixedRoot, native.verifyBytes(allocator, statement, pcs, call_id, public_root, bytes.items));
    std.debug.print("S31_SHA_FEED_WORD_PRIVATE verified=true rows={d} fixed={d} main={d} interaction={d} constraints={d}+{d} proof_bytes={d} fri_pow_bits=0 queries=12 custody=unjoined\n", .{ feed.rows, feed.fixed_width, feed.main_width, word.interaction_width, feed.n_constraints, word.n_constraints, bytes.items.len });
}

test "direct feed word lookup natively proves incoming, terminal and output events" {
    const allocator = std.testing.allocator;
    var block = [_]u8{0} ** 64;
    block[0] = 'a';
    block[1] = 'b';
    block[2] = 'c';
    block[3] = 0x80;
    block[63] = 24;
    const initial = sha.initial_state;
    const rounds = sha.witness(initial, block);
    const statement = feed.Statement{ .initial = initial, .terminal = rounds.states[64], .output = sha.compress(initial, block) };
    for (0..8) |i| try std.testing.expectEqual(initial[i] +% rounds.states[64][i], statement.output[i]);
    try exercise(allocator, statement, false);
    try exercise(allocator, statement, true);
    try exercisePrivate(allocator, statement);
}
