//! Native functional proof of a direct SHA round and its committed word LogUp.
//! The schedule and initial state are still verifier-owned in this harness.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const sha = @import("s31_sha_provider").compression;
const round = @import("sha_round_direct_air.zig");
const word = @import("sha_round_direct_word_logup.zig");
const bus = @import("sha_direct_word_bus.zig");
const native = @import("sha_round_direct_word_native_verifier.zig");
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

fn exercise(allocator: std.mem.Allocator, statement: round.Statement, mutate_interaction: bool, private_mode: bool) !void {
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, round.log_size);
    const call_id: u32 = 17;
    var fixed = if (private_mode) try round.writeFixedPrivate(allocator) else try round.writeFixed(allocator, statement.schedule);
    defer fixed.deinit();
    var main = try round.writeMain(allocator, statement);
    defer main.deinit();
    var channel = MC.Channel{};
    native.mixStatement(&channel, statement, pcs, call_id);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    const fixed_root = scheme.trees.items[0].commitment.root();
    try commit(&scheme, allocator, main.values, &channel);
    const challenge = try core.channel.lookup_transcript.drawLookupElements(allocator, &channel);
    const elements = bus.Elements.init(challenge.z, challenge.alpha);
    var interaction = try word.writeInteraction(allocator, fixed.values, main.values, call_id, elements);
    defer interaction.deinit();
    const expected = try native.expectedClaim(statement, call_id, elements);
    try std.testing.expect(interaction.claimed_sum.eql(expected));
    const round_component = round.Component{ .statement = statement, .private_mode = private_mode };
    const word_component = word.Component{ .call_id = call_id, .elements = elements, .claimed_sum = expected };
    if (mutate_interaction) {
        const at = round.storageIndex(0);
        @constCast(interaction.columns[0].values)[at] = interaction.columns[0].values[at].add(M31.one());
        try std.testing.expectError(error.InvalidShaRoundWordConstraint, word.validateCommittedTrace(&word_component, fixed.values, main.values, interaction.columns));
    } else {
        try word.validateCommittedTrace(&word_component, fixed.values, main.values, interaction.columns);
    }
    core.channel.lookup_transcript.mixInteractionClaim(&channel, &.{expected});
    try commit(&scheme, allocator, interaction.columns, &channel);
    const handles = [_]prover.air.component_prover.ComponentProver{ round_component.asProverComponent(), word_component.asProverComponent() };
    var timer = try std.time.Timer.start();
    scheme_owned = false;
    var proof = Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true }) catch |err| {
        if (mutate_interaction and err == error.ConstraintsNotSatisfied) return;
        return err;
    };
    defer proof.deinit(allocator);
    if (mutate_interaction) return error.MutatedRoundWordTraceProved;
    const prove_ns = timer.read();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.proof);
    timer.reset();
    try native.verifyBytesMode(allocator, statement, pcs, call_id, fixed_root, bytes.items, private_mode);
    const verify_ns = timer.read();
    std.debug.print("S31_SHA_ROUND_WORD proved=true native_verified={any} private_mode={any} rows={d} fixed={d} main={d} interaction={d} constraints={d}+{d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{
        true,
        private_mode,
        round.rows,
        round.fixed_width,
        round.main_width,
        word.interaction_width,
        round.n_constraints,
        word.n_constraints,
        prove_ns / std.time.ns_per_ms,
        verify_ns / std.time.ns_per_ms,
        bytes.items.len,
    });
    if (native.verifyBytesMode(allocator, statement, pcs, call_id + 1, fixed_root, bytes.items, private_mode)) |_| return error.AlteredShaCallIdAccepted else |_| {}
    var changed = statement;
    changed.initial[0] ^= 1;
    if (native.verifyBytesMode(allocator, changed, pcs, call_id, fixed_root, bytes.items, private_mode)) |_| return error.AlteredShaInitialAccepted else |_| {}
    if (native.verifyBytesMode(allocator, statement, pcs, call_id, fixed_root, bytes.items[0 .. bytes.items.len - 1], private_mode)) |_| return error.TruncatedShaRoundWordProofAccepted else |_| {}
}

test "direct round word lookup natively proves authenticated W and boundary events" {
    const allocator = std.testing.allocator;
    var block = [_]u8{0} ** 64;
    block[0] = 'a';
    block[1] = 'b';
    block[2] = 'c';
    block[3] = 0x80;
    block[63] = 24;
    const witness = sha.witness(sha.initial_state, block);
    const statement = round.Statement{ .initial = sha.initial_state, .final = witness.states[64], .schedule = witness.schedule };
    try exercise(allocator, statement, false, false);
    try exercise(allocator, statement, true, false);
    try exercise(allocator, statement, false, true);
}
