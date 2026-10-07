//! Native functional proof of a direct SHA round and its committed word LogUp.
//! The schedule and initial state are still verifier-owned in this harness.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const sha = @import("s31_sha_provider").compression;
const round = @import("../air/sha_round_shift_air.zig");
const word = @import("../air/sha_round_shift_word_logup.zig");
const bus = @import("../air/sha_round_shift_word_bus.zig");
const native = @import("../verification/sha_round_shift_word_native_verifier.zig");
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
    var fixed = try round.writeFixedPrivate(allocator);
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
    const round_component = round.Component{ .statement = statement };
    const word_component = word.Component{ .call_id = call_id, .elements = elements, .claimed_sum = expected };
    if (mutate_interaction) {
        const at = round.storageIndex(0);
        @constCast(interaction.columns[0].values)[at] = interaction.columns[0].values[at].add(M31.one());
        try std.testing.expectError(error.InvalidShaShiftWordConstraint, word.validateCommittedTrace(&word_component, fixed.values, main.values, interaction.columns));
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
    std.debug.print("S31_SHA_ROUND_SHIFT_WORD proved=true native_verified={any} private_mode={any} rows={d} fixed={d} main={d} interaction={d} constraints={d}+{d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{
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

test "shift-register round word lookup natively proves authenticated W and boundary events" {
    const allocator = std.testing.allocator;
    var block = [_]u8{0} ** 64;
    block[0] = 'a';
    block[1] = 'b';
    block[2] = 'c';
    block[3] = 0x80;
    block[63] = 24;
    const witness = sha.witness(sha.initial_state, block);
    const statement = round.Statement{ .initial = sha.initial_state, .final = witness.states[64], .schedule = witness.schedule };
    try exercise(allocator, statement, false, true);
    try exercise(allocator, statement, true, true);
}

fn wordAt(main: []const Column, logical: usize, first_bit: usize) u32 {
    const storage = round.storageIndex(logical);
    var value: u32 = 0;
    for (0..32) |bit| value |= main[first_bit + bit].values[storage].toU32() << @intCast(bit);
    return value;
}

fn expectInvalidRound(s: round.Statement, fixed: []const Column, main: []const Column) !void {
    try std.testing.expectError(error.InvalidShaShiftConstraint, round.validateCommittedTrace(s, fixed, main));
}

test "shift rows reconstruct every state and reject history, transition, carry, K, W and padding mutation" {
    const allocator = std.testing.allocator;
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(i * 73 + 19);
    const initial: sha.State = .{ 0x1234_5678, 0xfedc_ba98, 0, 0xffff_ffff, 0x89ab_cdef, 0x7654_3210, 0x1357_9bdf, 0x2468_ace0 };
    const reference = sha.witness(initial, block);
    const statement = round.Statement{ .initial = initial, .final = reference.states[64], .schedule = reference.schedule };
    var fixed = try round.writeFixedPrivate(allocator);
    defer fixed.deinit();
    var main = try round.writeMain(allocator, statement);
    defer main.deinit();
    try round.validateCommittedTrace(statement, fixed.values, main.values);
    for (0..65) |t| {
        const row = t + 3;
        const got = sha.State{
            wordAt(main.values, row, 0),
            wordAt(main.values, row - 1, 0),
            wordAt(main.values, row - 2, 0),
            wordAt(main.values, row - 3, 0),
            wordAt(main.values, row, 32),
            wordAt(main.values, row - 1, 32),
            wordAt(main.values, row - 2, 32),
            wordAt(main.values, row - 3, 32),
        };
        try std.testing.expectEqualDeep(reference.states[t], got);
    }
    var digest_state = reference.states[64];
    for (&digest_state, initial) |*value, initial_word| value.* +%= initial_word;
    var independent = std.crypto.hash.sha2.Sha256.init(.{});
    independent.s = initial;
    independent.update(&block);
    try std.testing.expectEqualDeep(independent.s, digest_state);

    const changed_bits = [_]struct { row: usize, col: usize }{
        .{ .row = 0, .col = 0 }, // d history
        .{ .row = 1, .col = 32 }, // g history
        .{ .row = 2, .col = 0 }, // b history
        .{ .row = 3, .col = 32 }, // e initial and first active
        .{ .row = 20, .col = 1 }, // middle round state
        .{ .row = 64, .col = 32 }, // h final
        .{ .row = 67, .col = 0 }, // a final
    };
    for (changed_bits) |change| {
        const at = round.storageIndex(change.row);
        const old = main.values[change.col].values[at];
        @constCast(main.values[change.col].values)[at] = M31.one().sub(old);
        try expectInvalidRound(statement, fixed.values, main.values);
        @constCast(main.values[change.col].values)[at] = old;
    }
    const changed_scalars = [_]struct { row: usize, col: usize, value: u32 }{
        .{ .row = 9, .col = 64, .value = 2 }, // non-Boolean carry
        .{ .row = 9, .col = 76, .value = 49151 }, // private W low
        .{ .row = 68, .col = 0, .value = 1 }, // padding bit
        .{ .row = 67, .col = 64, .value = 1 }, // terminal carry
        .{ .row = 0, .col = 76, .value = 1 }, // history W
    };
    for (changed_scalars) |change| {
        const at = round.storageIndex(change.row);
        const old = main.values[change.col].values[at];
        @constCast(main.values[change.col].values)[at] = M31.fromCanonical(change.value);
        if (!old.eql(main.values[change.col].values[at])) try expectInvalidRound(statement, fixed.values, main.values);
        @constCast(main.values[change.col].values)[at] = old;
    }
    const k_at = round.storageIndex(11);
    const old_k = fixed.values[4].values[k_at];
    @constCast(fixed.values[4].values)[k_at] = old_k.add(M31.one());
    try expectInvalidRound(statement, fixed.values, main.values);
    @constCast(fixed.values[4].values)[k_at] = old_k;

    const elements = bus.Elements.init(core.fields.qm31.QM31.fromU32Unchecked(17, 3, 5, 7), core.fields.qm31.QM31.fromU32Unchecked(11, 13, 19, 23));
    var interaction = try word.writeInteraction(allocator, fixed.values, main.values, 17, elements);
    defer interaction.deinit();
    const component = word.Component{ .call_id = 17, .elements = elements, .claimed_sum = interaction.claimed_sum };
    try word.validateCommittedTrace(&component, fixed.values, main.values, interaction.columns);
    const addr_at = round.storageIndex(66);
    const old_addr = fixed.values[7].values[addr_at];
    @constCast(fixed.values[7].values)[addr_at] = old_addr.add(M31.one());
    try std.testing.expectError(error.InvalidShaShiftWordConstraint, word.validateCommittedTrace(&component, fixed.values, main.values, interaction.columns));
    @constCast(fixed.values[7].values)[addr_at] = old_addr;
    const selector_at = round.storageIndex(64);
    @constCast(fixed.values[2].values)[selector_at] = M31.zero();
    try std.testing.expectError(error.InvalidShaShiftWordConstraint, word.validateCommittedTrace(&component, fixed.values, main.values, interaction.columns));
}
