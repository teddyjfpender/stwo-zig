//! Native proof harness for eight public-boundary SHA feed-forward words.
//! The private state/word-bus join is deliberately outside this component.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const sha = @import("s31_sha_provider").compression;
const air = @import("sha_feed_direct_air.zig");
const native = @import("sha_feed_direct_native_verifier.zig");
const postcard = @import("interop_postcard");

const M31 = core.fields.m31.M31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn padded(message: []const u8) [64]u8 {
    std.debug.assert(message.len <= 55);
    var block = [_]u8{0} ** 64;
    @memcpy(block[0..message.len], message);
    block[message.len] = 0x80;
    std.mem.writeInt(u64, block[56..64], @as(u64, @intCast(message.len)) * 8, .big);
    return block;
}

fn statement(initial: sha.State, block: [64]u8) air.Statement {
    const rounds = sha.witness(initial, block);
    return .{ .initial = initial, .terminal = rounds.states[64], .output = sha.compress(initial, block) };
}

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

fn fixedRoot(allocator: std.mem.Allocator, s: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2) ![32]u8 {
    var fixed = try air.writeFixed(allocator, s);
    defer fixed.deinit();
    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try commit(&scheme, allocator, fixed.values, &channel);
    return scheme.trees.items[0].commitment.root();
}

fn proveAndVerify(allocator: std.mem.Allocator, s: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2, mutation: ?enum { output_bit, carry, fixed_input, fixed_terminal, fixed_output }) !void {
    const key_root = try fixedRoot(allocator, s, pcs);
    var fixed = try air.writeFixed(allocator, s);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, s);
    defer main.deinit();
    if (mutation) |m| switch (m) {
        .output_bit => @constCast(main.values[0].values)[air.storageIndex(3)] = M31.one().sub(main.values[0].values[air.storageIndex(3)]),
        .carry => @constCast(main.values[32].values)[air.storageIndex(2)] = M31.fromCanonical(2),
        .fixed_input => @constCast(fixed.values[0].values)[air.storageIndex(0)] = fixed.values[0].values[air.storageIndex(0)].add(M31.one()),
        .fixed_terminal => @constCast(fixed.values[2].values)[air.storageIndex(1)] = fixed.values[2].values[air.storageIndex(1)].add(M31.one()),
        .fixed_output => @constCast(fixed.values[4].values)[air.storageIndex(7)] = fixed.values[4].values[air.storageIndex(7)].add(M31.one()),
    };
    if (mutation == null) try air.validateCommittedTrace(fixed.values, main.values);
    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    const root = scheme.trees.items[0].commitment.root();
    if (mutation == .fixed_input or mutation == .fixed_terminal or mutation == .fixed_output) {
        try std.testing.expect(!std.mem.eql(u8, &key_root, &root));
        return;
    }
    try std.testing.expectEqualDeep(key_root, root);
    try commit(&scheme, allocator, main.values, &channel);
    const component = air.Component{};
    const handles = [_]prover.air.component_prover.ComponentProver{component.asProverComponent()};
    scheme_owned = false;
    var timer = try std.time.Timer.start();
    var proof = Engine.prove(allocator, &handles, &channel, scheme, .{ .include_all_preprocessed_columns = true }) catch |err| {
        if (mutation != null and err == error.ConstraintsNotSatisfied) return;
        return err;
    };
    const prove_ns = timer.read();
    defer proof.deinit(allocator);
    const roots = proof.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(@as(usize, 3), roots.len);
    try std.testing.expectEqualDeep(key_root, roots[0]);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try postcard.serializeProof(H, bytes.writer(allocator), proof.proof);
    if (mutation == null) {
        timer.reset();
        try native.verifyBytes(allocator, s, pcs, key_root, bytes.items);
        const verify_ns = timer.read();
        std.debug.print("S31_SHA_FEED_DIRECT verified=true rows={d} fixed={d} main={d} constraints={d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{ air.rows, air.fixed_width, air.main_width, air.n_constraints, prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, bytes.items.len });
        var changed = s;
        changed.initial[0] ^= 1;
        var changed_root = try fixedRoot(allocator, changed, pcs);
        try std.testing.expect(!std.mem.eql(u8, &changed_root, &key_root));
        try std.testing.expectError(error.WrongShaFeedFixedRoot, native.verifyBytes(allocator, changed, pcs, changed_root, bytes.items));
        changed = s;
        changed.terminal[1] ^= 1;
        changed_root = try fixedRoot(allocator, changed, pcs);
        try std.testing.expect(!std.mem.eql(u8, &changed_root, &key_root));
        try std.testing.expectError(error.WrongShaFeedFixedRoot, native.verifyBytes(allocator, changed, pcs, changed_root, bytes.items));
        changed = s;
        changed.output[7] ^= 1;
        changed_root = try fixedRoot(allocator, changed, pcs);
        try std.testing.expect(!std.mem.eql(u8, &changed_root, &key_root));
        try std.testing.expectError(error.WrongShaFeedFixedRoot, native.verifyBytes(allocator, changed, pcs, changed_root, bytes.items));
        try std.testing.expectError(error.EndOfStream, native.verifyBytes(allocator, s, pcs, key_root, bytes.items[0..4]));
    } else {
        if (native.verifyBytes(allocator, s, pcs, key_root, bytes.items)) |_| return error.MutatedShaFeedProofAccepted else |_| {}
    }
}

test "direct feed-forward AIR proves SHA compression outputs" {
    const allocator = std.testing.allocator;
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    for ([_][]const u8{ "", "abc" }) |message| {
        const s = statement(sha.initial_state, padded(message));
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});
        try std.testing.expectEqualSlices(u8, &digest, &sha.stateBytes(s.output));
        try proveAndVerify(allocator, s, pcs, null);
    }
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(73 * i + 19);
    const arbitrary_initial: sha.State = .{ 0x1234_5678, 0xfedc_ba98, 0, 0xffff_ffff, 0x89ab_cdef, 0x7654_3210, 0x1357_9bdf, 0x2468_ace0 };
    const s = statement(arbitrary_initial, block);
    var oracle = std.crypto.hash.sha2.Sha256.init(.{});
    oracle.s = arbitrary_initial;
    oracle.update(&block);
    try std.testing.expectEqualDeep(oracle.s, s.output);
    try proveAndVerify(allocator, s, pcs, null);
}

test "direct feed-forward AIR rejects output, carry, and boundary mutation" {
    const allocator = std.testing.allocator;
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    const s = statement(sha.initial_state, padded("abc"));
    try proveAndVerify(allocator, s, pcs, .output_bit);
    try proveAndVerify(allocator, s, pcs, .carry);
    try proveAndVerify(allocator, s, pcs, .fixed_input);
    try proveAndVerify(allocator, s, pcs, .fixed_terminal);
    try proveAndVerify(allocator, s, pcs, .fixed_output);
}

test "feed AIR exposes exact word-bus halves by fixed row" {
    const allocator = std.testing.allocator;
    const s = statement(sha.initial_state, padded("abc"));
    var fixed = try air.writeFixed(allocator, s);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, s);
    defer main.deinit();
    for (0..air.rows) |i| {
        const storage = air.storageIndex(i);
        var fv: [air.fixed_width]M31 = undefined;
        var mv: [air.main_width]M31 = undefined;
        for (&fv, fixed.values) |*slot, column| slot.* = column.values[storage];
        for (&mv, main.values) |*slot, column| slot.* = column.values[storage];
        const bus = air.busWords(M31, fv, mv);
        try std.testing.expectEqual(s.initial[i] & 0xffff, bus.incoming[0].toU32());
        try std.testing.expectEqual(s.initial[i] >> 16, bus.incoming[1].toU32());
        try std.testing.expectEqual(s.terminal[i] & 0xffff, bus.terminal[0].toU32());
        try std.testing.expectEqual(s.terminal[i] >> 16, bus.terminal[1].toU32());
        try std.testing.expectEqual(s.output[i] & 0xffff, bus.output[0].toU32());
        try std.testing.expectEqual(s.output[i] >> 16, bus.output[1].toU32());
    }
}

test "private feed mode puts state boundaries in main and keeps canonical row indices fixed" {
    const allocator = std.testing.allocator;
    const s = statement(sha.initial_state, padded("abc"));
    var fixed = try air.writeFixedPrivate(allocator);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, s);
    defer main.deinit();
    try air.validateCommittedTraceMode(fixed.values, main.values, true);
    try std.testing.expectError(error.InvalidShaFeedConstraint, air.validateCommittedTraceMode(fixed.values, main.values, false));
    const storage = air.storageIndex(0);
    @constCast(main.values[34].values)[storage] = main.values[34].values[storage].add(M31.one());
    try std.testing.expectError(error.InvalidShaFeedConstraint, air.validateCommittedTraceMode(fixed.values, main.values, true));
}
