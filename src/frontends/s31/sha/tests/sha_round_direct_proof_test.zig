//! Native proof harness for a SHA-256 round AIR with verifier-owned schedule.
//! This tests the round component in isolation, before a private word bus joins it.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const cpu = @import("stwo_circuit_cpu_integration");
const sha = @import("s31_sha_provider").compression;
const air = @import("../air/sha_round_direct_air.zig");
const native = @import("../verification/sha_round_direct_native_verifier.zig");
const postcard = @import("interop_postcard");

const M31 = core.fields.m31.M31;
const MC = cpu.prove.profiles.Blake2sM31MerkleChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Engine = cpu.prove.Internal.Engine;
const Column = prover.pcs.ColumnEvaluation;

fn statement(initial: sha.State, block: [64]u8) air.Statement {
    const witness = sha.witness(initial, block);
    return .{ .initial = initial, .final = witness.states[64], .schedule = witness.schedule };
}

fn padded(message: []const u8) [64]u8 {
    std.debug.assert(message.len <= 55);
    var block = [_]u8{0} ** 64;
    @memcpy(block[0..message.len], message);
    block[message.len] = 0x80;
    std.mem.writeInt(u64, block[56..64], @as(u64, @intCast(message.len)) * 8, .big);
    return block;
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
    var fixed = try air.writeFixed(allocator, s.schedule);
    defer fixed.deinit();
    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    defer Engine.deinit(&scheme, allocator);
    try commit(&scheme, allocator, fixed.values, &channel);
    return scheme.trees.items[0].commitment.root();
}

fn proveAndVerify(allocator: std.mem.Allocator, s: air.Statement, pcs: core.pcs.config_v2.PcsConfigV2, mutation: ?enum { state, carry, k, padding, terminal_state, terminal_carry }) !void {
    const key_root = try fixedRoot(allocator, s, pcs);
    var fixed = try air.writeFixed(allocator, s.schedule);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, s);
    defer main.deinit();
    if (mutation) |m| switch (m) {
        .state => @constCast(main.values[0].values)[air.storageIndex(19)] = M31.one().sub(main.values[0].values[air.storageIndex(19)]),
        .carry => @constCast(main.values[8 * 32].values)[air.storageIndex(9)] = M31.fromCanonical(2),
        .k => @constCast(fixed.values[5].values)[air.storageIndex(7)] = fixed.values[5].values[air.storageIndex(7)].add(M31.one()),
        .padding => @constCast(main.values[0].values)[air.storageIndex(120)] = M31.one(),
        .terminal_state => @constCast(main.values[0].values)[air.storageIndex(air.terminal_row)] = M31.one().sub(main.values[0].values[air.storageIndex(air.terminal_row)]),
        .terminal_carry => @constCast(main.values[8 * 32].values)[air.storageIndex(air.terminal_row)] = M31.one(),
    };
    if (mutation == null) try air.validateCommittedTrace(s, fixed.values, main.values);
    var channel = MC.Channel{};
    native.mixStatement(&channel, s, pcs);
    var scheme = try Engine.initRevision(allocator, pcs);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setStorePolynomialsCoefficients();
    try commit(&scheme, allocator, fixed.values, &channel);
    const root = scheme.trees.items[0].commitment.root();
    if (mutation == .k) {
        try std.testing.expect(!std.mem.eql(u8, &key_root, &root));
        return; // An independent fixed-column commitment rejects the changed K.
    }
    try std.testing.expectEqualDeep(key_root, root);
    try commit(&scheme, allocator, main.values, &channel);
    const component = air.Component{ .statement = s };
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
        std.debug.print("S31_SHA_ROUND_DIRECT verified=true w0={x} rows={d} fixed={d} main={d} constraints={d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12\n", .{ s.schedule[0], air.rows, air.fixed_width, air.main_width, air.n_constraints, prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, bytes.items.len });
        var changed_statement = s;
        changed_statement.final[0] ^= 1;
        if (native.verifyBytes(allocator, changed_statement, pcs, key_root, bytes.items)) |_| return error.ChangedShaTerminalAccepted else |_| {}
        changed_statement = s;
        changed_statement.initial[0] ^= 1;
        if (native.verifyBytes(allocator, changed_statement, pcs, key_root, bytes.items)) |_| return error.ChangedShaInitialAccepted else |_| {}
        var changed_schedule = s;
        changed_schedule.schedule[0] ^= 1;
        const changed_root = try fixedRoot(allocator, changed_schedule, pcs);
        try std.testing.expect(!std.mem.eql(u8, &changed_root, &key_root));
        try std.testing.expectError(error.WrongShaRoundFixedRoot, native.verifyBytes(allocator, changed_schedule, pcs, changed_root, bytes.items));
    } else {
        if (native.verifyBytes(allocator, s, pcs, key_root, bytes.items)) |_| return error.MutatedShaRoundProofAccepted else |_| {}
    }
}

test "SHA round direct AIR agrees with independently hashed empty and abc messages" {
    const allocator = std.testing.allocator;
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    for ([_][]const u8{ "", "abc" }) |message| {
        const block = padded(message);
        const s = statement(sha.initial_state, block);
        var state = s.final;
        for (&state, s.initial) |*word, initial| word.* +%= initial;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});
        try std.testing.expectEqualSlices(u8, &digest, &sha.stateBytes(state));
        try proveAndVerify(allocator, s, pcs, null);
    }
    var block: [64]u8 = undefined;
    for (&block, 0..) |*byte, i| byte.* = @truncate(73 * i + 19);
    const arbitrary_initial: sha.State = .{ 0x1234_5678, 0xfedc_ba98, 0x0, 0xffff_ffff, 0x89ab_cdef, 0x7654_3210, 0x1357_9bdf, 0x2468_ace0 };
    const arbitrary = statement(arbitrary_initial, block);
    var oracle = std.crypto.hash.sha2.Sha256.init(.{});
    oracle.s = arbitrary_initial;
    oracle.update(&block);
    var output = arbitrary.final;
    for (&output, arbitrary_initial) |*word, initial| word.* +%= initial;
    try std.testing.expectEqualDeep(oracle.s, output);
    try proveAndVerify(allocator, arbitrary, pcs, null);
}

test "SHA round AIR rejects state, carry, constant, schedule and padding changes" {
    const allocator = std.testing.allocator;
    const s = statement(sha.initial_state, padded("abc"));
    var fixed = try air.writeFixed(allocator, s.schedule);
    defer fixed.deinit();
    var main = try air.writeMain(allocator, s);
    defer main.deinit();
    try air.validateCommittedTrace(s, fixed.values, main.values);
    const initial = main.values[0].values[air.storageIndex(19)];
    @constCast(main.values[0].values)[air.storageIndex(19)] = M31.one().sub(initial);
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
    @constCast(main.values[0].values)[air.storageIndex(19)] = initial;
    const next_e_index = 4 * 32;
    const e_bit = main.values[next_e_index].values[air.storageIndex(19)];
    @constCast(main.values[next_e_index].values)[air.storageIndex(19)] = M31.one().sub(e_bit);
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
    @constCast(main.values[next_e_index].values)[air.storageIndex(19)] = e_bit;
    const old_carry = main.values[8 * 32].values[air.storageIndex(9)];
    @constCast(main.values[8 * 32].values)[air.storageIndex(9)] = M31.fromCanonical(2);
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
    @constCast(main.values[8 * 32].values)[air.storageIndex(9)] = old_carry;
    // A seven encoded with Boolean bits cannot satisfy either the six-addend
    // or seven-addend 16-bit sum. These checks exercise the integer bound
    // rather than a separate carry-range polynomial.
    const at = air.storageIndex(9);
    const original_three = [_]M31{
        main.values[8 * 32 + 0].values[at],
        main.values[8 * 32 + 1].values[at],
        main.values[8 * 32 + 2].values[at],
    };
    for (0..3) |i| @constCast(main.values[8 * 32 + i].values)[at] = M31.one();
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
    for (original_three, 0..) |value, i| @constCast(main.values[8 * 32 + i].values)[at] = value;
    const original_next_a = [_]M31{ main.values[8 * 32 + 6].values[at], main.values[8 * 32 + 7].values[at], main.values[8 * 32 + 8].values[at] };
    for (0..3) |i| @constCast(main.values[8 * 32 + 6 + i].values)[at] = M31.one();
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
    for (original_next_a, 0..) |value, i| @constCast(main.values[8 * 32 + 6 + i].values)[at] = value;
    var changed = s;
    changed.schedule[7] ^= 1;
    var changed_fixed = try air.writeFixed(allocator, changed.schedule);
    defer changed_fixed.deinit();
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTrace(s, changed_fixed.values, main.values));
    @constCast(fixed.values[5].values)[air.storageIndex(7)] = fixed.values[5].values[air.storageIndex(7)].add(M31.one());
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTrace(s, fixed.values, main.values));
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, air.log_size);
    try proveAndVerify(allocator, s, pcs, .state);
    try proveAndVerify(allocator, s, pcs, .carry);
    try proveAndVerify(allocator, s, pcs, .k);
    try proveAndVerify(allocator, s, pcs, .padding);
    try proveAndVerify(allocator, s, pcs, .terminal_state);
    try proveAndVerify(allocator, s, pcs, .terminal_carry);
}

test "eliminated T1 round relation matches independent SHA compression across varied states" {
    const allocator = std.testing.allocator;
    var seed: u32 = 0x92b7_a41d;
    for (0..16) |_| {
        var initial: sha.State = undefined;
        for (&initial) |*word| {
            seed = seed *% 1664525 +% 1013904223;
            word.* = seed;
        }
        var block: [64]u8 = undefined;
        for (&block) |*byte| {
            seed = seed *% 1664525 +% 1013904223;
            byte.* = @truncate(seed >> 16);
        }
        const s = statement(initial, block);
        var oracle = std.crypto.hash.sha2.Sha256.init(.{});
        oracle.s = initial;
        oracle.update(&block);
        var fed = s.final;
        for (&fed, initial) |*word, previous| word.* +%= previous;
        try std.testing.expectEqualDeep(oracle.s, fed);
        var fixed = try air.writeFixed(allocator, s.schedule);
        defer fixed.deinit();
        var main = try air.writeMain(allocator, s);
        defer main.deinit();
        try air.validateCommittedTrace(s, fixed.values, main.values);
    }
}

test "SHA quotient vanishing denominator is constant within bit-reversed blocks" {
    for ([_]u32{ 1, 2, 3 }) |extra| {
        const eval_log = air.log_size + extra;
        const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
        const trace_coset = core.poly.circle.canonic.CanonicCoset.new(air.log_size).coset();
        for (0..domain.size()) |i| {
            const representative = (i >> @intCast(air.log_size)) << @intCast(air.log_size);
            const point = domain.at(core.utils.bitReverseIndex(i, eval_log));
            const base = domain.at(core.utils.bitReverseIndex(representative, eval_log));
            const actual = core.constraints.cosetVanishing(M31, trace_coset, point);
            const assumed = core.constraints.cosetVanishing(M31, trace_coset, base);
            if (!actual.eql(assumed)) {
                std.debug.print("denominator mismatch eval_log={d} i={d} rep={d}\n", .{ eval_log, i, representative });
                return error.InvalidShaQuotientDenominator;
            }
        }
    }
}

test "private round mode keeps canonical K and row selectors while W and boundary state live in committed main" {
    const allocator = std.testing.allocator;
    const block = padded("abc");
    const actual = statement(sha.initial_state, block);
    var fixed = try air.writeFixedPrivate(allocator);
    defer fixed.deinit();
    var another_fixed = try air.writeFixedPrivate(allocator);
    defer another_fixed.deinit();
    for (fixed.values, another_fixed.values) |left, right| try std.testing.expectEqualSlices(M31, left.values, right.values);
    var main = try air.writeMain(allocator, actual);
    defer main.deinit();
    const untrusted = air.Statement{ .initial = @splat(0), .final = @splat(0), .schedule = @splat(0) };
    try air.validateCommittedTraceWithMode(untrusted, fixed.values, main.values, true);
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTraceWithMode(untrusted, fixed.values, main.values, false));
    const w_storage = air.storageIndex(0);
    @constCast(main.values[8 * 32 + 12].values)[w_storage] = main.values[8 * 32 + 12].values[w_storage].add(M31.one());
    try std.testing.expectError(error.InvalidShaRoundConstraint, air.validateCommittedTraceWithMode(untrusted, fixed.values, main.values, true));
}
