//! Throughput-quartet-v1 Keccak-f truth: the throughput-v1 MAIN witness,
//! tuples and RV32 tables, with the 427 round queries and 25 IO lanes cleared
//! four per degree-five batch (114 batches, 456 interaction columns instead of
//! 152 / 608). Qualification: geometry and transcript identity, degree <= 5,
//! SIMD parity, row residuals of the honest witness vanish on every row and
//! break under interaction tamper, forged permutations (wrong chi/theta
//! wiring, wrong round constant, skipped round) and forged IO do not close,
//! and a real proof passes a fresh OODS receiver while compact and
//! throughput-v1 receivers reject it.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const E = K.equations;
const L = K.layout;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const physical = rv.witness.physical;
const authority = K.authority;
const a = std.testing.allocator;
const P = E.BatchPolicy.throughput_quartet_v1;
const T1 = E.BatchPolicy.throughput_v1;
const fixture = @import("rv64_keccak_proof_test.zig");

test "throughput quartet geometry: 114 batches, 456 interaction columns, degree five, throughput tables" {
    try std.testing.expectEqual(@as(usize, 427), P.lookups());
    try std.testing.expectEqual(@as(usize, 320), P.chiLookups());
    try std.testing.expectEqual(@as(usize, 107), P.xor5Lookups());
    try std.testing.expectEqual(@as(usize, 107), P.roundBatches());
    try std.testing.expectEqual(@as(usize, 7), P.ioBatches());
    try std.testing.expectEqual(@as(usize, 114), P.batches());
    try std.testing.expectEqual(@as(usize, 456), P.interactionCount());
    try std.testing.expectEqual(@as(u8, 5), P.degree());
    try std.testing.expect(P.throughputTables() and T1.throughputTables());
    try std.testing.expect(!E.BatchPolicy.triple_v2.throughputTables() and !E.BatchPolicy.quartet_v3.throughputTables());
    try std.testing.expectEqual(T1.tableLog(.chi), P.tableLog(.chi));
    try std.testing.expectEqual(T1.tableLog(.xor5), P.tableLog(.xor5));
    // 1923 + 456 = 2379 committed columns per row (throughput-v1: 2531).
    try std.testing.expectEqual(@as(usize, 2379), L.MAIN + P.interactionCount());
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = E.Challenges.draw(&channel);
    const component = K.component.Component{ .kind = .permutation, .log_size = 10, .calls = 3, .challenges = ch, .claim = Q.zero(), .policy = P };
    try component.validate();
    try std.testing.expectEqual(@as(usize, 456), component.interactionCount());
    try std.testing.expectEqual(L.DIRECT + 114, component.nConstraints());
    try std.testing.expectEqual(@as(u8, 4), try component.constraintDegreeBound(L.DIRECT - 1));
    try std.testing.expectEqual(@as(u8, 5), try component.constraintDegreeBound(L.DIRECT));
    try std.testing.expectEqual(@as(u8, 5), try component.constraintDegreeBound(L.DIRECT + 113));
    try std.testing.expectError(error.InvalidConstraintIndex, component.constraintDegreeBound(L.DIRECT + 114));
    // Degree five still fits the log+2 quotient domain (4n quotient degree).
    try std.testing.expectEqual(@as(u32, 12), component.maxConstraintLogDegreeBound());
    // Tables are admitted only at the throughput universe sizes.
    const chi13 = K.component.Component{ .kind = .chi, .log_size = 13, .challenges = ch, .claim = Q.zero(), .policy = P };
    try std.testing.expectError(error.InvalidKeccakComponentGeometry, chi13.validate());
    const chi21 = K.component.Component{ .kind = .chi, .log_size = 21, .challenges = ch, .claim = Q.zero(), .policy = P };
    try chi21.validate();
}

test "throughput quartet transcript identity differs from every other Keccak profile" {
    const policies = [_]E.BatchPolicy{ .triple_v2, .quartet_v3, .throughput_v1, .throughput_quartet_v1 };
    var digests: [policies.len][32]u8 = undefined;
    for (policies, &digests) |policy, *out| {
        var channel = core.channel.blake2s.Blake2sChannel{};
        policy.mix(&channel);
        out.* = channel.digest;
    }
    for (0..3) |i| try std.testing.expect(!std.mem.eql(u8, &digests[i], &digests[3]));
}

fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn affine(values: []Q, rng: std.Random, x: Q) void {
    for (values) |*value| value.* = randomQ(rng).add(randomQ(rng).mul(x));
}
test "throughput quartet raw rows have degree at most five and genuinely use the fifth degree" {
    const count = P.constraints();
    const output = try a.alloc(Q, 7 * count);
    defer a.free(output);
    const scratch = try a.create(K.component.Scratch);
    defer a.destroy(scratch);
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    for (0..7) |t| {
        var prng = std.Random.DefaultPrng.init(0x4b5450513444454);
        const rng = prng.random();
        const x = Q.fromBase(M.fromCanonical(@intCast(t)));
        affine(&scratch.fixed, rng, x);
        affine(&scratch.main, rng, x);
        for (&scratch.shifted) |*state| affine(state, rng, x);
        affine(&scratch.previous_header, rng, x);
        affine(scratch.interaction[0..P.batches()], rng, x);
        const prior = randomQ(rng).add(randomQ(rng).mul(x));
        var sink = rv.evaluation.Sink{ .values = output[t * count ..][0..count] };
        E.emitForPolicy(Q, P, scratch.row(), scratch.interaction[0..P.batches()], prior, claim, ch, .{ .calls = 3, .first_id = core.fields.m31.Modulus - 3 }, &sink);
        try std.testing.expectEqual(count, sink.count);
    }
    // Full round batches and full IO batches use degree five; the partial
    // round batch 106 (three queries + a constant dummy) is only degree four.
    var fifth_nonzero = [_]bool{false} ** 3; // full round batch, partial round batch, IO batch
    for (0..count) |constraint| {
        var differences: [7]Q = undefined;
        for (&differences, 0..) |*value, i| value.* = output[i * count + constraint];
        for (0..6) |order| {
            for (0..6 - order) |i| differences[i] = differences[i + 1].sub(differences[i]);
            if (order == 4 and constraint >= L.DIRECT) {
                const batch = constraint - L.DIRECT;
                const slot: usize = if (batch < 106) 0 else if (batch == 106) 1 else 2;
                fifth_nonzero[slot] = fifth_nonzero[slot] or !differences[0].isZero();
            }
        }
        try std.testing.expect(differences[0].isZero());
    }
    try std.testing.expect(fifth_nonzero[0] and !fifth_nonzero[1] and fifth_nonzero[2]);
}

test "throughput quartet Base and full extension SIMD lanes retain every scalar residual" {
    const oracle = @import("rv64_keccak_lane_test.zig");
    try oracle.compareWithPolicy(rv.evaluation.PackedBase, P);
    try oracle.compareWithPolicy(rv.evaluation.PackedSecure, P);
}

/// Every constraint of `policy` at logical row `logical` of an honest trace
/// with generated interaction, evaluated from the committed columns exactly
/// as the AIR samples them (offsets -2,-1,+1,+2, previous header and the
/// previous row's final secure column). Returns the first nonzero index.
fn firstNonzeroResidual(trace: *const K.trace.Trace, policy: E.BatchPolicy, ch: E.Challenges, claim: Q, logical: usize, values: []Q) !?usize {
    const n = trace.size();
    const scratch = try a.create(K.component.Scratch);
    defer a.destroy(scratch);
    const r = physical(logical, trace.log_size);
    for (&scratch.fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
    const main = try trace.metadataRow(logical);
    for (&scratch.main, main) |*v, b| v.* = Q.fromBase(b);
    for (&scratch.shifted, L.MASK_OFFSETS[1..]) |*state, offset| {
        const neighbour = try trace.metadataRow(@intCast(@mod(@as(isize, @intCast(logical)) + offset, @as(isize, @intCast(n)))));
        for (state, neighbour[0..L.STATE]) |*v, b| v.* = Q.fromBase(b);
    }
    const previous_logical = (logical + n - 1) % n;
    const previous = try trace.metadataRow(previous_logical);
    for (&scratch.previous_header, previous[L.ACTIVE_A..]) |*v, b| v.* = Q.fromBase(b);
    const at = struct {
        fn secure(t: *const K.trace.Trace, row: usize, batch: usize) Q {
            const size = t.size();
            var limbs: [4]M = undefined;
            for (&limbs, 0..) |*limb, c| limb.* = t.interaction[(4 * batch + c) * size + row];
            return Q.fromM31Array(limbs);
        }
    };
    for (scratch.interaction[0..policy.batches()], 0..) |*v, batch| v.* = at.secure(trace, r, batch);
    const prior = at.secure(trace, physical(previous_logical, trace.log_size), policy.batches() - 1);
    var sink = rv.evaluation.Sink{ .values = values[0..policy.constraints()] };
    E.emitForPolicy(Q, policy, scratch.row(), scratch.interaction[0..policy.batches()], prior, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
    for (values[0..policy.constraints()], 0..) |value, i| if (!value.isZero()) return i;
    return null;
}

test "throughput quartet honest row residuals vanish on every row; interaction tamper is caught at its batch" {
    // Three calls: one full pair slot and a half slot (B absent) plus padding.
    const inputs = [_]K.trace.State{ fixture.inputState(11), fixture.inputState(12), fixture.inputState(13) };
    var trace = try K.trace.Trace.initWithLog(a, &inputs, 5, 7);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    const claim = try K.interaction.generateForPolicy(&trace, ch, P, .{});
    try std.testing.expectEqual(P.interactionCount() * trace.size(), trace.interaction.len);
    const values = try a.alloc(Q, P.constraints());
    defer a.free(values);
    for (0..trace.size()) |logical| try std.testing.expectEqual(@as(?usize, null), try firstNonzeroResidual(&trace, P, ch, claim, logical, values));
    // The same witness under throughput-v1 batching closes to the same claim:
    // identical fractions, only the per-batch grouping differs.
    var control = try K.trace.Trace.initWithLog(a, &inputs, 5, 7);
    defer control.deinit();
    try std.testing.expect(claim.eql(try K.interaction.generateForPolicy(&control, ch, T1, .{})));
    // A wrong claim breaks batch 0 on the first row only.
    try std.testing.expectEqual(@as(?usize, L.DIRECT), try firstNonzeroResidual(&trace, P, ch, claim.add(Q.one()), 0, values));
    // Tampering one limb of one batch on a round row (round 3 of slot 0)
    // breaks exactly that batch's clearing equation there: each batch,
    // including the partial batch 106 (dummy entry d = 1, c = 0) and the IO
    // batches, is pinned to its own four fractions.
    const round_row: usize = 1 + 3; // logical row of round 3 (rows 0,1 are input planes, row 2 is round 0)
    const io_row: usize = 0; // input plane A is an IO row
    for ([_][2]usize{ .{ round_row, 0 }, .{ round_row, 57 }, .{ round_row, 106 }, .{ io_row, 107 }, .{ io_row, 113 } }) |case| {
        const r = physical(case[0], trace.log_size);
        const index = (4 * case[1] + 2) * trace.size() + r;
        const saved = trace.interaction[index];
        trace.interaction[index] = saved.add(M.one());
        try std.testing.expectEqual(@as(?usize, L.DIRECT + case[1]), try firstNonzeroResidual(&trace, P, ch, claim, case[0], values));
        trace.interaction[index] = saved;
    }
    // Giving the dummy slot of the partial batch weight (an honest-looking
    // extra fraction 1/1 hidden in the dummy entry) does not satisfy batch 106.
    {
        const r = physical(round_row, trace.log_size);
        var limbs: [4]M = undefined;
        for (&limbs, 0..) |*limb, c| limb.* = trace.interaction[(4 * 106 + c) * trace.size() + r];
        const shifted = Q.fromM31Array(limbs).sub(Q.one()).toM31Array();
        var saved: [4]M = undefined;
        for (&saved, shifted, 0..) |*s, v, c| {
            s.* = trace.interaction[(4 * 106 + c) * trace.size() + r];
            trace.interaction[(4 * 106 + c) * trace.size() + r] = v;
        }
        try std.testing.expectEqual(@as(?usize, L.DIRECT + 106), try firstNonzeroResidual(&trace, P, ch, claim, round_row, values));
        for (saved, 0..) |v, c| trace.interaction[(4 * 106 + c) * trace.size() + r] = v;
    }
    for (0..trace.size()) |logical| try std.testing.expectEqual(@as(?usize, null), try firstNonzeroResidual(&trace, P, ch, claim, logical, values));
}

test "throughput quartet serial and pooled interaction agree byte for byte" {
    const inputs = [_]K.trace.State{ fixture.inputState(21), fixture.inputState(22), fixture.inputState(23), fixture.inputState(24), fixture.inputState(25) };
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    var serial = try K.trace.Trace.initWithLog(a, &inputs, 1, 9);
    defer serial.deinit();
    const expected = try K.interaction.generateForPolicy(&serial, ch, P, .{});
    for ([_]usize{ 2, 3, 8 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = K.parallel.MIN_STACK, .backing_allocator = a });
        defer pool.deinit();
        var pooled = try K.trace.Trace.initWithLog(a, &inputs, 1, 9);
        defer pooled.deinit();
        try pooled.releaseMain();
        try std.testing.expect(expected.eql(try K.interaction.generateForPolicy(&pooled, ch, P, .{ .pool = &pool })));
        try std.testing.expectEqualSlices(M, serial.interaction, pooled.interaction);
    }
}

/// LogUp closure oracle (batching-independent; the quartet clears the same
/// fractions as throughput-v1): permutation round queries the AIR accepts for
/// this (possibly forged) witness against table multiplicities.
fn closure(trace: *const K.trace.Trace, ch: E.Challenges, chi_counts: []const u64, xor_counts: []const u64) !Q {
    const n = trace.size();
    var sum = Q.zero();
    for (0..n) |logical| {
        const r = physical(logical, trace.log_size);
        var fixed: [L.FIXED]M = undefined;
        for (&fixed, 0..) |*v, c| v.* = trace.fixed[c * n + r];
        const main = try trace.metadataRow(logical);
        var round = M.zero();
        for (fixed[2..26]) |s| round = round.add(s);
        round = round.mul(main[L.ACTIVE_A]);
        if (!round.isZero()) {
            const next = try trace.metadataRow((logical + 1) % n);
            for (0..P.lookups()) |event| {
                const tuple = E.throughputTupleFor(M, main[0..L.STATE], main[L.STATE..L.ACTIVE_A], next[0..L.STATE], fixed[2..26], event);
                var lifted: [6]Q = undefined;
                for (&lifted, tuple) |*v, b| v.* = Q.fromBase(b);
                const lookup = if (event < P.chiLookups()) ch.chi else ch.xor5;
                sum = sum.sub((try lookup.denominator(&lifted).inv()).mulM31(round));
            }
        }
    }
    for ([_][]const u64{ chi_counts, xor_counts }, 0..) |counts, k| {
        const lookup = if (k == 0) ch.chi else ch.xor5;
        for (counts, 0..) |count, i| if (count != 0) {
            const tuple = try K.tables.tupleAt(P, if (k == 0) .chi else .xor5, i);
            var lifted: [6]Q = undefined;
            for (&lifted, tuple) |*v, b| v.* = Q.fromBase(b);
            sum = sum.add((try lookup.denominator(&lifted).inv()).mulM31(M.fromCanonical(@intCast(count))));
        };
    }
    return sum;
}
fn roundRow(round: usize) usize {
    return 2 + round;
}
fn parities(state: authority.State) [5]u64 {
    var out: [5]u64 = @splat(0);
    for (0..5) |x| for (0..5) |y| {
        out[x] ^= state[authority.laneIndex(x, y)];
    };
    return out;
}
/// Overwrite rows from round `from` on with `states` (round `from` input),
/// recomputing parities and later rounds honestly.
fn rewriteFrom(trace: *K.trace.Trace, from: usize, initial: [2]authority.State) !void {
    var states = initial;
    for (from..25) |r| {
        const row = &trace.metadata[roundRow(r)];
        row.state_a = states[0];
        row.state_b = states[1];
        if (r < 24) {
            row.parity_a = parities(states[0]);
            row.parity_b = parities(states[1]);
            for (&states) |*state| try authority.applyRound(state, r);
        }
    }
}
fn expectForged(trace: *const K.trace.Trace, honest_chi: []const u64, honest_xor: []const u64, ch: E.Challenges) !void {
    // The native authority refuses the forged witness (out-of-table tuple)...
    try std.testing.expect(std.meta.isError(K.throughput_counts.Counts.fromTrace(a, trace)));
    // ...and the honest multiplicities leave a nonzero LogUp residual.
    try std.testing.expect(!(try closure(trace, ch, honest_chi, honest_xor)).isZero());
}
test "throughput quartet rejects wrong round constant, skipped round and wrong theta parity" {
    const inputs = [_]K.trace.State{ fixture.inputState(31), fixture.inputState(32) };
    var trace = try K.trace.Trace.init(a, &inputs, 1);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    var honest = try K.throughput_counts.Counts.fromTrace(a, &trace);
    defer honest.deinit();
    try std.testing.expect((try closure(&trace, ch, honest.chi, honest.xor5)).isZero());
    const saved = try a.dupe(K.trace.PackedRow, trace.metadata);
    defer a.free(saved);
    // Wrong round constant: round 7 applies round 8's iota constant; every
    // later round is recomputed honestly from that state.
    {
        var states: [2]authority.State = .{ trace.metadata[roundRow(7)].state_a, trace.metadata[roundRow(7)].state_b };
        for (&states) |*state| {
            try authority.applyRound(state, 7);
            state[0] ^= authority.round_constants[7] ^ authority.round_constants[8];
        }
        try rewriteFrom(&trace, 8, states);
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    // Skipped round: round 12's output row repeats its input (no permutation
    // applied), later rounds honest.
    {
        const states: [2]authority.State = .{ trace.metadata[roundRow(12)].state_a, trace.metadata[roundRow(12)].state_b };
        try rewriteFrom(&trace, 13, states);
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    // Skipped round with a consistent final state: drop round 23 entirely so
    // the published output is the 23-round permutation.
    {
        const states: [2]authority.State = .{ trace.metadata[roundRow(23)].state_a, trace.metadata[roundRow(23)].state_b };
        const row = &trace.metadata[roundRow(24)];
        row.state_a = states[0];
        row.state_b = states[1];
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    // Wrong theta parity in the second paired execution at (x=0, z=63), round 2.
    {
        const row = &trace.metadata[roundRow(2)];
        row.parity_b[0] ^= @as(u64, 1) << 63;
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    // Wrong chi output on the iota lane (x=0,y=0,z=0) of round 19, first execution.
    {
        const row = &trace.metadata[roundRow(19) + 1];
        row.state_a[0] ^= 1;
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    try std.testing.expect((try closure(&trace, ch, honest.chi, honest.xor5)).isZero());
}

fn ioTuple(id: u32, direction: u32, lane: usize, state: K.trace.State) [L.IO_ARITY]Q {
    var tuple: [L.IO_ARITY]Q = undefined;
    tuple[0] = Q.fromBase(M.fromCanonical(id));
    tuple[1] = Q.fromBase(M.fromCanonical(direction));
    tuple[2] = Q.fromBase(M.fromCanonical(@intCast(lane)));
    for (0..8) |byte| tuple[3 + byte] = Q.fromBase(M.fromCanonical(@intCast((state[lane] >> @as(u6, @intCast(8 * byte))) & 255)));
    return tuple;
}
/// IO11 mass a caller (sponge or Word16 bridge) would publish for `inputs`
/// with outputs `outputs`, IDs from `first`.
fn ioSum(inputs: []const K.trace.State, outputs: []const K.trace.State, first: u32, ch: E.Challenges) !Q {
    var sum = Q.zero();
    for (inputs, outputs, 0..) |input, output, i| for (0..L.IO_LANES) |lane| {
        sum = sum.add(try ch.io.denominator(&ioTuple(first + @as(u32, @intCast(i)), 0, lane, input)).inv());
        sum = sum.add(try ch.io.denominator(&ioTuple(first + @as(u32, @intCast(i)), 1, lane, output)).inv());
    };
    return sum;
}
test "throughput quartet IO closes only against the true permutation outputs, IDs and inputs" {
    const inputs = [_]K.trace.State{ fixture.inputState(41), fixture.inputState(42), fixture.inputState(43) };
    var outputs: [3]K.trace.State = undefined;
    for (&outputs, inputs) |*o, i| o.* = fixture.reference(i);
    var f = try fixture.Fixture.initWithPolicy(a, &inputs, 9, 8, P);
    defer f.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    const claim = try K.interaction.generateForPolicy(&f.trace, ch, P, .{});
    const total = claim.add(try f.chi.generateInteraction(ch)).add(try f.xor5.generateInteraction(ch));
    try std.testing.expect(total.eql(try ioSum(&inputs, &outputs, 9, ch)));
    // Forged output byte (absorb/squeeze forgery seen by the caller), forged
    // input lane, swapped call IDs and a shifted ID span all leave IO open.
    var forged_out = outputs;
    forged_out[1][4] ^= 1 << 13;
    try std.testing.expect(!total.eql(try ioSum(&inputs, &forged_out, 9, ch)));
    var forged_in = inputs;
    forged_in[2][24] ^= 1 << 63;
    try std.testing.expect(!total.eql(try ioSum(&forged_in, &outputs, 9, ch)));
    const swapped_in = [_]K.trace.State{ inputs[1], inputs[0], inputs[2] };
    const swapped_out = [_]K.trace.State{ outputs[1], outputs[0], outputs[2] };
    try std.testing.expect(!total.eql(try ioSum(&swapped_in, &swapped_out, 9, ch)));
    try std.testing.expect(!total.eql(try ioSum(&inputs, &outputs, 10, ch)));
}

test "throughput quartet actual proof and fresh OODS receiver pass; compact and throughput-v1 receivers reject" {
    // The fixture verifies with a fresh receiver, then asserts that the
    // triple-v2 and the throughput-v1 receivers both reject the quartet proof
    // (and, for tamper, that one sampled interaction value fails OODS).
    _ = try fixture.throughput_testing.proveQuartet(a, 3, 1, 8, false);
    _ = try fixture.throughput_testing.proveQuartet(a, 1, core.fields.m31.Modulus - 2, 5, true);
    _ = try fixture.throughput_testing.proveQuartet(a, 0, 1, 5, false);
}
