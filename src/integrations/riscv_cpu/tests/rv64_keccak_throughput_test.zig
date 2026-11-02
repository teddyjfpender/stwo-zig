//! Throughput-v1 Keccak-f truth: same MAIN witness as the compact component,
//! lookups through the RV32 throughput tables (2^21 five-output chi, 2^16
//! three-position xor5). Qualification: geometry, degree, SIMD parity, a fresh
//! receiver proof, and forged witnesses / multiplicities / tables rejected.
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
const P = E.BatchPolicy.throughput_v1;
const fixture = @import("rv64_keccak_proof_test.zig");

test "throughput geometry: 152 batches, 608 interaction columns, degree four, 2^21/2^16 tables" {
    try std.testing.expectEqual(@as(usize, 427), P.lookups());
    try std.testing.expectEqual(@as(usize, 143), P.roundBatches());
    try std.testing.expectEqual(@as(usize, 152), P.batches());
    try std.testing.expectEqual(@as(usize, 608), P.interactionCount());
    try std.testing.expectEqual(@as(u8, 4), P.degree());
    try std.testing.expectEqual(@as(u32, 21), P.tableLog(.chi));
    try std.testing.expectEqual(@as(u32, 16), P.tableLog(.xor5));
    // MAIN is unchanged: 1923 + 608 = 2531 committed columns vs 1923 + 2596.
    try std.testing.expectEqual(@as(usize, 2531), L.MAIN + P.interactionCount());
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = E.Challenges.draw(&channel);
    const component = K.component.Component{ .kind = .permutation, .log_size = 10, .calls = 3, .challenges = ch, .claim = Q.zero(), .policy = .throughput_v1 };
    try std.testing.expectEqual(@as(usize, 608), component.interactionCount());
    try std.testing.expectEqual(L.DIRECT + 152, component.nConstraints());
    try std.testing.expectEqual(@as(u8, 4), try component.constraintDegreeBound(L.DIRECT + 151));
    // Tables are only admitted at their policy's universe size.
    const chi = K.component.Component{ .kind = .chi, .log_size = 13, .challenges = ch, .claim = Q.zero(), .policy = .throughput_v1 };
    try std.testing.expectError(error.InvalidKeccakComponentGeometry, chi.validate());
    const chi21 = K.component.Component{ .kind = .chi, .log_size = 21, .challenges = ch, .claim = Q.zero(), .policy = .throughput_v1 };
    try chi21.validate();
    const compact21 = K.component.Component{ .kind = .chi, .log_size = 21, .challenges = ch, .claim = Q.zero() };
    try std.testing.expectError(error.InvalidKeccakComponentGeometry, compact21.validate());
    const quartet = K.component.Component{ .kind = .permutation, .log_size = 10, .calls = 3, .challenges = ch, .claim = Q.zero(), .policy = .quartet_v3 };
    try std.testing.expectError(error.InvalidKeccakPolicy, quartet.validate());
}

test "throughput profile identity differs from triple and quartet transcripts" {
    var digests: [3][32]u8 = undefined;
    for ([_]E.BatchPolicy{ .triple_v2, .quartet_v3, .throughput_v1 }, &digests) |policy, *out| {
        var channel = core.channel.blake2s.Blake2sChannel{};
        policy.mix(&channel);
        out.* = channel.digest;
    }
    try std.testing.expect(!std.mem.eql(u8, &digests[0], &digests[2]));
    try std.testing.expect(!std.mem.eql(u8, &digests[1], &digests[2]));
}

test "throughput mass admission: bounded by field size, never wraps before compact admission" {
    const max_slots: u64 = (core.fields.m31.Modulus - 1) / (24 * 320);
    _ = try L.admitThroughputRoster(&.{@intCast(2 * max_slots)});
    try std.testing.expectError(error.KeccakLookupMassExceeded, L.admitThroughputRoster(&.{@intCast(2 * max_slots + 2)}));
    // Compact admission (1600 chi/row) is strictly tighter; every admitted
    // compact geometry is admitted here.
    const compact_max = 2 * ((core.fields.m31.Modulus - 1) / (24 * 1600));
    _ = try L.admitRoster(&.{compact_max}, &.{});
    _ = try L.admitThroughputRoster(&.{compact_max});
    // Table multiplicities: total >= p and padded xor5 rows are rejected.
    const chi = try a.alloc(u64, 1 << 21);
    defer a.free(chi);
    @memset(chi, 0);
    chi[5] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidKeccakTableCounts, K.tables.Trace.initPolicy(a, .chi, .throughput_v1, chi));
    const xor5 = try a.alloc(u64, 1 << 16);
    defer a.free(xor5);
    @memset(xor5, 0);
    xor5[46_656] = 1;
    try std.testing.expectError(error.InvalidKeccakTableCounts, K.tables.Trace.initPolicy(a, .xor5, .throughput_v1, xor5));
    // Wrong-size count vectors (compact sizes) are rejected.
    const small: [8192]u64 = @splat(0);
    try std.testing.expectError(error.InvalidKeccakTableCounts, K.tables.Trace.initPolicy(a, .chi, .throughput_v1, &small));
}

fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn affine(values: []Q, rng: std.Random, x: Q) void {
    for (values) |*value| value.* = randomQ(rng).add(randomQ(rng).mul(x));
}
test "throughput raw rows have degree at most four" {
    const count = P.constraints();
    const output = try a.alloc(Q, 6 * count);
    defer a.free(output);
    const scratch = try a.create(K.component.Scratch);
    defer a.destroy(scratch);
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    for (0..6) |t| {
        var prng = std.Random.DefaultPrng.init(0x4b54505544454734);
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
    var fourth_nonzero = false;
    for (0..count) |constraint| {
        var differences: [6]Q = undefined;
        for (&differences, 0..) |*value, i| value.* = output[i * count + constraint];
        for (0..5) |order| {
            for (0..5 - order) |i| differences[i] = differences[i + 1].sub(differences[i]);
            if (order == 3 and constraint >= L.DIRECT) fourth_nonzero = fourth_nonzero or !differences[0].isZero();
        }
        try std.testing.expect(differences[0].isZero());
    }
    try std.testing.expect(fourth_nonzero);
}

test "throughput Base and full extension SIMD lanes retain every scalar residual" {
    const oracle = @import("rv64_keccak_lane_test.zig");
    try oracle.compareWithPolicy(rv.evaluation.PackedBase, .throughput_v1);
    try oracle.compareWithPolicy(rv.evaluation.PackedSecure, .throughput_v1);
}

test "throughput tuples are the RV32 authority's on every active row (independent Keccak reference)" {
    const inputs = [_]K.trace.State{ fixture.inputState(3), fixture.inputState(4), fixture.inputState(5) };
    var trace = try K.trace.Trace.init(a, &inputs, 1);
    defer trace.deinit();
    // Each lookup indexes an exact table row; that row's outputs equal the
    // next round's state computed by the authority's round function.
    var counts = try K.throughput_counts.Counts.fromTrace(a, &trace);
    defer counts.deinit();
    var chi_total: u64 = 0;
    for (counts.chi) |c| chi_total += c;
    var xor_total: u64 = 0;
    for (counts.xor5) |c| xor_total += c;
    // Two slots x 24 round rows, every round row clears 320 + 107 queries.
    try std.testing.expectEqual(@as(u64, 2 * 24 * 320), chi_total);
    try std.testing.expectEqual(@as(u64, 2 * 24 * 107), xor_total);
    // Serial and pooled counts agree.
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = K.parallel.MIN_STACK, .backing_allocator = a });
    defer pool.deinit();
    var big = try K.trace.Trace.initWithLog(a, &inputs, 1, 14);
    defer big.deinit();
    var serial = try K.throughput_counts.Counts.fromTraceWithOptions(a, &big, .{});
    defer serial.deinit();
    var pooled = try K.throughput_counts.Counts.fromTraceWithOptions(a, &big, .{ .pool = &pool });
    defer pooled.deinit();
    try std.testing.expectEqualSlices(u64, serial.chi, pooled.chi);
    try std.testing.expectEqualSlices(u64, serial.xor5, pooled.xor5);
    try std.testing.expectEqualSlices(u64, counts.chi, serial.chi);
}

/// Claim oracle with no table index: the permutation claim the AIR accepts
/// for this (possibly forged) witness, plus table claims for `chi`/`xor5`
/// multiplicities over the canonical (or tampered) table tuples.
fn closure(trace: *const K.trace.Trace, ch: E.Challenges, chi_counts: []const u64, xor_counts: []const u64, chi_fixed: ?[]const M) !Q {
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
            var tuple = try K.tables.tupleAt(.throughput_v1, if (k == 0) .chi else .xor5, i);
            if (k == 0) if (chi_fixed) |f| {
                for (&tuple, 0..) |*v, c| v.* = f[c * counts.len + physical(i, 21)];
            };
            var lifted: [6]Q = undefined;
            for (&lifted, tuple) |*v, b| v.* = Q.fromBase(b);
            sum = sum.add((try lookup.denominator(&lifted).inv()).mulM31(M.fromCanonical(@intCast(count))));
        };
    }
    return sum;
}
fn setBit(row: *K.trace.PackedRow, comptime field: []const u8, cell: usize, a_plane: bool, value: u1) void {
    const words = if (a_plane) &@field(row, field ++ "_a") else &@field(row, field ++ "_b");
    const bit: u6 = @intCast(cell % 64);
    words[cell / 64] = (words[cell / 64] & ~(@as(u64, 1) << bit)) | (@as(u64, value) << bit);
}
fn getBit(row: *const K.trace.PackedRow, comptime field: []const u8, cell: usize, a_plane: bool) u1 {
    const words = if (a_plane) &@field(row, field ++ "_a") else &@field(row, field ++ "_b");
    return @intCast((words[cell / 64] >> @intCast(cell % 64)) & 1);
}
/// Logical row holding round `round`'s input state for the first slot.
fn roundRow(round: usize) usize {
    return 2 + round;
}
fn expectForged(trace: *const K.trace.Trace, honest_chi: []const u64, honest_xor: []const u64, ch: E.Challenges) !void {
    // The native authority refuses the forged witness outright...
    try std.testing.expect(std.meta.isError(K.throughput_counts.Counts.fromTrace(a, trace)));
    // ...and no table-row multiplicity set closes the LogUp sum: the honest
    // counts leave a nonzero residual, and the forged tuple is out of table.
    try std.testing.expect(!(try closure(trace, ch, honest_chi, honest_xor, null)).isZero());
}
test "throughput rejects wrong chi outputs (each lane), wrong xor5 parity and wrong theta/rho/pi wiring" {
    const inputs = [_]K.trace.State{ fixture.inputState(7), fixture.inputState(8) };
    var trace = try K.trace.Trace.init(a, &inputs, 1);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    var honest = try K.throughput_counts.Counts.fromTrace(a, &trace);
    defer honest.deinit();
    // Honest witness closes exactly against its own table multiplicities
    // (IO excluded from the oracle; the IO lanes are unchanged from compact).
    try std.testing.expect((try closure(&trace, ch, honest.chi, honest.xor5, null)).isZero());
    const saved = try a.dupe(K.trace.PackedRow, trace.metadata);
    defer a.free(saved);
    // Wrong chi output in each of the five lanes x of row (y=2, z=17), round 5.
    for (0..5) |x| {
        const cell = authority.laneIndex(x, 2) * 64 + 17;
        const row = &trace.metadata[roundRow(5) + 1];
        setBit(row, "state", cell, true, ~getBit(row, "state", cell, true));
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    // Wrong chi output in the second paired execution (b plane) and on the iota lane.
    {
        const row = &trace.metadata[roundRow(0) + 1];
        setBit(row, "state", 0, false, ~getBit(row, "state", 0, false));
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    // Wrong xor5 parity at (x=3, z=40), round 11.
    {
        const row = &trace.metadata[roundRow(11)];
        setBit(row, "parity", 3 * 64 + 40, true, ~getBit(row, "parity", 3 * 64 + 40, true));
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    // Wrong theta/rho/pi wiring: round 9 applied with one rho offset off by
    // one (chi/iota exact); every later round and parity row is recomputed
    // honestly from the forged state, so the only broken relation is the
    // wiring of round 9's chi queries.
    {
        var states: [2]authority.State = .{ trace.metadata[roundRow(9)].state_a, trace.metadata[roundRow(9)].state_b };
        for (&states) |*state| buggyRound(state, 9);
        for (10..25) |r| {
            const row = &trace.metadata[roundRow(r)];
            row.state_a = states[0];
            row.state_b = states[1];
            if (r < 24) {
                row.parity_a = parities(states[0]);
                row.parity_b = parities(states[1]);
                for (&states) |*state| try authority.applyRound(state, r);
            }
        }
        try expectForged(&trace, honest.chi, honest.xor5, ch);
        @memcpy(trace.metadata, saved);
    }
    try std.testing.expect((try closure(&trace, ch, honest.chi, honest.xor5, null)).isZero());
}
fn parities(state: authority.State) [5]u64 {
    var out: [5]u64 = @splat(0);
    for (0..5) |x| for (0..5) |y| {
        out[x] ^= state[authority.laneIndex(x, y)];
    };
    return out;
}
/// Keccak round with rho offset of lane (1,1) off by one: a plausible wiring bug.
fn buggyRound(state: *authority.State, round: usize) void {
    var columns = [_]u64{0} ** 5;
    for (0..5) |x| for (0..5) |y| {
        columns[x] ^= state[authority.laneIndex(x, y)];
    };
    for (0..5) |x| {
        const delta = columns[(x + 4) % 5] ^ std.math.rotl(u64, columns[(x + 1) % 5], 1);
        for (0..5) |y| state[authority.laneIndex(x, y)] ^= delta;
    }
    var rho_pi: authority.State = @splat(0);
    for (0..5) |x| for (0..5) |y| {
        const offset: u6 = if (x == 1 and y == 1) authority.rho_offsets[x][y] +% 1 else authority.rho_offsets[x][y];
        rho_pi[authority.laneIndex(y, (2 * x + 3 * y) % 5)] = std.math.rotl(u64, state[authority.laneIndex(x, y)], offset);
    };
    for (0..5) |y| for (0..5) |x| {
        state[authority.laneIndex(x, y)] = rho_pi[authority.laneIndex(x, y)] ^ (~rho_pi[authority.laneIndex((x + 1) % 5, y)] & rho_pi[authority.laneIndex((x + 2) % 5, y)]);
    };
    state[0] ^= authority.round_constants[round];
}

test "throughput rejects multiplicity forgery and table tamper" {
    const inputs = [_]K.trace.State{fixture.inputState(9)};
    var trace = try K.trace.Trace.init(a, &inputs, 1);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    var honest = try K.throughput_counts.Counts.fromTrace(a, &trace);
    defer honest.deinit();
    try std.testing.expect((try closure(&trace, ch, honest.chi, honest.xor5, null)).isZero());
    // Moving one unit of multiplicity between rows (mass preserved) breaks it.
    var used: usize = 0;
    while (honest.chi[used] == 0) used += 1;
    const forged = try a.dupe(u64, honest.chi);
    defer a.free(forged);
    forged[used] -= 1;
    forged[(used + 1) % forged.len] += 1;
    try std.testing.expect(!(try closure(&trace, ch, forged, honest.xor5, null)).isZero());
    // The committed table component's claim moves with the multiplicity, so
    // the stitched sum (permutation + tables) no longer matches IO.
    var table = try K.tables.Trace.initPolicy(a, .chi, .throughput_v1, honest.chi);
    defer table.deinit();
    var bad = try K.tables.Trace.initPolicy(a, .chi, .throughput_v1, forged);
    defer bad.deinit();
    const good_claim = try table.generateInteraction(ch);
    const bad_claim = try bad.generateInteraction(ch);
    try std.testing.expect(!good_claim.eql(bad_claim));
    // Table tamper: flip one output of a used chi row. The fixed root binds the
    // canonical table (receiver recomputes it), and even the tamper's own
    // claim does not close against the honest witness.
    var tampered = try K.tables.Trace.initPolicy(a, .chi, .throughput_v1, honest.chi);
    defer tampered.deinit();
    const r = physical(used, 21);
    const n: usize = 1 << 21;
    tampered.fixed[1 * n + r] = M.fromCanonical(tampered.fixed[1 * n + r].toU32() ^ 1);
    try std.testing.expect(!std.mem.eql(u8, std.mem.sliceAsBytes(table.fixed), std.mem.sliceAsBytes(tampered.fixed)));
    try std.testing.expect(!(try closure(&trace, ch, honest.chi, honest.xor5, tampered.fixed)).isZero());
}

test "throughput actual proof and fresh OODS receiver pass; compact receiver rejects it" {
    _ = try fixture.throughput_testing.prove(a, 3, 1, 8, false);
    _ = try fixture.throughput_testing.prove(a, 1, core.fields.m31.Modulus - 2, 5, true);
}
