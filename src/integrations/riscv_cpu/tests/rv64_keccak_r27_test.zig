//! Throughput-r27-v1 Keccak-f truth: the throughput-quartet lookups on a
//! 27-row slot. One complemented A plane per direction replaces the two
//! pair29 planes; call B's IO bits are (v + s[-1] - 1) / 8 of the packed
//! state next to the plane, forced boolean by active * t * (t - 8) = 0.
//! Qualification: geometry/identity, degree <= 5, SIMD parity, slot semantics
//! against an independent permutation, honest residuals on every row,
//! forged planes / packed cells rejected by the direct equations, same LogUp
//! claim as the pair29 quartet, forged permutations rejected, real proof with
//! a fresh receiver and cross-profile receivers rejecting.
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
const P = E.BatchPolicy.throughput_r27_v1;
const Q4 = E.BatchPolicy.throughput_quartet_v1;
const fixture = @import("rv64_keccak_proof_test.zig");
/// Direct-constraint index of state cell i's plane booleanity / unpack equation.
fn booleanIndex(i: usize) usize {
    return 13 + 2 * i;
}
fn unpackIndex(i: usize) usize {
    return 13 + 2 * i + 1;
}

test "r27 geometry: 27 rows per pair, 120 batches, 480 interaction columns, degree five" {
    try std.testing.expectEqual(L.Geometry.pair27, P.geometry());
    try std.testing.expectEqual(@as(usize, 27), P.geometry().rowsPerPair());
    try std.testing.expectEqual(L.Geometry.pair29, Q4.geometry());
    try std.testing.expectEqual(@as(usize, 50), P.ioLookups());
    try std.testing.expectEqual(@as(usize, 107), P.roundBatches());
    try std.testing.expectEqual(@as(usize, 13), P.ioBatches());
    try std.testing.expectEqual(@as(usize, 120), P.batches());
    try std.testing.expectEqual(@as(usize, 480), P.interactionCount());
    try std.testing.expectEqual(@as(u8, 5), P.degree());
    try std.testing.expectEqual(L.DIRECT + 120, P.constraints());
    // Fixed column meaning is pair29's: plane rows 0 / 27, round r at 2 + r.
    try std.testing.expectEqual(@as(usize, 0), L.Geometry.pair27.phaseColumn(0));
    try std.testing.expectEqual(@as(usize, 2), L.Geometry.pair27.phaseColumn(1));
    try std.testing.expectEqual(@as(usize, 25), L.Geometry.pair27.phaseColumn(24));
    try std.testing.expectEqual(@as(usize, 26), L.Geometry.pair27.phaseColumn(25));
    try std.testing.expectEqual(@as(usize, 27), L.Geometry.pair27.phaseColumn(26));
    // 2^18 rows hold 9,709 pairs (pair29: 9,039).
    try std.testing.expectEqual(@as(u32, 18), try L.logSizeFor(.pair27, 19_418));
    try std.testing.expectEqual(@as(u32, 19), try L.logSizeFor(.pair27, 19_420));
    try std.testing.expectEqual(@as(u32, 19), try L.logSize(19_418));
    try L.validateGeometryFor(.pair27, 19_418, 1, 18);
    try std.testing.expectError(error.InvalidKeccakComponentGeometry, L.validateGeometry(19_418, 1, 18));
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = E.Challenges.draw(&channel);
    const component = K.component.Component{ .kind = .permutation, .log_size = 18, .calls = 19_418, .challenges = ch, .claim = Q.zero(), .policy = P };
    try component.validate();
    try std.testing.expectEqual(@as(usize, 480), component.interactionCount());
    try std.testing.expectEqual(@as(u8, 4), try component.constraintDegreeBound(L.DIRECT - 1));
    try std.testing.expectEqual(@as(u8, 5), try component.constraintDegreeBound(L.DIRECT + 119));
    const too_many = K.component.Component{ .kind = .permutation, .log_size = 18, .calls = 19_420, .challenges = ch, .claim = Q.zero(), .policy = P };
    try std.testing.expectError(error.InvalidKeccakComponentGeometry, too_many.validate());
    // Transcript identity differs from every other profile.
    const policies = [_]E.BatchPolicy{ .triple_v2, .quartet_v3, .throughput_v1, .throughput_quartet_v1, .throughput_r27_v1 };
    var digests: [policies.len][32]u8 = undefined;
    for (policies, &digests) |policy, *out| {
        var c = core.channel.blake2s.Blake2sChannel{};
        policy.mix(&c);
        out.* = c.digest;
    }
    for (0..4) |i| try std.testing.expect(!std.mem.eql(u8, &digests[i], &digests[4]));
}

fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn affine(values: []Q, rng: std.Random, x: Q) void {
    for (values) |*value| value.* = randomQ(rng).add(randomQ(rng).mul(x));
}
test "r27 raw rows have degree at most five, unpack degree four" {
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
        var prng = std.Random.DefaultPrng.init(0x4b52323744454734);
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
    var fourth_unpack = false;
    var fifth_io = false;
    for (0..count) |constraint| {
        var differences: [7]Q = undefined;
        for (&differences, 0..) |*value, i| value.* = output[i * count + constraint];
        for (0..6) |order| {
            for (0..6 - order) |i| differences[i] = differences[i + 1].sub(differences[i]);
            // Direct equations stay <= 4 (the fifth difference vanishes).
            if (order == 4 and constraint < L.DIRECT) try std.testing.expect(differences[0].isZero());
            if (order == 3 and constraint == unpackIndex(7)) fourth_unpack = !differences[0].isZero();
            if (order == 4 and constraint == L.DIRECT + P.roundBatches() + 6) fifth_io = !differences[0].isZero();
        }
        try std.testing.expect(differences[0].isZero());
    }
    try std.testing.expect(fourth_unpack and fifth_io);
}

test "r27 Base and full extension SIMD lanes retain every scalar residual" {
    const oracle = @import("rv64_keccak_lane_test.zig");
    try oracle.compareWithPolicy(rv.evaluation.PackedBase, P);
    try oracle.compareWithPolicy(rv.evaluation.PackedSecure, P);
}

/// Bits of call A / call B in direction `out` recovered from a pair27 slot by
/// the AIR's own IO tuple algebra (bytes of each lane).
fn slotBits(trace: *const K.trace.Trace, slot: usize, b_call: bool, out: bool) !K.trace.State {
    const n = trace.size();
    const plane_row = slot * 27 + (if (out) @as(usize, 26) else 0);
    const logical = if (b_call and !out) plane_row + 1 else plane_row;
    var qm: [L.MAIN]Q = undefined;
    for (&qm, try trace.metadataRow(logical)) |*v, b| v.* = Q.fromBase(b);
    var previous: [L.STATE]Q = undefined;
    for (&previous, (try trace.metadataRow((logical + n - 1) % n))[0..L.STATE]) |*v, b| v.* = Q.fromBase(b);
    var qf: [L.FIXED]Q = undefined;
    const r = physical(logical, trace.log_size);
    for (&qf, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
    const row = E.Row{ .main = &qm, .fixed = &qf, .state_minus_two = &previous, .state_minus_one = &previous, .state_plus_one = &previous, .state_plus_two = &previous };
    var state: K.trace.State = undefined;
    for (&state, 0..) |*lane, l| {
        const entry = if (b_call) L.IO_LANES + l else l;
        const tuple = E.ioTupleR27For(Q, row, entry);
        try std.testing.expect(tuple[1].eql(Q.fromBase(M.fromCanonical(@intFromBool(out)))));
        try std.testing.expect(tuple[0].eql(Q.fromBase(M.fromCanonical(trace.first_call_id + @as(u32, @intCast(2 * slot)) + @intFromBool(b_call)))));
        try std.testing.expect(!E.ioActiveR27For(Q, row, entry).isZero());
        lane.* = 0;
        for (0..8) |byte| {
            const value = try tuple[3 + byte].tryIntoM31();
            try std.testing.expect(value.toU32() < 256);
            lane.* |= @as(u64, value.toU32()) << @intCast(8 * byte);
        }
    }
    return state;
}
test "r27 slot semantics: complemented planes and packed B digits reproduce inputs and outputs exactly" {
    const inputs = [_]K.trace.State{ fixture.inputState(51), fixture.inputState(52), fixture.inputState(53) };
    var trace = try K.trace.Trace.initWithLogGeometry(a, &inputs, 7, 8, .pair27);
    defer trace.deinit();
    try std.testing.expectEqual(@as(usize, 2 * 27), trace.metadata.len);
    // Slot 0 holds calls 0 (A) and 1 (B); slot 1 holds call 2 (A) only.
    try std.testing.expectEqualSlices(u64, &inputs[0], &try slotBits(&trace, 0, false, false));
    try std.testing.expectEqualSlices(u64, &inputs[1], &try slotBits(&trace, 0, true, false));
    try std.testing.expectEqualSlices(u64, &fixture.reference(inputs[0]), &try slotBits(&trace, 0, false, true));
    try std.testing.expectEqualSlices(u64, &fixture.reference(inputs[1]), &try slotBits(&trace, 0, true, true));
    try std.testing.expectEqualSlices(u64, &inputs[2], &try slotBits(&trace, 1, false, false));
    try std.testing.expectEqualSlices(u64, &fixture.reference(inputs[2]), &try slotBits(&trace, 1, false, true));
    // Call B of slot 1 is absent: its IO weights vanish on every row.
    for (27..54) |logical| {
        var qm: [L.MAIN]Q = undefined;
        for (&qm, try trace.metadataRow(logical)) |*v, b| v.* = Q.fromBase(b);
        var qf: [L.FIXED]Q = undefined;
        for (&qf, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * trace.size() + physical(logical, trace.log_size)]);
        const row = E.Row{ .main = &qm, .fixed = &qf, .state_minus_two = qm[0..L.STATE], .state_minus_one = qm[0..L.STATE], .state_plus_one = qm[0..L.STATE], .state_plus_two = qm[0..L.STATE] };
        for (L.IO_LANES..2 * L.IO_LANES) |entry| try std.testing.expect(E.ioActiveR27For(Q, row, entry).isZero());
    }
    // Columns 1 and 28 (pair29's B planes) are identically zero.
    for (0..trace.size()) |logical| {
        const r = physical(logical, trace.log_size);
        try std.testing.expect(trace.fixed[1 * trace.size() + r].isZero() and trace.fixed[28 * trace.size() + r].isZero());
    }
}

const Rows = struct {
    scratch: *K.component.Scratch,
    prior: Q,
    fn init(trace: *const K.trace.Trace, policy: E.BatchPolicy, logical: usize) !Rows {
        const n = trace.size();
        const scratch = try a.create(K.component.Scratch);
        errdefer a.destroy(scratch);
        const r = physical(logical, trace.log_size);
        for (&scratch.fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
        for (&scratch.main, try trace.metadataRow(logical)) |*v, b| v.* = Q.fromBase(b);
        for (&scratch.shifted, L.MASK_OFFSETS[1..]) |*state, offset| {
            const neighbour = try trace.metadataRow(@intCast(@mod(@as(isize, @intCast(logical)) + offset, @as(isize, @intCast(n)))));
            for (state, neighbour[0..L.STATE]) |*v, b| v.* = Q.fromBase(b);
        }
        const previous_logical = (logical + n - 1) % n;
        for (&scratch.previous_header, (try trace.metadataRow(previous_logical))[L.ACTIVE_A..]) |*v, b| v.* = Q.fromBase(b);
        var prior = Q.zero();
        if (trace.interaction.len != 0) {
            for (scratch.interaction[0..policy.batches()], 0..) |*v, batch| v.* = secureAt(trace, r, batch);
            prior = secureAt(trace, physical(previous_logical, trace.log_size), policy.batches() - 1);
        } else @memset(scratch.interaction[0..policy.batches()], Q.zero());
        return .{ .scratch = scratch, .prior = prior };
    }
    fn deinit(self: Rows) void {
        a.destroy(self.scratch);
    }
    fn secureAt(t: *const K.trace.Trace, row: usize, batch: usize) Q {
        var limbs: [4]M = undefined;
        for (&limbs, 0..) |*limb, c| limb.* = t.interaction[(4 * batch + c) * t.size() + row];
        return Q.fromM31Array(limbs);
    }
    fn emit(self: Rows, trace: *const K.trace.Trace, policy: E.BatchPolicy, ch: E.Challenges, claim: Q, values: []Q) void {
        var sink = rv.evaluation.Sink{ .values = values[0..policy.constraints()] };
        E.emitForPolicy(Q, policy, self.scratch.row(), self.scratch.interaction[0..policy.batches()], self.prior, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
    }
};
fn firstNonzero(values: []const Q) ?usize {
    for (values, 0..) |value, i| if (!value.isZero()) return i;
    return null;
}

test "r27 honest residuals vanish on every row (odd calls, incomplete tail); same claim as the pair29 quartet" {
    // log 7 = 128 rows: 4 complete slots (108 rows) + an incomplete tail of
    // 20 rows; 5 calls use 3 slots, the third with call B absent.
    const inputs = [_]K.trace.State{ fixture.inputState(61), fixture.inputState(62), fixture.inputState(63), fixture.inputState(64), fixture.inputState(65) };
    var trace = try K.trace.Trace.initWithLogGeometry(a, &inputs, 3, 7, .pair27);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    const claim = try K.interaction.generateForPolicy(&trace, ch, P, .{});
    try std.testing.expectEqual(P.interactionCount() * trace.size(), trace.interaction.len);
    const values = try a.alloc(Q, P.constraints());
    defer a.free(values);
    for (0..trace.size()) |logical| {
        const rows = try Rows.init(&trace, P, logical);
        defer rows.deinit();
        rows.emit(&trace, P, ch, claim, values);
        try std.testing.expectEqual(@as(?usize, null), firstNonzero(values));
    }
    // Identical fraction multiset: the pair29 quartet over the same calls
    // closes to the same claim (round queries and IO tuples are the same).
    var control = try K.trace.Trace.initWithLog(a, &inputs, 3, 8);
    defer control.deinit();
    try std.testing.expect(claim.eql(try K.interaction.generateForPolicy(&control, ch, Q4, .{})));
    // Pooled generation is byte-identical.
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = K.parallel.MIN_STACK, .backing_allocator = a });
    defer pool.deinit();
    var pooled = try K.trace.Trace.initWithLogGeometry(a, &inputs, 3, 7, .pair27);
    defer pooled.deinit();
    try pooled.releaseMain();
    try std.testing.expect(claim.eql(try K.interaction.generateForPolicy(&pooled, ch, P, .{ .pool = &pool })));
    try std.testing.expectEqualSlices(M, trace.interaction, pooled.interaction);
    // One-limb interaction tamper on an IO batch of the output-plane row.
    {
        const logical: usize = 26;
        const r = physical(logical, trace.log_size);
        const index = (4 * (P.roundBatches() + 9) + 1) * trace.size() + r;
        trace.interaction[index] = trace.interaction[index].add(M.one());
        const rows = try Rows.init(&trace, P, logical);
        defer rows.deinit();
        rows.emit(&trace, P, ch, claim, values);
        try std.testing.expectEqual(@as(?usize, L.DIRECT + P.roundBatches() + 9), firstNonzero(values));
        trace.interaction[index] = trace.interaction[index].sub(M.one());
    }
}

test "r27 direct equations reject forged planes and non-canonical packed cells" {
    const inputs = [_]K.trace.State{ fixture.inputState(71), fixture.inputState(72) };
    var trace = try K.trace.Trace.initWithLogGeometry(a, &inputs, 1, 6, .pair27);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = E.Challenges.draw(&channel);
    const values = try a.alloc(Q, P.constraints());
    defer a.free(values);
    const cell: usize = 64 * 13 + 37;
    // (1) Flipped input-plane bit: the plane stays boolean, but on the v0 row
    // t = v0 + p' - 1 leaves {0, 8}; the unpack equation of that cell fails.
    {
        const rows = try Rows.init(&trace, P, 1);
        defer rows.deinit();
        rows.scratch.shifted[1][cell] = Q.one().sub(rows.scratch.shifted[1][cell]);
        rows.emit(&trace, P, ch, Q.zero(), values);
        try std.testing.expectEqual(@as(?usize, unpackIndex(cell)), firstNonzero(values[0..L.DIRECT]));
    }
    // (2) Non-boolean plane cell (2) on the input-plane row.
    {
        const rows = try Rows.init(&trace, P, 0);
        defer rows.deinit();
        rows.scratch.main[cell] = Q.fromBase(M.fromCanonical(2));
        rows.emit(&trace, P, ch, Q.zero(), values);
        try std.testing.expectEqual(@as(?usize, booleanIndex(cell)), firstNonzero(values[0..L.DIRECT]));
    }
    // (3) Non-canonical packed v0 cell: every value outside {1 - p, 9 - p}
    // fails the unpack equation (B digit not boolean).
    for ([_]u32{ 2, 3, 7, 10, 16, core.fields.m31.Modulus - 1 }) |value| {
        const rows = try Rows.init(&trace, P, 1);
        defer rows.deinit();
        rows.scratch.main[cell] = Q.fromBase(M.fromCanonical(value));
        rows.emit(&trace, P, ch, Q.zero(), values);
        try std.testing.expectEqual(@as(?usize, unpackIndex(cell)), firstNonzero(values[0..L.DIRECT]));
    }
    // (4) Flipped output-plane bit: on the output-plane row t = p' + v24 - 1.
    {
        const rows = try Rows.init(&trace, P, 26);
        defer rows.deinit();
        rows.scratch.main[cell] = Q.one().sub(rows.scratch.main[cell]);
        rows.emit(&trace, P, ch, Q.zero(), values);
        try std.testing.expectEqual(@as(?usize, unpackIndex(cell)), firstNonzero(values[0..L.DIRECT]));
    }
    // (5) A non-canonical final-state cell (v24 + 16) next to a boolean
    // output plane breaks that plane row's unpack equation.
    {
        const rows = try Rows.init(&trace, P, 26);
        defer rows.deinit();
        rows.scratch.shifted[1][cell] = rows.scratch.shifted[1][cell].add(Q.fromBase(M.fromCanonical(16)));
        rows.emit(&trace, P, ch, Q.zero(), values);
        try std.testing.expectEqual(@as(?usize, unpackIndex(cell)), firstNonzero(values[0..L.DIRECT]));
    }
    // (6) Honest rows pass the direct equations.
    for (0..27) |logical| {
        const rows = try Rows.init(&trace, P, logical);
        defer rows.deinit();
        rows.emit(&trace, P, ch, Q.zero(), values);
        try std.testing.expectEqual(@as(?usize, null), firstNonzero(values[0..L.DIRECT]));
    }
}

/// LogUp closure oracle over the round queries (geometry-independent: round
/// rows are found by their fixed selectors).
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
test "r27 forged permutations (chi output, round constant, skipped round) do not close" {
    const inputs = [_]K.trace.State{ fixture.inputState(81), fixture.inputState(82) };
    var trace = try K.trace.Trace.initWithLogGeometry(a, &inputs, 1, 6, .pair27);
    defer trace.deinit();
    var channel = core.channel.blake2s.Blake2sChannel{};
    P.mix(&channel);
    const ch = E.Challenges.draw(&channel);
    var honest = try K.throughput_counts.Counts.fromTrace(a, &trace);
    defer honest.deinit();
    try std.testing.expect((try closure(&trace, ch, honest.chi, honest.xor5)).isZero());
    // One slot: 24 round rows x 320 chi queries.
    var chi_total: u64 = 0;
    for (honest.chi) |c| chi_total += c;
    try std.testing.expectEqual(@as(u64, 24 * 320), chi_total);
    const saved = try a.dupe(K.trace.PackedRow, trace.metadata);
    defer a.free(saved);
    const roundRow = struct {
        fn at(round: usize) usize {
            return 1 + round;
        }
    }.at;
    // Wrong chi output (call B, lane (2,3), z = 9) of round 4.
    trace.metadata[roundRow(5)].state_b[authority.laneIndex(2, 3)] ^= 1 << 9;
    try std.testing.expect(std.meta.isError(K.throughput_counts.Counts.fromTrace(a, &trace)));
    try std.testing.expect(!(try closure(&trace, ch, honest.chi, honest.xor5)).isZero());
    @memcpy(trace.metadata, saved);
    // Wrong round constant in round 16 and a skipped round 20, later rounds honest.
    for ([_]usize{ 16, 20 }) |round| {
        var states: [2]authority.State = .{ trace.metadata[roundRow(round)].state_a, trace.metadata[roundRow(round)].state_b };
        if (round == 16) for (&states) |*state| {
            try authority.applyRound(state, round);
            state[0] ^= authority.round_constants[round] ^ authority.round_constants[0];
        };
        for (round + 1..25) |r| {
            const row = &trace.metadata[roundRow(r)];
            row.state_a = states[0];
            row.state_b = states[1];
            if (r < 24) {
                var pa: [5]u64 = @splat(0);
                var pb: [5]u64 = @splat(0);
                for (0..5) |x| for (0..5) |y| {
                    pa[x] ^= states[0][authority.laneIndex(x, y)];
                    pb[x] ^= states[1][authority.laneIndex(x, y)];
                };
                row.parity_a = pa;
                row.parity_b = pb;
                for (&states) |*state| try authority.applyRound(state, r);
            }
        }
        try std.testing.expect(std.meta.isError(K.throughput_counts.Counts.fromTrace(a, &trace)));
        try std.testing.expect(!(try closure(&trace, ch, honest.chi, honest.xor5)).isZero());
        @memcpy(trace.metadata, saved);
    }
}

test "r27 actual proof and fresh OODS receiver pass; compact, throughput-v1 and pair29 quartet receivers reject" {
    _ = try fixture.throughput_testing.proveR27(a, 3, 1, 8, false);
    _ = try fixture.throughput_testing.proveR27(a, 1, core.fields.m31.Modulus - 2, 5, true);
    _ = try fixture.throughput_testing.proveR27(a, 0, 1, 5, false);
    // Five calls (three slots, the last without call B) at log 7.
    _ = try fixture.throughput_testing.proveR27(a, 5, 9, 7, false);
}
