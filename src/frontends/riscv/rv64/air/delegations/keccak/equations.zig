//! One QM31 authority for the concrete paired permutation and its stitched LogUp.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
pub const BatchPolicy = @import("batch_policy.zig").Policy;
const L = @import("layout.zig");
const V = @import("../../evaluation.zig");
pub const lookup_tuple_authority = @import("../../../../air/guest_precompile/keccakf_lookup_tuples.zig");
const tuples = lookup_tuple_authority;
pub const LookupFor = @import("../../providers/tables.zig").ChallengesFor;
pub const Lookup = LookupFor(Q);
pub fn IoFor(comptime C: type) type {
    return struct {
        offset: C,
        coefficients: [L.IO_ARITY]C,
        pub fn draw(channel: anytype) @This() {
            var result: @This() = undefined;
            result.offset = channel.drawSecureFelt();
            for (&result.coefficients) |*coefficient| coefficient.* = channel.drawSecureFelt();
            return result;
        }
        pub fn denominatorBase(self: @This(), tuple: *const [L.IO_ARITY]M) C {
            var result = self.offset;
            for (tuple, self.coefficients) |value, coefficient| result = result.sub(coefficient.mulM31(value));
            return result;
        }
        pub fn denominator(self: @This(), tuple: *const [L.IO_ARITY]C) C {
            var result = self.offset;
            for (tuple, self.coefficients) |value, coefficient| result = result.sub(value.mul(coefficient));
            return result;
        }
    };
}
pub const Io = IoFor(Q);
/// Keccak lookup challenges over constant lane C (QM31 natively).
pub fn ChallengesFor(comptime C: type) type {
    return struct {
        chi: LookupFor(C),
        xor5: LookupFor(C),
        io: IoFor(C),
        pub fn draw(channel: anytype) @This() {
            return .{ .chi = LookupFor(C).draw(channel), .xor5 = LookupFor(C).draw(channel), .io = IoFor(C).draw(channel) };
        }
    };
}
pub const Challenges = ChallengesFor(Q);
pub const Public = V.CallSpanFor(Q);
const zero_header: [3]Q = @splat(Q.zero());
pub const Row = RowFor(Q);
pub fn RowFor(comptime F: type) type {
    return struct {
        const zeros: [3]F = @splat(F.zero());

        previous_header: *const [3]F = &zeros,
        fixed: *const [L.FIXED]F,
        main: *const [L.MAIN]F,
        state_minus_two: *const [L.STATE]F,
        state_minus_one: *const [L.STATE]F,
        state_plus_one: *const [L.STATE]F,
        state_plus_two: *const [L.STATE]F,
    };
}
pub fn lookupDenominator(row: Row, ch: Challenges, event: usize) Q {
    return lookupDenominatorFor(Q, row, ch, event);
}
/// Shared raw tuple authority for classic and GKR local arguments.
pub fn lookupTupleFor(comptime F: type, row: RowFor(F), event: usize) [6]F {
    return if (event < L.STATE) tuples.chi(F, row.main[0..L.STATE], row.main[L.STATE..L.ACTIVE_A], row.state_plus_one, row.fixed[2..26], event) else tuples.xor5(F, row.main[0..L.STATE], row.main[L.STATE..L.ACTIVE_A], event - L.STATE);
}
pub fn lookupDenominatorFor(comptime F: type, row: RowFor(F), ch: ChallengesFor(V.ConstFor(F)), event: usize) V.SecureFor(F) {
    if (event < L.STATE) return V.denominatorFor(F, ch.chi.offset, &ch.chi.coefficients, &lookupTupleFor(F, row, event), true);
    return V.denominatorFor(F, ch.xor5.offset, &ch.xor5.coefficients, &lookupTupleFor(F, row, event), true);
}
pub fn ioTuple(row: Row, lane: usize) [L.IO_ARITY]Q {
    return ioTupleFor(Q, row, lane);
}
fn MainCells(comptime F: type) type {
    return struct {
        values: []const F,
        pub inline fn at(self: @This(), index: usize) F {
            return self.values[index];
        }
    };
}
pub fn ioTupleFor(comptime F: type, row: RowFor(F), lane: usize) [L.IO_ARITY]F {
    return ioTupleAccessors(F, MainCells(F){ .values = row.main }, row.fixed, lane);
}
pub fn ioTupleAccessors(comptime F: type, main: anytype, fixed: []const F, lane: usize) [L.IO_ARITY]F {
    var tuple: [L.IO_ARITY]F = undefined;
    tuple[0] = main.at(L.BASE_ID).add(fixed[1]).add(fixed[28]);
    tuple[1] = fixed[27].add(fixed[28]);
    tuple[2] = if (F == M) M.fromCanonical(@intCast(lane)) else V.qFor(F, @intCast(lane));
    for (0..8) |byte| {
        var value = F.zero();
        for (0..8) |bit| value = value.add(main.at(64 * lane + 8 * byte + bit).mul(if (F == M) M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(bit))) else V.qFor(F, @as(u32, 1) << @as(u5, @intCast(bit)))));
        tuple[3 + byte] = value;
    }
    return tuple;
}
pub fn roundActive(row: Row) Q {
    return roundActiveFor(Q, row);
}
pub fn roundActiveFor(comptime F: type, row: RowFor(F)) F {
    var result = F.zero();
    for (row.fixed[2..26]) |s| result = result.add(s);
    return result.mul(row.main[L.ACTIVE_A]);
}
pub fn ioActive(row: Row) Q {
    return ioActiveFor(Q, row);
}
pub fn ioActiveFor(comptime F: type, row: RowFor(F)) F {
    return ioActiveAccessors(F, MainCells(F){ .values = row.main }, row.fixed);
}
pub fn ioActiveAccessors(comptime F: type, main: anytype, fixed: []const F) F {
    return main.at(L.ACTIVE_A).mul(fixed[0].add(fixed[27])).add(main.at(L.ACTIVE_B).mul(fixed[1].add(fixed[28])));
}

/// Triple batching gives degree four. Cross-column stitching needs only the
/// final secure column at the predecessor point and one transcript-bound claim.
pub fn emit(row: Row, interaction: []const Q, previous_final: Q, claim: Q, ch: Challenges, public: Public, sink: anytype) void {
    return emitFor(Q, row, interaction, previous_final, claim, ch, public, sink);
}
pub fn emitFor(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: V.ConstFor(F), ch: ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    return emitForBatch(F, 3, row, interaction, previous_final, claim, ch, public, sink);
}
pub fn emitForPolicy(comptime F: type, policy: BatchPolicy, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: V.ConstFor(F), ch: ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    switch (policy) {
        .triple_v2 => emitForBatch(F, 3, row, interaction, previous_final, claim, ch, public, sink),
        .quartet_v3 => emitForBatch(F, 4, row, interaction, previous_final, claim, ch, public, sink),
        .throughput_v1 => emitThroughputFor(F, row, interaction, previous_final, claim, ch, public, sink),
        .throughput_quartet_v1 => emitThroughputQuartetFor(F, row, interaction, previous_final, claim, ch, public, sink),
        .throughput_r27_v1 => emitThroughputR27For(F, row, interaction, previous_final, claim, ch, public, sink),
    }
}
/// Multiplication by a small canonical constant in lane F (M31 natively).
pub fn ScaleFor(comptime F: type) type {
    return struct {
        pub inline fn apply(value: F, constant: u32) F {
            return value.mul(if (F == M) M.fromCanonical(constant) else V.qFor(F, constant));
        }
    };
}
const TP = @import("batch_policy.zig");
/// Throughput tuple for round-row query `event`: chi rows (y,z) first, then
/// xor5 triples. Both tuples are the RV32 authority's; only placement is RV64.
pub fn throughputTupleFor(comptime F: type, state: []const F, parity: []const F, next: []const F, round_selectors: []const F, event: usize) [6]F {
    if (event < TP.THROUGHPUT_CHI) return tuples.throughputChi(F, ScaleFor(F).apply, state, parity, next, round_selectors, event);
    return tuples.throughputXor5(F, state, parity, event - TP.THROUGHPUT_CHI);
}
pub fn throughputDenominatorFor(comptime F: type, row: RowFor(F), ch: ChallengesFor(V.ConstFor(F)), event: usize) V.SecureFor(F) {
    const lookup = if (event < TP.THROUGHPUT_CHI) ch.chi else ch.xor5;
    return V.denominatorFor(F, lookup.offset, &lookup.coefficients, &throughputTupleFor(F, row.main[0..L.STATE], row.main[L.STATE..L.ACTIVE_A], row.state_plus_one, row.fixed[2..26], event), true);
}
/// Throughput-v1: MAIN and direct equations are the compact ones; 427 round
/// queries (320 five-output chi + 107 three-position xor5) are cleared three
/// per degree-four batch. The trailing batch holds one query and two dummy
/// entries (denominator one, weight zero); IO batches are unchanged.
pub fn emitThroughputFor(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: V.ConstFor(F), ch: ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    const policy = BatchPolicy.throughput_v1;
    emitDirectFor(F, row, public, sink, true);
    const coefficient = roundActiveFor(F, row).neg();
    for (0..policy.roundBatches()) |batch| {
        var d: [3]V.SecureFor(F) = @splat(V.SecureFor(F).one());
        var c: [3]F = @splat(F.zero());
        for (0..3) |i| if (3 * batch + i < policy.lookups()) {
            d[i] = throughputDenominatorFor(F, row, ch, 3 * batch + i);
            c[i] = coefficient;
        };
        const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) V.mulBaseFor(F, V.splatFor(F, claim), row.fixed[L.FIRST]) else V.SecureFor(F).zero());
        sink.emit(clearTripleFor(F, d, c, delta));
    }
    emitIoTriplesFor(F, row, interaction, policy.roundBatches(), ch, sink);
}
/// Throughput-quartet-v1: the throughput-v1 MAIN, direct equations, tuples
/// and tables; the 427 round queries are cleared four per degree-five batch
/// (106 full batches + one batch of three queries and one dummy entry with
/// denominator one and weight zero), then the IO lanes four per batch.
/// Degree: delta * d0 d1 d2 d3 is 1 + 4; c * (triple products) is 2 + 3.
pub fn emitThroughputQuartetFor(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: V.ConstFor(F), ch: ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    const policy = BatchPolicy.throughput_quartet_v1;
    emitDirectFor(F, row, public, sink, true);
    emitRoundQuartetsFor(F, policy, row, interaction, previous_final, claim, ch, sink);
    emitIoQuartetsFor(F, row, interaction, policy.roundBatches(), ch, sink);
}
/// Constant c of lane F (M31 natively).
fn constantFor(comptime F: type, value: u32) F {
    return if (F == M) M.fromCanonical(value) else V.qFor(F, value);
}
/// 1/8 in M31: 8 * 2^28 = 2^31 = p + 1.
pub const INV8: u32 = 1 << 28;
/// 27-row slot IO entry `entry` (0..49) on the current row. Entries 0..24 are
/// group A (call A, lane = entry): bits 1 - v of a complemented plane row.
/// Entries 25..49 are group B (call B = BASE_ID + 1, lane = entry - 25): bits
/// (v + s[-1] - 1) / 8, the b digit of the packed state next to a plane
/// (v0 after the input plane; v24 before the output plane). Direction is the
/// output-plane selector fixed[27] in both groups. Every element is affine
/// in the committed columns, so IO denominators stay linear.
pub fn ioTupleR27For(comptime F: type, row: RowFor(F), entry: usize) [L.IO_ARITY]F {
    const Cells = struct { values: []const F, pub fn at(self: @This(), i: usize) F { return self.values[i]; } };
    return ioTupleR27Accessors(F, Cells{ .values = row.main }, Cells{ .values = row.state_minus_one }, row.fixed, entry);
}
pub fn ioTupleR27Accessors(comptime F: type, main: anytype, previous: anytype, fixed: []const F, entry: usize) [L.IO_ARITY]F {
    const group_b = entry >= L.IO_LANES;
    const lane = entry % L.IO_LANES;
    var tuple: [L.IO_ARITY]F = undefined;
    tuple[0] = if (group_b) main.at(L.BASE_ID).add(F.one()) else main.at(L.BASE_ID);
    tuple[1] = fixed[27];
    tuple[2] = constantFor(F, @intCast(lane));
    for (0..8) |byte| {
        var value = F.zero();
        for (0..8) |bit| {
            const cell = 64 * lane + 8 * byte + bit;
            const digit = if (group_b) main.at(cell).add(previous.at(cell)).sub(F.one()) else F.one().sub(main.at(cell));
            value = value.add(digit.mul(constantFor(F, @as(u32, 1) << @as(u5, @intCast(bit)))));
        }
        tuple[3 + byte] = if (group_b) value.mul(constantFor(F, INV8)) else value;
    }
    return tuple;
}
/// Weight of IO entry `entry`: group A on the two plane rows of an active
/// slot, group B on the v0 row and the output-plane row of a slot with B.
pub fn ioActiveR27For(comptime F: type, row: RowFor(F), entry: usize) F {
    const Cells = struct { values: []const F, pub fn at(self: @This(), i: usize) F { return self.values[i]; } };
    return ioActiveR27Accessors(F, Cells{ .values = row.main }, row.fixed, entry);
}
pub fn ioActiveR27Accessors(comptime F: type, main: anytype, fixed: []const F, entry: usize) F {
    if (entry < L.IO_LANES) return main.at(L.ACTIVE_A).mul(fixed[0].add(fixed[27]));
    return main.at(L.ACTIVE_B).mul(fixed[2].add(fixed[27]));
}
/// Direct equations of the 27-row slot. Header, booleanity of the two plane
/// rows, parity-zero and padding equations are those of `emitDirectFor`; the
/// pair29 unpack equations v0 = a + 8b / v24 = a' + 8b' are replaced by one
/// per cell: on the v0 row and on the output-plane row (fixed[2] + fixed[27]),
/// active * t * (t - 8) = 0 with t = v + s[-1] - 1. With the plane bit p
/// boolean (complement of call A's bit) this forces the packed neighbour to
/// 1 - p + 8b with b in {0,1}: call A's bit is 1 - p and call B's bit is b.
/// Degree: fixed * active * t^2 = 4.
pub fn emitDirectR27For(comptime F: type, row: RowFor(F), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    const active = row.main[L.ACTIVE_A];
    const second = row.main[L.ACTIVE_B];
    const id = row.main[L.BASE_ID];
    const previous_active = row.previous_header[0];
    const previous_second = row.previous_header[1];
    const previous_id = row.previous_header[2];
    const phase_first = row.fixed[0];
    const continuation = F.one().sub(phase_first);
    const first_id = V.firstIdFor(F, public);
    const last_id = V.lastIdFor(F, public);
    sink.emit(active.mul(active.sub(F.one())));
    sink.emit(second.mul(second.sub(F.one())));
    sink.emit(second.mul(F.one().sub(active)));
    sink.emit(F.one().sub(row.fixed[L.COMPLETE_SLOT]).mul(active));
    sink.emit(row.fixed[L.FIRST].mul(active.sub(V.nonemptyFor(F, public))));
    sink.emit(continuation.mul(active.sub(previous_active)));
    sink.emit(continuation.mul(second.sub(previous_second)));
    sink.emit(continuation.mul(id.sub(previous_id)));
    sink.emit(phase_first.sub(row.fixed[L.FIRST]).mul(F.one().sub(previous_active)).mul(active));
    sink.emit(phase_first.mul(active).mul(previous_active.sub(previous_second)));
    sink.emit(phase_first.sub(row.fixed[L.FIRST]).mul(previous_active.sub(active)).mul(previous_id.add(previous_second).sub(last_id)));
    sink.emit(active.mul(id.sub(first_id).sub(row.fixed[L.SLOT_INDEX].mul(V.qFor(F, 2)))));
    sink.emit(F.one().sub(active).mul(id));
    const planes = row.fixed[0].add(row.fixed[27]);
    const plane_gate = planes.mul(active);
    const unpack_gate = row.fixed[2].add(row.fixed[27]).mul(active);
    const eight = V.qFor(F, 8);
    for (0..L.STATE) |i| {
        const v = row.main[i];
        sink.emit(plane_gate.mul(v.mul(F.one().sub(v))));
        const t = v.add(row.state_minus_one[i]).sub(F.one());
        sink.emit(unpack_gate.mul(t.mul(t.sub(eight))));
    }
    const parity_zero = planes.add(row.fixed[26]);
    for (row.main[L.STATE..L.ACTIVE_A]) |v| sink.emit(parity_zero.mul(v));
    const padding = F.one().sub(active);
    for (row.main[0..L.ACTIVE_A]) |v| sink.emit(padding.mul(v));
}
/// Throughput-r27-v1: 27-row slot direct equations, the throughput round
/// queries four per batch (as throughput-quartet-v1), then the 50 IO entries
/// (group A, group B) four per batch: 13 batches, the last with two dummies.
pub fn emitThroughputR27For(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: V.ConstFor(F), ch: ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    const policy = BatchPolicy.throughput_r27_v1;
    emitDirectR27For(F, row, public, sink);
    emitRoundQuartetsFor(F, policy, row, interaction, previous_final, claim, ch, sink);
    for (0..policy.ioBatches()) |local| {
        const batch = policy.roundBatches() + local;
        var d: [4]V.SecureFor(F) = @splat(V.SecureFor(F).one());
        var c: [4]F = @splat(F.zero());
        for (0..4) |i| if (4 * local + i < policy.ioLookups()) {
            d[i] = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTupleR27For(F, row, 4 * local + i), true);
            c[i] = ioActiveR27For(F, row, 4 * local + i);
        };
        sink.emit(clearQuartetFor(F, false, d, c, interaction[batch].sub(interaction[batch - 1])));
    }
}
/// Throughput round queries four per batch (shared by both quartet throughput
/// profiles): 106 full batches and one of three queries plus a dummy.
fn emitRoundQuartetsFor(comptime F: type, comptime policy: BatchPolicy, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: V.ConstFor(F), ch: ChallengesFor(V.ConstFor(F)), sink: anytype) void {
    const coefficient = roundActiveFor(F, row).neg();
    for (0..policy.roundBatches()) |batch| {
        var d: [4]V.SecureFor(F) = @splat(V.SecureFor(F).one());
        var c: [4]F = @splat(F.zero());
        var full = true;
        for (0..4) |i| {
            if (4 * batch + i < policy.lookups()) {
                d[i] = throughputDenominatorFor(F, row, ch, 4 * batch + i);
                c[i] = coefficient;
            } else full = false;
        }
        const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) V.mulBaseFor(F, V.splatFor(F, claim), row.fixed[L.FIRST]) else V.SecureFor(F).zero());
        sink.emit(if (full) clearQuartetFor(F, true, d, c, delta) else clearQuartetFor(F, false, d, c, delta));
    }
}
/// One triple polynomial with per-entry weights (dummy entries: d = 1, c = 0).
pub fn clearTripleFor(comptime F: type, d: [3]V.SecureFor(F), c: [3]F, delta: V.SecureFor(F)) V.SecureFor(F) {
    const numerator = V.mulBaseFor(F, d[1], c[0]).mul(d[2])
        .add(V.mulBaseFor(F, d[0], c[1]).mul(d[2]))
        .add(V.mulBaseFor(F, d[0], c[2]).mul(d[1]));
    return delta.mul(d[0]).mul(d[1]).mul(d[2]).sub(numerator);
}
/// IO11 lanes three per batch after `first` round batches (shared by triple-v2 and throughput-v1).
fn emitIoTriplesFor(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), first: usize, ch: ChallengesFor(V.ConstFor(F)), sink: anytype) void {
    for (0..L.IO_BATCHES) |local| {
        const batch = first + local;
        var denominators: [3]V.SecureFor(F) = @splat(V.SecureFor(F).one());
        var coefficients: [3]F = @splat(F.zero());
        for (0..3) |i| if (3 * local + i < L.IO_LANES) {
            denominators[i] = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTupleFor(F, row, 3 * local + i), true);
            coefficients[i] = ioActiveFor(F, row);
        };
        sink.emit(clearTripleFor(F, denominators, coefficients, interaction[batch].sub(interaction[batch - 1])));
    }
}
pub fn emitForBatch(comptime F: type, comptime width: usize, row: RowFor(F), interaction: []const V.SecureFor(F), previous_final: V.SecureFor(F), claim: V.ConstFor(F), ch: ChallengesFor(V.ConstFor(F)), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype) void {
    emitDirectFor(F, row, public, sink, true);
    if (comptime width == 3) {
        const coefficient = roundActiveFor(F, row).neg();
        for (0..L.LOOKUPS / 3) |batch| {
            const d0 = lookupDenominatorFor(F, row, ch, 3 * batch);
            const d1 = lookupDenominatorFor(F, row, ch, 3 * batch + 1);
            const d2 = lookupDenominatorFor(F, row, ch, 3 * batch + 2);
            const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) V.mulBaseFor(F, V.splatFor(F, claim), row.fixed[L.FIRST]) else V.SecureFor(F).zero());
            const numerator = V.mulBaseFor(F, d0.mul(d1).add(d0.mul(d2)).add(d1.mul(d2)), coefficient);
            sink.emit(delta.mul(d0).mul(d1).mul(d2).sub(numerator));
        }
        emitIoTriplesFor(F, row, interaction, L.LOOKUPS / 3, ch, sink);
    } else {
        const coefficient = roundActiveFor(F, row).neg();
        for (0..L.LOOKUPS / 4) |batch| {
            var d: [4]V.SecureFor(F) = undefined;
            for (&d, 0..) |*value, i| value.* = lookupDenominatorFor(F, row, ch, 4 * batch + i);
            const delta = interaction[batch].sub(if (batch == 0) previous_final else interaction[batch - 1]).add(if (batch == 0) V.mulBaseFor(F, V.splatFor(F, claim), row.fixed[L.FIRST]) else V.SecureFor(F).zero());
            sink.emit(clearQuartetFor(F, true, d, @splat(coefficient), delta));
        }
        emitIoQuartetsFor(F, row, interaction, L.LOOKUPS / 4, ch, sink);
    }
}
/// IO11 lanes four per degree-five batch after `first` round batches (shared
/// by quartet-v3 and throughput-quartet-v1). Dummy entries: d = 1, c = 0.
fn emitIoQuartetsFor(comptime F: type, row: RowFor(F), interaction: []const V.SecureFor(F), first: usize, ch: ChallengesFor(V.ConstFor(F)), sink: anytype) void {
    for (0..(L.IO_LANES + 3) / 4) |local| {
        const batch = first + local;
        var d: [4]V.SecureFor(F) = @splat(V.SecureFor(F).one());
        var c: [4]F = @splat(F.zero());
        for (0..4) |i| if (4 * local + i < L.IO_LANES) {
            d[i] = V.denominatorFor(F, ch.io.offset, &ch.io.coefficients, &ioTupleFor(F, row, 4 * local + i), true);
            c[i] = ioActiveFor(F, row);
        };
        sink.emit(clearQuartetFor(F, false, d, c, interaction[batch].sub(interaction[batch - 1])));
    }
}

/// Shared direct permutation authority. Legacy retains its exact degree-four
/// active boundary bit gate. The explicit pair2n authority removes that factor:
/// inactive state bits are already zero by the unchanged padding equations.
pub fn emitDirectFor(comptime F: type, row: RowFor(F), public: V.CallSpanFor(V.ConstFor(F)), sink: anytype, comptime active_bit_gate: bool) void {
    const active = row.main[L.ACTIVE_A];
    const second = row.main[L.ACTIVE_B];
    const id = row.main[L.BASE_ID];
    const previous_active = row.previous_header[0];
    const previous_second = row.previous_header[1];
    const previous_id = row.previous_header[2];
    const phase_first = row.fixed[0];
    const continuation = F.one().sub(phase_first);
    const first_id = V.firstIdFor(F, public);
    const last_id = V.lastIdFor(F, public);
    sink.emit(active.mul(active.sub(F.one())));
    sink.emit(second.mul(second.sub(F.one())));
    sink.emit(second.mul(F.one().sub(active)));
    sink.emit(F.one().sub(row.fixed[L.COMPLETE_SLOT]).mul(active));
    sink.emit(row.fixed[L.FIRST].mul(active.sub(V.nonemptyFor(F, public))));
    sink.emit(continuation.mul(active.sub(previous_active)));
    sink.emit(continuation.mul(second.sub(previous_second)));
    sink.emit(continuation.mul(id.sub(previous_id)));
    sink.emit(phase_first.sub(row.fixed[L.FIRST]).mul(F.one().sub(previous_active)).mul(active));
    sink.emit(phase_first.mul(active).mul(previous_active.sub(previous_second)));
    sink.emit(phase_first.sub(row.fixed[L.FIRST]).mul(previous_active.sub(active)).mul(previous_id.add(previous_second).sub(last_id)));
    sink.emit(active.mul(id.sub(first_id).sub(row.fixed[L.SLOT_INDEX].mul(V.qFor(F, 2)))));
    sink.emit(F.one().sub(active).mul(id));
    const boundary = row.fixed[0].add(row.fixed[1]).add(row.fixed[27]).add(row.fixed[28]);
    for (0..L.STATE) |i| {
        const v = row.main[i];
        sink.emit((if (active_bit_gate) boundary.mul(active) else boundary).mul(v.mul(F.one().sub(v))));
        const input = v.sub(row.state_minus_two[i]).sub(row.state_minus_one[i].mul(V.qFor(F, 8)));
        const output = v.sub(row.state_plus_one[i]).sub(row.state_plus_two[i].mul(V.qFor(F, 8)));
        sink.emit(row.fixed[2].mul(input).add(row.fixed[26].mul(output)));
    }
    const parity_zero = boundary.add(row.fixed[26]);
    for (row.main[L.STATE..L.ACTIVE_A]) |v| sink.emit(parity_zero.mul(v));
    const padding = F.one().sub(active);
    for (row.main[0..L.ACTIVE_A]) |v| sink.emit(padding.mul(v));
}

/// One quartet polynomial, including distinct IO weights and dummy entries.
/// Factoring changes neither the numerator nor the order of emitted residuals.
pub fn clearQuartetFor(comptime F: type, comptime same_coefficient: bool, d: [4]V.SecureFor(F), c: [4]F, delta: V.SecureFor(F)) V.SecureFor(F) {
    const p01 = d[0].mul(d[1]);
    const p23 = d[2].mul(d[3]);
    const numerator = if (same_coefficient)
        V.mulBaseFor(F, p01.mul(d[2].add(d[3])).add(p23.mul(d[0].add(d[1]))), c[0])
    else
        p23.mul(V.mulBaseFor(F, d[1], c[0]).add(V.mulBaseFor(F, d[0], c[1]))).add(p01.mul(V.mulBaseFor(F, d[3], c[2]).add(V.mulBaseFor(F, d[2], c[3]))));
    return delta.mul(p01).mul(p23).sub(numerator);
}
