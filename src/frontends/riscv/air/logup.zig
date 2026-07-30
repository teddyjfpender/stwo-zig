//! Real LogUp interaction machinery for the RISC-V AIR.
//!
//! This module owns the batched-fraction cumulative columns, the generic
//! pairs-batched transition constraint, and the public boundary terms of the
//! cross-shard buses:
//!
//!  - CPU state chain (`OpcodeRelation`): every executed row consumes its
//!    in-state `(pc, clk)` and emits its out-state `(next_pc, clk + 1)`.
//!    Sharding is irrelevant to the bus — the multiset telescopes globally,
//!    with the initial and final CPU states supplied publicly by the verifier.
//!  - Program lookup (`program_access`): every executed row consumes the exact
//!    decoded `(pc, opcode_id, value_1, value_2, value_3)` tuple; the program
//!    table emits each unique tuple weighted by its execution multiplicity.
//!
//! The cumulative-sum column S obeys, over the trace domain,
//!   [S(x) - S(x·g⁻¹) + is_first(x)·claimed] · d1(x) · d2(x)
//!       - [n1(x)·d2(x) + n2(x)·d1(x)] = 0
//! where g is the canonic-coset step. The identity between "trace-order row
//! shift" and "evaluation at x·g⁻¹" is proven by a test in this file against
//! the exact interpolation pipeline the prover uses.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const circle = @import("stwo_core").circle;
const canonic = @import("stwo_core").poly.circle.canonic;
const relation_challenges = @import("relation_challenges.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
pub const SECURE_EXTENSION_DEGREE = qm31.SECURE_EXTENSION_DEGREE;
const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;

pub const LogupError = error{ ZeroDenominator, StepClockCycle, OutOfMemory };

/// Lift a base-field circle point into the secure field.
pub fn liftPoint(p: CirclePointM31) CirclePointQM31 {
    return .{ .x = QM31.fromBase(p.x), .y = QM31.fromBase(p.y) };
}

/// The trace-order predecessor mask point: `point - g` for the canonic coset
/// step g of the component's domain. Sampling a committed column at this
/// point reads the previous trace row.
pub fn prevRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(liftPoint(step));
}

/// One pairs-batched row: the fraction n1/d1 + n2/d2. Single-fraction rows
/// set `n2 = 0, d2 = 1`.
pub const RowPair = struct {
    n1: QM31,
    d1: QM31,
    n2: QM31,
    d2: QM31,

    pub fn single(n: QM31, d: QM31) RowPair {
        return .{ .n1 = n, .d1 = d, .n2 = QM31.zero(), .d2 = QM31.one() };
    }
};

/// Cumulative sums in TRACE ORDER plus the component's claimed sum.
pub const CumulativeColumn = struct {
    sums: []QM31,
    claimed: QM31,

    pub fn deinit(self: *CumulativeColumn, allocator: std.mem.Allocator) void {
        allocator.free(self.sums);
        self.* = undefined;
    }
};

/// Accumulate batched fractions row by row. `pairs.len` must be the full
/// domain size; padding rows must carry zero numerators.
pub fn cumulativeColumn(
    allocator: std.mem.Allocator,
    pairs: []const RowPair,
) LogupError!CumulativeColumn {
    const sums = try allocator.alloc(QM31, pairs.len);
    errdefer allocator.free(sums);
    var acc = QM31.zero();
    for (pairs, 0..) |pair, i| {
        const denom = pair.d1.mul(pair.d2);
        const numer = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
        const denom_inv = denom.inv() catch return error.ZeroDenominator;
        acc = acc.add(numer.mul(denom_inv));
        sums[i] = acc;
    }
    return .{ .sums = sums, .claimed = acc };
}

/// The pairs-batched LogUp transition constraint. Works identically on OODS
/// mask samples and on lifted domain values; degree 3 in the trace columns.
pub fn pairConstraint(
    s: QM31,
    s_prev: QM31,
    is_first: QM31,
    claimed: QM31,
    pair: RowPair,
) QM31 {
    const delta = s.sub(s_prev).add(is_first.mul(claimed));
    return delta.mul(pair.d1).mul(pair.d2)
        .sub(pair.n1.mul(pair.d2)).sub(pair.n2.mul(pair.d1));
}

// ---------------------------------------------------------------------------
// Bus tuples
// ---------------------------------------------------------------------------

/// CPU state-chain pair for one executed row: consume (pc, clk), emit
/// (next_pc, clk + 1), both gated by the row enabler.
pub fn stateChainPair(
    relations: *const relation_challenges.Relations,
    pc: QM31,
    clk: QM31,
    next_pc: QM31,
    enabler: QM31,
) RowPair {
    return .{
        .n1 = enabler,
        .d1 = stateDenominator(relations, next_pc, clk.add(QM31.one())),
        .n2 = enabler.neg(),
        .d2 = stateDenominator(relations, pc, clk),
    };
}

fn stateDenominator(
    relations: *const relation_challenges.Relations,
    pc: QM31,
    clk: QM31,
) QM31 {
    return relations.registers_state.combineSecure(.{ pc, clk });
}

/// Program-lookup denominator over Stark-V's decoded five-field tuple.
pub fn programDenominator(
    relations: *const relation_challenges.Relations,
    pc: QM31,
    opcode_id: QM31,
    value_1: QM31,
    value_2: QM31,
    value_3: QM31,
) QM31 {
    return relations.program_access.combineSecure(.{ pc, opcode_id, value_1, value_2, value_3 });
}

/// Executed-row side of the program bus: consume the fetched instruction.
pub fn programConsume(
    relations: *const relation_challenges.Relations,
    pc: QM31,
    opcode_id: QM31,
    value_1: QM31,
    value_2: QM31,
    value_3: QM31,
    enabler: QM31,
) RowPair {
    return RowPair.single(
        enabler.neg(),
        programDenominator(relations, pc, opcode_id, value_1, value_2, value_3),
    );
}

/// ROM side of the program bus: emit the tuple with its multiplicity.
pub fn programEmit(
    relations: *const relation_challenges.Relations,
    pc: QM31,
    opcode_id: QM31,
    value_1: QM31,
    value_2: QM31,
    value_3: QM31,
    multiplicity: QM31,
) RowPair {
    return RowPair.single(
        multiplicity,
        programDenominator(relations, pc, opcode_id, value_1, value_2, value_3),
    );
}

/// Public boundary of the CPU state chain: the verifier emits the initial
/// state and consumes the final one, closing the global telescope.
pub fn stateBoundary(
    relations: *const relation_challenges.Relations,
    initial_pc: u32,
    final_pc: u32,
    total_steps: u32,
) LogupError!QM31 {
    // The final state is `(final_pc, total_steps + 1)`. Reject a field-cycle
    // alias even when this helper is called outside statement validation.
    if (total_steps >= m31.Modulus - 1) return error.StepClockCycle;
    const d_init = stateDenominator(
        relations,
        QM31.fromBase(M31.fromU64(initial_pc)),
        QM31.one(),
    );
    const d_final = stateDenominator(
        relations,
        QM31.fromBase(M31.fromU64(final_pc)),
        QM31.fromBase(M31.fromU64(total_steps)).add(QM31.one()),
    );
    const init_term = QM31.one().mul((d_init.inv() catch return error.ZeroDenominator));
    const final_term = QM31.one().mul((d_final.inv() catch return error.ZeroDenominator));
    return init_term.sub(final_term);
}

/// Global cross-shard acceptance: all component claims plus the public
/// boundary must cancel exactly.
pub fn verifyGlobalCancellation(claims: []const QM31, boundary: QM31) !void {
    var total = boundary;
    for (claims) |claim| total = total.add(claim);
    if (!total.eql(QM31.zero())) return error.LogupSumNonZero;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const eval_mod = @import("stwo_prover_engine").poly.circle.evaluation;
const poly_mod = @import("stwo_prover_engine").poly.circle.poly;
const infra = @import("../infra_trace.zig");

test "geometry: trace-order shift equals evaluation at point minus coset step" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 3;
    const n: usize = 1 << log_size;

    var values: [8]M31 = undefined;
    for (&values, 0..) |*v, i| v.* = M31.fromU64(@as(u64, i) * 37 + 11);
    var shifted: [8]M31 = undefined;
    for (0..n) |i| shifted[i] = values[(i + n - 1) % n];

    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);

    var col_a = [_]M31{M31.zero()} ** 8;
    var col_s = [_]M31{M31.zero()} ** 8;
    for (0..n) |i| {
        col_a[table.map(i)] = values[i];
        col_s[table.map(i)] = shifted[i];
    }

    const coset = canonic.CanonicCoset.new(log_size);
    const domain = coset.circleDomain();
    const eval_a = try eval_mod.CircleEvaluation.init(domain, &col_a);
    const eval_s = try eval_mod.CircleEvaluation.init(domain, &col_s);
    var coeffs_a = try poly_mod.interpolateFromEvaluation(allocator, eval_a);
    defer coeffs_a.deinit(allocator);
    var coeffs_s = try poly_mod.interpolateFromEvaluation(allocator, eval_s);
    defer coeffs_s.deinit(allocator);

    const step = coset.coset_value.step;
    const probe = circle.SECURE_FIELD_CIRCLE_GEN.mul(987654321);
    const at_probe = coeffs_s.evalAtPoint(probe);
    const at_shifted_probe = coeffs_a.evalAtPoint(probe.sub(liftPoint(step)));
    try std.testing.expect(at_probe.eql(at_shifted_probe));

    // Second independent probe point.
    const probe2 = circle.SECURE_FIELD_CIRCLE_GEN.mul(1234567);
    try std.testing.expect(
        coeffs_s.evalAtPoint(probe2).eql(coeffs_a.evalAtPoint(probe2.sub(liftPoint(step)))),
    );
}

test "cumulativeColumn accumulates batched fractions and reports the claim" {
    const allocator = std.testing.allocator;
    const one = QM31.one();
    const two = QM31.fromU32Unchecked(2, 0, 0, 0);
    const three = QM31.fromU32Unchecked(3, 0, 0, 0);
    const pairs = [_]RowPair{
        .{ .n1 = one, .d1 = two, .n2 = one.neg(), .d2 = three },
        RowPair.single(one, two),
    };
    var col = try cumulativeColumn(allocator, &pairs);
    defer col.deinit(allocator);

    const half = two.inv() catch unreachable;
    const third = three.inv() catch unreachable;
    const row0 = half.sub(third);
    try std.testing.expect(col.sums[0].eql(row0));
    try std.testing.expect(col.sums[1].eql(row0.add(half)));
    try std.testing.expect(col.claimed.eql(col.sums[1]));
}

test "pairConstraint vanishes exactly on honest cumulative columns" {
    const allocator = std.testing.allocator;
    var pairs: [4]RowPair = undefined;
    for (&pairs, 0..) |*pair, i| {
        pair.* = .{
            .n1 = QM31.fromU32Unchecked(@intCast(i + 1), 0, 3, 0),
            .d1 = QM31.fromU32Unchecked(@intCast(7 + i), 1, 0, 2),
            .n2 = QM31.fromU32Unchecked(5, @intCast(i), 0, 0).neg(),
            .d2 = QM31.fromU32Unchecked(11, 0, @intCast(2 * i + 1), 0),
        };
    }
    var col = try cumulativeColumn(allocator, &pairs);
    defer col.deinit(allocator);

    for (0..pairs.len) |i| {
        const s = col.sums[i];
        // Trace-order wraparound: row 0's predecessor is the last row.
        const s_prev = if (i == 0) col.sums[pairs.len - 1] else col.sums[i - 1];
        const is_first = if (i == 0) QM31.one() else QM31.zero();
        const c = pairConstraint(s, s_prev, is_first, col.claimed, pairs[i]);
        try std.testing.expect(c.eql(QM31.zero()));
    }

    // A forged claim breaks the first row.
    const forged = pairConstraint(
        col.sums[0],
        col.sums[pairs.len - 1],
        QM31.one(),
        col.claimed.add(QM31.one()),
        pairs[0],
    );
    try std.testing.expect(!forged.eql(QM31.zero()));
}

const StateTestEdge = struct { pc: u32, clock: u32, next_pc: u32 };

fn stateTestClaim(
    allocator: std.mem.Allocator,
    relations: *const relation_challenges.Relations,
    edges: []const StateTestEdge,
) !QM31 {
    const pairs = try allocator.alloc(RowPair, edges.len);
    defer allocator.free(pairs);
    for (edges, 0..) |edge, index| {
        pairs[index] = stateChainPair(
            relations,
            QM31.fromBase(M31.fromU64(edge.pc)),
            QM31.fromBase(M31.fromU64(edge.clock)),
            QM31.fromBase(M31.fromU64(edge.next_pc)),
            QM31.one(),
        );
    }
    var column = try cumulativeColumn(allocator, pairs);
    defer column.deinit(allocator);
    return column.claimed;
}

test "state chain closes for one, two, many, and interleaved shards" {
    const allocator = std.testing.allocator;
    const relations = relation_challenges.Relations.dummy();
    const edges = [_]StateTestEdge{
        .{ .pc = 0x1000, .clock = 1, .next_pc = 0x1004 },
        .{ .pc = 0x1004, .clock = 2, .next_pc = 0x1008 },
        .{ .pc = 0x1008, .clock = 3, .next_pc = 0x100c },
        .{ .pc = 0x100c, .clock = 4, .next_pc = 0x1010 },
        .{ .pc = 0x1010, .clock = 5, .next_pc = 0x1014 },
        .{ .pc = 0x1014, .clock = 6, .next_pc = 0x1018 },
    };
    const boundary = try stateBoundary(&relations, 0x1000, 0x1018, edges.len);

    const one = try stateTestClaim(allocator, &relations, &edges);
    try verifyGlobalCancellation(&.{one}, boundary);

    const two = [_]QM31{
        try stateTestClaim(allocator, &relations, edges[0..3]),
        try stateTestClaim(allocator, &relations, edges[3..]),
    };
    try verifyGlobalCancellation(&two, boundary);

    var many: [edges.len]QM31 = undefined;
    for (&many, 0..) |*claim, index| {
        claim.* = try stateTestClaim(allocator, &relations, edges[index .. index + 1]);
    }
    try verifyGlobalCancellation(&many, boundary);

    const even = [_]StateTestEdge{ edges[0], edges[2], edges[4] };
    const odd = [_]StateTestEdge{ edges[1], edges[3], edges[5] };
    const interleaved = [_]QM31{
        try stateTestClaim(allocator, &relations, &even),
        try stateTestClaim(allocator, &relations, &odd),
    };
    try verifyGlobalCancellation(&interleaved, boundary);
}

test "state chain rejects omission, duplication, boundary mutation, and field cycles" {
    const allocator = std.testing.allocator;
    const relations = relation_challenges.Relations.dummy();
    const edges = [_]StateTestEdge{
        .{ .pc = 0x1000, .clock = 1, .next_pc = 0x1004 },
        .{ .pc = 0x1004, .clock = 2, .next_pc = 0x1008 },
        .{ .pc = 0x1008, .clock = 3, .next_pc = 0x100c },
        .{ .pc = 0x100c, .clock = 4, .next_pc = 0x1010 },
    };
    const boundary = try stateBoundary(&relations, 0x1000, 0x1010, edges.len);
    const prefix = try stateTestClaim(allocator, &relations, edges[0..2]);
    const omitted = try stateTestClaim(allocator, &relations, edges[3..]);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyGlobalCancellation(&.{ prefix, omitted }, boundary),
    );

    const suffix = try stateTestClaim(allocator, &relations, edges[2..]);
    const duplicated = try stateTestClaim(allocator, &relations, edges[1..2]);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyGlobalCancellation(&.{ prefix, suffix, duplicated }, boundary),
    );

    const all = try stateTestClaim(allocator, &relations, &edges);
    const wrong_pc = try stateBoundary(&relations, 0x1000, 0x1014, edges.len);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyGlobalCancellation(&.{all}, wrong_pc),
    );
    const wrong_clock = try stateBoundary(&relations, 0x1000, 0x1010, edges.len + 1);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyGlobalCancellation(&.{all}, wrong_clock),
    );

    try std.testing.expectError(
        error.StepClockCycle,
        stateBoundary(&relations, 0x1000, 0x1000, m31.Modulus - 1),
    );
    try std.testing.expectError(
        error.StepClockCycle,
        stateBoundary(&relations, 0x1000, 0x1000, m31.Modulus),
    );
}

test "program bus balances executed rows against ROM multiplicities" {
    const relations = relation_challenges.Relations.dummy();

    const allocator = std.testing.allocator;
    const pc0 = QM31.fromBase(M31.fromU64(0x1000));
    const pc1 = QM31.fromBase(M31.fromU64(0x1004));
    const addi = [_]QM31{
        QM31.fromBase(M31.fromU64(10)),
        QM31.fromBase(M31.fromU64(1)),
        QM31.zero(),
        QM31.fromBase(M31.fromU64(10)),
    };
    const add = [_]QM31{
        QM31.zero(),
        QM31.fromBase(M31.fromU64(3)),
        QM31.fromBase(M31.fromU64(1)),
        QM31.fromBase(M31.fromU64(2)),
    };

    // pc0 executed twice (a loop), pc1 once.
    const executed = [_]RowPair{
        programConsume(&relations, pc0, addi[0], addi[1], addi[2], addi[3], QM31.one()),
        programConsume(&relations, pc0, addi[0], addi[1], addi[2], addi[3], QM31.one()),
        programConsume(&relations, pc1, add[0], add[1], add[2], add[3], QM31.one()),
    };
    const rom = [_]RowPair{
        programEmit(&relations, pc0, addi[0], addi[1], addi[2], addi[3], QM31.fromU32Unchecked(2, 0, 0, 0)),
        programEmit(&relations, pc1, add[0], add[1], add[2], add[3], QM31.one()),
    };

    var exec_col = try cumulativeColumn(allocator, &executed);
    defer exec_col.deinit(allocator);
    var rom_col = try cumulativeColumn(allocator, &rom);
    defer rom_col.deinit(allocator);

    try verifyGlobalCancellation(&.{ exec_col.claimed, rom_col.claimed }, QM31.zero());

    // Wrong multiplicity is caught.
    const rom_bad = [_]RowPair{
        programEmit(&relations, pc0, addi[0], addi[1], addi[2], addi[3], QM31.one()),
        programEmit(&relations, pc1, add[0], add[1], add[2], add[3], QM31.one()),
    };
    var rom_bad_col = try cumulativeColumn(allocator, &rom_bad);
    defer rom_bad_col.deinit(allocator);
    try std.testing.expectError(
        error.LogupSumNonZero,
        verifyGlobalCancellation(&.{ exec_col.claimed, rom_bad_col.claimed }, QM31.zero()),
    );
}
