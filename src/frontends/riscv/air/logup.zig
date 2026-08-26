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
const fields = @import("stwo_core").fields;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const circle = @import("stwo_core").circle;
const canonic = @import("stwo_core").poly.circle.canonic;
const work_pool = @import("stwo_prover_engine").work_pool;
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
pub fn RowPairFor(comptime S: type) type {
    return struct {
        n1: S,
        d1: S,
        n2: S,
        d2: S,

        pub fn single(n: S, d: S) @This() {
            return .{ .n1 = n, .d1 = d, .n2 = S.zero(), .d2 = S.one() };
        }
    };
}

pub const RowPair = RowPairFor(QM31);

/// Cumulative sums in TRACE ORDER plus the component's claimed sum.
pub const CumulativeColumn = struct {
    sums: []QM31,
    claimed: QM31,

    pub fn deinit(self: *CumulativeColumn, allocator: std.mem.Allocator) void {
        allocator.free(self.sums);
        self.* = undefined;
    }
};

/// Cache-bounded row count used by the parallel LogUp prefix builder. Each
/// worker batch-inverts every fraction for one chunk, then publishes an exact
/// local prefix; a tiny ordered scan supplies the chunk offsets.
pub const PARALLEL_CHUNK_ROWS: usize = 4096;

/// Owned committed columns and claims produced by `generateParallelColumns`.
pub fn ParallelColumns(comptime n_sums: usize) type {
    return struct {
        columns: [4 * n_sums][]M31,
        claims: [n_sums]QM31,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.columns) |column| allocator.free(column);
            self.* = undefined;
        }
    };
}

/// Builds several pairs-batched cumulative columns without materialising a
/// full-domain `RowPair` matrix or repeatedly scattering bit-reversed rows.
///
/// `context` is a small copyable value with
/// `fn rowPairsAt(self, logical_row: usize) [n_sums]RowPair`. It must return
/// zero-numerator padding pairs outside the active witness. Chunks write local
/// prefixes to disjoint trace-order ranges, then a second parallel pass
/// transposes once into the committed bit-reversed layout.
pub fn generateParallelColumns(
    comptime n_sums: usize,
    allocator: std.mem.Allocator,
    context: anytype,
    log_size: u32,
    pool: *work_pool.WorkPool,
) !ParallelColumns(n_sums) {
    return ParallelColumnGenerator(n_sums, @TypeOf(context)).generate(
        allocator,
        context,
        log_size,
        pool,
    );
}

fn ParallelColumnGenerator(comptime n_sums: usize, comptime Context: type) type {
    return struct {
        const Generator = @This();

        const Chunk = struct {
            allocator: std.mem.Allocator,
            context: Context,
            trace_sums: []QM31,
            trace_size: usize,
            row_start: usize,
            row_end: usize,
            totals: [n_sums]QM31 = .{QM31.zero()} ** n_sums,
            offsets: [n_sums]QM31 = .{QM31.zero()} ** n_sums,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                };
            }

            fn runFallible(self: *@This()) !void {
                const chunk_len = self.row_end - self.row_start;
                const term_len = n_sums * chunk_len;
                const numerators = try self.allocator.alloc(QM31, term_len);
                defer self.allocator.free(numerators);
                const denominators = try self.allocator.alloc(QM31, term_len);
                defer self.allocator.free(denominators);
                const inverses = try self.allocator.alloc(QM31, term_len);
                defer self.allocator.free(inverses);

                for (self.row_start..self.row_end, 0..) |row, local_row| {
                    const pairs = self.context.rowPairsAt(row);
                    for (pairs, 0..) |pair, sum_index| {
                        const term_index = sum_index * chunk_len + local_row;
                        denominators[term_index] = pair.d1.mul(pair.d2);
                        numerators[term_index] = pair.n1.mul(pair.d2)
                            .add(pair.n2.mul(pair.d1));
                    }
                }
                try fields.batchInverseInPlace(QM31, denominators, inverses);

                for (0..n_sums) |sum_index| {
                    var accumulator = QM31.zero();
                    for (0..chunk_len) |local_row| {
                        const term_index = sum_index * chunk_len + local_row;
                        accumulator = accumulator.add(
                            numerators[term_index].mul(inverses[term_index]),
                        );
                        self.trace_sums[
                            sum_index * self.trace_size +
                                self.row_start + local_row
                        ] = accumulator;
                    }
                    self.totals[sum_index] = accumulator;
                }
            }
        };

        const PlacementWorker = struct {
            columns: *[4 * n_sums][]M31,
            trace_sums: []const QM31,
            logical_rows: []const usize,
            chunks: []const Chunk,
            trace_size: usize,
            committed_start: usize,
            committed_end: usize,

            fn run(self: *@This()) void {
                for (0..n_sums) |sum_index| {
                    for (self.committed_start..self.committed_end) |committed_row| {
                        const logical_row = self.logical_rows[committed_row];
                        const offset = self.chunks[logical_row / PARALLEL_CHUNK_ROWS]
                            .offsets[sum_index];
                        const current = self.trace_sums[
                            sum_index * self.trace_size + logical_row
                        ].add(offset).toM31Array();
                        for (current, 0..) |coordinate, coordinate_index| {
                            self.columns[4 * sum_index + coordinate_index][committed_row] =
                                coordinate;
                        }
                    }
                }
            }
        };

        fn generate(
            allocator: std.mem.Allocator,
            context: Context,
            log_size: u32,
            pool: *work_pool.WorkPool,
        ) !ParallelColumns(n_sums) {
            const size = @as(usize, 1) << @intCast(log_size);
            var result: ParallelColumns(n_sums) = undefined;
            var allocated_columns: usize = 0;
            errdefer for (result.columns[0..allocated_columns]) |column| allocator.free(column);
            for (&result.columns) |*column| {
                column.* = try allocator.alloc(M31, size);
                allocated_columns += 1;
            }

            const trace_sums = try allocator.alloc(QM31, n_sums * size);
            defer allocator.free(trace_sums);
            const chunk_count = std.math.divCeil(
                usize,
                size,
                PARALLEL_CHUNK_ROWS,
            ) catch unreachable;
            const chunks = try allocator.alloc(Chunk, chunk_count);
            defer allocator.free(chunks);
            for (chunks, 0..) |*chunk, index| {
                const row_start = index * PARALLEL_CHUNK_ROWS;
                chunk.* = .{
                    .allocator = allocator,
                    .context = context,
                    .trace_sums = trace_sums,
                    .trace_size = size,
                    .row_start = row_start,
                    .row_end = @min(size, row_start + PARALLEL_CHUNK_ROWS),
                };
            }

            var wait_group = std.Thread.WaitGroup{};
            for (chunks[1..]) |*chunk| pool.spawnWg(&wait_group, Chunk.run, .{chunk});
            Chunk.run(&chunks[0]);
            wait_group.wait();
            for (chunks) |chunk| if (chunk.err) |err| return err;

            for (0..n_sums) |sum_index| {
                var claim = QM31.zero();
                for (chunks) |*chunk| {
                    chunk.offsets[sum_index] = claim;
                    claim = claim.add(chunk.totals[sum_index]);
                }
                result.claims[sum_index] = claim;
            }

            const placement = try permutation.BitReversalTable.init(allocator, log_size);
            defer placement.deinit(allocator);
            const logical_rows = try allocator.alloc(usize, size);
            defer allocator.free(logical_rows);
            for (placement.mapping, 0..) |committed_row, logical_row| {
                logical_rows[committed_row] = logical_row;
            }
            const worker_count = @min(chunk_count, pool.workerCount());
            const workers = try allocator.alloc(PlacementWorker, worker_count);
            defer allocator.free(workers);
            for (workers, 0..) |*worker, index| {
                worker.* = .{
                    .columns = &result.columns,
                    .trace_sums = trace_sums,
                    .logical_rows = logical_rows,
                    .chunks = chunks,
                    .trace_size = size,
                    .committed_start = size * index / worker_count,
                    .committed_end = size * (index + 1) / worker_count,
                };
            }
            wait_group = .{};
            for (workers[1..]) |*worker| {
                pool.spawnWg(&wait_group, PlacementWorker.run, .{worker});
            }
            PlacementWorker.run(&workers[0]);
            wait_group.wait();
            return result;
        }
    };
}

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
    return pairConstraintGeneric(QM31, s, s_prev, is_first, claimed, pair);
}

/// Scalar-generic authority used unchanged by native and recursive OODS
/// composition. The returned polynomial remains cubic; this is algebraic
/// degree, not runtime complexity.
pub fn pairConstraintGeneric(
    comptime S: type,
    s: S,
    s_prev: S,
    is_first: S,
    claimed: S,
    pair: RowPairFor(S),
) S {
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
const permutation = @import("../infra_trace/permutation.zig");

test "geometry: trace-order shift equals evaluation at point minus coset step" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 3;
    const n: usize = 1 << log_size;

    var values: [8]M31 = undefined;
    for (&values, 0..) |*v, i| v.* = M31.fromU64(@as(u64, i) * 37 + 11);
    var shifted: [8]M31 = undefined;
    for (0..n) |i| shifted[i] = values[(i + n - 1) % n];

    const table = try permutation.BitReversalTable.init(allocator, log_size);
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
