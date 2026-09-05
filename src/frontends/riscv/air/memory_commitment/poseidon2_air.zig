//! Exact pinned Stark-V Poseidon2-M31 AIR for sparse Merkle hashes.
//!
//! The 445-column layout matches the generated Rust component:
//! enabler, 16 inputs, 426 degree-reduction temporaries, wide, and io.
//! RV32IM sparse trees use narrow mode (`wide = io = 0`).

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const infra = @import("../../infra_trace.zig");
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const constants = @import("poseidon2_constants.zig");
const permutation = @import("poseidon2.zig");
const poseidon_work = @import("../../prover/poseidon_witness_work.zig");

pub const WIDTH: usize = 16;
pub const N_TEMPORARIES: usize = 426;
pub const N_MAIN_COLUMNS: usize = 1 + WIDTH + N_TEMPORARIES + 2;
pub const N_MATERIALIZATION_CONSTRAINTS: usize = N_TEMPORARIES;
pub const N_PERMUTATION_CONSTRAINTS: usize = 1 + N_MATERIALIZATION_CONSTRAINTS;
pub const N_FLAG_CONSTRAINTS: usize = 3;
pub const N_CONSTRAINTS: usize = N_PERMUTATION_CONSTRAINTS + N_FLAG_CONSTRAINTS;
pub const N_SUMS: usize = 2;
pub const N_INTERACTION_COLUMNS: usize = N_SUMS * 4;
const INPUT_START: usize = 1;
const TEMP_START: usize = INPUT_START + WIDTH;
pub const WIDE_COLUMN: usize = TEMP_START + N_TEMPORARIES;
pub const IO_COLUMN: usize = WIDE_COLUMN + 1;
const FIRST_FULL_ROUND_WIDTH: usize = 2 * WIDTH;
const MATERIALIZED_FULL_ROUND_WIDTH: usize = 3 * WIDTH;
const PARTIAL_ROUND_WIDTH: usize = 3;
const OUTPUT_START: usize = TEMP_START + N_TEMPORARIES - WIDTH;

pub const Call = struct {
    input: [WIDTH]u32,
    wide: bool = false,
    io: bool = false,
    /// Narrow output already carried by the Merkle witness. Interaction
    /// generation may use it instead of recomputing 426 main-trace
    /// temporaries. Only the input and one-lane narrow-output relations have
    /// nonzero multiplicity in this mode; the Poseidon lookup AIR still binds
    /// them to the separately committed permutation row and rejects any
    /// disagreement.
    narrow_output: ?u32 = null,

    pub fn narrow(left: u32, right: u32) Call {
        var input = [_]u32{0} ** WIDTH;
        input[0] = left;
        input[1] = right;
        return .{ .input = input };
    }

    pub fn narrowWithOutput(left: u32, right: u32, output_value: u32) Call {
        var call = narrow(left, right);
        call.narrow_output = output_value;
        return call;
    }
};

pub const Columns = struct {
    values: [N_MAIN_COLUMNS][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.values);
        self.* = undefined;
    }
};

pub const Claims = struct {
    sums: [N_SUMS]QM31,

    pub fn total(self: Claims) QM31 {
        return self.sums[0].add(self.sums[1]);
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,

    pub fn deinit(self: *Interaction, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        self.* = undefined;
    }
};

pub fn generateMain(
    allocator: std.mem.Allocator,
    calls: []const Call,
    log_size: u32,
) !Columns {
    const size = @as(usize, 1) << @intCast(log_size);
    var columns = try allocateColumns(allocator, N_MAIN_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    try generateMainInto(allocator, &columns, calls, log_size);
    return .{ .values = columns };
}

pub const GeneratedMainWithWorkReceipt = struct {
    columns: Columns,
    receipt: poseidon_work.ProducerReceipt,
};

/// Allocating exact-work route for callers that own the returned columns.
/// Receipt construction occurs after the complete trace succeeds; an
/// allocation or shape failure cannot publish a partial row count.
pub fn generateMainWithWorkReceipt(
    allocator: std.mem.Allocator,
    calls: []const Call,
    log_size: u32,
    authority: *const poseidon_work.Authority,
) !GeneratedMainWithWorkReceipt {
    var columns = try generateMain(allocator, calls, log_size);
    errdefer columns.deinit(allocator);
    return .{
        .columns = columns,
        .receipt = try poseidon_work.complete(
            authority,
            .base_air_row_materialization,
            @intCast(calls.len),
        ),
    };
}

/// Writes the exact main trace into caller-owned final storage.
///
/// The resident Metal path plans all 445 columns before witness generation, so
/// allocating another multi-gigabyte column set merely to copy it into that
/// arena would defeat residency. The ordinary allocator-returning API above is
/// a thin owner around this same implementation.
pub fn generateMainInto(
    allocator: std.mem.Allocator,
    columns: *[N_MAIN_COLUMNS][]M31,
    calls: []const Call,
    log_size: u32,
) !void {
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    for (columns) |column| {
        if (column.len != size) return error.InvalidTraceShape;
        @memset(column, M31.zero());
    }
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    if (work_pool.getGlobalPool()) |pool| {
        const worker_count = @min(
            pool.workerCount(),
            @max(@as(usize, 1), calls.len / 4096),
        );
        if (worker_count > 1) {
            const logical_rows = try allocator.alloc(usize, size);
            defer allocator.free(logical_rows);
            for (table.mapping, 0..) |committed_row, logical_row| {
                logical_rows[committed_row] = logical_row;
            }
            const workers = try allocator.alloc(MainTraceWorker, worker_count);
            defer allocator.free(workers);
            for (workers, 0..) |*worker, index| {
                worker.* = .{
                    .columns = columns,
                    .calls = calls,
                    .logical_rows = logical_rows,
                    .committed_start = size * index / worker_count,
                    .committed_end = size * (index + 1) / worker_count,
                };
            }
            var wait_group = std.Thread.WaitGroup{};
            for (workers[1..]) |*worker| {
                pool.spawnWg(&wait_group, MainTraceWorker.run, .{worker});
            }
            MainTraceWorker.run(&workers[0]);
            wait_group.wait();
            return;
        }
    }
    for (calls, 0..) |call, row_index| {
        const row = fill(call);
        const dst = table.map(row_index);
        for (row, 0..) |value, column| columns.*[column][dst] = value;
    }
}

/// Caller-owned exact-work route.  The hot implementation remains the same
/// branch-free loop as `generateMainInto`; only its successful boundary
/// constructs the digest-bound receipt.
pub fn generateMainIntoWithWorkReceipt(
    allocator: std.mem.Allocator,
    columns: *[N_MAIN_COLUMNS][]M31,
    calls: []const Call,
    log_size: u32,
    authority: *const poseidon_work.Authority,
) !poseidon_work.ProducerReceipt {
    try generateMainInto(allocator, columns, calls, log_size);
    return poseidon_work.complete(
        authority,
        .base_air_row_materialization,
        @intCast(calls.len),
    );
}

/// Writes disjoint committed ranges so hundreds of column streams never share
/// cache lines between workers. The inverse placement maps each destination
/// back to the canonical witness call without changing protocol order.
const MainTraceWorker = struct {
    columns: *[N_MAIN_COLUMNS][]M31,
    calls: []const Call,
    logical_rows: []const usize,
    committed_start: usize,
    committed_end: usize,

    fn run(self: *@This()) void {
        for (self.committed_start..self.committed_end) |committed_row| {
            const logical_row = self.logical_rows[committed_row];
            if (logical_row >= self.calls.len) continue;
            const row = fill(self.calls[logical_row]);
            for (row, 0..) |value, column| {
                self.columns[column][committed_row] = value;
            }
        }
    }
};

/// Fill exactly the generated Rust witness row, including degree-reduction
/// temporaries. The final permutation state occupies temporaries 410..425.
pub fn fill(call: Call) [N_MAIN_COLUMNS]M31 {
    var row = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    row[0] = M31.one();
    var state: [WIDTH]M31 = undefined;
    for (&state, call.input, 0..) |*value, input, lane| {
        value.* = M31.fromU64(input);
        row[INPUT_START + lane] = value.*;
    }

    externalMatrixM31(&state);
    var cursor: usize = TEMP_START;
    fillFirstFullRound(&row, &cursor, &state, constants.EXTERNAL_ROUND[0]);
    for (constants.EXTERNAL_ROUND[1..4]) |round| {
        fillMaterializedFullRound(&row, &cursor, &state, round);
    }
    for (constants.INTERNAL_ROUND) |round_constant| {
        fillMaterializedPartialRound(
            &row,
            &cursor,
            &state,
            round_constant,
            constants.INTERNAL_MATRIX,
        );
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| {
        fillMaterializedFullRound(&row, &cursor, &state, round);
    }
    for (state) |value| {
        row[cursor] = value;
        cursor += 1;
    }
    std.debug.assert(cursor == WIDE_COLUMN);
    row[WIDE_COLUMN] = M31.fromU64(@intFromBool(call.wide));
    row[IO_COLUMN] = M31.fromU64(@intFromBool(call.io));
    return row;
}

pub fn output(row: [N_MAIN_COLUMNS]M31) [WIDTH]M31 {
    return row[OUTPUT_START..][0..WIDTH].*;
}

/// Exact degree-three constraint order emitted by pinned Stark-V's felt AIR
/// compiler: enabler boolean, 426 materializations, then three flag checks.
pub fn evaluate(main: [N_MAIN_COLUMNS]QM31) [N_CONSTRAINTS]QM31 {
    return evaluateGeneric(QM31, main);
}

/// Single-source constraint replay over either native `QM31` or a recorder.
pub fn evaluateGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [N_CONSTRAINTS]S {
    const enabler = main[0];
    var state = main[INPUT_START..][0..WIDTH].*;
    externalMatrixSecure(S, &state);
    var result: [N_CONSTRAINTS]S = undefined;
    var constraint: usize = 1;
    var cursor: usize = TEMP_START;
    const one = S.one();
    result[0] = enabler.mul(one.sub(enabler));

    evaluateFirstFullRound(
        S,
        main,
        &cursor,
        &state,
        constants.EXTERNAL_ROUND[0],
        enabler,
        &result,
        &constraint,
    );
    for (constants.EXTERNAL_ROUND[1..4]) |round| {
        evaluateMaterializedFullRound(
            S,
            main,
            &cursor,
            &state,
            round,
            enabler,
            &result,
            &constraint,
        );
    }
    for (constants.INTERNAL_ROUND) |round_constant| {
        evaluateMaterializedPartialRound(
            S,
            main,
            &cursor,
            &state,
            round_constant,
            constants.INTERNAL_MATRIX,
            enabler,
            &result,
            &constraint,
        );
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| {
        evaluateMaterializedFullRound(
            S,
            main,
            &cursor,
            &state,
            round,
            enabler,
            &result,
            &constraint,
        );
    }
    for (state, 0..) |expected, lane| {
        const actual = main[cursor + lane];
        result[constraint] = enabler.mul(actual.sub(expected));
        constraint += 1;
    }
    cursor += WIDTH;
    std.debug.assert(cursor == WIDE_COLUMN);
    std.debug.assert(constraint == N_PERMUTATION_CONSTRAINTS);

    const wide = main[WIDE_COLUMN];
    const io = main[IO_COLUMN];
    result[constraint] = wide.mul(one.sub(wide));
    result[constraint + 1] = io.mul(one.sub(io));
    result[constraint + 2] = wide.mul(io);
    return result;
}

/// Protocol-shell constraints for callers that admit only the narrow
/// permutation mode. The generic pinned evaluator deliberately continues to
/// support wide and atomic-I/O rows.
pub fn narrowModeConstraints(main: [N_MAIN_COLUMNS]QM31) [2]QM31 {
    return narrowModeConstraintsGeneric(QM31, main);
}

pub fn narrowModeConstraintsGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [2]S {
    return .{ main[WIDE_COLUMN], main[IO_COLUMN] };
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    calls: []const Call,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    return generateInteractionSerial(
        allocator,
        log_size,
        InteractionContext{ .calls = calls, .relations = relations },
    );
}

/// Generates the atomic-I/O interaction trace from outputs already committed
/// by the typed Poseidon executor. This is the recursion-provider fast path:
/// it preserves the exact four-entry/batching convention while avoiding a
/// second scalar permutation merely to recover the 16 output words.
pub fn generateIoInteractionFromOutputs(
    allocator: std.mem.Allocator,
    calls: []const Call,
    outputs: []const [WIDTH]u32,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Interaction {
    try validateIoOutputs(calls, outputs, log_size);
    return generateInteractionSerial(
        allocator,
        log_size,
        IoInteractionContext{
            .calls = calls,
            .outputs = outputs,
            .relations = relations,
        },
    );
}

/// Rebuilds only the two ordered atomic-I/O LogUp claims from retained typed
/// executor outputs. This is the allocation-free audit companion to
/// `generateIoInteractionFromOutputs`: proof generation still uses the full
/// interaction writer above, while independent receipt checks need not
/// allocate or materialize cumulative columns.
///
/// Padding contributes zero numerators, so iterating the active prefix is
/// exactly equivalent to traversing the full power-of-two domain. The sum
/// order remains the protocol order `[poseidon2, poseidon2_io]`.
pub fn claimsFromIoOutputs(
    calls: []const Call,
    outputs: []const [WIDTH]u32,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Claims {
    var result: Claims = undefined;
    try claimsFromIoOutputsInto(
        &result,
        calls,
        outputs,
        log_size,
        relations,
    );
    return result;
}

/// Failure-atomic prepared destination form of `claimsFromIoOutputs`.
/// `destination` is written only after every retained word and denominator
/// has been validated.
pub fn claimsFromIoOutputsInto(
    destination: *Claims,
    calls: []const Call,
    outputs: []const [WIDTH]u32,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !void {
    try validateIoOutputs(calls, outputs, log_size);
    var claims = Claims{
        .sums = [_]QM31{QM31.zero()} ** N_SUMS,
    };
    for (calls, outputs) |call, output_value| {
        const pairs = ioRowPairsFromOutput(call, output_value, relations);
        for (pairs, 0..) |pair, sum_index| {
            const denominator = pair.d1.mul(pair.d2);
            const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
            const inverse = denominator.inv() catch return error.ZeroDenominator;
            claims.sums[sum_index] = claims.sums[sum_index].add(
                numerator.mul(inverse),
            );
        }
    }
    destination.* = claims;
}

fn generateInteractionSerial(
    allocator: std.mem.Allocator,
    log_size: u32,
    context: anytype,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    const pairs = try allocator.alloc([N_SUMS]logup.RowPair, size);
    defer allocator.free(pairs);
    for (0..size) |index| pairs[index] = context.rowPairsAt(index);

    var cumulative: [N_SUMS]logup.CumulativeColumn = undefined;
    var initialized: usize = 0;
    defer for (cumulative[0..initialized]) |*column| column.deinit(allocator);
    for (&cumulative, 0..) |*column, sum_index| {
        const row_pairs = try allocator.alloc(logup.RowPair, size);
        defer allocator.free(row_pairs);
        for (pairs, row_pairs) |row, *pair| pair.* = row[sum_index];
        column.* = try logup.cumulativeColumn(allocator, row_pairs);
        initialized += 1;
    }

    var columns = try allocateColumns(allocator, N_INTERACTION_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (0..size) |row| {
        const dst = table.map(row);
        for (0..N_SUMS) |sum_index| {
            const current = cumulative[sum_index].sums[row].toM31Array();
            for (0..4) |coordinate| {
                columns[sum_index * 4 + coordinate][dst] = current[coordinate];
            }
        }
    }
    return .{
        .columns = columns,
        .claims = .{ .sums = .{ cumulative[0].claimed, cumulative[1].claimed } },
    };
}

/// Parallel cache-bounded interaction generation for production-sized hash
/// traces. The narrow Merkle output is already carried by each call, so this
/// path performs only the relation work required by Tree 2.
pub fn generateInteractionParallel(
    allocator: std.mem.Allocator,
    calls: []const Call,
    log_size: u32,
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len > size) return error.InvalidTraceShape;
    const generated = try logup.generateParallelColumns(
        N_SUMS,
        allocator,
        InteractionContext{ .calls = calls, .relations = relations },
        log_size,
        pool,
    );
    return .{
        .columns = generated.columns,
        .claims = .{ .sums = generated.claims },
    };
}

/// Parallel companion to `generateIoInteractionFromOutputs` for provider
/// traces large enough to amortize work-pool scheduling.
pub fn generateIoInteractionFromOutputsParallel(
    allocator: std.mem.Allocator,
    calls: []const Call,
    outputs: []const [WIDTH]u32,
    log_size: u32,
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Interaction {
    try validateIoOutputs(calls, outputs, log_size);
    const generated = try logup.generateParallelColumns(
        N_SUMS,
        allocator,
        IoInteractionContext{
            .calls = calls,
            .outputs = outputs,
            .relations = relations,
        },
        log_size,
        pool,
    );
    return .{
        .columns = generated.columns,
        .claims = .{ .sums = generated.claims },
    };
}

const InteractionContext = struct {
    calls: []const Call,
    relations: *const relations_mod.Relations,

    pub fn rowPairsAt(self: @This(), row: usize) [N_SUMS]logup.RowPair {
        if (row < self.calls.len) return rowPairsFromCall(self.calls[row], self.relations);
        return paddingPairs();
    }
};

const IoInteractionContext = struct {
    calls: []const Call,
    outputs: []const [WIDTH]u32,
    relations: *const relations_mod.Relations,

    pub fn rowPairsAt(self: @This(), row: usize) [N_SUMS]logup.RowPair {
        if (row < self.calls.len) return ioRowPairsFromOutput(
            self.calls[row],
            self.outputs[row],
            self.relations,
        );
        return paddingPairs();
    }
};

fn validateIoOutputs(
    calls: []const Call,
    outputs: []const [WIDTH]u32,
    log_size: u32,
) !void {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(log_size);
    if (calls.len != outputs.len or calls.len > size)
        return error.InvalidTraceShape;
    for (calls, outputs) |call, output_value| {
        if (call.wide or !call.io or call.narrow_output != null)
            return error.InvalidTraceShape;
        for (call.input) |word| if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidTraceShape;
        for (output_value) |word| if (word >= @import("stwo_core").fields.m31.Modulus)
            return error.InvalidTraceShape;
    }
}

fn ioRowPairsFromOutput(
    call: Call,
    output_value: [WIDTH]u32,
    relations: *const relations_mod.Relations,
) [N_SUMS]logup.RowPair {
    var input: [WIDTH]QM31 = undefined;
    var output_secure: [WIDTH]QM31 = undefined;
    for (&input, call.input) |*destination, word|
        destination.* = QM31.fromBase(M31.fromCanonical(word));
    for (&output_secure, output_value) |*destination, word|
        destination.* = QM31.fromBase(M31.fromCanonical(word));
    var narrow = [_]QM31{QM31.zero()} ** WIDTH;
    narrow[0] = output_secure[0];
    var wide_output = [_]QM31{QM31.zero()} ** WIDTH;
    @memcpy(wide_output[0..8], output_secure[0..8]);
    var io_tuple: [2 * WIDTH]QM31 = undefined;
    @memcpy(io_tuple[0..WIDTH], &input);
    @memcpy(io_tuple[WIDTH..], &output_secure);

    var list = lookup_entry.List{};
    append(&list, .poseidon2, QM31.zero(), input);
    append(&list, .poseidon2, QM31.zero(), narrow);
    append(&list, .poseidon2, QM31.zero(), wide_output);
    append(&list, .poseidon2_io, QM31.one(), io_tuple);
    return .{
        list.pair(0, relations) catch unreachable,
        list.pair(1, relations) catch unreachable,
    };
}

pub fn interactionConstraints(
    main: [N_MAIN_COLUMNS]QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_SUMS]QM31 {
    return interactionConstraintsGeneric(QM31, main, is_first, sums, previous, claims, relations);
}

pub fn interactionConstraintsGeneric(
    comptime S: type,
    main: [N_MAIN_COLUMNS]S,
    is_first: S,
    sums: [N_SUMS]S,
    previous: [N_SUMS]S,
    claims: [N_SUMS]S,
    relations: anytype,
) [N_SUMS]S {
    const pairs = rowPairsGeneric(S, main, relations);
    var result: [N_SUMS]S = undefined;
    for (&result, 0..) |*value, index| {
        value.* = logup.pairConstraintGeneric(
            S,
            sums[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }
    return result;
}

pub fn rowPairsFromCall(call: Call, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    if (call.narrow_output != null and !call.wide and !call.io)
        return narrowRowPairsFromCall(call, relations);
    var secure: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&secure, fill(call)) |*dst, value| dst.* = QM31.fromBase(value);
    return rowPairs(secure, relations);
}

/// Field-identical specialization of `rowPairsFromCall` for a canonical
/// narrow call.  With enabler one and wide/io zero the four lookup entries
/// carry constant numerators (-1, 1, 0, 0), and every denominator is a base
/// field tuple combined with the relation challenges, so the row never needs
/// the 445-column main row, its QM31 promotion, or the entry-list copies.
/// The `-1` numerator is `enabler * (1 - io)` negated exactly as the generic
/// builder computes it.
pub fn narrowRowPairsFromCall(call: Call, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    std.debug.assert(call.narrow_output != null and !call.wide and !call.io);
    var input: [WIDTH]M31 = undefined;
    for (&input, call.input) |*value, word| value.* = M31.fromU64(word);
    const output_value = M31.fromU64(call.narrow_output.?);
    var narrow = [_]M31{M31.zero()} ** WIDTH;
    narrow[0] = output_value;
    var io_tuple: [2 * WIDTH]M31 = undefined;
    @memcpy(io_tuple[0..WIDTH], &input);
    @memcpy(io_tuple[WIDTH..], &narrow);
    const one = QM31.one();
    return .{
        .{
            .n1 = one.neg(),
            .d1 = relations.poseidon2.combineBase(input),
            .n2 = one,
            .d2 = relations.poseidon2.combineBase(narrow),
        },
        .{
            .n1 = QM31.zero(),
            .d1 = relations.poseidon2.combineBase(narrow),
            .n2 = QM31.zero(),
            .d2 = relations.poseidon2_io.combineBase(io_tuple),
        },
    };
}

pub fn rowPairs(main: [N_MAIN_COLUMNS]QM31, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    return rowPairsGeneric(QM31, main, relations);
}

pub fn rowPairsGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S, relations: anytype) [N_SUMS]logup.RowPairFor(S) {
    const list = entriesGeneric(S, main);
    return .{
        list.pairWith(0, relations) catch unreachable,
        list.pairWith(1, relations) catch unreachable,
    };
}

pub fn entries(main: [N_MAIN_COLUMNS]QM31) lookup_entry.List {
    return entriesGeneric(QM31, main);
}

pub fn entriesGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) lookup_entry.Builder(S).List {
    const EntryBuilder = lookup_entry.Builder(S);
    const enabler = main[0];
    const wide = main[WIDE_COLUMN];
    const io = main[IO_COLUMN];
    const one = S.one();
    const input = main[INPUT_START..][0..WIDTH].*;
    const out = main[OUTPUT_START..][0..WIDTH].*;
    var narrow = [_]S{S.zero()} ** WIDTH;
    narrow[0] = out[0];
    var wide_output = [_]S{S.zero()} ** WIDTH;
    @memcpy(wide_output[0..8], out[0..8]);
    var io_tuple: [2 * WIDTH]S = undefined;
    @memcpy(io_tuple[0..WIDTH], &input);
    @memcpy(io_tuple[WIDTH..], &out);
    var list = EntryBuilder.List{};
    appendGeneric(S, &list, .poseidon2, enabler.mul(one.sub(io)).neg(), input);
    appendGeneric(S, &list, .poseidon2, enabler.mul(one.sub(wide).sub(io)), narrow);
    appendGeneric(S, &list, .poseidon2, enabler.mul(wide), wide_output);
    appendGeneric(S, &list, .poseidon2_io, enabler.mul(io), io_tuple);
    return list;
}

pub fn paddingPairs() [N_SUMS]logup.RowPair {
    const zero = QM31.zero();
    const one = QM31.one();
    return .{
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
    };
}

const runtime = @import("poseidon2_air_runtime.zig").Runtime(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .lookup_entry = lookup_entry,
    .WIDTH = WIDTH,
    .N_MAIN_COLUMNS = N_MAIN_COLUMNS,
    .N_CONSTRAINTS = N_CONSTRAINTS,
    .FIRST_FULL_ROUND_WIDTH = FIRST_FULL_ROUND_WIDTH,
    .MATERIALIZED_FULL_ROUND_WIDTH = MATERIALIZED_FULL_ROUND_WIDTH,
    .PARTIAL_ROUND_WIDTH = PARTIAL_ROUND_WIDTH,
});
const fillFirstFullRound = runtime.fillFirstFullRound;
const fillMaterializedFullRound = runtime.fillMaterializedFullRound;
const fillMaterializedPartialRound = runtime.fillMaterializedPartialRound;
const evaluateFirstFullRound = runtime.evaluateFirstFullRound;
const evaluateMaterializedFullRound = runtime.evaluateMaterializedFullRound;
const evaluateMaterializedPartialRound = runtime.evaluateMaterializedPartialRound;
const externalMatrixM31 = runtime.externalMatrixM31;
const externalMatrixSecure = runtime.externalMatrixSecure;
const m4M31 = runtime.m4M31;
const m4Secure = runtime.m4Secure;
const internalMatrixM31 = runtime.internalMatrixM31;
const internalMatrixSecure = runtime.internalMatrixSecure;
const allocateColumns = runtime.allocateColumns;
const freeColumns = runtime.freeColumns;
const baseSecure = runtime.baseSecure;
const append = runtime.append;
const appendGeneric = runtime.appendGeneric;
const secureRow = runtime.secureRow;
const expectAllZero = runtime.expectAllZero;

const AirTests = @import("poseidon2_air_test.zig").Tests(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .logup = logup,
    .relations_mod = relations_mod,
    .permutation = permutation,
    .WIDTH = WIDTH,
    .N_MAIN_COLUMNS = N_MAIN_COLUMNS,
    .N_CONSTRAINTS = N_CONSTRAINTS,
    .INPUT_START = INPUT_START,
    .TEMP_START = TEMP_START,
    .WIDE_COLUMN = WIDE_COLUMN,
    .IO_COLUMN = IO_COLUMN,
    .OUTPUT_START = OUTPUT_START,
    .Call = Call,
    .Claims = Claims,
    .fill = fill,
    .output = output,
    .evaluate = evaluate,
    .generateInteraction = generateInteraction,
    .generateIoInteractionFromOutputs = generateIoInteractionFromOutputs,
    .claimsFromIoOutputs = claimsFromIoOutputs,
    .claimsFromIoOutputsInto = claimsFromIoOutputsInto,
    .rowPairsFromCall = rowPairsFromCall,
    .rowPairs = rowPairs,
    .secureRow = secureRow,
    .expectAllZero = expectAllZero,
});

test "poseidon2 AIR test module is linked" {
    _ = AirTests;
}

test "poseidon2 narrow row pairs are field-identical to the generic entry builder" {
    var prng = std.Random.DefaultPrng.init(0x9a11_5001);
    const random = prng.random();
    const randomQM31 = struct {
        fn call(r: std.Random) QM31 {
            return QM31.fromM31(
                M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
                M31.fromCanonical(r.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus)),
            );
        }
    }.call;
    for (0..32) |_| {
        var relations: relations_mod.Relations = undefined;
        inline for (std.meta.fields(relations_mod.Relations)) |field| {
            @field(relations, field.name) = @TypeOf(@field(relations, field.name)).init(
                randomQM31(random),
                randomQM31(random),
            );
        }
        var call = Call{ .input = undefined, .narrow_output = 0 };
        for (&call.input) |*word| word.* = random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus);
        call.narrow_output = random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus);
        var interaction_main = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
        interaction_main[0] = M31.one();
        for (call.input, 0..) |value, lane| interaction_main[INPUT_START + lane] = M31.fromU64(value);
        interaction_main[OUTPUT_START] = M31.fromU64(call.narrow_output.?);
        var secure: [N_MAIN_COLUMNS]QM31 = undefined;
        for (&secure, interaction_main) |*dst, value| dst.* = QM31.fromBase(value);
        const expected = rowPairs(secure, &relations);
        const actual = narrowRowPairsFromCall(call, &relations);
        for (expected, actual) |lhs, rhs| {
            try std.testing.expect(lhs.n1.eql(rhs.n1) and lhs.d1.eql(rhs.d1) and
                lhs.n2.eql(rhs.n2) and lhs.d2.eql(rhs.d2));
        }
    }
}
