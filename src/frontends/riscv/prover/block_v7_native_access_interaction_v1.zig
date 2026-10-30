//! Producer-only fusion of the original Word/Range/Universal sidecar generators.
//! Same49 columns, every physical claim, byte-counter seal and logical prefix.
//! Decode each typed access once; invert17 denominators in bounded worker tiles.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Transition = @import("block_v5_word_execution_transition_v1.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Universal = @import("block_v5_opcode_memory_interaction_v1.zig");
const Source = @import("block_execution_access_bridge_v2.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Counters = @import("../air/lookups/tables/counter.zig");
const Snapshot = @import("../air/block/memory_range_interaction_v2.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Pool = engine.work_pool;
pub const COLUMN_COUNT = Transition.COLUMN_COUNT + Range.COLUMN_COUNT + Universal.COLUMN_COUNT;
pub const TILE_ROWS = 256;
pub const MAX_WORKERS = 16;
const DENOMINATORS = 3 + Range.REQUEST_COUNT;
const RANGE_OFFSET = Transition.COLUMN_COUNT;
const UNIVERSAL_OFFSET = RANGE_OFFSET + Range.COLUMN_COUNT;
pub const Result = struct {
    columns: [COLUMN_COUNT][]M,
    transition_sum: Q,
    universal_sum: Q,
    range_claims: Range.Claims,
    active_count: u64,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.columns) |column| a.free(column);
        self.* = undefined;
    }
};

pub fn generate(a: std.mem.Allocator, trace: anytype, challenges: *const Word.Challenges, expected_snapshot: Range.SNAPSHOT) !Result {
    return generateWithScratch(a, a, trace, challenges, expected_snapshot);
}
/// Output lives with the interaction tree; scratch must use a charged backing
/// allocator that actually releases between slots, not the metadata arena.
pub fn generateWithScratch(a: std.mem.Allocator, scratch: std.mem.Allocator, trace: anytype, challenges: *const Word.Challenges, expected_snapshot: Range.SNAPSHOT) !Result {
    const log = trace.log_size;
    if (log == 0 or log > 24) return error.InvalidUniversalMemoryDomain;
    const size: usize = @as(usize, 1) << @intCast(log);
    if (trace.domainSize() != size) return error.InvalidUniversalMemoryDomain;
    const range = challenges.universal_prefix.get(.range_check_8_8);
    const memory = challenges.universal_prefix.get(.memory_access);
    if (range.arity != 2) return error.InvalidExecutionRangeChallenge;
    if (memory.arity != 7) return error.InvalidUniversalMemoryDomain;
    var columns: [COLUMN_COUNT][]M = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| a.free(column);
    for (&columns) |*column| {
        column.* = try a.alloc(M, size);
        initialized += 1;
    }
    var lease: ?Pool.WorkLease = null;
    if (size >= 16384) if (Pool.currentScopedPool()) |pool| {
        const count = @min(@min(pool.workerCount(), MAX_WORKERS), size / TILE_ROWS);
        if (count > 1) lease = pool.acquire(try Pool.WorkerBudget.init(count)) catch |err| switch (err) {
            error.WorkerBudgetUnavailable => null,
            else => return err,
        };
    };
    defer if (lease) |*held| held.deinit();
    const count = if (lease) |*held| held.workerCount() else 1;
    const tile_rows = @min(TILE_ROWS, size);
    const scratch_len = count * tile_rows * DENOMINATORS;
    const denominators = try scratch.alloc(Q, scratch_len);
    defer scratch.free(denominators);
    const inverses = try scratch.alloc(Q, scratch_len);
    defer scratch.free(inverses);
    const active = try scratch.alloc(bool, count * tile_rows);
    defer scratch.free(active);
    var counters: [MAX_WORKERS]Counters.Counter = undefined;
    var counters_ready: usize = 0;
    defer for (counters[0..counters_ready]) |*counter| counter.deinit(scratch);
    for (counters[0..count]) |*counter| {
        counter.* = try Counters.Counter.init(scratch, .range_check_8_8);
        counters_ready += 1;
    }
    var jobs: [MAX_WORKERS]Job(@TypeOf(trace)) = undefined;
    var wait = std.Thread.WaitGroup{};
    {
        defer {
            wait.wait();
            if (lease) |*held| held.completeWave();
        }
        for (jobs[0..count], 0..) |*job, i| {
            job.* = .{
                .trace = trace,
                .challenges = challenges,
                .columns = &columns,
                .counter = &counters[i],
                .begin = size * i / count,
                .end = size * (i + 1) / count,
                .denominators = denominators[i * tile_rows * DENOMINATORS ..][0 .. tile_rows * DENOMINATORS],
                .inverses = inverses[i * tile_rows * DENOMINATORS ..][0 .. tile_rows * DENOMINATORS],
                .active = active[i * tile_rows ..][0..tile_rows],
            };
            if (i + 1 < count) try lease.?.spawnWg(&wait, Job(@TypeOf(trace)).run, .{job}) else job.run();
        }
    }
    var result = Result{ .columns = columns, .transition_sum = Q.zero(), .universal_sum = Q.zero(), .range_claims = @splat(Q.zero()), .active_count = 0 };
    for (jobs[0..count]) |job| {
        if (job.failure) |err| return err;
        result.transition_sum = result.transition_sum.add(job.transition_sum);
        result.universal_sum = result.universal_sum.add(job.universal_sum);
        result.active_count += job.active_count;
        for (&result.range_claims, job.range_claims) |*sum, value| sum.* = sum.add(value);
    }
    for (counters[1..count]) |counter| for (counters[0].values, counter.values) |*sum, value| {
        sum.* = sum.add(value);
    };
    if (!std.mem.eql(u8, &Snapshot.counterSnapshot(&counters[0]), &expected_snapshot)) return error.ExecutionRangeCounterChangedAfterSeal;
    const size_m = M.fromU64(size);
    const transition_shift = try result.transition_sum.divM31(size_m);
    const universal_shift = try result.universal_sum.divM31(size_m);
    const count_shift = try M.fromU64(result.active_count).div(size_m);
    var range_shifts: Range.Claims = undefined;
    for (&range_shifts, result.range_claims) |*shift, sum| shift.* = try sum.divM31(size_m);
    var transition_prefix = Q.zero();
    var universal_prefix = Q.zero();
    var range_prefixes: Range.Claims = @splat(Q.zero());
    var count_prefix = M.zero();
    for (0..size) |logical| {
        const physical = Framework.committedRow(logical, log);
        const term = read(&columns, 0, physical);
        transition_prefix = transition_prefix.add(term).sub(transition_shift);
        // A nonzero inverse exactly identifies an active row. Inactive terms
        // were explicitly zeroed and active zero denominators were rejected.
        count_prefix = count_prefix.add(if (term.isZero()) M.zero() else M.one()).sub(count_shift);
        write(&columns, 4, physical, transition_prefix);
        columns[8][physical] = count_prefix;
        for (&range_prefixes, range_shifts, 0..) |*prefix, shift, batch| {
            const offset = RANGE_OFFSET + 4 * batch;
            prefix.* = prefix.add(read(&columns, offset, physical)).sub(shift);
            write(&columns, offset, physical, prefix.*);
        }
        universal_prefix = universal_prefix.add(read(&columns, UNIVERSAL_OFFSET, physical)).sub(read(&columns, UNIVERSAL_OFFSET + 4, physical)).sub(universal_shift);
        write(&columns, UNIVERSAL_OFFSET + 8, physical, universal_prefix);
    }
    if (!transition_prefix.isZero()) return error.InvalidExecutionTransitionPrefix;
    if (!count_prefix.isZero()) return error.InvalidExecutionCountPrefix;
    if (!universal_prefix.isZero()) return error.InvalidUniversalMemoryPrefix;
    for (range_prefixes) |prefix| if (!prefix.isZero()) return error.InvalidExecutionRangePrefix;
    return result;
}
fn Job(comptime Trace: type) type {
    return struct {
        trace: Trace,
        challenges: *const Word.Challenges,
        columns: *[COLUMN_COUNT][]M,
        counter: *Counters.Counter,
        begin: usize,
        end: usize,
        denominators: []Q,
        inverses: []Q,
        active: []bool,
        transition_sum: Q = Q.zero(),
        universal_sum: Q = Q.zero(),
        range_claims: Range.Claims = @splat(Q.zero()),
        active_count: u64 = 0,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.fill() catch |err| {
                self.failure = err;
            };
        }
        fn fill(self: *@This()) !void {
            const range = self.challenges.universal_prefix.get(.range_check_8_8);
            const memory = self.challenges.universal_prefix.get(.memory_access);
            var begin = self.begin;
            while (begin < self.end) {
                const end = @min(self.end, begin + self.active.len);
                const length = end - begin;
                for (begin..end, 0..) |logical, local| {
                    const pair = try self.trace.pairAt(logical);
                    const decoded = try Source.decodePair(pair);
                    self.active[local] = decoded.active;
                    const den = self.denominators[local * DENOMINATORS ..][0..DENOMINATORS];
                    if (!decoded.active) {
                        @memset(den, Q.one());
                        continue;
                    }
                    const witness = try self.trace.witnessAt(logical);
                    const transition = Integer.transitionAtPoint(pair, witness);
                    var tuple: Bus.TransitionTuple = undefined;
                    for (transition, &tuple) |value, *cell| cell.* = try base(value, error.NonBaseExecutionSidecarWitness);
                    _ = try Bus.decodeTransitionTuple(tuple);
                    den[0] = self.challenges.transition.combineBase(Word.fromByteTransition(M, tuple));
                    const opposite = try Universal.pointFromPair(pair);
                    var consumed: Universal.Tuple = undefined;
                    var emitted: Universal.Tuple = undefined;
                    for (opposite.consumed, &consumed) |value, *cell| cell.* = try base(value, error.NonBaseNativeMemoryTuple);
                    for (opposite.emitted, &emitted) |value, *cell| cell.* = try base(value, error.NonBaseNativeMemoryTuple);
                    den[1] = try memory.combineBase(&consumed);
                    den[2] = try memory.combineBase(&emitted);
                    const bytes = Range.bytesAtPoint(pair, witness);
                    for (0..Range.REQUEST_COUNT) |request| {
                        const byte_pair = [2]M{ try base(bytes[2 * request], error.NonBaseExecutionRangeByte), try base(bytes[2 * request + 1], error.NonBaseExecutionRangeByte) };
                        try self.counter.registerBase(M.one(), &byte_pair);
                        den[3 + request] = try range.combineBase(&byte_pair);
                    }
                }
                try core.fields.batchInverseInPlace(Q, self.denominators[0 .. length * DENOMINATORS], self.inverses[0 .. length * DENOMINATORS]);
                for (begin..end, 0..) |logical, local| {
                    const physical = Framework.committedRow(logical, self.trace.log_size);
                    const inv = self.inverses[local * DENOMINATORS ..][0..DENOMINATORS];
                    if (!self.active[local]) {
                        write(self.columns, 0, physical, Q.zero());
                        write(self.columns, UNIVERSAL_OFFSET, physical, Q.zero());
                        write(self.columns, UNIVERSAL_OFFSET + 4, physical, Q.zero());
                        for (0..Range.BATCH_COUNT) |batch| write(self.columns, RANGE_OFFSET + 4 * batch, physical, Q.zero());
                        continue;
                    }
                    self.active_count += 1;
                    self.transition_sum = self.transition_sum.add(inv[0]);
                    self.universal_sum = self.universal_sum.add(inv[1]).sub(inv[2]);
                    write(self.columns, 0, physical, inv[0]);
                    write(self.columns, UNIVERSAL_OFFSET, physical, inv[1]);
                    write(self.columns, UNIVERSAL_OFFSET + 4, physical, inv[2]);
                    for (0..Range.BATCH_COUNT) |batch| {
                        const term = inv[3 + 2 * batch].add(inv[4 + 2 * batch]);
                        self.range_claims[batch] = self.range_claims[batch].add(term);
                        write(self.columns, RANGE_OFFSET + 4 * batch, physical, term);
                    }
                }
                begin = end;
            }
        }
    };
}
fn base(value: Q, failure: anyerror) !M {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return failure;
    return limbs[0];
}
fn write(columns: *[COLUMN_COUNT][]M, offset: usize, row: usize, value: Q) void {
    for (value.toM31Array(), 0..) |limb, i| columns[offset + i][row] = limb;
}
fn read(columns: *const [COLUMN_COUNT][]M, offset: usize, row: usize) Q {
    return Q.fromM31Array(.{ columns[offset][row], columns[offset + 1][row], columns[offset + 2][row], columns[offset + 3][row] });
}
