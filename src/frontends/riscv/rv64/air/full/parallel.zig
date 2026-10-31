//! Bounded row work on the prover's existing pool. Each joined wave borrows one
//! evaluated coset; no worker survives scratch reuse. Arithmetic remains in
//! Component.emit, exactly as at OODS points and in serial proving.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const E = @import("../evaluation.zig");
const L = E.L;
const frame = @import("frame.zig");
const component_mod = @import("component.zig");
const Component = component_mod.Component;
const Evaluation = @import("coset_evaluation.zig").Evaluation;
const Column = engine.air.accumulation.ColumnAccumulator;
const packed_rows = @import("packed_rows.zig");
// Debug's unoptimized extension-field temporaries need a larger frame; the
// production optimized path is qualified with a 256 KiB worker guard.
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub const MIN_ROWS_PER_WORKER = 64;
pub const TILE_ROWS = 4096;
// A separate cache tile, not a scheduling or protocol geometry parameter.
pub const NATIVE_TILE_ROWS = 16;
// Fixed QM31 scratch; the coordinator additionally reserves the exact native
// tile width (FIXED + main + interaction + required previous lanes) * 64 bytes.
pub const WORKER_SCRATCH_BYTES = @sizeOf(Scratch);

/// All fallible shape validation precedes submission. The only subsequent
/// errors are structured lease/submission errors; every submitted helper is
/// drained before returning an error or releasing its contexts.
pub fn evaluatePart(component: *const Component, evaluation: *const Evaluation, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool) !void {
    const tile_rows = if (comptime @import("builtin").is_test) testing.tile_rows_override orelse TILE_ROWS else TILE_ROWS;
    const native_gather = if (comptime @import("builtin").is_test) testing.native_gather else true;
    const simd = if (comptime @import("builtin").is_test) testing.simd else true;
    return evaluatePartImpl(component, evaluation, part, output, inverse, pool, tile_rows, null, native_gather, simd);
}
fn evaluatePartImpl(component: *const Component, evaluation: *const Evaluation, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool, tile_rows: usize, fail_after_helpers: ?usize, native_gather: bool, simd: bool) !void {
    try validate(component, evaluation, part, output);
    if (pool) |active| if (active.stackSize() < MIN_STACK_BYTES) return error.InvalidRv64ParallelStack;
    var previous_main: [12]PreviousSource = undefined;
    var previous_interaction: [36]PreviousSource = undefined;
    var n_previous_main: usize = 0;
    var n_previous_interaction: usize = 0;
    for (0..component.mainCount()) |i| if (component.needsPreviousMain(i)) {
        if (n_previous_main == previous_main.len) return error.InvalidRv64ParallelShape;
        previous_main[n_previous_main] = .{ .destination = i, .values = evaluation.previous_values[frame.FIXED + i] };
        n_previous_main += 1;
    };
    const inter_start = frame.FIXED + component.mainCount();
    for (0..component.interactionCount()) |i| if (component.needsPreviousInteraction(i)) {
        if (n_previous_interaction == previous_interaction.len) return error.InvalidRv64ParallelShape;
        previous_interaction[n_previous_interaction] = .{ .destination = i, .values = evaluation.previous_values[inter_start + i] };
        n_previous_interaction += 1;
    };
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, evaluation.size / MIN_ROWS_PER_WORKER)) else 1;
    // Keep row-gather arrays off worker stacks. This one bounded allocation is
    // made by the coordinator; each task owns a disjoint scratch element.
    const scratch = try evaluation.allocator.alloc(Scratch, workers);
    defer evaluation.allocator.free(scratch);
    for (scratch) |*item| item.* = if (simd) .{ .simd = undefined } else .{ .scalar = undefined };
    const native_stride = frame.FIXED + component.mainCount() + component.interactionCount() + n_previous_main + n_previous_interaction;
    // One cache line per source and worker. Allocation and all fallible work
    // precede pool acquisition; the wave drains before either owner is freed.
    const per_worker = if (native_gather and !simd) NATIVE_TILE_ROWS * native_stride else 0;
    const native = try evaluation.allocator.alignedAlloc(M, .@"64", workers * per_worker);
    defer evaluation.allocator.free(native);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    if (workers == 1) {
        jobs[0] = .{ .component = component, .evaluation = evaluation, .scratch = &scratch[0], .native = native[0..per_worker], .simd = simd, .part = part, .output = output.*, .previous_main = previous_main[0..n_previous_main], .previous_interaction = previous_interaction[0..n_previous_interaction], .inverse = inverse, .start = 0, .end = evaluation.size };
        jobs[0].run();
        output.* = jobs[0].output;
        return;
    }
    const active = pool.?;
    var counter = TileCursor{};
    // Tiny domains retain their original static partitions. Production tile
    // admission guarantees at least one tile per admitted worker.
    const dynamic = evaluation.size / workers >= tile_rows;
    if (comptime @import("builtin").is_test) if (dynamic) {
        testing.dynamic_waves += 1;
    };
    var lease = try active.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    var wait_group = std.Thread.WaitGroup{};
    defer {
        wait_group.wait();
        lease.completeWave();
    }
    // Buckets are zero-initialized by columns(). Per-job additive copies avoid
    // sharing the sequential fresh-index cursor while retaining prior terms.
    output.next_fresh_index = null;
    for (jobs[0..workers], 0..) |*job, i| {
        job.* = .{ .component = component, .evaluation = evaluation, .scratch = &scratch[i], .native = native[i * per_worker ..][0..per_worker], .simd = simd, .part = part, .output = output.*, .previous_main = previous_main[0..n_previous_main], .previous_interaction = previous_interaction[0..n_previous_interaction], .inverse = inverse, .counter = if (dynamic) &counter else null, .tile_rows = tile_rows, .start = evaluation.size * i / workers, .end = evaluation.size * (i + 1) / workers };
    }
    for (jobs[1..workers], 0..) |*job, submitted| {
        if (comptime @import("builtin").is_test) {
            if (fail_after_helpers == submitted) return error.InjectedRv64SpawnFailure;
        }
        try lease.spawnWg(&wait_group, Job.run, .{job});
    }
    jobs[0].run();
}

const Tile = struct { start: usize, end: usize };
// One mutable scheduling word on its own cache line, alive until every helper
// drains. Relaxed claims allocate disjoint ranges; no field reduction is shared.
const TileCursor = struct {
    next: std.atomic.Value(usize) align(128) = .init(0),
    padding: [128 - @sizeOf(std.atomic.Value(usize))]u8 = undefined,
    pub fn claim(self: *TileCursor, size: usize, tile_rows: usize) ?Tile {
        const start = self.next.fetchAdd(tile_rows, .monotonic);
        if (start >= size) return null;
        return .{ .start = start, .end = @min(size, start + tile_rows) };
    }
};

const PreviousSource = packed_rows.PreviousSource;

const Job = struct {
    component: *const Component,
    evaluation: *const Evaluation,
    scratch: *Scratch,
    simd: bool,
    native: []M,
    part: usize,
    output: Column,
    previous_main: []const PreviousSource,
    previous_interaction: []const PreviousSource,
    inverse: M,
    counter: ?*TileCursor = null,
    tile_rows: usize = TILE_ROWS,
    start: usize,
    end: usize,
    fn run(self: *Job) void {
        if (self.simd) {
            self.scratch.simd.initialize();
            var first = true;
            while (self.nextTile(&first)) |tile| packed_rows.evaluate(self.component, self.evaluation, &self.scratch.simd, self.part, tile.start, tile.end, self.previous_main, self.previous_interaction, &self.output, self.inverse);
            return;
        }
        const scratch = &self.scratch.scalar;
        const component = self.component;
        const evaluation = self.evaluation;
        const values = evaluation.current_values;
        const main = scratch.main[0..component.mainCount()];
        const prior_main = scratch.prior_main[0..component.mainCount()];
        const current = scratch.current[0..component.interactionCount()];
        const prior = scratch.prior[0..component.interactionCount()];
        // Every unshifted prior lane is permanently zero for this worker wave.
        @memset(prior_main[component.plan.main_count..], Q.zero());
        @memset(prior, Q.zero());
        @memset(&scratch.logical, Q.zero());
        const main_sources = values[frame.FIXED..][0..component.mainCount()];
        const interaction_sources = values[frame.FIXED + component.mainCount() ..];
        var first_static = true;
        while (true) {
            const tile = self.nextTile(&first_static) orelse break;
            var start = tile.start;
            while (start < tile.end) {
                const count = if (self.native.len == 0) 1 else @min(NATIVE_TILE_ROWS, tile.end - start);
                const stride = frame.FIXED + main.len + current.len + self.previous_main.len + self.previous_interaction.len;
                if (self.native.len != 0) self.gather(start, count, stride);
                for (0..count) |offset| {
                    const row = start + offset;
                    var fixed: frame.Geometry = undefined;
                    if (self.native.len == 0) {
                        // Qualification oracle: original direct row gathers.
                        const prior_row = evaluation.previousRow(self.part, row);
                        for (&fixed, values[0..frame.FIXED]) |*value, source| value.* = Q.fromBase(source[row]);
                        for (main, main_sources) |*value, source| value.* = Q.fromBase(source[row]);
                        for (self.previous_main) |source| prior_main[source.destination] = Q.fromBase(source.values[prior_row]);
                        for (current, interaction_sources) |*value, source| value.* = Q.fromBase(source[row]);
                        for (self.previous_interaction) |source| prior[source.destination] = Q.fromBase(source.values[prior_row]);
                    } else {
                        const native_row = self.native[offset * stride ..][0..stride];
                        for (&fixed, native_row[0..frame.FIXED]) |*value, source| value.* = Q.fromBase(source);
                        for (main, native_row[frame.FIXED..][0..main.len]) |*value, source| value.* = Q.fromBase(source);
                        for (current, native_row[frame.FIXED + main.len ..][0..current.len]) |*value, source| value.* = Q.fromBase(source);
                        const shifted = native_row[frame.FIXED + main.len + current.len ..];
                        for (self.previous_main, shifted[0..self.previous_main.len]) |source, value| prior_main[source.destination] = Q.fromBase(value);
                        for (self.previous_interaction, shifted[self.previous_main.len..]) |source, value| prior[source.destination] = Q.fromBase(value);
                    }
                    // Promotion changes storage only; domain and OODS retain
                    // the single logical substitution and emission authority.
                    var accumulator = E.WeightedAccumulator{ .powers = self.output.random_coeff_powers };
                    var sink = E.Sink{ .values = null, .weighted_accumulator = &accumulator };
                    const inflated = component.inflation.applyPrepared(main[0..component.plan.main_count], &scratch.logical);
                    component.emitInflated(fixed, main, prior_main, current, prior, inflated, &sink);
                    std.debug.assert(sink.count == component.constraint_count);
                    self.output.accumulate(evaluation.globalRow(self.part, row), accumulator.accumulation.mulM31(self.inverse));
                }
                start += count;
            }
        }
    }
    fn nextTile(self: *Job, first: *bool) ?Tile {
        if (self.counter) |cursor| return cursor.claim(self.evaluation.size, self.tile_rows);
        if (!first.*) return null;
        first.* = false;
        return .{ .start = self.start, .end = self.end };
    }
    fn gather(self: *Job, start: usize, count: usize, stride: usize) void {
        var previous_rows: [NATIVE_TILE_ROWS]usize = undefined;
        for (previous_rows[0..count], 0..) |*row, i| row.* = self.evaluation.previousRow(self.part, start + i);
        // The expensive wide sources are read column-first in contiguous
        // cache-line pieces. Only compact required previous masks are gathered.
        const current_count = frame.FIXED + self.component.mainCount() + self.component.interactionCount();
        for (self.evaluation.current_values, 0..) |source, column| {
            for (source[start..][0..count], 0..) |value, i| self.native[i * stride + column] = value;
        }
        for (self.previous_main, 0..) |source, column| {
            for (previous_rows[0..count], 0..) |row, i| self.native[i * stride + current_count + column] = source.values[row];
        }
        for (self.previous_interaction, 0..) |source, column| {
            for (previous_rows[0..count], 0..) |row, i| self.native[i * stride + current_count + self.previous_main.len + column] = source.values[row];
        }
    }
};

const Scratch = union { scalar: ScalarScratch, simd: packed_rows.Scratch };
const ScalarScratch = struct {
    logical: E.Main,
    main: [L.MAIN + frame.WIDTH]Q,
    prior_main: [L.MAIN + frame.WIDTH]Q,
    current: [component_mod.MAX_INTERACTION]Q,
    prior: [component_mod.MAX_INTERACTION]Q,
};

fn validate(component: *const Component, evaluation: *const Evaluation, part: usize, output: *const Column) !void {
    const total = frame.FIXED + component.mainCount() + component.interactionCount();
    if (part >= 4 or component.log_size != evaluation.trace_log or evaluation.current_values.len != total or evaluation.previous_values.len != total or evaluation.previous_columns.len != total or output.col.len() != 4 * evaluation.size or output.random_coeff_powers.len != component.constraint_count) return error.InvalidRv64ParallelShape;
    for (evaluation.current_values, evaluation.previous_values, evaluation.previous_columns, 0..) |current, previous, actual, i| {
        const expected = if (i < frame.FIXED) false else if (i < frame.FIXED + component.mainCount()) component.needsPreviousMain(i - frame.FIXED) else component.needsPreviousInteraction(i - frame.FIXED - component.mainCount());
        if (current.len != evaluation.size or actual != expected or (expected and previous.len != evaluation.size)) return error.InvalidRv64ParallelShape;
    }
}

/// Functional tests exercise the exact scheduler with small tiles, avoiding
/// large full-domain fixtures while a production proof is using the host.
pub const testing = if (@import("builtin").is_test) struct {
    threadlocal var native_gather: bool = true;
    threadlocal var simd: bool = true;
    pub const GatherBinding = struct {
        previous: bool,
        previous_packed: bool,
        pub fn init(enabled: bool) GatherBinding {
            const previous = native_gather;
            const previous_packed = simd;
            native_gather = enabled;
            if (!enabled) simd = false;
            return .{ .previous = previous, .previous_packed = previous_packed };
        }
        pub fn deinit(self: *GatherBinding) void {
            native_gather = self.previous;
            simd = self.previous_packed;
        }
    };
    threadlocal var tile_rows_override: ?usize = null;
    threadlocal var dynamic_waves: usize = 0;
    pub fn dynamicWaveCount() usize {
        return dynamic_waves;
    }
    pub const TileRowsBinding = struct {
        previous: ?usize,
        pub fn init(tile_rows: usize) !TileRowsBinding {
            if (tile_rows == 0 or tile_rows > TILE_ROWS) return error.InvalidRv64TileRows;
            const prior = tile_rows_override;
            tile_rows_override = tile_rows;
            return .{ .previous = prior };
        }
        pub fn deinit(self: *TileRowsBinding) void {
            tile_rows_override = self.previous;
        }
    };
    pub fn evaluatePartWithTiles(component: *const Component, evaluation: *const Evaluation, part: usize, output: *Column, inverse: M, pool: ?*work.WorkPool, tile_rows: usize, fail_after_helpers: ?usize) !void {
        if (tile_rows == 0 or tile_rows > TILE_ROWS) return error.InvalidRv64TileRows;
        return evaluatePartImpl(component, evaluation, part, output, inverse, pool, tile_rows, fail_after_helpers, true, true);
    }
    pub fn evaluatePartUntiled(component: *const Component, evaluation: *const Evaluation, part: usize, output: *Column, inverse: M) !void {
        return evaluatePartImpl(component, evaluation, part, output, inverse, null, TILE_ROWS, null, false, false);
    }
    pub const Cursor = TileCursor;
    pub const Range = Tile;
} else struct {};
