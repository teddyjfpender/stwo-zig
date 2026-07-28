//! The eval arena: planning and the lift, for device composition.
//!
//! Increment 3.7 §3 established the fact that shapes this file. The compiled
//! kernels read a trace value as
//!
//! ```
//! uint target = offset == 0 ? row : offset_circle(...);
//! uint global = arena[args.interaction_offsets + interaction] + column;
//! return arena[arena[args.trace_offsets + global] + target];
//! ```
//!
//! with `row` running over the **evaluation** domain, so an arena column must be
//! `2^eval_log` words long. The product publishes columns at `2^trace_log`
//! (`pcs/scheme_views.polynomials`), which is why the host evaluator is handed
//! `shift_amt = evaluation_log_size - column.log_size + 1`. **The eval arena is
//! therefore not placement — it is placement plus a lift**, and the lift is the
//! staging pass: writing the lifted copy into the arena is the same bytes as
//! `src/tests/metal/composition_lift_bridge_test.zig` verified byte-exact on a
//! 1-part and a 5-part component of the authenticated bundle.
//!
//! The lifting map is `component_prover.Poly.at`'s own: evaluation position `p`
//! reads trace index `((p >> s) << 1) + (p & 1)` with `s` the column's shift.
//! That is each adjacent pair emitted `2^(s-1)` times — a streaming 8-byte
//! granule duplication, not a gather, which is why it runs at 89.84 GB/s
//! single-threaded ReleaseFast and parallelises per column with no sharing.
//!
//! ## Layout
//!
//! One contiguous word range per component, in the order the eleven `EvalLayout`
//! offsets are consumed:
//!
//! | block | words |
//! | --- | --- |
//! | lifted columns | `columns * 2^eval_log` |
//! | `trace_offsets` | `columns` |
//! | `interaction_offsets` | `interactions` |
//! | `ext_params` | `4 * ext_params` |
//! | `random_coeffs` | `4 * coefficients` |
//! | `denom_inv` | `2^(eval_log - trace_log)` |
//! | four coordinate planes | `4 * 2^eval_log` |
//!
//! Every accepted component reuses the *same* buffer, sized to the largest
//! plan, so the stage costs one resident allocation per proof rather than one
//! per component.

const std = @import("std");
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const WorkPool = @import("stwo_prover_engine").work_pool.WorkPool;

pub const Error = error{
    InvalidCompositionComponent,
    EvalArenaTooLarge,
    EvalArenaColumnShape,
};

/// The default ceiling on one proof's eval arena, in bytes. The arena is the
/// peak *single component* requirement, not the sum, so this is generous: the
/// whole-portfolio lift volume increment 3.7 priced is 0.76-4.80 GB spread
/// across 29-46 components. A plan above the cap is refused before anything is
/// allocated, which is a planning refusal and therefore a whole-stage decline.
pub const default_byte_cap: usize = 8 * 1024 * 1024 * 1024;
pub const byte_cap_env = "STWO_ZIG_COMPOSITION_EVAL_ARENA_BYTES";

/// One component's resolved geometry and its offsets inside the shared arena.
pub const Plan = struct {
    columns: u32,
    interactions: u32,
    eval_rows: u32,
    trace_log_size: u32,
    denominator_count: u32,
    ext_param_count: u32,
    coefficient_count: u32,
    column_base: u32,
    trace_offsets: u32,
    interaction_offsets: u32,
    ext_params: u32,
    random_coeffs: u32,
    denom_inv: u32,
    coordinates: [4]u32,
    /// Total words the plan occupies, which is what the shared arena is sized by.
    words: u64,
    /// `interaction_offsets` content: the flat base of each interaction's
    /// columns. Owned by the caller's allocator.
    bases: []u32,

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.bases);
        self.* = undefined;
    }

    pub fn columnOffset(self: Plan, global: u32) u32 {
        return self.column_base + global * self.eval_rows;
    }
};

/// Counts columns per interaction the way the emitted preamble indexes them:
/// `trace_col` and `preprocessed_col` share one flat table addressed by
/// `bases[interaction] + column`, so both contribute to the same census.
fn columnCounts(
    allocator: std.mem.Allocator,
    component: composition.Component,
) ![]u32 {
    var interactions: u32 = 0;
    for (component.parts) |part|
        interactions = @max(interactions, part.program.header.n_interactions);
    if (interactions == 0) return Error.InvalidCompositionComponent;
    const counts = try allocator.alloc(u32, interactions);
    errdefer allocator.free(counts);
    @memset(counts, 0);
    for (component.parts) |part| {
        for (part.program.base_insts) |instruction| switch (instruction.op) {
            .trace_col, .preprocessed_col => {
                if (instruction.interaction >= counts.len)
                    return Error.InvalidCompositionComponent;
                counts[instruction.interaction] =
                    @max(counts[instruction.interaction], instruction.a + 1);
            },
            else => {},
        };
    }
    return counts;
}

/// True when this arena contract can express the component at all. Mirrors the
/// eligibility the 3.5 smoke and the 3.7 bridge both used, so a component that
/// is accepted here is one of the shapes those tests verified byte-exact.
pub fn expressible(component: composition.Component) bool {
    if (component.parts.len == 0) return false;
    if (component.evaluation_log_size <= component.trace_log_size) return false;
    if (component.evaluation_log_size < 3) return false;
    if (component.n_constraints == 0) return false;
    for (component.parts) |part| {
        if (part.program.header.n_base_params != 0) return false;
        if (part.program.header.domain_log_size != component.trace_log_size) return false;
        if (part.program.header.n_interactions == 0) return false;
    }
    return true;
}

pub fn plan(allocator: std.mem.Allocator, component: composition.Component) !Plan {
    if (!expressible(component)) return Error.InvalidCompositionComponent;
    const eval_log = component.evaluation_log_size;
    const trace_log = component.trace_log_size;
    if (eval_log >= 31) return Error.InvalidCompositionComponent;
    const eval_rows: u32 = @as(u32, 1) << @intCast(eval_log);
    const denominator_count: u32 = @as(u32, 1) << @intCast(eval_log - trace_log);
    if (component.denominator_inverses.len != denominator_count)
        return Error.InvalidCompositionComponent;

    const counts = try columnCounts(allocator, component);
    defer allocator.free(counts);
    const bases = try allocator.alloc(u32, counts.len);
    errdefer allocator.free(bases);
    var columns: u32 = 0;
    for (counts, bases) |count, *base| {
        base.* = columns;
        columns = std.math.add(u32, columns, count) catch
            return Error.InvalidCompositionComponent;
    }
    if (columns == 0) return Error.InvalidCompositionComponent;

    var ext_param_count: u32 = 0;
    var coefficient_count: u32 = 0;
    for (component.parts) |part| {
        ext_param_count = @max(ext_param_count, part.program.header.n_ext_params);
        coefficient_count = @max(
            coefficient_count,
            part.rc_base + part.program.header.n_constraints,
        );
    }
    if (coefficient_count > component.n_constraints)
        return Error.InvalidCompositionComponent;
    coefficient_count = component.n_constraints;

    var next: u64 = 0;
    const column_base = next;
    next += @as(u64, columns) * eval_rows;
    const trace_offsets = next;
    next += columns;
    const interaction_offsets = next;
    next += bases.len;
    const ext_params = next;
    next += 4 * @as(u64, ext_param_count);
    const random_coeffs = next;
    next += 4 * @as(u64, coefficient_count);
    const denom_inv = next;
    next += denominator_count;
    var coordinates: [4]u64 = undefined;
    for (&coordinates) |*offset| {
        offset.* = next;
        next += eval_rows;
    }
    // Every offset is a `u32` word index in the ABI, so a plan that cannot be
    // addressed is a planning refusal rather than a truncation.
    if (next > std.math.maxInt(u32)) return Error.EvalArenaTooLarge;

    return .{
        .columns = columns,
        .interactions = @intCast(bases.len),
        .eval_rows = eval_rows,
        .trace_log_size = trace_log,
        .denominator_count = denominator_count,
        .ext_param_count = ext_param_count,
        .coefficient_count = coefficient_count,
        .column_base = @intCast(column_base),
        .trace_offsets = @intCast(trace_offsets),
        .interaction_offsets = @intCast(interaction_offsets),
        .ext_params = @intCast(ext_params),
        .random_coeffs = @intCast(random_coeffs),
        .denom_inv = @intCast(denom_inv),
        .coordinates = .{
            @intCast(coordinates[0]),
            @intCast(coordinates[1]),
            @intCast(coordinates[2]),
            @intCast(coordinates[3]),
        },
        .words = next,
        .bases = bases,
    };
}

/// The product's lifting map, read out of `component_prover.Poly.at`.
pub fn liftedIndex(position: usize, shift_amt: std.math.Log2Int(usize)) usize {
    return ((position >> shift_amt) << 1) + (position & 1);
}

/// Materialises one evaluation-domain column from one trace-domain column.
///
/// Written as the pair duplication it is rather than as a per-position gather,
/// which is what makes it stream. Identical to the routine the 3.7 lift bridge
/// verified byte-exact against `simd_evaluator` at the product's own shift.
pub fn liftColumn(
    destination: []u32,
    source: []const u32,
    shift_amt: std.math.Log2Int(usize),
) !void {
    if (shift_amt == 0) return Error.EvalArenaColumnShape;
    const stride: usize = @as(usize, 1) << shift_amt;
    if (source.len == 0 or source.len % 2 != 0) return Error.EvalArenaColumnShape;
    if (destination.len != source.len * (stride / 2)) return Error.EvalArenaColumnShape;
    var position: usize = 0;
    while (position < destination.len) : (position += stride) {
        const pair = liftedIndex(position, shift_amt);
        const low = source[pair];
        const high = source[pair + 1];
        var replica: usize = 0;
        while (replica < stride) : (replica += 2) {
            destination[position + replica] = low;
            destination[position + replica + 1] = high;
        }
    }
}

/// One resolved read site, reduced to what the lift needs. `values` is the
/// product's own trace-domain column reinterpreted as words, and `shift_amt` is
/// the shift `proving/air/component.zig:355` hands the host evaluator — so the
/// device and the host lift from byte-identical inputs by construction. An
/// empty `values` marks a census slot no instruction ever reads; the lift zeroes
/// it rather than leaving whatever the previous component wrote there.
pub const ResolvedScratch = struct {
    values: []const u32 = &.{},
    shift_amt: std.math.Log2Int(usize) = 0,
};

const LiftWorker = struct {
    words: []u32,
    plan: *const Plan,
    resolved: []const ResolvedScratch,
    stride: usize,
    start: usize,
    err: ?anyerror = null,

    fn run(self: *LiftWorker) void {
        var column = self.start;
        while (column < self.resolved.len) : (column += self.stride) {
            const rows: usize = self.plan.eval_rows;
            const offset = self.plan.columnOffset(@intCast(column));
            const destination = self.words[offset..][0..rows];
            const source = self.resolved[column];
            if (source.values.len == 0) {
                @memset(destination, 0);
                continue;
            }
            liftColumn(destination, source.values, source.shift_amt) catch |err| {
                self.err = err;
                return;
            };
        }
    }
};

/// Stages one component's columns into the arena at their planned offsets.
///
/// This is the whole upload: there is no separate copy step, because the lifted
/// copy *is* the staged copy. Parallel per column over the prover's existing
/// pool — the columns share nothing, so the only serialization is the wait.
pub fn lift(
    words: []u32,
    component_plan: Plan,
    resolved: []const ResolvedScratch,
    pool: ?*WorkPool,
) !void {
    if (resolved.len != component_plan.columns) return Error.EvalArenaColumnShape;
    const ready = pool orelse {
        var worker = LiftWorker{
            .words = words,
            .plan = &component_plan,
            .resolved = resolved,
            .stride = 1,
            .start = 0,
        };
        worker.run();
        if (worker.err) |err| return err;
        return;
    };
    const worker_count = @max(1, @min(ready.workerCount(), resolved.len));
    if (worker_count == 1) {
        var worker = LiftWorker{
            .words = words,
            .plan = &component_plan,
            .resolved = resolved,
            .stride = 1,
            .start = 0,
        };
        worker.run();
        if (worker.err) |err| return err;
        return;
    }
    var buffer: [64]LiftWorker = undefined;
    const workers = buffer[0..@min(worker_count, buffer.len)];
    for (workers, 0..) |*worker, index| {
        worker.* = .{
            .words = words,
            .plan = &component_plan,
            .resolved = resolved,
            .stride = workers.len,
            .start = index,
        };
    }
    var wait_group = std.Thread.WaitGroup{};
    for (workers[1..]) |*worker| ready.spawnWg(&wait_group, LiftWorker.run, .{worker});
    LiftWorker.run(&workers[0]);
    wait_group.wait();
    for (workers) |worker| if (worker.err) |err| return err;
}

test "the lifting map matches the product's own column reader" {
    try std.testing.expectEqual(@as(usize, 0), liftedIndex(0, 2));
    try std.testing.expectEqual(@as(usize, 1), liftedIndex(1, 2));
    try std.testing.expectEqual(@as(usize, 0), liftedIndex(2, 2));
    try std.testing.expectEqual(@as(usize, 1), liftedIndex(3, 2));
    try std.testing.expectEqual(@as(usize, 2), liftedIndex(4, 2));
    try std.testing.expectEqual(@as(usize, 3), liftedIndex(5, 2));
    for (0..16) |position|
        try std.testing.expectEqual(position, liftedIndex(position, 1));
}

test "a lifted column reproduces the map at both shifts the bundle produces" {
    var source = [_]u32{ 10, 11, 12, 13, 14, 15, 16, 17 };
    var wide: [16]u32 = undefined;
    try liftColumn(&wide, &source, 2);
    for (0..wide.len) |position|
        try std.testing.expectEqual(source[liftedIndex(position, 2)], wide[position]);

    var identity: [8]u32 = undefined;
    try liftColumn(&identity, &source, 1);
    try std.testing.expectEqualSlices(u32, &source, &identity);
}

test "a mismatched destination is refused rather than asserted" {
    var source = [_]u32{ 1, 2, 3, 4 };
    var destination: [7]u32 = undefined;
    try std.testing.expectError(
        Error.EvalArenaColumnShape,
        liftColumn(&destination, &source, 2),
    );
    try std.testing.expectError(
        Error.EvalArenaColumnShape,
        liftColumn(destination[0..4], &source, 0),
    );
}

test "the arena byte cap is read from the process and defaults closed" {
    // The default is a ceiling, not a target: it exists so that a pathological
    // claim refuses before a multi-gigabyte allocation is attempted.
    try std.testing.expect(default_byte_cap > 0);
    try std.testing.expectEqualStrings(
        "STWO_ZIG_COMPOSITION_EVAL_ARENA_BYTES",
        byte_cap_env,
    );
}
