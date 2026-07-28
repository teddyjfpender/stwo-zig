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
//! `2^eval_log` words long. The host evaluator is handed
//! `shift_amt = evaluation_log_size - column.log_size + 1` for the same reason,
//! and the lifting map is `component_prover.Poly.at`'s own: evaluation position
//! `p` reads index `((p >> s) << 1) + (p & 1)`. Writing that map's image into the
//! arena is the staging pass, and it is the same bytes
//! `src/tests/metal/composition_lift_bridge_test.zig` verified byte-exact on a
//! 1-part and a 5-part component of the authenticated bundle.
//!
//! **Increment 3.15 measured `s` on the product path and it is 1 on every column
//! of every portfolio workload**, so that map is the identity and the staging
//! pass is a copy, not a duplication. Increment 3.7 §3 stated — and this comment
//! used to repeat — that "the product publishes columns at `2^trace_log`". It
//! does not: `pcs/scheme_views.polynomials` hands back the committed tree
//! columns, and `pcs/tree_builders.zig:169` stores the **extended** values in
//! them. The host's `shift_amt` machinery is correct and general, and on this
//! product it is exercised only at its identity. The consequence for Option B is
//! recorded under `Mode` below, and it is the whole finding of 3.15.
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
//!
//! ## The stored-domain mode (increment 3.15, Option B)
//!
//! `Mode.stored` is the same arena with the lift deleted. Library 2's kernels
//! (`stwo_zig_eval_sd_<hash>`) apply `((row >> shift) << 1) + (row & 1)`
//! themselves, reading the column at the length the product already published
//! it at, so staging becomes a `@memcpy` of exactly the committed words instead
//! of a `2^eval_log`-word duplication. Two things change in the layout and
//! nothing else does.
//!
//! 1. **A shift table.** One word per *global* column, holding the column's own
//!    `ResolvedColumn.shift_amt`, placed at `args.base_params + n_base_params`
//!    per `eval_abi.TraceAbi.shiftTableOffset`. `expressible` already refuses any
//!    component with `n_base_params != 0`, so the table starts exactly at
//!    `base_params` for every component this arena can plan — but the *offset*
//!    is computed from the contract rather than assumed, so a future
//!    parameterized program needs no change here.
//! 2. **Columns are packed, not strided.** A column's required extent is exactly
//!    its own length: with `shift = eval_log - column_log + 1`, the largest index
//!    the reader can form is `((eval_rows - 1) >> shift) << 1 | 1`, i.e.
//!    `2^column_log - 1`. Column lengths are therefore *not* uniform in general
//!    (a preprocessed column may be committed at a different log size than the
//!    component's trace), and they are not known until `resolve` runs — so the
//!    plan reserves the only capacity that is always sufficient,
//!    `columns * 2^eval_log`, and `store` packs the actual columns consecutively
//!    into it, publishing the real offsets through `trace_offsets`. That block is
//!    written per evaluation in both modes, so runtime placement costs nothing
//!    and removes the one shape a fixed stride could not express.
//!
//! Reserving the eval-domain capacity means the *allocation* does not shrink.
//! The **resident** footprint shrinks by whatever the packing leaves untouched,
//! because the column region is placed last in stored mode and the pages past
//! the packed prefix are never faulted in.
//!
//! **On this product that saving is zero, measured.** Every observed shift is 1,
//! so the packed prefix is the whole capacity and the stored arena holds exactly
//! the words the lifted one held. The mode is correct, byte-exact and general —
//! a column committed at a shorter log size *would* be packed short and *would*
//! be read correctly by Library 2 — but the portfolio does not contain one, and
//! the honest statement of what Option B buys here is "one indirection through a
//! shift table, in exchange for the same bytes". See the `Volume` diagnostic.

const std = @import("std");
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const eval_program = @import("stwo_cairo_frontend").witness.eval_program;
const WorkPool = @import("stwo_prover_impl").work_pool.WorkPool;
const eval_abi = @import("eval_abi.zig");

/// Which trace ABI the planned arena feeds. `lifted` is increment 3.8's
/// Option-A layout, byte-for-byte unchanged; `stored` is Option B.
pub const Mode = enum {
    lifted,
    stored,

    pub fn abi(self: Mode) eval_abi.TraceAbi {
        return switch (self) {
            .lifted => .eval_domain,
            .stored => .stored_domain,
        };
    }
};

/// Words reserved for a census slot no instruction ever reads. The reader can
/// still *form* an index into it if a kernel were ever emitted that touched it,
/// so the slot is given a real pair and a shift that pins the index to `{0,1}`
/// rather than an offset that would address outside the region.
const null_column_words: u32 = 2;

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
    mode: Mode,
    columns: u32,
    interactions: u32,
    eval_rows: u32,
    eval_log_size: u32,
    trace_log_size: u32,
    denominator_count: u32,
    ext_param_count: u32,
    coefficient_count: u32,
    column_base: u32,
    /// Words reserved for the whole column region. In `lifted` mode this is
    /// exactly `columns * eval_rows` and every column occupies a fixed stride;
    /// in `stored` mode it is the same bound used as a capacity, and the columns
    /// packed inside it are shorter.
    column_capacity: u64,
    /// Offset of the runtime base-parameter block. Zero in `lifted` mode, where
    /// no program in this bundle declares a base parameter and nothing reads it;
    /// in `stored` mode it is the block whose tail is the per-column shift table.
    base_params: u32,
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

    /// The fixed stride placement, valid in `lifted` mode only. Stored-domain
    /// offsets are packed at staging time and published through `trace_offsets`.
    pub fn columnOffset(self: Plan, global: u32) u32 {
        return self.column_base + global * self.eval_rows;
    }

    /// Where this plan's shift table begins, given a part's own parameter count.
    /// Routed through the ABI contract rather than open-coded so the two sides
    /// of the layout cannot drift.
    pub fn shiftTable(self: Plan, program: eval_program.Program) u32 {
        return self.mode.abi().shiftTableOffset(self.base_params, program);
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

/// The Option-A planner. Retained as the name every existing caller and test
/// uses, and byte-for-byte the layout increment 3.8 shipped.
pub fn plan(allocator: std.mem.Allocator, component: composition.Component) !Plan {
    return planFor(allocator, component, .lifted);
}

pub fn planFor(
    allocator: std.mem.Allocator,
    component: composition.Component,
    mode: Mode,
) !Plan {
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

    // `columns * eval_rows` is the column region in both modes: a fixed stride
    // in `lifted`, a sufficient capacity in `stored` (a column's extent is its
    // own length, and no legal column exceeds `eval_rows`).
    const column_capacity: u64 = @as(u64, columns) * eval_rows;

    var next: u64 = 0;
    // In `stored` mode the column region goes *last*, so every block the stage
    // writes on every evaluation sits in the low pages and the untouched tail of
    // the capacity is never faulted in. In `lifted` mode it stays first, because
    // that layout is what increment 3.8 measured and 3.13 gated.
    var column_base: u64 = 0;
    if (mode == .lifted) {
        column_base = next;
        next += column_capacity;
    }
    const trace_offsets = next;
    next += columns;
    const interaction_offsets = next;
    next += bases.len;
    // The base-parameter block. Empty in `lifted` mode — no eligible program
    // declares a base parameter and no eval-domain kernel reads the block — and
    // in `stored` mode it is `n_base_params` (zero, enforced by `expressible`)
    // program words followed by one shift word per global column.
    const base_params = next;
    if (mode == .stored) next += columns;
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
    if (mode == .stored) {
        column_base = next;
        next += column_capacity;
    }
    // Every offset is a `u32` word index in the ABI, so a plan that cannot be
    // addressed is a planning refusal rather than a truncation.
    if (next > std.math.maxInt(u32)) return Error.EvalArenaTooLarge;

    return .{
        .mode = mode,
        .columns = columns,
        .interactions = @intCast(bases.len),
        .eval_rows = eval_rows,
        .eval_log_size = eval_log,
        .trace_log_size = trace_log,
        .denominator_count = denominator_count,
        .ext_param_count = ext_param_count,
        .coefficient_count = coefficient_count,
        .column_base = @intCast(column_base),
        .column_capacity = column_capacity,
        .base_params = @intCast(base_params),
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

const StoreWorker = struct {
    words: []u32,
    plan: *const Plan,
    resolved: []const ResolvedScratch,
    stride: usize,
    start: usize,

    fn run(self: *StoreWorker) void {
        var column = self.start;
        while (column < self.resolved.len) : (column += self.stride) {
            // The offset was published into `trace_offsets` by the serial pass,
            // so the workers share nothing and need no offsets array of their
            // own — they read the same block the kernel will read.
            const offset: usize = self.words[self.plan.trace_offsets + column];
            const source = self.resolved[column].values;
            if (source.len == 0) {
                @memset(self.words[offset..][0..null_column_words], 0);
                continue;
            }
            @memcpy(self.words[offset..][0..source.len], source);
        }
    }
};

/// Stages one component's columns into the arena **without lifting them**, and
/// publishes the two blocks that placement produces: `trace_offsets` and the
/// per-column shift table.
///
/// Returns the words actually written, which is the honest staging volume — the
/// quantity Option A pays twice over.
///
/// The serial prefix pass is where correctness lives. For every column it checks
/// the ABI's own extent identity, `(eval_rows >> shift) << 1 == values.len`: that
/// is precisely the statement that the largest index Library 2's reader can form
/// lands inside the committed column, so a column that passes it cannot be read
/// out of bounds by any row of any part. A column that fails it is refused here,
/// before a single word is written, and the caller answers with the host
/// evaluation of that component.
/// What one component's staging actually moved, and at what shifts.
///
/// `lifted_bytes` is the volume the Option-A path would have written for the
/// same component. Reporting the two side by side is the only way to price the
/// ABI change honestly: the saving is a property of the *committed* column log
/// sizes, which no test that builds its own column store can observe.
pub const Volume = struct {
    stored_bytes: u64 = 0,
    lifted_bytes: u64 = 0,
    shift_min: u32 = std.math.maxInt(u32),
    shift_max: u32 = 0,

    pub fn fold(self: *Volume, other: Volume) void {
        self.stored_bytes += other.stored_bytes;
        self.lifted_bytes += other.lifted_bytes;
        self.shift_min = @min(self.shift_min, other.shift_min);
        self.shift_max = @max(self.shift_max, other.shift_max);
    }
};

pub fn store(
    words: []u32,
    component_plan: Plan,
    resolved: []const ResolvedScratch,
    pool: ?*WorkPool,
) !Volume {
    if (component_plan.mode != .stored) return Error.EvalArenaColumnShape;
    if (resolved.len != component_plan.columns) return Error.EvalArenaColumnShape;

    const limit = component_plan.column_base + component_plan.column_capacity;
    var cursor: u64 = component_plan.column_base;
    var volume = Volume{
        .lifted_bytes = @as(u64, component_plan.columns) *
            component_plan.eval_rows * @sizeOf(u32),
    };
    for (resolved, 0..) |source, index| {
        var shift: u32 = undefined;
        var needed: u64 = undefined;
        if (source.values.len == 0) {
            // Never read. Pin the reader's index to `{0, 1}` inside the pair
            // rather than leaving a shift that could address the whole arena.
            shift = component_plan.eval_log_size;
            needed = null_column_words;
        } else {
            if (source.shift_amt == 0) return Error.EvalArenaColumnShape;
            if (source.shift_amt > component_plan.eval_log_size)
                return Error.EvalArenaColumnShape;
            const extent = (@as(u64, component_plan.eval_rows) >> source.shift_amt) << 1;
            if (extent != source.values.len) return Error.EvalArenaColumnShape;
            shift = source.shift_amt;
            needed = source.values.len;
        }
        if (cursor + needed > limit) return Error.EvalArenaTooLarge;
        words[component_plan.trace_offsets + index] = @intCast(cursor);
        words[component_plan.base_params + index] = shift;
        cursor += needed;
        volume.stored_bytes += needed * @sizeOf(u32);
        if (source.values.len != 0) {
            volume.shift_min = @min(volume.shift_min, shift);
            volume.shift_max = @max(volume.shift_max, shift);
        }
    }

    const ready = pool orelse {
        var worker = StoreWorker{
            .words = words,
            .plan = &component_plan,
            .resolved = resolved,
            .stride = 1,
            .start = 0,
        };
        worker.run();
        return volume;
    };
    const worker_count = @max(1, @min(ready.workerCount(), resolved.len));
    if (worker_count == 1) {
        var worker = StoreWorker{
            .words = words,
            .plan = &component_plan,
            .resolved = resolved,
            .stride = 1,
            .start = 0,
        };
        worker.run();
        return volume;
    }
    var buffer: [64]StoreWorker = undefined;
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
    for (workers[1..]) |*worker| ready.spawnWg(&wait_group, StoreWorker.run, .{worker});
    StoreWorker.run(&workers[0]);
    wait_group.wait();
    return volume;
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

/// A hand-built two-column stored-domain plan. Building it directly rather than
/// through `planFor` keeps this test about `store`'s placement contract; the
/// planner's own layout is pinned by the layout test below it.
fn storedFixture(bases: []u32, eval_log: u32, columns: u32) Plan {
    const eval_rows = @as(u32, 1) << @intCast(eval_log);
    return .{
        .mode = .stored,
        .columns = columns,
        .interactions = @intCast(bases.len),
        .eval_rows = eval_rows,
        .eval_log_size = eval_log,
        .trace_log_size = eval_log - 1,
        .denominator_count = 2,
        .ext_param_count = 0,
        .coefficient_count = 1,
        .column_base = 64,
        .column_capacity = @as(u64, columns) * eval_rows,
        .base_params = 16,
        .trace_offsets = 0,
        .interaction_offsets = 8,
        .ext_params = 32,
        .random_coeffs = 36,
        .denom_inv = 40,
        .coordinates = .{ 42, 44, 46, 48 },
        .words = 64 + @as(u64, columns) * eval_rows,
        .bases = bases,
    };
}

test "stored staging packs columns and publishes their shifts" {
    var bases = [_]u32{0};
    const component_plan = storedFixture(&bases, 3, 2);
    var words = [_]u32{0} ** 80;
    // Both columns are committed at the trace log size, so both carry shift 2
    // and four words: `(8 >> 2) << 1 == 4`.
    const first = [_]u32{ 1, 2, 3, 4 };
    const second = [_]u32{ 5, 6, 7, 8 };
    const resolved = [_]ResolvedScratch{
        .{ .values = &first, .shift_amt = 2 },
        .{ .values = &second, .shift_amt = 2 },
    };
    const volume = try store(&words, component_plan, &resolved, null);
    try std.testing.expectEqual(@as(u64, 8 * @sizeOf(u32)), volume.stored_bytes);
    // Two four-word columns against a two-column eval-domain plan: the ABI
    // change is worth exactly the ratio of these two numbers on this fixture.
    try std.testing.expectEqual(@as(u64, 16 * @sizeOf(u32)), volume.lifted_bytes);
    try std.testing.expectEqual(@as(u32, 2), volume.shift_min);
    try std.testing.expectEqual(@as(u32, 2), volume.shift_max);
    // Packed consecutively from the region base, not strided by `eval_rows`.
    try std.testing.expectEqual(@as(u32, 64), words[component_plan.trace_offsets]);
    try std.testing.expectEqual(@as(u32, 68), words[component_plan.trace_offsets + 1]);
    try std.testing.expectEqual(@as(u32, 2), words[component_plan.base_params]);
    try std.testing.expectEqual(@as(u32, 2), words[component_plan.base_params + 1]);
    try std.testing.expectEqualSlices(u32, &first, words[64..68]);
    try std.testing.expectEqualSlices(u32, &second, words[68..72]);

    // The reader's own map, run over every evaluation row against the words the
    // staging just placed: this is the property the ABI rests on.
    for (0..component_plan.eval_rows) |row| {
        const index = ((row >> 2) << 1) + (row & 1);
        const offset = words[component_plan.trace_offsets];
        try std.testing.expectEqual(first[index], words[offset + index]);
    }
}

test "a column whose length contradicts its shift is refused before any write" {
    var bases = [_]u32{0};
    const component_plan = storedFixture(&bases, 3, 1);
    var words = [_]u32{0} ** 80;
    // Shift 2 at `eval_rows = 8` demands a four-word column; this one is eight.
    const wrong = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const resolved = [_]ResolvedScratch{.{ .values = &wrong, .shift_amt = 2 }};
    try std.testing.expectError(
        Error.EvalArenaColumnShape,
        store(&words, component_plan, &resolved, null),
    );
    try std.testing.expectEqual(@as(u32, 0), words[64]);
    // And the lifted planner's staging refuses to run against a stored plan.
    try std.testing.expectError(
        Error.EvalArenaColumnShape,
        store(&words, storedLiftedFixture(&bases), &resolved, null),
    );
}

fn storedLiftedFixture(bases: []u32) Plan {
    var lifted = storedFixture(bases, 3, 1);
    lifted.mode = .lifted;
    return lifted;
}

test "an unread census slot gets a real pair and an index-pinning shift" {
    var bases = [_]u32{0};
    const component_plan = storedFixture(&bases, 3, 2);
    var words = [_]u32{0} ** 80;
    const present = [_]u32{ 1, 2, 3, 4 };
    const resolved = [_]ResolvedScratch{
        .{},
        .{ .values = &present, .shift_amt = 2 },
    };
    const volume = try store(&words, component_plan, &resolved, null);
    try std.testing.expectEqual(@as(u64, 6 * @sizeOf(u32)), volume.stored_bytes);
    try std.testing.expectEqual(
        component_plan.eval_log_size,
        words[component_plan.base_params],
    );
    // Every row of the unread slot addresses inside its own pair.
    for (0..component_plan.eval_rows) |row| {
        const index = ((row >> component_plan.eval_log_size) << 1) + (row & 1);
        try std.testing.expect(index < null_column_words);
    }
    try std.testing.expectEqual(@as(u32, 66), words[component_plan.trace_offsets + 1]);
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
