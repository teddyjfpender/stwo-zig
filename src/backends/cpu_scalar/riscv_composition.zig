//! Bounded SIMD composition for frontend-authenticated RISC-V polynomial pairs.
//!
//! The frontend exports semantic and lookup polynomial DAGs from the same typed
//! builders used by its reference AIR. This module only accelerates adjacent
//! semantic/lookup components whose exported contracts and committed-column
//! shapes agree exactly. Everything else remains on the generic component
//! evaluator. Eligible components accumulate directly into one secure column
//! per evaluation log, avoiding one full-domain temporary per component.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const constraints = core.constraints;
const m31 = core.fields.m31;
const qm31 = core.fields.qm31;
const packed_qm31 = core.fields.packed_qm31;
const canonic = core.poly.circle.canonic;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedM31 = m31.PackedM31;
const PackedQM31 = packed_qm31.PackedQM31;
const Component = prover.air.component_prover.ComponentProver;
const BaseCapability = prover.air.component_prover.BasePolynomialCapabilityV1;
const LookupCapability = prover.air.component_prover.LookupPolynomialCapabilityV1;
const BaseProgram = prover.air.component_prover.OwnedBasePolynomialProgram;
const LookupProgram = prover.air.component_prover.OwnedLookupPolynomialProgram;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const SecureColumn = prover.secure_column.SecureColumnByCoords;

const TILE_ROWS: usize = 4096;
const MAX_MAIN_COLUMNS: usize = 128;
const MAX_PROGRAM_NODES: usize = 8192;
const MAX_LOOKUP_ENTRIES: usize = 64;

comptime {
    if (!std.math.isPowerOfTwo(m31.PACK_WIDTH) or TILE_ROWS % m31.PACK_WIDTH != 0) {
        @compileError("RISC-V composition tiles must contain whole SIMD packs");
    }
}

pub const TelemetrySnapshot = struct {
    attempts: u64 = 0,
    admissions: u64 = 0,
    declines: u64 = 0,
    eligible_pairs: u64 = 0,
    fallback_components: u64 = 0,
    distinct_buckets: u64 = 0,
    row_tiles: u64 = 0,
    max_scratch_bytes_per_worker: u64 = 0,

    pub fn delta(after: TelemetrySnapshot, before: TelemetrySnapshot) TelemetrySnapshot {
        return .{
            .attempts = after.attempts -| before.attempts,
            .admissions = after.admissions -| before.admissions,
            .declines = after.declines -| before.declines,
            .eligible_pairs = after.eligible_pairs -| before.eligible_pairs,
            .fallback_components = after.fallback_components -| before.fallback_components,
            .distinct_buckets = after.distinct_buckets -| before.distinct_buckets,
            .row_tiles = after.row_tiles -| before.row_tiles,
            .max_scratch_bytes_per_worker = after.max_scratch_bytes_per_worker,
        };
    }
};

const AtomicCounter = std.atomic.Value(u64);

const Telemetry = struct {
    attempts: AtomicCounter = .init(0),
    admissions: AtomicCounter = .init(0),
    declines: AtomicCounter = .init(0),
    eligible_pairs: AtomicCounter = .init(0),
    fallback_components: AtomicCounter = .init(0),
    distinct_buckets: AtomicCounter = .init(0),
    row_tiles: AtomicCounter = .init(0),
    max_scratch_bytes_per_worker: AtomicCounter = .init(0),
};

var telemetry: Telemetry = .{};

pub fn telemetrySnapshot() TelemetrySnapshot {
    return .{
        .attempts = telemetry.attempts.load(.monotonic),
        .admissions = telemetry.admissions.load(.monotonic),
        .declines = telemetry.declines.load(.monotonic),
        .eligible_pairs = telemetry.eligible_pairs.load(.monotonic),
        .fallback_components = telemetry.fallback_components.load(.monotonic),
        .distinct_buckets = telemetry.distinct_buckets.load(.monotonic),
        .row_tiles = telemetry.row_tiles.load(.monotonic),
        .max_scratch_bytes_per_worker = telemetry.max_scratch_bytes_per_worker.load(.monotonic),
    };
}

fn resetTelemetryForTesting() void {
    inline for (std.meta.fields(Telemetry)) |field| {
        @field(telemetry, field.name).store(0, .monotonic);
    }
}

fn recordMax(counter: *AtomicCounter, value: u64) void {
    var observed = counter.load(.monotonic);
    while (value > observed) {
        if (counter.cmpxchgWeak(observed, value, .monotonic, .monotonic)) |actual| {
            observed = actual;
            continue;
        }
        return;
    }
}

const BaseProgramEntry = struct {
    program_id: u64,
    exporter: *const fn (*const anyopaque, std.mem.Allocator) anyerror!BaseProgram,
    program: BaseProgram,
    reachable: []bool,

    fn deinit(self: *BaseProgramEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.reachable);
        self.program.deinit();
        self.* = undefined;
    }
};

const LookupProgramEntry = struct {
    program_id: u64,
    exporter: *const fn (*const anyopaque, std.mem.Allocator) anyerror!LookupProgram,
    program: LookupProgram,
    reachable: []bool,

    fn deinit(self: *LookupProgramEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.reachable);
        self.program.deinit();
        self.* = undefined;
    }
};

const PairJob = struct {
    base_program_index: usize,
    lookup_program_index: usize,
    eval_log_size: u32,
    row_count: usize,
    main_columns: []const Poly,
    semantic_selector: []const M31,
    lookup_selector: []const M31,
    interaction_columns: []const Poly,
    parameters: []QM31,
    semantic_power_start: usize = 0,
    lookup_power_start: usize = 0,

    fn deinit(self: *PairJob, allocator: std.mem.Allocator) void {
        allocator.free(self.parameters);
        self.* = undefined;
    }
};

const Bucket = struct {
    eval_log_size: u32,
    row_count: usize,
    pair_indices: []usize,
    output: ?SecureColumn,
    denominator_inverses: [2]PackedM31,

    fn deinit(self: *Bucket, allocator: std.mem.Allocator) void {
        allocator.free(self.pair_indices);
        if (self.output) |*output| output.deinit(allocator);
        self.* = undefined;
    }
};

const HostWorker = struct {
    component: Component,
    trace: *const Trace,
    accumulator: Accumulator,
    err: ?anyerror = null,

    fn run(self: *HostWorker) void {
        self.component.evaluateConstraintQuotientsOnDomain(
            self.trace,
            &self.accumulator,
        ) catch |err| {
            self.err = err;
        };
    }

    fn runParallel(self: *HostWorker, pool: *prover.work_pool.WorkPool) void {
        self.component.evaluateConstraintQuotientsOnDomainParallel(
            self.trace,
            &self.accumulator,
            pool,
        ) catch |err| {
            self.err = err;
        };
    }
};

const EvaluationContext = struct {
    allocator: std.mem.Allocator,
    pairs: []const PairJob,
    base_programs: []const BaseProgramEntry,
    lookup_programs: []const LookupProgramEntry,
    powers: []const PackedQM31,
    max_main_columns: usize,
    max_base_nodes: usize,
    max_lookup_nodes: usize,
    max_lookup_entries: usize,
};

const TileWorker = struct {
    context: *const EvaluationContext,
    bucket: *Bucket,
    row_start: usize,
    row_end: usize,
    err: ?anyerror = null,

    fn run(self: *TileWorker) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *TileWorker) !void {
        const context = self.context;
        const allocator = context.allocator;
        const main_values = try allocator.alloc(PackedM31, context.max_main_columns);
        defer allocator.free(main_values);
        const base_nodes = try allocator.alloc(PackedM31, context.max_base_nodes);
        defer allocator.free(base_nodes);
        const lookup_nodes = try allocator.alloc(PackedM31, context.max_lookup_nodes);
        defer allocator.free(lookup_nodes);
        const denominators = try allocator.alloc(PackedQM31, context.max_lookup_entries);
        defer allocator.free(denominators);

        const output = &self.bucket.output.?;
        const half = self.bucket.row_count / 2;
        var row = self.row_start;
        while (row < self.row_end) : (row += m31.PACK_WIDTH) {
            var previous_rows: [m31.PACK_WIDTH]usize = undefined;
            for (&previous_rows, 0..) |*previous, lane| {
                previous.* = core.utils.previousBitReversedCircleDomainIndex(
                    row + lane,
                    self.bucket.eval_log_size - 1,
                    self.bucket.eval_log_size,
                );
            }

            var accumulated = PackedQM31.zero();
            for (self.bucket.pair_indices) |pair_index| {
                const pair = &context.pairs[pair_index];
                for (pair.main_columns, main_values[0..pair.main_columns.len]) |column, *packed_value| {
                    packed_value.* = m31.loadPacked(column.values.ptr + row);
                }
                accumulated = accumulated.add(evaluatePair(
                    context,
                    pair,
                    row,
                    &previous_rows,
                    main_values,
                    base_nodes,
                    lookup_nodes,
                    denominators,
                ));
            }

            const denominator = self.bucket.denominator_inverses[@intFromBool(row >= half)];
            const coordinates = accumulated.mulBase(denominator).coordinates();
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                m31.storePacked(output.columns[coordinate].ptr + row, coordinates[coordinate]);
            }
        }
    }
};

/// Returns a complete composition evaluation when at least one exact adjacent
/// semantic/lookup pair is admitted. A null result leaves the generic prover in
/// full control. Unsupported components within an admitted proof are evaluated
/// by their unchanged reference vtables and merged afterward.
pub fn evaluate(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
) !?SecureColumn {
    if (!hasCandidatePair(components)) return null;
    _ = telemetry.attempts.fetchAdd(1, .monotonic);

    var base_programs = std.ArrayList(BaseProgramEntry).empty;
    defer {
        for (base_programs.items) |*entry| entry.deinit(allocator);
        base_programs.deinit(allocator);
    }
    var lookup_programs = std.ArrayList(LookupProgramEntry).empty;
    defer {
        for (lookup_programs.items) |*entry| entry.deinit(allocator);
        lookup_programs.deinit(allocator);
    }
    var pairs = std.ArrayList(PairJob).empty;
    defer {
        for (pairs.items) |*pair| pair.deinit(allocator);
        pairs.deinit(allocator);
    }

    const eligible = try allocator.alloc(bool, components.len);
    defer allocator.free(eligible);
    @memset(eligible, false);

    var component_index: usize = 0;
    while (component_index + 1 < components.len) {
        const pair = try resolvePair(
            allocator,
            components[component_index],
            components[component_index + 1],
            trace,
            &base_programs,
            &lookup_programs,
        );
        if (pair) |admitted_value| {
            var admitted = admitted_value;
            errdefer admitted.deinit(allocator);
            try pairs.append(allocator, admitted);
            eligible[component_index] = true;
            eligible[component_index + 1] = true;
            component_index += 2;
        } else {
            component_index += 1;
        }
    }

    if (pairs.items.len == 0) {
        _ = telemetry.declines.fetchAdd(1, .monotonic);
        return null;
    }

    var total_constraints: usize = 0;
    var max_log_size: u32 = 0;
    for (components) |component| {
        total_constraints = try std.math.add(
            usize,
            total_constraints,
            component.nConstraints(),
        );
        max_log_size = @max(max_log_size, component.maxConstraintLogDegreeBound());
    }
    if (max_log_size >= @bitSizeOf(usize)) {
        _ = telemetry.declines.fetchAdd(1, .monotonic);
        return null;
    }

    const powers = try prover.air.accumulation.generateSecurePowers(
        allocator,
        random_coeff,
        total_constraints,
    );
    defer allocator.free(powers);
    const packed_powers = try allocator.alloc(PackedQM31, powers.len);
    defer allocator.free(packed_powers);
    for (powers, packed_powers) |power, *packed_value| packed_value.* = PackedQM31.splat(power);

    const fallback_count = components.len - 2 * pairs.items.len;
    const host_workers = try allocator.alloc(HostWorker, fallback_count);
    defer allocator.free(host_workers);
    var initialized_host_workers: usize = 0;
    defer for (host_workers[0..initialized_host_workers]) |*worker| worker.accumulator.deinit();

    // `generateSecurePowers` stores [1, alpha, ...]. The generic accumulator
    // consumes components from the tail in declaration order, then each
    // component folds its constraints in reverse-root order. Assign the same
    // half-open slices here before any parallel work starts; eligible and host
    // components therefore cannot perturb one another's transcript powers.
    var power_cursor = total_constraints;
    var pair_cursor: usize = 0;
    var host_cursor: usize = 0;
    component_index = 0;
    while (component_index < components.len) {
        if (eligible[component_index]) {
            const semantic_count = components[component_index].nConstraints();
            if (semantic_count > power_cursor) return error.InvalidCompositionPowerOrder;
            power_cursor -= semantic_count;
            pairs.items[pair_cursor].semantic_power_start = power_cursor;

            const lookup_count = components[component_index + 1].nConstraints();
            if (lookup_count > power_cursor) return error.InvalidCompositionPowerOrder;
            power_cursor -= lookup_count;
            pairs.items[pair_cursor].lookup_power_start = power_cursor;
            pair_cursor += 1;
            component_index += 2;
            continue;
        }

        const constraint_count = components[component_index].nConstraints();
        if (constraint_count > power_cursor) return error.InvalidCompositionPowerOrder;
        host_workers[host_cursor] = .{
            .component = components[component_index],
            .trace = trace,
            .accumulator = try Accumulator.initForComponent(
                powers,
                allocator,
                max_log_size,
                power_cursor,
            ),
        };
        initialized_host_workers += 1;
        host_cursor += 1;
        power_cursor -= constraint_count;
        component_index += 1;
    }
    std.debug.assert(power_cursor == 0);
    std.debug.assert(pair_cursor == pairs.items.len);
    std.debug.assert(host_cursor == host_workers.len);

    var buckets = std.ArrayList(Bucket).empty;
    defer {
        for (buckets.items) |*bucket| bucket.deinit(allocator);
        buckets.deinit(allocator);
    }
    try buildBuckets(allocator, pairs.items, &buckets);

    var max_main_columns: usize = 0;
    var max_base_nodes: usize = 0;
    var max_lookup_nodes: usize = 0;
    var max_lookup_entries: usize = 0;
    for (pairs.items) |pair| {
        max_main_columns = @max(max_main_columns, pair.main_columns.len);
        max_base_nodes = @max(
            max_base_nodes,
            base_programs.items[pair.base_program_index].program.nodes.len,
        );
        max_lookup_nodes = @max(
            max_lookup_nodes,
            lookup_programs.items[pair.lookup_program_index].program.nodes.len,
        );
        max_lookup_entries = @max(
            max_lookup_entries,
            lookup_programs.items[pair.lookup_program_index].program.entries.len,
        );
    }
    const scratch_bytes = try scratchBytes(
        max_main_columns,
        max_base_nodes,
        max_lookup_nodes,
        max_lookup_entries,
    );

    var tile_count: usize = 0;
    for (buckets.items) |bucket| {
        tile_count = try std.math.add(
            usize,
            tile_count,
            std.math.divCeil(usize, bucket.row_count, TILE_ROWS) catch unreachable,
        );
    }
    const tile_workers = try allocator.alloc(TileWorker, tile_count);
    defer allocator.free(tile_workers);
    const context = EvaluationContext{
        .allocator = allocator,
        .pairs = pairs.items,
        .base_programs = base_programs.items,
        .lookup_programs = lookup_programs.items,
        .powers = packed_powers,
        .max_main_columns = max_main_columns,
        .max_base_nodes = max_base_nodes,
        .max_lookup_nodes = max_lookup_nodes,
        .max_lookup_entries = max_lookup_entries,
    };
    var tile_cursor: usize = 0;
    for (buckets.items) |*bucket| {
        var row_start: usize = 0;
        while (row_start < bucket.row_count) : (row_start += TILE_ROWS) {
            tile_workers[tile_cursor] = .{
                .context = &context,
                .bucket = bucket,
                .row_start = row_start,
                .row_end = @min(bucket.row_count, row_start + TILE_ROWS),
            };
            tile_cursor += 1;
        }
    }
    std.debug.assert(tile_cursor == tile_workers.len);

    _ = telemetry.admissions.fetchAdd(1, .monotonic);
    _ = telemetry.eligible_pairs.fetchAdd(@intCast(pairs.items.len), .monotonic);
    _ = telemetry.fallback_components.fetchAdd(@intCast(fallback_count), .monotonic);
    _ = telemetry.distinct_buckets.fetchAdd(@intCast(buckets.items.len), .monotonic);
    _ = telemetry.row_tiles.fetchAdd(@intCast(tile_workers.len), .monotonic);
    recordMax(&telemetry.max_scratch_bytes_per_worker, @intCast(scratch_bytes));

    if (prover.work_pool.getGlobalPool()) |pool| {
        var wait_group: std.Thread.WaitGroup = .{};
        if (dominantParallelHostWorker(host_workers)) |parallel_index| {
            for (host_workers, 0..) |*worker, index| {
                if (index == parallel_index) continue;
                pool.spawnWg(&wait_group, HostWorker.run, .{worker});
            }
            // Packed opcode tiles and the selected frontend evaluator write
            // independent accumulator buckets. Keep the caller on the
            // dominant domain while every packed tile drains as a pool leaf.
            for (tile_workers) |*worker| pool.spawnWg(&wait_group, TileWorker.run, .{worker});
            HostWorker.runParallel(&host_workers[parallel_index], pool);
        } else {
            for (host_workers) |*worker| pool.spawnWg(&wait_group, HostWorker.run, .{worker});
            for (tile_workers[1..]) |*worker| pool.spawnWg(&wait_group, TileWorker.run, .{worker});
            TileWorker.run(&tile_workers[0]);
        }
        wait_group.wait();
    } else {
        for (host_workers) |*worker| HostWorker.run(worker);
        for (tile_workers) |*worker| TileWorker.run(worker);
    }
    for (host_workers) |worker| if (worker.err) |err| return err;
    for (tile_workers) |worker| if (worker.err) |err| return err;

    var combined = try Accumulator.initForComponent(powers, allocator, max_log_size, 0);
    defer combined.deinit();
    for (host_workers) |*worker| combined.merge(&worker.accumulator);
    for (buckets.items) |*bucket| {
        const log_size = bucket.eval_log_size;
        if (combined.sub_accumulations[log_size]) |*host_bucket| {
            const accelerated = &bucket.output.?;
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                for (host_bucket.columns[coordinate], accelerated.columns[coordinate]) |*lhs, rhs| {
                    lhs.* = lhs.add(rhs);
                }
            }
        } else {
            combined.sub_accumulations[log_size] = bucket.output;
            bucket.output = null;
        }
    }
    return try combined.finalize();
}

fn dominantParallelHostWorker(workers: []const HostWorker) ?usize {
    var selected: ?usize = null;
    var selected_work: u128 = 0;
    for (workers, 0..) |worker, index| {
        if (worker.component.domain_parallel_evaluator == null) continue;
        const log_size = worker.component.maxConstraintLogDegreeBound();
        if (log_size >= @bitSizeOf(u128)) continue;
        const work = (@as(u128, 1) << @intCast(log_size)) *
            worker.component.nConstraints();
        if (selected == null or work > selected_work) {
            selected = index;
            selected_work = work;
        }
    }
    return selected;
}

fn hasCandidatePair(components: []const Component) bool {
    if (components.len < 2) return false;
    for (components[0 .. components.len - 1], components[1..]) |left, right| {
        if (baseCapability(left) != null and lookupCapability(right) != null) return true;
    }
    return false;
}

fn resolvePair(
    allocator: std.mem.Allocator,
    semantic_component: Component,
    lookup_component: Component,
    trace: *const Trace,
    base_programs: *std.ArrayList(BaseProgramEntry),
    lookup_programs: *std.ArrayList(LookupProgramEntry),
) !?PairJob {
    const base = baseCapability(semantic_component) orelse return null;
    const lookup = lookupCapability(lookup_component) orelse return null;
    const resolved = resolveTracePair(
        semantic_component,
        lookup_component,
        base,
        lookup,
        trace,
    ) orelse return null;

    const base_program_index = try findOrAddBaseProgram(
        allocator,
        base_programs,
        semantic_component,
        base,
    ) orelse return null;
    const lookup_program_index = try findOrAddLookupProgram(
        allocator,
        lookup_programs,
        lookup_component,
        lookup,
    ) orelse return null;
    const base_program = base_programs.items[base_program_index].program;
    const lookup_program = lookup_programs.items[lookup_program_index].program;
    if (base_program.column_count != base.main_column_count + 1 or
        base_program.roots.len != semantic_component.nConstraints() or
        lookup_program.column_count != lookup.main_column_count or
        lookup_program.batchCount() != lookup_component.nConstraints() or
        lookup.interaction_column_count != lookup_program.batchCount() *
            qm31.SECURE_EXTENSION_DEGREE)
    {
        return null;
    }

    const parameters = lookup.export_parameters(
        lookup_component.ctx,
        allocator,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    errdefer allocator.free(parameters);
    if (parameters.len != lookup_program.parameterCount()) {
        allocator.free(parameters);
        return null;
    }

    return .{
        .base_program_index = base_program_index,
        .lookup_program_index = lookup_program_index,
        .eval_log_size = resolved.eval_log_size,
        .row_count = resolved.row_count,
        .main_columns = resolved.main_columns,
        .semantic_selector = resolved.semantic_selector,
        .lookup_selector = resolved.lookup_selector,
        .interaction_columns = resolved.interaction_columns,
        .parameters = parameters,
    };
}

const ResolvedPair = struct {
    eval_log_size: u32,
    row_count: usize,
    main_columns: []const Poly,
    semantic_selector: []const M31,
    lookup_selector: []const M31,
    interaction_columns: []const Poly,
};

fn resolveTracePair(
    semantic_component: Component,
    lookup_component: Component,
    base: BaseCapability,
    lookup: LookupCapability,
    trace: *const Trace,
) ?ResolvedPair {
    if (base.trace_log_size != lookup.trace_log_size or
        base.selector_tree_index != lookup.selector_tree_index or
        base.main_tree_index != lookup.main_tree_index or
        base.first_main_column != lookup.first_main_column or
        base.main_column_count != lookup.main_column_count or
        base.main_column_count == 0 or base.main_column_count > MAX_MAIN_COLUMNS or
        lookup.interaction_column_count == 0)
    {
        return null;
    }
    const eval_log_size = semantic_component.maxConstraintLogDegreeBound();
    if (eval_log_size != lookup_component.maxConstraintLogDegreeBound() or
        eval_log_size == 0 or eval_log_size >= @bitSizeOf(usize) or
        base.trace_log_size != eval_log_size - 1)
    {
        return null;
    }
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    if (row_count < 2 * m31.PACK_WIDTH or row_count % m31.PACK_WIDTH != 0) return null;
    if (base.selector_tree_index >= trace.polys.items.len or
        base.main_tree_index >= trace.polys.items.len or
        lookup.interaction_tree_index >= trace.polys.items.len)
    {
        return null;
    }

    const selector_tree = trace.polys.items[base.selector_tree_index];
    const main_tree = trace.polys.items[base.main_tree_index];
    const interaction_tree = trace.polys.items[lookup.interaction_tree_index];
    if (base.selector_column >= selector_tree.len or
        lookup.selector_column >= selector_tree.len or
        base.first_main_column > main_tree.len or
        base.main_column_count > main_tree.len - base.first_main_column or
        lookup.first_interaction_column > interaction_tree.len or
        lookup.interaction_column_count >
            interaction_tree.len - lookup.first_interaction_column)
    {
        return null;
    }
    const semantic_selector = selector_tree[base.selector_column];
    const lookup_selector = selector_tree[lookup.selector_column];
    if (!validPoly(semantic_selector, eval_log_size, row_count) or
        !validPoly(lookup_selector, eval_log_size, row_count))
    {
        return null;
    }
    const main_columns = main_tree[base.first_main_column..][0..base.main_column_count];
    const interaction_columns = interaction_tree[lookup.first_interaction_column..][0..lookup.interaction_column_count];
    for (main_columns) |column| if (!validPoly(column, eval_log_size, row_count)) return null;
    for (interaction_columns) |column| if (!validPoly(column, eval_log_size, row_count)) return null;
    return .{
        .eval_log_size = eval_log_size,
        .row_count = row_count,
        .main_columns = main_columns,
        .semantic_selector = semantic_selector.values,
        .lookup_selector = lookup_selector.values,
        .interaction_columns = interaction_columns,
    };
}

fn validPoly(poly: Poly, log_size: u32, row_count: usize) bool {
    return poly.log_size == log_size and poly.values.len == row_count;
}

fn baseCapability(component: Component) ?BaseCapability {
    const capability = component.backend_composition_capability orelse return null;
    return switch (capability) {
        .base_polynomial_v1 => |value| value,
        else => null,
    };
}

fn lookupCapability(component: Component) ?LookupCapability {
    const capability = component.backend_composition_capability orelse return null;
    return switch (capability) {
        .lookup_polynomial_v1 => |value| value,
        else => null,
    };
}

fn findOrAddBaseProgram(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(BaseProgramEntry),
    component: Component,
    capability: BaseCapability,
) !?usize {
    for (entries.items, 0..) |entry, index| {
        if (entry.program_id != capability.program_id) continue;
        if (entry.exporter != capability.export_program) return null;
        return index;
    }
    var program = capability.export_program(component.ctx, allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    var retained = false;
    defer if (!retained) program.deinit();
    program.validate() catch return null;
    if (!boundedNodes(program.nodes)) return null;
    const reachable = try baseReachable(allocator, program);
    errdefer allocator.free(reachable);
    try entries.append(allocator, .{
        .program_id = capability.program_id,
        .exporter = capability.export_program,
        .program = program,
        .reachable = reachable,
    });
    retained = true;
    return entries.items.len - 1;
}

fn findOrAddLookupProgram(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(LookupProgramEntry),
    component: Component,
    capability: LookupCapability,
) !?usize {
    for (entries.items, 0..) |entry, index| {
        if (entry.program_id != capability.program_id) continue;
        if (entry.exporter != capability.export_program) return null;
        return index;
    }
    var program = capability.export_program(component.ctx, allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return null,
    };
    var retained = false;
    defer if (!retained) program.deinit();
    program.validate() catch return null;
    if (!boundedNodes(program.nodes) or program.entries.len > MAX_LOOKUP_ENTRIES) return null;
    const reachable = try lookupReachable(allocator, program);
    errdefer allocator.free(reachable);
    try entries.append(allocator, .{
        .program_id = capability.program_id,
        .exporter = capability.export_program,
        .program = program,
        .reachable = reachable,
    });
    retained = true;
    return entries.items.len - 1;
}

fn boundedNodes(nodes: []const prover.air.component_prover.BasePolynomialNode) bool {
    if (nodes.len == 0 or nodes.len > MAX_PROGRAM_NODES) return false;
    for (nodes) |node| {
        if (node.op == .constant and node.value >= m31.Modulus) return false;
    }
    return true;
}

fn baseReachable(allocator: std.mem.Allocator, program: BaseProgram) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.roots) |root| reachable[root] = true;
    markAncestors(program.nodes, reachable);
    return reachable;
}

fn lookupReachable(allocator: std.mem.Allocator, program: LookupProgram) ![]bool {
    const reachable = try allocator.alloc(bool, program.nodes.len);
    @memset(reachable, false);
    for (program.entries) |entry| {
        reachable[entry.numerator] = true;
        for (entry.values[0..entry.arity]) |value| reachable[value] = true;
    }
    markAncestors(program.nodes, reachable);
    return reachable;
}

fn markAncestors(
    nodes: []const prover.air.component_prover.BasePolynomialNode,
    reachable: []bool,
) void {
    var cursor = nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
}

fn buildBuckets(
    allocator: std.mem.Allocator,
    pairs: []const PairJob,
    buckets: *std.ArrayList(Bucket),
) !void {
    var max_log_size: u32 = 0;
    for (pairs) |pair| max_log_size = @max(max_log_size, pair.eval_log_size);
    const counts = try allocator.alloc(usize, @as(usize, max_log_size) + 1);
    defer allocator.free(counts);
    @memset(counts, 0);
    for (pairs) |pair| counts[pair.eval_log_size] += 1;

    for (counts, 0..) |count, log_size_usize| {
        if (count == 0) continue;
        try appendBucket(allocator, buckets, @intCast(log_size_usize), count);
    }
    const cursors = try allocator.alloc(usize, buckets.items.len);
    defer allocator.free(cursors);
    @memset(cursors, 0);
    for (pairs, 0..) |pair, pair_index| {
        const bucket_index = bucketIndex(buckets.items, pair.eval_log_size).?;
        buckets.items[bucket_index].pair_indices[cursors[bucket_index]] = pair_index;
        cursors[bucket_index] += 1;
    }
}

fn appendBucket(
    allocator: std.mem.Allocator,
    buckets: *std.ArrayList(Bucket),
    eval_log_size: u32,
    pair_count: usize,
) !void {
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    const pair_indices = try allocator.alloc(usize, pair_count);
    errdefer allocator.free(pair_indices);
    var output = try SecureColumn.zeros(allocator, row_count);
    errdefer output.deinit(allocator);
    try buckets.append(allocator, .{
        .eval_log_size = eval_log_size,
        .row_count = row_count,
        .pair_indices = pair_indices,
        .output = output,
        .denominator_inverses = try denominatorInverses(eval_log_size),
    });
}

fn bucketIndex(buckets: []const Bucket, eval_log_size: u32) ?usize {
    for (buckets, 0..) |bucket, index| {
        if (bucket.eval_log_size == eval_log_size) return index;
    }
    return null;
}

fn denominatorInverses(eval_log_size: u32) ![2]PackedM31 {
    const scalars = try denominatorScalars(eval_log_size);
    return .{ m31.splatPacked(scalars[0]), m31.splatPacked(scalars[1]) };
}

fn denominatorScalars(eval_log_size: u32) ![2]M31 {
    if (eval_log_size == 0) return error.InvalidCompositionLogSize;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const trace_coset = canonic.CanonicCoset.new(eval_log_size - 1).coset();
    var result: [2]M31 = undefined;
    for (&result, 0..) |*inverse, index| {
        inverse.* = try constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core.utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    return result;
}

fn scratchBytes(
    main_columns: usize,
    base_nodes: usize,
    lookup_nodes: usize,
    lookup_entries: usize,
) !usize {
    const packed_m31_count = try std.math.add(
        usize,
        try std.math.add(usize, main_columns, base_nodes),
        lookup_nodes,
    );
    return try std.math.add(
        usize,
        try std.math.mul(usize, packed_m31_count, @sizeOf(PackedM31)),
        try std.math.mul(usize, lookup_entries, @sizeOf(PackedQM31)),
    );
}

fn evaluatePair(
    context: *const EvaluationContext,
    pair: *const PairJob,
    row: usize,
    previous_rows: *const [m31.PACK_WIDTH]usize,
    main_values: []const PackedM31,
    base_nodes: []PackedM31,
    lookup_nodes: []PackedM31,
    denominators: []PackedQM31,
) PackedQM31 {
    const base_entry = &context.base_programs[pair.base_program_index];
    const lookup_entry = &context.lookup_programs[pair.lookup_program_index];
    const semantic_selector = m31.loadPacked(pair.semantic_selector.ptr + row);
    evaluateNodes(
        base_entry.program.nodes,
        base_entry.reachable,
        base_nodes,
        main_values[0..pair.main_columns.len],
        semantic_selector,
    );
    var semantic = PackedQM31.zero();
    for (base_entry.program.roots, 0..) |root, root_index| {
        const power = context.powers[
            pair.semantic_power_start + base_entry.program.roots.len - 1 - root_index
        ];
        semantic = semantic.add(power.mulBase(base_nodes[root]));
    }

    evaluateNodes(
        lookup_entry.program.nodes,
        lookup_entry.reachable,
        lookup_nodes,
        main_values[0..pair.main_columns.len],
        null,
    );
    const program = lookup_entry.program;
    var parameter_cursor: usize = 0;
    for (program.entries, denominators[0..program.entries.len]) |entry, *denominator| {
        denominator.* = PackedQM31.zero();
        for (entry.values[0..entry.arity], 0..) |root, value_index| {
            denominator.* = denominator.add(
                PackedQM31.splat(pair.parameters[parameter_cursor + 1 + value_index])
                    .mulBase(lookup_nodes[root]),
            );
        }
        denominator.* = denominator.sub(PackedQM31.splat(pair.parameters[parameter_cursor]));
        parameter_cursor += 1 + entry.arity;
    }

    const lookup_selector = m31.loadPacked(pair.lookup_selector.ptr + row);
    var lookup = PackedQM31.zero();
    for (0..program.batchCount()) |batch| {
        const first = batch * program.batch_size;
        const has_second = first + 1 < program.entries.len and program.batch_size == 2;
        const current = loadSecure(pair.interaction_columns, batch * 4, row);
        const previous = gatherSecure(
            pair.interaction_columns,
            batch * 4,
            previous_rows,
        );
        const claim = PackedQM31.splat(pair.parameters[parameter_cursor + batch]);
        const delta = current.sub(previous).add(claim.mulBase(lookup_selector));
        const first_entry = program.entries[first];
        var constraint = if (has_second) blk: {
            const second_entry = program.entries[first + 1];
            break :blk delta.mul(denominators[first]).mul(denominators[first + 1])
                .sub(denominators[first + 1].mulBase(lookup_nodes[first_entry.numerator]))
                .sub(denominators[first].mulBase(lookup_nodes[second_entry.numerator]));
        } else delta.mul(denominators[first])
            .sub(PackedQM31.fromBase(lookup_nodes[first_entry.numerator]));
        const power = context.powers[
            pair.lookup_power_start + program.batchCount() - 1 - batch
        ];
        constraint = power.mul(constraint);
        lookup = lookup.add(constraint);
    }
    return semantic.add(lookup);
}

fn evaluateNodes(
    nodes: []const prover.air.component_prover.BasePolynomialNode,
    reachable: []const bool,
    values: []PackedM31,
    columns: []const PackedM31,
    selector: ?PackedM31,
) void {
    for (nodes, reachable, 0..) |node, is_reachable, index| {
        if (!is_reachable) continue;
        values[index] = switch (node.op) {
            .constant => @splat(node.value),
            .column => if (node.value < columns.len)
                columns[node.value]
            else
                selector.?,
            .add => m31.addPacked(values[node.lhs], values[node.rhs]),
            .sub => m31.subPacked(values[node.lhs], values[node.rhs]),
            .mul => m31.mulPacked(values[node.lhs], values[node.rhs]),
            .neg => m31.negPacked(values[node.lhs]),
        };
    }
}

fn loadSecure(columns: []const Poly, first_column: usize, row: usize) PackedQM31 {
    return .{
        .c0 = .{
            .a = m31.loadPacked(columns[first_column].values.ptr + row),
            .b = m31.loadPacked(columns[first_column + 1].values.ptr + row),
        },
        .c1 = .{
            .a = m31.loadPacked(columns[first_column + 2].values.ptr + row),
            .b = m31.loadPacked(columns[first_column + 3].values.ptr + row),
        },
    };
}

fn gatherSecure(
    columns: []const Poly,
    first_column: usize,
    rows: *const [m31.PACK_WIDTH]usize,
) PackedQM31 {
    var coordinates: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
        @splat(0), @splat(0), @splat(0), @splat(0),
    };
    for (rows, 0..) |row, lane| {
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            coordinates[coordinate][lane] = columns[first_column + coordinate].values[row].v;
        }
    }
    return .{
        .c0 = .{ .a = coordinates[0], .b = coordinates[1] },
        .c1 = .{ .a = coordinates[2], .b = coordinates[3] },
    };
}

test "cpu RISC-V composition: packed secure arithmetic matches scalar QM31" {
    const Helpers = struct {
        fn pack(values: [m31.PACK_WIDTH]QM31) PackedQM31 {
            var coordinates: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
                @splat(0), @splat(0), @splat(0), @splat(0),
            };
            for (values, 0..) |value, lane| {
                const scalar = value.toM31Array();
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    coordinates[coordinate][lane] = scalar[coordinate].v;
                }
            }
            return .{
                .c0 = .{ .a = coordinates[0], .b = coordinates[1] },
                .c1 = .{ .a = coordinates[2], .b = coordinates[3] },
            };
        }

        fn expectEqual(expected: [m31.PACK_WIDTH]QM31, actual: PackedQM31) !void {
            const coordinates = actual.coordinates();
            for (expected, 0..) |value, lane| {
                const unpacked = QM31.fromM31(
                    M31.fromCanonical(coordinates[0][lane]),
                    M31.fromCanonical(coordinates[1][lane]),
                    M31.fromCanonical(coordinates[2][lane]),
                    M31.fromCanonical(coordinates[3][lane]),
                );
                try std.testing.expect(value.eql(unpacked));
            }
        }
    };

    var lhs: [m31.PACK_WIDTH]QM31 = undefined;
    var rhs: [m31.PACK_WIDTH]QM31 = undefined;
    var products: [m31.PACK_WIDTH]QM31 = undefined;
    var base_products: [m31.PACK_WIDTH]QM31 = undefined;
    const base = M31.fromCanonical(17);
    for (0..m31.PACK_WIDTH) |lane| {
        const value: u32 = @intCast(lane + 1);
        lhs[lane] = QM31.fromU32Unchecked(value, value + 2, value + 4, value + 6);
        rhs[lane] = QM31.fromU32Unchecked(value + 8, value + 10, value + 12, value + 14);
        products[lane] = lhs[lane].mul(rhs[lane]);
        base_products[lane] = lhs[lane].mulM31(base);
    }
    try Helpers.expectEqual(products, Helpers.pack(lhs).mul(Helpers.pack(rhs)));
    try Helpers.expectEqual(
        base_products,
        Helpers.pack(lhs).mulBase(m31.splatPacked(base)),
    );
}

const DifferentialPair = struct {
    trace_log_size: u32,
    relation_z: QM31,
    relation_alpha: QM31,
    claim: QM31,

    fn cast(ctx: *const anyopaque) *const DifferentialPair {
        return @ptrCast(@alignCast(ctx));
    }

    fn semanticComponent(self: *const DifferentialPair) Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = oneConstraint,
                .maxConstraintLogDegreeBound = evalLogSize,
                .traceLogDegreeBounds = unusedTraceBounds,
                .maskPoints = unusedMaskPoints,
                .preprocessedColumnIndices = noPreprocessedIndices,
                .evaluateConstraintQuotientsAtPoint = unusedPointEvaluation,
                .evaluateConstraintQuotientsOnDomain = evaluateSemanticReference,
            },
            .backend_composition_capability = .{
                .base_polynomial_v1 = .{
                    .program_id = 0x1001,
                    .trace_log_size = self.trace_log_size,
                    .selector_tree_index = 0,
                    .selector_column = 1,
                    .main_tree_index = 1,
                    .first_main_column = 0,
                    .main_column_count = 2,
                    .export_program = exportSemanticProgram,
                },
            },
        };
    }

    fn lookupComponent(self: *const DifferentialPair, mismatched_offset: bool) Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = oneConstraint,
                .maxConstraintLogDegreeBound = evalLogSize,
                .traceLogDegreeBounds = unusedTraceBounds,
                .maskPoints = unusedMaskPoints,
                .preprocessedColumnIndices = noPreprocessedIndices,
                .evaluateConstraintQuotientsAtPoint = unusedPointEvaluation,
                .evaluateConstraintQuotientsOnDomain = evaluateLookupReference,
            },
            .backend_composition_capability = .{
                .lookup_polynomial_v1 = .{
                    .program_id = 0x2001,
                    .trace_log_size = self.trace_log_size,
                    .selector_tree_index = 0,
                    .selector_column = 0,
                    .main_tree_index = 1,
                    .first_main_column = if (mismatched_offset) 1 else 0,
                    .main_column_count = 2,
                    .interaction_tree_index = 2,
                    .first_interaction_column = 0,
                    .interaction_column_count = 4,
                    .export_program = exportLookupProgram,
                    .export_parameters = exportLookupParameters,
                },
            },
        };
    }

    fn oneConstraint(_: *const anyopaque) usize {
        return 1;
    }

    fn evalLogSize(ctx: *const anyopaque) u32 {
        return cast(ctx).trace_log_size + 1;
    }

    fn unusedTraceBounds(
        _: *const anyopaque,
        _: std.mem.Allocator,
    ) !core.air.components.TraceLogDegreeBounds {
        return error.UnusedDifferentialHook;
    }

    fn unusedMaskPoints(
        _: *const anyopaque,
        _: std.mem.Allocator,
        _: core.circle.CirclePointQM31,
        _: u32,
    ) !core.air.components.MaskPoints {
        return error.UnusedDifferentialHook;
    }

    fn noPreprocessedIndices(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.alloc(usize, 0);
    }

    fn unusedPointEvaluation(
        _: *const anyopaque,
        _: core.circle.CirclePointQM31,
        _: *const core.air.components.MaskValues,
        _: *core.air.accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {}

    fn exportSemanticProgram(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !BaseProgram {
        const nodes = try allocator.dupe(prover.air.component_prover.BasePolynomialNode, &.{
            .{ .op = .column, .value = 0 },
            .{ .op = .column, .value = 1 },
            .{ .op = .mul, .lhs = 0, .rhs = 1 },
            .{ .op = .column, .value = 2 },
            .{ .op = .sub, .lhs = 2, .rhs = 3 },
        });
        errdefer allocator.free(nodes);
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .roots = try allocator.dupe(u32, &.{4}),
            .column_count = 3,
        };
    }

    fn exportLookupProgram(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !LookupProgram {
        const nodes = try allocator.dupe(prover.air.component_prover.BasePolynomialNode, &.{
            .{ .op = .column, .value = 0 },
            .{ .op = .column, .value = 1 },
        });
        errdefer allocator.free(nodes);
        const entries = try allocator.alloc(prover.air.component_prover.LookupPolynomialEntry, 1);
        errdefer allocator.free(entries);
        var roots: [prover.air.component_prover.MAX_LOOKUP_POLYNOMIAL_ARITY]u32 = undefined;
        roots[0] = 0;
        entries[0] = .{ .numerator = 1, .values = roots, .arity = 1 };
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .entries = entries,
            .column_count = 2,
            .batch_size = 1,
        };
    }

    fn exportLookupParameters(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]QM31 {
        const self = cast(ctx);
        return allocator.dupe(QM31, &.{ self.relation_z, self.relation_alpha, self.claim });
    }

    fn evaluateSemanticReference(
        ctx: *const anyopaque,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !void {
        const self = cast(ctx);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        const main = trace.polys.items[1];
        const is_active = trace.polys.items[0][1].values;
        const denominators = try denominatorScalars(eval_log_size);
        var columns = try accumulator.columns(
            accumulator.allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer accumulator.allocator.free(columns);
        for (0..row_count) |row| {
            const constraint = main[0].values[row].mul(main[1].values[row])
                .sub(is_active[row]);
            columns[0].accumulate(
                row,
                columns[0].random_coeff_powers[0].mulM31(constraint)
                    .mulM31(denominators[@intFromBool(row >= row_count / 2)]),
            );
        }
    }

    fn evaluateLookupReference(
        ctx: *const anyopaque,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !void {
        const self = cast(ctx);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        const main = trace.polys.items[1];
        const is_first = trace.polys.items[0][0].values;
        const interaction = trace.polys.items[2];
        const denominators = try denominatorScalars(eval_log_size);
        var columns = try accumulator.columns(
            accumulator.allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer accumulator.allocator.free(columns);
        for (0..row_count) |row| {
            const previous_row = core.utils.previousBitReversedCircleDomainIndex(
                row,
                self.trace_log_size,
                eval_log_size,
            );
            const current = secureAt(interaction, row);
            const previous = secureAt(interaction, previous_row);
            const relation_denominator = self.relation_alpha.mulM31(main[0].values[row])
                .sub(self.relation_z);
            const delta = current.sub(previous).add(self.claim.mulM31(is_first[row]));
            const constraint = delta.mul(relation_denominator)
                .sub(QM31.fromBase(main[1].values[row]));
            columns[0].accumulate(
                row,
                columns[0].random_coeff_powers[0].mul(constraint)
                    .mulM31(denominators[@intFromBool(row >= row_count / 2)]),
            );
        }
    }

    fn secureAt(columns: []const Poly, row: usize) QM31 {
        return QM31.fromM31(
            columns[0].values[row],
            columns[1].values[row],
            columns[2].values[row],
            columns[3].values[row],
        );
    }
};

test "cpu RISC-V composition: exported adjacent pair matches generic and records admission" {
    const allocator = std.testing.allocator;
    const eval_log_size: u32 = @intCast(std.math.log2_int(usize, m31.PACK_WIDTH) + 1);
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    const mock = DifferentialPair{
        .trace_log_size = eval_log_size - 1,
        .relation_z = QM31.fromU32Unchecked(3, 5, 7, 11),
        .relation_alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
        .claim = QM31.fromU32Unchecked(29, 31, 37, 41),
    };

    const is_first = try allocator.alloc(M31, row_count);
    defer allocator.free(is_first);
    const is_active = try allocator.alloc(M31, row_count);
    defer allocator.free(is_active);
    const main_0 = try allocator.alloc(M31, row_count);
    defer allocator.free(main_0);
    const main_1 = try allocator.alloc(M31, row_count);
    defer allocator.free(main_1);
    var interaction_values: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    for (&interaction_values) |*values| values.* = try allocator.alloc(M31, row_count);
    defer for (interaction_values) |values| allocator.free(values);

    for (0..row_count) |row| {
        is_first[row] = M31.fromCanonical(@intFromBool(row == 0));
        is_active[row] = M31.one();
        main_0[row] = M31.fromCanonical(@intCast(2 * row + 3));
        main_1[row] = M31.fromCanonical(@intCast(5 * row + 7));
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            interaction_values[coordinate][row] = M31.fromCanonical(
                @intCast((coordinate + 2) * (row + 1) + 43),
            );
        }
    }

    const preprocessed = try allocator.dupe(Poly, &.{
        .{ .log_size = eval_log_size, .values = is_first },
        .{ .log_size = eval_log_size, .values = is_active },
    });
    defer allocator.free(preprocessed);
    const main = try allocator.dupe(Poly, &.{
        .{ .log_size = eval_log_size, .values = main_0 },
        .{ .log_size = eval_log_size, .values = main_1 },
    });
    defer allocator.free(main);
    const interaction = try allocator.alloc(Poly, qm31.SECURE_EXTENSION_DEGREE);
    defer allocator.free(interaction);
    for (interaction, interaction_values) |*poly, values| {
        poly.* = .{ .log_size = eval_log_size, .values = values };
    }
    const tree_items = try allocator.dupe([]const Poly, &.{
        preprocessed,
        main,
        interaction,
    });
    var trace = Trace{ .polys = core.pcs.TreeVec([]const Poly).initOwned(tree_items) };
    defer trace.polys.deinit(allocator);

    const components = [_]Component{
        mock.semanticComponent(),
        mock.lookupComponent(false),
    };
    const component_provers = prover.air.component_prover.ComponentProvers{
        .components = components[0..],
        .n_preprocessed_columns = preprocessed.len,
    };
    const random_coeff = QM31.fromU32Unchecked(47, 53, 59, 61);
    var reference = try component_provers.computeCompositionEvaluation(
        allocator,
        random_coeff,
        &trace,
    );
    defer reference.deinit(allocator);

    resetTelemetryForTesting();
    var accelerated = (try evaluate(
        allocator,
        components[0..],
        random_coeff,
        &trace,
    )).?;
    defer accelerated.deinit(allocator);
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        for (reference.columns[coordinate], accelerated.columns[coordinate]) |expected, actual| {
            try std.testing.expect(expected.eql(actual));
        }
    }
    const admitted = telemetrySnapshot();
    try std.testing.expectEqual(@as(u64, 1), admitted.attempts);
    try std.testing.expectEqual(@as(u64, 1), admitted.admissions);
    try std.testing.expectEqual(@as(u64, 0), admitted.declines);
    try std.testing.expectEqual(@as(u64, 1), admitted.eligible_pairs);
    try std.testing.expectEqual(@as(u64, 0), admitted.fallback_components);
    try std.testing.expectEqual(@as(u64, 1), admitted.distinct_buckets);
    try std.testing.expectEqual(@as(u64, 1), admitted.row_tiles);
    try std.testing.expect(admitted.max_scratch_bytes_per_worker != 0);

    const mismatched = [_]Component{
        mock.semanticComponent(),
        mock.lookupComponent(true),
    };
    resetTelemetryForTesting();
    try std.testing.expect(try evaluate(
        allocator,
        mismatched[0..],
        random_coeff,
        &trace,
    ) == null);
    const declined = telemetrySnapshot();
    try std.testing.expectEqual(@as(u64, 1), declined.attempts);
    try std.testing.expectEqual(@as(u64, 0), declined.admissions);
    try std.testing.expectEqual(@as(u64, 1), declined.declines);

    var fallback_semantic = mock.semanticComponent();
    fallback_semantic.backend_composition_capability = null;
    const mixed = [_]Component{
        fallback_semantic,
        mock.semanticComponent(),
        mock.lookupComponent(false),
    };
    const mixed_provers = prover.air.component_prover.ComponentProvers{
        .components = mixed[0..],
        .n_preprocessed_columns = preprocessed.len,
    };
    var mixed_reference = try mixed_provers.computeCompositionEvaluation(
        allocator,
        random_coeff,
        &trace,
    );
    defer mixed_reference.deinit(allocator);

    resetTelemetryForTesting();
    var mixed_accelerated = (try evaluate(
        allocator,
        mixed[0..],
        random_coeff,
        &trace,
    )).?;
    defer mixed_accelerated.deinit(allocator);
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        for (mixed_reference.columns[coordinate], mixed_accelerated.columns[coordinate]) |expected, actual| {
            try std.testing.expect(expected.eql(actual));
        }
    }
    const mixed_snapshot = telemetrySnapshot();
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.attempts);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.admissions);
    try std.testing.expectEqual(@as(u64, 0), mixed_snapshot.declines);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.eligible_pairs);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.fallback_components);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.distinct_buckets);
    try std.testing.expectEqual(@as(u64, 1), mixed_snapshot.row_tiles);
}
