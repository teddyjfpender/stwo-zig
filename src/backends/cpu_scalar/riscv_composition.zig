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
const admission = @import("riscv_composition_admission.zig");

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
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const SecureColumn = prover.secure_column.SecureColumnByCoords;
const BaseProgramEntry = admission.BaseProgramEntry;
const LookupProgramEntry = admission.LookupProgramEntry;
const PairJob = admission.PairJob;

const TILE_ROWS: usize = 4096;

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
    if (!admission.hasCandidatePair(components)) return null;
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
        const pair = try admission.resolvePair(
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
