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
const lanes = @import("riscv_composition_lanes.zig");

const qm31 = core.fields.qm31;
const packed_qm31 = core.fields.packed_qm31;

const QM31 = qm31.QM31;
const PackedQM31 = packed_qm31.PackedQM31;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const SecureColumn = prover.secure_column.SecureColumnByCoords;
const BaseProgramEntry = admission.BaseProgramEntry;
const LookupProgramEntry = admission.LookupProgramEntry;
const PairJob = admission.PairJob;
const Bucket = lanes.Bucket;
const EvaluationContext = lanes.EvaluationContext;
const Tile = lanes.Tile;
const TileLane = lanes.TileLane;
const TILE_ROWS = lanes.TILE_ROWS;
/// Exact-pair lanes can span several adjacent semantic/lookup components, so
/// they belong to one synthetic aggregate rather than impersonating a real
/// component registry entry. The lane is the canonical chunk identity.
const PAIR_AGGREGATE_REGISTRY_INDEX: u32 = std.math.maxInt(u32);

pub const TelemetrySnapshot = struct {
    attempts: u64 = 0,
    /// Prepared-plan admissions; task-profile widths own worker truth.
    admissions: u64 = 0,
    declines: u64 = 0,
    eligible_pairs: u64 = 0,
    fallback_components: u64 = 0,
    prepared_fallback_components: u64 = 0,
    coordinator_fallback_components: u64 = 0,
    distinct_buckets: u64 = 0,
    row_tiles: u64 = 0,
    /// Planned lanes, not physically admitted or observed workers.
    execution_lanes: u64 = 0,
    /// Graph attempts; a strict lease decline can follow this counter.
    structured_executions: u64 = 0,
    pool_lease_declines: u64 = 0,
    finite_budget_rejections: u64 = 0,
    unprepared_fallback_rejections: u64 = 0,
    /// Process-lifetime high-water mark; `delta` intentionally preserves the
    /// absolute value rather than pretending maxima are additive counters.
    max_graph_peak_active: u64 = 0,
    /// Process-lifetime high-water mark with the same snapshot semantics.
    max_scratch_bytes_per_worker: u64 = 0,

    pub fn delta(after: TelemetrySnapshot, before: TelemetrySnapshot) TelemetrySnapshot {
        return .{
            .attempts = after.attempts -| before.attempts,
            .admissions = after.admissions -| before.admissions,
            .declines = after.declines -| before.declines,
            .eligible_pairs = after.eligible_pairs -| before.eligible_pairs,
            .fallback_components = after.fallback_components -| before.fallback_components,
            .prepared_fallback_components = after.prepared_fallback_components -|
                before.prepared_fallback_components,
            .coordinator_fallback_components = after.coordinator_fallback_components -|
                before.coordinator_fallback_components,
            .distinct_buckets = after.distinct_buckets -| before.distinct_buckets,
            .row_tiles = after.row_tiles -| before.row_tiles,
            .execution_lanes = after.execution_lanes -| before.execution_lanes,
            .structured_executions = after.structured_executions -| before.structured_executions,
            .pool_lease_declines = after.pool_lease_declines -| before.pool_lease_declines,
            .finite_budget_rejections = after.finite_budget_rejections -|
                before.finite_budget_rejections,
            .unprepared_fallback_rejections = after.unprepared_fallback_rejections -|
                before.unprepared_fallback_rejections,
            .max_graph_peak_active = after.max_graph_peak_active,
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
    prepared_fallback_components: AtomicCounter = .init(0),
    coordinator_fallback_components: AtomicCounter = .init(0),
    distinct_buckets: AtomicCounter = .init(0),
    row_tiles: AtomicCounter = .init(0),
    execution_lanes: AtomicCounter = .init(0),
    structured_executions: AtomicCounter = .init(0),
    pool_lease_declines: AtomicCounter = .init(0),
    finite_budget_rejections: AtomicCounter = .init(0),
    unprepared_fallback_rejections: AtomicCounter = .init(0),
    max_graph_peak_active: AtomicCounter = .init(0),
    max_scratch_bytes_per_worker: AtomicCounter = .init(0),
};

var telemetry: Telemetry = .{};

/// Explicit execution contract for the bounded RISC-V composition plan.
/// `worker_budget` includes the coordinator. Callers that require an
/// admissible scaling result leave `serial_on_contention` false; the legacy
/// backend wrapper enables it because it has no request-level admission API.
/// Strict callers also leave `allow_unprepared_fallback` false so every worker
/// path is prepared before the structured graph can launch.
pub const ExecutionOptions = struct {
    worker_budget: prover.work_pool.WorkerBudget = prover.work_pool.WorkerBudget.serial(),
    pool: ?*prover.work_pool.WorkPool = null,
    byte_budget: usize = std.math.maxInt(usize),
    serial_on_contention: bool = false,
    allow_unprepared_fallback: bool = false,
    requested_worker_count: usize = 0,
    pool_capacity: usize = 0,
    task_recorder: ?*prover.stage_profile.Recorder = null,

    fn requestedWorkerCount(self: ExecutionOptions) usize {
        return if (self.requested_worker_count == 0)
            self.worker_budget.count
        else
            self.requested_worker_count;
    }

    fn poolCapacity(self: ExecutionOptions) usize {
        if (self.pool_capacity != 0) return self.pool_capacity;
        return if (self.pool) |pool| pool.workerCount() else 1;
    }
};

pub fn telemetrySnapshot() TelemetrySnapshot {
    return .{
        .attempts = telemetry.attempts.load(.monotonic),
        .admissions = telemetry.admissions.load(.monotonic),
        .declines = telemetry.declines.load(.monotonic),
        .eligible_pairs = telemetry.eligible_pairs.load(.monotonic),
        .fallback_components = telemetry.fallback_components.load(.monotonic),
        .prepared_fallback_components = telemetry.prepared_fallback_components.load(.monotonic),
        .coordinator_fallback_components = telemetry.coordinator_fallback_components.load(.monotonic),
        .distinct_buckets = telemetry.distinct_buckets.load(.monotonic),
        .row_tiles = telemetry.row_tiles.load(.monotonic),
        .execution_lanes = telemetry.execution_lanes.load(.monotonic),
        .structured_executions = telemetry.structured_executions.load(.monotonic),
        .pool_lease_declines = telemetry.pool_lease_declines.load(.monotonic),
        .finite_budget_rejections = telemetry.finite_budget_rejections.load(.monotonic),
        .unprepared_fallback_rejections = telemetry.unprepared_fallback_rejections.load(.monotonic),
        .max_graph_peak_active = telemetry.max_graph_peak_active.load(.monotonic),
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

const HostWorker = struct {
    component: Component,
    trace: *const Trace,
    accumulator: Accumulator,
    expected_next_power_index: usize,
    component_registry_index: u32,
    prepared: prover.air.prepared_domain.PreparedDomainEvaluation = undefined,
    prepared_initialized: bool = false,

    fn run(task_context: *prover.task_graph.TaskContext) anyerror!void {
        const self: *HostWorker = @ptrCast(@alignCast(task_context.user_context));
        if (self.prepared_initialized) {
            try self.prepared.run(task_context);
        } else {
            try self.component.evaluateConstraintQuotientsOnDomain(
                self.trace,
                &self.accumulator,
            );
        }
    }

    fn taskClass(self: *const HostWorker) prover.task_graph.TaskClass {
        if (self.prepared_initialized) return self.prepared.task_class;
        // Legacy evaluators may allocate and are not admitted alongside leaf
        // work. Keeping them on the coordinator is the safe mixed-capability
        // migration boundary.
        return .coordinator;
    }

    fn resources(self: *const HostWorker) prover.task_graph.ResourceReservation {
        if (self.prepared_initialized) return self.prepared.resources;
        return .{};
    }

    fn deinit(self: *HostWorker) void {
        if (self.prepared_initialized) self.prepared.deinit();
        self.accumulator.deinit();
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
    if (prover.work_pool.getGlobalPool()) |pool| {
        return evaluateWithExecution(
            allocator,
            components,
            random_coeff,
            trace,
            .{
                .worker_budget = try prover.work_pool.WorkerBudget.init(pool.workerCount()),
                .pool = pool,
                .serial_on_contention = true,
                .allow_unprepared_fallback = true,
            },
        );
    }
    return evaluateWithExecution(
        allocator,
        components,
        random_coeff,
        trace,
        .{ .allow_unprepared_fallback = true },
    );
}

/// Evaluates the same canonical plan under an explicit worker and byte budget.
/// Planning and all fallible preparation complete before the graph launches.
pub fn evaluateWithExecution(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    execution: ExecutionOptions,
) !?SecureColumn {
    _ = try prover.work_pool.WorkerBudget.init(execution.worker_budget.count);
    if (execution.worker_budget.count > 1 and execution.pool == null) {
        return error.WorkPoolRequired;
    }
    if (execution.pool) |pool| {
        if (execution.worker_budget.count > pool.workerCount()) {
            return error.WorkerBudgetUnavailable;
        }
    }
    if (!admission.hasCandidatePair(components)) return null;

    if (execution.byte_budget == std.math.maxInt(usize)) {
        return evaluatePlan(allocator, components, random_coeff, trace, execution);
    }
    const helper_bytes = try helperResidentBytes(execution);
    const heap_budget = std.math.sub(
        usize,
        execution.byte_budget,
        helper_bytes,
    ) catch {
        _ = telemetry.finite_budget_rejections.fetchAdd(1, .monotonic);
        return error.TaskMemoryBudgetExceeded;
    };
    var bounded = prover.host_budget_allocator.HostBudgetAllocator.init(
        allocator,
        heap_budget,
    );
    return evaluatePlan(
        bounded.allocator(),
        components,
        random_coeff,
        trace,
        execution,
    ) catch |failure| {
        if (failure == error.OutOfMemory and bounded.didExceedBudget()) {
            _ = telemetry.finite_budget_rejections.fetchAdd(1, .monotonic);
            return error.TaskMemoryBudgetExceeded;
        }
        if (failure == error.FiniteCompositionByteBudgetUnsupported) {
            _ = telemetry.finite_budget_rejections.fetchAdd(1, .monotonic);
        }
        return failure;
    };
}

fn helperResidentBytes(execution: ExecutionOptions) !usize {
    const helper_count = execution.worker_budget.helperCount();
    if (helper_count == 0) return 0;
    const pool = execution.pool orelse return error.WorkPoolRequired;
    return pool.helperReservationBytes(execution.worker_budget);
}

fn evaluatePlan(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    execution: ExecutionOptions,
) !?SecureColumn {
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
    if (!execution.allow_unprepared_fallback) {
        for (components, eligible) |component, is_eligible| {
            if (!is_eligible and component.prepare_domain_evaluator == null) {
                _ = telemetry.unprepared_fallback_rejections.fetchAdd(1, .monotonic);
                return error.UnpreparedCompositionFallback;
            }
        }
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

    var buckets = std.ArrayList(Bucket).empty;
    defer {
        for (buckets.items) |*bucket| bucket.deinit(allocator);
        buckets.deinit(allocator);
    }
    try lanes.buildBuckets(allocator, pairs.items, &buckets);

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
    const scratch_bytes = try lanes.scratchBytes(
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

    const fallback_count = components.len - 2 * pairs.items.len;
    if (fallback_count >= prover.task_graph.MAX_COMPONENT_TASKS) {
        _ = telemetry.declines.fetchAdd(1, .monotonic);
        return null;
    }
    const configured_lanes = execution.worker_budget.count;
    const lane_count = @min(
        tile_count,
        configured_lanes,
        prover.task_graph.MAX_COMPONENT_TASKS - fallback_count,
    );
    std.debug.assert(lane_count > 0);
    const task_count = fallback_count + lane_count;
    var graph = try prover.task_graph.ComponentTaskGraph.init(allocator, task_count);
    defer graph.deinit();

    const host_workers = try allocator.alloc(HostWorker, fallback_count);
    defer allocator.free(host_workers);
    var initialized_host_workers: usize = 0;
    defer {
        var index = initialized_host_workers;
        while (index > 0) {
            index -= 1;
            host_workers[index].deinit();
        }
    }

    // `generateSecurePowers` stores [1, alpha, ...]. The generic accumulator
    // consumes components from the tail in declaration order, then each
    // component folds its constraints in reverse-root order. Assign and
    // prepare every host component on the coordinator before any task starts;
    // eligible and host components therefore cannot perturb one another's
    // transcript powers or allocator ownership.
    var power_cursor = total_constraints;
    var pair_cursor: usize = 0;
    var host_cursor: usize = 0;
    var prepared_fallback_count: usize = 0;
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
        const next_power_cursor = power_cursor - constraint_count;
        const registry_index = std.math.cast(u32, component_index) orelse
            return error.InvalidCompositionTaskKey;
        host_workers[host_cursor] = .{
            .component = components[component_index],
            .trace = trace,
            .accumulator = try Accumulator.initForComponent(
                powers,
                allocator,
                max_log_size,
                power_cursor,
            ),
            .expected_next_power_index = next_power_cursor,
            .component_registry_index = registry_index,
        };
        initialized_host_workers += 1;
        if (try components[component_index].prepareConstraintQuotientsOnDomain(
            allocator,
            trace,
            &host_workers[host_cursor].accumulator,
        )) |prepared| {
            host_workers[host_cursor].prepared = prepared;
            host_workers[host_cursor].prepared_initialized = true;
            if (host_workers[host_cursor].accumulator.next_power_index !=
                next_power_cursor)
            {
                return error.InvalidCompositionPowerOrder;
            }
            prepared_fallback_count += 1;
        }
        host_cursor += 1;
        power_cursor = next_power_cursor;
        component_index += 1;
    }
    if (power_cursor != 0 or pair_cursor != pairs.items.len or
        host_cursor != host_workers.len)
    {
        return error.InvalidCompositionPowerOrder;
    }
    if (execution.byte_budget != std.math.maxInt(usize) and
        prepared_fallback_count != fallback_count)
    {
        return error.FiniteCompositionByteBudgetUnsupported;
    }

    const tiles = try allocator.alloc(Tile, tile_count);
    defer allocator.free(tiles);
    const context = EvaluationContext{
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
            tiles[tile_cursor] = .{
                .bucket = bucket,
                .row_start = row_start,
                .row_end = @min(bucket.row_count, row_start + TILE_ROWS),
            };
            tile_cursor += 1;
        }
    }
    std.debug.assert(tile_cursor == tiles.len);

    const tile_lanes = try allocator.alloc(TileLane, lane_count);
    defer allocator.free(tile_lanes);
    var initialized_tile_lanes: usize = 0;
    defer {
        var index = initialized_tile_lanes;
        while (index > 0) {
            index -= 1;
            tile_lanes[index].deinit();
        }
    }
    for (tile_lanes, 0..) |*lane, lane_index| {
        lane.* = try TileLane.init(
            allocator,
            &context,
            tiles,
            lane_index,
            lane_count,
        );
        initialized_tile_lanes += 1;
    }
    for (host_workers) |*worker| {
        const planned_rows = try componentRows(worker.component);
        if (execution.byte_budget != std.math.maxInt(usize)) {
            try requireHeapBackedResources(worker.resources());
        }
        _ = try graph.addTask(.{
            .key = .{
                .epoch = 0,
                .stage_rank = 0,
                .component_registry_index = worker.component_registry_index,
                .shard_or_chunk_index = 0,
            },
            .name = "riscv-composition-fallback",
            .stage_id = "composition_domain",
            .component_kind = "riscv_fallback_component",
            .func = HostWorker.run,
            .context = worker,
            .class = worker.taskClass(),
            .resources = worker.resources(),
            .work_estimate = try componentWorkEstimate(worker.component, planned_rows),
            .work_unit = .rows,
            .planned_work_units = planned_rows,
        });
    }
    for (tile_lanes, 0..) |*lane, lane_index| {
        const resources = try lane.resources(scratch_bytes);
        if (execution.byte_budget != std.math.maxInt(usize)) {
            try requireHeapBackedResources(resources);
        }
        _ = try graph.addTask(.{
            .key = .{
                .epoch = 0,
                .stage_rank = 1,
                .component_registry_index = PAIR_AGGREGATE_REGISTRY_INDEX,
                .shard_or_chunk_index = std.math.cast(u32, lane_index) orelse
                    return error.InvalidCompositionTaskKey,
            },
            .name = "riscv-composition-tile-lane",
            .stage_id = "composition_domain",
            .component_kind = "riscv_pair_lane",
            .func = TileLane.run,
            .context = lane,
            .resources = resources,
            .work_estimate = try lane.workEstimate(),
            .work_unit = .tiles,
            .planned_work_units = @intCast(
                std.math.divCeil(usize, tiles.len - lane_index, lane_count) catch unreachable,
            ),
        });
    }

    // Complete every fallible allocation before launching the graph. A sole
    // accelerated bucket already on the final domain can still transfer its
    // ownership directly; every mixed or lifted result receives caller-owned
    // destination storage up front.
    var combined = try Accumulator.initForComponent(powers, allocator, max_log_size, 0);
    defer combined.deinit();
    var needs_preallocated_output = false;
    for (host_workers) |worker| {
        if (!worker.prepared_initialized) {
            // A legacy coordinator evaluator has not declared which domain
            // buckets it will materialize, so reserve the general result.
            needs_preallocated_output = true;
            break;
        }
        for (worker.accumulator.sub_accumulations, 0..) |maybe_sub, log_size| {
            if (maybe_sub != null and log_size != max_log_size) {
                needs_preallocated_output = true;
                break;
            }
        }
        if (needs_preallocated_output) break;
    }
    if (!needs_preallocated_output) {
        for (buckets.items) |bucket| {
            if (bucket.eval_log_size != max_log_size) {
                needs_preallocated_output = true;
                break;
            }
        }
    }
    var prepared_output: ?SecureColumn = if (needs_preallocated_output)
        try SecureColumn.uninitialized(allocator, @as(usize, 1) << @intCast(max_log_size))
    else
        null;
    defer if (prepared_output) |*output| output.deinit(allocator);

    // Legacy counters describe the plan; the flat profile owns worker truth.
    _ = telemetry.admissions.fetchAdd(1, .monotonic);
    _ = telemetry.eligible_pairs.fetchAdd(@intCast(pairs.items.len), .monotonic);
    _ = telemetry.fallback_components.fetchAdd(@intCast(fallback_count), .monotonic);
    _ = telemetry.prepared_fallback_components.fetchAdd(
        @intCast(prepared_fallback_count),
        .monotonic,
    );
    _ = telemetry.coordinator_fallback_components.fetchAdd(
        @intCast(fallback_count - prepared_fallback_count),
        .monotonic,
    );
    _ = telemetry.distinct_buckets.fetchAdd(@intCast(buckets.items.len), .monotonic);
    _ = telemetry.row_tiles.fetchAdd(@intCast(tiles.len), .monotonic);
    _ = telemetry.execution_lanes.fetchAdd(@intCast(tile_lanes.len), .monotonic);
    _ = telemetry.structured_executions.fetchAdd(1, .monotonic);
    recordMax(&telemetry.max_scratch_bytes_per_worker, @intCast(scratch_bytes));

    const execution_report = graph.execute(.{
        .worker_budget = execution.worker_budget,
        .pool = execution.pool,
        // Finite heap ownership is enforced by HostBudgetAllocator and shared
        // helper residency was reserved before planning. Resource declarations
        // still validate worker-stack shape; finite plans reject non-heap scratch.
        .byte_budget = std.math.maxInt(usize),
        .ready_policy = .critical_path,
        .task_profile_recorder = execution.task_recorder,
        .task_profile_graph_id = "cpu_composition_riscv",
        .requested_worker_count = execution.requestedWorkerCount(),
        .pool_capacity = execution.poolCapacity(),
    }) catch |failure| switch (failure) {
        error.WorkerBudgetUnavailable => if (execution.serial_on_contention) serial: {
            _ = telemetry.pool_lease_declines.fetchAdd(1, .monotonic);
            break :serial try graph.execute(.{
                .worker_budget = prover.work_pool.WorkerBudget.serial(),
                .byte_budget = std.math.maxInt(usize),
                .ready_policy = .critical_path,
                .task_profile_recorder = execution.task_recorder,
                .task_profile_graph_id = "cpu_composition_riscv",
                .requested_worker_count = execution.requestedWorkerCount(),
                .pool_capacity = execution.poolCapacity(),
            });
        } else return failure,
        else => return failure,
    };
    recordMax(&telemetry.max_graph_peak_active, @intCast(execution_report.peak_active_tasks));
    for (host_workers) |worker| {
        if (worker.accumulator.next_power_index != worker.expected_next_power_index) {
            return error.InvalidCompositionPowerOrder;
        }
    }

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
    if (prepared_output) |*output| {
        try combined.finalizeInto(output);
        const result = output.*;
        prepared_output = null;
        return result;
    }
    return try combined.finalize();
}

fn requireHeapBackedResources(resources: prover.task_graph.ResourceReservation) !void {
    if (resources.exclusive_scratch_bytes != 0 or resources.device_resident_bytes != 0) {
        return error.FiniteCompositionByteBudgetUnsupported;
    }
}

fn componentWorkEstimate(component: Component, rows: u64) !u64 {
    return prover.task_graph.checkedWorkEstimate(&.{
        rows,
        std.math.cast(u64, component.nConstraints()) orelse
            return error.WorkEstimateOverflow,
    });
}

fn componentRows(component: Component) !u64 {
    const log_size = component.maxConstraintLogDegreeBound();
    if (log_size >= @bitSizeOf(u64)) return error.WorkEstimateOverflow;
    return @as(u64, 1) << @intCast(log_size);
}
