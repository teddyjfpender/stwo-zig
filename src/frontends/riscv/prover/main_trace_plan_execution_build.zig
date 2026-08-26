//! Coordinator-only construction and validation for the Tree-1 epoch graphs.

const std = @import("std");
const prover_engine = @import("stwo_prover_engine");
const component_order = @import("../air/component_order.zig");
const plan_mod = @import("main_trace_plan.zig");
const plan_types = @import("main_trace_plan_types.zig");
const types = @import("main_trace_plan_execution_types.zig");

const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;

pub const TaskRecord = struct {
    descriptor: types.Task,
    kernel: types.Kernel,
    started: std.atomic.Value(bool) = .init(false),
    completed: std.atomic.Value(bool) = .init(false),

    fn run(context: *task_graph.TaskContext) anyerror!void {
        const self: *TaskRecord = @ptrCast(@alignCast(context.user_context));
        const expected_class = types.taskClass(self.descriptor.kind);
        if (!context.key.eql(self.descriptor.key) or
            context.task_class != expected_class or
            context.worker_budget.count != 1)
        {
            return error.InvalidTree1TaskContext;
        }
        if (self.started.swap(true, .acq_rel)) {
            return error.DuplicateTree1TaskStart;
        }
        try self.kernel.run(
            self.kernel.context,
            &self.descriptor,
            context,
        );
        if (context.isCancelled()) return;
        self.completed.store(true, .release);
    }
};

pub const TaskRange = struct {
    start: usize = 0,
    len: usize = 0,
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    admission: types.Admission,
    graphs: [types.WAVE_COUNT]task_graph.ComponentTaskGraph,
    task_ranges: [types.WAVE_COUNT]TaskRange,
    tasks: []TaskRecord,

    pub fn deinit(self: *Prepared) void {
        for (&self.graphs) |*graph| graph.deinit();
        self.allocator.free(self.tasks);
        self.* = undefined;
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    plan: *const plan_mod.Plan,
    kernel: types.Kernel,
) !Prepared {
    const facts = try validatePlan(plan);
    const tasks = try allocator.alloc(TaskRecord, facts.total_task_count);
    errdefer allocator.free(tasks);

    var graphs: [types.WAVE_COUNT]task_graph.ComponentTaskGraph = undefined;
    var initialized_graphs: usize = 0;
    errdefer for (graphs[0..initialized_graphs]) |*graph| graph.deinit();
    for (facts.wave_counts, 0..) |capacity, index| {
        graphs[index] = try task_graph.ComponentTaskGraph.init(
            allocator,
            capacity,
        );
        initialized_graphs += 1;
    }

    var ranges = [_]TaskRange{.{}} ** types.WAVE_COUNT;
    var cursor: usize = 0;
    try beginWave(&ranges, .prepare, cursor, facts.wave_counts);
    try appendTask(
        &graphs[types.waveIndex(.prepare)],
        tasks,
        &cursor,
        kernel,
        facts.admission,
        plan.worker_stack_bytes,
        task(.prepare, plan_mod.prepareTaskKey()),
    );

    try beginWave(&ranges, .generation, cursor, facts.wave_counts);
    for (plan.opcodeChunks(), 0..) |rows, chunk_index| {
        try appendTask(
            &graphs[types.waveIndex(.generation)],
            tasks,
            &cursor,
            kernel,
            facts.admission,
            plan.worker_stack_bytes,
            .{
                .key = plan_mod.opcodeFillTaskKey(@intCast(chunk_index)),
                .kind = .opcode_fill,
                .registry_index = null,
                .chunk_index = @intCast(chunk_index),
                .rows = rows,
                .columns = null,
            },
        );
    }
    const lookup_start = lookupStart(plan);
    for (0..lookup_start) |infra_index| {
        const registry_index = @as(usize, plan.n_components) + infra_index;
        const columns = plan.infrastructureRange(infra_index) orelse
            return error.InvalidTree1Plan;
        if (infra_index == @as(usize, plan.poseidon_infra_index)) {
            for (plan.poseidonChunks(), 0..) |rows, chunk_index| {
                try appendTask(
                    &graphs[types.waveIndex(.generation)],
                    tasks,
                    &cursor,
                    kernel,
                    facts.admission,
                    plan.worker_stack_bytes,
                    .{
                        .key = try plan.infraFillKey(
                            infra_index,
                            @intCast(chunk_index),
                        ),
                        .kind = .poseidon_fill,
                        .registry_index = @intCast(registry_index),
                        .chunk_index = @intCast(chunk_index),
                        .rows = rows,
                        .columns = columns,
                    },
                );
            }
        } else {
            try appendTask(
                &graphs[types.waveIndex(.generation)],
                tasks,
                &cursor,
                kernel,
                facts.admission,
                plan.worker_stack_bytes,
                .{
                    .key = try plan.infraFillKey(infra_index, 0),
                    .kind = .infrastructure_fill,
                    .registry_index = @intCast(registry_index),
                    .chunk_index = 0,
                    .rows = null,
                    .columns = columns,
                },
            );
        }
    }

    try beginWave(&ranges, .reduce, cursor, facts.wave_counts);
    try appendTask(
        &graphs[types.waveIndex(.reduce)],
        tasks,
        &cursor,
        kernel,
        facts.admission,
        plan.worker_stack_bytes,
        task(.opcode_reduce, plan_mod.opcodeReduceTaskKey()),
    );

    try beginWave(&ranges, .audit, cursor, facts.wave_counts);
    if (plan.opcode_audit_enabled) {
        for (0..@as(usize, plan.n_components)) |component_index| {
            try appendTask(
                &graphs[types.waveIndex(.audit)],
                tasks,
                &cursor,
                kernel,
                facts.admission,
                plan.worker_stack_bytes,
                .{
                    .key = plan_mod.opcodeAuditTaskKey(@intCast(component_index)),
                    .kind = .opcode_audit,
                    .registry_index = @intCast(component_index),
                    .chunk_index = 0,
                    .rows = null,
                    .columns = plan.componentRange(component_index),
                },
            );
        }
    }

    try beginWave(&ranges, .lookup_seed, cursor, facts.wave_counts);
    try appendTask(
        &graphs[types.waveIndex(.lookup_seed)],
        tasks,
        &cursor,
        kernel,
        facts.admission,
        plan.worker_stack_bytes,
        task(.lookup_seed, plan_mod.lookupSeedTaskKey()),
    );

    try beginWave(&ranges, .finalization, cursor, facts.wave_counts);
    for (0..@as(usize, plan.n_components)) |component_index| {
        try appendTask(
            &graphs[types.waveIndex(.finalization)],
            tasks,
            &cursor,
            kernel,
            facts.admission,
            plan.worker_stack_bytes,
            .{
                .key = plan_mod.opcodeFinalizeTaskKey(@intCast(component_index)),
                .kind = .opcode_finalize,
                .registry_index = @intCast(component_index),
                .chunk_index = 0,
                .rows = null,
                .columns = plan.componentRange(component_index),
            },
        );
    }
    for (lookup_start..@as(usize, plan.n_infra)) |infra_index| {
        try appendTask(
            &graphs[types.waveIndex(.finalization)],
            tasks,
            &cursor,
            kernel,
            facts.admission,
            plan.worker_stack_bytes,
            .{
                .key = try plan.infraFinalizeKey(infra_index),
                .kind = .lookup_finalize,
                .registry_index = @intCast(
                    @as(usize, plan.n_components) + infra_index,
                ),
                .chunk_index = 0,
                .rows = null,
                .columns = plan.infrastructureRange(infra_index),
            },
        );
    }

    try beginWave(&ranges, .seal, cursor, facts.wave_counts);
    try appendTask(
        &graphs[types.waveIndex(.seal)],
        tasks,
        &cursor,
        kernel,
        facts.admission,
        plan.worker_stack_bytes,
        task(.seal, plan_mod.sealTaskKey()),
    );

    if (cursor != tasks.len) return error.InvalidTree1Plan;
    for (graphs, facts.wave_counts) |graph, expected_count| {
        if (graph.count != expected_count or graph.capacity != expected_count) {
            return error.InvalidTree1Plan;
        }
    }
    try validateCanonicalOrder(tasks);
    return .{
        .allocator = allocator,
        .admission = facts.admission,
        .graphs = graphs,
        .task_ranges = ranges,
        .tasks = tasks,
    };
}

const PlanFacts = struct {
    wave_counts: [types.WAVE_COUNT]usize,
    total_task_count: usize,
    admission: types.Admission,
};

fn validatePlan(plan: *const plan_mod.Plan) !PlanFacts {
    try plan.task_counts.validate();
    const planned_workers: usize = plan.planned_worker_count;
    const requested_workers: usize = plan.requested_worker_count;
    const pool_capacity: usize = plan.pool_capacity;
    if (requested_workers == 0 or
        requested_workers > work_pool.MAX_WORKERS or
        planned_workers == 0 or
        planned_workers > work_pool.MAX_WORKERS or
        pool_capacity == 0 or
        pool_capacity > work_pool.MAX_WORKERS or
        planned_workers > pool_capacity or
        plan.worker_stack_bytes == 0 or
        plan.opcode_chunk_count == 0 or
        plan.poseidon_chunk_count == 0)
    {
        return error.InvalidTree1Plan;
    }
    const expected_workers = if (requested_workers <= pool_capacity)
        requested_workers
    else switch (plan.contention_policy) {
        .strict => return error.InvalidTree1Plan,
        .compatibility => 1,
    };
    if (planned_workers != expected_workers or
        @as(usize, plan.opcode_chunk_count) > planned_workers or
        @as(usize, plan.poseidon_chunk_count) > planned_workers or
        plan.n_components == 0 or
        plan.ordinary_steps == 0 or
        @as(usize, plan.n_infra) < component_order.LOOKUP_TABLE_COUNT + 1)
    {
        return error.InvalidTree1Plan;
    }

    const lookup_start = lookupStart(plan);
    if (@as(usize, plan.poseidon_infra_index) >= lookup_start or
        @as(usize, plan.descriptor_count) !=
            @as(usize, plan.n_components) + @as(usize, plan.n_infra))
    {
        return error.InvalidTree1Plan;
    }
    try plan_types.validateAlignedPartition(
        plan.opcodeChunks(),
        plan.ordinary_steps,
        plan_mod.OPCODE_ROWS_PER_CHUNK,
    );
    const poseidon_chunks = plan.poseidonChunks();
    const poseidon_domain = try poseidon_chunks[poseidon_chunks.len - 1].end();
    try plan_types.validateAlignedPartition(
        poseidon_chunks,
        poseidon_domain,
        plan_mod.POSEIDON_ROWS_PER_CHUNK,
    );

    var column_cursor: u32 = 0;
    for (0..@as(usize, plan.descriptor_count)) |registry_index| {
        const range = plan.descriptorRange(registry_index) orelse
            return error.InvalidTree1Plan;
        if (range.start != column_cursor or range.len == 0) {
            return error.InvalidTree1Plan;
        }
        column_cursor = try range.end();
    }
    if (column_cursor != plan.total_columns) return error.InvalidTree1Plan;
    for (plan.column_offsets[@as(usize, plan.descriptor_count) + 1 ..]) |unused| {
        if (unused != 0) return error.InvalidTree1Plan;
    }

    var generation_count = std.math.add(
        usize,
        @as(usize, plan.opcode_chunk_count),
        lookup_start - 1,
    ) catch return error.Tree1ResourceOverflow;
    generation_count = std.math.add(
        usize,
        generation_count,
        @as(usize, plan.poseidon_chunk_count),
    ) catch return error.Tree1ResourceOverflow;
    const audit_count = if (plan.opcode_audit_enabled)
        @as(usize, plan.n_components)
    else
        0;
    const finalization_count = @as(usize, plan.n_components) +
        component_order.LOOKUP_TABLE_COUNT;
    const wave_counts = [_]usize{
        1,
        generation_count,
        1,
        audit_count,
        1,
        finalization_count,
        1,
    };
    const declared_counts = [_]usize{
        plan.task_counts.prepare_wave,
        plan.task_counts.generation_wave,
        plan.task_counts.reduce_wave,
        plan.task_counts.audit_wave,
        plan.task_counts.lookup_seed_wave,
        plan.task_counts.finalization_wave,
        plan.task_counts.seal_wave,
    };
    if (!std.mem.eql(usize, &wave_counts, &declared_counts) or
        @as(usize, plan.task_counts.descriptor_slots) != plan.descriptor_count)
    {
        return error.InvalidTree1Plan;
    }
    var total_task_count: usize = 0;
    for (wave_counts) |count| {
        total_task_count = std.math.add(
            usize,
            total_task_count,
            count,
        ) catch return error.Tree1ResourceOverflow;
    }

    const helper_count = planned_workers - 1;
    const expected_stack_bytes = std.math.mul(
        usize,
        helper_count,
        plan.worker_stack_bytes,
    ) catch return error.Tree1ResourceOverflow;
    const expected_submission_bytes = std.math.mul(
        usize,
        helper_count,
        work_pool.STRUCTURED_JOB_RESERVATION_BYTES,
    ) catch return error.Tree1ResourceOverflow;
    if (plan.resources.helper_worker_stack_bytes != expected_stack_bytes or
        plan.resources.helper_submission_bytes != expected_submission_bytes)
    {
        return error.InvalidTree1Plan;
    }

    const planned_host_bytes = try plan.requiredHostBytes();
    const helper_bytes = std.math.add(
        usize,
        expected_stack_bytes,
        expected_submission_bytes,
    ) catch return error.Tree1ResourceOverflow;
    if (planned_host_bytes > plan.host_byte_budget or
        helper_bytes > planned_host_bytes)
    {
        return error.TaskMemoryBudgetExceeded;
    }
    const resident_bytes = planned_host_bytes - helper_bytes;
    if (plan.resources.main_output_payload_bytes > resident_bytes) {
        return error.InvalidTree1Plan;
    }
    return .{
        .wave_counts = wave_counts,
        .total_task_count = total_task_count,
        .admission = .{
            .host_byte_budget = plan.host_byte_budget,
            .planned_host_bytes = planned_host_bytes,
            .final_output_bytes = plan.resources.main_output_payload_bytes,
            .shared_resident_bytes = resident_bytes -
                plan.resources.main_output_payload_bytes,
            .helper_worker_stack_bytes = expected_stack_bytes,
            .helper_submission_bytes = expected_submission_bytes,
        },
    };
}

fn beginWave(
    ranges: *[types.WAVE_COUNT]TaskRange,
    wave: types.Wave,
    cursor: usize,
    counts: [types.WAVE_COUNT]usize,
) !void {
    const index = types.waveIndex(wave);
    ranges[index] = .{ .start = cursor, .len = counts[index] };
    if (index > 0) {
        const previous = ranges[index - 1];
        if (previous.start + previous.len != cursor) {
            return error.InvalidTree1Plan;
        }
    }
}

fn appendTask(
    graph: *task_graph.ComponentTaskGraph,
    records: []TaskRecord,
    cursor: *usize,
    kernel: types.Kernel,
    admission: types.Admission,
    worker_stack_bytes: usize,
    descriptor: types.Task,
) !void {
    if (cursor.* >= records.len) return error.InvalidTree1Plan;
    const record = &records[cursor.*];
    record.* = .{ .descriptor = descriptor, .kernel = kernel };
    const anchor = graph.count == 0;
    const work_units: u64 = if (descriptor.rows) |rows| rows.len else 0;
    const class = types.taskClass(descriptor.kind);
    _ = try graph.addTask(.{
        .key = descriptor.key,
        .name = types.taskName(descriptor.kind),
        .stage_id = "riscv.main_trace.tree1",
        .component_kind = types.taskName(descriptor.kind),
        .func = TaskRecord.run,
        .context = record,
        .class = class,
        .parallel_eligible = class == .leaf,
        .resources = .{
            .final_output_bytes = if (anchor)
                admission.final_output_bytes
            else
                0,
            .shared_resident_bytes = if (anchor)
                admission.shared_resident_bytes
            else
                0,
            .worker_stack_bytes = worker_stack_bytes,
        },
        .work_estimate = work_units,
        .work_unit = if (descriptor.rows != null) .rows else .unspecified,
        .planned_work_units = work_units,
    });
    cursor.* += 1;
}

fn task(kind: types.TaskKind, key: task_graph.TaskKey) types.Task {
    return .{
        .key = key,
        .kind = kind,
        .registry_index = null,
        .chunk_index = 0,
        .rows = null,
        .columns = null,
    };
}

fn validateCanonicalOrder(tasks: []const TaskRecord) !void {
    for (tasks[1..], tasks[0 .. tasks.len - 1]) |current, previous| {
        if (!previous.descriptor.key.lessThan(current.descriptor.key)) {
            return error.NonCanonicalTree1TaskOrder;
        }
    }
}

fn lookupStart(plan: *const plan_mod.Plan) usize {
    return @as(usize, plan.n_infra) - component_order.LOOKUP_TABLE_COUNT;
}
