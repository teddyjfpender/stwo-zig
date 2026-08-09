//! Integration tests for coordinator-prepared composition-domain tasks.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const accumulation = @import("accumulation.zig");
const component_parallel = @import("component_parallel.zig");
const prepared_domain = @import("prepared_domain.zig");
const task_graph = @import("../task_graph.zig");
const work_pool = @import("../work_pool.zig");

const QM31 = qm31.QM31;

const Control = struct {
    prepare_calls: std.atomic.Value(usize) = .init(0),
    run_calls: std.atomic.Value(usize) = .init(0),
    legacy_calls: std.atomic.Value(usize) = .init(0),
    live_states: std.atomic.Value(usize) = .init(0),
    barrier_target: usize = 0,
    barrier_entered: std.atomic.Value(usize) = .init(0),
    barrier_open: std.Thread.ResetEvent = .{},

    fn waitAtBarrier(self: *Control) !void {
        if (self.barrier_target == 0) return;
        const entered = self.barrier_entered.fetchAdd(1, .acq_rel) + 1;
        if (entered == self.barrier_target) {
            self.barrier_open.set();
            return;
        }
        try self.barrier_open.timedWait(5 * std.time.ns_per_s);
    }
};

const PreparedState = struct {
    allocator: std.mem.Allocator,
    accumulators: []accumulation.ColumnAccumulator,
    control: *Control,
    value: QM31,
    run_error: ?anyerror,

    fn run(raw: *anyopaque, context: *task_graph.TaskContext) anyerror!void {
        const self: *PreparedState = @ptrCast(@alignCast(raw));
        // Cooperative cancellation is not itself a task failure. The graph
        // retains ownership of the canonical failure that requested it.
        if (context.isCancelled()) return;
        _ = self.control.run_calls.fetchAdd(1, .monotonic);
        try self.control.waitAtBarrier();
        if (self.run_error) |run_error| return run_error;
        for (self.accumulators) |*column| {
            var folded = QM31.zero();
            for (column.random_coeff_powers) |power| {
                folded = folded.add(self.value.mul(power));
            }
            for (0..4) |row| column.accumulate(row, folded);
        }
    }

    fn deinit(raw: *anyopaque) void {
        const self: *PreparedState = @ptrCast(@alignCast(raw));
        const allocator = self.allocator;
        allocator.free(self.accumulators);
        _ = self.control.live_states.fetchSub(1, .monotonic);
        allocator.destroy(self);
    }

    const vtable = prepared_domain.VTable{
        .run = run,
        .deinit = deinit,
    };
};

const MockComponent = struct {
    registry_index: u32,
    value: QM31,
    control: *Control,
    /// Mirrors `ComponentProver`'s capability marker. The generic scheduler
    /// deliberately selects the prepared path only when every marker is set.
    prepare_domain_evaluator: ?u8 = 0,
    domain_parallel_evaluator: ?u8 = null,
    pool_exclusive_domain: bool = false,
    preparation_error: ?anyerror = null,
    run_error: ?anyerror = null,
    worker_stack_bytes: usize = 4096,
    declared_constraints: usize = 1,
    emitted_constraints: usize = 1,

    pub fn nConstraints(self: MockComponent) usize {
        return self.declared_constraints;
    }

    pub fn maxConstraintLogDegreeBound(_: MockComponent) u32 {
        return 2;
    }

    pub fn prepareConstraintQuotientsOnDomain(
        self: MockComponent,
        allocator: std.mem.Allocator,
        _: *const u8,
        accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!?prepared_domain.PreparedDomainEvaluation {
        _ = self.control.prepare_calls.fetchAdd(1, .monotonic);
        if (self.preparation_error) |prepare_error| return prepare_error;

        const accumulators = try accumulator.columns(allocator, &.{.{
            .log_size = 2,
            .n_cols = self.emitted_constraints,
        }});
        errdefer allocator.free(accumulators);
        const state = try allocator.create(PreparedState);
        state.* = .{
            .allocator = allocator,
            .accumulators = accumulators,
            .control = self.control,
            .value = self.value,
            .run_error = self.run_error,
        };
        _ = self.control.live_states.fetchAdd(1, .monotonic);
        return .{
            .context = state,
            .vtable = &PreparedState.vtable,
            .task_class = .leaf,
            .resources = .{
                .final_output_bytes = @sizeOf(QM31) * 4,
                .worker_stack_bytes = self.worker_stack_bytes,
            },
        };
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: MockComponent,
        _: *const u8,
        accumulator: *accumulation.DomainEvaluationAccumulator,
    ) anyerror!void {
        _ = self.control.legacy_calls.fetchAdd(1, .monotonic);
        for (0..self.emitted_constraints) |_| {
            try accumulator.accumulateConstant(2, self.value);
        }
    }

    pub fn evaluateConstraintQuotientsOnDomainParallel(
        self: MockComponent,
        trace: *const u8,
        accumulator: *accumulation.DomainEvaluationAccumulator,
        _: *work_pool.WorkPool,
    ) anyerror!void {
        return self.evaluateConstraintQuotientsOnDomain(trace, accumulator);
    }
};

fn component(index: u32, value: u32, control: *Control) MockComponent {
    return .{
        .registry_index = index,
        .value = QM31.fromU32Unchecked(value, 0, 0, 0),
        .control = control,
    };
}

fn runComposition(
    allocator: std.mem.Allocator,
    components: []const MockComponent,
    worker_count: usize,
) !@import("../secure_column.zig").SecureColumnByCoords {
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = worker_count,
        .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer pool.deinit();
    return runCompositionWithPool(allocator, components, &pool);
}

fn runCompositionWithPool(
    allocator: std.mem.Allocator,
    components: []const MockComponent,
    pool: *work_pool.WorkPool,
) !@import("../secure_column.zig").SecureColumnByCoords {
    const trace: u8 = 0;
    var total_constraints: usize = 0;
    for (components) |mock| {
        total_constraints = std.math.add(
            usize,
            total_constraints,
            mock.nConstraints(),
        ) catch return error.ConstraintCountOverflow;
    }
    return component_parallel.compute(
        allocator,
        components,
        2,
        total_constraints,
        QM31.fromU32Unchecked(3, 1, 0, 0),
        &trace,
        pool,
    );
}

fn expectConstantColumn(
    column: anytype,
    expected: QM31,
) !void {
    try std.testing.expectEqual(@as(usize, 4), column.len());
    for (0..column.len()) |row| {
        try std.testing.expect(column.at(row).eql(expected));
    }
}

test "prepared composition is canonical with one two and four workers" {
    const allocator = std.testing.allocator;
    var control = Control{};
    const components = [_]MockComponent{
        component(0, 5, &control),
        component(1, 7, &control),
        component(2, 11, &control),
        component(3, 13, &control),
    };
    const alpha = QM31.fromU32Unchecked(3, 1, 0, 0);
    const expected = components[0].value.mul(alpha.mul(alpha).mul(alpha))
        .add(components[1].value.mul(alpha.mul(alpha)))
        .add(components[2].value.mul(alpha))
        .add(components[3].value);

    for ([_]usize{ 1, 2, 4 }) |worker_count| {
        var output = try runComposition(allocator, &components, worker_count);
        defer output.deinit(allocator);
        try expectConstantColumn(&output, expected);
    }
    try std.testing.expectEqual(@as(usize, 12), control.prepare_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 12), control.run_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.legacy_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.live_states.load(.acquire));
}

test "mixed prepared capabilities retain the exact legacy path" {
    const allocator = std.testing.allocator;
    var control = Control{};
    var components = [_]MockComponent{
        component(0, 17, &control),
        component(1, 19, &control),
    };
    components[1].prepare_domain_evaluator = null;
    const alpha = QM31.fromU32Unchecked(3, 1, 0, 0);
    const expected = components[0].value.mul(alpha).add(components[1].value);

    var output = try runComposition(allocator, &components, 1);
    defer output.deinit(allocator);
    try expectConstantColumn(&output, expected);
    try std.testing.expectEqual(@as(usize, 0), control.prepare_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.run_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), control.legacy_calls.load(.acquire));
}

test "prepared composition retains identity when the shared lease is busy" {
    const allocator = std.testing.allocator;
    var control = Control{};
    const components = [_]MockComponent{
        component(0, 53, &control),
        component(1, 59, &control),
    };
    const alpha = QM31.fromU32Unchecked(3, 1, 0, 0);
    const expected = components[0].value.mul(alpha).add(components[1].value);

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer pool.deinit();
    var competing_lease = try pool.acquire(try work_pool.WorkerBudget.init(2));
    defer competing_lease.deinit();

    var output = try runCompositionWithPool(allocator, &components, &pool);
    defer output.deinit(allocator);
    try expectConstantColumn(&output, expected);
    try std.testing.expectEqual(@as(usize, 2), control.prepare_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 2), control.run_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.legacy_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.live_states.load(.acquire));
}

test "prepared composition rejects an undersized helper stack before run" {
    const allocator = std.testing.allocator;
    var control = Control{};
    var components = [_]MockComponent{
        component(0, 61, &control),
        component(1, 67, &control),
    };
    components[1].worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES;

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES / 2,
    });
    defer pool.deinit();

    try std.testing.expectError(
        error.TaskWorkerStackExceeded,
        runCompositionWithPool(allocator, &components, &pool),
    );
    try std.testing.expectEqual(@as(usize, 2), control.prepare_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.run_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.live_states.load(.acquire));
}

test "prepared composition rejects a component that under-consumes its power range" {
    const allocator = std.testing.allocator;
    var control = Control{};
    var components = [_]MockComponent{
        component(0, 71, &control),
        component(1, 73, &control),
    };
    components[0].emitted_constraints = 0;

    try std.testing.expectError(
        error.ConstraintPowerRangeMismatch,
        runComposition(allocator, &components, 2),
    );
    try std.testing.expectEqual(@as(usize, 0), control.run_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.live_states.load(.acquire));
}

test "legacy parallel composition rejects a component power-range mismatch" {
    const allocator = std.testing.allocator;
    var control = Control{};
    var components = [_]MockComponent{
        component(0, 79, &control),
        component(1, 83, &control),
    };
    components[0].emitted_constraints = 0;
    components[1].prepare_domain_evaluator = null;

    try std.testing.expectError(
        error.ConstraintPowerRangeMismatch,
        runComposition(allocator, &components, 2),
    );
    try std.testing.expectEqual(@as(usize, 2), control.legacy_calls.load(.acquire));
}

test "preparation failure rolls back every owner before task launch" {
    const allocator = std.testing.allocator;
    var control = Control{};
    var components = [_]MockComponent{
        component(0, 23, &control),
        component(1, 29, &control),
        component(2, 31, &control),
    };
    components[1].preparation_error = error.PreparationFailure;

    try std.testing.expectError(
        error.PreparationFailure,
        runComposition(allocator, &components, 2),
    );
    try std.testing.expectEqual(@as(usize, 2), control.prepare_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.run_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.live_states.load(.acquire));
}

test "task capacity rejection occurs before component preparation" {
    const allocator = std.testing.allocator;
    var control = Control{};
    const components = try allocator.alloc(
        MockComponent,
        task_graph.MAX_COMPONENT_TASKS + 1,
    );
    defer allocator.free(components);
    for (components, 0..) |*mock, index| {
        mock.* = component(@intCast(index), 1, &control);
    }

    try std.testing.expectError(
        error.InvalidTaskCapacity,
        runComposition(allocator, components, 1),
    );
    try std.testing.expectEqual(@as(usize, 0), control.prepare_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.run_calls.load(.acquire));
}

test "simultaneous prepared failures report the lowest component key" {
    const allocator = std.testing.allocator;
    var control = Control{ .barrier_target = 2 };
    var components = [_]MockComponent{
        component(0, 37, &control),
        component(1, 41, &control),
    };
    components[0].run_error = error.CanonicalFailure;
    components[1].run_error = error.LaterFailure;

    try std.testing.expectError(
        error.CanonicalFailure,
        runComposition(allocator, &components, 2),
    );
    try std.testing.expectEqual(@as(usize, 2), control.run_calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), control.live_states.load(.acquire));
}

test "prepared domain run performs no allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    const powers = try accumulation.generateSecurePowers(
        allocator,
        QM31.fromU32Unchecked(3, 1, 0, 0),
        1,
    );
    defer allocator.free(powers);
    var accumulator = try accumulation.DomainEvaluationAccumulator.initForComponent(
        powers,
        allocator,
        2,
        1,
    );
    defer accumulator.deinit();
    var control = Control{};
    const mock = component(0, 43, &control);
    const trace: u8 = 0;
    var prepared = (try mock.prepareConstraintQuotientsOnDomain(
        allocator,
        &trace,
        &accumulator,
    )).?;
    defer prepared.deinit();

    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    var cancellation = task_graph.CancellationToken{};
    var context = task_graph.TaskContext{
        .user_context = prepared.context,
        .cancellation = &cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
    try prepared.run(&context);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), accumulator.next_power_index);
}
