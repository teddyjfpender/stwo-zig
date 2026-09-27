//! Differential and adversarial tests for the prepared Tree-1 epoch.

const std = @import("std");
const prover_engine = @import("stwo_prover_engine");
const component_order = @import("../air/component_order.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace_mod = @import("../runner/trace.zig");
const execution = @import("main_trace_plan_execution.zig");
const plan_mod = @import("main_trace_plan.zig");

const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;

const OPCODE_ROWS: usize = 4 * plan_mod.OPCODE_ROWS_PER_CHUNK;
const POSEIDON_ROWS: usize = 4 * plan_mod.POSEIDON_ROWS_PER_CHUNK;
const TEST_STACK_BYTES: usize = 64 * 1024;

fn testStatement() statement_mod.RiscVStatement {
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = 4;
    statement.initial_pc = 0;
    statement.final_pc = 0;
    statement.public_data = undefined;
    statement.total_steps = 0;
    for (0..4) |index| {
        statement.component_descs[index] = .{
            .family = .auipc,
            .log_size = 16,
            .n_rows = plan_mod.OPCODE_ROWS_PER_CHUNK,
            .n_columns = trace_mod.nColumnsForFamily(.auipc),
        };
        statement.total_steps += plan_mod.OPCODE_ROWS_PER_CHUNK;
    }

    var infra_index: usize = 0;
    statement.infra_descs[infra_index] = .{
        .kind = .program,
        .log_size = 2,
        .n_rows = 4,
        .n_columns = program_commitment.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .memory,
        .log_size = 4,
        .n_rows = 16,
        .n_columns = memory_trace.N_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .merkle,
        .log_size = 14,
        .n_rows = POSEIDON_ROWS,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .poseidon2,
        .log_size = 14,
        .n_rows = POSEIDON_ROWS,
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .clock_update,
        .log_size = 4,
        .n_rows = 16,
        .n_columns = infra.CLOCK_UPDATE_COLS,
    };
    infra_index += 1;
    for (component_order.lookupTables()) |kind| {
        statement.infra_descs[infra_index] = .{
            .kind = statement_mod.infraKindForTable(kind),
            .log_size = lookup_schema.logSize(kind),
            .n_rows = @intCast(lookup_schema.size(kind)),
            .n_columns = 1,
        };
        infra_index += 1;
    }
    statement.n_infra = @intCast(infra_index);
    return statement;
}

fn testOptions(workers: usize) plan_mod.BuildOptions {
    return .{
        .execution = .{
            .worker_count = workers,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        },
        .pool_capacity = workers,
        .worker_stack_bytes = TEST_STACK_BYTES,
        .enable_opcode_audit = true,
    };
}

const KernelMode = union(enum) {
    normal,
    reject_nested,
    fail_lookup_seed,
    fail_started_opcode_wave: struct {
        width: usize,
        failing_chunk: u32,
    },
};

const SyntheticKernel = struct {
    opcode: []u64,
    poseidon: []u64,
    infrastructure: []u64,
    mode: KernelMode = .normal,
    expected_generation: usize,
    expected_audits: usize,
    expected_finalization: usize,
    callback_runs: std.atomic.Value(usize) = .init(0),
    barrier_arrivals: std.atomic.Value(usize) = .init(0),
    nested_rejections: std.atomic.Value(usize) = .init(0),
    prepare_done: std.atomic.Value(bool) = .init(false),
    generation_done: std.atomic.Value(usize) = .init(0),
    reduce_done: std.atomic.Value(bool) = .init(false),
    audits_done: std.atomic.Value(usize) = .init(0),
    lookup_seed_done: std.atomic.Value(bool) = .init(false),
    finalization_done: std.atomic.Value(usize) = .init(0),
    reduced_word: std.atomic.Value(u64) = .init(0),
    lookup_seed_word: std.atomic.Value(u64) = .init(0),
    seal_word: std.atomic.Value(u64) = .init(0),
    seal_done: std.atomic.Value(bool) = .init(false),

    fn run(
        opaque_context: *anyopaque,
        task: *const execution.Task,
        context: *task_graph.TaskContext,
    ) anyerror!void {
        const self: *SyntheticKernel = @ptrCast(@alignCast(opaque_context));
        _ = self.callback_runs.fetchAdd(1, .monotonic);
        const expected_class: task_graph.TaskClass = switch (task.kind) {
            .prepare, .opcode_reduce, .lookup_seed, .seal => .coordinator,
            else => .leaf,
        };
        if (context.worker_budget.count != 1 or
            context.task_class != expected_class)
        {
            return error.LeafObservedNestedWorkerBudget;
        }

        switch (self.mode) {
            .normal => {},
            .fail_lookup_seed => {
                if (task.kind == .lookup_seed) {
                    return error.InjectedLookupSeedFailure;
                }
            },
            .reject_nested => {
                context.spawnChild(child, .{}) catch |failure| {
                    if (failure != error.NestedSubmissionRejected) return failure;
                    _ = self.nested_rejections.fetchAdd(1, .monotonic);
                };
            },
            .fail_started_opcode_wave => |failure_plan| {
                if (task.kind == .opcode_fill and
                    task.chunk_index < failure_plan.width)
                {
                    _ = self.barrier_arrivals.fetchAdd(1, .acq_rel);
                    while (self.barrier_arrivals.load(.acquire) <
                        failure_plan.width)
                    {
                        std.atomic.spinLoopHint();
                    }
                    if (task.chunk_index == failure_plan.failing_chunk) {
                        return error.InjectedGenerationFailure;
                    }
                    while (!context.isCancelled()) std.atomic.spinLoopHint();
                    return;
                }
            },
        }

        // Perturb completion order without changing semantic placement.
        var spins: usize = @as(usize, task.key.shard_or_chunk_index % 7) * 31;
        while (spins > 0) : (spins -= 1) std.atomic.spinLoopHint();
        switch (task.kind) {
            .prepare => {
                if (self.prepare_done.swap(true, .acq_rel)) {
                    return error.DuplicateSyntheticPrepare;
                }
            },
            .opcode_fill => {
                if (!self.prepare_done.load(.acquire)) {
                    return error.GenerationCrossedPrepareBarrier;
                }
                const rows = task.rows.?;
                const end: usize = @intCast(try rows.end());
                if (end > self.opcode.len) return error.TestOutputRangeOverflow;
                for (@as(usize, rows.start)..end) |row| {
                    self.opcode[row] = semanticWord(row, 0x4f50_434f_4445);
                }
                _ = self.generation_done.fetchAdd(1, .release);
            },
            .poseidon_fill => {
                if (!self.prepare_done.load(.acquire)) {
                    return error.GenerationCrossedPrepareBarrier;
                }
                const rows = task.rows.?;
                const end: usize = @intCast(try rows.end());
                if (end > self.poseidon.len) return error.TestOutputRangeOverflow;
                for (@as(usize, rows.start)..end) |row| {
                    self.poseidon[row] = semanticWord(row, 0x5032_4d33_3156);
                }
                _ = self.generation_done.fetchAdd(1, .release);
            },
            .infrastructure_fill => {
                if (!self.prepare_done.load(.acquire)) {
                    return error.GenerationCrossedPrepareBarrier;
                }
                const registry_index: usize = @intCast(task.registry_index.?);
                if (registry_index >= self.infrastructure.len) {
                    return error.TestOutputRangeOverflow;
                }
                self.infrastructure[registry_index] = semanticWord(
                    registry_index,
                    0x494e_4652_4100,
                );
                _ = self.generation_done.fetchAdd(1, .release);
            },
            .opcode_reduce => {
                if (self.generation_done.load(.acquire) !=
                    self.expected_generation)
                {
                    return error.ReduceCrossedGenerationBarrier;
                }
                var reduced: u64 = 0x5452_4545_3152_4544;
                for (self.opcode) |word| reduced = foldWord(reduced, word);
                for (self.poseidon) |word| reduced = foldWord(reduced, word);
                self.reduced_word.store(reduced, .release);
                self.reduce_done.store(true, .release);
            },
            .opcode_audit => {
                if (!self.reduce_done.load(.acquire)) {
                    return error.AuditCrossedReduceBarrier;
                }
                _ = self.audits_done.fetchAdd(1, .release);
            },
            .lookup_seed => {
                if (!self.reduce_done.load(.acquire) or
                    self.audits_done.load(.acquire) != self.expected_audits)
                {
                    return error.LookupSeedCrossedAuditBarrier;
                }
                self.lookup_seed_word.store(
                    foldWord(
                        self.reduced_word.load(.acquire),
                        0x4c4f_4f4b_5550_5345,
                    ),
                    .release,
                );
                self.lookup_seed_done.store(true, .release);
            },
            .opcode_finalize, .lookup_finalize => {
                if (!self.lookup_seed_done.load(.acquire)) {
                    return error.FinalizationCrossedLookupSeedBarrier;
                }
                const registry_index: usize = @intCast(task.registry_index.?);
                if (registry_index >= self.infrastructure.len) {
                    return error.TestOutputRangeOverflow;
                }
                self.infrastructure[registry_index] = semanticWord(
                    registry_index,
                    self.lookup_seed_word.load(.acquire),
                );
                _ = self.finalization_done.fetchAdd(1, .release);
            },
            .seal => {
                if (self.finalization_done.load(.acquire) !=
                    self.expected_finalization)
                {
                    return error.SealCrossedFinalizationBarrier;
                }
                var sealed = self.lookup_seed_word.load(.acquire);
                for (self.infrastructure) |word| sealed = foldWord(sealed, word);
                self.seal_word.store(sealed, .release);
                self.seal_done.store(true, .release);
            },
        }
    }

    fn child() void {}
};

fn initSyntheticKernel(
    plan: *const plan_mod.Plan,
    opcode: []u64,
    poseidon: []u64,
    infrastructure: []u64,
    mode: KernelMode,
) SyntheticKernel {
    return .{
        .opcode = opcode,
        .poseidon = poseidon,
        .infrastructure = infrastructure,
        .mode = mode,
        .expected_generation = plan.task_counts.generation_wave,
        .expected_audits = plan.task_counts.audit_wave,
        .expected_finalization = plan.task_counts.finalization_wave,
    };
}

fn foldWord(accumulator: u64, word: u64) u64 {
    return (accumulator ^ word) *% 0x9e37_79b9_7f4a_7c15;
}

fn semanticWord(index: usize, domain: u64) u64 {
    var value: u64 = @intCast(index);
    value = (value *% 0x9e37_79b9_7f4a_7c15) ^ domain;
    value ^= value >> 29;
    return value *% 0xbf58_476d_1ce4_e5b9;
}

const RunResult = struct {
    opcode: []u64,
    poseidon: []u64,
    infrastructure: []u64,
    keys: []task_graph.TaskKey,
    seal_word: u64,
    report: execution.EpochReport,
    admission: execution.Admission,

    fn deinit(self: *RunResult, allocator: std.mem.Allocator) void {
        allocator.free(self.opcode);
        allocator.free(self.poseidon);
        allocator.free(self.infrastructure);
        allocator.free(self.keys);
        self.* = undefined;
    }
};

fn runSynthetic(workers: usize) !RunResult {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(workers));

    const opcode = try allocator.alloc(u64, OPCODE_ROWS);
    errdefer allocator.free(opcode);
    const poseidon = try allocator.alloc(u64, POSEIDON_ROWS);
    errdefer allocator.free(poseidon);
    const infrastructure = try allocator.alloc(u64, plan.descriptor_count);
    errdefer allocator.free(infrastructure);
    @memset(opcode, 0);
    @memset(poseidon, 0);
    @memset(infrastructure, std.math.maxInt(u64));

    var kernel = initSyntheticKernel(
        &plan,
        opcode,
        poseidon,
        infrastructure,
        .normal,
    );
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        .{ .context = &kernel, .run = SyntheticKernel.run },
    );
    defer prepared.deinit();

    var pool: work_pool.WorkPool = undefined;
    var pool_initialized = false;
    defer if (pool_initialized) pool.deinit();
    if (workers > 1) {
        try pool.initInPlaceWithOptions(.{
            .worker_count = workers,
            .stack_size = TEST_STACK_BYTES,
            .backing_allocator = allocator,
        });
        pool_initialized = true;
    }
    const report = try prepared.execute(if (pool_initialized) &pool else null);
    if (!kernel.seal_done.load(.acquire)) return error.SyntheticSealMissing;
    inline for (std.meta.fields(execution.Wave)) |field| {
        const wave: execution.Wave = @enumFromInt(field.value);
        const wave_report = prepared.waveReport(wave) orelse
            return error.SyntheticWaveReportMissing;
        if (wave_report.peak_reserved_bytes !=
            prepared.admission().planned_host_bytes)
        {
            return error.SyntheticWaveResourceDrift;
        }
    }
    const keys = try allocator.alloc(task_graph.TaskKey, prepared.plannedTaskCount());
    errdefer allocator.free(keys);
    for (keys, 0..) |*key, index| {
        key.* = (try prepared.publishedTask(index)).key;
    }
    return .{
        .opcode = opcode,
        .poseidon = poseidon,
        .infrastructure = infrastructure,
        .keys = keys,
        .seal_word = kernel.seal_word.load(.acquire),
        .report = report,
        .admission = prepared.admission(),
    };
}

fn expectCanonicalKeys(keys: []const task_graph.TaskKey) !void {
    for (keys[1..], keys[0 .. keys.len - 1]) |current, previous| {
        try std.testing.expect(previous.lessThan(current));
    }
}

fn expectCompleteOutput(result: *const RunResult) !void {
    for (result.opcode, 0..) |actual, row| {
        try std.testing.expectEqual(
            semanticWord(row, 0x4f50_434f_4445),
            actual,
        );
    }
    for (result.poseidon, 0..) |actual, row| {
        try std.testing.expectEqual(
            semanticWord(row, 0x5032_4d33_3156),
            actual,
        );
    }
}

test "main trace epoch: N=1/2/4 preserve exact bytes and canonical publication" {
    const allocator = std.testing.allocator;
    var serial = try runSynthetic(1);
    defer serial.deinit(allocator);
    var dual = try runSynthetic(2);
    defer dual.deinit(allocator);
    var quad = try runSynthetic(4);
    defer quad.deinit(allocator);

    try std.testing.expectEqualSlices(u64, serial.opcode, dual.opcode);
    try std.testing.expectEqualSlices(u64, serial.opcode, quad.opcode);
    try std.testing.expectEqualSlices(u64, serial.poseidon, dual.poseidon);
    try std.testing.expectEqualSlices(u64, serial.poseidon, quad.poseidon);
    try std.testing.expectEqualSlices(
        u64,
        serial.infrastructure,
        dual.infrastructure,
    );
    try std.testing.expectEqualSlices(
        u64,
        serial.infrastructure,
        quad.infrastructure,
    );
    try std.testing.expectEqual(serial.seal_word, dual.seal_word);
    try std.testing.expectEqual(serial.seal_word, quad.seal_word);
    try expectCompleteOutput(&serial);
    try expectCanonicalKeys(serial.keys);
    try expectCanonicalKeys(dual.keys);
    try expectCanonicalKeys(quad.keys);

    for (
        [_]*const RunResult{ &serial, &dual, &quad },
        [_]usize{ 1, 2, 4 },
    ) |result, workers| {
        try std.testing.expectEqual(workers, result.report.configured_workers);
        try std.testing.expectEqual(@as(usize, 7), result.report.attempted_waves);
        try std.testing.expectEqual(result.keys.len, result.report.succeeded_tasks);
        try std.testing.expectEqual(@as(usize, 0), result.report.failed_tasks);
        try std.testing.expectEqual(@as(usize, 0), result.report.cancelled_tasks);
        try std.testing.expectEqual(
            result.keys.len,
            result.report.finished_tasks,
        );
        try std.testing.expectEqual(
            result.admission.planned_host_bytes,
            result.report.peak_reserved_bytes,
        );
    }
}

test "main trace epoch: execution and nested-work rejection allocate nothing" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    const opcode = try allocator.alloc(u64, OPCODE_ROWS);
    defer allocator.free(opcode);
    const poseidon = try allocator.alloc(u64, POSEIDON_ROWS);
    defer allocator.free(poseidon);
    const infrastructure = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(infrastructure);
    @memset(opcode, 0);
    @memset(poseidon, 0);
    @memset(infrastructure, std.math.maxInt(u64));

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer pool.deinit();

    var kernel = initSyntheticKernel(
        &plan,
        opcode,
        poseidon,
        infrastructure,
        .reject_nested,
    );
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var prepared = try execution.PreparedEpoch.prepare(
        failing.allocator(),
        &plan,
        .{ .context = &kernel, .run = SyntheticKernel.run },
    );
    defer prepared.deinit();
    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;

    const report = try prepared.execute(&pool);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        prepared.plannedTaskCount(),
        kernel.nested_rejections.load(.acquire),
    );
    try std.testing.expect(report.peak_active_tasks <= 4);
    try std.testing.expectEqual(
        prepared.admission().planned_host_bytes,
        report.peak_reserved_bytes,
    );
}

test "main trace epoch: injected failure joins cancellation and publishes nothing" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    const opcode = try allocator.alloc(u64, OPCODE_ROWS);
    defer allocator.free(opcode);
    const poseidon = try allocator.alloc(u64, POSEIDON_ROWS);
    defer allocator.free(poseidon);
    const infrastructure = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(infrastructure);

    var kernel = initSyntheticKernel(
        &plan,
        opcode,
        poseidon,
        infrastructure,
        .{ .fail_started_opcode_wave = .{
            .width = 4,
            .failing_chunk = 0,
        } },
    );
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        .{ .context = &kernel, .run = SyntheticKernel.run },
    );
    defer prepared.deinit();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer pool.deinit();

    try std.testing.expectError(
        error.InjectedGenerationFailure,
        prepared.execute(&pool),
    );
    try std.testing.expectEqual(execution.Lifecycle.failed, prepared.lifecycle());
    try std.testing.expectError(
        error.Tree1EpochNotPublished,
        prepared.publishedTask(0),
    );
    const report = prepared.report().?;
    try std.testing.expectEqual(@as(usize, 1), report.failed_tasks);
    try std.testing.expectEqual(@as(usize, 3), report.cancelled_tasks);
    try std.testing.expectEqual(
        prepared.plannedTaskCount() - 5,
        report.unsubmitted_cancelled_tasks,
    );
    try std.testing.expectEqual(
        prepared.plannedTaskCount(),
        report.succeeded_tasks + report.failed_tasks +
            report.cancelled_tasks + report.unsubmitted_cancelled_tasks,
    );
    try std.testing.expect(report.cancellation_winner.?.eql(
        plan_mod.opcodeFillTaskKey(0),
    ));
}

test "main trace epoch: caller cancellation is joined and transactional" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(1));
    const opcode = try allocator.alloc(u64, OPCODE_ROWS);
    defer allocator.free(opcode);
    const poseidon = try allocator.alloc(u64, POSEIDON_ROWS);
    defer allocator.free(poseidon);
    const infrastructure = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(infrastructure);
    var kernel = initSyntheticKernel(
        &plan,
        opcode,
        poseidon,
        infrastructure,
        .normal,
    );
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        .{ .context = &kernel, .run = SyntheticKernel.run },
    );
    defer prepared.deinit();

    try std.testing.expect(prepared.requestCancellation());
    try std.testing.expectError(error.Tree1EpochCancelled, prepared.execute(null));
    try std.testing.expectEqual(@as(usize, 0), kernel.callback_runs.load(.acquire));
    const report = prepared.report().?;
    try std.testing.expectEqual(
        prepared.plannedTaskCount(),
        report.unsubmitted_cancelled_tasks,
    );
    try std.testing.expectError(
        error.Tree1EpochNotPublished,
        prepared.publishedTask(0),
    );
}

test "main trace epoch: late coordinator failure drains later waves under one lease" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    const opcode = try allocator.alloc(u64, OPCODE_ROWS);
    defer allocator.free(opcode);
    const poseidon = try allocator.alloc(u64, POSEIDON_ROWS);
    defer allocator.free(poseidon);
    const infrastructure = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(infrastructure);
    @memset(opcode, 0);
    @memset(poseidon, 0);
    @memset(infrastructure, std.math.maxInt(u64));

    var kernel = initSyntheticKernel(
        &plan,
        opcode,
        poseidon,
        infrastructure,
        .fail_lookup_seed,
    );
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        .{ .context = &kernel, .run = SyntheticKernel.run },
    );
    defer prepared.deinit();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer pool.deinit();

    try std.testing.expectError(
        error.InjectedLookupSeedFailure,
        prepared.execute(&pool),
    );
    const report = prepared.report().?;
    const preceding_successes: usize = plan.task_counts.prepare_wave +
        plan.task_counts.generation_wave +
        plan.task_counts.reduce_wave +
        plan.task_counts.audit_wave;
    try std.testing.expectEqual(preceding_successes, report.succeeded_tasks);
    try std.testing.expectEqual(@as(usize, 1), report.failed_tasks);
    try std.testing.expectEqual(@as(usize, 0), report.cancelled_tasks);
    try std.testing.expectEqual(
        @as(usize, plan.task_counts.finalization_wave) +
            plan.task_counts.seal_wave,
        report.unsubmitted_cancelled_tasks,
    );
    try std.testing.expectEqual(@as(usize, 7), report.attempted_waves);
    try std.testing.expect(report.cancellation_winner.?.eql(
        plan_mod.lookupSeedTaskKey(),
    ));
    try std.testing.expectError(
        error.Tree1EpochNotPublished,
        prepared.publishedTask(0),
    );
}

test "main trace epoch: preparation and finite admission fail before launch" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    var ignored: u8 = 0;
    const NoRun = struct {
        fn run(
            _: *anyopaque,
            _: *const execution.Task,
            _: *task_graph.TaskContext,
        ) !void {
            return error.UnexpectedGenerationLaunch;
        }
    };
    const kernel = execution.Kernel{ .context = &ignored, .run = NoRun.run };

    var under_budget = plan;
    under_budget.host_byte_budget = (try plan.requiredHostBytes()) - 1;
    try std.testing.expectError(
        error.TaskMemoryBudgetExceeded,
        execution.PreparedEpoch.prepare(allocator, &under_budget, kernel),
    );
    var wrong_count = plan;
    wrong_count.task_counts.generation_wave += 1;
    try std.testing.expectError(
        error.InvalidTree1Plan,
        execution.PreparedEpoch.prepare(allocator, &wrong_count, kernel),
    );

    // Task records, state, and each exact per-wave graph allocation belong to
    // coordinator preparation. Sampled early failures must all roll back before
    // a callback can launch.
    for (0..3) |failure_index| {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = failure_index },
        );
        try std.testing.expectError(
            error.OutOfMemory,
            execution.PreparedEpoch.prepare(
                failing.allocator(),
                &plan,
                kernel,
            ),
        );
    }

    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        kernel,
    );
    defer prepared.deinit();
    try std.testing.expectError(error.WorkPoolRequired, prepared.execute(null));

    var narrow_pool: work_pool.WorkPool = undefined;
    try narrow_pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer narrow_pool.deinit();
    try std.testing.expectError(
        error.Tree1PoolCapacityMismatch,
        prepared.execute(&narrow_pool),
    );

    var wrong_stack_pool: work_pool.WorkPool = undefined;
    try wrong_stack_pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = 2 * TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer wrong_stack_pool.deinit();
    try std.testing.expectError(
        error.Tree1PoolStackSizeMismatch,
        prepared.execute(&wrong_stack_pool),
    );
    try std.testing.expectEqual(execution.Lifecycle.prepared, prepared.lifecycle());
    try std.testing.expect(prepared.report() == null);
}
