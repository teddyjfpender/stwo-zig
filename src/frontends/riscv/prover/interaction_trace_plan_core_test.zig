//! Differential, ownership, and cancellation tests for R-003.

const std = @import("std");
const builtin = @import("builtin");
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
const execution = @import("interaction_trace_plan_execution.zig");
const plan_mod = @import("interaction_trace_plan.zig");

const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;

const TEST_STACK_BYTES: usize = 128 * 1024;
const RETAINED_INPUT_BYTES: usize = 64 * 1024;
const PREPARED_GENERATOR_BYTES: usize = 96 * 1024;
const SENTINEL: u64 = std.math.maxInt(u64);
const RELATION_WORD: u64 = 0x5245_4c41_5449_4f4e;

fn testStatement() statement_mod.RiscVStatement {
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = 4;
    statement.initial_pc = 0;
    statement.final_pc = 0;
    statement.public_data = undefined;
    statement.total_steps = 0;
    const families = [_]trace_mod.OpcodeFamily{
        .auipc,
        .base_alu_imm,
        .base_alu_reg,
        .branch_eq,
    };
    const log_sizes = [_]u32{ 10, 10, 12, 10 };
    const rows = [_]u32{ 701, 613, 3_021, 887 };
    for (families, log_sizes, rows, 0..) |family, log_size, n_rows, index| {
        statement.component_descs[index] = .{
            .family = family,
            .log_size = log_size,
            .n_rows = n_rows,
            .n_columns = trace_mod.nColumnsForFamily(family),
        };
        statement.total_steps += n_rows;
    }

    var infra_index: usize = 0;
    statement.infra_descs[infra_index] = .{
        .kind = .program,
        .log_size = 6,
        .n_rows = 37,
        .n_columns = program_commitment.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .memory,
        .log_size = 16,
        .n_rows = plan_mod.OPCODE_SHARD_ROWS,
        .n_columns = memory_trace.N_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .memory,
        .log_size = 10,
        .n_rows = 777,
        .n_columns = memory_trace.N_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .merkle,
        .log_size = 12,
        .n_rows = 3_121,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .poseidon2,
        .log_size = 12,
        .n_rows = 3_121,
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .clock_update,
        .log_size = 8,
        .n_rows = 255,
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
        .retained_input_bytes = RETAINED_INPUT_BYTES,
        .prepared_generator_bytes = PREPARED_GENERATOR_BYTES,
    };
}

const KernelMode = union(enum) {
    normal,
    fail_pair: struct {
        first: u32,
        second: u32,
    },
};

const SyntheticKernel = struct {
    output: []u64,
    claims: []u64,
    relation: *const u64,
    observed_relation_addresses: []usize,
    work_sinks: []u64,
    mode: KernelMode = .normal,
    heavy_iterations: usize = 0,
    barrier_arrivals: std.atomic.Value(usize) = .init(0),
    reserve_done: std.atomic.Value(bool) = .init(false),
    producer_runs: std.atomic.Value(usize) = .init(0),
    seal_done: std.atomic.Value(bool) = .init(false),
    seal_word: std.atomic.Value(u64) = .init(0),

    fn run(
        opaque_context: *anyopaque,
        task: *const execution.Task,
        context: *task_graph.TaskContext,
    ) anyerror!void {
        const self: *SyntheticKernel = @ptrCast(@alignCast(opaque_context));
        switch (task.kind) {
            .reserve => {
                if (self.reserve_done.swap(true, .acq_rel)) {
                    return error.DuplicateSyntheticReserve;
                }
                if (!std.mem.allEqual(u64, self.output, SENTINEL) or
                    !std.mem.allEqual(u64, self.claims, SENTINEL))
                {
                    return error.SyntheticDestinationNotPristine;
                }
            },
            .seal => {
                if (!self.reserve_done.load(.acquire)) {
                    return error.SyntheticReserveMissing;
                }
                if (self.producer_runs.load(.acquire) !=
                    self.observed_relation_addresses.len)
                {
                    return error.SyntheticProducerMissing;
                }
                const expected_address = @intFromPtr(self.relation);
                for (self.observed_relation_addresses) |address| {
                    if (address != expected_address) {
                        return error.RelationPointerWasNotShared;
                    }
                }
                self.seal_word.store(
                    foldCanonical(self.output, self.claims, self.work_sinks),
                    .release,
                );
                self.seal_done.store(true, .release);
            },
            else => {
                if (!self.reserve_done.load(.acquire)) {
                    return error.ProducerCrossedReserveBarrier;
                }
                const registry_index = task.registry_index.?;
                switch (self.mode) {
                    .normal => {},
                    .fail_pair => |failure| {
                        if (registry_index == failure.first or
                            registry_index == failure.second)
                        {
                            _ = self.barrier_arrivals.fetchAdd(1, .acq_rel);
                            while (self.barrier_arrivals.load(.acquire) < 2) {
                                std.atomic.spinLoopHint();
                            }
                            if (registry_index == failure.first) {
                                return error.InjectedEarlierTree2Failure;
                            }
                            return error.InjectedLaterTree2Failure;
                        }
                    },
                }
                if (context.isCancelled()) return;
                const index: usize = @intCast(registry_index);
                self.observed_relation_addresses[index] =
                    @intFromPtr(self.relation);
                if (isHeavyRegistry(index) and self.heavy_iterations != 0) {
                    self.work_sinks[index] = heavyWord(
                        registry_index,
                        self.relation.*,
                        self.heavy_iterations,
                    );
                } else {
                    self.work_sinks[index] = semanticWord(
                        registry_index,
                        registry_index,
                        self.relation.* ^ 0x574f_524b,
                    );
                }
                writeProducer(
                    self.output,
                    self.claims,
                    task,
                    self.relation.*,
                );
                _ = self.producer_runs.fetchAdd(1, .release);
                try context.setCompletedWork(
                    @as(u64, 1) << @intCast(task.log_size),
                );
            },
        }
    }
};

fn writeProducer(
    output: []u64,
    claims: []u64,
    task: *const execution.Task,
    relation: u64,
) void {
    const registry_index = task.registry_index.?;
    const columns = task.columns.?;
    const column_start: usize = @intCast(columns.start);
    const column_end: usize = @intCast(columns.start + columns.len);
    for (output[column_start..column_end], column_start..) |*value, index| {
        value.* = semanticWord(registry_index, @intCast(index), relation);
    }
    const claim_range = task.claims.?;
    const claim_start: usize = @intCast(claim_range.start);
    const claim_end: usize = @intCast(claim_range.start + claim_range.len);
    for (claims[claim_start..claim_end], claim_start..) |*value, index| {
        value.* = semanticWord(
            registry_index,
            @intCast(index),
            relation ^ 0x434c_4149_4d00,
        );
    }
}

fn writeSerialProducer(
    output: []u64,
    claims: []u64,
    plan: *const plan_mod.Plan,
    registry_index: usize,
    relation: u64,
) void {
    const columns = plan.descriptorColumnRange(registry_index).?;
    const column_start: usize = @intCast(columns.start);
    const column_end: usize = @intCast(columns.start + columns.len);
    for (output[column_start..column_end], column_start..) |*value, index| {
        value.* = semanticWord(@intCast(registry_index), @intCast(index), relation);
    }
    const claim_range = plan.descriptorClaimRange(registry_index).?;
    const claim_start: usize = @intCast(claim_range.start);
    const claim_end: usize = @intCast(claim_range.start + claim_range.len);
    for (claims[claim_start..claim_end], claim_start..) |*value, index| {
        value.* = semanticWord(
            @intCast(registry_index),
            @intCast(index),
            relation ^ 0x434c_4149_4d00,
        );
    }
}

fn semanticWord(registry_index: u32, slot_index: u32, domain: u64) u64 {
    var value = domain ^ (@as(u64, registry_index) << 32) ^ slot_index;
    value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
    return value ^ (value >> 31);
}

fn heavyWord(registry_index: u32, relation: u64, iterations: usize) u64 {
    var value = semanticWord(registry_index, @intCast(iterations), relation);
    for (0..iterations) |iteration| {
        value +%= @as(u64, @intCast(iteration)) *% 0x9e37_79b9_7f4a_7c15;
        value ^= value >> 17;
        value *%= 0xbf58_476d_1ce4_e5b9;
        value ^= value << 23;
    }
    return value;
}

fn isHeavyRegistry(index: usize) bool {
    return index == 0 or index == 1 or index == 3 or index == 4;
}

fn foldCanonical(output: []const u64, claims: []const u64, work: []const u64) u64 {
    var result: u64 = 0x5452_4545_3253_4541;
    for (output) |word| result = (result ^ word) *% 0x9e37_79b9_7f4a_7c15;
    for (claims) |word| result = (result ^ word) *% 0x9e37_79b9_7f4a_7c15;
    for (work) |word| result = (result ^ word) *% 0x9e37_79b9_7f4a_7c15;
    return result;
}

const RunResult = struct {
    output: []u64,
    claims: []u64,
    work_sinks: []u64,
    keys: []task_graph.TaskKey,
    seal_word: u64,
    report: execution.EpochReport,
    admission: execution.Admission,

    fn deinit(self: *RunResult, allocator: std.mem.Allocator) void {
        allocator.free(self.output);
        allocator.free(self.claims);
        allocator.free(self.work_sinks);
        allocator.free(self.keys);
        self.* = undefined;
    }
};

fn runPrepared(workers: usize, heavy_iterations: usize) !RunResult {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(workers));
    const output = try allocator.alloc(u64, plan.total_columns);
    errdefer allocator.free(output);
    const claims = try allocator.alloc(u64, plan.total_claims);
    errdefer allocator.free(claims);
    const observed = try allocator.alloc(usize, plan.descriptor_count);
    defer allocator.free(observed);
    const work_sinks = try allocator.alloc(u64, plan.descriptor_count);
    errdefer allocator.free(work_sinks);
    @memset(output, SENTINEL);
    @memset(claims, SENTINEL);
    @memset(observed, 0);
    @memset(work_sinks, 0);

    const relation = RELATION_WORD;
    var kernel = SyntheticKernel{
        .output = output,
        .claims = claims,
        .relation = &relation,
        .observed_relation_addresses = observed,
        .work_sinks = work_sinks,
        .heavy_iterations = heavy_iterations,
    };
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        &statement,
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
    const keys = try allocator.alloc(task_graph.TaskKey, prepared.plannedTaskCount());
    errdefer allocator.free(keys);
    for (keys, 0..) |*key, index| {
        key.* = (try prepared.publishedTask(index)).key;
    }
    return .{
        .output = output,
        .claims = claims,
        .work_sinks = work_sinks,
        .keys = keys,
        .seal_word = kernel.seal_word.load(.acquire),
        .report = report,
        .admission = prepared.admission(),
    };
}

fn serialReference(allocator: std.mem.Allocator) !RunResult {
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(1));
    const output = try allocator.alloc(u64, plan.total_columns);
    errdefer allocator.free(output);
    const claims = try allocator.alloc(u64, plan.total_claims);
    errdefer allocator.free(claims);
    const work_sinks = try allocator.alloc(u64, plan.descriptor_count);
    errdefer allocator.free(work_sinks);
    for (0..@as(usize, plan.descriptor_count)) |registry_index| {
        writeSerialProducer(output, claims, &plan, registry_index, RELATION_WORD);
        work_sinks[registry_index] = semanticWord(
            @intCast(registry_index),
            @intCast(registry_index),
            RELATION_WORD ^ 0x574f_524b,
        );
    }
    const keys = try allocator.alloc(task_graph.TaskKey, 0);
    return .{
        .output = output,
        .claims = claims,
        .work_sinks = work_sinks,
        .keys = keys,
        .seal_word = foldCanonical(output, claims, work_sinks),
        .report = undefined,
        .admission = undefined,
    };
}

fn expectCanonicalKeys(keys: []const task_graph.TaskKey) !void {
    for (keys[1..], keys[0 .. keys.len - 1]) |current, previous| {
        try std.testing.expect(previous.lessThan(current));
    }
}

test "interaction trace plan: exact statement ranges claims classes and budget" {
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    try plan_mod.validate(&plan, &statement);
    try std.testing.expectEqual(
        @as(u32, statement.nInteractionColumns()),
        plan.total_columns,
    );
    try std.testing.expectEqual(plan.total_columns / 4, plan.total_claims);
    try std.testing.expectEqual(
        @sizeOf(statement_mod.RiscVInteractionClaim),
        plan.resources.claim_payload_bytes,
    );
    try std.testing.expectEqual(
        @as(u16, @intCast(statement.n_components + statement.n_infra)),
        plan.descriptor_count,
    );
    try std.testing.expectEqual(
        @as(u16, plan.descriptor_count),
        plan.task_counts.producer_wave,
    );
    try std.testing.expectEqual(
        @as(usize, plan.descriptor_count + 2),
        try plan.task_counts.total(),
    );

    var column_cursor: u32 = 0;
    var claim_cursor: u32 = 0;
    for (0..@as(usize, plan.descriptor_count)) |registry_index| {
        const columns = plan.descriptorColumnRange(registry_index).?;
        const claims = plan.descriptorClaimRange(registry_index).?;
        try std.testing.expectEqual(column_cursor, columns.start);
        try std.testing.expectEqual(claim_cursor, claims.start);
        try std.testing.expectEqual(columns.len / 4, claims.len);
        column_cursor = try columns.end();
        claim_cursor = try claims.end();
    }
    try std.testing.expectEqual(plan.total_columns, column_cursor);
    try std.testing.expectEqual(plan.total_claims, claim_cursor);
    try std.testing.expectEqual(
        task_graph.TaskClass.leaf,
        plan.descriptorClass(0).?,
    );
    try std.testing.expectEqual(
        task_graph.TaskClass.pool_exclusive,
        plan.descriptorClass(2).?,
    );
    try std.testing.expectEqual(
        task_graph.TaskClass.pool_exclusive,
        plan.descriptorClass(plan.descriptor_count - 1).?,
    );

    const required = try plan.requiredHostBytes();
    var exact_options = testOptions(4);
    exact_options.execution.host_byte_budget = required;
    const exact = try plan_mod.build(&statement, exact_options);
    try std.testing.expectEqual(required, try exact.requiredHostBytes());
    exact_options.execution.host_byte_budget = required - 1;
    try std.testing.expectError(
        error.TaskMemoryBudgetExceeded,
        plan_mod.build(&statement, exact_options),
    );

    var mutated = plan;
    mutated.column_offsets[1] += 4;
    try std.testing.expectError(
        error.InvalidPlan,
        plan_mod.validate(&mutated, &statement),
    );

    var compatibility = testOptions(4);
    compatibility.pool_capacity = 2;
    compatibility.execution.contention_policy = .compatibility;
    const serial_fallback = try plan_mod.build(&statement, compatibility);
    try std.testing.expectEqual(@as(u8, 1), serial_fallback.planned_worker_count);
    compatibility.execution.contention_policy = .strict;
    try std.testing.expectError(
        error.WorkerBudgetUnavailable,
        plan_mod.build(&statement, compatibility),
    );

    var invalid_geometry = statement;
    invalid_geometry.infra_descs[0].n_columns -= 1;
    try std.testing.expectError(
        error.InvalidInfrastructureDescriptor,
        plan_mod.build(&invalid_geometry, testOptions(1)),
    );
    var invalid_order = statement;
    const merkle_index: usize = 3;
    const poseidon_index: usize = 4;
    const saved = invalid_order.infra_descs[merkle_index];
    invalid_order.infra_descs[merkle_index] =
        invalid_order.infra_descs[poseidon_index];
    invalid_order.infra_descs[poseidon_index] = saved;
    try std.testing.expectError(
        error.InvalidDescriptorOrder,
        plan_mod.build(&invalid_order, testOptions(1)),
    );
}

test "interaction trace plan: N=1/2/4 equal predecessor bytes claims and seal" {
    const allocator = std.testing.allocator;
    var predecessor = try serialReference(allocator);
    defer predecessor.deinit(allocator);
    var serial = try runPrepared(1, 0);
    defer serial.deinit(allocator);
    var dual = try runPrepared(2, 0);
    defer dual.deinit(allocator);
    var quad = try runPrepared(4, 0);
    defer quad.deinit(allocator);

    for ([_]*const RunResult{ &serial, &dual, &quad }) |candidate| {
        try std.testing.expectEqualSlices(u64, predecessor.output, candidate.output);
        try std.testing.expectEqualSlices(u64, predecessor.claims, candidate.claims);
        try std.testing.expectEqualSlices(
            u64,
            predecessor.work_sinks,
            candidate.work_sinks,
        );
        try std.testing.expectEqual(predecessor.seal_word, candidate.seal_word);
        try expectCanonicalKeys(candidate.keys);
        try std.testing.expectEqual(
            candidate.keys.len,
            candidate.report.succeeded_tasks,
        );
        try std.testing.expectEqual(@as(usize, 3), candidate.report.attempted_waves);
        try std.testing.expectEqual(@as(usize, 0), candidate.report.failed_tasks);
        try std.testing.expectEqual(@as(usize, 0), candidate.report.cancelled_tasks);
        try std.testing.expectEqual(
            candidate.report.planned_tasks - 2,
            candidate.report.published_producers,
        );
        try std.testing.expectEqual(
            candidate.admission.planned_host_bytes,
            candidate.report.peak_reserved_bytes,
        );
    }
    try std.testing.expect(serial.report.peak_active_tasks <= 1);
    try std.testing.expect(dual.report.peak_active_tasks <= 2);
    try std.testing.expect(quad.report.peak_active_tasks <= 4);
}

test "interaction trace epoch: execute allocates nothing" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    const output = try allocator.alloc(u64, plan.total_columns);
    defer allocator.free(output);
    const claims = try allocator.alloc(u64, plan.total_claims);
    defer allocator.free(claims);
    const observed = try allocator.alloc(usize, plan.descriptor_count);
    defer allocator.free(observed);
    const work_sinks = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(work_sinks);
    @memset(output, SENTINEL);
    @memset(claims, SENTINEL);
    @memset(observed, 0);
    @memset(work_sinks, 0);

    const relation = RELATION_WORD;
    var kernel = SyntheticKernel{
        .output = output,
        .claims = claims,
        .relation = &relation,
        .observed_relation_addresses = observed,
        .work_sinks = work_sinks,
    };
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = failing.allocator(),
    });
    defer pool.deinit();
    var prepared = try execution.PreparedEpoch.prepare(
        failing.allocator(),
        &plan,
        &statement,
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
        prepared.admission().planned_host_bytes,
        report.peak_reserved_bytes,
    );
}

test "interaction trace epoch: simultaneous failures return lowest TaskKey and publish nothing" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    const output = try allocator.alloc(u64, plan.total_columns);
    defer allocator.free(output);
    const claims = try allocator.alloc(u64, plan.total_claims);
    defer allocator.free(claims);
    const observed = try allocator.alloc(usize, plan.descriptor_count);
    defer allocator.free(observed);
    const work_sinks = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(work_sinks);
    @memset(output, SENTINEL);
    @memset(claims, SENTINEL);
    @memset(observed, 0);
    @memset(work_sinks, 0);

    const relation = RELATION_WORD;
    var kernel = SyntheticKernel{
        .output = output,
        .claims = claims,
        .relation = &relation,
        .observed_relation_addresses = observed,
        .work_sinks = work_sinks,
        .mode = .{ .fail_pair = .{ .first = 0, .second = 1 } },
    };
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        &statement,
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
        error.InjectedEarlierTree2Failure,
        prepared.execute(&pool),
    );
    try std.testing.expectEqual(execution.Lifecycle.failed, prepared.lifecycle());
    try std.testing.expectError(
        error.Tree2EpochNotPublished,
        prepared.publishedTask(0),
    );
    const report = prepared.report().?;
    try std.testing.expectEqual(@as(usize, 2), report.failed_tasks);
    try std.testing.expectEqual(
        prepared.plannedTaskCount(),
        report.succeeded_tasks + report.failed_tasks + report.cancelled_tasks +
            report.unsubmitted_cancelled_tasks,
    );
    try std.testing.expect(report.cancellation_winner != null);
    try std.testing.expect(!kernel.seal_done.load(.acquire));
}

test "interaction trace epoch: caller cancellation drains every wave without callbacks" {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(1));
    const output = try allocator.alloc(u64, plan.total_columns);
    defer allocator.free(output);
    const claims = try allocator.alloc(u64, plan.total_claims);
    defer allocator.free(claims);
    const observed = try allocator.alloc(usize, plan.descriptor_count);
    defer allocator.free(observed);
    const work_sinks = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(work_sinks);
    @memset(output, SENTINEL);
    @memset(claims, SENTINEL);
    @memset(observed, 0);
    @memset(work_sinks, 0);
    const relation = RELATION_WORD;
    var kernel = SyntheticKernel{
        .output = output,
        .claims = claims,
        .relation = &relation,
        .observed_relation_addresses = observed,
        .work_sinks = work_sinks,
    };
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        &statement,
        .{ .context = &kernel, .run = SyntheticKernel.run },
    );
    defer prepared.deinit();
    try std.testing.expect(prepared.requestCancellation());
    try std.testing.expectError(
        error.Tree2EpochCancelled,
        prepared.execute(null),
    );
    const report = prepared.report().?;
    try std.testing.expectEqual(@as(usize, 0), report.started_tasks);
    try std.testing.expectEqual(@as(usize, 0), report.published_producers);
    try std.testing.expectEqual(
        prepared.plannedTaskCount(),
        report.unsubmitted_cancelled_tasks,
    );
    try std.testing.expect(!kernel.reserve_done.load(.acquire));
    try std.testing.expect(!kernel.seal_done.load(.acquire));
}

fn noOpKernel(
    context: *anyopaque,
    task: *const execution.Task,
    task_context: *task_graph.TaskContext,
) !void {
    _ = context;
    _ = task;
    _ = task_context;
}

fn prepareAllocationCase(allocator: std.mem.Allocator) !void {
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(4));
    var byte: u8 = 0;
    var prepared = try execution.PreparedEpoch.prepare(
        allocator,
        &plan,
        &statement,
        .{ .context = &byte, .run = noOpKernel },
    );
    prepared.deinit();
}

test "interaction trace epoch: preparation rolls back every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareAllocationCase,
        .{},
    );
}
