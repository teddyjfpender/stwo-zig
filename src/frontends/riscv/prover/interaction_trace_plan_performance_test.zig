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

const TimedResult = struct {
    elapsed_ns: u64,
    seal_word: u64,
};

fn measurePrepared(workers: usize, iterations: usize) !TimedResult {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(workers));
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
        .heavy_iterations = iterations,
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
    var timer = try std.time.Timer.start();
    _ = try prepared.execute(if (pool_initialized) &pool else null);
    return .{
        .elapsed_ns = timer.read(),
        .seal_word = kernel.seal_word.load(.acquire),
    };
}

fn measureSerial(iterations: usize) !TimedResult {
    const allocator = std.testing.allocator;
    const statement = testStatement();
    const plan = try plan_mod.build(&statement, testOptions(1));
    const output = try allocator.alloc(u64, plan.total_columns);
    defer allocator.free(output);
    const claims = try allocator.alloc(u64, plan.total_claims);
    defer allocator.free(claims);
    const work_sinks = try allocator.alloc(u64, plan.descriptor_count);
    defer allocator.free(work_sinks);
    var timer = try std.time.Timer.start();
    for (0..@as(usize, plan.descriptor_count)) |registry_index| {
        writeSerialProducer(output, claims, &plan, registry_index, RELATION_WORD);
        work_sinks[registry_index] = if (isHeavyRegistry(registry_index))
            heavyWord(@intCast(registry_index), RELATION_WORD, iterations)
        else
            semanticWord(
                @intCast(registry_index),
                @intCast(registry_index),
                RELATION_WORD ^ 0x574f_524b,
            );
    }
    const seal_word = foldCanonical(output, claims, work_sinks);
    return .{ .elapsed_ns = timer.read(), .seal_word = seal_word };
}

fn median(samples: *[3]u64) u64 {
    std.mem.sort(u64, samples, {}, comptime std.sort.asc(u64));
    return samples[1];
}

test "interaction trace epoch: paired scheduler performance sample" {
    const iterations: usize = switch (builtin.mode) {
        .Debug => 100_000,
        .ReleaseSafe => 400_000,
        .ReleaseFast, .ReleaseSmall => 1_000_000,
    };
    _ = try measureSerial(iterations / 10);
    _ = try measurePrepared(1, iterations / 10);
    _ = try measurePrepared(4, iterations / 10);

    var serial_samples: [3]u64 = undefined;
    var one_samples: [3]u64 = undefined;
    var four_samples: [3]u64 = undefined;
    var expected_seal: ?u64 = null;
    for (0..3) |index| {
        const serial = try measureSerial(iterations);
        const one = try measurePrepared(1, iterations);
        const four = try measurePrepared(4, iterations);
        expected_seal = expected_seal orelse serial.seal_word;
        try std.testing.expectEqual(expected_seal.?, serial.seal_word);
        try std.testing.expectEqual(expected_seal.?, one.seal_word);
        try std.testing.expectEqual(expected_seal.?, four.seal_word);
        serial_samples[index] = serial.elapsed_ns;
        one_samples[index] = one.elapsed_ns;
        four_samples[index] = four.elapsed_ns;
    }
    const serial_ns = median(&serial_samples);
    const one_ns = median(&one_samples);
    const four_ns = median(&four_samples);
    // A deliberately loose development ceiling catches accidental per-row
    // scheduler dispatch while leaving the normative R-006 CI gate untouched.
    try std.testing.expect(one_ns <= serial_ns * 2);
    std.debug.print(
        "R-003 synthetic {s}: serial={d}ns N1={d}ns N4={d}ns " ++
            "N1/serial={d:.3} N1/N4={d:.3}\n",
        .{
            @tagName(builtin.mode),
            serial_ns,
            one_ns,
            four_ns,
            @as(f64, @floatFromInt(one_ns)) / @as(f64, @floatFromInt(serial_ns)),
            @as(f64, @floatFromInt(one_ns)) / @as(f64, @floatFromInt(four_ns)),
        },
    );
}
