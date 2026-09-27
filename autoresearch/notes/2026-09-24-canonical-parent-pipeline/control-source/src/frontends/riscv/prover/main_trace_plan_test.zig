//! Adversarial unit tests for the pure RISC-V Tree-1 coordinator plan.

const std = @import("std");
const task_graph = @import("stwo_prover_engine").task_graph;
const component_order = @import("../air/component_order.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace_mod = @import("../runner/trace.zig");
const plan_mod = @import("main_trace_plan.zig");
const plan_types = @import("main_trace_plan_types.zig");

fn testStatement(opcode_shards: usize, poseidon_rows: u32) statement_mod.RiscVStatement {
    std.debug.assert(opcode_shards > 0 and opcode_shards <= 4);
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = @intCast(opcode_shards);
    statement.initial_pc = 0;
    statement.final_pc = 0;
    statement.public_data = undefined;
    statement.total_steps = 0;
    for (0..opcode_shards) |index| {
        const rows: u32 = if (opcode_shards == 1)
            16
        else
            plan_mod.OPCODE_ROWS_PER_CHUNK;
        statement.component_descs[index] = .{
            .family = .auipc,
            .log_size = computeOpcodeLogSize(rows),
            .n_rows = rows,
            .n_columns = trace_mod.nColumnsForFamily(.auipc),
        };
        statement.total_steps += rows;
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
    const poseidon_log = @max(@as(u32, 4), computeLogSize(poseidon_rows));
    statement.infra_descs[infra_index] = .{
        .kind = .merkle,
        .log_size = poseidon_log,
        .n_rows = poseidon_rows,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .poseidon2,
        .log_size = poseidon_log,
        .n_rows = poseidon_rows,
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

fn testOptions(workers: usize, budget: usize) plan_mod.BuildOptions {
    return .{
        .execution = .{
            .worker_count = workers,
            .host_byte_budget = budget,
            .contention_policy = .strict,
        },
        .pool_capacity = workers,
        // The production default is separately present in `BuildOptions`.
        .worker_stack_bytes = 64 * 1024,
    };
}

fn computeLogSize(count: u32) u32 {
    if (count <= 1) return 1;
    return @intCast(std.math.log2_int_ceil(u32, count));
}

fn computeOpcodeLogSize(count: u32) u32 {
    return @max(@as(u32, 4), computeLogSize(count));
}

test "main trace plan: exact descriptor and chunk coverage" {
    const statement = testStatement(1, 16);
    const plan = try plan_mod.build(&statement, testOptions(1, std.math.maxInt(usize)));
    try plan_mod.validate(&plan, &statement);

    try std.testing.expect(plan.total_columns < 2048);
    var covered = [_]bool{false} ** 2048;
    for (0..@as(usize, plan.descriptor_count)) |registry_index| {
        const range = plan.descriptorRange(registry_index).?;
        const end_offset = try range.end();
        try std.testing.expect(end_offset <= plan.total_columns);
        for (@as(usize, range.start)..@as(usize, end_offset)) |column| {
            try std.testing.expect(!covered[column]);
            covered[column] = true;
        }
    }
    for (covered[0..@as(usize, plan.total_columns)]) |was_covered|
        try std.testing.expect(was_covered);
    try std.testing.expect(plan.descriptorRange(plan.descriptor_count) == null);
    try std.testing.expectEqual(
        trace_mod.nColumnsForFamily(.auipc),
        plan.componentRange(0).?.len,
    );
    try std.testing.expectEqual(
        @as(u32, poseidon2_air.N_MAIN_COLUMNS),
        plan.infrastructureRange(plan.poseidon_infra_index).?.len,
    );
    try plan_types.validateAlignedPartition(
        plan.opcodeChunks(),
        statement.total_steps,
        plan_mod.OPCODE_ROWS_PER_CHUNK,
    );
    try plan_types.validateAlignedPartition(
        plan.poseidonChunks(),
        16,
        plan_mod.POSEIDON_ROWS_PER_CHUNK,
    );

    var corrupt = plan;
    corrupt.column_offsets[1] += 1;
    try std.testing.expectError(
        error.InvalidColumnCoverage,
        plan_mod.validate(&corrupt, &statement),
    );
}

test "main trace plan: block partitions preserve nonterminal alignment" {
    const statement = testStatement(1, 3 * plan_mod.POSEIDON_ROWS_PER_CHUNK);
    const plan = try plan_mod.build(&statement, testOptions(3, std.math.maxInt(usize)));
    try std.testing.expectEqual(@as(u8, 3), plan.poseidon_chunk_count);
    try std.testing.expectEqual(@as(u32, 4096), plan.poseidonChunks()[0].len);
    try std.testing.expectEqual(@as(u32, 4096), plan.poseidonChunks()[1].len);
    try std.testing.expectEqual(@as(u32, 8192), plan.poseidonChunks()[2].len);
    for (plan.poseidonChunks()[0 .. plan.poseidonChunks().len - 1]) |range| {
        try std.testing.expectEqual(
            @as(u32, 0),
            (try range.end()) % plan_mod.POSEIDON_ROWS_PER_CHUNK,
        );
    }
    try plan_mod.validate(&plan, &statement);

    var corrupt = plan;
    corrupt.poseidon_chunk_ranges[1].start += 1;
    try std.testing.expectError(
        error.InvalidChunkCoverage,
        plan_mod.validate(&corrupt, &statement),
    );
}

test "main trace plan: construction and task identities are deterministic" {
    const statement = testStatement(4, 16);
    var options = testOptions(4, std.math.maxInt(usize));
    options.enable_opcode_audit = true;
    const first = try plan_mod.build(&statement, options);
    const second = try plan_mod.build(&statement, options);
    try std.testing.expect(std.meta.eql(first, second));
    try std.testing.expectEqual(@as(u16, 1), first.task_counts.prepare_wave);
    try std.testing.expectEqual(@as(u16, 1), first.task_counts.reduce_wave);
    try std.testing.expectEqual(@as(u16, 1), first.task_counts.lookup_seed_wave);
    try std.testing.expectEqual(@as(u16, 1), first.task_counts.seal_wave);
    try std.testing.expectEqual(
        @as(u16, @intCast(
            @as(usize, first.n_components) + component_order.LOOKUP_TABLE_COUNT,
        )),
        first.task_counts.finalization_wave,
    );

    const keys = [_]task_graph.TaskKey{
        plan_mod.prepareTaskKey(),
        plan_mod.opcodeFillTaskKey(0),
        plan_mod.opcodeFillTaskKey(1),
        try first.infraFillKey(0, 0),
        plan_mod.opcodeReduceTaskKey(),
        plan_mod.opcodeAuditTaskKey(0),
        plan_mod.lookupSeedTaskKey(),
        plan_mod.opcodeFinalizeTaskKey(0),
        try first.infraFinalizeKey(first.n_infra - 1),
        plan_mod.sealTaskKey(),
    };
    for (keys, 0..) |lhs, lhs_index| {
        try std.testing.expectEqual(plan_mod.MAIN_TRACE_EPOCH, lhs.epoch);
        for (keys[lhs_index + 1 ..]) |rhs|
            try std.testing.expect(!task_graph.TaskKey.eql(lhs, rhs));
    }
    try std.testing.expect(task_graph.TaskKey.lessThan(keys[0], keys[1]));
    try std.testing.expect(task_graph.TaskKey.lessThan(keys[3], keys[4]));
    try std.testing.expect(task_graph.TaskKey.lessThan(keys[4], keys[5]));
    try std.testing.expect(task_graph.TaskKey.lessThan(keys[5], keys[6]));
    try std.testing.expect(task_graph.TaskKey.lessThan(keys[6], keys[7]));
    try std.testing.expect(task_graph.TaskKey.lessThan(keys[8], keys[9]));
}

test "main trace plan: exact finite budget boundary fails one byte under" {
    const statement = testStatement(1, 16);
    const probe = try plan_mod.build(&statement, testOptions(1, std.math.maxInt(usize)));
    const boundary = try probe.requiredHostBytes();
    const exact = try plan_mod.build(&statement, testOptions(1, boundary));
    try std.testing.expectEqual(boundary, try exact.requiredHostBytes());
    try std.testing.expectError(
        error.TaskMemoryBudgetExceeded,
        plan_mod.build(&statement, testOptions(1, boundary - 1)),
    );
}

test "main trace plan: budget deterministically reduces private counter chunks" {
    const statement = testStatement(4, 16);
    const wide = try plan_mod.build(&statement, testOptions(4, std.math.maxInt(usize)));
    try std.testing.expectEqual(@as(u8, 4), wide.opcode_chunk_count);
    const counter_unit = try plan_mod.counterSetReservationBytes();
    const fixed_total = (try wide.requiredHostBytes()) - 4 * counter_unit;
    const two_chunk_budget = fixed_total + 2 * counter_unit;

    const narrowed = try plan_mod.build(&statement, testOptions(4, two_chunk_budget));
    try std.testing.expectEqual(@as(u8, 2), narrowed.opcode_chunk_count);
    try std.testing.expectEqual(two_chunk_budget, try narrowed.requiredHostBytes());
    try plan_types.validateAlignedPartition(
        narrowed.opcodeChunks(),
        statement.total_steps,
        plan_mod.OPCODE_ROWS_PER_CHUNK,
    );
    const repeated = try plan_mod.build(&statement, testOptions(4, two_chunk_budget));
    try std.testing.expect(std.meta.eql(narrowed, repeated));
}

test "main trace plan: pool contention policy is explicit" {
    const statement = testStatement(4, 16);
    var strict = testOptions(4, std.math.maxInt(usize));
    strict.pool_capacity = 2;
    try std.testing.expectError(
        error.WorkerBudgetUnavailable,
        plan_mod.build(&statement, strict),
    );

    var compatibility = strict;
    compatibility.execution.contention_policy = .compatibility;
    const plan = try plan_mod.build(&statement, compatibility);
    try std.testing.expectEqual(@as(u8, 4), plan.requested_worker_count);
    try std.testing.expectEqual(@as(u8, 1), plan.planned_worker_count);
    try std.testing.expectEqual(@as(u8, 1), plan.opcode_chunk_count);
}

test "main trace plan: overflow and malformed geometry fail closed" {
    try std.testing.expectError(
        error.ResourceCalculationOverflow,
        plan_mod.checkedBytesForCells(std.math.maxInt(usize), 2),
    );
    var overflowing = plan_mod.Resources{};
    overflowing.main_output_payload_bytes = std.math.maxInt(usize);
    overflowing.retained_opcode_payload_bytes = 1;
    try std.testing.expectError(error.ResourceCalculationOverflow, overflowing.total());

    const statement = testStatement(1, 16);
    var overflow_options = testOptions(2, std.math.maxInt(usize));
    overflow_options.worker_stack_bytes = std.math.maxInt(usize);
    try std.testing.expectError(
        error.ResourceCalculationOverflow,
        plan_mod.build(&statement, overflow_options),
    );

    var wrong_width = statement;
    wrong_width.component_descs[0].n_columns += 1;
    try std.testing.expectError(
        error.InvalidOpcodeDescriptor,
        plan_mod.build(&wrong_width, testOptions(1, std.math.maxInt(usize))),
    );
    var wrong_total = statement;
    wrong_total.total_steps += 1;
    try std.testing.expectError(
        error.InvalidTotalSteps,
        plan_mod.build(&wrong_total, testOptions(1, std.math.maxInt(usize))),
    );
    var excessive = statement;
    excessive.n_components = statement_mod.MAX_COMPONENTS + 1;
    try std.testing.expectError(
        error.InvalidComponentCount,
        plan_mod.build(&excessive, testOptions(1, std.math.maxInt(usize))),
    );
}

test "main trace plan: task capacity and compact size are pinned" {
    var counts = plan_mod.TaskCounts{ .generation_wave = task_graph.MAX_COMPONENT_TASKS };
    try counts.validate();
    counts.generation_wave = task_graph.MAX_COMPONENT_TASKS + 1;
    try std.testing.expectError(error.TaskCapacityExceeded, counts.validate());

    try std.testing.expectEqual(@as(usize, 1024), task_graph.MAX_COMPONENT_TASKS);
    try std.testing.expect(plan_mod.LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES > 0);
    try std.testing.expectEqual(@as(usize, 2_981_888), plan_mod.LOOKUP_COUNTER_SET_CELLS);
    try std.testing.expectEqual(
        @as(usize, 11_927_552),
        plan_mod.LOOKUP_COUNTER_SET_PAYLOAD_BYTES,
    );
    try std.testing.expect(@sizeOf(plan_mod.Plan) <= plan_mod.MAX_PLAN_SIZE_BYTES);
    try std.testing.expect(@sizeOf(plan_mod.Plan) < @sizeOf(statement_mod.RiscVStatement));
}
