//! Pure coordinator-side planning for the RISC-V Tree-1 construction epoch.
//!
//! This module does not execute work, allocate, discover a process-global pool,
//! or retain the input statement. It derives exact column/chunk coverage,
//! finite host-resource admission, task-wave capacity, and stable task facts
//! for the later R-002 integration.
//!
//! The resource total is conservative across its named classes: each is counted
//! even where a future lifetime proof could reuse bytes. Arena page padding,
//! allocation and graph/profile metadata, backend-private commitment scratch,
//! and the coordinator's pre-existing stack are outside this first seam. They
//! must be named before this becomes whole-proof memory authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_api = @import("stwo_prover_api");
const component_order = @import("../air/component_order.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const guest_statement = @import("../air/guest_precompile/statement.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace_mod = @import("../runner/trace.zig");
const plan_types = @import("main_trace_plan_types.zig");

pub const Error = plan_types.Error;
pub const BuildOptions = plan_types.BuildOptions;
pub const ColumnRange = plan_types.ColumnRange;
pub const RowRange = plan_types.RowRange;
pub const Resources = plan_types.Resources;
pub const TaskCounts = plan_types.TaskCounts;
pub const Plan = plan_types.Plan;
pub const StageRank = plan_types.StageRank;
pub const MAIN_TRACE_EPOCH = plan_types.MAIN_TRACE_EPOCH;
pub const MAX_DESCRIPTORS = plan_types.MAX_DESCRIPTORS;
pub const MAX_PLAN_SIZE_BYTES = plan_types.MAX_PLAN_SIZE_BYTES;
pub const OPCODE_ROWS_PER_CHUNK = plan_types.OPCODE_ROWS_PER_CHUNK;
pub const POSEIDON_ROWS_PER_CHUNK = plan_types.POSEIDON_ROWS_PER_CHUNK;
pub const LOOKUP_COUNTER_SET_CELLS = plan_types.LOOKUP_COUNTER_SET_CELLS;
pub const LOOKUP_COUNTER_SET_PAYLOAD_BYTES = plan_types.LOOKUP_COUNTER_SET_PAYLOAD_BYTES;
pub const LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES = plan_types.LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES;

pub const prepareTaskKey = plan_types.prepareTaskKey;
pub const opcodeFillTaskKey = plan_types.opcodeFillTaskKey;
pub const infrastructureFillTaskKey = plan_types.infrastructureFillTaskKey;
pub const opcodeReduceTaskKey = plan_types.opcodeReduceTaskKey;
pub const opcodeAuditTaskKey = plan_types.opcodeAuditTaskKey;
pub const lookupSeedTaskKey = plan_types.lookupSeedTaskKey;
pub const opcodeFinalizeTaskKey = plan_types.opcodeFinalizeTaskKey;
pub const infrastructureFinalizeTaskKey = plan_types.infrastructureFinalizeTaskKey;
pub const sealTaskKey = plan_types.sealTaskKey;
pub const checkedBytesForCells = plan_types.checkedBytesForCells;
pub const counterSetReservationBytes = plan_types.counterSetReservationBytes;

const work_pool = plan_types.work_pool;

/// Runtime cardinalities which bind an extension-aware base plan to all three
/// independently owned sources: ordinary trace rows, frozen call records, and
/// frozen guest execution rows.
pub const Poseidon2ExecutionCounts = struct {
    ordinary_rows: usize,
    call_records: usize,
    guest_execution_rows: usize,
};

pub fn build(
    statement: *const statement_mod.RiscVStatement,
    options: BuildOptions,
) Error!Plan {
    return buildWithOrdinarySteps(statement, statement.total_steps, options);
}

/// Builds the base Tree-1 plan for a Poseidon2 extension statement. Guest
/// retirements remain statement-visible but never enter ordinary-row chunking.
pub fn buildPoseidon2(
    statement: *const statement_mod.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    counts: Poseidon2ExecutionCounts,
    options: BuildOptions,
) Error!Plan {
    const ordinary_steps = try validatePoseidon2Binding(
        statement,
        extension,
        counts,
    );
    return buildWithOrdinarySteps(statement, ordinary_steps, options);
}

fn buildWithOrdinarySteps(
    statement: *const statement_mod.RiscVStatement,
    ordinary_steps: u32,
    options: BuildOptions,
) Error!Plan {
    const shape = try validateStatementGeometry(statement, ordinary_steps);
    const admitted_workers = try resolveAdmittedWorkers(
        options.execution,
        options.pool_capacity,
    );
    if (options.worker_stack_bytes == 0) return error.InvalidWorkerStackSize;

    var result = Plan{
        .resources = .{},
        .task_counts = .{},
        .host_byte_budget = options.execution.host_byte_budget,
        .worker_stack_bytes = options.worker_stack_bytes,
        .column_offsets = .{0} ** (MAX_DESCRIPTORS + 1),
        .opcode_chunk_ranges = .{RowRange{}} ** work_pool.MAX_WORKERS,
        .poseidon_chunk_ranges = .{RowRange{}} ** work_pool.MAX_WORKERS,
        .total_steps = statement.total_steps,
        .ordinary_steps = ordinary_steps,
        .total_columns = 0,
        .n_components = shape.n_components,
        .n_infra = shape.n_infra,
        .descriptor_count = shape.descriptor_count,
        .poseidon_infra_index = shape.poseidon_infra_index,
        .requested_worker_count = try plan_types.checkedU8(options.execution.worker_count),
        .planned_worker_count = try plan_types.checkedU8(admitted_workers),
        .pool_capacity = try plan_types.checkedU8(options.pool_capacity),
        .opcode_chunk_count = 0,
        .poseidon_chunk_count = 0,
        .contention_policy = options.execution.contention_policy,
        .opcode_audit_enabled = options.enable_opcode_audit,
    };

    var cursor: usize = 0;
    var registry_index: usize = 0;
    const n_components: usize = shape.n_components;
    const n_infra: usize = shape.n_infra;
    for (statement.component_descs[0..n_components]) |desc| {
        cursor = try appendColumnRange(&result, registry_index, cursor, desc.n_columns);
        registry_index += 1;
    }
    for (statement.infra_descs[0..n_infra]) |desc| {
        cursor = try appendColumnRange(&result, registry_index, cursor, desc.n_columns);
        registry_index += 1;
    }
    if (registry_index != shape.descriptor_count) return error.InvalidColumnCoverage;
    result.total_columns = try plan_types.checkedU32(cursor);

    const natural_opcode_chunks = plan_types.naturalChunkCount(
        ordinary_steps,
        OPCODE_ROWS_PER_CHUNK,
        admitted_workers,
    );
    const poseidon_desc = statement.infra_descs[shape.poseidon_infra_index];
    const poseidon_chunks = plan_types.naturalChunkCount(
        poseidon_desc.n_rows,
        POSEIDON_ROWS_PER_CHUNK,
        admitted_workers,
    );

    const fixed_resources = try fixedResources(
        statement,
        shape,
        ordinary_steps,
        admitted_workers,
        options.worker_stack_bytes,
    );
    const opcode_chunks = try admitOpcodeChunks(
        natural_opcode_chunks,
        try fixed_resources.total(),
        try counterSetReservationBytes(),
        options.execution.host_byte_budget,
    );

    result.opcode_chunk_count = try plan_types.checkedU8(opcode_chunks);
    result.poseidon_chunk_count = try plan_types.checkedU8(poseidon_chunks);
    try plan_types.writeAlignedPartition(
        &result.opcode_chunk_ranges,
        opcode_chunks,
        ordinary_steps,
        OPCODE_ROWS_PER_CHUNK,
    );
    try plan_types.writeAlignedPartition(
        &result.poseidon_chunk_ranges,
        poseidon_chunks,
        try plan_types.checkedDomainU32(poseidon_desc.log_size),
        POSEIDON_ROWS_PER_CHUNK,
    );

    result.resources = fixed_resources;
    result.resources.lookup_counter_payload_bytes = try plan_types.checkedMul(
        opcode_chunks,
        LOOKUP_COUNTER_SET_PAYLOAD_BYTES,
    );
    result.resources.lookup_counter_descriptor_bytes = try plan_types.checkedMul(
        opcode_chunks,
        LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES,
    );
    if (try result.requiredHostBytes() > options.execution.host_byte_budget)
        return error.TaskMemoryBudgetExceeded;

    result.task_counts = try deriveTaskCounts(
        shape,
        opcode_chunks,
        poseidon_chunks,
        options.enable_opcode_audit,
    );
    try validateCommon(&result, statement, ordinary_steps);
    return result;
}

/// Revalidates every compact derived value without allocating or reconstructing
/// another capacity-sized plan.
pub fn validate(
    plan: *const Plan,
    statement: *const statement_mod.RiscVStatement,
) Error!void {
    if (plan.ordinary_steps != statement.total_steps)
        return error.InvalidPlan;
    return validateCommon(plan, statement, statement.total_steps);
}

/// Revalidates both the compact plan and the extension/runtime cardinality
/// binding. A plan created for one call count cannot be replayed for another.
pub fn validatePoseidon2(
    plan: *const Plan,
    statement: *const statement_mod.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    counts: Poseidon2ExecutionCounts,
) Error!void {
    const ordinary_steps = try validatePoseidon2Binding(
        statement,
        extension,
        counts,
    );
    return validateCommon(plan, statement, ordinary_steps);
}

fn validateCommon(
    plan: *const Plan,
    statement: *const statement_mod.RiscVStatement,
    ordinary_steps: u32,
) Error!void {
    const shape = try validateStatementGeometry(statement, ordinary_steps);
    if (plan.n_components != shape.n_components or
        plan.n_infra != shape.n_infra or
        plan.descriptor_count != shape.descriptor_count or
        plan.poseidon_infra_index != shape.poseidon_infra_index or
        plan.total_steps != statement.total_steps or
        plan.ordinary_steps != ordinary_steps)
        return error.InvalidPlan;

    const admitted = try resolveAdmittedWorkers(.{
        .worker_count = plan.requested_worker_count,
        .host_byte_budget = plan.host_byte_budget,
        .contention_policy = plan.contention_policy,
    }, plan.pool_capacity);
    if (@as(usize, plan.planned_worker_count) != admitted) return error.InvalidPlan;

    var cursor: usize = 0;
    var registry_index: usize = 0;
    if (plan.column_offsets[0] != 0) return error.InvalidColumnCoverage;
    const n_components: usize = shape.n_components;
    const n_infra: usize = shape.n_infra;
    for (statement.component_descs[0..n_components]) |desc| {
        try validateOffset(plan, registry_index, cursor, desc.n_columns);
        cursor = try plan_types.checkedAdd(cursor, desc.n_columns);
        registry_index += 1;
    }
    for (statement.infra_descs[0..n_infra]) |desc| {
        try validateOffset(plan, registry_index, cursor, desc.n_columns);
        cursor = try plan_types.checkedAdd(cursor, desc.n_columns);
        registry_index += 1;
    }
    if (registry_index != @as(usize, plan.descriptor_count) or
        cursor != @as(usize, plan.total_columns) or
        plan.column_offsets[registry_index] != plan.total_columns)
        return error.InvalidColumnCoverage;
    for (plan.column_offsets[registry_index + 1 ..]) |unused| {
        if (unused != 0) return error.InvalidColumnCoverage;
    }

    const natural_opcode_chunks = plan_types.naturalChunkCount(
        ordinary_steps,
        OPCODE_ROWS_PER_CHUNK,
        admitted,
    );
    if (plan.opcode_chunk_count == 0 or
        @as(usize, plan.opcode_chunk_count) > natural_opcode_chunks)
        return error.InvalidChunkCoverage;
    try plan_types.validateAlignedPartition(
        plan.opcodeChunks(),
        ordinary_steps,
        OPCODE_ROWS_PER_CHUNK,
    );

    const poseidon_desc = statement.infra_descs[shape.poseidon_infra_index];
    const poseidon_domain = try plan_types.checkedDomainU32(poseidon_desc.log_size);
    const expected_poseidon_chunks = plan_types.naturalChunkCount(
        poseidon_desc.n_rows,
        POSEIDON_ROWS_PER_CHUNK,
        admitted,
    );
    if (@as(usize, plan.poseidon_chunk_count) != expected_poseidon_chunks)
        return error.InvalidChunkCoverage;
    try plan_types.validateAlignedPartition(
        plan.poseidonChunks(),
        poseidon_domain,
        POSEIDON_ROWS_PER_CHUNK,
    );

    const fixed_resources = try fixedResources(
        statement,
        shape,
        ordinary_steps,
        admitted,
        plan.worker_stack_bytes,
    );
    const selected_chunks = try admitOpcodeChunks(
        natural_opcode_chunks,
        try fixed_resources.total(),
        try counterSetReservationBytes(),
        plan.host_byte_budget,
    );
    if (@as(usize, plan.opcode_chunk_count) != selected_chunks)
        return error.InvalidPlan;

    var expected_resources = fixed_resources;
    expected_resources.lookup_counter_payload_bytes = try plan_types.checkedMul(
        selected_chunks,
        LOOKUP_COUNTER_SET_PAYLOAD_BYTES,
    );
    expected_resources.lookup_counter_descriptor_bytes = try plan_types.checkedMul(
        selected_chunks,
        LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES,
    );
    if (!std.meta.eql(expected_resources, plan.resources)) return error.InvalidPlan;
    if (try plan.requiredHostBytes() > plan.host_byte_budget)
        return error.TaskMemoryBudgetExceeded;

    const expected_counts = try deriveTaskCounts(
        shape,
        selected_chunks,
        expected_poseidon_chunks,
        plan.opcode_audit_enabled,
    );
    if (!std.meta.eql(expected_counts, plan.task_counts)) return error.InvalidPlan;
    try plan.task_counts.validate();
}

fn validatePoseidon2Binding(
    statement: *const statement_mod.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    counts: Poseidon2ExecutionCounts,
) Error!u32 {
    extension.validate(statement) catch
        return error.InvalidPoseidon2ExecutionBinding;
    const ordinary_rows = std.math.cast(u32, counts.ordinary_rows) orelse
        return error.InvalidPoseidon2ExecutionBinding;
    const call_records = std.math.cast(u32, counts.call_records) orelse
        return error.InvalidPoseidon2ExecutionBinding;
    const guest_execution_rows = std.math.cast(
        u32,
        counts.guest_execution_rows,
    ) orelse return error.InvalidPoseidon2ExecutionBinding;
    const n_guest = extension.counts.n_guest;
    if (extension.counts.custom_retirements != n_guest or
        extension.counts.frozen_call_count != n_guest or
        call_records != n_guest or
        guest_execution_rows != n_guest)
    {
        return error.InvalidPoseidon2ExecutionBinding;
    }
    const expected_ordinary = std.math.sub(
        u32,
        statement.total_steps,
        n_guest,
    ) catch return error.InvalidPoseidon2ExecutionBinding;
    if (ordinary_rows != expected_ordinary)
        return error.InvalidPoseidon2ExecutionBinding;
    return ordinary_rows;
}

const StatementShape = struct {
    n_components: u16,
    n_infra: u16,
    descriptor_count: u16,
    poseidon_infra_index: u16,
};

fn validateStatementGeometry(
    statement: *const statement_mod.RiscVStatement,
    ordinary_steps: u32,
) Error!StatementShape {
    if (ordinary_steps == 0 or ordinary_steps > statement.total_steps)
        return error.InvalidTotalSteps;
    if (statement.n_components == 0 or
        statement.n_components > statement_mod.MAX_COMPONENTS)
        return error.InvalidComponentCount;
    if (statement.n_infra < 4 + component_order.LOOKUP_TABLE_COUNT or
        statement.n_infra > statement_mod.MAX_INFRA_COMPONENTS)
        return error.InvalidInfrastructureCount;

    const n_components: usize = @intCast(statement.n_components);
    const n_infra: usize = @intCast(statement.n_infra);
    var total_rows: u64 = 0;
    var previous_family_index: ?usize = null;
    var previous_rows: u32 = 0;
    for (statement.component_descs[0..n_components]) |desc| {
        if (desc.n_rows == 0 or desc.n_rows > OPCODE_ROWS_PER_CHUNK or
            desc.log_size != computeOpcodeLogSize(desc.n_rows) or
            desc.n_columns != trace_mod.nColumnsForFamily(desc.family))
            return error.InvalidOpcodeDescriptor;
        const family_index = component_order.opcodeFamilyIndex(desc.family);
        if (previous_family_index) |previous| {
            if (family_index < previous) return error.InvalidDescriptorOrder;
            if (family_index == previous and previous_rows != OPCODE_ROWS_PER_CHUNK)
                return error.InvalidOpcodeDescriptor;
        }
        previous_family_index = family_index;
        previous_rows = desc.n_rows;
        total_rows = std.math.add(u64, total_rows, desc.n_rows) catch
            return error.ResourceCalculationOverflow;
    }
    if (total_rows != ordinary_steps) return error.InvalidTotalSteps;

    const program = statement.infra_descs[0];
    if (program.kind != .program or program.n_rows == 0 or
        program.n_columns != program_commitment.N_MAIN_COLUMNS or
        program.log_size != computeLogSize(program.n_rows))
        return error.InvalidInfrastructureDescriptor;

    var index: usize = 1;
    const memory_start = index;
    while (index < n_infra and statement.infra_descs[index].kind == .memory) : (index += 1) {}
    for (statement.infra_descs[memory_start..index], 0..) |desc, shard_index| {
        if (desc.n_rows == 0 or desc.n_rows > OPCODE_ROWS_PER_CHUNK or
            desc.n_columns != memory_trace.N_COLUMNS or
            desc.log_size != @max(@as(u32, 4), computeLogSize(desc.n_rows)))
            return error.InvalidInfrastructureDescriptor;
        if (shard_index + 1 < index - memory_start and
            desc.n_rows != OPCODE_ROWS_PER_CHUNK)
            return error.InvalidInfrastructureDescriptor;
    }
    if (index + 3 + component_order.LOOKUP_TABLE_COUNT != n_infra)
        return error.InvalidDescriptorOrder;

    const merkle_desc = statement.infra_descs[index];
    const poseidon_desc = statement.infra_descs[index + 1];
    const clock_desc = statement.infra_descs[index + 2];
    if (merkle_desc.kind != .merkle or
        merkle_desc.n_columns != merkle_node.N_MAIN_COLUMNS or
        merkle_desc.log_size != @max(@as(u32, 4), computeLogSize(merkle_desc.n_rows)))
        return error.InvalidInfrastructureDescriptor;
    if (poseidon_desc.kind != .poseidon2 or
        poseidon_desc.n_columns != poseidon2_air.N_MAIN_COLUMNS or
        poseidon_desc.log_size != @max(@as(u32, 4), computeLogSize(poseidon_desc.n_rows)) or
        poseidon_desc.n_rows != merkle_desc.n_rows or
        poseidon_desc.log_size >= 32)
        return error.InvalidInfrastructureDescriptor;
    if (clock_desc.kind != .clock_update or
        clock_desc.n_columns != infra.CLOCK_UPDATE_COLS or
        clock_desc.log_size != @max(@as(u32, 4), computeLogSize(clock_desc.n_rows)))
        return error.InvalidInfrastructureDescriptor;
    const poseidon_infra_index = index + 1;

    index += 3;
    for (component_order.lookupTables()) |kind| {
        const desc = statement.infra_descs[index];
        if (desc.kind != statement_mod.infraKindForTable(kind) or
            desc.log_size != lookup_schema.logSize(kind) or
            desc.n_rows != lookup_schema.size(kind) or
            desc.n_columns != 1)
            return error.InvalidInfrastructureDescriptor;
        index += 1;
    }
    if (index != n_infra) return error.InvalidDescriptorOrder;

    for (statement.component_descs[0..n_components]) |desc|
        _ = try plan_types.checkedDomain(desc.log_size);
    for (statement.infra_descs[0..n_infra]) |desc|
        _ = try plan_types.checkedDomain(desc.log_size);

    const descriptor_count = try plan_types.checkedAdd(n_components, n_infra);
    if (descriptor_count > MAX_DESCRIPTORS) return error.InvalidInfrastructureCount;
    return .{
        .n_components = try plan_types.checkedU16(n_components),
        .n_infra = try plan_types.checkedU16(n_infra),
        .descriptor_count = try plan_types.checkedU16(descriptor_count),
        .poseidon_infra_index = try plan_types.checkedU16(poseidon_infra_index),
    };
}

fn fixedResources(
    statement: *const statement_mod.RiscVStatement,
    shape: StatementShape,
    ordinary_steps: u32,
    admitted_workers: usize,
    worker_stack_bytes: usize,
) Error!Resources {
    if (worker_stack_bytes == 0) return error.InvalidWorkerStackSize;
    var result = Resources{};
    var seen_log_sizes = [_]bool{false} ** @bitSizeOf(usize);
    var total_columns: usize = 0;

    const n_components: usize = shape.n_components;
    const n_infra: usize = shape.n_infra;
    for (statement.component_descs[0..n_components]) |desc| {
        const payload = try descriptorPayloadBytes(desc.log_size, desc.n_columns);
        result.main_output_payload_bytes = try plan_types.checkedAdd(
            result.main_output_payload_bytes,
            payload,
        );
        result.retained_opcode_payload_bytes = try plan_types.checkedAdd(
            result.retained_opcode_payload_bytes,
            payload,
        );
        total_columns = try plan_types.checkedAdd(total_columns, desc.n_columns);
        try addPlacementResource(&result, &seen_log_sizes, desc.log_size);
    }
    for (statement.infra_descs[0..n_infra]) |desc| {
        const payload = try descriptorPayloadBytes(desc.log_size, desc.n_columns);
        result.main_output_payload_bytes = try plan_types.checkedAdd(
            result.main_output_payload_bytes,
            payload,
        );
        if (desc.kind == .clock_update) {
            result.retained_clock_payload_bytes = try plan_types.checkedAdd(
                result.retained_clock_payload_bytes,
                payload,
            );
        }
        total_columns = try plan_types.checkedAdd(total_columns, desc.n_columns);
        try addPlacementResource(&result, &seen_log_sizes, desc.log_size);
    }

    result.column_descriptor_bytes = try plan_types.checkedMul(
        total_columns,
        @sizeOf(prover_api.ColumnEvaluation),
    );
    result.column_log_size_bytes = try plan_types.checkedMul(total_columns, @sizeOf(u32));
    result.ownership_ledger_bytes = try plan_types.checkedMul(total_columns, @sizeOf(bool));
    result.opcode_classification_bytes = try plan_types.checkedMul(
        ordinary_steps,
        @sizeOf(trace_mod.ProofOpcode),
    );

    const poseidon_desc = statement.infra_descs[shape.poseidon_infra_index];
    result.poseidon_inverse_placement_payload_bytes = try plan_types.checkedMul(
        try plan_types.checkedDomain(poseidon_desc.log_size),
        @sizeOf(usize),
    );
    result.poseidon_inverse_placement_descriptor_bytes = @sizeOf([]const usize);

    if (admitted_workers == 0) return error.InvalidWorkerBudget;
    const helper_count = admitted_workers - 1;
    result.helper_worker_stack_bytes = try plan_types.checkedMul(
        helper_count,
        worker_stack_bytes,
    );
    result.helper_submission_bytes = try plan_types.checkedMul(
        helper_count,
        work_pool.STRUCTURED_JOB_RESERVATION_BYTES,
    );
    return result;
}

fn addPlacementResource(
    resources: *Resources,
    seen: *[@bitSizeOf(usize)]bool,
    log_size: u32,
) Error!void {
    const log_index: usize = @intCast(log_size);
    if (seen[log_index]) return;
    seen[log_index] = true;
    resources.forward_placement_payload_bytes = try plan_types.checkedAdd(
        resources.forward_placement_payload_bytes,
        try plan_types.checkedMul(
            try plan_types.checkedDomain(log_size),
            @sizeOf(usize),
        ),
    );
    resources.forward_placement_descriptor_bytes = try plan_types.checkedAdd(
        resources.forward_placement_descriptor_bytes,
        @sizeOf(infra.BitReversalTable),
    );
}

fn resolveAdmittedWorkers(
    execution: prover_api.CpuCompositionExecutionRequest,
    pool_capacity: usize,
) Error!usize {
    _ = work_pool.WorkerBudget.init(execution.worker_count) catch
        return error.InvalidWorkerBudget;
    if (pool_capacity == 0 or pool_capacity > work_pool.MAX_WORKERS)
        return error.InvalidPoolCapacity;
    if (execution.worker_count <= pool_capacity) return execution.worker_count;
    return switch (execution.contention_policy) {
        .strict => error.WorkerBudgetUnavailable,
        .compatibility => 1,
    };
}

fn deriveTaskCounts(
    shape: StatementShape,
    opcode_chunks: usize,
    poseidon_chunks: usize,
    opcode_audit_enabled: bool,
) Error!TaskCounts {
    const non_table_infra = @as(usize, shape.n_infra) - component_order.LOOKUP_TABLE_COUNT;
    var generation = try plan_types.checkedAdd(opcode_chunks, non_table_infra - 1);
    generation = try plan_types.checkedAdd(generation, poseidon_chunks);
    const finalization = try plan_types.checkedAdd(
        shape.n_components,
        component_order.LOOKUP_TABLE_COUNT,
    );
    const descriptor_slots = try plan_types.checkedAdd(shape.n_components, shape.n_infra);
    const result = TaskCounts{
        .descriptor_slots = try plan_types.checkedTaskCount(descriptor_slots),
        .prepare_wave = 1,
        .generation_wave = try plan_types.checkedTaskCount(generation),
        .reduce_wave = 1,
        .audit_wave = if (opcode_audit_enabled) shape.n_components else 0,
        .lookup_seed_wave = 1,
        .finalization_wave = try plan_types.checkedTaskCount(finalization),
        .seal_wave = 1,
    };
    try result.validate();
    return result;
}

fn admitOpcodeChunks(
    natural_chunks: usize,
    fixed_bytes: usize,
    counter_unit_bytes: usize,
    host_byte_budget: usize,
) Error!usize {
    if (natural_chunks == 0 or counter_unit_bytes == 0) return error.InvalidPlan;
    const minimum = try plan_types.checkedAdd(fixed_bytes, counter_unit_bytes);
    if (host_byte_budget < minimum) return error.TaskMemoryBudgetExceeded;
    const affordable = 1 + (host_byte_budget - minimum) / counter_unit_bytes;
    return @min(natural_chunks, affordable);
}

fn appendColumnRange(
    plan: *Plan,
    registry_index: usize,
    cursor: usize,
    width: u32,
) Error!usize {
    if (registry_index >= MAX_DESCRIPTORS) return error.InvalidColumnCoverage;
    if (plan.column_offsets[registry_index] != try plan_types.checkedU32(cursor))
        return error.InvalidColumnCoverage;
    const end_offset = try plan_types.checkedAdd(cursor, width);
    plan.column_offsets[registry_index + 1] = try plan_types.checkedU32(end_offset);
    return end_offset;
}

fn validateOffset(
    plan: *const Plan,
    registry_index: usize,
    cursor: usize,
    width: u32,
) Error!void {
    if (registry_index >= MAX_DESCRIPTORS) return error.InvalidColumnCoverage;
    const start = try plan_types.checkedU32(cursor);
    const end_offset = try plan_types.checkedU32(try plan_types.checkedAdd(cursor, width));
    if (plan.column_offsets[registry_index] != start or
        plan.column_offsets[registry_index + 1] != end_offset)
        return error.InvalidColumnCoverage;
}

fn descriptorPayloadBytes(log_size: u32, columns: u32) Error!usize {
    const cells = try plan_types.checkedMul(
        try plan_types.checkedDomain(log_size),
        columns,
    );
    return checkedBytesForCells(cells, @sizeOf(M31));
}

fn computeLogSize(count: u32) u32 {
    if (count <= 1) return 1;
    return @intCast(std.math.log2_int_ceil(u32, count));
}

fn computeOpcodeLogSize(count: u32) u32 {
    return @max(@as(u32, 4), computeLogSize(count));
}
