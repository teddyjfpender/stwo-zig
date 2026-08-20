//! Pure coordinator-side planning for the RISC-V Tree-2 interaction epoch.
//!
//! The plan is deliberately pointer-free. It fixes one output-column range,
//! one detailed-claim range, one task class, and one stable `TaskKey` for every
//! admitted statement descriptor before any worker starts. Completion order
//! can therefore affect scheduling only; it cannot affect Tree-2 layout or the
//! canonical interaction claim.
//!
//! This is the R-003 integration boundary beneath the transcript. `R.draw`
//! remains coordinator-owned and supplies one borrowed `Relations` value to a
//! prepared production kernel. `I.claim-mix` and commitment publication remain
//! outside this plan and may run only after its seal wave publishes success.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine");
const component_order = @import("../air/component_order.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace_mod = @import("../runner/trace.zig");

pub const task_graph = prover_engine.task_graph;
pub const work_pool = prover_engine.work_pool;

pub const MAX_DESCRIPTORS: usize =
    statement_mod.MAX_COMPONENTS + statement_mod.MAX_INFRA_COMPONENTS;
pub const INTERACTION_TRACE_EPOCH: u16 = 2;
pub const INTERNAL_PARALLEL_LOG_SIZE: u32 = 12;
pub const OPCODE_SHARD_ROWS: u32 = 1 << 16;
pub const MAX_CANCELLATION_TILE_ROWS: u32 = 4096;

pub const Error = error{
    InvalidComponentCount,
    InvalidInfrastructureCount,
    InvalidOpcodeDescriptor,
    InvalidInfrastructureDescriptor,
    InvalidDescriptorOrder,
    InvalidTotalSteps,
    InvalidPoolCapacity,
    InvalidWorkerBudget,
    InvalidWorkerStackSize,
    WorkerBudgetUnavailable,
    ResourceCalculationOverflow,
    TaskMemoryBudgetExceeded,
    TaskCapacityExceeded,
    InvalidColumnCoverage,
    InvalidClaimCoverage,
    InvalidTaskIndex,
    InvalidPlan,
};

pub const StageRank = enum(u16) {
    reserve = 0,
    producer = 10,
    seal = 20,
};

comptime {
    if (@intFromEnum(StageRank.reserve) >= @intFromEnum(StageRank.producer) or
        @intFromEnum(StageRank.producer) >= @intFromEnum(StageRank.seal))
    {
        @compileError("interaction task stage ranks must be strictly ordered");
    }
}

pub const ColumnRange = struct {
    start: u32,
    len: u32,

    pub fn end(self: ColumnRange) Error!u32 {
        return std.math.add(u32, self.start, self.len) catch
            error.InvalidColumnCoverage;
    }
};

/// Canonical flattened detailed-claim ordinals. Every claim owns exactly four
/// consecutive M31 interaction columns, so claim and column coverage are tied
/// rather than maintained by independent append cursors.
pub const ClaimRange = struct {
    start: u32,
    len: u32,

    pub fn end(self: ClaimRange) Error!u32 {
        return std.math.add(u32, self.start, self.len) catch
            error.InvalidClaimCoverage;
    }
};

pub const TaskCounts = struct {
    reserve_wave: u16,
    producer_wave: u16,
    seal_wave: u16,

    pub fn total(self: TaskCounts) Error!usize {
        var result: usize = 0;
        inline for (std.meta.fields(TaskCounts)) |field| {
            const count: usize = @field(self, field.name);
            if (count > task_graph.MAX_COMPONENT_TASKS) {
                return error.TaskCapacityExceeded;
            }
            result = try checkedAdd(result, count);
        }
        return result;
    }
};

/// Complete host-resident byte classes visible at the first R-003 seam.
/// Generator-specific prepared storage is supplied by the production adapter;
/// it must include every placement, inverse, scan, and kernel scratch buffer
/// that survives into worker execution.
pub const Resources = struct {
    retained_input_bytes: usize = 0,
    interaction_output_payload_bytes: usize = 0,
    column_descriptor_bytes: usize = 0,
    claim_payload_bytes: usize = 0,
    ownership_ledger_bytes: usize = 0,
    prepared_generator_bytes: usize = 0,
    helper_worker_stack_bytes: usize = 0,
    helper_submission_bytes: usize = 0,

    pub fn total(self: Resources) Error!usize {
        var result: usize = 0;
        inline for (std.meta.fields(Resources)) |field| {
            result = try checkedAdd(result, @field(self, field.name));
        }
        return result;
    }

    pub fn finalOutputBytes(self: Resources) Error!usize {
        var result = try checkedAdd(
            self.interaction_output_payload_bytes,
            self.column_descriptor_bytes,
        );
        result = try checkedAdd(result, self.claim_payload_bytes);
        result = try checkedAdd(result, self.ownership_ledger_bytes);
        return result;
    }

    pub fn helperBytes(self: Resources) Error!usize {
        return try checkedAdd(
            self.helper_worker_stack_bytes,
            self.helper_submission_bytes,
        );
    }
};

pub const BuildOptions = struct {
    execution: prover_api.CpuCompositionExecutionRequest,
    /// Total process-pool capacity, including the coordinator lane.
    pool_capacity: usize,
    worker_stack_bytes: usize = work_pool.WORKER_STACK_SIZE,
    /// Tree-1 retained columns/counters, witness views, and the one shared
    /// relations object that remain borrowed throughout Tree 2.
    retained_input_bytes: usize,
    /// Exact coordinator-prepared storage required by all component kernels.
    /// Worker callbacks may not allocate additional storage.
    prepared_generator_bytes: usize,
};

/// Compact statement-derived authority for one Tree-2 construction attempt.
/// Descriptor order is opcode shards followed by infrastructure descriptors.
pub const Plan = struct {
    resources: Resources,
    task_counts: TaskCounts,
    host_byte_budget: usize,
    worker_stack_bytes: usize,
    column_offsets: [MAX_DESCRIPTORS + 1]u32,
    claim_offsets: [MAX_DESCRIPTORS + 1]u32,
    task_classes: [MAX_DESCRIPTORS]task_graph.TaskClass,
    total_columns: u32,
    total_claims: u32,
    n_components: u16,
    n_infra: u16,
    descriptor_count: u16,
    /// Statement-wide and base-owned retirement cardinalities are separate for
    /// extension statements. They are equal on the byte-identical base path.
    total_steps: u32,
    ordinary_steps: u32,
    requested_worker_count: u8,
    planned_worker_count: u8,
    pool_capacity: u8,
    contention_policy: prover_api.CpuCompositionContentionPolicy,

    pub fn requiredHostBytes(self: *const Plan) Error!usize {
        return self.resources.total();
    }

    pub fn descriptorColumnRange(
        self: *const Plan,
        registry_index: usize,
    ) ?ColumnRange {
        if (registry_index >= self.descriptor_count) return null;
        const start = self.column_offsets[registry_index];
        const end_offset = self.column_offsets[registry_index + 1];
        if (end_offset < start) return null;
        return .{ .start = start, .len = end_offset - start };
    }

    pub fn descriptorClaimRange(
        self: *const Plan,
        registry_index: usize,
    ) ?ClaimRange {
        if (registry_index >= self.descriptor_count) return null;
        const start = self.claim_offsets[registry_index];
        const end_offset = self.claim_offsets[registry_index + 1];
        if (end_offset < start) return null;
        return .{ .start = start, .len = end_offset - start };
    }

    pub fn componentColumnRange(
        self: *const Plan,
        component_index: usize,
    ) ?ColumnRange {
        if (component_index >= self.n_components) return null;
        return self.descriptorColumnRange(component_index);
    }

    pub fn componentClaimRange(
        self: *const Plan,
        component_index: usize,
    ) ?ClaimRange {
        if (component_index >= self.n_components) return null;
        return self.descriptorClaimRange(component_index);
    }

    pub fn infrastructureColumnRange(
        self: *const Plan,
        infra_index: usize,
    ) ?ColumnRange {
        if (infra_index >= self.n_infra) return null;
        return self.descriptorColumnRange(self.n_components + infra_index);
    }

    pub fn infrastructureClaimRange(
        self: *const Plan,
        infra_index: usize,
    ) ?ClaimRange {
        if (infra_index >= self.n_infra) return null;
        return self.descriptorClaimRange(self.n_components + infra_index);
    }

    pub fn descriptorClass(
        self: *const Plan,
        registry_index: usize,
    ) ?task_graph.TaskClass {
        if (registry_index >= self.descriptor_count) return null;
        return self.task_classes[registry_index];
    }

    pub fn producerTaskKey(
        self: *const Plan,
        registry_index: usize,
    ) Error!task_graph.TaskKey {
        if (registry_index >= self.descriptor_count) {
            return error.InvalidTaskIndex;
        }
        return taskKey(.producer, @intCast(registry_index), 0);
    }
};

pub fn reserveTaskKey() task_graph.TaskKey {
    return taskKey(.reserve, 0, 0);
}

pub fn sealTaskKey() task_graph.TaskKey {
    return taskKey(.seal, 0, 0);
}

pub fn build(
    statement: *const statement_mod.RiscVStatement,
    options: BuildOptions,
) Error!Plan {
    return derive(statement, statement.total_steps, options);
}

pub fn buildForOrdinarySteps(
    statement: *const statement_mod.RiscVStatement,
    ordinary_steps: u32,
    options: BuildOptions,
) Error!Plan {
    return derive(statement, ordinary_steps, options);
}

/// Re-derives every range, class, task count, and resource byte from the
/// statement and the compact options retained by the plan.
pub fn validate(
    plan: *const Plan,
    statement: *const statement_mod.RiscVStatement,
) Error!void {
    if (plan.ordinary_steps != statement.total_steps) return error.InvalidPlan;
    return validateForOrdinarySteps(plan, statement, statement.total_steps);
}

pub fn validateForOrdinarySteps(
    plan: *const Plan,
    statement: *const statement_mod.RiscVStatement,
    ordinary_steps: u32,
) Error!void {
    const expected = try derive(statement, ordinary_steps, .{
        .execution = .{
            .worker_count = plan.requested_worker_count,
            .host_byte_budget = plan.host_byte_budget,
            .contention_policy = plan.contention_policy,
        },
        .pool_capacity = plan.pool_capacity,
        .worker_stack_bytes = plan.worker_stack_bytes,
        .retained_input_bytes = plan.resources.retained_input_bytes,
        .prepared_generator_bytes = plan.resources.prepared_generator_bytes,
    });
    if (!std.meta.eql(expected, plan.*)) return error.InvalidPlan;
}

fn derive(
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
        .resources = .{
            .retained_input_bytes = options.retained_input_bytes,
            .prepared_generator_bytes = options.prepared_generator_bytes,
        },
        .task_counts = .{
            .reserve_wave = 1,
            .producer_wave = shape.descriptor_count,
            .seal_wave = 1,
        },
        .host_byte_budget = options.execution.host_byte_budget,
        .worker_stack_bytes = options.worker_stack_bytes,
        .column_offsets = .{0} ** (MAX_DESCRIPTORS + 1),
        .claim_offsets = .{0} ** (MAX_DESCRIPTORS + 1),
        .task_classes = .{.coordinator} ** MAX_DESCRIPTORS,
        .total_columns = 0,
        .total_claims = 0,
        .n_components = shape.n_components,
        .n_infra = shape.n_infra,
        .descriptor_count = shape.descriptor_count,
        .total_steps = statement.total_steps,
        .ordinary_steps = ordinary_steps,
        .requested_worker_count = try checkedU8(options.execution.worker_count),
        .planned_worker_count = try checkedU8(admitted_workers),
        .pool_capacity = try checkedU8(options.pool_capacity),
        .contention_policy = options.execution.contention_policy,
    };
    _ = try result.task_counts.total();

    var column_cursor: usize = 0;
    var claim_cursor: usize = 0;
    var registry_index: usize = 0;
    for (statement.component_descs[0..shape.n_components]) |desc| {
        const columns = opcode_interaction.nColumns(desc.family);
        try appendDescriptor(
            &result,
            registry_index,
            &column_cursor,
            &claim_cursor,
            columns,
            desc.log_size,
            classForOpcode(desc.log_size),
        );
        registry_index += 1;
    }
    for (statement.infra_descs[0..shape.n_infra]) |desc| {
        try appendDescriptor(
            &result,
            registry_index,
            &column_cursor,
            &claim_cursor,
            statement_mod.nInteractionColsForInfra(desc.kind),
            desc.log_size,
            classForInfrastructure(desc.kind, desc.log_size),
        );
        registry_index += 1;
    }
    if (registry_index != shape.descriptor_count or
        column_cursor != @as(usize, statement.nInteractionColumns()))
    {
        return error.InvalidColumnCoverage;
    }
    if (column_cursor % 4 != 0 or claim_cursor != column_cursor / 4) {
        return error.InvalidClaimCoverage;
    }
    result.total_columns = try checkedU32(column_cursor);
    result.total_claims = try checkedU32(claim_cursor);

    result.resources.column_descriptor_bytes = try checkedMul(
        column_cursor,
        @sizeOf(prover_api.ColumnEvaluation),
    );
    // The live prover owns one boxed fixed-capacity claim, not a compact
    // active-prefix allocation. Count that exact production owner while the
    // flattened active ordinals above remain the canonical placement map.
    result.resources.claim_payload_bytes =
        @sizeOf(statement_mod.RiscVInteractionClaim);
    const ledger_slots = try checkedAdd(
        shape.descriptor_count,
        try checkedAdd(column_cursor, claim_cursor),
    );
    result.resources.ownership_ledger_bytes = try checkedMul(
        ledger_slots,
        @sizeOf(bool),
    );
    const helper_count = admitted_workers - 1;
    result.resources.helper_worker_stack_bytes = try checkedMul(
        helper_count,
        options.worker_stack_bytes,
    );
    result.resources.helper_submission_bytes = try checkedMul(
        helper_count,
        work_pool.STRUCTURED_JOB_RESERVATION_BYTES,
    );
    if (try result.requiredHostBytes() > result.host_byte_budget) {
        return error.TaskMemoryBudgetExceeded;
    }
    return result;
}

const StatementShape = struct {
    n_components: u16,
    n_infra: u16,
    descriptor_count: u16,
};

fn validateStatementGeometry(
    statement: *const statement_mod.RiscVStatement,
    ordinary_steps: u32,
) Error!StatementShape {
    if (ordinary_steps == 0 or ordinary_steps > statement.total_steps)
        return error.InvalidTotalSteps;
    if (statement.n_components == 0 or
        statement.n_components > statement_mod.MAX_COMPONENTS)
    {
        return error.InvalidComponentCount;
    }
    if (statement.n_infra < 4 + component_order.LOOKUP_TABLE_COUNT or
        statement.n_infra > statement_mod.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidInfrastructureCount;
    }

    const n_components: usize = @intCast(statement.n_components);
    const n_infra: usize = @intCast(statement.n_infra);
    var total_rows: u64 = 0;
    var previous_family_index: ?usize = null;
    var previous_rows: u32 = 0;
    for (statement.component_descs[0..n_components]) |desc| {
        const domain = try checkedDomain(desc.log_size);
        if (desc.n_rows == 0 or desc.n_rows > OPCODE_SHARD_ROWS or
            @as(usize, desc.n_rows) > domain or
            desc.log_size != computeOpcodeLogSize(desc.n_rows) or
            desc.n_columns != trace_mod.nColumnsForFamily(desc.family))
        {
            return error.InvalidOpcodeDescriptor;
        }
        const family_index = component_order.opcodeFamilyIndex(desc.family);
        if (previous_family_index) |previous| {
            if (family_index < previous) return error.InvalidDescriptorOrder;
            if (family_index == previous and previous_rows != OPCODE_SHARD_ROWS) {
                return error.InvalidOpcodeDescriptor;
            }
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
    {
        return error.InvalidInfrastructureDescriptor;
    }
    var infra_index: usize = 1;
    const memory_start = infra_index;
    while (infra_index < n_infra and
        statement.infra_descs[infra_index].kind == .memory)
    {
        infra_index += 1;
    }
    for (
        statement.infra_descs[memory_start..infra_index],
        0..,
    ) |desc, shard_index| {
        if (desc.n_rows == 0 or desc.n_rows > OPCODE_SHARD_ROWS or
            desc.n_columns != memory_trace.N_COLUMNS or
            desc.log_size != @max(@as(u32, 4), computeLogSize(desc.n_rows)) or
            (shard_index + 1 < infra_index - memory_start and
                desc.n_rows != OPCODE_SHARD_ROWS))
        {
            return error.InvalidInfrastructureDescriptor;
        }
    }
    if (infra_index + 3 + component_order.LOOKUP_TABLE_COUNT != n_infra or
        statement.infra_descs[infra_index].kind != .merkle or
        statement.infra_descs[infra_index + 1].kind != .poseidon2 or
        statement.infra_descs[infra_index + 2].kind != .clock_update)
    {
        return error.InvalidDescriptorOrder;
    }
    const merkle_desc = statement.infra_descs[infra_index];
    const poseidon_desc = statement.infra_descs[infra_index + 1];
    const clock_desc = statement.infra_descs[infra_index + 2];
    if (merkle_desc.n_columns != merkle_node.N_MAIN_COLUMNS or
        merkle_desc.log_size !=
            @max(@as(u32, 4), computeLogSize(merkle_desc.n_rows)) or
        poseidon_desc.n_columns != poseidon2_air.N_MAIN_COLUMNS or
        poseidon_desc.n_rows != merkle_desc.n_rows or
        poseidon_desc.log_size != merkle_desc.log_size or
        poseidon_desc.log_size >= 32 or
        clock_desc.n_columns != infra.CLOCK_UPDATE_COLS or
        clock_desc.log_size !=
            @max(@as(u32, 4), computeLogSize(clock_desc.n_rows)))
    {
        return error.InvalidInfrastructureDescriptor;
    }
    infra_index += 3;
    for (component_order.lookupTables()) |kind| {
        const desc = statement.infra_descs[infra_index];
        if (desc.kind != statement_mod.infraKindForTable(kind) or
            desc.log_size != lookup_schema.logSize(kind) or
            desc.n_rows != lookup_schema.size(kind) or desc.n_columns != 1)
        {
            return error.InvalidInfrastructureDescriptor;
        }
        infra_index += 1;
    }
    if (infra_index != n_infra) return error.InvalidDescriptorOrder;

    for (statement.infra_descs[0..n_infra]) |desc| {
        const domain = try checkedDomain(desc.log_size);
        // Merkle, Poseidon2, and clock-update retain their minimum domain even
        // when this proof has no active rows. Their padding-only interaction
        // columns are protocol-bearing and therefore remain planned.
        if (@as(usize, desc.n_rows) > domain or desc.n_columns == 0) {
            return error.InvalidInfrastructureDescriptor;
        }
    }

    const descriptor_count = try checkedAdd(n_components, n_infra);
    if (descriptor_count > MAX_DESCRIPTORS) {
        return error.InvalidInfrastructureCount;
    }
    return .{
        .n_components = try checkedU16(n_components),
        .n_infra = try checkedU16(n_infra),
        .descriptor_count = try checkedU16(descriptor_count),
    };
}

fn appendDescriptor(
    plan: *Plan,
    registry_index: usize,
    column_cursor: *usize,
    claim_cursor: *usize,
    column_count_value: anytype,
    log_size: u32,
    class: task_graph.TaskClass,
) Error!void {
    if (registry_index >= MAX_DESCRIPTORS) return error.InvalidColumnCoverage;
    const column_count: usize = @intCast(column_count_value);
    if (column_count == 0 or column_count % 4 != 0) {
        return error.InvalidClaimCoverage;
    }
    if (plan.column_offsets[registry_index] != try checkedU32(column_cursor.*) or
        plan.claim_offsets[registry_index] != try checkedU32(claim_cursor.*))
    {
        return error.InvalidPlan;
    }
    const column_end = try checkedAdd(column_cursor.*, column_count);
    const claim_end = try checkedAdd(claim_cursor.*, column_count / 4);
    plan.column_offsets[registry_index + 1] = try checkedU32(column_end);
    plan.claim_offsets[registry_index + 1] = try checkedU32(claim_end);
    plan.task_classes[registry_index] = class;
    plan.resources.interaction_output_payload_bytes = try checkedAdd(
        plan.resources.interaction_output_payload_bytes,
        try checkedMul(
            try checkedMul(try checkedDomain(log_size), column_count),
            @sizeOf(M31),
        ),
    );
    column_cursor.* = column_end;
    claim_cursor.* = claim_end;
}

fn classForOpcode(log_size: u32) task_graph.TaskClass {
    return if (log_size >= INTERNAL_PARALLEL_LOG_SIZE)
        .pool_exclusive
    else
        .leaf;
}

fn classForInfrastructure(
    kind: statement_mod.InfraKind,
    log_size: u32,
) task_graph.TaskClass {
    return switch (kind) {
        .merkle, .poseidon2 => if (log_size >= INTERNAL_PARALLEL_LOG_SIZE)
            .pool_exclusive
        else
            .leaf,
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => .pool_exclusive,
        .program, .memory, .clock_update => .leaf,
    };
}

fn taskKey(
    stage: StageRank,
    registry_index: u32,
    shard_or_chunk_index: u32,
) task_graph.TaskKey {
    return .{
        .epoch = INTERACTION_TRACE_EPOCH,
        .stage_rank = @intFromEnum(stage),
        .component_registry_index = registry_index,
        .shard_or_chunk_index = shard_or_chunk_index,
    };
}

fn resolveAdmittedWorkers(
    execution: prover_api.CpuCompositionExecutionRequest,
    pool_capacity: usize,
) Error!usize {
    _ = work_pool.WorkerBudget.init(execution.worker_count) catch
        return error.InvalidWorkerBudget;
    if (pool_capacity == 0 or pool_capacity > work_pool.MAX_WORKERS) {
        return error.InvalidPoolCapacity;
    }
    if (execution.worker_count <= pool_capacity) return execution.worker_count;
    return switch (execution.contention_policy) {
        .strict => error.WorkerBudgetUnavailable,
        .compatibility => 1,
    };
}

fn checkedDomain(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.ResourceCalculationOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn computeLogSize(count: u32) u32 {
    if (count <= 1) return 1;
    return @intCast(std.math.log2_int_ceil(u32, count));
}

fn computeOpcodeLogSize(count: u32) u32 {
    return @max(@as(u32, 4), computeLogSize(count));
}

fn checkedAdd(lhs: usize, rhs: usize) Error!usize {
    return std.math.add(usize, lhs, rhs) catch
        error.ResourceCalculationOverflow;
}

fn checkedMul(lhs: usize, rhs: usize) Error!usize {
    return std.math.mul(usize, lhs, rhs) catch
        error.ResourceCalculationOverflow;
}

fn checkedU8(value: usize) Error!u8 {
    return std.math.cast(u8, value) orelse error.ResourceCalculationOverflow;
}

fn checkedU16(value: usize) Error!u16 {
    return std.math.cast(u16, value) orelse error.ResourceCalculationOverflow;
}

fn checkedU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.ResourceCalculationOverflow;
}
