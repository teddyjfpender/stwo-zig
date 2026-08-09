//! Compact value types and checked primitives for RISC-V Tree-1 planning.
//!
//! Nothing in this module executes work, allocates, retains a statement, or
//! discovers runtime state. Keeping these primitives separate makes the
//! coordinator plan small enough to audit and gives later graph integration a
//! stable task/range/resource vocabulary without inventing a second protocol.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine");
const component_order = @import("../air/component_order.zig");
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const statement_mod = @import("../air/statement.zig");

pub const task_graph = prover_engine.task_graph;
pub const work_pool = prover_engine.work_pool;

pub const MAX_DESCRIPTORS: usize =
    statement_mod.MAX_COMPONENTS + statement_mod.MAX_INFRA_COMPONENTS;
pub const OPCODE_ROWS_PER_CHUNK: u32 = 1 << 16;
pub const POSEIDON_ROWS_PER_CHUNK: u32 = 4096;

pub const LOOKUP_COUNTER_SET_CELLS: usize = counterSetCellCount();
pub const LOOKUP_COUNTER_SET_PAYLOAD_BYTES: usize =
    LOOKUP_COUNTER_SET_CELLS * @sizeOf(M31);
pub const LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES: usize = @sizeOf(lookup_counter.Set);

comptime {
    // These are pinned by the six Stark-V lookup domains. A schema change must
    // make the Tree-1 budget change explicit instead of silently changing it.
    if (LOOKUP_COUNTER_SET_CELLS != 2_981_888)
        @compileError("RISC-V lookup-counter domain total changed");
    if (LOOKUP_COUNTER_SET_PAYLOAD_BYTES != 11_927_552)
        @compileError("RISC-V lookup-counter payload size changed");
}

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
    InvalidChunkCoverage,
    InvalidTaskIndex,
    InvalidPlan,
    TaskKeyOverflow,
};

/// Stable ranks within the first main-trace planning epoch. Gaps allow a later
/// coordinator barrier without renumbering every subsequent task identity.
pub const StageRank = enum(u16) {
    prepare = 0,
    fill = 10,
    reduce = 15,
    audit = 20,
    lookup_seed = 30,
    finalize = 40,
    seal = 50,
};

pub const MAIN_TRACE_EPOCH: u16 = 1;

comptime {
    if (@intFromEnum(StageRank.prepare) >= @intFromEnum(StageRank.fill) or
        @intFromEnum(StageRank.fill) >= @intFromEnum(StageRank.reduce) or
        @intFromEnum(StageRank.reduce) >= @intFromEnum(StageRank.audit) or
        @intFromEnum(StageRank.audit) >= @intFromEnum(StageRank.lookup_seed) or
        @intFromEnum(StageRank.lookup_seed) >= @intFromEnum(StageRank.finalize) or
        @intFromEnum(StageRank.finalize) >= @intFromEnum(StageRank.seal))
        @compileError("main-trace task stage ranks must be strictly ordered");
}

pub fn prepareTaskKey() task_graph.TaskKey {
    return taskKey(.prepare, 0, 0);
}

pub fn opcodeFillTaskKey(chunk_index: u32) task_graph.TaskKey {
    return taskKey(.fill, 0, chunk_index);
}

pub fn infrastructureFillTaskKey(
    opcode_component_count: u32,
    infra_index: u32,
    chunk_index: u32,
) Error!task_graph.TaskKey {
    return taskKey(
        .fill,
        std.math.add(u32, opcode_component_count, infra_index) catch
            return error.TaskKeyOverflow,
        chunk_index,
    );
}

pub fn opcodeAuditTaskKey(component_index: u32) task_graph.TaskKey {
    return taskKey(.audit, component_index, 0);
}

/// Deterministic merge of chunk-private opcode lookup counters. This is a
/// distinct barrier task: audits and lookup-table seeding may only observe the
/// merged counter set after it completes.
pub fn opcodeReduceTaskKey() task_graph.TaskKey {
    return taskKey(.reduce, 0, 0);
}

pub fn lookupSeedTaskKey() task_graph.TaskKey {
    return taskKey(.lookup_seed, 0, 0);
}

pub fn opcodeFinalizeTaskKey(component_index: u32) task_graph.TaskKey {
    return taskKey(.finalize, component_index, 0);
}

/// Generic infrastructure finalization identity. The statement-side planner
/// decides which infrastructure descriptors have a finalization task; this
/// constructor deliberately does not mislabel every infra index as a table.
pub fn infrastructureFinalizeTaskKey(
    opcode_component_count: u32,
    infra_index: u32,
) Error!task_graph.TaskKey {
    return taskKey(
        .finalize,
        std.math.add(u32, opcode_component_count, infra_index) catch
            return error.TaskKeyOverflow,
        0,
    );
}

pub fn sealTaskKey() task_graph.TaskKey {
    return taskKey(.seal, 0, 0);
}

fn taskKey(stage: StageRank, registry_index: u32, chunk_index: u32) task_graph.TaskKey {
    return .{
        .epoch = MAIN_TRACE_EPOCH,
        .stage_rank = @intFromEnum(stage),
        .component_registry_index = registry_index,
        .shard_or_chunk_index = chunk_index,
    };
}

pub const ColumnRange = struct {
    start: u32,
    len: u32,

    pub fn end(self: ColumnRange) Error!u32 {
        return std.math.add(u32, self.start, self.len) catch
            error.InvalidColumnCoverage;
    }
};

pub const RowRange = struct {
    start: u32 = 0,
    len: u32 = 0,

    pub fn end(self: RowRange) Error!u32 {
        return std.math.add(u32, self.start, self.len) catch
            error.InvalidChunkCoverage;
    }
};

/// Named host byte classes currently closed by this planning seam. `total`
/// uses checked addition over every field, so a newly added named class cannot
/// be omitted accidentally from finite-budget admission. Arena page padding,
/// allocation metadata, and graph/profile metadata remain outside this seam.
pub const Resources = struct {
    main_output_payload_bytes: usize = 0,
    retained_opcode_payload_bytes: usize = 0,
    retained_clock_payload_bytes: usize = 0,
    column_descriptor_bytes: usize = 0,
    column_log_size_bytes: usize = 0,
    ownership_ledger_bytes: usize = 0,
    opcode_classification_bytes: usize = 0,
    forward_placement_payload_bytes: usize = 0,
    forward_placement_descriptor_bytes: usize = 0,
    poseidon_inverse_placement_payload_bytes: usize = 0,
    poseidon_inverse_placement_descriptor_bytes: usize = 0,
    lookup_counter_payload_bytes: usize = 0,
    lookup_counter_descriptor_bytes: usize = 0,
    helper_worker_stack_bytes: usize = 0,
    helper_submission_bytes: usize = 0,

    pub fn total(self: Resources) Error!usize {
        var result: usize = 0;
        inline for (std.meta.fields(Resources)) |field| {
            result = std.math.add(usize, result, @field(self, field.name)) catch
                return error.ResourceCalculationOverflow;
        }
        return result;
    }
};

/// Counts are per drained sub-wave. Row chunks do not consume descriptor slots
/// in the same wave, matching ADR-0027's fixed-capacity model.
pub const TaskCounts = struct {
    descriptor_slots: u16 = 0,
    prepare_wave: u16 = 0,
    generation_wave: u16 = 0,
    reduce_wave: u16 = 0,
    audit_wave: u16 = 0,
    lookup_seed_wave: u16 = 0,
    finalization_wave: u16 = 0,
    seal_wave: u16 = 0,

    pub fn validate(self: TaskCounts) Error!void {
        inline for (std.meta.fields(TaskCounts)) |field| {
            if (@as(usize, @field(self, field.name)) > task_graph.MAX_COMPONENT_TASKS)
                return error.TaskCapacityExceeded;
        }
    }

    pub fn maxWave(self: TaskCounts) usize {
        var result: usize = 0;
        inline for (std.meta.fields(TaskCounts)) |field| {
            result = @max(result, @as(usize, @field(self, field.name)));
        }
        return result;
    }
};

pub const BuildOptions = struct {
    execution: prover_api.CpuCompositionExecutionRequest,
    /// Total request capacity, including its coordinator lane.
    pool_capacity: usize,
    worker_stack_bytes: usize = work_pool.WORKER_STACK_SIZE,
    enable_opcode_audit: bool = false,
};

/// Compact, pointer-free facts for one admitted main-trace construction.
/// `column_offsets[i..i+2]` is global descriptor `i`, with opcode descriptors
/// first and infrastructure descriptors following.
pub const Plan = struct {
    resources: Resources,
    task_counts: TaskCounts,
    host_byte_budget: usize,
    worker_stack_bytes: usize,
    column_offsets: [MAX_DESCRIPTORS + 1]u32,
    opcode_chunk_ranges: [work_pool.MAX_WORKERS]RowRange,
    poseidon_chunk_ranges: [work_pool.MAX_WORKERS]RowRange,
    total_steps: u32,
    total_columns: u32,
    n_components: u16,
    n_infra: u16,
    descriptor_count: u16,
    poseidon_infra_index: u16,
    requested_worker_count: u8,
    /// Width selected by pure admission planning. Production execution must
    /// acquire and hold a matching pool lease across all drained graph waves.
    planned_worker_count: u8,
    pool_capacity: u8,
    opcode_chunk_count: u8,
    poseidon_chunk_count: u8,
    contention_policy: prover_api.CpuCompositionContentionPolicy,
    opcode_audit_enabled: bool,

    pub fn requiredHostBytes(self: *const Plan) Error!usize {
        return self.resources.total();
    }

    pub fn descriptorRange(self: *const Plan, registry_index: usize) ?ColumnRange {
        if (registry_index >= @as(usize, self.descriptor_count)) return null;
        const start = self.column_offsets[registry_index];
        const end_offset = self.column_offsets[registry_index + 1];
        if (end_offset < start) return null;
        return .{ .start = start, .len = end_offset - start };
    }

    pub fn componentRange(self: *const Plan, component_index: usize) ?ColumnRange {
        if (component_index >= @as(usize, self.n_components)) return null;
        return self.descriptorRange(component_index);
    }

    pub fn infrastructureRange(self: *const Plan, infra_index: usize) ?ColumnRange {
        if (infra_index >= @as(usize, self.n_infra)) return null;
        return self.descriptorRange(@as(usize, self.n_components) + infra_index);
    }

    pub fn opcodeChunks(self: *const Plan) []const RowRange {
        return self.opcode_chunk_ranges[0..@as(usize, self.opcode_chunk_count)];
    }

    pub fn poseidonChunks(self: *const Plan) []const RowRange {
        return self.poseidon_chunk_ranges[0..@as(usize, self.poseidon_chunk_count)];
    }

    pub fn infraFillKey(
        self: *const Plan,
        infra_index: usize,
        chunk_index: u32,
    ) Error!task_graph.TaskKey {
        if (infra_index >= @as(usize, self.n_infra)) return error.InvalidTaskIndex;
        return infrastructureFillTaskKey(
            self.n_components,
            @intCast(infra_index),
            chunk_index,
        );
    }

    pub fn infraFinalizeKey(
        self: *const Plan,
        infra_index: usize,
    ) Error!task_graph.TaskKey {
        if (infra_index >= @as(usize, self.n_infra)) return error.InvalidTaskIndex;
        return infrastructureFinalizeTaskKey(
            self.n_components,
            @intCast(infra_index),
        );
    }
};

/// A capacity regression here becomes a main-thread stack regression. Future
/// large ownership belongs in an explicitly allocated workspace, not `Plan`.
pub const MAX_PLAN_SIZE_BYTES: usize = 4096;

comptime {
    if (@sizeOf(Plan) > MAX_PLAN_SIZE_BYTES)
        @compileError("main-trace Plan exceeded its pinned coordinator size ceiling");
}

pub fn naturalChunkCount(rows: u32, rows_per_chunk: u32, workers: usize) usize {
    std.debug.assert(rows_per_chunk != 0);
    std.debug.assert(workers != 0);
    const row_chunks: usize = if (rows == 0)
        1
    else
        @as(usize, 1 + (rows - 1) / rows_per_chunk);
    return @min(workers, row_chunks);
}

/// Partitions whole alignment units deterministically. Every nonterminal
/// boundary is aligned; the final chunk alone owns a partial tail. When fewer
/// workers than units are admitted, contiguous units are distributed with at
/// most one-unit skew without splitting a cache-aligned block.
pub fn writeAlignedPartition(
    destination: *[work_pool.MAX_WORKERS]RowRange,
    chunk_count: usize,
    total_rows: u32,
    alignment_rows: u32,
) Error!void {
    if (alignment_rows == 0 or chunk_count == 0 or chunk_count > destination.len)
        return error.InvalidChunkCoverage;
    destination.* = .{RowRange{}} ** work_pool.MAX_WORKERS;
    const total_units: u64 = if (total_rows == 0)
        1
    else
        1 + (@as(u64, total_rows) - 1) / alignment_rows;
    if (chunk_count > total_units) return error.InvalidChunkCoverage;

    for (0..chunk_count) |chunk_index| {
        const start_unit = (std.math.mul(u64, total_units, chunk_index) catch
            return error.ResourceCalculationOverflow) / chunk_count;
        const end_unit = (std.math.mul(u64, total_units, chunk_index + 1) catch
            return error.ResourceCalculationOverflow) / chunk_count;
        const raw_start = std.math.mul(u64, start_unit, alignment_rows) catch
            return error.ResourceCalculationOverflow;
        const raw_end = std.math.mul(u64, end_unit, alignment_rows) catch
            return error.ResourceCalculationOverflow;
        const start = @min(raw_start, total_rows);
        const end = @min(raw_end, total_rows);
        destination[chunk_index] = .{
            .start = try checkedU32FromU64(start),
            .len = try checkedU32FromU64(end - start),
        };
    }
}

pub fn validateAlignedPartition(
    ranges: []const RowRange,
    total_rows: u32,
    alignment_rows: u32,
) Error!void {
    if (alignment_rows == 0 or ranges.len == 0 or ranges.len > work_pool.MAX_WORKERS)
        return error.InvalidChunkCoverage;
    var cursor: u32 = 0;
    for (ranges, 0..) |range, index| {
        if (range.start != cursor) return error.InvalidChunkCoverage;
        if (index != 0 and range.start % alignment_rows != 0)
            return error.InvalidChunkCoverage;
        if (total_rows != 0 and range.len == 0) return error.InvalidChunkCoverage;
        cursor = try range.end();
        if (cursor > total_rows) return error.InvalidChunkCoverage;
        if (index + 1 < ranges.len and cursor % alignment_rows != 0)
            return error.InvalidChunkCoverage;
    }
    if (cursor != total_rows) return error.InvalidChunkCoverage;
}

pub fn checkedBytesForCells(cell_count: usize, element_size: usize) Error!usize {
    return checkedMul(cell_count, element_size);
}

pub fn counterSetReservationBytes() Error!usize {
    return checkedAdd(
        LOOKUP_COUNTER_SET_PAYLOAD_BYTES,
        LOOKUP_COUNTER_SET_DESCRIPTOR_BYTES,
    );
}

pub fn checkedDomain(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.ResourceCalculationOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn checkedDomainU32(log_size: u32) Error!u32 {
    if (log_size >= 32) return error.ResourceCalculationOverflow;
    return @as(u32, 1) << @intCast(log_size);
}

pub fn checkedAdd(lhs: anytype, rhs: anytype) Error!usize {
    const lhs_usize = std.math.cast(usize, lhs) orelse
        return error.ResourceCalculationOverflow;
    const rhs_usize = std.math.cast(usize, rhs) orelse
        return error.ResourceCalculationOverflow;
    return std.math.add(usize, lhs_usize, rhs_usize) catch
        error.ResourceCalculationOverflow;
}

pub fn checkedMul(lhs: anytype, rhs: anytype) Error!usize {
    const lhs_usize = std.math.cast(usize, lhs) orelse
        return error.ResourceCalculationOverflow;
    const rhs_usize = std.math.cast(usize, rhs) orelse
        return error.ResourceCalculationOverflow;
    return std.math.mul(usize, lhs_usize, rhs_usize) catch
        error.ResourceCalculationOverflow;
}

pub fn checkedU8(value: usize) Error!u8 {
    if (value > std.math.maxInt(u8)) return error.ResourceCalculationOverflow;
    return @intCast(value);
}

pub fn checkedU16(value: usize) Error!u16 {
    if (value > std.math.maxInt(u16)) return error.ResourceCalculationOverflow;
    return @intCast(value);
}

pub fn checkedU32(value: usize) Error!u32 {
    if (value > std.math.maxInt(u32)) return error.ResourceCalculationOverflow;
    return @intCast(value);
}

pub fn checkedU32FromU64(value: u64) Error!u32 {
    if (value > std.math.maxInt(u32)) return error.ResourceCalculationOverflow;
    return @intCast(value);
}

pub fn checkedTaskCount(value: usize) Error!u16 {
    if (value > task_graph.MAX_COMPONENT_TASKS) return error.TaskCapacityExceeded;
    return checkedU16(value);
}

fn counterSetCellCount() usize {
    var result: usize = 0;
    for (component_order.LOOKUP_TABLES) |kind| result += lookup_schema.size(kind);
    return result;
}
