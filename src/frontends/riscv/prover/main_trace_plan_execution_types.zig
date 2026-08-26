//! Stable value vocabulary for prepared RISC-V Tree-1 execution.

const prover_engine = @import("stwo_prover_engine");
const plan_mod = @import("main_trace_plan.zig");

pub const task_graph = prover_engine.task_graph;
pub const WAVE_COUNT: usize = 7;

pub const Wave = enum(u8) {
    prepare,
    generation,
    reduce,
    audit,
    lookup_seed,
    finalization,
    seal,
};

pub const TaskKind = enum {
    prepare,
    opcode_fill,
    infrastructure_fill,
    poseidon_fill,
    opcode_reduce,
    opcode_audit,
    lookup_seed,
    opcode_finalize,
    lookup_finalize,
    seal,
};

/// Immutable coordinator-derived facts for one allocation-free callback.
/// Generation tasks carry their exact disjoint row and/or descriptor ranges;
/// later stages carry the canonical descriptor they audit or finalize.
pub const Task = struct {
    key: task_graph.TaskKey,
    kind: TaskKind,
    registry_index: ?u32,
    chunk_index: u32,
    rows: ?plan_mod.RowRange,
    columns: ?plan_mod.ColumnRange,
};

/// The caller prepares every destination and all kernel state before graph
/// preparation. The context must support concurrent disjoint-range calls.
pub const Kernel = struct {
    context: *anyopaque,
    run: *const fn (
        context: *anyopaque,
        task: *const Task,
        task_context: *task_graph.TaskContext,
    ) anyerror!void,
};

/// Exact plan-level resource split presented to every drained graph. Executor
/// and graph metadata remain named coordinator allocations outside the first
/// plan seam, as documented by `main_trace_plan.zig`.
pub const Admission = struct {
    host_byte_budget: usize,
    planned_host_bytes: usize,
    final_output_bytes: usize,
    shared_resident_bytes: usize,
    helper_worker_stack_bytes: usize,
    helper_submission_bytes: usize,
};

pub const Lifecycle = enum {
    prepared,
    executing,
    published,
    failed,
};

/// Closed accounting across all non-empty drained waves. `peak_reserved_bytes`
/// is a high-water value, not a sum of repeated resident reservations.
pub const EpochReport = struct {
    configured_workers: usize,
    planned_tasks: usize,
    attempted_waves: usize,
    submitted_tasks: usize,
    succeeded_tasks: usize,
    failed_tasks: usize,
    cancelled_tasks: usize,
    unsubmitted_cancelled_tasks: usize,
    started_tasks: usize,
    finished_tasks: usize,
    duplicate_starts: usize,
    duplicate_finishes: usize,
    peak_active_tasks: usize,
    peak_reserved_bytes: usize,
    cancellation_winner: ?task_graph.TaskKey,
};

pub fn taskClass(kind: TaskKind) task_graph.TaskClass {
    return switch (kind) {
        .prepare, .opcode_reduce, .lookup_seed, .seal => .coordinator,
        .opcode_fill,
        .infrastructure_fill,
        .poseidon_fill,
        .opcode_audit,
        .opcode_finalize,
        .lookup_finalize,
        => .leaf,
    };
}

pub fn taskName(kind: TaskKind) []const u8 {
    return switch (kind) {
        .prepare => "opcode-prepare",
        .opcode_fill => "opcode-fill",
        .infrastructure_fill => "infrastructure-fill",
        .poseidon_fill => "poseidon2-fill",
        .opcode_reduce => "opcode-reduce",
        .opcode_audit => "opcode-audit",
        .lookup_seed => "lookup-seed",
        .opcode_finalize => "opcode-finalize",
        .lookup_finalize => "lookup-finalize",
        .seal => "seal",
    };
}

pub fn waveIndex(wave: Wave) usize {
    return @intFromEnum(wave);
}
