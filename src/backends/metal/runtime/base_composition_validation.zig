//! Composition partition geometry, admission and independent CPU parity diagnostics.
//! Partial secure-composition evaluation for resident production AIRs.
//!
//! Frontend semantic and opcode-lookup components export the same polynomial
//! DAGs consumed by their reference evaluators. This stage resolves each DAG to
//! a content-addressed kernel in the authenticated core Metal library, evaluates
//! those components from proof-owned resident Merkle trees, and overlaps GPU
//! execution with the remaining host components. Every job consumes its
//! preassigned slice of the protocol's one random-power vector before log-size
//! buckets are merged normally.

const std = @import("std");
const execution_policy = @import("../execution_policy.zig");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition_domain_scratch = @import("composition_domain_scratch.zig");
const composition_device_buckets = @import("composition_device_buckets.zig");
const composition_partition_parity = @import("composition_partition_parity.zig");
const lookup_resident = @import("base_polynomial_lookup_jobs.zig");
const metal_runtime = @import("../runtime.zig");
const telemetry = @import("../telemetry.zig");
const host_graph = @import("base_polynomial_host_graph.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Poly = prover.air.component_prover.Poly;
const BaseCapability = prover.air.component_prover.BasePolynomialCapabilityV1;
const ConstraintRange = prover.air.component_prover.ComponentConstraintRangeV1;
const SecureColumn = prover.secure_column.SecureColumnByCoords;
const DeviceBucketSet = composition_device_buckets.DeviceBucketSet;

const parity_env = "STWO_ZIG_RISCV_METAL_COMPOSITION_PARITY";
pub const COMPOSITION_DOMAIN_SCRATCH_CONCURRENCY: u16 = composition_domain_scratch.OWNER_WINDOWS;

/// Frees pooled composition-domain scratch buffers; the Metal backend calls
/// this before tearing the shared runtime down.
pub const releasePooledCompositionScratch = composition_domain_scratch.tryReleasePooledResidents;
/// Below 2^16 evaluation rows, four direct dispatches plus one lookup dispatch
/// do not amortize the resident command setup. Keep the complete reference
/// component on the host until this measured crossover; larger components use
/// the split resident programs without changing their relation or transcript.
const mixed_component_min_eval_log_size: u32 = 16;

pub const BaseProgramEntry = struct {
    program_id: u64,
    program: prover.air.component_prover.OwnedBasePolynomialProgram,
    plan: ?metal_runtime.BasePolynomialPlan = null,

    pub fn deinit(self: *BaseProgramEntry) void {
        if (self.plan) |*plan| plan.deinit();
        self.program.deinit();
        self.* = undefined;
    }
};

pub const HostWorker = host_graph.Worker;

pub const SemanticJob = struct {
    capability: BaseCapability,
    component: Component,
    power_start: usize,
    constraint_count: usize,
    row_count: usize,
    eval_log_size: u32,
    main_columns: []const Poly,
    selector: [*]const M31,
};

pub const ComponentPartition = struct {
    bases: [prover.air.component_prover.MAX_BASE_POLYNOMIAL_PARTITIONS_V1]struct {
        capability: BaseCapability,
        constraints: ConstraintRange,
    } = undefined,
    base_count: usize = 0,
    lookup: ?lookup_resident.Capability = null,
    framework: ?prover.air.component_prover.FrameworkPolynomialCapabilityV1 = null,
    lookup_constraints: ConstraintRange = .{ .start = 0, .count = 0 },

    pub fn accelerated(self: @This()) bool {
        return self.base_count != 0 or self.lookup != null or self.framework != null;
    }
};

/// Diagnostic-only split shadow. Each accelerated family and the host fallback
/// are compared independently before any merge, so a field-program defect,
/// an intra-command accumulation hazard, and a host/merge defect have distinct
/// evidence. Per-job device replay is attempted only after a family mismatch.
pub fn validateDevicePartitionParity(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    composition_domain_resident: ?*const metal_runtime.ResidentBuffer,
    runtime: *metal_runtime.Runtime,
    semantic_jobs: []const SemanticJob,
    main_column_ptrs: []const [*]const u32,
    dispatches: []const metal_runtime.BasePolynomialDispatch,
    power_words: []const u32,
    semantic_buckets: *const DeviceBucketSet,
    lookup_jobs: []const lookup_resident.Job,
    lookup_main_column_ptrs: []const [*]const u32,
    interaction_column_ptrs: []const [*]const u32,
    lookup_dispatches: []const metal_runtime.LookupPolynomialDispatch,
    parameter_words: []const u32,
    lookup_buckets: *const DeviceBucketSet,
) !void {
    var timer = try std.time.Timer.start();
    if (semantic_jobs.len != 0) {
        var reference = try composition_partition_parity.referenceForJobs(
            allocator,
            components,
            powers,
            max_log_size,
            trace,
            semantic_jobs,
        );
        defer reference.deinit(allocator);
        var actual = try composition_partition_parity.finalizeBucketClone(
            allocator,
            semantic_buckets.buckets,
            max_log_size,
        );
        defer actual.deinit(allocator);
        if (composition_partition_parity.firstMismatch(&reference, &actual)) |mismatch| {
            std.log.err(
                "resident RISC-V semantic partition mismatch: row={} coordinate={} CPU={} Metal={}",
                .{ mismatch.row, mismatch.coordinate, mismatch.expected, mismatch.actual },
            );
            try diagnoseSemanticJobs(
                allocator,
                components,
                powers,
                max_log_size,
                trace,
                residency_handles,
                composition_domain_resident,
                runtime,
                semantic_jobs,
                main_column_ptrs,
                dispatches,
                power_words,
            );
            return error.MetalCompositionParityMismatch;
        }
        logPartitionParity("semantic", &actual, semantic_jobs.len);
    }

    if (lookup_jobs.len != 0) {
        var reference = try composition_partition_parity.referenceForJobs(
            allocator,
            components,
            powers,
            max_log_size,
            trace,
            lookup_jobs,
        );
        defer reference.deinit(allocator);
        var actual = try composition_partition_parity.finalizeBucketClone(
            allocator,
            lookup_buckets.buckets,
            max_log_size,
        );
        defer actual.deinit(allocator);
        if (composition_partition_parity.firstMismatch(&reference, &actual)) |mismatch| {
            std.log.err(
                "resident RISC-V lookup partition mismatch: row={} coordinate={} CPU={} Metal={}",
                .{ mismatch.row, mismatch.coordinate, mismatch.expected, mismatch.actual },
            );
            try diagnoseLookupJobs(
                allocator,
                components,
                powers,
                max_log_size,
                trace,
                residency_handles,
                composition_domain_resident,
                runtime,
                lookup_jobs,
                lookup_main_column_ptrs,
                interaction_column_ptrs,
                lookup_dispatches,
                power_words,
                parameter_words,
            );
            return error.MetalCompositionParityMismatch;
        }
        logPartitionParity("lookup", &actual, lookup_jobs.len);
    }

    std.log.info(
        "METAL_RISCV_COMPOSITION_PARTITIONS_V1 elapsed_ns={}",
        .{timer.read()},
    );
}

pub fn validateHostPartitionParity(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    host_workers: []const HostWorker,
) !void {
    if (host_workers.len != 0) {
        var reference = try composition_partition_parity.referenceForHostWorkers(
            allocator,
            components,
            powers,
            max_log_size,
            trace,
            host_workers,
        );
        defer reference.deinit(allocator);
        var actual = try composition_partition_parity.finalizeHostWorkerClones(
            allocator,
            host_workers,
            max_log_size,
        );
        defer actual.deinit(allocator);
        if (composition_partition_parity.firstMismatch(&reference, &actual)) |mismatch| {
            std.log.err(
                "resident RISC-V host partition mismatch: row={} coordinate={} CPU={} prepared={} ",
                .{ mismatch.row, mismatch.coordinate, mismatch.expected, mismatch.actual },
            );
            try diagnoseHostWorkers(
                allocator,
                components,
                powers,
                max_log_size,
                trace,
                host_workers,
            );
            return error.MetalCompositionParityMismatch;
        }
        logPartitionParity("host", &actual, host_workers.len);
    }
}

fn diagnoseSemanticJobs(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    composition_domain_resident: ?*const metal_runtime.ResidentBuffer,
    runtime: *metal_runtime.Runtime,
    jobs: []const SemanticJob,
    main_column_ptrs: []const [*]const u32,
    dispatches: []const metal_runtime.BasePolynomialDispatch,
    power_words: []const u32,
) !void {
    for (jobs, dispatches, 0..) |job, dispatch, job_index| {
        const one_job = [_]SemanticJob{job};
        var buckets = try DeviceBucketSet.init(allocator, max_log_size, &one_job);
        defer buckets.deinit();
        var one_dispatch = [_]metal_runtime.BasePolynomialDispatch{dispatch};
        one_dispatch[0].output_index = buckets.outputIndex(job.eval_log_size);
        _ = try runtime.evaluateBasePolynomialBatch(
            residency_handles,
            composition_domain_resident,
            main_column_ptrs,
            &one_dispatch,
            power_words,
            buckets.outputs,
        );
        var actual = try composition_partition_parity.finalizeBucketClone(
            allocator,
            buckets.buckets,
            max_log_size,
        );
        defer actual.deinit(allocator);
        var reference = try composition_partition_parity.referenceForJob(
            allocator,
            components,
            powers,
            max_log_size,
            trace,
            job.component,
            job.power_start,
            job.constraint_count,
        );
        defer reference.evaluation.deinit(allocator);
        if (composition_partition_parity.firstMismatch(
            &reference.evaluation,
            &actual,
        )) |mismatch| {
            std.log.err(
                "resident RISC-V semantic job mismatch: job={} component={} program_id=0x{x} power_start={} constraints={} eval_log={} row={} coordinate={} CPU={} Metal={}",
                .{
                    job_index,
                    reference.component_index,
                    job.capability.program_id,
                    job.power_start,
                    job.constraint_count,
                    job.eval_log_size,
                    mismatch.row,
                    mismatch.coordinate,
                    mismatch.expected,
                    mismatch.actual,
                },
            );
            return error.MetalCompositionParityMismatch;
        }
    }
    std.log.err(
        "resident RISC-V semantic jobs pass individually but their shared-output batch differs; intra-encoder accumulation ordering is invalid",
        .{},
    );
}

fn diagnoseLookupJobs(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    composition_domain_resident: ?*const metal_runtime.ResidentBuffer,
    runtime: *metal_runtime.Runtime,
    jobs: []const lookup_resident.Job,
    main_column_ptrs: []const [*]const u32,
    interaction_column_ptrs: []const [*]const u32,
    dispatches: []const metal_runtime.LookupPolynomialDispatch,
    power_words: []const u32,
    parameter_words: []const u32,
) !void {
    for (jobs, dispatches, 0..) |job, dispatch, job_index| {
        const one_job = [_]lookup_resident.Job{job};
        var buckets = try DeviceBucketSet.init(allocator, max_log_size, &one_job);
        defer buckets.deinit();
        var one_dispatch = [_]metal_runtime.LookupPolynomialDispatch{dispatch};
        one_dispatch[0].output_index = buckets.outputIndex(job.eval_log_size);
        _ = try runtime.evaluateLookupPolynomialBatch(
            residency_handles,
            composition_domain_resident,
            main_column_ptrs,
            interaction_column_ptrs,
            &one_dispatch,
            power_words,
            parameter_words,
            buckets.outputs,
        );
        var actual = try composition_partition_parity.finalizeBucketClone(
            allocator,
            buckets.buckets,
            max_log_size,
        );
        defer actual.deinit(allocator);
        var reference = try composition_partition_parity.referenceForJob(
            allocator,
            components,
            powers,
            max_log_size,
            trace,
            job.component,
            job.power_start,
            job.constraint_count,
        );
        defer reference.evaluation.deinit(allocator);
        if (composition_partition_parity.firstMismatch(
            &reference.evaluation,
            &actual,
        )) |mismatch| {
            std.log.err(
                "resident RISC-V lookup job mismatch: job={} component={} program_index={} power_start={} constraints={} trace_log={} eval_log={} row={} coordinate={} CPU={} Metal={}",
                .{
                    job_index,
                    reference.component_index,
                    job.program_index,
                    job.power_start,
                    job.constraint_count,
                    job.trace_log_size,
                    job.eval_log_size,
                    mismatch.row,
                    mismatch.coordinate,
                    mismatch.expected,
                    mismatch.actual,
                },
            );
            return error.MetalCompositionParityMismatch;
        }
    }
    std.log.err(
        "resident RISC-V lookup jobs pass individually but their shared-output batch differs; intra-encoder accumulation ordering is invalid",
        .{},
    );
}

fn diagnoseHostWorkers(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    workers: []const HostWorker,
) !void {
    for (workers, 0..) |worker, worker_index| {
        var actual = try composition_partition_parity.finalizeAccumulatorClone(
            allocator,
            &worker.accumulator,
        );
        defer actual.deinit(allocator);
        var reference = try composition_partition_parity.referenceForJob(
            allocator,
            components,
            powers,
            max_log_size,
            trace,
            worker.component,
            worker.expected_next_power_index,
            worker.component.nConstraints(),
        );
        defer reference.evaluation.deinit(allocator);
        if (composition_partition_parity.firstMismatch(
            &reference.evaluation,
            &actual,
        )) |mismatch| {
            std.log.err(
                "resident RISC-V host job mismatch: job={} component={} registry_index={} power_start={} constraints={} eval_log={} row={} coordinate={} CPU={} prepared={}",
                .{
                    worker_index,
                    reference.component_index,
                    worker.component_registry_index,
                    worker.expected_next_power_index,
                    worker.component.nConstraints(),
                    worker.component.maxConstraintLogDegreeBound(),
                    mismatch.row,
                    mismatch.coordinate,
                    mismatch.expected,
                    mismatch.actual,
                },
            );
            return error.MetalCompositionParityMismatch;
        }
    }
    std.log.err(
        "resident RISC-V host jobs pass individually but their accumulator merge differs",
        .{},
    );
}

pub fn logPartitionParity(
    comptime name: []const u8,
    column: *const SecureColumn,
    job_count: usize,
) void {
    const digest = composition_partition_parity.identity(column);
    const hex = std.fmt.bytesToHex(digest, .lower);
    std.log.info(
        "METAL_RISCV_COMPOSITION_PARTITION_V1 kind=" ++ name ++
            " jobs={} rows={} identity_sha256={s}",
        .{ job_count, column.len(), &hex },
    );
}

/// Diagnostic-only shadow evaluation. It replays the complete ordinary CPU
/// component path after the device/host merge and compares every canonical
/// field coordinate before the composition is committed or mixed into the
/// transcript. The environment switch never changes proof data.
pub fn validateFullCpuParityIfRequested(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    candidate: *const SecureColumn,
    requested: bool,
) !void {
    if (!requested) return;

    var timer = try std.time.Timer.start();
    const component_provers = prover.air.component_prover.ComponentProvers{
        .components = components,
        .n_preprocessed_columns = if (trace.polys.items.len == 0)
            0
        else
            trace.polys.items[0].len,
    };
    var reference = try component_provers.computeCompositionEvaluation(
        allocator,
        random_coeff,
        trace,
    );
    defer reference.deinit(allocator);
    if (reference.len() != candidate.len()) {
        std.log.err(
            "resident RISC-V composition parity length mismatch: CPU={} Metal={}",
            .{ reference.len(), candidate.len() },
        );
        return error.MetalCompositionParityMismatch;
    }
    for (0..candidate.len()) |row| {
        inline for (0..4) |coordinate| {
            const expected = reference.columns[coordinate][row];
            const actual = candidate.columns[coordinate][row];
            if (!expected.eql(actual)) {
                std.log.err(
                    "resident RISC-V composition parity mismatch: row={} coordinate={} CPU={} Metal={}",
                    .{ row, coordinate, expected.toU32(), actual.toU32() },
                );
                return error.MetalCompositionParityMismatch;
            }
        }
    }
    const identity = compositionIdentity(candidate);
    const identity_hex = std.fmt.bytesToHex(identity, .lower);
    std.log.info(
        "METAL_RISCV_COMPOSITION_PARITY_V1 rows={} constraints={} elapsed_ns={} identity_sha256={s}",
        .{ candidate.len(), component_provers.totalConstraints(), timer.read(), &identity_hex },
    );
}

pub fn compositionParityRequested() !bool {
    const value = std.posix.getenv(parity_env) orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidMetalCompositionParityMode;
}

fn compositionIdentity(column: *const SecureColumn) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo/metal/riscv-composition-parity/v1\x00");
    var encoded: [4]u8 = undefined;
    for (0..column.len()) |row| {
        inline for (0..4) |coordinate| {
            std.mem.writeInt(
                u32,
                &encoded,
                column.columns[coordinate][row].toU32(),
                .little,
            );
            hasher.update(&encoded);
        }
    }
    return hasher.finalResult();
}
/// Picks the host component with the most domain work. Only one component may
/// recursively split over the shared pool at a time; all others remain leaf
/// jobs. This is the same scheduling invariant as the generic composition
/// path, preserved here while resident RISC-V jobs run on the GPU.
pub fn dominantParallelHostWorker(workers: []const HostWorker) ?usize {
    var selected: ?usize = null;
    var selected_work: u128 = 0;
    for (workers, 0..) |worker, index| {
        if (worker.component.domain_parallel_evaluator == null) continue;
        const log_size = worker.component.maxConstraintLogDegreeBound();
        if (log_size >= @bitSizeOf(u128)) continue;
        const work = (@as(u128, 1) << @intCast(log_size)) *
            worker.component.nConstraints();
        if (selected == null or work > selected_work) {
            selected = index;
            selected_work = work;
        }
    }
    return selected;
}

pub fn declineResidentPolynomial() ?SecureColumn {
    telemetry.record(.cpu_riscv_polynomial_composition_decline);
    return null;
}

pub fn componentPartition(component: Component, mode: execution_policy.Mode, recursive_profile: bool) !ComponentPartition {
    const capability = component.backend_composition_capability orelse return .{};
    return switch (capability) {
        .framework_polynomial_v1 => |value| .{ .framework = value },
        .base_polynomial_v1 => |value| singleBasePartition(
            value,
            .{ .start = 0, .count = component.nConstraints() },
        ),
        .lookup_polynomial_v1 => |value| .{
            .lookup = .{ .v1 = value },
            .lookup_constraints = .{ .start = 0, .count = component.nConstraints() },
        },
        .lookup_polynomial_v2 => |value| .{
            .lookup = .{ .v2 = value },
            .lookup_constraints = .{ .start = 0, .count = component.nConstraints() },
        },
        .base_lookup_polynomial_v1 => |selected| blk: {
            if (mode == .hybrid and !recursive_profile and component.maxConstraintLogDegreeBound() < mixed_component_min_eval_log_size)
                break :blk .{};
            const exported = try selected.export_capabilities(component.ctx);
            try exported.validate(component.nConstraints());
            var result = ComponentPartition{
                .base_count = exported.base_partition_count,
                .lookup = .{ .v1 = exported.lookup },
                .lookup_constraints = exported.lookup_constraints,
            };
            for (exported.base_partitions[0..exported.base_partition_count], 0..) |base, index| {
                result.bases[index] = .{
                    .capability = base.capability,
                    .constraints = base.constraints,
                };
            }
            break :blk result;
        },
        else => .{},
    };
}

fn singleBasePartition(
    capability: BaseCapability,
    constraints: ConstraintRange,
) ComponentPartition {
    var result = ComponentPartition{ .base_count = 1 };
    result.bases[0] = .{ .capability = capability, .constraints = constraints };
    return result;
}

pub fn rangePowerStart(
    component_power_start: usize,
    total_constraints: usize,
    range: ConstraintRange,
) !usize {
    const range_end = std.math.add(usize, range.start, range.count) catch
        return error.InvalidBackendCompositionPartition;
    if (range.count == 0 or range_end > total_constraints)
        return error.InvalidBackendCompositionPartition;
    return std.math.add(
        usize,
        component_power_start,
        total_constraints - range_end,
    ) catch error.InvalidBackendCompositionPartition;
}

pub fn hasTreeResidency(handles: []const ?*anyopaque, indices: []const usize) bool {
    for (indices) |index| if (index >= handles.len or handles[index] == null) return false;
    return true;
}

pub fn collectCompositionDomainRequests(
    allocator: std.mem.Allocator,
    components: []const Component,
    partitions: []const ComponentPartition,
    trace: *const Trace,
) ![]composition_domain_scratch.RequestV1 {
    var requests = std.ArrayList(composition_domain_scratch.RequestV1).empty;
    errdefer requests.deinit(allocator);
    for (components, partitions) |component, partition| {
        const evaluation_log_size = component.maxConstraintLogDegreeBound();
        for (partition.bases[0..partition.base_count]) |base| {
            const capability = base.capability;
            try appendCompositionDomainRange(
                &requests,
                allocator,
                trace,
                capability.selector_tree_index,
                capability.selector_column,
                1,
                capability.trace_log_size,
                evaluation_log_size,
            );
            try appendCompositionDomainRange(
                &requests,
                allocator,
                trace,
                capability.main_tree_index,
                capability.first_main_column,
                capability.main_column_count,
                capability.trace_log_size,
                evaluation_log_size,
            );
        }
        if (partition.lookup) |capability| {
            const geometry = lookup_resident.physicalGeometry(capability);
            try appendCompositionDomainRange(
                &requests,
                allocator,
                trace,
                geometry.selector_tree_index,
                geometry.selector_column,
                1,
                geometry.trace_log_size,
                evaluation_log_size,
            );
            try appendCompositionDomainRange(
                &requests,
                allocator,
                trace,
                geometry.main_tree_index,
                geometry.first_main_column,
                geometry.main_column_count,
                geometry.trace_log_size,
                evaluation_log_size,
            );
            try appendCompositionDomainRange(
                &requests,
                allocator,
                trace,
                geometry.interaction_tree_index,
                geometry.first_interaction_column,
                geometry.interaction_column_count,
                geometry.trace_log_size,
                evaluation_log_size,
            );
        }
    }
    return requests.toOwnedSlice(allocator);
}

fn appendCompositionDomainRange(
    requests: *std.ArrayList(composition_domain_scratch.RequestV1),
    allocator: std.mem.Allocator,
    trace: *const Trace,
    tree_index: usize,
    first_column: usize,
    column_count: usize,
    trace_log_size: u32,
    evaluation_log_size: u32,
) !void {
    if (tree_index >= trace.polys.items.len or
        first_column > trace.polys.items[tree_index].len or
        column_count > trace.polys.items[tree_index].len - first_column or
        evaluation_log_size <= trace_log_size)
    {
        return error.InvalidCompositionDomainScratchRequest;
    }
    for (first_column..first_column + column_count) |column_index| {
        const poly = trace.polys.items[tree_index][column_index];
        try poly.validate();
        if (poly.log_size == evaluation_log_size) continue;
        if (poly.log_size > evaluation_log_size)
            return error.InvalidCompositionDomainScratchRequest;
        try requests.append(allocator, .{
            .tree_index = tree_index,
            .column_index = column_index,
            .trace_log_size = trace_log_size,
            .evaluation_log_size = evaluation_log_size,
        });
    }
}

pub fn findBaseProgram(entries: []BaseProgramEntry, program_id: u64) ?*BaseProgramEntry {
    for (entries) |*entry| if (entry.program_id == program_id) return entry;
    return null;
}

pub fn validateBaseProgram(
    program: prover.air.component_prover.OwnedBasePolynomialProgram,
    capability: BaseCapability,
    expected_constraint_count: usize,
) !void {
    try program.validate();
    if (program.column_count != capability.main_column_count + 1 or
        program.roots.len != expected_constraint_count)
        return error.InvalidBasePolynomialProgram;
}

const ResolvedBaseJob = struct {
    row_count: usize,
    eval_log_size: u32,
    main_columns: []const Poly,
    selector: [*]const M31,
};

pub fn resolveBaseJob(
    component: Component,
    capability: BaseCapability,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
) !ResolvedBaseJob {
    if (capability.selector_tree_index >= trace.polys.items.len or
        capability.main_tree_index >= trace.polys.items.len or
        capability.selector_tree_index >= residency_handles.len or
        capability.main_tree_index >= residency_handles.len or
        residency_handles[capability.selector_tree_index] == null or
        residency_handles[capability.main_tree_index] == null)
        return error.MissingBasePolynomialResidency;
    const eval_log_size = component.maxConstraintLogDegreeBound();
    if (eval_log_size <= capability.trace_log_size or
        eval_log_size - capability.trace_log_size > 3 or
        eval_log_size >= @bitSizeOf(usize))
        return error.InvalidBasePolynomialProgram;
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    const selector_tree = trace.polys.items[capability.selector_tree_index];
    const main_tree = trace.polys.items[capability.main_tree_index];
    if (capability.selector_column >= selector_tree.len or
        capability.first_main_column > main_tree.len or
        capability.main_column_count > main_tree.len - capability.first_main_column)
        return error.InvalidBasePolynomialProgram;
    const selector = selector_tree[capability.selector_column];
    if (selector.log_size != eval_log_size or selector.values.len != row_count)
        return error.InvalidBasePolynomialProgram;
    const main = main_tree[capability.first_main_column..][0..capability.main_column_count];
    for (main) |column| {
        if (column.log_size != eval_log_size or column.values.len != row_count)
            return error.InvalidBasePolynomialProgram;
    }
    return .{
        .row_count = row_count,
        .eval_log_size = eval_log_size,
        .main_columns = main,
        .selector = selector.values.ptr,
    };
}
