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
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const base_codegen = @import("base_polynomial_codegen.zig");
const column_pointer_packing = @import("column_pointer_packing.zig");
const lookup_resident = @import("base_polynomial_lookup_jobs.zig");
const metal_runtime = @import("../runtime.zig");
const shared_runtime = @import("../shared_runtime.zig");
const telemetry = @import("../telemetry.zig");
const base_composition_work = @import("base_composition_work.zig");
const host_graph = @import("base_polynomial_host_graph.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Poly = prover.air.component_prover.Poly;
const BaseCapability = prover.air.component_prover.BasePolynomialCapabilityV1;
const ConstraintRange = prover.air.component_prover.ComponentConstraintRangeV1;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const SecureColumn = prover.secure_column.SecureColumnByCoords;
const composition_work = prover.air.composition_work;

const disable_env = "STWO_ZIG_RISCV_METAL_SEMANTICS";
/// Below 2^16 evaluation rows, four direct dispatches plus one lookup dispatch
/// do not amortize the resident command setup. Keep the complete reference
/// component on the host until this measured crossover; larger components use
/// the split resident programs without changing their relation or transcript.
const mixed_component_min_eval_log_size: u32 = 16;

const BaseProgramEntry = struct {
    program_id: u64,
    program: prover.air.component_prover.OwnedBasePolynomialProgram,
    plan: ?metal_runtime.BasePolynomialPlan = null,

    fn deinit(self: *BaseProgramEntry) void {
        if (self.plan) |*plan| plan.deinit();
        self.program.deinit();
        self.* = undefined;
    }
};

const HostWorker = host_graph.Worker;

const SemanticJob = struct {
    capability: BaseCapability,
    component: Component,
    power_start: usize,
    constraint_count: usize,
    row_count: usize,
    eval_log_size: u32,
    main_columns: []const Poly,
    selector: [*]const M31,
};

const ComponentPartition = struct {
    bases: [prover.air.component_prover.MAX_BASE_POLYNOMIAL_PARTITIONS_V1]struct {
        capability: BaseCapability,
        constraints: ConstraintRange,
    } = undefined,
    base_count: usize = 0,
    lookup: ?lookup_resident.Capability = null,
    lookup_constraints: ConstraintRange = .{ .start = 0, .count = 0 },

    fn accelerated(self: @This()) bool {
        return self.base_count != 0 or self.lookup != null;
    }
};

pub fn evaluate(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
) !?SecureColumn {
    return evaluateWithWorkCapture(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        null,
    );
}

pub fn evaluateWithWorkCapture(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    work_capture: ?*composition_work.Capture,
) !?SecureColumn {
    return evaluateInternal(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        work_capture,
        null,
    );
}

pub fn evaluateWithExecution(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    execution: prover.air.composition_execution.Execution,
) !?SecureColumn {
    if (execution.task_recorder != null) try execution.validateCapacity();
    return evaluateInternal(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        execution.composition_work_capture,
        if (execution.task_recorder != null) execution else null,
    );
}

fn evaluateInternal(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    work_capture: ?*composition_work.Capture,
    profiled_execution: ?prover.air.composition_execution.Execution,
) !?SecureColumn {
    if (components.len == 0) return null;

    var total_constraints: usize = 0;
    var max_log_size: u32 = 0;
    var semantic_count: usize = 0;
    var lookup_count: usize = 0;
    var accelerated_component_count: usize = 0;
    const partitions = try allocator.alloc(ComponentPartition, components.len);
    defer allocator.free(partitions);
    for (components, partitions) |component, *partition| {
        total_constraints = try std.math.add(
            usize,
            total_constraints,
            component.nConstraints(),
        );
        max_log_size = @max(max_log_size, component.maxConstraintLogDegreeBound());
        partition.* = try componentPartition(component);
        semantic_count += partition.base_count;
        if (partition.lookup != null) lookup_count += 1;
        if (partition.accelerated()) accelerated_component_count += 1;
    }
    if (semantic_count + lookup_count == 0) return null;
    telemetry.recordN(
        .riscv_base_polynomial_eligible_component,
        @intCast(semantic_count),
    );
    telemetry.recordN(
        .riscv_lookup_polynomial_eligible_component,
        @intCast(lookup_count),
    );
    if (std.posix.getenv(disable_env)) |value| {
        if (std.mem.eql(u8, value, "0")) return declineResidentPolynomial();
    }
    if (trace.polys.items.len == 0 or residency_handles.len == 0)
        return declineResidentPolynomial();
    for (partitions) |partition| {
        for (partition.bases[0..partition.base_count]) |base| {
            const capability = base.capability;
            if (!hasTreeResidency(
                residency_handles,
                &.{ capability.selector_tree_index, capability.main_tree_index },
            )) return declineResidentPolynomial();
        }
        if (partition.lookup) |capability| {
            if (!lookup_resident.hasResidency(capability, residency_handles))
                return declineResidentPolynomial();
        }
    }

    const powers = try prover.air.accumulation.generateSecurePowers(
        allocator,
        random_coeff,
        total_constraints,
    );
    defer allocator.free(powers);
    const power_words = try allocator.alloc(u32, powers.len * 4);
    defer allocator.free(power_words);
    for (powers, 0..) |power, index| {
        const coordinates = power.toM31Array();
        inline for (0..4) |coordinate|
            power_words[index * 4 + coordinate] = coordinates[coordinate].toU32();
    }

    var base_programs = std.ArrayList(BaseProgramEntry).empty;
    defer {
        for (base_programs.items) |*entry| entry.deinit();
        base_programs.deinit(allocator);
    }
    var lookup_catalog = lookup_resident.Catalog.init(allocator);
    defer lookup_catalog.deinit();
    const semantic_jobs = try allocator.alloc(SemanticJob, semantic_count);
    defer allocator.free(semantic_jobs);
    const lookup_jobs = try allocator.alloc(lookup_resident.Job, lookup_count);
    defer allocator.free(lookup_jobs);
    var initialized_lookup_jobs: usize = 0;
    defer for (lookup_jobs[0..initialized_lookup_jobs]) |*job| job.deinit(allocator);
    const host_workers = try allocator.alloc(
        HostWorker,
        components.len - accelerated_component_count,
    );
    defer allocator.free(host_workers);
    var initialized_workers: usize = 0;
    defer for (host_workers[0..initialized_workers]) |*worker| worker.deinit();

    var power_cursor = total_constraints;
    var semantic_index: usize = 0;
    var lookup_index: usize = 0;
    var host_index: usize = 0;
    for (components, partitions, 0..) |component, partition, component_registry_index| {
        const constraint_count = component.nConstraints();
        if (constraint_count > power_cursor) return error.InvalidBasePolynomialProgram;
        const power_start = power_cursor - constraint_count;
        power_cursor = power_start;

        for (partition.bases[0..partition.base_count]) |base| {
            const capability = base.capability;
            const range = base.constraints;
            const job_power_start = try rangePowerStart(
                power_start,
                constraint_count,
                range,
            );
            const job = try resolveBaseJob(component, capability, trace, residency_handles);
            semantic_jobs[semantic_index] = .{
                .capability = capability,
                .component = component,
                .power_start = job_power_start,
                .constraint_count = range.count,
                .row_count = job.row_count,
                .eval_log_size = job.eval_log_size,
                .main_columns = job.main_columns,
                .selector = job.selector,
            };
            semantic_index += 1;

            if (findBaseProgram(base_programs.items, capability.program_id) == null) {
                var program = try capability.export_program(component.ctx, allocator);
                errdefer program.deinit();
                try validateBaseProgram(program, capability, range.count);
                try base_programs.append(allocator, .{
                    .program_id = capability.program_id,
                    .program = program,
                });
            }
        }

        if (partition.lookup) |capability| {
            const range = partition.lookup_constraints;
            lookup_jobs[lookup_index] = try lookup_catalog.appendJob(
                component,
                capability,
                trace,
                residency_handles,
                try rangePowerStart(power_start, constraint_count, range),
                range.count,
            );
            initialized_lookup_jobs += 1;
            lookup_index += 1;
        }

        if (partition.accelerated()) continue;

        {
            host_workers[host_index] = .{
                .component = component,
                .trace = trace,
                .accumulator = try Accumulator.initForComponent(
                    powers,
                    allocator,
                    max_log_size,
                    power_start + constraint_count,
                ),
                .expected_next_power_index = power_start,
                .component_registry_index = std.math.cast(
                    u32,
                    component_registry_index,
                ) orelse return error.InvalidCompositionTaskKey,
            };
            initialized_workers += 1;
            if (profiled_execution != null) {
                try host_workers[host_index].prepare(allocator);
            }
            host_index += 1;
        }
    }
    std.debug.assert(power_cursor == 0);
    std.debug.assert(semantic_index == semantic_jobs.len);
    std.debug.assert(lookup_index == lookup_jobs.len);
    std.debug.assert(host_index == host_workers.len);

    // Ordinary host-only components start before resident AOT resolution, and
    // the dominant reviewed splitter may consume the ambient pool while this
    // thread submits device work. Profiled proving deliberately selects the
    // separate prepared graph path: it drains under the explicit request
    // before synchronous device dispatch, so every host worker is attributable
    // and no private thread or ambient-pool work escapes the task receipt.
    var wait_group = std.Thread.WaitGroup{};
    const pool = if (profiled_execution == null)
        prover.work_pool.getGlobalPool()
    else
        null;
    var host_pending = pool != null;
    defer if (host_pending) wait_group.wait();
    var parallel_thread: ?std.Thread = null;
    defer if (parallel_thread) |thread| thread.join();
    var parallel_on_caller: ?usize = null;
    if (profiled_execution) |execution| {
        try host_graph.execute(allocator, host_workers, execution);
    } else if (pool) |active| {
        const parallel_index = dominantParallelHostWorker(host_workers);
        for (host_workers, 0..) |*worker, index| {
            if (parallel_index != null and index == parallel_index.?) continue;
            active.spawnWg(&wait_group, HostWorker.runLegacy, .{worker});
        }
        if (parallel_index) |index| {
            parallel_thread = std.Thread.spawn(
                .{},
                HostWorker.runParallel,
                .{ &host_workers[index], active },
            ) catch null;
            if (parallel_thread == null) parallel_on_caller = index;
        }
    } else {
        for (host_workers) |*worker| HostWorker.runLegacy(worker);
    }

    var lease = shared_runtime.acquireExisting() catch return declineResidentPolynomial();
    defer lease.deinit();
    for (base_programs.items) |*entry| {
        const name = try base_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        entry.plan = lease.runtime.prepareBasePolynomialAot(name) catch
            return declineResidentPolynomial();
    }
    lookup_catalog.prepareAll(lease.runtime) catch return declineResidentPolynomial();

    const bucket_index = try allocator.alloc(?u32, max_log_size + 1);
    defer allocator.free(bucket_index);
    @memset(bucket_index, null);
    var bucket_count: usize = 0;
    for (semantic_jobs) |job| {
        if (bucket_index[job.eval_log_size] == null) {
            bucket_index[job.eval_log_size] = @intCast(bucket_count);
            bucket_count += 1;
        }
    }
    for (lookup_jobs) |job| {
        if (bucket_index[job.eval_log_size] == null) {
            bucket_index[job.eval_log_size] = @intCast(bucket_count);
            bucket_count += 1;
        }
    }
    const buckets = try allocator.alloc(?SecureColumn, max_log_size + 1);
    defer allocator.free(buckets);
    @memset(buckets, null);
    defer for (buckets) |*bucket| if (bucket.*) |*owned| owned.deinit(allocator);
    const outputs = try allocator.alloc(
        metal_runtime.BasePolynomialOutput,
        bucket_count,
    );
    defer allocator.free(outputs);
    for (bucket_index, 0..) |maybe_output, log_size| {
        const output_index = maybe_output orelse continue;
        const row_count = @as(usize, 1) << @intCast(log_size);
        buckets[log_size] = try SecureColumn.zeros(allocator, row_count);
        const bucket = &buckets[log_size].?;
        var columns: [4][*]u32 = undefined;
        inline for (0..4) |coordinate|
            columns[coordinate] = @ptrCast(bucket.columns[coordinate].ptr);
        outputs[output_index] = .{
            .columns = columns,
            .row_count = @intCast(row_count),
        };
    }

    var total_main_columns: usize = 0;
    for (semantic_jobs) |job| total_main_columns = try std.math.add(
        usize,
        total_main_columns,
        job.main_columns.len,
    );
    const main_column_ptrs = try allocator.alloc([*]const u32, total_main_columns);
    defer allocator.free(main_column_ptrs);
    const dispatches = try allocator.alloc(
        metal_runtime.BasePolynomialDispatch,
        semantic_jobs.len,
    );
    defer allocator.free(dispatches);
    var main_column_cursor: usize = 0;
    for (semantic_jobs, dispatches) |job, *dispatch| {
        const entry = findBaseProgram(base_programs.items, job.capability.program_id).?;
        const denominator_inverses = try denominators(
            job.capability.trace_log_size,
            job.eval_log_size,
        );
        dispatch.* = .{
            .plan = entry.plan.?.handle,
            .selector = @ptrCast(job.selector),
            .main_column_offset = @intCast(main_column_cursor),
            .main_column_count = @intCast(job.capability.main_column_count),
            .row_count = @intCast(job.row_count),
            .power_word_offset = @intCast(job.power_start * 4),
            .power_word_count = @intCast(job.constraint_count * 4),
            .output_index = bucket_index[job.eval_log_size].?,
            .denominator_inverses = .{
                denominator_inverses[0].toU32(),
                denominator_inverses[1].toU32(),
            },
        };
        try column_pointer_packing.pack(main_column_ptrs, &main_column_cursor, job.main_columns);
    }
    std.debug.assert(main_column_cursor == main_column_ptrs.len);

    var total_lookup_main_columns: usize = 0;
    var total_interaction_columns: usize = 0;
    var total_parameters: usize = 0;
    for (lookup_jobs) |job| {
        total_lookup_main_columns = try std.math.add(
            usize,
            total_lookup_main_columns,
            job.main_columns.len,
        );
        total_interaction_columns = try std.math.add(
            usize,
            total_interaction_columns,
            job.interaction_columns.len,
        );
        total_parameters = try std.math.add(usize, total_parameters, job.parameters.len);
    }
    const lookup_main_column_ptrs = try allocator.alloc([*]const u32, total_lookup_main_columns);
    defer allocator.free(lookup_main_column_ptrs);
    const interaction_column_ptrs = try allocator.alloc([*]const u32, total_interaction_columns);
    defer allocator.free(interaction_column_ptrs);
    const parameter_words = try allocator.alloc(u32, total_parameters * 4);
    defer allocator.free(parameter_words);
    const lookup_dispatches = try allocator.alloc(
        metal_runtime.LookupPolynomialDispatch,
        lookup_jobs.len,
    );
    defer allocator.free(lookup_dispatches);
    var lookup_main_cursor: usize = 0;
    var interaction_cursor: usize = 0;
    var parameter_cursor: usize = 0;
    for (lookup_jobs, lookup_dispatches) |job, *dispatch| {
        const denominator_inverses = try denominators(
            job.trace_log_size,
            job.eval_log_size,
        );
        dispatch.* = .{
            .plan = lookup_catalog.planHandle(job.program_index),
            .selector = @ptrCast(job.selector),
            .main_column_offset = @intCast(lookup_main_cursor),
            .main_column_count = @intCast(job.main_columns.len),
            .interaction_column_offset = @intCast(interaction_cursor),
            .interaction_column_count = @intCast(job.interaction_columns.len),
            .row_count = @intCast(job.row_count),
            .power_word_offset = @intCast(job.power_start * 4),
            .power_word_count = @intCast(job.constraint_count * 4),
            .parameter_word_offset = @intCast(parameter_cursor * 4),
            .parameter_word_count = @intCast(job.parameters.len * 4),
            .output_index = bucket_index[job.eval_log_size].?,
            .denominator_inverses = .{
                denominator_inverses[0].toU32(),
                denominator_inverses[1].toU32(),
            },
        };
        try column_pointer_packing.pack(lookup_main_column_ptrs, &lookup_main_cursor, job.main_columns);
        try column_pointer_packing.pack(interaction_column_ptrs, &interaction_cursor, job.interaction_columns);
        for (job.parameters, 0..) |parameter, index| {
            const coordinates = parameter.toM31Array();
            inline for (0..4) |coordinate|
                parameter_words[(parameter_cursor + index) * 4 + coordinate] =
                    coordinates[coordinate].toU32();
        }
        parameter_cursor += job.parameters.len;
    }
    std.debug.assert(lookup_main_cursor == lookup_main_column_ptrs.len);
    std.debug.assert(interaction_cursor == interaction_column_ptrs.len);
    std.debug.assert(parameter_cursor * 4 == parameter_words.len);

    var semantic_gpu_result: ?metal_runtime.MetalError!f64 = null;
    if (semantic_jobs.len != 0) semantic_gpu_result = lease.runtime.evaluateBasePolynomialBatch(
        residency_handles,
        main_column_ptrs,
        dispatches,
        power_words,
        outputs,
    );
    var lookup_gpu_result: ?metal_runtime.MetalError!f64 = null;
    if (lookup_jobs.len != 0) lookup_gpu_result = lease.runtime.evaluateLookupPolynomialBatch(
        residency_handles,
        lookup_main_column_ptrs,
        interaction_column_ptrs,
        lookup_dispatches,
        power_words,
        parameter_words,
        outputs,
    );
    if (parallel_on_caller) |index| HostWorker.runParallel(&host_workers[index], pool.?);
    if (parallel_thread) |thread| {
        thread.join();
        parallel_thread = null;
    }
    if (pool != null) {
        wait_group.wait();
        host_pending = false;
    }
    for (host_workers) |worker| if (worker.err) |err| return err;
    if (semantic_gpu_result) |result| {
        const gpu_ms = result catch return declineResidentPolynomial();
        telemetry.record(.metal_riscv_base_polynomial_batch_dispatch);
        std.log.info(
            "resident RISC-V semantic composition: {d} components, {d} kernels, {d:.3} ms GPU",
            .{ semantic_jobs.len, base_programs.items.len, gpu_ms },
        );
    }
    if (lookup_gpu_result) |result| {
        const gpu_ms = result catch return declineResidentPolynomial();
        telemetry.record(.metal_riscv_lookup_polynomial_batch_dispatch);
        std.log.info(
            "resident RISC-V lookup composition: {d} components, {d} kernels, {d:.3} ms GPU",
            .{ lookup_jobs.len, lookup_catalog.programs.items.len, gpu_ms },
        );
    }

    const work_receipt = if (work_capture != null)
        try base_composition_work.build(
            allocator,
            components,
            total_constraints,
            max_log_size,
            semantic_jobs,
            lookup_jobs,
            host_workers,
            buckets,
        )
    else
        null;

    var combined = try Accumulator.initForComponent(powers, allocator, max_log_size, 0);
    defer combined.deinit();
    for (host_workers) |*worker| combined.merge(&worker.accumulator);
    for (buckets, 0..) |*maybe_bucket, log_size| {
        if (maybe_bucket.*) |bucket| {
            if (combined.sub_accumulations[log_size]) |*host_bucket| {
                for (0..4) |coordinate| {
                    for (host_bucket.columns[coordinate], bucket.columns[coordinate]) |*lhs, rhs|
                        lhs.* = lhs.add(rhs);
                }
            } else {
                combined.sub_accumulations[log_size] = bucket;
                maybe_bucket.* = null;
            }
        }
    }
    var result = try combined.finalize();
    errdefer result.deinit(allocator);
    if (work_receipt) |receipt| try work_capture.?.publish(receipt);
    return result;
}
/// Picks the host component with the most domain work. Only one component may
/// recursively split over the shared pool at a time; all others remain leaf
/// jobs. This is the same scheduling invariant as the generic composition
/// path, preserved here while resident RISC-V jobs run on the GPU.
fn dominantParallelHostWorker(workers: []const HostWorker) ?usize {
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

fn declineResidentPolynomial() ?SecureColumn {
    telemetry.record(.cpu_riscv_polynomial_composition_decline);
    return null;
}

fn componentPartition(component: Component) !ComponentPartition {
    const capability = component.backend_composition_capability orelse return .{};
    return switch (capability) {
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
            if (component.maxConstraintLogDegreeBound() < mixed_component_min_eval_log_size)
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

fn rangePowerStart(
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

fn hasTreeResidency(handles: []const ?*anyopaque, indices: []const usize) bool {
    for (indices) |index| if (index >= handles.len or handles[index] == null) return false;
    return true;
}

fn findBaseProgram(entries: []BaseProgramEntry, program_id: u64) ?*BaseProgramEntry {
    for (entries) |*entry| if (entry.program_id == program_id) return entry;
    return null;
}

fn validateBaseProgram(
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

fn resolveBaseJob(
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
    if (eval_log_size != capability.trace_log_size + 1 or
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

fn denominators(trace_log_size: u32, eval_log_size: u32) ![2]M31 {
    if (eval_log_size != trace_log_size + 1) return error.InvalidBasePolynomialProgram;
    const eval_domain = core.poly.circle.canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const coset = core.poly.circle.canonic.CanonicCoset.new(trace_log_size).coset();
    var result: [2]M31 = undefined;
    for (&result, 0..) |*inverse, index| {
        inverse.* = try core.constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(core.utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    return result;
}
