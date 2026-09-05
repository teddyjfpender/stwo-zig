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
const composition_domain_scratch = @import("composition_domain_scratch.zig");
const composition_device_buckets = @import("composition_device_buckets.zig");
const composition_partition_parity = @import("composition_partition_parity.zig");
const lookup_resident = @import("base_polynomial_lookup_jobs.zig");
const quotient_geometry = @import("polynomial_quotient_geometry.zig");
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
const DeviceBucketSet = composition_device_buckets.DeviceBucketSet;
const M31TwiddleTree = prover.poly.twiddles.TwiddleTree([]const M31);

const disable_env = "STWO_ZIG_RISCV_METAL_SEMANTICS";
const parity_env = "STWO_ZIG_RISCV_METAL_COMPOSITION_PARITY";
pub const COMPOSITION_DOMAIN_SCRATCH_CONCURRENCY: u16 = composition_domain_scratch.OWNER_WINDOWS;

/// Frees pooled composition-domain scratch buffers; the Metal backend calls
/// this before tearing the shared runtime down.
pub const releasePooledCompositionScratch = composition_domain_scratch.releasePooledResidents;
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
        null,
        work_capture,
        null,
    );
}

pub fn evaluateWithWorkCaptureAndTwiddles(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    composition_twiddles: ?M31TwiddleTree,
    work_capture: ?*composition_work.Capture,
) !?SecureColumn {
    return evaluateInternal(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        composition_twiddles,
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
        null,
        execution.composition_work_capture,
        if (execution.task_recorder != null) execution else null,
    );
}

pub fn evaluateWithExecutionAndTwiddles(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
    composition_twiddles: ?M31TwiddleTree,
    execution: prover.air.composition_execution.Execution,
) !?SecureColumn {
    if (execution.task_recorder != null) try execution.validateCapacity();
    return evaluateInternal(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        composition_twiddles,
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
    composition_twiddles: ?M31TwiddleTree,
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

    const expansion_requests = try collectCompositionDomainRequests(
        allocator,
        components,
        partitions,
        trace,
    );
    defer allocator.free(expansion_requests);
    var scratch_lock_held = false;
    if (expansion_requests.len != 0) {
        composition_domain_scratch.acquireOwnerWindow();
        scratch_lock_held = true;
    }
    defer if (scratch_lock_held) composition_domain_scratch.releaseOwnerWindow();

    var lease = shared_runtime.acquireExisting() catch return declineResidentPolynomial();
    defer lease.deinit();
    var composition_scratch: ?composition_domain_scratch.OwnedV1 = null;
    defer if (composition_scratch) |*owned| owned.deinit();
    var accelerated_trace = trace;
    var composition_domain_resident: ?*const metal_runtime.ResidentBuffer = null;
    if (expansion_requests.len != 0) {
        const twiddles = composition_twiddles orelse
            return error.MissingCompositionDomainTwiddles;
        composition_scratch = try composition_domain_scratch.OwnedV1.init(
            allocator,
            lease.runtime,
            trace,
            expansion_requests,
            twiddles,
        );
        const owned = &composition_scratch.?;
        accelerated_trace = &owned.trace;
        composition_domain_resident = &owned.resident;
        telemetry.record(.metal_circle_transform_dispatch);
        std.log.info(
            "resident RISC-V composition-domain input: columns={} log={} bytes={} gpu_ms={d:.3} fill_ms={d:.3} fill_workers={} transform_ms={d:.3}",
            .{
                owned.entries.len,
                owned.evaluation_log_size,
                owned.resident.byte_length,
                owned.gpu_milliseconds,
                @as(f64, @floatFromInt(owned.host_fill_nanoseconds)) / 1e6,
                owned.host_fill_workers,
                @as(f64, @floatFromInt(owned.transform_wall_nanoseconds)) / 1e6,
            },
        );
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
            const job = try resolveBaseJob(
                component,
                capability,
                accelerated_trace,
                residency_handles,
            );
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
                accelerated_trace,
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

    for (base_programs.items) |*entry| {
        const name = try base_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        entry.plan = lease.runtime.prepareBasePolynomialAot(name) catch
            return declineResidentPolynomial();
    }
    lookup_catalog.prepareAll(lease.runtime) catch return declineResidentPolynomial();

    var semantic_buckets = try DeviceBucketSet.init(
        allocator,
        max_log_size,
        semantic_jobs,
    );
    defer semantic_buckets.deinit();
    var lookup_buckets = try DeviceBucketSet.init(
        allocator,
        max_log_size,
        lookup_jobs,
    );
    defer lookup_buckets.deinit();

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
        const denominator_inverses = try quotient_geometry.derive(
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
            .output_index = semantic_buckets.outputIndex(job.eval_log_size),
            .denominator_count = denominator_inverses.count,
            .denominator_inverses = quotient_geometry.words(denominator_inverses),
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
        const denominator_inverses = try quotient_geometry.derive(
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
            .output_index = lookup_buckets.outputIndex(job.eval_log_size),
            .denominator_count = denominator_inverses.count,
            .denominator_inverses = quotient_geometry.words(denominator_inverses),
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
        composition_domain_resident,
        main_column_ptrs,
        dispatches,
        power_words,
        semantic_buckets.outputs,
    );
    var lookup_gpu_result: ?metal_runtime.MetalError!f64 = null;
    if (lookup_jobs.len != 0) lookup_gpu_result = lease.runtime.evaluateLookupPolynomialBatch(
        residency_handles,
        composition_domain_resident,
        lookup_main_column_ptrs,
        interaction_column_ptrs,
        lookup_dispatches,
        power_words,
        parameter_words,
        lookup_buckets.outputs,
    );
    const semantic_gpu_ms = if (semantic_gpu_result) |result|
        result catch return declineResidentPolynomial()
    else
        null;
    const lookup_gpu_ms = if (lookup_gpu_result) |result|
        result catch return declineResidentPolynomial()
    else
        null;
    const parity_requested = try compositionParityRequested();

    // Both Metal batch entry points are synchronous.  On the ordinary route,
    // the five authenticated D5 dispatches have consumed the scratch before
    // host-only workers are joined, so free its one-gigabyte arena and release
    // the global one-owner lease immediately.  Diagnostic per-job replay still
    // needs the exact pointers and therefore retains the lease through parity.
    if (!parity_requested and composition_scratch != null) {
        composition_scratch.?.deinit();
        composition_scratch = null;
        composition_domain_resident = null;
        composition_domain_scratch.releaseOwnerWindow();
        scratch_lock_held = false;
    }
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
    if (semantic_gpu_ms) |gpu_ms| {
        telemetry.record(.metal_riscv_base_polynomial_batch_dispatch);
        std.log.info(
            "resident RISC-V semantic composition: {d} components, {d} kernels, {d:.3} ms GPU",
            .{ semantic_jobs.len, base_programs.items.len, gpu_ms },
        );
    }
    if (lookup_gpu_ms) |gpu_ms| {
        telemetry.record(.metal_riscv_lookup_polynomial_batch_dispatch);
        std.log.info(
            "resident RISC-V lookup composition: {d} components, {d} kernels, {d:.3} ms GPU",
            .{ lookup_jobs.len, lookup_catalog.programs.items.len, gpu_ms },
        );
    }

    if (parity_requested) try validatePartitionParity(
        allocator,
        components,
        powers,
        max_log_size,
        trace,
        residency_handles,
        composition_domain_resident,
        lease.runtime,
        semantic_jobs,
        main_column_ptrs,
        dispatches,
        power_words,
        &semantic_buckets,
        lookup_jobs,
        lookup_main_column_ptrs,
        interaction_column_ptrs,
        lookup_dispatches,
        parameter_words,
        &lookup_buckets,
        host_workers,
    );
    if (parity_requested and composition_scratch != null) {
        composition_scratch.?.deinit();
        composition_scratch = null;
        composition_domain_resident = null;
        composition_domain_scratch.releaseOwnerWindow();
        scratch_lock_held = false;
    }

    // Each batch ABI returns a complete zero-origin device result. Merge only
    // after both commands and all host workers have succeeded; this preserves
    // semantic and lookup contributions that share the same evaluation log.
    try composition_device_buckets.mergeCompleted(
        &semantic_buckets,
        &lookup_buckets,
    );

    const work_receipt = if (work_capture != null)
        try base_composition_work.build(
            allocator,
            components,
            total_constraints,
            max_log_size,
            semantic_jobs,
            lookup_jobs,
            host_workers,
            semantic_buckets.buckets,
        )
    else
        null;

    var combined = try Accumulator.initForComponent(powers, allocator, max_log_size, 0);
    defer combined.deinit();
    for (host_workers) |*worker| combined.merge(&worker.accumulator);
    for (semantic_buckets.buckets, 0..) |*maybe_bucket, log_size| {
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
    try validateFullCpuParityIfRequested(
        allocator,
        components,
        random_coeff,
        trace,
        &result,
        parity_requested,
    );
    if (work_receipt) |receipt| try work_capture.?.publish(receipt);
    return result;
}

/// Diagnostic-only split shadow. Each accelerated family and the host fallback
/// are compared independently before any merge, so a field-program defect,
/// an intra-command accumulation hazard, and a host/merge defect have distinct
/// evidence. Per-job device replay is attempted only after a family mismatch.
fn validatePartitionParity(
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
    host_workers: []const HostWorker,
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
    std.log.info(
        "METAL_RISCV_COMPOSITION_PARTITIONS_V1 elapsed_ns={}",
        .{timer.read()},
    );
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

fn logPartitionParity(
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
fn validateFullCpuParityIfRequested(
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

fn compositionParityRequested() !bool {
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

fn collectCompositionDomainRequests(
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
