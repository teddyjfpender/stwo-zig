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
const base_codegen = @import("base_polynomial_codegen.zig");
const column_pointer_packing = @import("column_pointer_packing.zig");
const composition_domain_scratch = @import("composition_domain_scratch.zig");
const composition_device_buckets = @import("composition_device_buckets.zig");
const composition_partition_parity = @import("composition_partition_parity.zig");
const lookup_resident = @import("base_polynomial_lookup_jobs.zig");
const framework_jobs_mod = @import("framework_polynomial_jobs.zig");
const framework_batch = @import("framework_polynomial_batch.zig");
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
pub const releasePooledCompositionScratch = composition_domain_scratch.tryReleasePooledResidents;
/// Below 2^16 evaluation rows, four direct dispatches plus one lookup dispatch
/// do not amortize the resident command setup. Keep the complete reference
/// component on the host until this measured crossover; larger components use
/// the split resident programs without changing their relation or transcript.
const mixed_component_min_eval_log_size: u32 = 16;

const validation = @import("base_composition_validation.zig");
const BaseProgramEntry = validation.BaseProgramEntry;
const SemanticJob = validation.SemanticJob;
const ComponentPartition = validation.ComponentPartition;
const validateDevicePartitionParity = validation.validateDevicePartitionParity;
const validateHostPartitionParity = validation.validateHostPartitionParity;
const logPartitionParity = validation.logPartitionParity;
const validateFullCpuParityIfRequested = validation.validateFullCpuParityIfRequested;
const compositionParityRequested = validation.compositionParityRequested;
const dominantParallelHostWorker = validation.dominantParallelHostWorker;
const declineResidentPolynomial = validation.declineResidentPolynomial;
const componentPartition = validation.componentPartition;
const rangePowerStart = validation.rangePowerStart;
const hasTreeResidency = validation.hasTreeResidency;
const collectCompositionDomainRequests = validation.collectCompositionDomainRequests;
const findBaseProgram = validation.findBaseProgram;
const validateBaseProgram = validation.validateBaseProgram;
const resolveBaseJob = validation.resolveBaseJob;
const HostWorker = host_graph.Worker;

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
    const execution_mode = try execution_policy.requested();
    const admission_diagnostic = try compositionParityRequested();
    var timing = host_graph.WallTiming.requested();
    defer if (timing) |*clock| clock.finish();
    if (components.len == 0) return null;
    var lease = shared_runtime.acquireExisting() catch return declineResidentPolynomial();
    defer lease.deinit();

    var total_constraints: usize = 0;
    var max_log_size: u32 = 0;
    var semantic_count: usize = 0;
    var lookup_count: usize = 0;
    var framework_count: usize = 0;
    var accelerated_component_count: usize = 0;
    const partitions = try allocator.alloc(ComponentPartition, components.len);
    defer allocator.free(partitions);
    for (components) |component| {
        total_constraints = try std.math.add(usize, total_constraints, component.nConstraints());
        max_log_size = @max(max_log_size, component.maxConstraintLogDegreeBound());
    }
    const job_storage = try allocator.alloc(framework_jobs_mod.Job, components.len);
    defer allocator.free(job_storage);
    defer for (job_storage[0..framework_count]) |*job| job.deinit();
    const tree_counts = try allocator.alloc(usize, trace.polys.items.len);
    defer allocator.free(tree_counts);
    for (trace.polys.items, tree_counts) |tree, *count| count.* = tree.len;
    var cursor = total_constraints;
    for (components, partitions) |component, *partition| {
        cursor -= component.nConstraints();
        partition.* = try componentPartition(component, execution_mode, lease.runtime.admitted_profile == .recursive_framework_v1);
        // Keep the retained core host route available for matched measurements.
        if (lease.runtime.admitted_profile != .recursive_framework_v1 and
            std.posix.getenv("STWO_RISCV_CPU_HASH_COMPOSITION") != null)
            partition.framework = null;
        if (partition.framework) |capability| {
            // Export and authenticate once. Availability is determined by the
            // exact executable identity, never the component name or workload.
            var job = try framework_jobs_mod.Job.init(allocator, component, capability, tree_counts, cursor);
            const supported = if (lease.runtime.admitted_profile) |profile| supported: {
                for (profile.exports()) |entry| {
                    if (std.mem.eql(u8, entry.name, job.kernel_name)) break :supported true;
                }
                break :supported false;
            } else false;
            if (admission_diagnostic) std.debug.print("METAL_FRAMEWORK_ADMISSION name={s} supported={}\n", .{ job.kernel_name, supported });
            if (supported) {
                job_storage[framework_count] = job;
                framework_count += 1;
            } else {
                job.deinit();
                partition.framework = null;
            }
        }
        // Resident-only families cannot address a streamed host tree. Keep
        // that entire component on the host while independently admitted
        // framework jobs stage their exact columns in bounded domain groups.
        var resident = true;
        for (partition.bases[0..partition.base_count]) |base| {
            resident = resident and hasTreeResidency(residency_handles, &.{ base.capability.selector_tree_index, base.capability.main_tree_index });
        }
        if (partition.lookup) |capability| resident = resident and lookup_resident.hasResidency(capability, residency_handles);
        if (!resident) partition.* = .{};
        semantic_count += partition.base_count;
        if (partition.lookup != null) lookup_count += 1;
        if (partition.accelerated()) accelerated_component_count += 1;
    }
    const framework_jobs = job_storage[0..framework_count];
    if (admission_diagnostic) std.debug.print("METAL_COMPOSITION_ADMISSION base={} lookup={} framework={} resident_handles={any}\n", .{ semantic_count, lookup_count, framework_count, residency_handles });
    if (semantic_count + lookup_count + framework_count == 0) return null;
    const host_component_count = components.len - accelerated_component_count;
    if (host_component_count != 0) {
        // Fail before preparing or launching any host worker in a mixed graph.
        try execution_mode.admitHost(.composition);
    }
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
    // Cold program admission precedes bulk scratch allocation. In particular,
    // core-only bundles may lack newly exported provider kernels; decline that
    // request before reconstructing expanded provider columns or starting CPU work.
    var base_programs = std.ArrayList(BaseProgramEntry).empty;
    defer {
        for (base_programs.items) |*entry| entry.deinit();
        base_programs.deinit(allocator);
    }
    for (components, partitions) |component, partition| {
        for (partition.bases[0..partition.base_count]) |base| {
            if (findBaseProgram(base_programs.items, base.capability.program_id) == null) {
                var program = try base.capability.export_program(component.ctx, allocator);
                errdefer program.deinit();
                try validateBaseProgram(program, base.capability, base.constraints.count);
                try base_programs.append(allocator, .{
                    .program_id = base.capability.program_id,
                    .program = program,
                });
            }
        }
    }
    for (base_programs.items) |*entry| {
        const name = try base_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        entry.plan = lease.runtime.prepareBasePolynomialAot(name) catch
            return declineResidentPolynomial();
    }
    for (framework_jobs) |*job| job.prepare(lease.runtime) catch |err| switch (err) {
        error.FrameworkPolynomialUnavailable => return declineResidentPolynomial(),
        else => return err,
    };

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
    defer for (host_workers[0..initialized_workers]) |*worker| {
        // The later join defers run first, including on error or resident decline.
        worker.reportTiming();
        worker.deinit();
    };

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
                .timing = .{ .origin = if (timing) |clock| clock.origin else null },
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

    lookup_catalog.prepareAll(lease.runtime) catch |err| {
        if (admission_diagnostic) std.debug.print("METAL_COMPOSITION_LOOKUP_DECLINED {s}\n", .{@errorName(err)});
        return declineResidentPolynomial();
    };

    // All AOT families have resolved before host work starts. A dominant
    // reviewed splitter may consume the ambient pool while this
    // thread submits device work. Profiled proving deliberately selects the
    // separate prepared graph path: it drains under the explicit request
    // before synchronous device dispatch, so every host worker is attributable
    // and no private thread or ambient-pool work escapes the task receipt.
    // Count executed host placement, not a tentative partition that may have
    // declined for a missing AOT kernel. Terminal fallback counts the full roster.
    telemetry.recordN(.cpu_composition_component, @intCast(host_component_count));
    if (timing) |*clock| clock.enter(.host_launch_or_inline);
    var wait_group = std.Thread.WaitGroup{};
    const pool = if (profiled_execution == null)
        prover.work_pool.getGlobalPool()
    else
        null;
    if (timing) |*clock| clock.scheduler = if (profiled_execution != null)
        .structured
    else if (pool != null)
        .pool
    else
        .inline_host;
    var host_pending = pool != null;
    defer if (host_pending) wait_group.wait();
    var parallel_thread: ?std.Thread = null;
    defer if (parallel_thread) |thread| thread.join();
    var parallel_on_caller: ?usize = null;
    if (profiled_execution) |execution| {
        if (host_workers.len != 0) try host_graph.execute(allocator, host_workers, execution);
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

    if (timing) |*clock| clock.enter(.device_preparation);

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

    var framework_buckets = try DeviceBucketSet.init(allocator, max_log_size, framework_jobs);
    defer framework_buckets.deinit();

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

    if (timing) |*clock| clock.enter(.semantic_dispatch);
    var semantic_gpu_result: ?metal_runtime.MetalError!f64 = null;
    if (semantic_jobs.len != 0) semantic_gpu_result = lease.runtime.evaluateBasePolynomialBatch(
        residency_handles,
        composition_domain_resident,
        main_column_ptrs,
        dispatches,
        power_words,
        semantic_buckets.outputs,
    );
    if (timing) |*clock| clock.enter(.lookup_dispatch);
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

    if (timing) |*clock| clock.enter(.device_partition_parity);
    if (parity_requested) try validateDevicePartitionParity(
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
    );
    // Device replay is the final consumer of the old family scratch. Release
    // it before framework groups acquire the same bounded owner window.
    if (timing) |*clock| clock.enter(.scratch_release);
    if (composition_scratch != null) {
        composition_scratch.?.deinit();
        composition_scratch = null;
        composition_domain_resident = null;
        composition_domain_scratch.releaseOwnerWindow();
        scratch_lock_held = false;
    }
    if (timing) |*clock| clock.enter(.framework_dispatch);
    const framework_result = try framework_batch.evaluate(
        allocator,
        lease.runtime,
        framework_jobs,
        trace,
        residency_handles,
        composition_twiddles,
        power_words,
        &framework_buckets,
        scratch_lock_held,
    );
    if (framework_result.dispatches != 0) {
        telemetry.recordN(.metal_framework_polynomial_dispatch, @intCast(framework_result.dispatches));
        if (admission_diagnostic or std.posix.getenv("STWO_RISCV_EXECUTION_PROFILE") != null) std.debug.print("METAL_FRAMEWORK_COMPOSITION components={} groups={} gpu_ms={d:.3}\n", .{
            framework_result.dispatches, framework_result.groups, framework_result.gpu_milliseconds,
        });
    }
    if (timing) |*clock| clock.enter(.host_wait);
    if (parallel_on_caller) |index| HostWorker.runParallel(&host_workers[index], pool.?);
    if (parallel_thread) |thread| {
        thread.join();
        parallel_thread = null;
    }
    if (pool != null) {
        wait_group.wait();
        host_pending = false;
    }
    if (timing) |*clock| clock.enter(.partition_parity);
    for (host_workers) |worker| if (worker.err) |err| return err;
    if (semantic_gpu_ms) |gpu_ms| {
        if (timing != null) std.log.info("metal composition device: family=semantic gpu_ms={d:.6}", .{gpu_ms});
        telemetry.record(.metal_riscv_base_polynomial_batch_dispatch);
        std.log.info(
            "resident RISC-V semantic composition: {d} components, {d} kernels, {d:.3} ms GPU",
            .{ semantic_jobs.len, base_programs.items.len, gpu_ms },
        );
    }
    if (lookup_gpu_ms) |gpu_ms| {
        if (timing != null) std.log.info("metal composition device: family=lookup gpu_ms={d:.6}", .{gpu_ms});
        telemetry.record(.metal_riscv_lookup_polynomial_batch_dispatch);
        std.log.info(
            "resident RISC-V lookup composition: {d} components, {d} kernels, {d:.3} ms GPU",
            .{ lookup_jobs.len, lookup_catalog.programs.items.len, gpu_ms },
        );
    }

    if (parity_requested) try validateHostPartitionParity(
        allocator,
        components,
        powers,
        max_log_size,
        trace,
        host_workers,
    );

    if (parity_requested and framework_jobs.len != 0) {
        var reference = try composition_partition_parity.referenceForJobs(
            allocator,
            components,
            powers,
            max_log_size,
            trace,
            framework_jobs,
        );
        defer reference.deinit(allocator);
        var actual = try composition_partition_parity.finalizeBucketClone(allocator, framework_buckets.buckets, max_log_size);
        defer actual.deinit(allocator);
        if (composition_partition_parity.firstMismatch(&reference, &actual) != null)
            return error.MetalCompositionParityMismatch;
        logPartitionParity("framework", &actual, framework_jobs.len);
    }

    // Each batch ABI returns a complete zero-origin device result. Merge only
    // after both commands and all host workers have succeeded; this preserves
    // semantic and lookup contributions that share the same evaluation log.
    if (timing) |*clock| clock.enter(.device_merge);
    try composition_device_buckets.mergeCompleted(
        &semantic_buckets,
        &lookup_buckets,
    );

    try composition_device_buckets.mergeCompleted(&semantic_buckets, &framework_buckets);

    if (timing) |*clock| clock.enter(.work_receipt);
    const work_receipt = if (work_capture != null)
        try base_composition_work.build(
            allocator,
            components,
            total_constraints,
            max_log_size,
            semantic_jobs,
            lookup_jobs,
            framework_jobs,
            host_workers,
            semantic_buckets.buckets,
        )
    else
        null;

    if (timing) |*clock| clock.enter(.accumulation);
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
    if (timing) |*clock| clock.enter(.full_parity);
    try validateFullCpuParityIfRequested(
        allocator,
        components,
        random_coeff,
        trace,
        &result,
        parity_requested,
    );
    if (timing) |*clock| clock.enter(.publication);
    if (work_receipt) |receipt| try work_capture.?.publish(receipt);
    if (timing) |*clock| {
        clock.completed = true;
        clock.enter(.cleanup);
    }
    return result;
}
