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
const lookup_codegen = @import("lookup_polynomial_codegen.zig");
const metal_runtime = @import("../runtime.zig");
const shared_runtime = @import("../shared_runtime.zig");
const telemetry = @import("../telemetry.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Poly = prover.air.component_prover.Poly;
const BaseCapability = prover.air.component_prover.BasePolynomialCapabilityV1;
const LookupCapability = prover.air.component_prover.LookupPolynomialCapabilityV1;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const SecureColumn = prover.secure_column.SecureColumnByCoords;

const disable_env = "STWO_ZIG_RISCV_METAL_SEMANTICS";

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

const LookupProgramEntry = struct {
    program_id: u64,
    program: prover.air.component_prover.OwnedLookupPolynomialProgram,
    plan: ?metal_runtime.LookupPolynomialPlan = null,

    fn deinit(self: *LookupProgramEntry) void {
        if (self.plan) |*plan| plan.deinit();
        self.program.deinit();
        self.* = undefined;
    }
};

const HostWorker = struct {
    component: Component,
    trace: *const Trace,
    accumulator: Accumulator,
    err: ?anyerror = null,

    fn run(self: *HostWorker) void {
        self.component.evaluateConstraintQuotientsOnDomain(
            self.trace,
            &self.accumulator,
        ) catch |err| {
            self.err = err;
        };
    }
};

const SemanticJob = struct {
    capability: BaseCapability,
    component: Component,
    power_start: usize,
    row_count: usize,
    eval_log_size: u32,
    main_columns: []const Poly,
    selector: [*]const M31,
};

const LookupJob = struct {
    capability: LookupCapability,
    component: Component,
    power_start: usize,
    row_count: usize,
    eval_log_size: u32,
    main_columns: []const Poly,
    interaction_columns: []const Poly,
    selector: [*]const M31,
    parameters: []QM31,
};

pub fn evaluate(
    allocator: std.mem.Allocator,
    components: []const Component,
    random_coeff: QM31,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
) !?SecureColumn {
    if (components.len == 0) return null;

    var total_constraints: usize = 0;
    var max_log_size: u32 = 0;
    var semantic_count: usize = 0;
    var lookup_count: usize = 0;
    for (components) |component| {
        total_constraints = try std.math.add(
            usize,
            total_constraints,
            component.nConstraints(),
        );
        max_log_size = @max(max_log_size, component.maxConstraintLogDegreeBound());
        if (baseCapability(component) != null) semantic_count += 1;
        if (lookupCapability(component) != null) lookup_count += 1;
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
    for (components) |component| {
        if (baseCapability(component)) |capability| {
            if (!hasTreeResidency(
                residency_handles,
                &.{ capability.selector_tree_index, capability.main_tree_index },
            )) return declineResidentPolynomial();
        }
        if (lookupCapability(component)) |capability| {
            if (!hasTreeResidency(
                residency_handles,
                &.{
                    capability.selector_tree_index,
                    capability.main_tree_index,
                    capability.interaction_tree_index,
                },
            )) return declineResidentPolynomial();
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
    var lookup_programs = std.ArrayList(LookupProgramEntry).empty;
    defer {
        for (lookup_programs.items) |*entry| entry.deinit();
        lookup_programs.deinit(allocator);
    }
    const semantic_jobs = try allocator.alloc(SemanticJob, semantic_count);
    defer allocator.free(semantic_jobs);
    const lookup_jobs = try allocator.alloc(LookupJob, lookup_count);
    defer allocator.free(lookup_jobs);
    var initialized_lookup_jobs: usize = 0;
    defer for (lookup_jobs[0..initialized_lookup_jobs]) |job| allocator.free(job.parameters);
    const host_workers = try allocator.alloc(
        HostWorker,
        components.len - semantic_count - lookup_count,
    );
    defer allocator.free(host_workers);
    var initialized_workers: usize = 0;
    defer for (host_workers[0..initialized_workers]) |*worker| worker.accumulator.deinit();

    var power_cursor = total_constraints;
    var semantic_index: usize = 0;
    var lookup_index: usize = 0;
    var host_index: usize = 0;
    for (components) |component| {
        const constraint_count = component.nConstraints();
        if (constraint_count > power_cursor) return error.InvalidBasePolynomialProgram;
        const power_start = power_cursor - constraint_count;
        power_cursor = power_start;

        if (baseCapability(component)) |capability| {
            const job = try resolveBaseJob(component, capability, trace, residency_handles);
            semantic_jobs[semantic_index] = .{
                .capability = capability,
                .component = component,
                .power_start = power_start,
                .row_count = job.row_count,
                .eval_log_size = job.eval_log_size,
                .main_columns = job.main_columns,
                .selector = job.selector,
            };
            semantic_index += 1;

            if (findBaseProgram(base_programs.items, capability.program_id) == null) {
                var program = try capability.export_program(component.ctx, allocator);
                errdefer program.deinit();
                try validateBaseProgram(program, capability, component);
                try base_programs.append(allocator, .{
                    .program_id = capability.program_id,
                    .program = program,
                });
            }
            continue;
        }

        if (lookupCapability(component)) |capability| {
            const job = try resolveLookupJob(component, capability, trace, residency_handles);
            if (findLookupProgram(lookup_programs.items, capability.program_id) == null) {
                var program = try capability.export_program(component.ctx, allocator);
                errdefer program.deinit();
                try validateLookupProgram(program, capability, component);
                try lookup_programs.append(allocator, .{
                    .program_id = capability.program_id,
                    .program = program,
                });
            }
            const program = findLookupProgram(
                lookup_programs.items,
                capability.program_id,
            ).?.program;
            const parameters = try capability.export_parameters(component.ctx, allocator);
            errdefer allocator.free(parameters);
            if (parameters.len != program.parameterCount())
                return error.InvalidLookupPolynomialProgram;
            lookup_jobs[lookup_index] = .{
                .capability = capability,
                .component = component,
                .power_start = power_start,
                .row_count = job.row_count,
                .eval_log_size = job.eval_log_size,
                .main_columns = job.main_columns,
                .interaction_columns = job.interaction_columns,
                .selector = job.selector,
                .parameters = parameters,
            };
            initialized_lookup_jobs += 1;
            lookup_index += 1;
            continue;
        }

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
            };
            initialized_workers += 1;
            host_index += 1;
        }
    }
    std.debug.assert(power_cursor == 0);
    std.debug.assert(semantic_index == semantic_jobs.len);
    std.debug.assert(lookup_index == lookup_jobs.len);
    std.debug.assert(host_index == host_workers.len);

    // Host-only components are independent once their coefficient slices are
    // assigned. Start them before resolving the resident AOT pipelines so any
    // cold-process Metal setup is hidden behind useful composition work.
    var wait_group = std.Thread.WaitGroup{};
    const pool = prover.work_pool.getGlobalPool();
    var host_pending = pool != null;
    defer if (host_pending) wait_group.wait();
    if (pool) |active| {
        for (host_workers) |*worker| active.spawnWg(&wait_group, HostWorker.run, .{worker});
    } else {
        for (host_workers) |*worker| HostWorker.run(worker);
    }

    var lease = shared_runtime.acquireExisting() catch return declineResidentPolynomial();
    defer lease.deinit();
    for (base_programs.items) |*entry| {
        const name = try base_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        entry.plan = lease.runtime.prepareBasePolynomialAot(name) catch
            return declineResidentPolynomial();
    }
    for (lookup_programs.items) |*entry| {
        const name = try lookup_codegen.kernelName(allocator, entry.program);
        defer allocator.free(name);
        entry.plan = lease.runtime.prepareLookupPolynomialAot(name) catch
            return declineResidentPolynomial();
    }

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
            .power_word_count = @intCast(job.component.nConstraints() * 4),
            .output_index = bucket_index[job.eval_log_size].?,
            .denominator_inverses = .{
                denominator_inverses[0].toU32(),
                denominator_inverses[1].toU32(),
            },
        };
        for (job.main_columns, main_column_ptrs[main_column_cursor..]) |column, *pointer|
            pointer.* = @ptrCast(column.values.ptr);
        main_column_cursor += job.main_columns.len;
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
        const entry = findLookupProgram(
            lookup_programs.items,
            job.capability.program_id,
        ).?;
        const denominator_inverses = try denominators(
            job.capability.trace_log_size,
            job.eval_log_size,
        );
        dispatch.* = .{
            .plan = entry.plan.?.handle,
            .selector = @ptrCast(job.selector),
            .main_column_offset = @intCast(lookup_main_cursor),
            .main_column_count = @intCast(job.main_columns.len),
            .interaction_column_offset = @intCast(interaction_cursor),
            .interaction_column_count = @intCast(job.interaction_columns.len),
            .row_count = @intCast(job.row_count),
            .power_word_offset = @intCast(job.power_start * 4),
            .power_word_count = @intCast(job.component.nConstraints() * 4),
            .parameter_word_offset = @intCast(parameter_cursor * 4),
            .parameter_word_count = @intCast(job.parameters.len * 4),
            .output_index = bucket_index[job.eval_log_size].?,
            .denominator_inverses = .{
                denominator_inverses[0].toU32(),
                denominator_inverses[1].toU32(),
            },
        };
        for (job.main_columns, lookup_main_column_ptrs[lookup_main_cursor..]) |column, *pointer|
            pointer.* = @ptrCast(column.values.ptr);
        for (job.interaction_columns, interaction_column_ptrs[interaction_cursor..]) |column, *pointer|
            pointer.* = @ptrCast(column.values.ptr);
        for (job.parameters, 0..) |parameter, index| {
            const coordinates = parameter.toM31Array();
            inline for (0..4) |coordinate|
                parameter_words[(parameter_cursor + index) * 4 + coordinate] =
                    coordinates[coordinate].toU32();
        }
        lookup_main_cursor += job.main_columns.len;
        interaction_cursor += job.interaction_columns.len;
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
            .{ lookup_jobs.len, lookup_programs.items.len, gpu_ms },
        );
    }

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
    return try combined.finalize();
}

fn declineResidentPolynomial() ?SecureColumn {
    telemetry.record(.cpu_riscv_polynomial_composition_decline);
    return null;
}

fn baseCapability(component: Component) ?BaseCapability {
    const capability = component.backend_composition_capability orelse return null;
    return switch (capability) {
        .base_polynomial_v1 => |value| value,
        else => null,
    };
}

fn lookupCapability(component: Component) ?LookupCapability {
    const capability = component.backend_composition_capability orelse return null;
    return switch (capability) {
        .lookup_polynomial_v1 => |value| value,
        else => null,
    };
}

fn hasTreeResidency(handles: []const ?*anyopaque, indices: []const usize) bool {
    for (indices) |index| if (index >= handles.len or handles[index] == null) return false;
    return true;
}

fn findBaseProgram(entries: []BaseProgramEntry, program_id: u64) ?*BaseProgramEntry {
    for (entries) |*entry| if (entry.program_id == program_id) return entry;
    return null;
}

fn findLookupProgram(entries: []LookupProgramEntry, program_id: u64) ?*LookupProgramEntry {
    for (entries) |*entry| if (entry.program_id == program_id) return entry;
    return null;
}

fn validateBaseProgram(
    program: prover.air.component_prover.OwnedBasePolynomialProgram,
    capability: BaseCapability,
    component: Component,
) !void {
    try program.validate();
    if (program.column_count != capability.main_column_count + 1 or
        program.roots.len != component.nConstraints())
        return error.InvalidBasePolynomialProgram;
}

fn validateLookupProgram(
    program: prover.air.component_prover.OwnedLookupPolynomialProgram,
    capability: LookupCapability,
    component: Component,
) !void {
    try program.validate();
    if (program.column_count != capability.main_column_count or
        program.batchCount() != component.nConstraints() or
        capability.interaction_column_count != program.batchCount() * 4)
        return error.InvalidLookupPolynomialProgram;
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

const ResolvedLookupJob = struct {
    row_count: usize,
    eval_log_size: u32,
    main_columns: []const Poly,
    interaction_columns: []const Poly,
    selector: [*]const M31,
};

fn resolveLookupJob(
    component: Component,
    capability: LookupCapability,
    trace: *const Trace,
    residency_handles: []const ?*anyopaque,
) !ResolvedLookupJob {
    if (capability.selector_tree_index >= trace.polys.items.len or
        capability.main_tree_index >= trace.polys.items.len or
        capability.interaction_tree_index >= trace.polys.items.len or
        capability.selector_tree_index >= residency_handles.len or
        capability.main_tree_index >= residency_handles.len or
        capability.interaction_tree_index >= residency_handles.len or
        residency_handles[capability.selector_tree_index] == null or
        residency_handles[capability.main_tree_index] == null or
        residency_handles[capability.interaction_tree_index] == null)
        return error.MissingLookupPolynomialResidency;
    const eval_log_size = component.maxConstraintLogDegreeBound();
    if (eval_log_size != capability.trace_log_size + 1 or
        eval_log_size >= @bitSizeOf(usize))
        return error.InvalidLookupPolynomialProgram;
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    const selector_tree = trace.polys.items[capability.selector_tree_index];
    const main_tree = trace.polys.items[capability.main_tree_index];
    const interaction_tree = trace.polys.items[capability.interaction_tree_index];
    if (capability.selector_column >= selector_tree.len or
        capability.first_main_column > main_tree.len or
        capability.main_column_count > main_tree.len - capability.first_main_column or
        capability.first_interaction_column > interaction_tree.len or
        capability.interaction_column_count >
            interaction_tree.len - capability.first_interaction_column)
        return error.InvalidLookupPolynomialProgram;
    const selector = selector_tree[capability.selector_column];
    if (selector.log_size != eval_log_size or selector.values.len != row_count)
        return error.InvalidLookupPolynomialProgram;
    const main = main_tree[capability.first_main_column..][0..capability.main_column_count];
    const interaction = interaction_tree[capability.first_interaction_column..][0..capability.interaction_column_count];
    for (main) |column| {
        if (column.log_size != eval_log_size or column.values.len != row_count)
            return error.InvalidLookupPolynomialProgram;
    }
    for (interaction) |column| {
        if (column.log_size != eval_log_size or column.values.len != row_count)
            return error.InvalidLookupPolynomialProgram;
    }
    return .{
        .row_count = row_count,
        .eval_log_size = eval_log_size,
        .main_columns = main,
        .interaction_columns = interaction,
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
