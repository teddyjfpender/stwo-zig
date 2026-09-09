//! Execute admitted framework jobs in evaluation-domain groups. Each group
//! expands its required columns once and retains that resident owner until the
//! synchronous command completes. Equations and invocation words come from the
//! job owner; this module owns scheduling and physical storage only.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const runtime_mod = @import("../runtime.zig");
const jobs_mod = @import("framework_polynomial_jobs.zig");
const scratch_mod = @import("composition_domain_scratch.zig");
const buckets_mod = @import("composition_device_buckets.zig");
const geometry = @import("polynomial_quotient_geometry.zig");
const policy = @import("../execution_policy.zig");
const Trace = prover.air.component_prover.Trace;
const Column = prover.air.component_prover.TypedPolynomialColumnV1;
const Twiddles = prover.poly.twiddles.TwiddleTree([]const core.fields.m31.M31);

pub const Result = struct { gpu_milliseconds: f64 = 0, dispatches: usize = 0, groups: usize = 0 };

pub fn evaluate(
    allocator: std.mem.Allocator,
    runtime: *runtime_mod.Runtime,
    jobs: []const jobs_mod.Job,
    trace: *const Trace,
    residents: []const ?*anyopaque,
    twiddles: ?Twiddles,
    power_words: []const u32,
    buckets: *const buckets_mod.DeviceBucketSet,
    scratch_window_held: bool,
) !Result {
    var result: Result = .{};
    for (buckets.output_index_by_log, 0..) |maybe_output, log| {
        const output_index = maybe_output orelse continue;
        var requests: std.ArrayList(scratch_mod.RequestV1) = .empty;
        defer requests.deinit(allocator);
        try appendRequests(allocator, &requests, jobs, @intCast(log), trace);
        // The existing semantic/lookup scratch may still be needed by its
        // diagnostic replay. Avoid a nested global lease or unbounded second
        // allocation in mixed graphs; the current recursive catalog has no
        // semantic/lookup expansion in flight here.
        if (requests.items.len != 0 and scratch_window_held)
            return error.MixedFrameworkCompositionScratch;
        var scratch: ?scratch_mod.OwnedV1 = null;
        defer if (scratch) |*owned| {
            owned.deinit();
            scratch_mod.releaseOwnerWindow();
        };
        if (requests.items.len != 0) {
            // Coefficient filling in the existing scratch owner still runs
            // on the host. Do not hide it behind a successful GPU transform.
            try policy.admitHost(.composition);
            const tower = twiddles orelse return error.MissingCompositionDomainTwiddles;
            const exact = try tower.subtree(@intCast(log - 1));
            scratch_mod.acquireOwnerWindow();
            scratch = scratch_mod.OwnedV1.init(allocator, runtime, trace, requests.items, exact) catch |err| {
                scratch_mod.releaseOwnerWindow();
                return err;
            };
        }
        const input = if (scratch) |*owned| &owned.trace else trace;
        var columns: std.ArrayList(?[*]const u32) = .empty;
        defer columns.deinit(allocator);
        var profiles: std.ArrayList(u32) = .empty;
        defer profiles.deinit(allocator);
        var relations: std.ArrayList(u32) = .empty;
        defer relations.deinit(allocator);
        var dispatches: std.ArrayList(runtime_mod.FrameworkPolynomialDispatch) = .empty;
        defer dispatches.deinit(allocator);
        for (jobs) |job| {
            if (job.eval_log_size != log) continue;
            const pointers = try job.columnPointers(allocator, input);
            defer allocator.free(pointers);
            const denominators = try geometry.derive(job.trace_log_size, job.eval_log_size);
            try dispatches.append(allocator, .{
                .plan = job.plan.?.handle,
                .column_offset = try wordCount(columns.items.len),
                .column_count = try wordCount(pointers.len),
                .profile_word_offset = try wordCount(profiles.items.len),
                .profile_word_count = try wordCount(job.profile_words.len),
                .relation_word_offset = try wordCount(relations.items.len),
                .relation_word_count = try wordCount(job.relation_words.len),
                .power_word_offset = try wordCount(try std.math.mul(usize, job.power_start, 4)),
                .power_word_count = try wordCount(try std.math.mul(usize, job.constraint_count, 4)),
                .output_index = 0,
                .row_count = try wordCount(job.row_count),
                .trace_log_size = job.trace_log_size,
                .denominator_count = denominators.count,
                .denominator_inverses = geometry.words(denominators),
            });
            try columns.appendSlice(allocator, pointers);
            try profiles.appendSlice(allocator, job.profile_words);
            try relations.appendSlice(allocator, job.relation_words);
        }
        result.gpu_milliseconds += try runtime.evaluateFrameworkPolynomialBatch(
            residents,
            if (scratch) |*owned| &owned.resident else null,
            columns.items,
            dispatches.items,
            profiles.items,
            relations.items,
            power_words,
            buckets.outputs[output_index..][0..1],
        );
        result.dispatches += dispatches.items.len;
        result.groups += 1;
    }
    return result;
}

fn appendRequests(allocator: std.mem.Allocator, requests: *std.ArrayList(scratch_mod.RequestV1), jobs: []const jobs_mod.Job, log: u32, trace: *const Trace) !void {
    var expand = [_]bool{false} ** 3;
    for (jobs) |job| {
        if (job.eval_log_size != log) continue;
        for (job.program.inputs) |input| switch (input) {
            .trace_column => |column| expand[column.tree_index] = (try needsExpansion(column, log, trace)) or expand[column.tree_index],
            .profile_parameter => {},
        };
        for (job.program.interaction_columns) |column|
            expand[column.tree_index] = (try needsExpansion(column, log, trace)) or expand[column.tree_index];
    }
    // Close over every reference in this group, not just the first component
    // requiring expansion: shared columns move together into one owned buffer.
    // Already-sized columns are re-evaluated from their retained coefficients.
    for (jobs) |job| {
        if (job.eval_log_size != log) continue;
        for (job.program.inputs) |input| switch (input) {
            .trace_column => |column| if (expand[column.tree_index]) {
                try requests.append(allocator, request(column, job));
            },
            .profile_parameter => {},
        };
        for (job.program.interaction_columns) |column| if (expand[column.tree_index]) {
            try requests.append(allocator, request(column, job));
        };
    }
}

fn needsExpansion(column: Column, log: u32, trace: *const Trace) !bool {
    if (column.tree_index >= trace.polys.items.len or column.column_index >= trace.polys.items[column.tree_index].len)
        return error.InvalidFrameworkPolynomialInput;
    const poly = trace.polys.items[column.tree_index][column.column_index];
    try poly.validate();
    if (poly.log_size > log) return error.InvalidFrameworkPolynomialInput;
    return poly.log_size < log;
}

fn request(column: Column, job: jobs_mod.Job) scratch_mod.RequestV1 {
    return .{ .tree_index = column.tree_index, .column_index = column.column_index, .trace_log_size = job.trace_log_size, .evaluation_log_size = job.eval_log_size };
}

fn wordCount(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.FrameworkPolynomialGeometryOverflow;
}
