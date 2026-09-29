//! Bounded coefficient-basis reduction. Source coefficients remain immutable;
//! each destination group is joined before borrowed owners may be retired.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const shared = @import("../shared_runtime.zig");
const admission = @import("external_allocation_admission_v1.zig");
const telemetry = @import("../telemetry.zig");

const Source = extern struct {
    words: [*]const u32,
    length: usize,
    coefficients: [4]u32,
};
const Admit = *const fn (*anyopaque, usize) callconv(.c) bool;
const Release = *const fn (*anyopaque, usize) callconv(.c) bool;
extern fn stwo_zig_metal_fold_coefficients_v1(
    *anyopaque,
    [*]const Source,
    usize,
    [*]u32,
    u32,
    *anyopaque,
    Admit,
    Release,
    *u64,
) bool;

fn release(context: *anyopaque, bytes: usize) callconv(.c) bool {
    const scope: *admission.Scope = @ptrCast(@alignCast(context));
    scope.releaseJoined(bytes) catch |err| {
        scope.failure = err;
        return false;
    };
    return true;
}

pub fn fold(a: std.mem.Allocator, jobs: anytype) !void {
    if (jobs.len == 0) return;
    // Validate all shapes before modifying any output, including contiguous
    // ownership and absence of aliases with coefficients in the same group.
    for (jobs) |job| {
        const size = job.coordinates[0].len;
        if (size == 0 or size > std.math.maxInt(u32) or job.source.len == 0 or job.source.len > size)
            return error.InvalidCoefficientFold;
        const bytes = try std.math.mul(usize, size, @sizeOf(M31));
        const output_start = @intFromPtr(job.coordinates[0].ptr);
        const output_end = try std.math.add(usize, output_start, try std.math.mul(usize, bytes, 4));
        inline for (0..4) |coord| {
            if (job.coordinates[coord].len != size or @intFromPtr(job.coordinates[coord].ptr) != output_start + coord * bytes)
                return error.InvalidCoefficientFold;
            if (job.coefficients[coord].v >= 0x7fffffff) return error.InvalidCoefficientFold;
        }
        const source_start = @intFromPtr(job.source.ptr);
        const source_end = try std.math.add(usize, source_start, try std.math.mul(usize, job.source.len, @sizeOf(M31)));
        if (source_start < output_end and output_start < source_end) return error.InvalidCoefficientFold;
    }
    const order = try a.alloc(usize, jobs.len);
    defer a.free(order);
    for (order, 0..) |*index, i| index.* = i;
    const Context = struct {
        jobs: @TypeOf(jobs),
        fn less(self: @This(), lhs: usize, rhs: usize) bool {
            const l = @intFromPtr(self.jobs[lhs].coordinates[0].ptr);
            const r = @intFromPtr(self.jobs[rhs].coordinates[0].ptr);
            return if (l == r) lhs < rhs else l < r;
        }
    };
    std.mem.sort(usize, order, Context{ .jobs = jobs }, Context.less);
    const sources = try a.alloc(Source, jobs.len);
    defer a.free(sources);
    var scope = try admission.Scope.init(a, .explicit_unbudgeted);
    defer scope.deinit();
    var lease = try shared.acquire();
    defer lease.deinit();
    var start: usize = 0;
    while (start < order.len) {
        const first = jobs[order[start]];
        var end = start;
        while (end < order.len and jobs[order[end]].coordinates[0].ptr == first.coordinates[0].ptr) : (end += 1) {
            const job = jobs[order[end]];
            inline for (0..4) |coord| {
                if (job.coordinates[coord].ptr != first.coordinates[coord].ptr or job.coordinates[coord].len != first.coordinates[coord].len)
                    return error.InvalidCoefficientFold;
            }
            sources[end - start] = .{
                .words = @ptrCast(job.source.ptr),
                .length = job.source.len,
                .coefficients = .{ job.coefficients[0].v, job.coefficients[1].v, job.coefficients[2].v, job.coefficients[3].v },
            };
        }
        var dispatches: u64 = 0;
        const ok = stwo_zig_metal_fold_coefficients_v1(
            lease.runtime.handle,
            sources.ptr,
            end - start,
            @ptrCast(first.coordinates[0].ptr),
            @intCast(first.coordinates[0].len),
            &scope,
            admission.Scope.callback,
            release,
            &dispatches,
        );
        // The FFI joins all commands and destroys private owners on either
        // outcome. Failed constructor reservations are also cleared here.
        try scope.releaseAfterJoin();
        if (scope.failure) |err| return err;
        if (!ok) return error.NativeCoefficientFoldFailed;
        telemetry.recordN(.metal_coefficient_fold_dispatch, dispatches);
        start = end;
    }
}
