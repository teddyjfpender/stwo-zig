//! Joined physical CPU projection with private U16/U8 histograms.
//! This schedules total, prevalidated row formatters, not an instruction machine.
const std = @import("std");
const Shared = @import("../providers/native_fill.zig");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
const U16 = 65536;
const U8 = 256;
pub const HISTOGRAM_BYTES_PER_WORKER = (U16 + U8) * @sizeOf(u64);
pub const Kernel = struct {
    context: *const anyopaque,
    rows: *const fn (*const anyopaque, usize, usize, []u64, []u64) void,
};
pub fn fill(a: std.mem.Allocator, log: u32, kernel: Kernel, counts16: []u64, counts8: []u64, pool: ?*work.WorkPool) !void {
    return fillImpl(a, log, kernel, counts16, counts8, pool, null);
}
fn fillImpl(a: std.mem.Allocator, log: u32, kernel: Kernel, counts16: []u64, counts8: []u64, pool: ?*work.WorkPool, fail_after: ?usize) !void {
    if (log < 5 or log > @import("layout.zig").MAX_LOG or counts16.len != U16 or counts8.len != U8) return error.InvalidNativeProjectionShape;
    const n: usize = @as(usize, 1) << @intCast(log);
    if (comptime @import("builtin").is_test) {
        if (fail_after) |after| {
            return Shared.testing.failSubmission(Adapter, a, kernel, n, .{ counts16, counts8 }, .{ 3 * n, 3 * n }, pool.?, after) catch |err| return mapError(err);
        }
    }
    return Shared.fill(Adapter, a, kernel, n, .{ counts16, counts8 }, .{ 3 * n, 3 * n }, pool) catch |err| return mapError(err);
}
const Adapter = struct {
    pub const Context = Kernel;
    pub const BINS = [_]usize{ U16, U8 };
    pub fn rows(kernel: Kernel, start: usize, end: usize, counts: []u64) void {
        kernel.rows(kernel.context, start, end, counts[0..U16], counts[U16..]);
    }
    pub fn prepare(_: Kernel) void {}
};
fn mapError(err: anyerror) anyerror {
    return switch (err) {
        error.InvalidNativeFillShape => error.InvalidNativeProjectionShape,
        error.InvalidNativeFillPhase => error.InvalidNativeProjectionPhase,
        error.InvalidNativeFillStack => error.InvalidNativeProjectionStack,
        error.InvalidNativeFillMass => error.InvalidNativeProjectionMass,
        error.InjectedNativeFillSubmissionFailure => error.InjectedNativeProjectionSubmissionFailure,
        else => err,
    };
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(a: std.mem.Allocator, log: u32, kernel: Kernel, counts16: []u64, counts8: []u64, pool: *work.WorkPool, after: usize) !void {
        return fillImpl(a, log, kernel, counts16, counts8, pool, after);
    }
} else struct {};
