//! Test-only (excluded from jobs/lint.zig by its _test.zig name): open the job runtime's libraries for opt-in real-GPU tests.
//! Same table as ops.Libraries.open, except `transcript_draw_u32s_on`, which
//! the frozen rv64 base images do not export (reported to runtime in
//! M8-INTERFACES.md); it is bound to a stub that fails if a test draws raw.
const std = @import("std");
const O = @import("ops.zig");

fn missingDrawU32s(_: [*]u32, _: u32, _: u64, _: u64, _: [*]u32, _: [*]u32, _: [*]u32, _: *anyopaque) callconv(.c) c_int {
    return 1;
}
fn sym(lib: *std.DynLib, comptime T: type, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse {
        std.log.err("missing symbol: {s}", .{name});
        return error.MissingJobsRuntimeSymbol;
    };
}
pub const Gpu = struct {
    libs: O.Libraries,
    pub fn open() !?Gpu {
        const base_path = std.posix.getenv("STWO_RV64_M8_GPU_BASE") orelse return null;
        const addon_path = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return null;
        var base = try std.DynLib.open(base_path);
        errdefer base.close();
        var addon = try std.DynLib.open(addon_path);
        errdefer addon.close();
        var out: O.Libraries = .{ .base = base, .addon = addon, .ops = undefined };
        const E = O.Exec;
        const X = O.Wait;
        out.ops.exec = .{
            .alloc_u32 = try sym(&out.base, @FieldType(E, "alloc_u32"), "stwo_exec_context_alloc_u32"),
            .alloc_u32_long = try sym(&out.base, @FieldType(E, "alloc_u32_long"), "stwo_exec_context_alloc_u32_long"),
            .free_u32 = try sym(&out.base, @FieldType(E, "free_u32"), "stwo_exec_context_free_u32"),
            .channel_init_on = try sym(&out.base, @FieldType(E, "channel_init_on"), "stwo_rv64_channel_init_on"),
            .channel_mix_on = try sym(&out.base, @FieldType(E, "channel_mix_on"), "stwo_rv64_channel_mix_on"),
            .channel_draw_on = try sym(&out.base, @FieldType(E, "channel_draw_on"), "stwo_rv64_channel_draw_on"),
            .channel_queries_on = try sym(&out.base, @FieldType(E, "channel_queries_on"), "stwo_rv64_channel_queries_on"),
            .transcript_draw_u32s_on = out.base.lookup(@FieldType(E, "transcript_draw_u32s_on"), "stwo_blake2s_transcript_draw_u32s_on") orelse missingDrawU32s,
            .pow_persistent_on = try sym(&out.base, @FieldType(E, "pow_persistent_on"), "stwo_blake2s_pow_persistent_on"),
            .copy_async = try sym(&out.addon, @FieldType(E, "copy_async"), "stwo_rv64_jobs_copy_async"),
            .event_record = try sym(&out.addon, @FieldType(E, "event_record"), "stwo_rv64_jobs_event_record"),
            .stream_wait = try sym(&out.addon, @FieldType(E, "stream_wait"), "stwo_rv64_jobs_stream_wait"),
            .host_fn = try sym(&out.addon, @FieldType(E, "host_fn"), "stwo_rv64_jobs_host_fn"),
        };
        out.ops.wait = .{
            .context_create = try sym(&out.base, @FieldType(X, "context_create"), "stwo_exec_context_create_options"),
            .context_destroy = try sym(&out.base, @FieldType(X, "context_destroy"), "stwo_exec_context_destroy"),
            .lane_stream = try sym(&out.base, @FieldType(X, "lane_stream"), "stwo_exec_context_lane_stream"),
            .stream_create = try sym(&out.addon, @FieldType(X, "stream_create"), "stwo_rv64_jobs_stream_create"),
            .stream_destroy = try sym(&out.addon, @FieldType(X, "stream_destroy"), "stwo_rv64_jobs_stream_destroy"),
            .event_create = try sym(&out.addon, @FieldType(X, "event_create"), "stwo_rv64_jobs_event_create"),
            .event_destroy = try sym(&out.addon, @FieldType(X, "event_destroy"), "stwo_rv64_jobs_event_destroy"),
            .event_sync = try sym(&out.addon, @FieldType(X, "event_sync"), "stwo_rv64_jobs_event_wait_host"),
            .host_alloc = try sym(&out.addon, @FieldType(X, "host_alloc"), "stwo_rv64_jobs_host_alloc"),
            .host_free = try sym(&out.addon, @FieldType(X, "host_free"), "stwo_rv64_jobs_host_free"),
        };
        return .{ .libs = out };
    }
    pub fn close(self: *Gpu) void {
        self.libs.close();
    }
};
