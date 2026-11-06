//! Device operation table for the job runtime. Every entry is an existing
//! exported symbol of the frozen base image (`stwo_exec_context_*`, channel,
//! transcript and PoW kernels) or of the addon `libstwo-rv64-jobs.so`
//! (streams, events, host functions, pinned memory, explicit-stream copies).
//!
//! The table is split by who may call it. `Exec` entries only enqueue work and
//! are reachable from `Job.enqueue`. `Wait` entries block the host; only the
//! worker loop holds them (lint.zig enforces the split at source level).
const std = @import("std");

pub const c_int_t = c_int;
pub const ContextOptions = extern struct { version: u32 = 1, device_ordinal: u32, lane_count: u32 = 1, dependency_capacity: u32 = 0 };
pub const HostCall = *const fn (?*anyopaque) callconv(.c) void;
pub const CopyKind = enum(u32) { h2d = 1, d2h = 2, d2d = 3 };

pub const Exec = struct {
    // base image, exec context (lane 0 = exec stream)
    alloc_u32: *const fn (*anyopaque, usize, *?[*]u32) callconv(.c) c_int,
    alloc_u32_long: *const fn (*anyopaque, usize, *?[*]u32) callconv(.c) c_int,
    free_u32: *const fn (*anyopaque, [*]u32) callconv(.c) c_int,
    // native OM31 channel (NAT/rv64/channel.h)
    channel_init_on: *const fn (*anyopaque, u32, [*]u32, [*]const u32, u64) callconv(.c) c_int,
    channel_mix_on: *const fn (*anyopaque, u32, [*]u32, u32, u64, u64, ?[*]const u32, u32, u32, [*]u32) callconv(.c) c_int,
    channel_draw_on: *const fn (*anyopaque, u32, [*]u32, u32, u64, u64, u32, [*]u32, [*]u32) callconv(.c) c_int,
    channel_queries_on: *const fn (*anyopaque, u32, [*]u32, u32, u64, u64, u32, u32, [*]u32, [*]u32) callconv(.c) c_int,
    // stream-level transcript / PoW (NAT/transcript, NAT/pow)
    transcript_draw_u32s_on: *const fn ([*]u32, u32, u64, u64, [*]u32, [*]u32, [*]u32, *anyopaque) callconv(.c) c_int,
    pow_persistent_on: *const fn ([*]const u32, u32, c_ulonglong, [*]u32, [*]c_ulonglong, [*]u32, [*]u32, *anyopaque) callconv(.c) c_int,
    // addon: explicit-stream async copy, events, host functions
    copy_async: *const fn (*anyopaque, *const anyopaque, usize, u32, *anyopaque) callconv(.c) c_int,
    event_record: *const fn (*anyopaque, *anyopaque) callconv(.c) c_int,
    stream_wait: *const fn (*anyopaque, *anyopaque) callconv(.c) c_int,
    host_fn: *const fn (*anyopaque, HostCall, ?*anyopaque) callconv(.c) c_int,
};

pub const Wait = struct {
    // base image context lifecycle (worker thread only)
    context_create: *const fn (*const ContextOptions, *?*anyopaque) callconv(.c) c_int,
    context_destroy: *const fn (*anyopaque) callconv(.c) c_int,
    lane_stream: *const fn (*anyopaque, u32, *?*anyopaque) callconv(.c) c_int,
    // addon lifecycle and the single host wait per job
    stream_create: *const fn (u32, *?*anyopaque) callconv(.c) c_int,
    stream_destroy: *const fn (*anyopaque) callconv(.c) c_int,
    event_create: *const fn (*?*anyopaque) callconv(.c) c_int,
    event_destroy: *const fn (*anyopaque) callconv(.c) c_int,
    // lint:host-wait-begin (worker loop only: one event wait per job)
    event_sync: *const fn (*anyopaque) callconv(.c) c_int,
    // lint:host-wait-end
    host_alloc: *const fn (usize, *?*anyopaque) callconv(.c) c_int,
    host_free: *const fn (*anyopaque) callconv(.c) c_int,
};

pub const Ops = struct {
    exec: Exec,
    wait: Wait,
};

pub const Libraries = struct {
    base: std.DynLib,
    addon: std.DynLib,
    ops: Ops,
    pub fn open(base_path: []const u8, addon_path: []const u8) !Libraries {
        var base = try std.DynLib.open(base_path);
        errdefer base.close();
        var addon = try std.DynLib.open(addon_path);
        errdefer addon.close();
        const Version = *const fn () callconv(.c) u32;
        const version = addon.lookup(Version, "stwo_rv64_jobs_abi_version") orelse return error.MissingJobsAddonSymbol;
        if (version() != abi_version) return error.JobsAddonAbiMismatch;
        var out: Libraries = .{ .base = base, .addon = addon, .ops = undefined };
        out.ops.exec = .{
            .alloc_u32 = try sym(&out.base, @FieldType(Exec, "alloc_u32"), "stwo_exec_context_alloc_u32"),
            .alloc_u32_long = try sym(&out.base, @FieldType(Exec, "alloc_u32_long"), "stwo_exec_context_alloc_u32_long"),
            .free_u32 = try sym(&out.base, @FieldType(Exec, "free_u32"), "stwo_exec_context_free_u32"),
            .channel_init_on = try sym(&out.base, @FieldType(Exec, "channel_init_on"), "stwo_rv64_channel_init_on"),
            .channel_mix_on = try sym(&out.base, @FieldType(Exec, "channel_mix_on"), "stwo_rv64_channel_mix_on"),
            .channel_draw_on = try sym(&out.base, @FieldType(Exec, "channel_draw_on"), "stwo_rv64_channel_draw_on"),
            .channel_queries_on = try sym(&out.base, @FieldType(Exec, "channel_queries_on"), "stwo_rv64_channel_queries_on"),
            .transcript_draw_u32s_on = try sym(&out.base, @FieldType(Exec, "transcript_draw_u32s_on"), "stwo_blake2s_transcript_draw_u32s_on"),
            .pow_persistent_on = try sym(&out.base, @FieldType(Exec, "pow_persistent_on"), "stwo_blake2s_pow_persistent_on"),
            .copy_async = try sym(&out.addon, @FieldType(Exec, "copy_async"), "stwo_rv64_jobs_copy_async"),
            .event_record = try sym(&out.addon, @FieldType(Exec, "event_record"), "stwo_rv64_jobs_event_record"),
            .stream_wait = try sym(&out.addon, @FieldType(Exec, "stream_wait"), "stwo_rv64_jobs_stream_wait"),
            .host_fn = try sym(&out.addon, @FieldType(Exec, "host_fn"), "stwo_rv64_jobs_host_fn"),
        };
        out.ops.wait = .{
            .context_create = try sym(&out.base, @FieldType(Wait, "context_create"), "stwo_exec_context_create_options"),
            .context_destroy = try sym(&out.base, @FieldType(Wait, "context_destroy"), "stwo_exec_context_destroy"),
            .lane_stream = try sym(&out.base, @FieldType(Wait, "lane_stream"), "stwo_exec_context_lane_stream"),
            .stream_create = try sym(&out.addon, @FieldType(Wait, "stream_create"), "stwo_rv64_jobs_stream_create"),
            .stream_destroy = try sym(&out.addon, @FieldType(Wait, "stream_destroy"), "stwo_rv64_jobs_stream_destroy"),
            .event_create = try sym(&out.addon, @FieldType(Wait, "event_create"), "stwo_rv64_jobs_event_create"),
            .event_destroy = try sym(&out.addon, @FieldType(Wait, "event_destroy"), "stwo_rv64_jobs_event_destroy"),
            // lint:host-wait-begin
            .event_sync = try sym(&out.addon, @FieldType(Wait, "event_sync"), "stwo_rv64_jobs_event_wait_host"),
            // lint:host-wait-end
            .host_alloc = try sym(&out.addon, @FieldType(Wait, "host_alloc"), "stwo_rv64_jobs_host_alloc"),
            .host_free = try sym(&out.addon, @FieldType(Wait, "host_free"), "stwo_rv64_jobs_host_free"),
        };
        return out;
    }
    pub fn close(self: *Libraries) void {
        self.addon.close();
        self.base.close();
    }
};

/// Must equal STWO_RV64_JOBS_ABI_VERSION in NAT/rv64/jobs/runtime.cu.
pub const abi_version: u32 = 1;

fn sym(lib: *std.DynLib, comptime T: type, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse {
        std.log.err("missing M8 job runtime symbol: {s}", .{name});
        return error.MissingJobsRuntimeSymbol;
    };
}

pub fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}
