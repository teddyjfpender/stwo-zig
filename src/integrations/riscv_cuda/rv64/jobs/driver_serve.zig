//! `combined-serve` under STWO_RV64_M8_GPU_NATIVE=1 (requires STWO_RV64_M8_JOBS=1):
//! the GPU-native service install. Opens the base image + jobs addon (with the
//! peer ops), one DeviceWorker per GPU, and installs the driver over the
//! native and recursion factories (native_device.zig, outer_device.zig).
//! Until both factories land their `warm` fails closed, so selecting the
//! flag refuses service start with the factory's error (never a silent
//! fallback to the feeder or legacy path).
const std = @import("std");
const O = @import("ops.zig");
const W = @import("worker.zig");
const R = @import("driver_request.zig");
const mod = @import("mod.zig");
const ND = @import("native_device.zig");
const OD = @import("outer_device.zig");

pub fn install(a: std.mem.Allocator, library: []const u8) !void {
    const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingJobsAddon;
    var libs = try O.Libraries.open(library, addon);
    defer libs.close();
    const peer = try O.Peer.open(&libs.addon);
    const config = try mod.Config.fromEnv();
    var workers: [8]*W.Worker = undefined;
    var made: usize = 0;
    defer for (workers[0..made]) |w| w.destroy();
    for (config.devices[0..config.device_count]) |d| {
        workers[made] = try W.Worker.create(a, &libs.ops, .{ .device = d, .arena_words = 1 << 16, .pinned_slot_words = 1 << 12, .pinned_lazy = true, .plan_from_env = false });
        made += 1;
    }
    var native = ND.Native{};
    var recursion = OD.Recursion{ .a = a };
    defer recursion.deinit();
    // 28 GiB qualified cap per 5090 (rv64_combined_ethereum_main default);
    // the driver plans against min(cap, measured free memory) per GPU.
    var caps: [8]u64 = @splat((28 << 30) / 4);
    const drv = try R.Driver.install(a, &libs.ops, &peer, workers[0..made], native.factory(), recursion.factory(), .{ .capacity_words = caps[0..made], .max_segments = 64, .slab_words = (24 << 20) / 4 });
    defer drv.deinit();
    return error.M8GpuNativeServeLoopNotLanded;
}
