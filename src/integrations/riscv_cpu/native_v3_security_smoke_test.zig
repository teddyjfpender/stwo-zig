//! Explicit heavy gate: a real small ELF under the future V3 native profile.
//! Kept outside the integration's default test module and ordinary proof gates.
const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const native_ingress = @import("recursive_segment_v2_native_ingress.zig");
const producer = @import("recursive_segment_v2_detached_leaf_producer.zig");
const Engine = @import("recursive_segment_v2_leaf_outer.zig").Engine;

test "real SegmentV2 native proof verifies under V3 q193 security profile" {
    try (frontend.recursion.protocol.Profile{}).validate();
    try std.testing.expectEqualDeep(
        frontend.recursion.protocol.PCS_CONFIG,
        native_ingress.NativeProfile.protocol_v1.pcsConfig(),
    );
    var timer = try std.time.Timer.start();
    producer.checkNativeProfile(Engine, std.testing.allocator, 1, .protocol_v1) catch |err| {
        std.debug.print("SEGMENT_V3_SECURITY_SMOKE status=failed error={s} wall_ns={d} peak_rss_bytes={d}\n", .{
            @errorName(err), timer.read(), peakRssBytes(),
        });
        return err;
    };
    std.debug.print("SEGMENT_V3_SECURITY_SMOKE status=verified wall_ns={d} peak_rss_bytes={d} outer_proof_created=false\n", .{
        timer.read(), peakRssBytes(),
    });
}

fn peakRssBytes() u64 {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return 0;
    const rss = std.posix.getrusage(std.posix.rusage.SELF).maxrss;
    if (rss <= 0) return 0;
    const value: u64 = @intCast(rss);
    return if (builtin.os.tag == .linux) value * 1024 else value;
}
