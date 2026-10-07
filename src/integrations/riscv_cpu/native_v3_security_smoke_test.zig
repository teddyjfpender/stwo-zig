//! Explicit heavy gate: a real small ELF under the future V3 native profile.
//! Kept outside the integration's default test module and ordinary proof gates.
const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const native_ingress = @import("recursive_segment_v2_native_ingress.zig");
const pinned_ingress = @import("recursive_segment_v3_native_security_ingress.zig");
const producer = @import("recursive_segment_v2_detached_leaf_producer.zig");
const Engine = @import("recursive_segment_v2_leaf_outer.zig").Engine;

const KeyObserver = struct {
    observed: bool = false,

    pub fn onPrepared(self: *@This(), prepared: anytype) !void {
        const root = prepared.capture.proof.commitments[0];
        // This test derives the pin locally to exercise admission. Production
        // must obtain the expected identity from an independent key setup.
        const pin = pinned_ingress.identity(root);
        const key = try pinned_ingress.PinnedKeyV1.admit(root, pin);
        try key.validateCapture(Engine, &prepared.capture);
        try pinned_ingress.admitPreparedNativeV2(prepared, key);
        var weak_profile = prepared.*;
        weak_profile.pcs_config.fri_config.n_queries = 3;
        try std.testing.expectError(
            error.V3NativePcsProfileMismatch,
            pinned_ingress.admitPreparedNativeV2(&weak_profile, key),
        );
        weak_profile = prepared.*;
        weak_profile.pcs_config.pow_bits = 0;
        try std.testing.expectError(
            error.V3NativePcsProfileMismatch,
            pinned_ingress.admitPreparedNativeV2(&weak_profile, key),
        );
        weak_profile = prepared.*;
        weak_profile.pcs_config.fri_config.fold_step = 1;
        try std.testing.expectError(
            error.V3NativePcsProfileMismatch,
            pinned_ingress.admitPreparedNativeV2(&weak_profile, key),
        );
        weak_profile = prepared.*;
        weak_profile.captured_fri.interaction_pow_bits = 0;
        try std.testing.expectError(
            error.V3NativeInteractionPowMismatch,
            pinned_ingress.admitPreparedNativeV2(&weak_profile, key),
        );
        var bad_root = root;
        bad_root[0] ^= 1;
        const wrong_key = try pinned_ingress.PinnedKeyV1.admit(
            bad_root,
            pinned_ingress.identity(bad_root),
        );
        try std.testing.expectError(
            error.V3NativeTree0KeyMismatch,
            pinned_ingress.admitPreparedNativeV2(prepared, wrong_key),
        );
        var wrong_pin = pin;
        wrong_pin[0] ^= 1;
        try std.testing.expectError(
            error.V3NativeKeyPinMismatch,
            pinned_ingress.PinnedKeyV1.admit(root, wrong_pin),
        );
        self.observed = true;
    }
};

test "real SegmentV2 native proof verifies under V3 q193 security profile" {
    try (frontend.recursion.protocol.Profile{}).validate();
    try std.testing.expectEqualDeep(
        frontend.recursion.protocol.PCS_CONFIG,
        native_ingress.NativeProfile.protocol_v1.pcsConfig(),
    );
    var timer = try std.time.Timer.start();
    var observer = KeyObserver{};
    producer.checkNativeProfileWithObserver(Engine, std.testing.allocator, 1, .protocol_v1, &observer) catch |err| {
        std.debug.print("SEGMENT_V3_SECURITY_SMOKE status=failed error={s} wall_ns={d} peak_rss_bytes={d}\n", .{
            @errorName(err), timer.read(), peakRssBytes(),
        });
        return err;
    };
    try std.testing.expect(observer.observed);
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
