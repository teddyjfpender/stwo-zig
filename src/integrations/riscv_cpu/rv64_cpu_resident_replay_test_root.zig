test {
    _ = @import("word16_execution/prepared_test.zig");
    _ = @import("word16_global_execution/services/gkr_local/device_binding.zig");
    _ = @import("stwo_prover_api").device_pcs;
}
test "CPU resident replay rejects changed committed root and device authority" {
    const std = @import("std");
    const D = @import("stwo_prover_api").device_pcs;
    const columns = [_]D.Column{.{ .log_size = 5, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 17, .generation = 1 } }};
    const original = D.Tree{ .root = @splat(9), .columns = &columns };
    var restored = columns;
    restored[0].device.?.words = @ptrFromInt(8192);
    restored[0].device.?.generation = 2;
    var replay = D.Tree{ .root = original.root, .columns = &restored };
    try D.validateMainReplay(original, replay);
    replay.root[0] ^= 1;
    try std.testing.expectError(error.DeviceMainReplayRootMismatch, D.validateMainReplay(original, replay));
    replay.root = original.root;
    restored[0].device.?.context_token += 1;
    try std.testing.expectError(error.InvalidDeviceTraceTree, D.validateMainReplay(original, replay));
}
