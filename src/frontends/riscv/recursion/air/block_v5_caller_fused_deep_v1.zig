//! Genuine four-trace DEEP with original shared Keccak current/+27 masks.
const std = @import("std");
const Admission = @import("../../prover/block_v5_caller_fused_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_caller_fused_recursive_capture_v1.zig");
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !@import("blake3_native_deep.zig").Prepared {
    var owner = try @import("block_v5_caller_fused_components_v1.zig").Owner.init(a, admitted, capture, expected);
    defer owner.deinit();
    const logs: [4][]const u32 = .{ admitted.logs[0], admitted.logs[1], admitted.logs[2], admitted.logs[3] };
    return @import("blake3_component_deep_v1.zig").prepareComponents(a, owner.all(admitted.logs[0].len), &logs, admitted.config, &capture.proof);
}
