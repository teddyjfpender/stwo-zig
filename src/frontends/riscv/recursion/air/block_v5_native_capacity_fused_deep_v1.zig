//! Full optional-access PCS/FRI DEEP relation, using original component masks.
const std = @import("std");
const Admission = @import("../../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_native_capacity_fused_recursive_capture_v1.zig");
const Components = @import("block_v5_native_capacity_fused_components_v1.zig");
const Shared = @import("blake3_component_deep_v1.zig");
pub const Prepared = Shared.Prepared;
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    var owner = try Components.Owner.init(a, admitted, capture, expected);
    defer owner.deinit();
    var logs: [4][]const u32 = undefined;
    for (admitted.logs, &logs) |source, *target| target.* = source;
    return Shared.prepareComponents(a, owner.all(admitted.logs[0].len), logs[0..admitted.tree_count], admitted.config, &capture.proof);
}
