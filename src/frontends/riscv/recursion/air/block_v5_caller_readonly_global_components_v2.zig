//! Original memory-first component order and full committed union masks.
const std = @import("std");
const core = @import("stwo_core");
const Admission = @import("../../prover/block_v5_caller_readonly_global_recursive_admission_v2.zig");
const Capture = @import("../../prover/block_v5_caller_readonly_global_recursive_capture_v2.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    components: Admission.Fused.Components,
    handles: []core.air.components.Component,
    pub fn init(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Owner {
        try capture.validate(admitted, expected);
        var components = try Admission.Fused.Components.init(a, &admitted.schedule, &capture.original.claims, &capture.original.relations, &capture.original.memory_challenges, &capture.original.word, admitted.logs[3], admitted.logs[2], admitted.sealed.register_custody_mode, &capture.original.classification);
        errdefer components.deinit();
        return .{ .allocator = a, .components = components, .handles = try components.verifier() };
    }
    pub fn all(self: *const Owner, fixed_count: usize) core.air.components.Components {
        return .{ .components = self.handles, .n_preprocessed_columns = fixed_count };
    }
    pub fn deinit(self: *Owner) void {
        self.allocator.free(self.handles);
        self.components.deinit();
        self.* = undefined;
    }
};
