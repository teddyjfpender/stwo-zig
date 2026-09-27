//! Explicit CPU driver selection seam for the genuine input request forest.
//! No legacy H conversion or automatic fallback. A canonical caller must supply
//! independently admitted WM/v2 policies and a stable original template owner;
//! proof-carried key/schedule metadata is not an alternative initializer.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Run = @import("block_v5_input_request_forest_run_v1.zig");
const Receiver = @import("../recursion/block_v5_input_request_forest_receiver_v1.zig");
pub const Selection = struct {
    root_policy: Receiver.Policy,
    loader: Run.Loader,
    limits: @import("block_v5_input_request_forest_stage_v1.zig").Limits = .{},
};
pub const Result = Run.Result;
pub const complete_block_authority = false;
pub fn requireSelection(requested: bool, selection: ?Selection) !void {
    if (requested and selection == null) return error.MissingIndependentInputRequestForestPolicy;
    if (!requested and selection != null) return error.UnselectedInputRequestForestPolicy;
}
/// Invoke only after original job/source policies have been independently
/// admitted and their lifetime owner installed. Original source/provider and
/// global compensation verification remain mandatory outside this input route.
pub fn publish(a: std.mem.Allocator, dir: std.fs.Dir, selection: Selection) !Result {
    return Run.ForBackend(Cpu).run(a, dir, selection.root_policy, selection.loader, selection.limits);
}
