//! Compile-only real-context/real-C-ABI seam check. No GPU execution or proof
//! admission; this object is not installed or exported by the product.
const R = @import("rv64/resident.zig");
const S = @import("rv64/sumcheck.zig");
const Context = @import("stwo_cuda_backend").runtime.NativeContext;
export fn rv64_test_enqueue_native(context: *Context, lane: u32, input: *const S.Input, workspace: *const S.Workspace, split: bool) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane, .split_secure_sum = split, .fused_eq = split, .fused_fold_sum = split };
    _ = S.enqueue(&commands, input.*, workspace.*) catch return 1;
    return 0;
}
