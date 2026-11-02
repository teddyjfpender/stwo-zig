//! Compile-only real-context/real-C-ABI seam check. No GPU execution or proof
//! admission; this object is not installed or exported by the product.
const R = @import("rv64/resident.zig");
const S = @import("rv64/sumcheck.zig");
const Context = @import("stwo_cuda_backend").runtime.NativeContext;
export fn rv64_test_enqueue_native(context: *Context, lane: u32, input: *const S.Input, workspace: *const S.Workspace, split: bool) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane, .split_secure_sum = split, .fused_eq = split, .fused_fold_sum = split, .tail_count = if (split) 256 else 0 };
    _ = S.enqueue(&commands, input.*, workspace.*) catch return 1;
    return 0;
}

export fn rv64_test_tail_batch(context: *Context, lane: u32, jobs: [*]const R.TailJob, count: usize) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane };
    commands.tailBatch(jobs[0..count]) catch return 1;
    return 0;
}

export fn rv64_test_pcs(context: *Context, lane: u32, input: *const @import("rv64/pcs.zig").Fold) c_int {
    var commands = @import("rv64/pcs.zig").NativeCommands{ .context = context, .lane_index = lane };
    commands.fold(input.*) catch return 1;
    commands.leaves(input.input, input.count, input.steps, true, input.output.data) catch return 1;
    return 0;
}

export fn rv64_test_channel(context: *Context, lane: u32, state: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), seed: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), output: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), boundary: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32)) c_int {
    var channel = @import("rv64/channel.zig").NativeCommands{ .context = context, .lane_index = lane, .state = state.* };
    channel.initialize(seed.*, 1) catch return 1;
    channel.mix(null, false, 2, boundary.*) catch return 1;
    channel.draw(1, output.*, 3, boundary.*) catch return 1;
    return 0;
}
