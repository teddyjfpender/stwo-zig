//! Compile-only real-context/real-C-ABI seam check. No GPU execution or proof
//! admission; this object is not installed or exported by the product.
const R = @import("rv64/resident.zig");
const S = @import("rv64/sumcheck.zig");
const Context = @import("stwo_cuda_backend").runtime.NativeContext;

export fn rv64_test_deep(context: *Context, lane: u32, prepare: *const @import("rv64/deep.zig").Prepare, combine: *const @import("rv64/deep.zig").Combine) c_int {
    var commands = @import("rv64/deep.zig").NativeCommands{ .context = context, .lane_index = lane };
    commands.prepare(prepare.*) catch return 1;
    commands.combine(combine.*) catch return 1;
    return 0;
}
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

export fn rv64_test_batch(context: *Context, lane: u32, input: *const @import("rv64/batch.zig").Input, work: *const @import("rv64/batch.zig").Workspace) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane };
    _ = @import("rv64/batch.zig").enqueue(&commands, input.*, work.*) catch return 1;
    return 0;
}

export fn rv64_test_gkr(context: *Context, lane: u32, inputs: [*]const R.Fraction, count: usize, seed: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), arena: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), budget: usize) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane };
    _ = @import("rv64/gkr.zig").enqueue(&commands, inputs[0..count], seed.*, arena.*, budget, 1) catch return 1;
    return 0;
}

export fn rv64_test_parameter_map(context: *Context, lane: u32, reservoir: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), output: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), slots: [*]const u32, count: usize, verdict: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32)) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane };
    commands.gatherParameters(reservoir.*, output.*, slots[0..count], 10, verdict.*) catch return 1;
    return 0;
}

export fn rv64_test_joined_parameter_map(context: *Context, lane: u32, sources: *const [5]@import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), addresses: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), output: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), count: u32, verdict: *const @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32)) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane };
    commands.gatherJoinedParameters(sources.*, addresses.*, output.*, count, verdict.*) catch return 1;
    return 0;
}

export fn rv64_test_binding_metadata(context: *Context, lane: u32, regions: *const [6]@import("stwo_cuda_backend").runtime.column.DeviceSlice(u32)) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane };
    commands.deriveBindingMetadata(regions[0], regions[1], regions[2], regions[3], regions[4], regions[5], 0, 5, 0, 1, 5, 1) catch return 1;
    return 0;
}

export fn rv64_test_binding_witness(context: *Context, lane: u32, input: *const R.Fraction, eq: *const R.Plane, prefix: *const R.Plane, regions: *const [4]@import("stwo_cuda_backend").runtime.column.DeviceSlice(u32)) c_int {
    var commands = R.NativeCommands{ .context = context, .lane_index = lane };
    commands.buildBindingEq(regions[0], 4, eq.*, regions[1]) catch return 1;
    commands.projectBinding(input.*, eq.*, prefix.*, regions[0], regions[1], 4, 0) catch return 1;
    commands.scanPrefix(prefix.*, regions[2], regions[3], regions[1], 4, false) catch return 1;
    return 0;
}
