//! One full-range scope check for an adjacent run, followed by one D2D copy.
//! Both endpoints remain generation checked; adjacency is never authority.
const std = @import("std");
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
pub const Run = @import("device_copy_run.zig").Run;
pub fn execute(ctx: *SC.Context, copy: Native.CopyDevice, target: Slice, run: Run) !void {
    const source = Slice{ .address = run.source, .len = run.words, .owner = std.math.cast(usize, run.context_token) orelse return error.SizeOverflow, .generation = run.generation };
    const from = try ctx.deviceSlicePointer(u32, source, run.words);
    const destination = try target.sub(run.target_word, run.words);
    const to = try ctx.deviceSlicePointer(u32, destination, run.words);
    if (copy(ctx.native_context, to, from, try std.math.mul(usize, run.words, 4)) != 0) return error.CudaScopedCopyFailed;
}
test "scoped adjacent copy validates entire merged source and destination before native mutation" {
    const State = struct {
        copies: usize = 0,
        bytes: usize = 0,
        fn validate(_: *anyopaque, pointer: [*]const u32, words: u64, token: u64, generation: u64, scope: *const [8]u32) callconv(.c) c_int {
            if (token != 7 or !std.mem.allEqual(u32, scope, 3)) return 1;
            const address = @intFromPtr(pointer);
            if (address == 4096 and generation == 11 and words <= 96) return 0;
            if (address == 8192 and generation == 12 and words <= 96) return 0;
            return 1;
        }
        fn copy(raw: *anyopaque, to: *anyopaque, from: *const anyopaque, bytes: usize) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (@intFromPtr(to) != 8192 or @intFromPtr(from) != 4096) return 1;
            self.copies += 1;
            self.bytes = bytes;
            return 0;
        }
    };
    var state = State{};
    const api = SC.Api{ .allocate = undefined, .release = undefined, .validate_range = State.validate, .upload = undefined, .download = undefined, .sync = undefined, .lane_stream = undefined };
    var ctx = SC.Context{ .session = &state, .native_context = &state, .token = 7, .scope = @splat(3), .api = &api };
    const target = Slice{ .address = 8192, .len = 96, .owner = 7, .generation = 12 };
    var run = try Run.init(4096, 0, 32, 7, 11);
    try std.testing.expect(try run.append(try Run.init(4224, 32, 64, 7, 11)));
    try execute(&ctx, State.copy, target, run);
    try std.testing.expectEqual(@as(usize, 1), state.copies);
    try std.testing.expectEqual(@as(usize, 384), state.bytes);
    run.words += 1;
    try std.testing.expectError(error.InvalidDeviceAddress, execute(&ctx, State.copy, target, run));
    try std.testing.expectEqual(@as(usize, 1), state.copies);
    run.words -= 1;
    ctx.scope = @splat(4);
    try std.testing.expectError(error.InvalidDeviceAddress, execute(&ctx, State.copy, target, run));
    try std.testing.expectEqual(@as(usize, 1), state.copies);
}
