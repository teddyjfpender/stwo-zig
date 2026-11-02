//! Enqueue-only OM31 PCS primitives. Numerical success is not proof admission.
//! All borrowed arrays stay live until the owner joins and checks execution.
const std = @import("std");
const runtime = @import("stwo_cuda_backend").runtime;
const abi = @import("abi.zig");
const R = @import("resident.zig");
const Slice = runtime.column.DeviceSlice(u32);
pub const Fold = struct {
    input: R.Plane,
    output: R.Plane,
    twiddles: Slice,
    alpha: Slice,
    offsets: [4]u32,
    count: u32,
    steps: u32,
    first_is_circle: bool = false,
    accumulate_circle: bool = false,
};
pub const NativeCommands = Commands(runtime.NativeContext, abi);
pub fn Commands(comptime Context: type, comptime Api: type) type {
    return struct {
        const Self = @This();
        context: *Context,
        lane_index: u32,
        poisoned: bool = false,
        launches: u64 = 0,
        fn handle(self: *Self) !*anyopaque {
            if (self.poisoned) return error.JobPoisoned;
            const lane = try self.context.lane(self.lane_index);
            try self.context.validateLane(lane);
            return @ptrFromInt(lane.owner);
        }
        fn finish(self: *Self, status: c_int) !void {
            if (status != 0) {
                self.poisoned = true;
                return error.CudaEnqueueFailed;
            }
            self.launches +|= 1;
        }
        pub fn fold(self: *Self, job: Fold) !void {
            if (job.count == 0 or job.count > 1 << 28 or !std.math.isPowerOfTwo(job.count) or job.steps < 1 or job.steps > 4 or job.count < @as(u32, 1) << @intCast(job.steps)) return error.InvalidGeometry;
            if (job.input.coordinates != 8 or job.input.stride < job.count or job.output.coordinates != 8 or job.output.stride < job.count >> @intCast(job.steps)) return error.InvalidPlane;
            if (job.accumulate_circle and (!job.first_is_circle or job.steps != 1)) return error.InvalidGeometry;
            for (0..job.steps) |level| {
                const count = job.count >> @intCast(level + 1);
                const need: u64 = if (job.first_is_circle and level == 0) 2 * ((@as(u64, count) + 3) / 4) else count;
                if (job.offsets[level] > job.twiddles.len or need > job.twiddles.len - job.offsets[level]) return error.InvalidGeometry;
            }
            const owner = try self.handle();
            const packet = abi.FriFold{
                .input = try job.input.bind(self.context),
                .output = try job.output.bind(self.context),
                .twiddles = try self.context.deviceSlicePointer(u32, job.twiddles, job.twiddles.len),
                .twiddle_words = job.twiddles.len,
                .alpha = try self.context.deviceSlicePointer(u32, job.alpha, 8),
                .offsets = job.offsets,
                .count = job.count,
                .steps = job.steps,
                .first_is_circle = @intFromBool(job.first_is_circle),
                .accumulate_circle = @intFromBool(job.accumulate_circle),
            };
            try self.finish(Api.stwo_rv64_fri_fold_on(owner, self.lane_index, &packet));
        }
        pub fn leaves(self: *Self, input: R.Plane, count: u32, leaf_log: u32, prefixed: bool, hashes: Slice) !void {
            if (count == 0 or count > 1 << 28 or !std.math.isPowerOfTwo(count) or leaf_log > 4 or count < @as(u32, 1) << @intCast(leaf_log)) return error.InvalidGeometry;
            if (input.coordinates != 8 or input.stride < count) return error.InvalidPlane;
            const hash_count = count >> @intCast(leaf_log);
            if (hashes.len < @as(usize, hash_count) * 8 or hashes.address % 32 != 0) return error.InvalidDeviceAddress;
            const owner = try self.handle();
            try self.finish(Api.stwo_rv64_fri_leaves_on(owner, self.lane_index, try input.bind(self.context), count, leaf_log, @intFromBool(prefixed), try self.context.deviceSlicePointer(u32, hashes, @as(usize, hash_count) * 8), hash_count));
        }
    };
}
