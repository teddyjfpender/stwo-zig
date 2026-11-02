//! Typed enqueue-only commands over the existing CUDA context's generation-
//! checked device slices. No host array or allocator enters this interface.
const std = @import("std");
const runtime = @import("stwo_cuda_backend").runtime;
const abi = @import("abi.zig");
const Slice = runtime.column.DeviceSlice(u32);

pub const Plane = struct {
    data: Slice,
    stride: u32,
    coordinates: u32,

    fn shape(self: Plane, count: u32, coordinates: u32) !void {
        if (self.stride < count or self.coordinates != coordinates) return error.InvalidPlane;
    }
    fn bind(self: Plane, context: anytype) !abi.Plane {
        if (self.stride == 0 or self.coordinates == 0 or self.coordinates > 32) return error.InvalidPlane;
        const words = try std.math.mul(usize, self.stride, self.coordinates);
        return .{
            .words = try context.deviceSlicePointer(u32, self.data, words),
            .stride = self.stride,
            .coordinates = self.coordinates,
        };
    }
};
pub const Fraction = struct {
    n: Plane,
    d: Plane,
    count: u32,

    fn validate(self: Fraction) !void {
        if (self.count == 0 or self.count > 1 << 28 or !std.math.isPowerOfTwo(self.count))
            return error.InvalidGeometry;
        if (self.n.coordinates != 1 and self.n.coordinates != 8) return error.InvalidPlane;
        try self.n.shape(self.count, self.n.coordinates);
        try self.d.shape(self.count, 8);
    }
};
pub const NativeCommands = Commands(runtime.NativeContext, abi);

/// Borrow the context, assigned lane and all buffer owners until joined.
/// Successful enqueue is not successful computation: async errors and device
/// verdict must be checked by the owner before publication or ticket retirement.
pub fn Commands(comptime Context: type, comptime Api: type) type {
    return struct {
        context: *Context,
        lane_index: u32,
        poisoned: bool = false,
        /// Explicit tuning choice; preserve the established route by default.
        split_secure_sum: bool = false,
        launches: u64 = 0,
        const Self = @This();

        fn handle(self: *Self) !*anyopaque {
            if (self.poisoned) return error.JobPoisoned;
            const lane = try self.context.lane(self.lane_index);
            try self.context.validateLane(lane);
            return @ptrFromInt(lane.owner);
        }
        fn result(self: *Self, status: c_int, launches: u64) !void {
            if (status != 0) {
                self.poisoned = true;
                return error.CudaEnqueueFailed;
            }
            self.launches +|= launches;
        }
        pub fn project(self: *Self, tuples: Plane, weights: Plane, active: Plane, arity: u32, challenges: Slice, output: Fraction, verdict: Slice) !void {
            try output.validate();
            if (arity == 0 or arity > 32) return error.InvalidGeometry;
            try tuples.shape(output.count, arity);
            try weights.shape(output.count, 1);
            try active.shape(output.count, 1);
            try output.n.shape(output.count, 1);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_project_on(
                owner,
                self.lane_index,
                try tuples.bind(self.context),
                try weights.bind(self.context),
                try active.bind(self.context),
                output.count,
                arity,
                try self.context.deviceSlicePointer(u32, challenges, 8 * (@as(usize, arity) + 1)),
                try output.n.bind(self.context),
                try output.d.bind(self.context),
                try self.context.deviceSlicePointer(u32, verdict, 1),
            ), 1);
        }
        pub fn layer(self: *Self, input: Fraction, levels: u32, output: Fraction) !void {
            try input.validate();
            try output.validate();
            if (levels < 1 or levels > 2 or output.count != input.count >> @as(u5, @intCast(levels)))
                return error.InvalidGeometry;
            try output.n.shape(output.count, 8);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_layer_on(
                owner,
                self.lane_index,
                try input.n.bind(self.context),
                try input.d.bind(self.context),
                input.count,
                levels,
                try output.n.bind(self.context),
                try output.d.bind(self.context),
            ), 1);
        }
        pub fn fold(self: *Self, input: Fraction, challenge: Slice, output: Fraction) !void {
            try input.validate();
            try output.validate();
            if (input.count < 2 or output.count != input.count / 2) return error.InvalidGeometry;
            try output.n.shape(output.count, 8);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_fold_on(
                owner,
                self.lane_index,
                try input.n.bind(self.context),
                try input.d.bind(self.context),
                input.count,
                try self.context.deviceSlicePointer(u32, challenge, 8),
                try output.n.bind(self.context),
                try output.d.bind(self.context),
            ), 1);
        }
        pub fn eq(self: *Self, point: Slice, variables: u32, output: Plane) !void {
            if (variables == 0 or variables > 28) return error.InvalidGeometry;
            try output.shape(@as(u32, 1) << @as(u5, @intCast(variables - 1)), 8);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_eq_on(
                owner,
                self.lane_index,
                try self.context.deviceSlicePointer(u32, point, 8 * @as(usize, variables)),
                variables,
                try output.bind(self.context),
            ), variables);
        }
        pub fn sum(self: *Self, input: Fraction, eq_values: Plane, lambda: Slice, scratch_a: Plane, scratch_b: Plane, output: Plane) !void {
            try input.validate();
            if (input.count < 4) return error.InvalidGeometry;
            var groups = (input.count / 4 + 127) / 128;
            try scratch_a.shape(2 * groups, 8);
            try scratch_b.shape(2 * groups, 8);
            try output.shape(2, 8);
            try eq_values.shape(input.count / 4, 8);
            var waves: u64 = 1;
            while (groups > 1) : (groups = (groups + 127) / 128) waves += 1;
            const owner = try self.handle();
            const sum_function: *const @TypeOf(Api.stwo_rv64_gkr_sum_on) = if (self.split_secure_sum) &Api.stwo_rv64_gkr_sum_split_on else &Api.stwo_rv64_gkr_sum_on;
            try self.result(sum_function(
                owner,
                self.lane_index,
                try input.n.bind(self.context),
                try input.d.bind(self.context),
                input.count,
                try eq_values.bind(self.context),
                try self.context.deviceSlicePointer(u32, lambda, 8),
                try scratch_a.bind(self.context),
                try scratch_b.bind(self.context),
                try output.bind(self.context),
            ), waves);
        }

        pub fn initSumcheck(self: *Self, state: Slice, seed: Slice, claim: Slice, variables: u32) !void {
            if (variables == 0 or variables > 27) return error.InvalidGeometry;
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_sumcheck_init_on(
                owner,
                self.lane_index,
                try self.context.deviceSlicePointer(u32, state, abi.round_state_words),
                try self.context.deviceSlicePointer(u32, seed, 9),
                try self.context.deviceSlicePointer(u32, claim, 8),
                variables,
            ), 1);
        }
        pub fn round(self: *Self, state: Slice, variables: u32, expected: u32, sums: Plane, point: Slice, record: Slice) !void {
            if (variables == 0 or variables > 27 or expected >= variables) return error.InvalidGeometry;
            try sums.shape(2, 8);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_sumcheck_round_on(
                owner,
                self.lane_index,
                try self.context.deviceSlicePointer(u32, state, abi.round_state_words),
                variables,
                expected,
                try sums.bind(self.context),
                try self.context.deviceSlicePointer(u32, point, 8 * @as(usize, variables)),
                try self.context.deviceSlicePointer(u32, record, abi.round_record_words),
            ), 1);
        }

        pub fn packMask(self: *Self, input: Fraction, output: Slice) !void {
            if (input.count != 2) return error.InvalidGeometry;
            try input.n.shape(2, 8);
            try input.d.shape(2, 8);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_pack_mask_on(
                owner,
                self.lane_index,
                try input.n.bind(self.context),
                try input.d.bind(self.context),
                try self.context.deviceSlicePointer(u32, output, 32),
            ), 1);
        }
    };
}
