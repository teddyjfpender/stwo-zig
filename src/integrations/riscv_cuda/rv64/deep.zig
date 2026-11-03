//! Compact-coefficient OM31 DEEP commands. Immutable descriptors must be
//! independently derived from the admitted PCS masks; these commands do not
//! admit declarations, construct a proof or replace a receiver.
const runtime = @import("stwo_cuda_backend").runtime;
const abi = @import("abi.zig");
const R = @import("resident.zig");
const Slice = runtime.column.DeviceSlice(u32);
pub const Prepare = struct {
    trees: [4]?Slice,
    sources: Slice,
    terms: Slice,
    groups: Slice,
    points: Slice,
    values: Slice,
    alpha: Slice,
    weights: Slice,
    linear: Slice,
    coefficients: Slice,
    valid: Slice,
    verdict: Slice,
    source_count: u32,
    term_count: u32,
    group_count: u32,
};
pub const Combine = struct {
    groups: Slice,
    points: Slice,
    linear: Slice,
    evaluations: Slice,
    domain_xy: Slice,
    valid: Slice,
    output: R.Plane,
    verdict: Slice,
    group_count: u32,
    output_log: u32,
};
pub const NativeCommands = Commands(runtime.NativeContext, abi);
pub fn Commands(comptime Context: type, comptime Api: type) type {
    return struct {
        const Self = @This();
        context: *Context,
        lane_index: u32,
        poisoned: bool = false,
        launches: u64 = 0,
        fn owner(self: *Self) !*anyopaque {
            if (self.poisoned) return error.JobPoisoned;
            if (comptime @hasDecl(Context, "prepareKernelEnqueue")) try self.context.prepareKernelEnqueue();
            const lane = try self.context.lane(self.lane_index);
            try self.context.validateLane(lane);
            return @ptrFromInt(lane.owner);
        }
        fn pointer(self: *Self, s: Slice, need: usize) ![*]u32 {
            return self.context.deviceSlicePointer(u32, s, need);
        }
        fn finish(self: *Self, status: c_int, count: u32) !void {
            if (status != 0) {
                self.poisoned = true;
                return error.CudaEnqueueFailed;
            }
            if (comptime @hasDecl(Context, "recordKernels")) self.context.recordKernels(count) catch |err| {
                self.poisoned = true;
                return err;
            };
            self.launches +|= count;
        }
        pub fn prepare(self: *Self, j: Prepare) !void {
            if (j.source_count == 0 or j.source_count > 65536 or j.term_count == 0 or j.term_count > 65536 or j.group_count == 0 or j.group_count > 1024 or j.coefficients.len == 0) return error.InvalidGeometry;
            const handle = try self.owner();
            var trees: [4]?[*]const u32 = @splat(null);
            var tree_words: [4]u64 = @splat(0);
            for (j.trees, 0..) |source, i| if (source) |s| {
                if (s.len == 0) return error.InvalidGeometry;
                trees[i] = try self.pointer(s, s.len);
                tree_words[i] = s.len;
            };
            const packet = abi.DeepPrepare{
                .trees = trees,
                .tree_words = tree_words,
                .sources = try self.pointer(j.sources, @as(usize, j.source_count) * 4),
                .terms = try self.pointer(j.terms, @as(usize, j.term_count) * 4),
                .groups = try self.pointer(j.groups, @as(usize, j.group_count) * 8),
                .points = try self.pointer(j.points, @as(usize, j.group_count) * 16),
                .values = try self.pointer(j.values, @as(usize, j.term_count) * 8),
                .alpha = try self.pointer(j.alpha, 8),
                .weights = try self.pointer(j.weights, @as(usize, j.term_count) * 8),
                .linear = try self.pointer(j.linear, @as(usize, j.group_count) * 16),
                .coefficients = try self.pointer(j.coefficients, j.coefficients.len),
                .valid = try self.pointer(j.valid, 2),
                .status = try self.pointer(j.verdict, 1),
                .coefficient_words = j.coefficients.len,
                .source_count = j.source_count,
                .term_count = j.term_count,
                .group_count = j.group_count,
            };
            try self.finish(Api.stwo_rv64_deep_prepare_on(handle, self.lane_index, &packet), 3);
        }
        pub fn combine(self: *Self, j: Combine) !void {
            if (j.group_count == 0 or j.group_count > 1024 or j.output_log == 0 or j.output_log > 28 or j.evaluations.len == 0) return error.InvalidGeometry;
            const rows = @as(usize, 1) << @intCast(j.output_log);
            if (j.output.coordinates != 8 or j.output.stride < rows) return error.InvalidPlane;
            const handle = try self.owner();
            const packet = abi.DeepCombine{
                .groups = try self.pointer(j.groups, @as(usize, j.group_count) * 8),
                .points = try self.pointer(j.points, @as(usize, j.group_count) * 16),
                .linear = try self.pointer(j.linear, @as(usize, j.group_count) * 16),
                .evaluations = try self.pointer(j.evaluations, j.evaluations.len),
                .domain_xy = try self.pointer(j.domain_xy, rows * 2),
                .valid = try self.pointer(j.valid, 2),
                .output = try j.output.bind(self.context),
                .status = try self.pointer(j.verdict, 1),
                .evaluation_words = j.evaluations.len,
                .group_count = j.group_count,
                .output_log = j.output_log,
            };
            try self.finish(Api.stwo_rv64_deep_combine_on(handle, self.lane_index, &packet), 2);
        }
    };
}
