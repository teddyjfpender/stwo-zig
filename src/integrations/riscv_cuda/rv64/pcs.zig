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
pub const Open = struct {
    input: R.Plane,
    tree: Slice,
    queries: Slice,
    values: Slice,
    paths: Slice,
    verdict: Slice,
    layout: @import("fri.zig").Layer,
    query_count: u32,
};
pub const TraceSegment = struct { columns: Slice, stride: usize, count: u32, log: u32 };
pub const TraceOpen = struct { tree: Slice, queries: Slice, values: Slice, paths: Slice, verdict: Slice, tree_log: u32, lifting_log: u32, query_count: u32 };
pub fn Commands(comptime Context: type, comptime Api: type) type {
    return struct {
        const Self = @This();
        context: *Context,
        lane_index: u32,
        poisoned: bool = false,
        launches: u64 = 0,
        fn handle(self: *Self) !*anyopaque {
            if (self.poisoned) return error.JobPoisoned;
            if (comptime @hasDecl(Context, "prepareKernelEnqueue")) try self.context.prepareKernelEnqueue();
            const lane = try self.context.lane(self.lane_index);
            try self.context.validateLane(lane);
            return @ptrFromInt(lane.owner);
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
        fn bindTrace(self: *Self, segments: []const TraceSegment, log: u32, packets: *[96]abi.MixedSegment) !u32 {
            if (log < 1 or log > 28 or segments.len == 0 or segments.len > packets.len) return error.InvalidGeometry;
            var columns: u32 = 0;
            var previous: u32 = 0;
            for (segments, packets[0..segments.len]) |segment, *packet| {
                if (segment.log < 1 or segment.log > log or segment.log < previous or segment.count == 0 or segment.count > 65536 - columns) return error.InvalidGeometry;
                const rows = @as(u32, 1) << @intCast(segment.log);
                if (segment.stride < rows) return error.InvalidGeometry;
                const words = try std.math.mul(usize, segment.stride, segment.count);
                packet.* = .{ .columns = try self.context.deviceSlicePointer(u32, segment.columns, words), .stride_words = segment.stride, .capacity_words = words, .source_size = rows };
                columns += segment.count;
                previous = segment.log;
            }
            return columns;
        }
        pub fn traceTree(self: *Self, segments: []const TraceSegment, log: u32, nodes: Slice) !void {
            const owner = try self.handle();
            var packets: [96]abi.MixedSegment = undefined;
            _ = try self.bindTrace(segments, log, &packets);
            if (nodes.address % 32 != 0) return error.InvalidGeometry;
            const words = ((@as(usize, 2) << @intCast(log)) - 1) * 8;
            const output = try self.context.deviceSlicePointer(u32, nodes, words);
            try self.finish(Api.stwo_rv64_trace_tree_on(owner, self.lane_index, &packets, @intCast(segments.len), log, output, words), log + 1);
        }
        pub fn traceOpen(self: *Self, segments: []const TraceSegment, input: TraceOpen) !void {
            if (input.lifting_log < 1 or input.lifting_log > 28 or input.query_count == 0 or input.query_count > 1024 or input.tree.address % 32 != 0) return error.InvalidGeometry;
            const owner = try self.handle();
            var packets: [96]abi.MixedSegment = undefined;
            const columns = try self.bindTrace(segments, input.tree_log, &packets);
            const tree_words = ((@as(usize, 2) << @intCast(input.tree_log)) - 1) * 8;
            const value_words = @as(usize, columns) * input.query_count;
            const path_words = @as(usize, input.query_count) * input.tree_log * 8;
            const job = abi.TraceOpen{
                .tree = try self.context.deviceSlicePointer(u32, input.tree, tree_words),
                .queries = try self.context.deviceSlicePointer(u32, input.queries, input.query_count),
                .values = try self.context.deviceSlicePointer(u32, input.values, value_words),
                .paths = try self.context.deviceSlicePointer(u32, input.paths, path_words),
                .status = try self.context.deviceSlicePointer(u32, input.verdict, 1),
                .tree_words = tree_words,
                .value_words = value_words,
                .path_words = path_words,
                .tree_log = input.tree_log,
                .lifting_log = input.lifting_log,
                .query_count = input.query_count,
            };
            try self.finish(Api.stwo_rv64_trace_open_on(owner, self.lane_index, &packets, @intCast(segments.len), &job), 2);
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
            try self.finish(Api.stwo_rv64_fri_fold_on(owner, self.lane_index, &packet), 1);
        }
        pub fn leaves(self: *Self, input: R.Plane, count: u32, leaf_log: u32, prefixed: bool, hashes: Slice) !void {
            if (count == 0 or count > 1 << 28 or !std.math.isPowerOfTwo(count) or leaf_log > 4 or count < @as(u32, 1) << @intCast(leaf_log)) return error.InvalidGeometry;
            if (input.coordinates != 8 or input.stride < count) return error.InvalidPlane;
            const hash_count = count >> @intCast(leaf_log);
            if (hashes.len < @as(usize, hash_count) * 8 or hashes.address % 32 != 0) return error.InvalidDeviceAddress;
            const owner = try self.handle();
            try self.finish(Api.stwo_rv64_fri_leaves_on(owner, self.lane_index, try input.bind(self.context), count, leaf_log, @intFromBool(prefixed), try self.context.deviceSlicePointer(u32, hashes, @as(usize, hash_count) * 8), hash_count), 1);
        }
        pub fn tree(self: *Self, input: R.Plane, count: u32, leaf_log: u32, nodes: Slice) !void {
            if (count == 0 or count > 1 << 28 or !std.math.isPowerOfTwo(count) or (leaf_log != 0 and leaf_log != 2) or count < @as(u32, 1) << @intCast(leaf_log) or input.coordinates != 8 or input.stride < count) return error.InvalidGeometry;
            if (nodes.address % 32 != 0) return error.InvalidDeviceAddress;
            const leaves_count = count >> @intCast(leaf_log);
            const words = (@as(usize, leaves_count) * 2 - 1) * 8;
            const owner = try self.handle();
            try self.finish(Api.stwo_rv64_fri_tree_on(owner, self.lane_index, try input.bind(self.context), count, leaf_log, try self.context.deviceSlicePointer(u32, nodes, words), words), 1 + std.math.log2_int(u32, leaves_count));
        }
        pub fn terminal(self: *Self, input: R.Plane, count: u32, coefficient: Slice, verdict: Slice) !void {
            if (count < 2 or count > 65536 or !std.math.isPowerOfTwo(count) or input.coordinates != 8 or input.stride < count) return error.InvalidGeometry;
            const owner = try self.handle();
            try self.finish(Api.stwo_rv64_fri_terminal_on(owner, self.lane_index, try input.bind(self.context), count, try self.context.deviceSlicePointer(u32, coefficient, 8), try self.context.deviceSlicePointer(u32, verdict, 1)), 1);
        }
        pub fn open(self: *Self, j: Open) !void {
            try j.layout.validate();
            if (j.query_count == 0 or j.query_count > 1024 or j.input.coordinates != 8 or j.input.stride < j.layout.count) return error.InvalidGeometry;
            const owner = try self.handle();
            const tw = j.layout.treeWords();
            const vw = j.layout.valueWords(j.query_count);
            const pw = j.layout.pathWords(j.query_count);
            const packet = abi.FriOpen{
                .input = try j.input.bind(self.context),
                .tree = try self.context.deviceSlicePointer(u32, j.tree, tw),
                .queries = try self.context.deviceSlicePointer(u32, j.queries, j.query_count),
                .values = try self.context.deviceSlicePointer(u32, j.values, vw),
                .paths = try self.context.deviceSlicePointer(u32, j.paths, @max(pw, 1)),
                .status = try self.context.deviceSlicePointer(u32, j.verdict, 1),
                .tree_words = tw,
                .value_words = vw,
                .path_words = pw,
                .count = j.layout.count,
                .query_count = j.query_count,
                .fold_step = j.layout.fold_step,
                .leaf_log = j.layout.leaf_log,
                .shift = j.layout.shift,
            };
            try self.finish(Api.stwo_rv64_fri_open_on(owner, self.lane_index, &packet), if (pw == 0) 1 else 2);
        }
    };
}
