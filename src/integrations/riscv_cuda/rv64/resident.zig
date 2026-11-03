//! Typed enqueue-only commands over the existing CUDA context's generation-
//! checked device slices. Host metadata is bounded; numerical arrays stay resident.
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
    pub fn bind(self: Plane, context: anytype) !abi.Plane {
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
/// An initialized single-oracle continuation. All device owners remain borrowed
/// through joined completion; output planes must be disjoint from input planes.
pub const TailJob = struct {
    input: Fraction,
    output: Fraction,
    eq: Plane,
    point: Slice,
    lambda: Slice,
    state: Slice,
    /// Starts at the first remaining record, not at round zero.
    records: Slice,
    mask: Slice,
    variables: u32,
    first: u32,
};
pub const BatchOracle = struct { raw: ?Plane = null, variables: u32 };
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
        fused_eq: bool = false,
        fused_fold_sum: bool = false,
        /// Zero disables; otherwise a power of two in4..256. Profile on device.
        tail_count: u32 = 0,
        launches: u64 = 0,
        const Self = @This();

        fn handle(self: *Self) !*anyopaque {
            if (self.poisoned) return error.JobPoisoned;
            if (comptime @hasDecl(Context, "prepareKernelEnqueue")) try self.context.prepareKernelEnqueue();
            const lane = try self.context.lane(self.lane_index);
            try self.context.validateLane(lane);
            return @ptrFromInt(lane.owner);
        }
        fn result(self: *Self, status: c_int, launches: u64) !void {
            if (status != 0) {
                self.poisoned = true;
                return error.CudaEnqueueFailed;
            }
            if (comptime @hasDecl(Context, "recordKernels")) self.context.recordKernels(launches) catch |err| {
                self.poisoned = true;
                return err;
            };
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
            const eq_function: *const @TypeOf(Api.stwo_rv64_gkr_eq_on) = if (self.fused_eq) &Api.stwo_rv64_gkr_eq_fused_on else &Api.stwo_rv64_gkr_eq_on;
            try self.result(eq_function(
                owner,
                self.lane_index,
                try self.context.deviceSlicePointer(u32, point, 8 * @as(usize, variables)),
                variables,
                try output.bind(self.context),
            ), if (self.fused_eq) 1 + (@as(u64, variables) - 1 + 3) / 4 else variables);
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

        pub fn foldSum(self: *Self, input: Fraction, challenge: Slice, folded: Fraction, eq_values: Plane, lambda: Slice, scratch_a: Plane, scratch_b: Plane, output: Plane) !void {
            try input.validate();
            try folded.validate();
            if (input.count < 8 or folded.count != input.count / 2) return error.InvalidGeometry;
            try folded.n.shape(folded.count, 8);
            var groups = (input.count / 8 + 127) / 128;
            try eq_values.shape(input.count / 8, 8);
            try scratch_a.shape(2 * groups, 8);
            try scratch_b.shape(2 * groups, 8);
            try output.shape(2, 8);
            var waves: u64 = 1;
            while (groups > 1) : (groups = (groups + 127) / 128) waves += 1;
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_fold_sum_on(
                owner,
                self.lane_index,
                try input.n.bind(self.context),
                try input.d.bind(self.context),
                input.count,
                try self.context.deviceSlicePointer(u32, challenge, 8),
                try folded.n.bind(self.context),
                try folded.d.bind(self.context),
                try eq_values.bind(self.context),
                try self.context.deviceSlicePointer(u32, lambda, 8),
                try scratch_a.bind(self.context),
                try scratch_b.bind(self.context),
                try output.bind(self.context),
            ), waves);
        }

        pub fn tail(self: *Self, job: TailJob) !void {
            try self.tailBatch(&.{job});
        }
        /// Metadata is copied synchronously by the native launch. Every device
        /// owner remains borrowed until joined; this is independent-job batching.
        pub fn tailBatch(self: *Self, jobs: []const TailJob) !void {
            if (jobs.len == 0 or jobs.len > 8) return error.InvalidGeometry;
            const owner = try self.handle();
            var packet: [8]abi.TailJob = undefined;
            for (jobs, 0..) |j, i| {
                try j.input.validate();
                try j.output.validate();
                if (j.input.count < 4 or j.input.count > 256 or j.output.count != 2 or
                    j.variables == 0 or j.variables > 27 or j.first >= j.variables or
                    j.input.count != @as(u32, 2) << @as(u5, @intCast(j.variables - j.first))) return error.InvalidGeometry;
                try j.output.n.shape(2, 8);
                try j.eq.shape(j.input.count / 4, 8);
                packet[i] = .{
                    .n = try j.input.n.bind(self.context),
                    .d = try j.input.d.bind(self.context),
                    .out_n = try j.output.n.bind(self.context),
                    .out_d = try j.output.d.bind(self.context),
                    .eq = try j.eq.bind(self.context),
                    .point = try self.context.deviceSlicePointer(u32, j.point, 8 * @as(usize, j.variables)),
                    .lambda = try self.context.deviceSlicePointer(u32, j.lambda, 8),
                    .state = try self.context.deviceSlicePointer(u32, j.state, abi.round_state_words),
                    .records = try self.context.deviceSlicePointer(u32, j.records, abi.round_record_words * @as(usize, j.variables - j.first)),
                    .mask = try self.context.deviceSlicePointer(u32, j.mask, 32),
                    .count = j.input.count,
                    .variables = j.variables,
                    .first = j.first,
                };
            }
            try self.result(Api.stwo_rv64_sumcheck_tail_on(owner, self.lane_index, &packet, @intCast(jobs.len)), 1);
        }

        fn batchDescriptors(self: *Self, oracles: []const BatchOracle, variables: u32) ![abi.batch_max_oracles]abi.BatchOracle {
            if (oracles.len == 0 or oracles.len > abi.batch_max_oracles or variables > 27) return error.InvalidGeometry;
            var out: [abi.batch_max_oracles]abi.BatchOracle = undefined;
            var largest: u32 = 0;
            for (oracles, 0..) |oracle, j| {
                if (oracle.variables > variables) return error.InvalidGeometry;
                largest = @max(largest, oracle.variables);
                if (oracle.variables == 0) {
                    if (oracle.raw != null) return error.InvalidPlane;
                    out[j] = .{ .raw = null, .raw_stride = 0, .variables = 0 };
                } else {
                    const raw = oracle.raw orelse return error.InvalidPlane;
                    try raw.shape(2, 8);
                    const bound = try raw.bind(self.context);
                    out[j] = .{ .raw = bound.words, .raw_stride = bound.stride, .variables = oracle.variables };
                }
            }
            if (largest != variables) return error.InvalidGeometry;
            return out;
        }
        pub fn initBatch(self: *Self, state: Slice, seed: Slice, claims: Slice, alpha: Slice, oracles: []const BatchOracle, variables: u32) !void {
            const desc = try self.batchDescriptors(oracles, variables);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_batch_init_on(owner, self.lane_index, try self.context.deviceSlicePointer(u32, state, abi.batch_state_words), try self.context.deviceSlicePointer(u32, seed, 9), try self.context.deviceSlicePointer(u32, claims, 8 * oracles.len), try self.context.deviceSlicePointer(u32, alpha, 8), &desc, @intCast(oracles.len), variables), 1);
        }
        pub fn batchRound(self: *Self, state: Slice, oracles: []const BatchOracle, variables: u32, expected: u32, point: Slice, record: Slice) !void {
            if (expected >= variables) return error.InvalidGeometry;
            const desc = try self.batchDescriptors(oracles, variables);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_batch_round_on(owner, self.lane_index, try self.context.deviceSlicePointer(u32, state, abi.batch_state_words), &desc, @intCast(oracles.len), variables, expected, try self.context.deviceSlicePointer(u32, point, 8 * variables), try self.context.deviceSlicePointer(u32, record, abi.round_record_words)), 1);
        }
        pub fn packBatchMask(self: *Self, input: Fraction, output: Slice) !void {
            try input.validate();
            if (input.count != 2) return error.InvalidGeometry;
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_batch_mask_on(owner, self.lane_index, try input.n.bind(self.context), try input.d.bind(self.context), try self.context.deviceSlicePointer(u32, output, 32)), 1);
        }
        pub fn gatherParameters(self: *Self, reservoir: Slice, output: Slice, slots: []const u32, namespaces: u32, verdict: Slice) !void {
            const total = abi.relation_count * abi.relation_slot_stride;
            if (slots.len == 0 or slots.len > total or (namespaces != 9 and namespaces != 10)) return error.InvalidGeometry;
            for (slots) |slot| if (slot >= total) return error.InvalidGeometry;
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_parameter_gather_on(owner, self.lane_index, try self.context.deviceSlicePointer(u32, reservoir, total * 8), try self.context.deviceSlicePointer(u32, output, slots.len * 8), slots.ptr, @intCast(slots.len), namespaces, try self.context.deviceSlicePointer(u32, verdict, 1)), 1);
        }
        /// Immutable address map is retained GPU setup. Numerical sources stay
        /// resident in five independently owned protocol namespaces.
        pub fn gatherJoinedParameters(self: *Self, sources: [5]Slice, addresses: Slice, output: Slice, count: u32, verdict: Slice) !void {
            if (count == 0 or count > abi.joined_parameter_count) return error.InvalidGeometry;
            const owner = try self.handle();
            var job: abi.JoinedParameters = undefined;
            for (&job.sources, sources, abi.joined_namespace_counts, 0..) |*pointer, source, n, ns| pointer.* = try self.context.deviceSlicePointer(u32, source, @as(usize, n) * (if (ns == 0) @as(usize, 1) else 8));
            job.addresses = try self.context.deviceSlicePointer(u32, addresses, 2 * @as(usize, count));
            job.output = try self.context.deviceSlicePointer(u32, output, 8 * @as(usize, count));
            job.status = try self.context.deviceSlicePointer(u32, verdict, 1);
            job.count = count;
            job.reserved = 0;
            try self.result(Api.stwo_rv64_joined_parameter_gather_on(owner, self.lane_index, &job), 1);
        }
        pub fn packRoots(self: *Self, roots: []const Fraction, output: Slice) !void {
            if (roots.len == 0 or roots.len > abi.batch_max_oracles) return error.InvalidGeometry;
            var sources: [abi.batch_max_oracles]abi.GkrRoot = undefined;
            for (roots, 0..) |root, i| {
                try root.validate();
                if (root.count != 1 or root.n.coordinates != 8) return error.InvalidGeometry;
                sources[i] = .{ .n = try root.n.bind(self.context), .d = try root.d.bind(self.context) };
            }
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_pack_roots_on(owner, self.lane_index, &sources, @intCast(roots.len), try self.context.deviceSlicePointer(u32, output, roots.len * 16)), 1);
        }
        pub fn initGkr(self: *Self, state: Slice, seed: Slice, variables: []const u32, layers: u32, chain: u64) !void {
            if (variables.len == 0 or variables.len > abi.batch_max_oracles or layers == 0 or layers > 28 or state.address % 8 != 0) return error.InvalidGeometry;
            var largest: u32 = 0;
            for (variables) |v| {
                if (v == 0 or v > layers) return error.InvalidGeometry;
                largest = @max(largest, v);
            }
            if (largest != layers) return error.InvalidGeometry;
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_init_on(owner, self.lane_index, try self.context.deviceSlicePointer(u32, state, abi.gkr_state_words), try self.context.deviceSlicePointer(u32, seed, 9), variables.ptr, @intCast(variables.len), layers, chain), 1);
        }
        pub fn buildBindingEq(self: *Self, point: Slice, row_log: u32, output: Plane, verdict: Slice) !void {
            if (row_log == 0 or row_log > 22) return error.InvalidGeometry;
            try output.shape(@as(u32, 1) << @intCast(row_log), 8);
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_binding_eq_on(owner, self.lane_index, try self.context.deviceSlicePointer(u32, point, row_log * 8), row_log, try output.bind(self.context), try self.context.deviceSlicePointer(u32, verdict, 1)), 1 + (row_log + 3) / 4);
        }
        pub fn samplePoints(self: *Self, j: @import("samples.zig").Points) !void {
            if (j.count == 0 or j.count > 1024) return error.InvalidGeometry;
            const owner = try self.handle();
            const packet = abi.SamplePoints{
                .parameter = try self.context.deviceSlicePointer(u32, j.parameter, 8),
                .recipes = try self.context.deviceSlicePointer(u32, j.recipes, @as(usize, j.count) * 4),
                .points = try self.context.deviceSlicePointer(u32, j.points, @as(usize, j.count + 1) * 16),
                .factors = try self.context.deviceSlicePointer(u32, j.factors, @as(usize, j.count) * @import("samples.zig").factor_stride * 8),
                .ready = try self.context.deviceSlicePointer(u32, j.ready, j.count + 1),
                .status = try self.context.deviceSlicePointer(u32, j.verdict, 1),
                .count = j.count,
            };
            try self.result(Api.stwo_rv64_sample_points_on(owner, self.lane_index, &packet), 2);
        }
        pub fn sampleEvaluate(self: *Self, j: @import("samples.zig").Evaluation) !void {
            if (j.source_count == 0 or j.source_count > 65536 or j.term_capacity > 65536 or j.group_count == 0 or j.group_count > 1024 or j.first > j.term_capacity or j.count > j.term_capacity - j.first or j.sources.address % 8 != 0) return error.InvalidGeometry;
            const plan = try @import("samples.zig").Plan.init(j.coefficient_log, j.count);
            const owner = try self.handle();
            var trees: [4]?[*]const u32 = @splat(null);
            var tree_words: [4]u64 = @splat(0);
            for (j.trees, 0..) |source, i| if (source) |s| {
                if (s.len == 0) return error.InvalidGeometry;
                trees[i] = try self.context.deviceSlicePointer(u32, s, s.len);
                tree_words[i] = s.len;
            };
            const packet = abi.SampleEvaluation{
                .trees = trees,
                .tree_words = tree_words,
                .sources = try self.context.deviceSlicePointer(u32, j.sources, @as(usize, j.source_count) * 4),
                .terms = try self.context.deviceSlicePointer(u32, j.terms, @as(usize, j.term_capacity) * 4),
                .recipes = try self.context.deviceSlicePointer(u32, j.recipes, @as(usize, j.group_count) * 4),
                .factors = try self.context.deviceSlicePointer(u32, j.factors, @as(usize, j.group_count) * @import("samples.zig").factor_stride * 8),
                .point_ready = try self.context.deviceSlicePointer(u32, j.point_ready, j.group_count + 1),
                .scratch_a = try self.context.deviceSlicePointer(u32, j.scratch_a, plan.scratch_words),
                .scratch_b = try self.context.deviceSlicePointer(u32, j.scratch_b, plan.scratch_words),
                .values = try self.context.deviceSlicePointer(u32, j.values, @as(usize, j.term_capacity) * 8),
                .valid = try self.context.deviceSlicePointer(u32, j.valid, j.count),
                .status = try self.context.deviceSlicePointer(u32, j.verdict, 1),
                .scratch_words = plan.scratch_words,
                .value_words = j.values.len,
                .source_count = j.source_count,
                .term_capacity = j.term_capacity,
                .group_count = j.group_count,
                .first = j.first,
                .count = j.count,
                .coefficient_log = j.coefficient_log,
            };
            try self.result(Api.stwo_rv64_sample_evaluate_on(owner, self.lane_index, &packet), plan.dispatches);
        }
        pub fn projectBinding(self: *Self, input: Fraction, eq_column: Plane, prefix_column: Plane, metadata: Slice, verdict: Slice, row_log: u32, lane_log: u32) !void {
            if (row_log == 0 or row_log > 22 or lane_log > 8 or row_log + lane_log > 28) return error.InvalidGeometry;
            const rows = @as(u32, 1) << @intCast(row_log);
            if (input.count != rows << @intCast(lane_log)) return error.InvalidGeometry;
            try input.validate();
            try eq_column.shape(rows, 8);
            try prefix_column.shape(rows, 8);
            const owner = try self.handle();
            const job = abi.BindingProjection{
                .n = try input.n.bind(self.context),
                .d = try input.d.bind(self.context),
                .eq = try eq_column.bind(self.context),
                .prefix = try prefix_column.bind(self.context),
                .metadata = try self.context.deviceSlicePointer(u32, metadata, 260 * 8),
                .status = try self.context.deviceSlicePointer(u32, verdict, 1),
                .row_log = row_log,
                .lane_log = lane_log,
            };
            try self.result(Api.stwo_rv64_binding_project_on(owner, self.lane_index, &job), 1);
        }
        pub fn scanPrefix(self: *Self, data: Plane, scratch: Slice, claim: Slice, verdict: Slice, row_log: u32, center: bool) !void {
            const plan = try @import("prefix_plan.zig").Plan.init(row_log);
            try data.shape(plan.rows, 8);
            const owner = try self.handle();
            const job = abi.PrefixScan{
                .data = try data.bind(self.context),
                .scratch = try self.context.deviceSlicePointer(u32, scratch, plan.scratch_words),
                .scratch_words = plan.scratch_words,
                .claim = try self.context.deviceSlicePointer(u32, claim, 8),
                .status = try self.context.deviceSlicePointer(u32, verdict, 1),
                .row_log = row_log,
                .center = @intFromBool(center),
            };
            try self.result(Api.stwo_rv64_prefix_scan_on(owner, self.lane_index, &job), plan.dispatches(center));
        }
        pub fn deriveBindingMetadata(self: *Self, state: Slice, reservoir: Slice, row_point: Slice, carry: Slice, seed: Slice, verdict: Slice, instance: u32, row_log: u32, lane_log: u32, count: u32, layers: u32, chain: u64) !void {
            if (count == 0 or count > abi.batch_max_oracles or instance >= count or layers == 0 or layers > 28 or row_log == 0 or row_log > 22 or lane_log > 8 or row_log + lane_log > layers or state.address % 8 != 0) return error.InvalidGeometry;
            const owner = try self.handle();
            const job = abi.BindingMetadata{
                .state = try self.context.deviceSlicePointer(u32, state, abi.gkr_state_words),
                .reservoir = try self.context.deviceSlicePointer(u32, reservoir, 260 * 8),
                .row_point = try self.context.deviceSlicePointer(u32, row_point, row_log * 8),
                .carry = try self.context.deviceSlicePointer(u32, carry, row_log * 16),
                .seed = try self.context.deviceSlicePointer(u32, seed, 9),
                .status = try self.context.deviceSlicePointer(u32, verdict, 1),
                .chain = chain,
                .instance = instance,
                .row_log = row_log,
                .lane_log = lane_log,
                .count = count,
                .layers = layers,
            };
            try self.result(Api.stwo_rv64_gkr_binding_metadata_on(owner, self.lane_index, &job), 1);
        }
        pub fn beginGkr(self: *Self, state: Slice, depth: u32, count: u32, active: u32, roots: Slice, claims: Slice) !void {
            if (count == 0 or count > abi.batch_max_oracles or active == 0 or active > count or depth >= 28 or state.address % 8 != 0) return error.InvalidGeometry;
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_begin_on(owner, self.lane_index, try self.context.deviceSlicePointer(u32, state, abi.gkr_state_words), depth, count, active, try self.context.deviceSlicePointer(u32, roots, 16 * count), try self.context.deviceSlicePointer(u32, claims, 8 * active)), 1);
        }
        pub fn closeGkr(self: *Self, state: Slice, batch: Slice, records: Slice, masks: Slice, depth: u32, count: u32, active: u32) !void {
            if (count == 0 or count > abi.batch_max_oracles or active == 0 or active > count or depth >= 28 or state.address % 8 != 0) return error.InvalidGeometry;
            const owner = try self.handle();
            try self.result(Api.stwo_rv64_gkr_close_on(owner, self.lane_index, try self.context.deviceSlicePointer(u32, state, abi.gkr_state_words), try self.context.deviceSlicePointer(u32, batch, abi.batch_state_words), if (depth == 0) null else try self.context.deviceSlicePointer(u32, records, depth * abi.round_record_words), try self.context.deviceSlicePointer(u32, masks, 32 * active), depth, count, active), 1);
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
