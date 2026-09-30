//! Circuit-specific resident PCS commitment. The CUDA transform and lifted
//! Blake2s builder are shared with Cairo; circuit column heights and tree
//! order come only from `geometry.zig`. Mixed-height leaves are built directly
//! without allocating a dense lifted column or progressive state per row.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const field = cuda.abi.field;
const stages = cuda.runtime.stages;
const telemetry = cuda.runtime.telemetry;
const commit_tree = @import("stwo_native_cuda_integration").common.commit_tree;
const geometry = @import("geometry.zig");

pub const max_cohorts = stages.commitment.max_mixed_segments;

const NativeOps = struct {
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.PlainNative;
};

pub const InputForm = enum { evaluations, coefficients };

pub const Cohort = struct {
    first_column: usize,
    count: usize,
    trace_log: u32,
    evaluation_log: u32,
    coefficient_offset: usize,
    evaluation_offset: usize,
};

pub const Requirements = struct {
    coefficient_words: usize,
    evaluation_words: usize,
    column_log_words: usize,
    merkle_hashes: usize,
    merkle_layers: usize,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    role: geometry.TreeRole,
    input_form: InputForm,
    stage: telemetry.Stage,
    tree_size: u32,
    cohorts: []Cohort,
    column_logs: []const u32,
    layers: []field.MerkleLayerDescriptor,
    requirements: Requirements,

    pub fn init(allocator: std.mem.Allocator, tree: geometry.Tree, blowup: u32) !Plan {
        if (tree.column_logs.len == 0 or blowup == 0 or tree.lifted_log >= 31)
            return error.InvalidCircuitCommitGeometry;
        const tree_size: u32 = @as(u32, 1) << @intCast(tree.lifted_log);
        var cohorts = std.ArrayList(Cohort).empty;
        errdefer cohorts.deinit(allocator);
        var coefficient_offset: usize = 0;
        var evaluation_offset: usize = 0;
        var first: usize = 0;
        while (first < tree.column_logs.len) {
            const trace_log = tree.column_logs[first];
            const evaluation_log = std.math.add(u32, trace_log, blowup) catch return error.InvalidCircuitCommitGeometry;
            if (evaluation_log > tree.lifted_log) return error.InvalidCircuitCommitGeometry;
            var end = first + 1;
            while (end < tree.column_logs.len and tree.column_logs[end] == trace_log) : (end += 1) {}
            const count = end - first;
            try cohorts.append(allocator, .{
                .first_column = first,
                .count = count,
                .trace_log = trace_log,
                .evaluation_log = evaluation_log,
                .coefficient_offset = coefficient_offset,
                .evaluation_offset = evaluation_offset,
            });
            coefficient_offset = try add(coefficient_offset, try mul(count, try powerOfTwo(trace_log)));
            evaluation_offset = try add(evaluation_offset, try mul(count, try powerOfTwo(evaluation_log)));
            first = end;
        }
        if (cohorts.items.len > max_cohorts) return error.TooManyCircuitCommitCohorts;
        const layers = try allocator.alloc(field.MerkleLayerDescriptor, tree.lifted_log + 1);
        errdefer allocator.free(layers);
        var count: usize = tree_size;
        var offset: usize = 0;
        for (layers) |*layer| {
            layer.* = .{ .offset_hashes = offset, .hash_count = @intCast(count) };
            offset = try add(offset, count);
            count = @max(count / 2, 1);
        }
        return .{
            .allocator = allocator,
            .role = tree.role,
            .input_form = switch (tree.role) {
                .preprocessed, .composition => .coefficients,
                .main, .interaction => .evaluations,
            },
            .stage = if (tree.role == .composition) .constraint_evaluation else .trace_commit,
            .tree_size = tree_size,
            .cohorts = try cohorts.toOwnedSlice(allocator),
            .column_logs = tree.column_logs,
            .layers = layers,
            .requirements = .{
                .coefficient_words = coefficient_offset,
                .evaluation_words = evaluation_offset,
                .column_log_words = tree.column_logs.len,
                .merkle_hashes = offset,
                .merkle_layers = layers.len,
            },
        };
    }

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.cohorts);
        self.allocator.free(self.layers);
        self.* = undefined;
    }
};

pub const Buffers = struct {
    coefficients: common.Words,
    evaluations: common.Words,
    column_logs: common.Words,
    merkle_hashes: common.Hashes,
    merkle_layers: common.MerkleLayers,
    forward_twiddles: common.Words,
    inverse_twiddles: common.Words,

    pub fn validate(self: Buffers, plan: *const Plan) !void {
        const need = plan.requirements;
        if (self.coefficients.len != need.coefficient_words or
            self.evaluations.len != need.evaluation_words or
            self.column_logs.len != need.column_log_words or
            self.merkle_hashes.len != need.merkle_hashes or
            self.merkle_layers.len != need.merkle_layers or
            self.forward_twiddles.len < plan.tree_size / 2 or
            self.inverse_twiddles.len < plan.tree_size / 2)
            return error.InvalidCircuitCommitBuffers;
        const owner = self.coefficients.owner;
        const generation = self.coefficients.generation;
        inline for (.{ self.evaluations, self.column_logs, self.merkle_hashes, self.merkle_layers, self.forward_twiddles, self.inverse_twiddles }) |view| {
            if (view.owner != owner or view.generation != generation)
                return error.InvalidCircuitCommitBuffers;
        }
    }
};

pub const Bound = struct {
    plan: *const Plan,
    buffers: Buffers,
    primed: bool = false,
    executed: bool = false,

    pub fn init(plan: *const Plan, buffers: Buffers) !Bound {
        try buffers.validate(plan);
        return .{ .plan = plan, .buffers = buffers };
    }

    /// Upload only immutable geometry. Must run during ingress.
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.CircuitCommitAlreadyPrimed;
        try session.context.uploadSlice(u32, self.buffers.column_logs, self.plan.column_logs);
        try session.context.uploadSlice(field.MerkleLayerDescriptor, self.buffers.merkle_layers, self.plan.layers);
        self.primed = true;
    }

    pub fn execute(self: *Bound, session: anytype) !void {
        return self.executeWith(NativeOps, session);
    }

    pub fn executeWith(self: *Bound, comptime Ops: type, session: anytype) !void {
        if (!self.primed or self.executed) return error.InvalidCircuitCommitState;
        const plan = self.plan;
        const buffers = self.buffers;
        for (plan.cohorts) |cohort| {
            const trace_size = try powerOfTwo(cohort.trace_log);
            const eval_size = try powerOfTwo(cohort.evaluation_log);
            const coefficient_words = try mul(cohort.count, trace_size);
            const evaluation_words = try mul(cohort.count, eval_size);
            const coefficients = common.WordMatrix{
                .storage = try buffers.coefficients.sub(cohort.coefficient_offset, coefficient_words),
                .column_stride_words = trace_size,
            };
            const evaluations = common.WordMatrix{
                .storage = try buffers.evaluations.sub(cohort.evaluation_offset, evaluation_words),
                .column_stride_words = eval_size,
            };
            if (plan.input_form == .evaluations) {
                try Ops.Transform.inverseCompact(session, plan.stage, coefficients, coefficients, cohort.trace_log, buffers.inverse_twiddles);
            }
            try Ops.Transform.extend(
                session,
                plan.stage,
                coefficients,
                try buffers.column_logs.sub(cohort.first_column, cohort.count),
                evaluations,
                cohort.evaluation_log,
                buffers.forward_twiddles,
                false,
            );
        }
        var segments: [max_cohorts]commit_tree.LiftedSegment = undefined;
        for (plan.cohorts, segments[0..plan.cohorts.len]) |cohort, *segment| {
            const stride = try powerOfTwo(cohort.evaluation_log);
            segment.* = .{
                .columns = .{
                    .storage = try buffers.evaluations.sub(cohort.evaluation_offset, try mul(cohort.count, stride)),
                    .column_stride_words = stride,
                },
                .source_size = @intCast(stride),
            };
        }
        // The lifted Merkle message absorbs shorter columns first, matching
        // the CPU PCS and the Cairo resident commitment controller.
        std.sort.block(commit_tree.LiftedSegment, segments[0..plan.cohorts.len], {}, struct {
            fn lessThan(_: void, left: commit_tree.LiftedSegment, right: commit_tree.LiftedSegment) bool {
                return left.source_size < right.source_size;
            }
        }.lessThan);
        const Builder = commit_tree.BuilderFor(Ops.Commitment);
        if (plan.cohorts.len == 1 and segments[0].source_size == plan.tree_size) {
            _ = try Builder.baseField(session, plan.stage, plan.tree_size, segments[0].columns, buffers.merkle_hashes, plan.layers);
        } else {
            _ = try Builder.baseFieldMixed(session, plan.stage, plan.tree_size, segments[0..plan.cohorts.len], null, buffers.merkle_hashes, plan.layers);
        }
        self.executed = true;
    }

    /// Root aliases the final Merkle level: no device copy or extra 32-byte
    /// allocation on the critical path.
    pub fn root(self: Bound) !common.Words {
        if (!self.executed) return error.InvalidCircuitCommitState;
        return (try self.buffers.merkle_hashes.sub(self.buffers.merkle_hashes.len - 1, 1)).cast(u32);
    }
};

fn powerOfTwo(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.InvalidCircuitCommitGeometry;
    return @as(usize, 1) << @intCast(log);
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.InvalidCircuitCommitGeometry;
}

fn mul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.InvalidCircuitCommitGeometry;
}

const FakeSession = struct {
    context: struct {
        uploads: u32 = 0,

        pub fn uploadSlice(self: *@This(), comptime F: type, destination: anytype, source: []const F) !void {
            if (destination.len != source.len) return error.InvalidFakeUpload;
            self.uploads += 1;
        }
    } = .{},
    inverse_calls: u32 = 0,
    extend_calls: u32 = 0,
    mixed_calls: u32 = 0,
    tail_calls: u32 = 0,
};

const FakeOps = struct {
    pub const Transform = struct {
        pub fn inverseCompact(session: *FakeSession, stage: telemetry.Stage, input: common.WordMatrix, output: common.WordMatrix, _: u32, _: common.Words) !void {
            if (stage != .trace_commit or input.storage.address != output.storage.address)
                return error.InvalidFakeTransform;
            session.inverse_calls += 1;
        }

        pub fn extend(session: *FakeSession, stage: telemetry.Stage, _: common.WordMatrix, logs: common.Words, output: common.WordMatrix, _: u32, _: common.Words, _: bool) !void {
            if (stage != .trace_commit or logs.len != output.storage.len / output.column_stride_words)
                return error.InvalidFakeTransform;
            session.extend_calls += 1;
        }
    };

    pub const Commitment = struct {
        pub fn mixedLeaves(session: *FakeSession, stage: telemetry.Stage, size: u32, segments: []const commit_tree.LiftedSegment, output: common.Hashes) commit_tree.Error!void {
            if (stage != .trace_commit or size != 128 or segments.len != 2 or
                segments[0].source_size != 32 or segments[1].source_size != 64 or output.len != 128)
                return error.InvalidMerkleLayout;
            session.mixed_calls += 1;
        }

        pub fn contiguousLeaves(_: *FakeSession, _: telemetry.Stage, _: u32, _: common.WordMatrix, _: common.Hashes) commit_tree.Error!void {}

        pub fn contiguousTail(session: *FakeSession, stage: telemetry.Stage, input: common.Hashes, output: common.Hashes, levels: u32) commit_tree.Error!void {
            if (stage != .trace_commit or input.len != 128 or output.len != 127 or levels != 7)
                return error.InvalidMerkleLayout;
            session.tail_calls += 1;
        }

        pub fn layer(_: *FakeSession, _: telemetry.Stage, _: common.Hashes, _: common.Hashes, _: bool) commit_tree.Error!void {}
    };
};

test "resident circuit commitment uses packed mixed-height CUDA path" {
    const allocator = std.testing.allocator;
    var logs = [_]u32{ 4, 4, 5 };
    var plan = try Plan.init(allocator, .{
        .role = .main,
        .column_logs = &logs,
        .lifted_log = 7,
    }, 1);
    defer plan.deinit();
    try std.testing.expectEqual(InputForm.evaluations, plan.input_form);
    try std.testing.expectEqual(@as(usize, 2), plan.cohorts.len);
    try std.testing.expectEqual(@as(usize, 64), plan.requirements.coefficient_words);
    try std.testing.expectEqual(@as(usize, 128), plan.requirements.evaluation_words);
    try std.testing.expectEqual(@as(usize, 255), plan.requirements.merkle_hashes);
    try std.testing.expectEqual(@as(usize, 8), plan.requirements.merkle_layers);
    try commit_tree.validateLayout(plan.tree_size, plan.requirements.merkle_hashes, plan.layers);

    const owner: usize = 7;
    const buffers = Buffers{
        .coefficients = .{ .address = 0x300000, .len = 64, .owner = owner },
        .evaluations = .{ .address = 0x310000, .len = 128, .owner = owner },
        .column_logs = .{ .address = 0x320000, .len = 3, .owner = owner },
        .merkle_hashes = .{ .address = 0x200000, .len = 255, .owner = owner },
        .merkle_layers = .{ .address = 0x330000, .len = 8, .owner = owner },
        .forward_twiddles = .{ .address = 0x400000, .len = 64, .owner = owner },
        .inverse_twiddles = .{ .address = 0x410000, .len = 64, .owner = owner },
    };
    var bound = try Bound.init(&plan, buffers);
    try std.testing.expectError(error.InvalidCircuitCommitState, bound.root());
    var session = FakeSession{};
    try bound.prime(&session);
    try bound.executeWith(FakeOps, &session);
    const root = try bound.root();
    try std.testing.expectEqual(@as(usize, 0x200000 + 254 * 32), root.address);
    try std.testing.expectEqual(@as(usize, 8), root.len);
    try std.testing.expectEqual(@as(u32, 2), session.context.uploads);
    try std.testing.expectEqual(@as(u32, 2), session.inverse_calls);
    try std.testing.expectEqual(@as(u32, 2), session.extend_calls);
    try std.testing.expectEqual(@as(u32, 1), session.mixed_calls);
    try std.testing.expectEqual(@as(u32, 1), session.tail_calls);
}

test "resident circuit commitment native dispatch compiles against CUDA session" {
    const Dispatch = struct {
        fn execute(bound: *Bound, session: *cuda.runtime.NativeSession) !void {
            try bound.execute(session);
        }
    };
    const entry: *const fn (*Bound, *cuda.runtime.NativeSession) anyerror!void = &Dispatch.execute;
    try std.testing.expect(@intFromPtr(entry) != 0);
}

test "resident circuit commitment plans all four recorded AIR trees" {
    const allocator = std.testing.allocator;
    const circuit = @import("stwo_circuit_frontend");
    const circuit_cpu = @import("stwo_circuit_cpu_integration");
    const air_aot = @import("air_aot.zig");
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air_aot.build(allocator, encoded);
    defer catalog.deinit();
    const layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(circuit_cpu.air.recorded_sizes);
    var bound = try circuit_cpu.air.bind(
        allocator,
        &template,
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        &layout,
    );
    defer bound.deinit();
    const config = coreConfig: {
        const core = @import("stwo_core");
        const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
        break :coreConfig core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, layout.traceLogSize());
    };
    var shape = try geometry.Geometry.init(allocator, &layout, &bound, &catalog, config);
    defer shape.deinit();
    for (shape.trees, 0..) |tree, index| {
        var plan = try Plan.init(allocator, tree, config.fri_config.log_blowup_factor);
        defer plan.deinit();
        try std.testing.expectEqual(@as(u32, 1) << @intCast(tree.lifted_log), plan.tree_size);
        try std.testing.expectEqual(plan.requirements.coefficient_words * 2, plan.requirements.evaluation_words);
        try std.testing.expectEqual(@as(usize, plan.tree_size) * 2 - 1, plan.requirements.merkle_hashes);
        try commit_tree.validateLayout(plan.tree_size, plan.requirements.merkle_hashes, plan.layers);
        try std.testing.expect(plan.cohorts.len <= max_cohorts);
        try std.testing.expectEqual(index == 3, plan.stage == .constraint_evaluation);
    }
}
