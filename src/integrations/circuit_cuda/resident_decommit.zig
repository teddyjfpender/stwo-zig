//! Resident circuit query draw and mixed-height trace/FRI openings.
//! The opening kernels and record layout are shared with Cairo CUDA.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const shared = @import("stwo_native_cuda_integration").common;
const decommit = @import("stwo_cairo_cuda_integration").executor.pcs_decommit_topology;
const geometry_module = @import("geometry.zig");
const commit_module = @import("resident_commit.zig");

pub const Plan = struct {
    topology: decommit.Topology,

    pub fn init(
        allocator: std.mem.Allocator,
        geometry: *const geometry_module.Geometry,
        config: core.pcs.config_v2.PcsConfigV2,
    ) !Plan {
        const queries = config.fri_config.n_queries;
        if (queries == 0 or geometry.fri_layers.len == 0) return error.InvalidCircuitDecommitGeometry;
        var trees: [4]decommit.GenericTree = undefined;
        for (geometry.trees, &trees) |tree, *target| target.* = .{
            .column_logs = tree.column_logs,
            .lifted_log = tree.lifted_log,
        };
        const fri = try allocator.alloc(decommit.GenericFriLayer, geometry.fri_layers.len);
        defer allocator.free(fri);
        for (geometry.fri_layers, fri) |layer, *target| target.* = .{
            .evaluation_log = layer.evaluation_log,
            .cumulative_fold = layer.cumulative_fold,
            .fold_step = layer.fold_step,
            .log_rows_per_leaf = 2,
        };
        const capacity = try capacityWords(geometry, queries);
        return .{ .topology = try decommit.deriveGeneric(
            allocator,
            trees,
            fri,
            config.fri_config.log_blowup_factor,
            geometry.fri_input_log,
            queries,
            capacity,
            geometry.identity,
        ) };
    }

    pub fn deinit(self: *Plan) void {
        self.topology.deinit();
        self.* = undefined;
    }

    pub fn upload(self: *const Plan, session: anytype, buffers: shared.resident_views.Decommit) !void {
        try self.topology.uploadColumnLogs(session, buffers);
    }

    pub fn execute(
        self: *const Plan,
        session: anytype,
        sink: anytype,
        commits: [4]commit_module.Buffers,
        fri: shared.resident_views.Fri,
        buffers: shared.resident_views.Decommit,
        assembly: common.Words,
        proof: shared.resident_views.Proof,
    ) !void {
        if (assembly.len != self.topology.assembly_capacity_words or
            proof.decommitment.len != assembly.len)
            return error.InvalidCircuitDecommitBuffers;
        var trees: [4]decommit.OpeningTree = undefined;
        for (commits, self.topology.trace_openings, &trees) |tree, opening, *target| {
            const last = self.topology.trace_groups[opening.first_group + opening.group_count - 1];
            if (tree.evaluations.len != last.evaluation_offset_words + last.evaluation_words or
                tree.merkle_layers.len != @as(usize, opening.tree_log_size) + 1)
                return error.InvalidCircuitDecommitBuffers;
            target.* = .{
                .ordinal = opening.tree_index,
                .role = opening.role,
                .column_count = opening.column_count,
                .evaluations = tree.evaluations,
                .merkle_hashes = tree.merkle_hashes,
                .merkle_layers = tree.merkle_layers,
            };
        }
        try session.zeroResidentSlice(u32, .decommit, assembly);
        try sink.drawQueries(buffers.raw_queries, self.topology.query_log_size);
        try decommit.normalizeWith(cuda.runtime.stages.decommit.Native, session, self.topology, buffers, assembly);
        try decommit.openAllViewsWith(cuda.runtime.stages.decommit.Native, session, self.topology, &trees, fri, buffers, assembly);
        try shared.proof_assembly.captureDecommitment(session, .{ .proof = proof }, assembly);
    }
};

/// Conservative upper bound for the device record arena. It covers all
/// queries, trace values, expanded FRI values, and worst-case Merkle paths.
/// Actual used words are recorded by the assembly kernel; no host count or
/// host-selected opening is involved.
fn capacityWords(geometry: *const geometry_module.Geometry, queries: usize) !usize {
    var words = try add(1024, try mul(queries, 2));
    for (geometry.trees) |tree| {
        words = try add(words, try mul(queries, try add(tree.column_logs.len, 1)));
        // The device Merkle walk temporarily reserves one hash (8 words)
        // and two auxiliary nodes (10 words each) per query and level.
        // Earlier 8-word accounting covered only the hash staging area.
        words = try add(words, try mul(try mul(queries, tree.lifted_log), 28));
    }
    for (geometry.fri_layers) |layer| {
        const expanded = try mul(queries, try pow2(layer.fold_step));
        words = try add(words, try mul(expanded, 9));
        // Four rows share each FRI Merkle leaf. Its 28 staging words per
        // leaf and level fit under seven words per expanded row; eight
        // leaves margin for each fixed-capacity record.
        words = try add(words, try mul(try mul(expanded, layer.evaluation_log), 8));
    }
    return try add(words, 1024);
}

fn pow2(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.CircuitDecommitSizeOverflow;
    return @as(usize, 1) << @intCast(log);
}
fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.CircuitDecommitSizeOverflow;
}
fn mul(a: usize, b: usize) !usize {
    return std.math.mul(usize, a, b) catch error.CircuitDecommitSizeOverflow;
}

test "resident circuit decommit geometry covers all trace and four-fold FRI openings" {
    const allocator = std.testing.allocator;
    const circuit = @import("stwo_circuit_frontend");
    const cpu = @import("stwo_circuit_cpu_integration");
    const air = @import("air_aot.zig");
    const encoded = try std.fs.cwd().readFileAlloc(allocator, cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air.build(allocator, encoded);
    defer catalog.deinit();
    const layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(cpu.air.recorded_sizes);
    var bound = try cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&layout), &layout);
    defer bound.deinit();
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    const config = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, layout.traceLogSize());
    var geometry = try geometry_module.Geometry.init(allocator, &layout, &bound, &catalog, config);
    defer geometry.deinit();
    var plan = try Plan.init(allocator, &geometry, config);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 4), plan.topology.trace_openings.len);
    try std.testing.expectEqual(geometry.fri_layers.len, plan.topology.fri_openings.len);
    try std.testing.expectEqual(@as(usize, 70), plan.topology.query_count);
    try std.testing.expect(plan.topology.assembly_capacity_words < 1_100_000);
    for (plan.topology.fri_openings) |opening| try std.testing.expect(opening.fold_step <= 4);
}

test "resident circuit decommit controller typechecks native GPU openings" {
    const Dispatch = struct {
        fn run(
            plan: *const Plan,
            session: *cuda.runtime.NativeSession,
            sink: *@import("resident_transcript.zig").NativeSink,
            commits: [4]commit_module.Buffers,
            fri: shared.resident_views.Fri,
            buffers: shared.resident_views.Decommit,
            assembly: common.Words,
            proof: shared.resident_views.Proof,
        ) !void {
            try plan.execute(session, sink, commits, fri, buffers, assembly, proof);
        }
    };
    const entry: *const fn (*const Plan, *cuda.runtime.NativeSession, *@import("resident_transcript.zig").NativeSink, [4]commit_module.Buffers, shared.resident_views.Fri, shared.resident_views.Decommit, common.Words, shared.resident_views.Proof) anyerror!void = &Dispatch.run;
    try std.testing.expect(@intFromPtr(entry) != 0);
}
