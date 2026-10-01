//! Circuit PCS OODS samples over the four resident mixed-height trace trees.
//! Sample order is the circuit AIR's mask order, including every preprocessed
//! column. The same CUDA evaluator used by Cairo consumes the resulting
//! copy-free batches; no Cairo-specific compact protocol enters this path.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const field = cuda.abi.field;
const common = cuda.runtime.stages.common;
const canonic = @import("stwo_core").poly.circle.canonic;
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const quotient_geometry = @import("stwo_cairo_frontend").witness.quotient_geometry;
const shared = @import("stwo_native_cuda_integration").common;
const geometry_module = @import("geometry.zig");
const resident_commit = @import("resident_commit.zig");

pub const Cohort = struct {
    tree: u8,
    first_column: u32,
    first_sample: u32,
    sample_count: u32,
    coefficient_log: u32,
    coefficient_offset: usize,
    factor_first: usize,
    scratch_first: usize,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    offsets: []field.CirclePointBaseField,
    folds: []u32,
    indices: []u32,
    sources: []u32,
    cohorts: []Cohort,
    factor_count: usize,
    scratch_count: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        bound: *const circuit_cpu.air.Bundle,
        geometry: *const geometry_module.Geometry,
        blowup: u32,
    ) !Plan {
        if (blowup == 0 or blowup > 4) return error.InvalidCircuitOodsGeometry;
        const trees = geometry.trees;
        var masks = try quotient_geometry.deriveMasks(
            allocator,
            bound.*,
            trees[0].column_logs.len,
            trees[1].column_logs.len,
            trees[2].column_logs.len,
        );
        defer masks.deinit();
        var samples: std.ArrayList(Sample) = .empty;
        defer samples.deinit(allocator);
        var first_source: [4]usize = undefined;
        var column_offsets: [4][]usize = undefined;
        var total_sources: usize = 0;
        var initialized: usize = 0;
        defer for (column_offsets[0..initialized]) |offsets| allocator.free(offsets);
        for (trees, 0..) |tree, i| {
            first_source[i] = total_sources;
            total_sources = try add(total_sources, tree.column_logs.len);
            const offsets = try allocator.alloc(usize, tree.column_logs.len);
            column_offsets[i] = offsets;
            initialized += 1;
            var cursor: usize = 0;
            for (tree.column_logs, offsets) |log, *item| {
                item.* = cursor;
                cursor = try add(cursor, try pow2(log));
            }
        }
        for (trees[0].column_logs, 0..) |_, column|
            try samples.append(allocator, try sample(trees[0], 0, column, column_offsets[0][column], 0, blowup));
        for (masks.base_offsets, 0..) |offsets, column| {
            if (offsets.items.len == 0 or offsets.items.len > 2) return error.InvalidCircuitOodsGeometry;
            for (offsets.items) |offset|
                try samples.append(allocator, try sample(trees[1], 1, column, column_offsets[1][column], offset, blowup));
        }
        for (masks.interaction_offsets, 0..) |offsets, column| {
            if (offsets.items.len == 0 or offsets.items.len > 2) return error.InvalidCircuitOodsGeometry;
            for (offsets.items) |offset|
                try samples.append(allocator, try sample(trees[2], 2, column, column_offsets[2][column], offset, blowup));
        }
        for (trees[3].column_logs, 0..) |_, column|
            try samples.append(allocator, try sample(trees[3], 3, column, column_offsets[3][column], 0, blowup));
        if (samples.items.len == 0) return error.InvalidCircuitOodsGeometry;

        const offsets = try allocator.alloc(field.CirclePointBaseField, samples.items.len);
        errdefer allocator.free(offsets);
        const folds = try allocator.alloc(u32, samples.items.len);
        errdefer allocator.free(folds);
        const indices = try allocator.alloc(u32, samples.items.len);
        errdefer allocator.free(indices);
        const sources = try allocator.alloc(u32, samples.items.len);
        errdefer allocator.free(sources);
        var cohorts: std.ArrayList(Cohort) = .empty;
        errdefer cohorts.deinit(allocator);
        var factors: usize = 0;
        var scratch: usize = 0;
        for (samples.items, 0..) |entry, i| {
            offsets[i] = entry.offset;
            folds[i] = entry.fold;
            indices[i] = std.math.cast(u32, i) orelse return error.CircuitOodsSizeOverflow;
            sources[i] = std.math.cast(u32, first_source[entry.tree] + entry.column) orelse return error.CircuitOodsSizeOverflow;
            const rows = try pow2(entry.log);
            const blocks = std.math.divCeil(usize, rows, cuda.runtime.stages.oods.first_coefficients_per_block) catch return error.CircuitOodsSizeOverflow;
            var merged = false;
            if (cohorts.items.len != 0) {
                const previous = &cohorts.items[cohorts.items.len - 1];
                if (previous.tree == entry.tree and previous.coefficient_log == entry.log and
                    previous.first_column + previous.sample_count == entry.column and
                    previous.first_sample + previous.sample_count == i)
                {
                    previous.sample_count += 1;
                    merged = true;
                }
            }
            if (!merged) try cohorts.append(allocator, .{
                .tree = entry.tree,
                .first_column = @intCast(entry.column),
                .first_sample = @intCast(i),
                .sample_count = 1,
                .coefficient_log = entry.log,
                .coefficient_offset = entry.coefficient_offset,
                .factor_first = factors,
                .scratch_first = scratch,
            });
            factors = try add(factors, entry.log);
            scratch = try add(scratch, blocks);
        }
        return .{
            .allocator = allocator,
            .offsets = offsets,
            .folds = folds,
            .indices = indices,
            .sources = sources,
            .cohorts = try cohorts.toOwnedSlice(allocator),
            .factor_count = factors,
            .scratch_count = scratch,
        };
    }

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.offsets);
        self.allocator.free(self.folds);
        self.allocator.free(self.indices);
        self.allocator.free(self.sources);
        self.allocator.free(self.cohorts);
        self.* = undefined;
    }

    pub fn upload(self: *const Plan, session: anytype, view: shared.resident_views.Oods) !void {
        if (view.parameter.len != 1 or view.offset_points.len != self.offsets.len or
            view.fold_counts.len != self.folds.len or view.output_indices.len != self.indices.len or
            view.sampled_values.len != self.offsets.len or view.sample_points.len != self.offsets.len or
            view.evaluation_points.len != self.offsets.len or view.folding_factors.len < self.factor_count or
            view.reduce_a.len < self.scratch_count or view.reduce_b.len < self.scratch_count)
            return error.InvalidCircuitOodsBuffers;
        try session.context.uploadSlice(field.CirclePointBaseField, view.offset_points, self.offsets);
        try session.context.uploadSlice(u32, view.fold_counts, self.folds);
        try session.context.uploadSlice(u32, view.output_indices, self.indices);
    }

    pub fn bind(self: *const Plan, allocator: std.mem.Allocator, commits: [4]resident_commit.Buffers) !Bound {
        const batches = try allocator.alloc(shared.oods_batches.Batch, self.cohorts.len);
        errdefer allocator.free(batches);
        for (self.cohorts, batches) |cohort, *batch| {
            const words = try mul(cohort.sample_count, try pow2(cohort.coefficient_log));
            batch.* = .{
                .coefficients = .{
                    .storage = try commits[cohort.tree].coefficients.sub(cohort.coefficient_offset, words),
                    .column_stride_words = try pow2(cohort.coefficient_log),
                },
                .coefficient_rows = @intCast(try pow2(cohort.coefficient_log)),
                .coefficient_log_size = cohort.coefficient_log,
                .first_sample = cohort.first_sample,
                .sample_count = cohort.sample_count,
                .factor_first = cohort.factor_first,
                .scratch_first = cohort.scratch_first,
            };
        }
        return .{ .allocator = allocator, .batches = batches };
    }
};

pub const Bound = struct {
    allocator: std.mem.Allocator,
    batches: []shared.oods_batches.Batch,

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.batches);
        self.* = undefined;
    }

    pub fn execute(self: *const Bound, session: anytype, view: shared.resident_views.Oods) !void {
        for (self.batches) |batch| try shared.oods_executor.deriveBatch(cuda.runtime.stages.oods.Native, session, batch, view);
        for (self.batches) |batch| try shared.oods_executor.evaluateBatch(cuda.runtime.stages.oods.Native, session, batch, view);
    }
};

const Sample = struct {
    tree: u8,
    column: usize,
    log: u32,
    coefficient_offset: usize,
    offset: field.CirclePointBaseField,
    fold: u32,
};

fn sample(tree: geometry_module.Tree, tree_index: u8, column: usize, coefficient_offset: usize, offset: i32, blowup: u32) !Sample {
    if (column >= tree.column_logs.len or tree.lifted_log <= blowup) return error.InvalidCircuitOodsGeometry;
    const log = tree.column_logs[column];
    if (log == 0 or log > tree.lifted_log - blowup) return error.InvalidCircuitOodsGeometry;
    const step = canonic.CanonicCoset.new(tree.lifted_log - 1).step().mulSigned(offset);
    return .{
        .tree = tree_index,
        .column = column,
        .log = log,
        .coefficient_offset = coefficient_offset,
        .offset = .{ .x = step.x.v, .y = step.y.v },
        .fold = tree.lifted_log - blowup - log,
    };
}

fn pow2(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.CircuitOodsSizeOverflow;
    return @as(usize, 1) << @intCast(log);
}

fn add(a: usize, b: usize) !usize { return std.math.add(usize, a, b) catch error.CircuitOodsSizeOverflow; }
fn mul(a: usize, b: usize) !usize { return std.math.mul(usize, a, b) catch error.CircuitOodsSizeOverflow; }

test "circuit OODS samples every preprocessed column in canonical mask order" {
    const allocator = std.testing.allocator;
    const air = @import("air_aot.zig");
    const circuit = @import("stwo_circuit_frontend");
    const core = @import("stwo_core");
    const encoded = try std.fs.cwd().readFileAlloc(allocator, circuit_cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try circuit_cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air.build(allocator, encoded);
    defer catalog.deinit();
    const layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(circuit_cpu.air.recorded_sizes);
    var bound = try circuit_cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&layout), &layout);
    defer bound.deinit();
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    var geometry = try geometry_module.Geometry.init(allocator, &layout, &bound, &catalog, core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, layout.traceLogSize()));
    defer geometry.deinit();
    var plan = try Plan.init(allocator, &bound, &geometry, 1);
    defer plan.deinit();
    try std.testing.expect(plan.offsets.len > geometry.trees[0].column_logs.len + geometry.trees[1].column_logs.len + geometry.trees[2].column_logs.len);
    try std.testing.expectEqual(@as(usize, geometry.trees[0].column_logs.len), @as(usize, 45));
    for (0..plan.offsets.len) |i| try std.testing.expectEqual(@as(u32, @intCast(i)), plan.indices[i]);
    for (0..45) |i| try std.testing.expectEqual(@as(u32, @intCast(i)), plan.sources[i]);
    var covered: usize = 0;
    for (plan.cohorts) |cohort| {
        try std.testing.expectEqual(covered, cohort.first_sample);
        covered += cohort.sample_count;
    }
    try std.testing.expectEqual(plan.offsets.len, covered);
}
