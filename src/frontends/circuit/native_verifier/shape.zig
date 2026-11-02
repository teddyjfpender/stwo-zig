//! The static shape of a native proof: everything the circuit's topology
//! depends on, and the derived geometry the native verifier computes from
//! it at run time.
//!
//! Ports the geometry of `core/verifier.zig` `verifyImpl` (composition tree
//! of `4 * 2^split` columns at the mask log size, `stwo_7b211ed` trees as
//! tall as their largest column), `computeLiftingLogSize` and
//! `queryTreeLogSize` of `core/pcs/verifier.zig`, the sample order of
//! `core/pcs/quotients/samples.zig` (`buildColumnSampleBatchesFromParallelInputs`:
//! tree, column, the periodicity sample of a two-sample column first, then
//! its samples; batches by point in first-occurrence order) and the FRI
//! schedule of `core/fri/config.zig`.
//!
//! Mask points. `core/air/components.zig` leaves the offset-to-point rule to
//! each component; the RV64 components sample offset `k` at
//! `oods + k * step` with `step` the canonic coset step of the global
//! (mask) log size, `CanonicCoset.new(global_log).step()`. A column's
//! periodicity point is `points[1] + step(lifting_log).repeatedDouble(ext_log)`
//! (`samples.zig` lines 275-279), with `ext_log` the column's blowup-extended
//! log size. Both are the OODS point plus a constant M31 point, so two
//! samples share a batch exactly when their constant shifts are equal: the
//! native grouping by point value is reproduced by grouping on the shift's
//! `CirclePointIndex`, which is data-independent.

const std = @import("std");
const core = @import("stwo_core");

const CirclePointIndex = core.circle.CirclePointIndex;
const CirclePointM31 = core.circle.CirclePointM31;
const PcsConfig = core.pcs.PcsConfig;
const SECURE_EXTENSION_DEGREE = core.fields.qm31.SECURE_EXTENSION_DEGREE;

pub const ShapeError = error{
    /// Fewer than two trees, or a tree with more columns than offsets.
    InvalidTrees,
    /// The composition tree is not `4 * 2^split` columns of the global log
    /// size, each sampled once at offset 0.
    InvalidCompositionTree,
    /// `global_log` is 0, the split is outside `1..=8`, or no column is
    /// sampled.
    InvalidGeometry,
    /// The lifting domain is below the blowup, or the FRI schedule does not
    /// reach the last layer.
    InvalidFri,
    /// A mask offset moves off the global domain.
    InvalidOffset,
};

pub const Shape = struct {
    /// Per tree, per column (committed order): the trace log size, before
    /// the FRI blowup. The last tree is the composition tree.
    tree_column_log_sizes: []const []const u32,
    /// Per tree, per column: the mask offsets (rows relative to the OODS
    /// point) the column is sampled at; empty for an unsampled column.
    mask_offsets: []const []const []const i32,
    /// `max_log_degree_bound`: the composition mask log size
    /// (`compositionLogDegreeBound - composition_log_split`).
    global_log: u32,
    composition_log_split: u32,
    pcs: PcsConfig,

    pub fn nTrees(self: *const Shape) usize {
        return self.tree_column_log_sizes.len;
    }

    pub fn compositionTree(self: *const Shape) usize {
        return self.nTrees() - 1;
    }

    pub fn nColumns(self: *const Shape, tree: usize) usize {
        return self.tree_column_log_sizes[tree].len;
    }

    pub fn nQueries(self: *const Shape) usize {
        return self.pcs.fri_config.n_queries;
    }

    pub fn logBlowup(self: *const Shape) u32 {
        return self.pcs.fri_config.log_blowup_factor;
    }

    /// The committed (blowup-extended) log size of a column.
    pub fn extendedLogSize(self: *const Shape, tree: usize, column: usize) u32 {
        return self.tree_column_log_sizes[tree][column] + self.logBlowup();
    }

    /// The extended log sizes of a tree (allocated).
    pub fn extendedLogSizes(self: *const Shape, allocator: std.mem.Allocator, tree: usize) std.mem.Allocator.Error![]u32 {
        const out = try allocator.alloc(u32, self.nColumns(tree));
        for (out, 0..) |*log, column| log.* = self.extendedLogSize(tree, column);
        return out;
    }

    /// `MerkleVerifierLifted.init`: a tree is as tall as its largest column;
    /// 0 when it has none (then it is never queried).
    pub fn treeHeight(self: *const Shape, tree: usize) u32 {
        var height: u32 = 0;
        for (0..self.nColumns(tree)) |column| height = @max(height, self.extendedLogSize(tree, column));
        return height;
    }

    /// `computeLiftingLogSize`: the largest extended log size among sampled
    /// columns, the log size of the query domain.
    pub fn liftingLogSize(self: *const Shape) u32 {
        var out: u32 = 0;
        for (self.mask_offsets, 0..) |tree_offsets, tree| {
            for (tree_offsets, 0..) |offsets, column| {
                if (offsets.len != 0) out = @max(out, self.extendedLogSize(tree, column));
            }
        }
        return out;
    }

    /// `CirclePolyDegreeBound` of the FRI input: lifting log minus blowup.
    pub fn logDegreeBound(self: *const Shape) u32 {
        return self.liftingLogSize() - self.logBlowup();
    }

    /// `allFoldSteps(log_degree_bound - log_last_layer, fold_step)`: the
    /// fold step of every FRI layer, the first one being the circle layer.
    pub fn foldSteps(self: *const Shape, buffer: []u32) []const u32 {
        const config = self.pcs.fri_config;
        return core.fri.allFoldSteps(self.logDegreeBound() - config.log_last_layer_degree_bound, config.fold_step, buffer);
    }

    pub fn nFriLayers(self: *const Shape) usize {
        const config = self.pcs.fri_config;
        return core.fri.nFoldSteps(self.logDegreeBound() - config.log_last_layer_degree_bound, config.fold_step);
    }

    pub fn nLastLayerCoefficients(self: *const Shape) usize {
        return @as(usize, 1) << @intCast(self.pcs.fri_config.log_last_layer_degree_bound);
    }

    /// `compositionColumnCount(split, SECURE_EXTENSION_DEGREE)`.
    pub fn compositionColumnCount(self: *const Shape) usize {
        return SECURE_EXTENSION_DEGREE << @intCast(self.composition_log_split);
    }

    pub fn sampleCount(self: *const Shape, tree: usize, column: usize) usize {
        return self.mask_offsets[tree][column].len;
    }

    /// The index of the constant point added to the OODS point for mask
    /// offset `offset`: `offset * subgroupGen(global_log)`.
    pub fn maskShift(self: *const Shape, offset: i32) CirclePointIndex {
        const step = CirclePointIndex.subgroupGen(self.global_log);
        const magnitude: usize = @intCast(@abs(offset));
        const shift = step.mul(magnitude);
        return if (offset < 0) shift.neg() else shift;
    }

    /// `CanonicCoset.new(lifting_log).step().repeatedDouble(ext_log)`: the
    /// periodicity shift of a column.
    pub fn periodicityShift(self: *const Shape, tree: usize, column: usize) CirclePointIndex {
        const lifting_step = CirclePointIndex.subgroupGen(self.liftingLogSize());
        return lifting_step.mul(@as(usize, 1) << @intCast(self.extendedLogSize(tree, column)));
    }

    pub fn validate(self: *const Shape) ShapeError!void {
        if (self.nTrees() < 2 or self.mask_offsets.len != self.nTrees()) return error.InvalidTrees;
        for (self.tree_column_log_sizes, self.mask_offsets) |logs, offsets| {
            if (logs.len != offsets.len) return error.InvalidTrees;
        }
        if (self.global_log == 0 or self.composition_log_split == 0 or
            self.composition_log_split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT) return error.InvalidGeometry;
        const composition = self.compositionTree();
        if (self.nColumns(composition) != self.compositionColumnCount()) return error.InvalidCompositionTree;
        for (self.tree_column_log_sizes[composition], self.mask_offsets[composition]) |log, offsets| {
            if (log != self.global_log or offsets.len != 1 or offsets[0] != 0) return error.InvalidCompositionTree;
        }
        const global_size: i64 = @as(i64, 1) << @intCast(self.global_log);
        for (self.mask_offsets) |tree_offsets| {
            for (tree_offsets) |offsets| {
                for (offsets) |offset| {
                    if (offset <= -global_size or offset >= global_size) return error.InvalidOffset;
                }
            }
        }
        const lifting = self.liftingLogSize();
        if (lifting == 0) return error.InvalidGeometry;
        if (lifting < self.logBlowup()) return error.InvalidFri;
        const config = self.pcs.fri_config;
        if (config.fold_step == 0 or self.logDegreeBound() < config.log_last_layer_degree_bound) return error.InvalidFri;
        if (self.logDegreeBound() - config.log_last_layer_degree_bound < config.fold_step and
            self.logDegreeBound() != config.log_last_layer_degree_bound) return error.InvalidFri;
    }
};

/// One sampled value in the DEEP quotient: its column, its sample slot and
/// the power of the DEEP randomness it is weighted by.
pub const SampleRef = struct {
    tree: usize,
    column: usize,
    /// Index into the column's sampled values (the periodicity entry reuses
    /// sample 1).
    sample: usize,
    /// Column index in the flattened (tree-major) column list.
    flat_column: usize,
    /// `random_coeff^power`.
    power: usize,
};

/// The samples sharing one point: `oods + shift`.
pub const Batch = struct {
    shift: CirclePointIndex,
    entries: []const SampleRef,

    /// The constant point added to the OODS point.
    pub fn shiftPoint(self: Batch) CirclePointM31 {
        return self.shift.toPoint();
    }

    pub fn isOods(self: Batch) bool {
        return self.shift.v == 0;
    }
};

/// `buildColumnSampleBatchesFromParallelInputs`: the batches in
/// first-occurrence order, every entry in its native position.
pub const SamplePlan = struct {
    batches: []const Batch,
    n_samples: usize,

    pub fn init(allocator: std.mem.Allocator, shape: *const Shape) std.mem.Allocator.Error!SamplePlan {
        var batches: std.ArrayListUnmanaged(struct { shift: CirclePointIndex, entries: std.ArrayListUnmanaged(SampleRef) }) = .empty;
        var power: usize = 0;
        var flat_column: usize = 0;
        for (shape.mask_offsets, 0..) |tree_offsets, tree| {
            for (tree_offsets, 0..) |offsets, column| {
                defer flat_column += 1;
                if (offsets.len == 0) continue;
                if (offsets.len == 2) {
                    const shift = shape.maskShift(offsets[1]).add(shape.periodicityShift(tree, column));
                    try appendSample(allocator, &batches, shift, .{ .tree = tree, .column = column, .sample = 1, .flat_column = flat_column, .power = power });
                    power += 1;
                }
                for (offsets, 0..) |offset, sample| {
                    try appendSample(allocator, &batches, shape.maskShift(offset), .{ .tree = tree, .column = column, .sample = sample, .flat_column = flat_column, .power = power });
                    power += 1;
                }
            }
        }
        const out = try allocator.alloc(Batch, batches.items.len);
        for (out, batches.items) |*batch, *source| batch.* = .{ .shift = source.shift, .entries = try source.entries.toOwnedSlice(allocator) };
        batches.deinit(allocator);
        return .{ .batches = out, .n_samples = power };
    }

    fn appendSample(allocator: std.mem.Allocator, batches: anytype, shift: CirclePointIndex, sample: SampleRef) std.mem.Allocator.Error!void {
        for (batches.items) |*batch| {
            if (batch.shift.v == shift.v) {
                try batch.entries.append(allocator, sample);
                return;
            }
        }
        try batches.append(allocator, .{ .shift = shift, .entries = .empty });
        try batches.items[batches.items.len - 1].entries.append(allocator, sample);
    }
};

test "shape: validation and derived geometry of a two-tree statement" {
    const main_logs = [_]u32{ 4, 4, 4 };
    const comp_logs = [_]u32{5} ** 8;
    const offsets_0 = [_]i32{0};
    const offsets_01 = [_]i32{ 0, -1 };
    const main_offsets = [_][]const i32{ &offsets_0, &offsets_01, &.{} };
    const comp_offsets = [_][]const i32{&offsets_0} ** 8;
    const shape = Shape{
        .tree_column_log_sizes = &.{ &.{}, &main_logs, &comp_logs },
        .mask_offsets = &.{ &.{}, &main_offsets, &comp_offsets },
        .global_log = 5,
        .composition_log_split = 1,
        .pcs = .{ .pow_bits = 3, .fri_config = try core.fri.FriConfig.init(0, 1, 7) },
    };
    try shape.validate();
    try std.testing.expectEqual(@as(u32, 6), shape.liftingLogSize());
    try std.testing.expectEqual(@as(u32, 5), shape.treeHeight(1));
    try std.testing.expectEqual(@as(u32, 0), shape.treeHeight(0));
    try std.testing.expectEqual(@as(usize, 5), shape.nFriLayers());
    var buffer: [8]u32 = undefined;
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1, 1, 1 }, shape.foldSteps(&buffer));

    const plan = try SamplePlan.init(std.testing.allocator, &shape);
    defer {
        for (plan.batches) |batch| std.testing.allocator.free(batch.entries);
        std.testing.allocator.free(plan.batches);
    }
    // Column 0 at oods; column 1 periodic (sample 1 shifted), then at oods
    // and at the previous row; the composition columns at oods.
    try std.testing.expectEqual(@as(usize, 12), plan.n_samples);
    try std.testing.expectEqual(@as(usize, 3), plan.batches.len);
    try std.testing.expect(plan.batches[0].isOods());
    try std.testing.expectEqual(@as(usize, 10), plan.batches[0].entries.len);
    try std.testing.expectEqual(@as(usize, 1), plan.batches[1].entries.len);
    try std.testing.expectEqual(@as(usize, 1), plan.batches[1].entries[0].sample);
    try std.testing.expectEqual(@as(usize, 1), plan.batches[1].entries[0].power);
    try std.testing.expectEqual(@as(usize, 3), plan.batches[2].entries[0].power);
    try std.testing.expect(plan.batches[2].shift.v == shape.maskShift(-1).v);
    // The periodicity shift is `step(6).repeatedDouble(5)`.
    const expected = core.poly.circle.canonic.CanonicCoset.new(6).step().repeatedDouble(5);
    try std.testing.expect(shape.periodicityShift(1, 1).toPoint().eql(expected));
    try std.testing.expect(shape.maskShift(-1).toPoint().eql(core.poly.circle.canonic.CanonicCoset.new(5).step().neg()));

    var bad = shape;
    bad.global_log = 4;
    try std.testing.expectError(error.InvalidCompositionTree, bad.validate());
}
