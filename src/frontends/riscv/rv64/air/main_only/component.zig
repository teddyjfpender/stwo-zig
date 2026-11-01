//! Native OM31 MAIN-only verifier component. A route is incomplete until its
//! local GKR bindings and separate wide global LogUp components also verify.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const G = @import("../geometry.zig");
const A = @import("authority.zig");
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
pub const Component = struct {
    log_size: u32,
    public: A.PublicFor(O),
    offsets: [2]usize,
    pub fn role(self: *const @This()) A.Role {
        return std.meta.activeTag(self.public);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return A.shape(self.role()).constraints;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const @This(), index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return A.shape(self.role()).max_degree;
    }
    pub fn validate(self: *const @This()) !void {
        if (self.log_size < 5 or self.log_size > 22) return error.InvalidMainOnlyGeometry;
        switch (self.public) {
            .cpu => |p| try @import("../word16_execution/types.zig").validateInputs(.{ .steps = p.steps, .initial_pc = p.initial_pc, .final_pc = p.final_pc, .epoch = p.epoch }, self.log_size),
            .ls, .mul, .div => |p| {
                if (p.count >= @as(u32, 1) << @intCast(self.log_size)) return error.InvalidMainOnlyCount;
            },
            else => {},
        }
    }
    pub fn traceLogDegreeBounds(self: *const @This(), allocator: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        try self.validate();
        const widths = [_]usize{ A.shape(self.role()).fixed, A.shape(self.role()).main, 0 };
        const trees = try allocator.alloc([]u32, 3);
        errdefer allocator.free(trees);
        var initialized: usize = 0;
        errdefer for (trees[0..initialized]) |tree| allocator.free(tree);
        for (trees, widths) |*tree, n| {
            tree.* = try allocator.alloc(u32, n);
            @memset(tree.*, self.log_size);
            initialized += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), allocator: std.mem.Allocator) ![]usize {
        try self.validate();
        const result = try allocator.alloc(usize, A.shape(self.role()).fixed);
        for (result, 0..) |*v, i| v.* = self.offsets[0] + i;
        return result;
    }
    pub fn maskPoints(self: *const @This(), allocator: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        try self.validate();
        _ = try G.localPointFor(O, point, global_log, self.log_size);
        const widths = [_]usize{ A.shape(self.role()).fixed, A.shape(self.role()).main, 0 };
        const trees = try allocator.alloc([][]Point, 3);
        errdefer allocator.free(trees);
        var initialized: usize = 0;
        errdefer for (trees[0..initialized]) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        };
        for (trees, widths, 0..) |*tree, n, t| {
            tree.* = try allocator.alloc([]Point, n);
            var assigned: usize = 0;
            errdefer {
                for (tree.*[0..assigned]) |column| allocator.free(column);
                allocator.free(tree.*);
            }
            for (tree.*, 0..) |*column, c| {
                column.* = if (t == 1 and A.previousMain(self.role(), c)) try allocator.dupe(Point, &.{ point, G.previousPointFor(O, point, global_log) }) else try allocator.dupe(Point, &.{point});
                assigned += 1;
            }
            initialized += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, accumulator: *Acc, global_log: u32) !void {
        try self.validate();
        const s = A.shape(self.role());
        const masks = E.lane.NativeMasksForField(O){ .values = mask };
        var fixed: [3]O = undefined;
        var main: [128]O = undefined;
        var previous: [128]O = @splat(O.zero());
        for (fixed[0..s.fixed], 0..) |*v, c| v.* = try E.lane.sample(O, masks, 0, self.offsets[0] + c, 0, 1);
        for (main[0..s.main], 0..) |*v, c| {
            const prior = A.previousMain(self.role(), c);
            v.* = try E.lane.sample(O, masks, 1, self.offsets[1] + c, 0, if (prior) 2 else 1);
            if (prior) previous[c] = try E.lane.sample(O, masks, 1, self.offsets[1] + c, 1, 2);
        }
        var sink = E.SinkFor(O){ .accumulator = accumulator, .scale = try G.denominatorInverseFor(O, point, global_log, self.log_size) };
        try A.emitFor(O, self.public, fixed[0..s.fixed], main[0..s.main], previous[0..s.main], &sink);
        if (sink.count != s.constraints) return error.InvalidMainOnlyConstraintCount;
    }
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        // Only the verifier surface is exposed until the real wide prover
        // trace/domain interfaces are supplied; no pretend prover exists here.
        return core.air.derive.ForField(O).ComponentAdapter(@This(), void, void, void).asVerifierComponent(self);
    }
};
