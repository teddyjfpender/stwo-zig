//! PCS verifier adapter for the shared native truth arithmetic/terminal authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const Air = core.air.components.ForField(O);
const Point = core.circle.CirclePoint(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
pub const Authority = @import("truth_authority.zig");
const R = @import("native_roster.zig");
const Binding = @import("binding.zig");
const MP = @import("../../../logup_gkr/mle_point.zig");
pub const Component = struct {
    descriptor: Authority.Descriptor,
    span: R.Span,
    row_log: u32,
    parameters: Authority.ParametersFor(O),
    binding: *const Binding.ParametersFor(O),
    pub fn shifts(self: *const @This(), tree: usize, column: usize) []const i32 {
        if (tree == 2) return if (column < 8) &.{ 0, 2 } else &.{ 0, -1 };
        if (tree == 1) {
            if (self.descriptor.declaration.family == .keccak and self.descriptor.part == 0) {
                if (column < A.crypto.keccak.layout.STATE) return &.{ 0, -2, -1, 1, 2 };
                if (column >= A.crypto.keccak.layout.ACTIVE_A) return &.{ 0, -1 };
            } else if (self.descriptor.declaration.family != .keccak and column == 0) return &.{ 0, -1 };
        }
        return &.{0};
    }
    pub fn validate(self: *const @This()) !void {
        if (self.row_log < 5 or self.row_log > 23 or self.binding.point.slice().len != self.row_log) return error.NativeGkrTruthComponent;
        const terms = try Authority.terms(self.descriptor);
        for (terms, self.parameters.weights, self.binding.weights) |count, weights, expected| {
            const lanes = if (count == 0) @as(usize, 0) else @as(usize, 1) << @intCast(@import("roster.zig").laneLog(count));
            if (weights.len != lanes or expected.len != lanes) return error.NativeGkrTruthComponent;
            // Actual field values enter through producer/receiver derivation;
            // this shape adapter never trusts an independently guessed roster.
        }
    }
    pub fn nConstraints(self: *const @This()) usize {
        return self.span.constraints;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.row_log + self.span.split;
    }
    pub fn compositionLogSplit(self: *const @This()) u32 {
        return self.span.split;
    }
    pub fn constraintDegreeBound(self: *const @This(), index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return self.span.degree;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        try self.validate();
        const widths = [_]usize{ self.span.fixed, self.span.main, 16 };
        const trees = try a.alloc([]u32, 3);
        errdefer a.free(trees);
        var done: usize = 0;
        errdefer for (trees[0..done]) |tree| a.free(tree);
        for (trees, widths) |*tree, width| {
            tree.* = try a.alloc(u32, width);
            @memset(tree.*, self.row_log);
            done += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(trees);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        try self.validate();
        const out = try a.alloc(usize, self.span.fixed);
        for (out, 0..) |*v, i| v.* = self.span.fixed_offset + i;
        return out;
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        try self.validate();
        _ = try A.geometry.localPointFor(O, point, global_log, self.row_log);
        const trees = try a.alloc([][]Point, 3);
        errdefer a.free(trees);
        var done: usize = 0;
        errdefer for (trees[0..done]) |tree| {
            for (tree) |column| a.free(column);
            a.free(tree);
        };
        const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step;
        const lifted = Point{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) };
        for (trees, [_]usize{ self.span.fixed, self.span.main, 16 }, 0..) |*tree, width, t| {
            tree.* = try a.alloc([]Point, width);
            var assigned: usize = 0;
            errdefer {
                for (tree.*[0..assigned]) |column| a.free(column);
                a.free(tree.*);
            }
            for (tree.*, 0..) |*column, c| {
                const offsets = self.shifts(t, c);
                column.* = try a.alloc(Point, offsets.len);
                for (column.*, offsets) |*value, offset| value.* = point.add(lifted.mulSigned(offset));
                assigned += 1;
            }
            done += 1;
        }
        return Air.MaskPoints.initOwned(trees);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, masks: *const Air.MaskValues, acc: *Acc, global_log: u32) !void {
        try self.validate();
        const Sample = struct {
            component: *const Component,
            values: E.lane.NativeMasksForField(O),
            pub fn get(s: *const @This(), tree: usize, column: usize, offset: i32) !O {
                const shifts_ = s.component.shifts(tree, column);
                const index = std.mem.indexOfScalar(i32, shifts_, offset) orelse return error.InvalidTruthMask;
                const base = ([_]usize{ s.component.span.fixed_offset, s.component.span.main_offset, s.component.span.inter_offset })[tree];
                return E.lane.sample(O, s.values, tree, base + column, index, shifts_.len);
            }
        };
        const samples = Sample{ .component = self, .values = .{ .values = masks } };
        var eq: [8]O = undefined;
        var eq_next: [8]O = undefined;
        var prefix: [8]O = undefined;
        var prior: [8]O = undefined;
        for (0..8) |i| {
            eq[i] = try samples.get(2, i, 0);
            eq_next[i] = try samples.get(2, i, 2);
            prefix[i] = try samples.get(2, 8 + i, 0);
            prior[i] = try samples.get(2, 8 + i, -1);
        }
        const local_point = try A.geometry.localPointFor(O, point, global_log, self.row_log);
        const anchors = try MP.evalAnchorsFor(O, self.row_log, local_point);
        var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.row_log) };
        try Authority.emitFor(O, self.descriptor, self.parameters, &samples, .{ .eq = O.fromPartialEvals(eq), .eq_next2 = O.fromPartialEvals(eq_next), .prefix = O.fromPartialEvals(prefix), .prefix_previous = O.fromPartialEvals(prior) }, .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(O, &self.binding.point, local_point), .eq0 = self.binding.point.eq0, .eq1 = self.binding.point.eq1 }, &sink);
        if (sink.count != self.nConstraints()) return error.NativeGkrTruthComponent;
    }
    pub fn evaluateConstraintQuotientsOnDomain(_: *const @This(), _: *const P.Trace, _: *D.DomainEvaluationAccumulator) !void {
        return error.NativeGkrDeviceCompositionRequired;
    }
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) P.ComponentProver {
        return Adapter.asProverComponent(self);
    }
};
test "native reduced truth verifier is fully typed including every admitted family" {
    var component: Component = undefined;
    _ = component.asVerifierComponent();
}
