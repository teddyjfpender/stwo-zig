//! Typed point adapter for register endpoints and canonical scalar providers.
//! Native domain evaluation remains owned by the existing component.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const B = @import("boundary.zig");
const Lookup = @import("lookup.zig");
const Scalar = @import("../providers/scalar_range.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const Q = E.Q;
pub const Kind = enum { boundary, range16, range8 };
pub fn ChallengesFor(comptime C: type) type {
    return struct { register: Lookup.RegisterChallengesFor(C), range16: Scalar.ChallengesFor(C), range8: Scalar.ChallengesFor(C) };
}
pub const Component = ComponentFor(Q);
pub fn ComponentFor(comptime C: type) type {
    E.assertConstLane(C);
    return struct {
        const Self = @This();
        kind: Kind,
        log_size: u32,
        offsets: [3]usize,
        public: ?B.PublicFor(C) = null,
        claim: C,
        challenges: ChallengesFor(C),
        const Adapter = core.air.derive.ComponentAdapter(Self, engine.air.component_prover.ComponentProver, engine.air.component_prover.Trace, engine.air.accumulation.DomainEvaluationAccumulator);
        pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
            return Adapter.asVerifierComponent(self);
        }
        fn validateGeometry(self: *const Self) !void {
            const expected: u32 = switch (self.kind) {
                .boundary => 5,
                .range16 => 16,
                .range8 => 8,
            };
            if (self.log_size != expected) return error.InvalidWord16BoundaryGeometry;
            if (self.kind == .boundary and self.public == null) return error.MissingRegisterBoundaryPublic;
        }
        pub fn widths(self: *const Self) [3]usize {
            return if (self.kind == .boundary) .{ 34, 0, 8 } else .{ 3, 1, 8 };
        }
        pub fn nConstraints(_: *const Self) usize {
            return 3;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= 3) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
            try self.validateGeometry();
            var logs: [3][]u32 = undefined;
            var count: usize = 0;
            errdefer for (logs[0..count]) |l| a.free(l);
            for (self.widths(), &logs) |width, *out| {
                out.* = try points.emptyOrFilledLogs(a, width, self.log_size);
                count += 1;
            }
            return core.air.components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const out = try a.alloc(usize, self.widths()[0]);
            for (out, 0..) |*v, c| v.* = self.offsets[0] + c;
            return out;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: core.circle.CirclePointQM31, global_log: u32) !core.air.components.MaskPoints {
            try self.validateGeometry();
            _ = try geometry.localPoint(point, global_log, self.log_size);
            var masks: [3][][]core.circle.CirclePointQM31 = undefined;
            var count: usize = 0;
            errdefer for (masks[0..count]) |columns| points.freePointColumns(a, columns);
            for (self.widths(), &masks) |width, *out| {
                out.* = try points.currentPointColumns(a, width, point);
                count += 1;
            }
            for (masks[2][4..]) |*column| {
                const replacement = try a.dupe(core.circle.CirclePointQM31, &.{ point, geometry.previousPoint(point, global_log) });
                a.free(column.*);
                column.* = replacement;
            }
            return core.air.components.MaskPoints.initOwned(try a.dupe([][]core.circle.CirclePointQM31, &masks));
        }
        pub fn emitFor(self: *const Self, comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) void {
            comptime if (E.ConstFor(F) != C) @compileError("register boundary component lane mismatch");
            if (self.kind == .boundary) {
                B.emitWithInputsFor(F, fixed, current, previous, self.public.?, self.claim, self.challenges.register, sink);
            } else Scalar.rangeFor(F, fixed, main, current, previous, self.claim, if (self.kind == .range16) self.challenges.range16 else self.challenges.range8, sink);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: core.circle.CirclePointQM31, masks: *const core.air.components.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = acc };
            try self.evaluateQuotientsAtPointFor(Q, point, global_log, E.lane.NativeMasks{ .values = masks }, &sink);
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != C) @compileError("register boundary component lane mismatch");
            try self.validateGeometry();
            const w = self.widths();
            var fixed: [34]F = undefined;
            var main: [1]F = undefined;
            var current: [8]F = undefined;
            var previous: [8]F = @splat(F.zero());
            for (fixed[0..w[0]], 0..) |*v, c| v.* = try E.lane.sample(F, masks, 0, self.offsets[0] + c, 0, 1);
            for (main[0..w[1]], 0..) |*v, c| v.* = try E.lane.sample(F, masks, 1, self.offsets[1] + c, 0, 1);
            for (&current, 0..) |*v, c| {
                v.* = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 0, if (c >= 4) 2 else 1);
                if (c >= 4) previous[c] = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 1, 2);
            }
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            self.emitFor(F, fixed[0..w[0]], main[0..w[1]], &current, &previous, sink);
        }
    };
}
