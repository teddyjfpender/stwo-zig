//! Same-original-main SOURCE SHA connector masks. Five physical trees:
//! source fixed0/source main1/connector fixed2/capture main3/interaction4.
//! No raw/state request can be redirected to copied arithmetic inputs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Air = @import("block_v5_memory_source_sha_connector_air_v1.zig");
const Interaction = @import("block_v5_memory_source_sha_connector_interaction_v1.zig");
pub const Spec = struct {
    pub const FIXED_COUNT = Air.EXPANDED_FIXED_COUNT;
    pub const MAIN_COUNT = Air.MAIN_COUNT;
    pub const INTERACTION_COUNT = Air.INTERACTION_COUNT;
    pub const CONSTRAINT_COUNT = Air.CONSTRAINT_COUNT;
    pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
    pub const DEGREE = Air.DEGREE;
    pub const EXPANSION_BITS = Air.EXPANSION_BITS;
    rows: u32,
    expected_requests: u64,
    claim: Interaction.Claim,
    challenge: Air.Algebra(Q).Challenge,
    pub const Domain = struct {
        size: u32,
        challenge: Air.Algebra(Q).Challenge,
        normalized: [Air.PAIRS]Q,
        packed_challenge: Air.Algebra(P).Challenge,
        packed_normalized: [Air.PAIRS]P,
        pub fn evaluate(self: Domain, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, _: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
            if (size != self.size) return error.InvalidSourceShaConnectorGeometry;
            return Air.Algebra(Q).constraints(fixed, main, current, previous, self.normalized, self.challenge);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [FIXED_COUNT]P, main: [MAIN_COUNT]P, _: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, previous: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
            return Air.Algebra(P).constraints(fixed, main, current, previous, self.packed_normalized, self.packed_challenge);
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        if (size != self.rows) return error.InvalidSourceShaConnectorGeometry;
        const normalized = try Interaction.normalize(self.claim, size, self.expected_requests);
        var powers: [6]P = undefined;
        var packed_sums: [Air.PAIRS]P = undefined;
        for (&powers, self.challenge.powers) |*out, value| out.* = P.splat(value);
        for (&packed_sums, normalized) |*out, value| out.* = P.splat(value);
        return .{ .size = size, .challenge = self.challenge, .normalized = normalized, .packed_challenge = .{ .z = P.splat(self.challenge.z), .powers = powers }, .packed_normalized = packed_sums };
    }
    pub fn evaluate(self: Spec, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, previous_main: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, main, previous_main, current, previous, size);
    }
};
pub fn ForSourceFixed(comptime source_fixed_count: usize) type {
    return struct {
        const Self = @This();
        const Components = core.air.components;
        const Prover = engine.air.component_prover;
        const Accum = engine.air.accumulation;
        const Point = core.circle.CirclePointQM31;
        const Adapter = core.air.derive.ComponentAdapter(Self, Prover.ComponentProver, Prover.Trace, Accum.DomainEvaluationAccumulator);
        inner: @import("block_v5_word_quotient_adapter_v1.zig").For(Spec),
        pub fn init(row_log: u32, expected_requests: u64, claim: Interaction.Claim, challenge: Air.Algebra(Q).Challenge) !Self {
            if (row_log == 0 or row_log >= 31) return error.InvalidSourceShaConnectorGeometry;
            const rows: u32 = @as(u32, 1) << @intCast(row_log);
            _ = try Interaction.normalize(claim, rows, expected_requests);
            return .{ .inner = .{ .log_size = row_log, .spec = .{ .rows = rows, .expected_requests = expected_requests, .claim = claim, .challenge = challenge } } };
        }
        pub fn asProverComponent(self: *const Self) Prover.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) Components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.inner.nConstraints();
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.inner.maxConstraintLogDegreeBound();
        }
        pub fn compositionLogSplit(self: *const Self) u32 {
            return self.inner.compositionLogSplit();
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            return Air.degree(index);
        }
        pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
            return a.alloc(usize, 0);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Components.TraceLogDegreeBounds {
            const counts = [_]usize{ source_fixed_count, Air.SOURCE_MAIN_COUNT, Spec.FIXED_COUNT, Air.CAPTURE_MAIN_COUNT, Spec.INTERACTION_COUNT };
            const trees = try a.alloc([]u32, counts.len);
            var completed: usize = 0;
            errdefer {
                for (trees[0..completed]) |logs| a.free(logs);
                a.free(trees);
            }
            for (trees, counts) |*tree, count| {
                tree.* = try a.alloc(u32, count);
                @memset(tree.*, self.inner.log_size);
                completed += 1;
            }
            return .initOwned(trees);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !Components.MaskPoints {
            return staticMaskPoints(self.inner.log_size, a, point, max_log);
        }
        pub fn staticMaskPoints(log_size: u32, a: std.mem.Allocator, point: Point, max_log: u32) !Components.MaskPoints {
            var original = try @import("block_v5_word_quotient_adapter_v1.zig").For(Spec).staticMaskPoints(log_size, a, point, max_log);
            errdefer original.deinitDeep(a);
            const source_fixed = try a.alloc([]Point, source_fixed_count);
            errdefer a.free(source_fixed);
            for (source_fixed) |*column| column.* = &.{};
            const source_main = try a.dupe([]Point, original.items[1][0..Air.SOURCE_MAIN_COUNT]);
            errdefer a.free(source_main);
            const captures = try a.dupe([]Point, original.items[1][Air.SOURCE_MAIN_COUNT..]);
            errdefer a.free(captures);
            const trees = try a.dupe([][]Point, &.{ source_fixed, source_main, original.items[0], captures, original.items[2] });
            a.free(original.items[1]);
            a.free(original.items);
            return .initOwned(trees);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const Components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (mask.items.len != 5 or mask.items[0].len != source_fixed_count or mask.items[1].len != Air.SOURCE_MAIN_COUNT or mask.items[2].len != Spec.FIXED_COUNT or mask.items[3].len != Air.CAPTURE_MAIN_COUNT or mask.items[4].len != Spec.INTERACTION_COUNT) return error.InvalidSourceShaConnectorMasks;
            var main: [Spec.MAIN_COUNT][]Q = undefined;
            @memcpy(main[0..Air.SOURCE_MAIN_COUNT], mask.items[1]);
            @memcpy(main[Air.SOURCE_MAIN_COUNT..], mask.items[3]);
            var trees = [_][][]Q{ mask.items[2], &main, mask.items[4] };
            const view = Components.MaskValues{ .items = &trees };
            try self.inner.evaluateConstraintQuotientsAtPoint(point, &view, accumulator, max_log);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const Prover.Trace, accumulator: *Accum.DomainEvaluationAccumulator) !void {
            if (source.polys.items.len != 5 or source.polys.items[0].len != source_fixed_count or source.polys.items[1].len != Air.SOURCE_MAIN_COUNT or source.polys.items[2].len != Spec.FIXED_COUNT or source.polys.items[3].len != Air.CAPTURE_MAIN_COUNT or source.polys.items[4].len != Spec.INTERACTION_COUNT) return error.InvalidSourceShaConnectorTrees;
            const main = try accumulator.allocator.alloc(Prover.Poly, Spec.MAIN_COUNT);
            defer accumulator.allocator.free(main);
            @memcpy(main[0..Air.SOURCE_MAIN_COUNT], source.polys.items[1]);
            @memcpy(main[Air.SOURCE_MAIN_COUNT..], source.polys.items[3]);
            var trees = [_][]const Prover.Poly{ source.polys.items[2], main, source.polys.items[4] };
            var view = source.*;
            view.polys = .{ .items = &trees };
            try self.inner.evaluateConstraintQuotientsOnDomain(&view, accumulator);
        }
    };
}
