//! Shared typed page-binding kernel; schemas fix exact original source
//! inventory and grammar. No host/source descriptor grants proof authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Actual four-tree masks for original fixed0/private1/routing2/interaction3.
        //! Scalar and packed point/domain equations share the exact binding algebra.
        const Q = core.fields.qm31.QM31;
        const P = core.fields.packed_qm31.PackedQM31;
        const Air = Schema.BindingAir;
        const Routing = Schema.BindingPlan;
        const Interaction = Schema.BindingInteraction;
        const First = Schema.Protocol;
        pub const Spec = struct {
            pub const FIXED_COUNT = Air.FIXED_COUNT;
            pub const MAIN_COUNT = Air.MAIN_COUNT;
            pub const INTERACTION_COUNT = Air.INTERACTION_COUNT;
            pub const CONSTRAINT_COUNT = Air.CONSTRAINT_COUNT;
            pub const PREVIOUS_MAIN_MASK: [MAIN_COUNT]bool = @splat(false);
            pub const DEGREE = 3;
            pub const EXPANSION_BITS = 2;
            plan: *const Routing.Plan,
            claim: Interaction.Claim,
            challenge: Air.Algebra(Q).Challenge,
            pub const Domain = struct {
                challenge: Air.Algebra(Q).Challenge,
                normalized: [Air.PAIRS]Q,
                packed_challenge: Air.Algebra(P).Challenge,
                packed_normalized: [Air.PAIRS]P,
                size: u32,
                pub fn evaluate(self: Domain, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, _: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
                    if (size != self.size) return error.UntrustedMemorySourceBindingPage;
                    return Air.Algebra(Q).constraints(fixed, main, current, previous, self.normalized, self.challenge);
                }
                pub fn evaluatePacked(self: *const Domain, fixed: [FIXED_COUNT]P, main: [MAIN_COUNT]P, _: [MAIN_COUNT]P, current: [INTERACTION_COUNT]P, previous: [INTERACTION_COUNT]P) [CONSTRAINT_COUNT]P {
                    @setEvalBranchQuota(1_000_000);
                    return Air.Algebra(P).constraints(fixed, main, current, previous, self.packed_normalized, self.packed_challenge);
                }
            };
            pub fn prepareDomain(self: Spec, size: u32) !Domain {
                if (size != self.plan.rows()) return error.UntrustedMemorySourceBindingPage;
                const normalized = try Interaction.normalize(self.claim, self.plan);
                var packed_sums: [Air.PAIRS]P = undefined;
                for (&packed_sums, normalized) |*out, value| out.* = P.splat(value);
                var powers: [6]P = undefined;
                for (&powers, self.challenge.powers) |*out, value| out.* = P.splat(value);
                return .{ .challenge = self.challenge, .normalized = normalized, .packed_challenge = .{ .z = P.splat(self.challenge.z), .powers = powers }, .packed_normalized = packed_sums, .size = size };
            }
            pub fn evaluate(self: Spec, fixed: [FIXED_COUNT]Q, main: [MAIN_COUNT]Q, prior_main: [MAIN_COUNT]Q, current: [INTERACTION_COUNT]Q, previous: [INTERACTION_COUNT]Q, size: u32) ![CONSTRAINT_COUNT]Q {
                return (try self.prepareDomain(size)).evaluate(fixed, main, prior_main, current, previous, size);
            }
        };
        pub const Component = struct {
            inner: @import("block_v5_word_quotient_adapter_v1.zig").For(Spec),
            const Self = @This();
            const Components = core.air.components;
            const Prover = engine.air.component_prover;
            const Accum = engine.air.accumulation;
            const Point = core.circle.CirclePointQM31;
            const Adapter = core.air.derive.ComponentAdapter(Self, Prover.ComponentProver, Prover.Trace, Accum.DomainEvaluationAccumulator);
            pub fn init(plan: *const Routing.Plan, claim: Interaction.Claim, challenge: Air.Algebra(Q).Challenge) !Self {
                _ = try Interaction.normalize(claim, plan);
                return .{ .inner = .{ .log_size = plan.first.page.row_log, .spec = .{ .plan = plan, .claim = claim, .challenge = challenge } } };
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
                const result = try a.alloc(usize, First.FIXED_COUNT);
                for (result, 0..) |*out, i| out.* = i;
                return result;
            }
            pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Components.TraceLogDegreeBounds {
                const counts = [_]usize{ First.FIXED_COUNT, Air.MAIN_COUNT, Routing.ROUTING_COUNT, Air.INTERACTION_COUNT };
                const trees = try a.alloc([]u32, 4);
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
                @setEvalBranchQuota(1_000_000);
                var original = try self.inner.maskPoints(a, point, max_log);
                errdefer original.deinitDeep(a);
                const fixed = try a.dupe([]Point, original.items[0][0..First.FIXED_COUNT]);
                errdefer a.free(fixed);
                const routing = try a.dupe([]Point, original.items[0][First.FIXED_COUNT..]);
                errdefer a.free(routing);
                const trees = try a.dupe([][]Point, &.{ fixed, original.items[1], routing, original.items[2] });
                a.free(original.items[0]);
                a.free(original.items);
                return .initOwned(trees);
            }
            pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const Components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
                if (mask.items.len != 4 or mask.items[0].len != First.FIXED_COUNT or mask.items[1].len != Air.MAIN_COUNT or mask.items[2].len != Routing.ROUTING_COUNT or mask.items[3].len != Air.INTERACTION_COUNT) return error.InvalidMemorySourceBindingMasks;
                var fixed: [Air.FIXED_COUNT][]Q = undefined;
                @memcpy(fixed[0..First.FIXED_COUNT], mask.items[0]);
                @memcpy(fixed[First.FIXED_COUNT..], mask.items[2]);
                var trees = [_][][]Q{ &fixed, mask.items[1], mask.items[3] };
                const view = Components.MaskValues{ .items = &trees };
                @setEvalBranchQuota(1_000_000);
                try self.inner.evaluateConstraintQuotientsAtPoint(point, &view, accumulator, max_log);
            }
            pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const Prover.Trace, accumulator: *Accum.DomainEvaluationAccumulator) !void {
                if (source.polys.items.len != 4 or source.polys.items[0].len != First.FIXED_COUNT or source.polys.items[1].len != Air.MAIN_COUNT or source.polys.items[2].len != Routing.ROUTING_COUNT or source.polys.items[3].len != Air.INTERACTION_COUNT) return error.InvalidMemorySourceBindingTrees;
                const a = accumulator.allocator;
                const fixed = try a.alloc(Prover.Poly, Air.FIXED_COUNT);
                defer a.free(fixed);
                @memcpy(fixed[0..First.FIXED_COUNT], source.polys.items[0]);
                @memcpy(fixed[First.FIXED_COUNT..], source.polys.items[2]);
                var trees = [_][]const Prover.Poly{ fixed, source.polys.items[1], source.polys.items[3] };
                var view = source.*;
                view.polys = .{ .items = &trees };
                try self.inner.evaluateConstraintQuotientsOnDomain(&view, accumulator);
            }
        };
    };
}
