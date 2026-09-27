//! Native and verifier Stwo adapter for sorted-memory rows, the block-v2
//! transition/link/initial buses and the 35 universal byte-range requests.
//! Production still requires a proved initial-value provider and global bus
//! closure against execution, range table and authenticated initial state.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const component_prover = engine.air.component_prover;
const domain_accumulation = engine.air.accumulation;
const component = @import("memory_component.zig");
const trace = @import("memory_component_trace.zig");
const evaluator = @import("memory_component_eval.zig");
const order = @import("memory_order.zig");
const bus = @import("../../prover/block_memory_relation_v2.zig");
const range = @import("memory_range_interaction_v2.zig");
const support = @import("../memory_commitment/hash_component_prepared_support.zig");

pub const fixed_count = trace.fixed_column_count;
pub const main_count = trace.main_column_count;
pub const interaction_count = 12 + range.COLUMN_COUNT;
const source_count = fixed_count + main_count + interaction_count;
pub const expansion_bits: u32 = 2;
pub const production_active = false;

pub const Placement = struct {
    fixed_offset: usize = 0,
    main_offset: usize = 0,
    interaction_offset: usize = 0,
};

pub const Component = ComponentFor(false);
pub const CompactComponent = ComponentFor(true);

fn ComponentFor(comptime compact: bool) type {
    return struct {
        const main_width = if (compact) component.Layout.linked_previous else main_count;
        const source_width = fixed_count + main_width + interaction_count;
        definition: *const component.Definition,
        claim: component.Claim,
        interaction_claim: bus.ComponentClaim,
        range_plan: *const range.RangePlan,
        range_claims: range.Claims,
        challenges: *const bus.Challenges,
        placement: Placement,

        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, component_prover.ComponentProver, component_prover.Trace, domain_accumulation.DomainEvaluationAccumulator);

        pub fn init(definition: *const component.Definition, claim: component.Claim, interaction_claim: bus.ComponentClaim, range_plan: *const range.RangePlan, range_claims: range.Claims, challenges: *const bus.Challenges, placement: Placement) !Self {
            try claim.validate();
            try interaction_claim.validateCanonical();
            if (claim.log_size + expansion_bits >= circle.M31_CIRCLE_LOG_ORDER) return error.InvalidMemoryComponentLogSize;
            if (definition.inputs.len != component.Layout.len) return error.InvalidMemoryComponentDefinition;
            return .{ .definition = definition, .claim = claim, .interaction_claim = interaction_claim, .range_plan = range_plan, .range_claims = range_claims, .challenges = challenges, .placement = placement };
        }
        pub fn asProverComponent(self: *const Self) component_prover.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.definition.arena.constraintsView().len + 4 + range.BATCH_COUNT;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.claim.log_size + expansion_bits;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            // The cyclic-prefix terminal pin and fixed linear link selectors
            // bound the v2 link recurrence to degree five.
            return expansion_bits;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
            return 5;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
            const fixed_logs = try filledLogs(a, fixed_count, self.claim.log_size);
            errdefer a.free(fixed_logs);
            const main_logs = try filledLogs(a, main_width, self.claim.log_size);
            errdefer a.free(main_logs);
            const interaction_logs = try filledLogs(a, interaction_count, self.claim.log_size);
            errdefer a.free(interaction_logs);
            return components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed_logs, main_logs, interaction_logs }));
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: circle.CirclePointQM31, max_log: u32) !components.MaskPoints {
            if (max_log < self.claim.log_size) return error.InvalidMemoryMaskDegree;
            const shifted = @import("../logup.zig").prevRowPoint(max_log, point);
            const fixed_points = try pointColumns(a, fixed_count, &.{point});
            errdefer freePointColumns(a, fixed_points);
            const main_points = try pointColumns(a, main_width, &.{ point, shifted });
            errdefer freePointColumns(a, main_points);
            const interaction_points = try pointColumns(a, interaction_count, &.{ point, shifted });
            errdefer freePointColumns(a, interaction_points);
            return components.MaskPoints.initOwned(try a.dupe([][]circle.CirclePointQM31, &.{ fixed_points, main_points, interaction_points }));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const indices = try a.alloc(usize, fixed_count);
            for (indices, 0..) |*index, i| index.* = self.placement.fixed_offset + i;
            return indices;
        }

        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: circle.CirclePointQM31, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            // The shared proof may carry additional trees after the three trace
            // trees owned by this component (for example the composition tree).
            if (mask.items.len < 3 or max_log < self.claim.log_size) return error.InvalidMemoryPointMask;
            if (mask.items[0].len < self.placement.fixed_offset + fixed_count or mask.items[1].len < self.placement.main_offset + main_width or mask.items[2].len < self.placement.interaction_offset + interaction_count) return error.InvalidMemoryPointMask;
            var fixed: [fixed_count]Q = undefined;
            var main: [main_width]Q = undefined;
            var previous: [main_width]Q = undefined;
            var interaction: [interaction_count]Q = undefined;
            var previous_interaction: [interaction_count]Q = undefined;
            for (&fixed, 0..) |*value, i| value.* = try pointAt(mask.items[0][self.placement.fixed_offset + i], 0);
            for (&main, &previous, 0..) |*value, *before, i| {
                value.* = try pointAt(mask.items[1][self.placement.main_offset + i], 0);
                before.* = try pointAt(mask.items[1][self.placement.main_offset + i], 1);
            }
            for (&interaction, &previous_interaction, 0..) |*value, *before, i| {
                value.* = try pointAt(mask.items[2][self.placement.interaction_offset + i], 0);
                before.* = try pointAt(mask.items[2][self.placement.interaction_offset + i], 1);
            }
            const a = std.heap.page_allocator;
            const scratch = try a.alloc(Q, self.definition.arena.nodeCount());
            defer a.free(scratch);
            const direct = try a.alloc(Q, self.definition.arena.constraintsView().len);
            defer a.free(direct);
            const inputs = composeInputs(fixed, main, previous);
            try evaluator.evaluate(Q, &self.definition.arena, &inputs, scratch, direct);
            const lookup = try bus.interactionConstraints(self.challenges, .sorted, interactionPoint(fixed, expandedMain(main), interaction, previous_interaction), self.interaction_claim, @as(u32, 1) << @intCast(self.claim.log_size));
            const range_checks = try self.range_plan.evaluateAt(scratch, rangeSums(interaction), rangeSums(previous_interaction), fixed[trace.fixed.first], self.range_claims, self.challenges.universal_prefix.get(.range_check_8_8));
            const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.claim.log_size).coset(), point.repeatedDouble(max_log - self.claim.log_size)).inv();
            for (direct) |value| accumulator.accumulate(value.mul(inverse));
            for (lookup) |value| accumulator.accumulate(value.mul(inverse));
            for (range_checks) |value| accumulator.accumulate(value.mul(inverse));
        }

        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, source: *const component_prover.Trace, accumulator: *domain_accumulation.DomainEvaluationAccumulator) !void {
            const a = accumulator.allocator;
            if (source.polys.items.len != 3) return error.InvalidMemoryTraceTrees;
            const trees = source.polys.items;
            if (trees[0].len < self.placement.fixed_offset + fixed_count or trees[1].len < self.placement.main_offset + main_width or trees[2].len < self.placement.interaction_offset + interaction_count) return error.InvalidMemoryTraceColumns;
            const eval_log = self.claim.log_size + expansion_bits;
            const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
            const eval_size = domain.size();
            var polys: [source_width]component_prover.Poly = undefined;
            for (0..fixed_count) |i| polys[i] = trees[0][self.placement.fixed_offset + i];
            for (0..main_width) |i| polys[fixed_count + i] = trees[1][self.placement.main_offset + i];
            for (0..interaction_count) |i| polys[fixed_count + main_width + i] = trees[2][self.placement.interaction_offset + i];
            var owned_count: usize = 0;
            for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.claim.log_size, eval_log));
            const owned = try a.alloc([]M, owned_count);
            var initialized: usize = 0;
            defer {
                for (owned[0..initialized]) |column| a.free(column);
                a.free(owned);
            }
            var evals: [source_width][]const M = undefined;
            for (polys, &evals) |poly, *out| out.* = try support.evaluationValues(a, poly, eval_log, eval_size, owned, &initialized);
            if (owned.len != 0) {
                var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &twiddles);
                try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
            }
            var inverses: [1 << expansion_bits]M = undefined;
            const trace_coset = canonic.CanonicCoset.new(self.claim.log_size).coset();
            for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, expansion_bits))).inv();
            const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
            defer a.free(columns);
            var result = columns[0];
            const work = try a.alloc(Q, self.definition.arena.nodeCount());
            defer a.free(work);
            const direct = try a.alloc(Q, self.definition.arena.constraintsView().len);
            defer a.free(direct);
            const shift: std.math.Log2Int(usize) = @intCast(self.claim.log_size);
            for (0..eval_size) |row| {
                const prev_row = core.utils.previousBitReversedCircleDomainIndex(row, self.claim.log_size, eval_log);
                var fixed: [fixed_count]Q = undefined;
                var main: [main_width]Q = undefined;
                var previous: [main_width]Q = undefined;
                var interaction: [interaction_count]Q = undefined;
                var before_interaction: [interaction_count]Q = undefined;
                for (&fixed, 0..) |*value, i| value.* = Q.fromBase(evals[i][row]);
                for (&main, &previous, 0..) |*value, *before, i| {
                    value.* = Q.fromBase(evals[fixed_count + i][row]);
                    before.* = Q.fromBase(evals[fixed_count + i][prev_row]);
                }
                for (&interaction, &before_interaction, 0..) |*value, *before, i| {
                    value.* = Q.fromBase(evals[fixed_count + main_width + i][row]);
                    before.* = Q.fromBase(evals[fixed_count + main_width + i][prev_row]);
                }
                const inputs = composeInputs(fixed, main, previous);
                try evaluator.evaluate(Q, &self.definition.arena, &inputs, work, direct);
                const lookup = try bus.interactionConstraints(self.challenges, .sorted, interactionPoint(fixed, expandedMain(main), interaction, before_interaction), self.interaction_claim, @as(u32, 1) << @intCast(self.claim.log_size));
                const range_checks = try self.range_plan.evaluateAt(work, rangeSums(interaction), rangeSums(before_interaction), fixed[trace.fixed.first], self.range_claims, self.challenges.universal_prefix.get(.range_check_8_8));
                var folded = Q.zero();
                const powers = result.random_coeff_powers;
                for (direct, 0..) |value, i| folded = folded.add(powers[powers.len - 1 - i].mul(value));
                for (lookup, 0..) |value, i| folded = folded.add(powers[powers.len - 1 - direct.len - i].mul(value));
                for (range_checks, 0..) |value, i| folded = folded.add(powers[powers.len - 1 - direct.len - lookup.len - i].mul(value));
                result.accumulate(row, folded.mulM31(inverses[row >> shift]));
            }
        }
    };
}

pub fn composeInputs(fixed: [fixed_count]Q, main: anytype, previous: anytype) [component.Layout.len]Q {
    var result: [component.Layout.len]Q = @splat(Q.zero());
    const expanded = expandedMain(main);
    @memcpy(result[0..main_count], &expanded);
    for (0..5) |i| result[component.Layout.shifted_previous + i] = previous[order.Layout.current_key + i];
    for (0..8) |i| result[component.Layout.shifted_previous + 5 + i] = previous[order.Layout.current_clock + i];
    for (0..4) |i| result[component.Layout.shifted_previous + 13 + i] = previous[component.Layout.after + i];
    result[component.Layout.active] = fixed[trace.fixed.active];
    result[component.Layout.first] = fixed[trace.fixed.first];
    result[component.Layout.last] = fixed[trace.fixed.last];
    result[component.Layout.global_first] = fixed[trace.fixed.global_first];
    result[component.Layout.global_last] = fixed[trace.fixed.global_last];
    return result;
}

pub fn interactionPoint(fixed: [fixed_count]Q, main: [main_count]Q, interaction: [interaction_count]Q, previous: [interaction_count]Q) bus.InteractionPoint {
    const active = fixed[trace.fixed.active];
    var point = bus.InteractionPoint{
        .active = active,
        .transition = @splat(Q.zero()),
        .link_emit = active.sub(fixed[trace.fixed.global_last]),
        .emitted = @splat(Q.zero()),
        .link_consume = active.sub(fixed[trace.fixed.global_first]),
        .consumed = @splat(Q.zero()),
        .initial_request = fixed[trace.fixed.global_first].add(main[order.Layout.active].mul(Q.one().sub(main[order.Layout.same]))),
        .initial = @splat(Q.zero()),
        .first = fixed[trace.fixed.first],
        .domain_last = fixed[trace.fixed.domain_last],
        .transition_column = secure(interaction, 0),
        .initial_column = secure(interaction, 4),
        .prefix_column = secure(interaction, 8),
        .previous_prefix_column = secure(previous, 8),
    };
    point.transition[0] = main[order.Layout.current_key + 4];
    @memcpy(point.transition[1..5], main[order.Layout.current_key..][0..4]);
    @memcpy(point.transition[5..13], main[order.Layout.current_clock..][0..8]);
    @memcpy(point.transition[13..17], main[order.Layout.current_value..][0..4]);
    @memcpy(point.transition[17..21], main[component.Layout.after..][0..4]);
    point.initial[0] = point.transition[0];
    @memcpy(point.initial[1..5], point.transition[1..5]);
    @memcpy(point.initial[5..9], point.transition[13..17]);
    @memcpy(point.emitted[0..8], fixed[trace.fixed.ordinal..][0..8]);
    point.emitted[8] = point.transition[0];
    @memcpy(point.emitted[9..13], point.transition[1..5]);
    @memcpy(point.emitted[13..21], point.transition[5..13]);
    @memcpy(point.emitted[21..25], point.transition[17..21]);
    @memcpy(point.consumed[0..8], fixed[trace.fixed.previous_ordinal..][0..8]);
    point.consumed[8] = main[component.Layout.linked_previous + 4];
    @memcpy(point.consumed[9..13], main[component.Layout.linked_previous..][0..4]);
    @memcpy(point.consumed[13..21], main[component.Layout.linked_previous + 5 ..][0..8]);
    @memcpy(point.consumed[21..25], main[component.Layout.linked_previous + 13 ..][0..4]);
    return point;
}
pub fn rangeSums(columns: [interaction_count]Q) [range.BATCH_COUNT]Q {
    var sums: [range.BATCH_COUNT]Q = undefined;
    for (&sums, 0..) |*sum, batch| sum.* = secure(columns, 12 + 4 * batch);
    return sums;
}
fn secure(columns: [interaction_count]Q, start: usize) Q {
    return Q.fromPartialEvals(.{ columns[start], columns[start + 1], columns[start + 2], columns[start + 3] });
}
fn filledLogs(a: std.mem.Allocator, count: usize, log_size: u32) ![]u32 {
    const values = try a.alloc(u32, count);
    @memset(values, log_size);
    return values;
}
fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingMemoryMaskPoint;
    return values[index];
}
fn pointColumns(a: std.mem.Allocator, count: usize, points: []const circle.CirclePointQM31) ![][]circle.CirclePointQM31 {
    const values = try a.alloc([]circle.CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (values[0..initialized]) |column| a.free(column);
        a.free(values);
    }
    for (values) |*column| {
        column.* = try a.dupe(circle.CirclePointQM31, points);
        initialized += 1;
    }
    return values;
}
fn freePointColumns(a: std.mem.Allocator, columns: [][]circle.CirclePointQM31) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}

pub fn expandedMain(main: anytype) [main_count]Q {
    var full: [main_count]Q = @splat(Q.zero());
    @memcpy(full[0..main.len], &main);
    if (main.len == component.Layout.linked_previous) {
        @memcpy(full[component.Layout.linked_previous..][0..5], full[order.Layout.previous_key..][0..5]);
        @memcpy(full[component.Layout.linked_previous + 5 ..][0..8], full[order.Layout.previous_clock..][0..8]);
        @memcpy(full[component.Layout.linked_previous + 13 ..][0..4], full[order.Layout.previous_value..][0..4]);
    }
    return full;
}
