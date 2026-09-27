//! Capacity-specific adapters around the exact established fused equations.
//! Original fixed-active views alias real committed main selectors. A final
//! activity-link equation makes that source dependency explicit; it changes
//! no request numerator, access ordinal, count or bus sign.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Old = @import("block_v5_native_projection_fused_component_v2.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Opcode = @import("../runner/trace.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const Poly = engine.air.component_prover.Poly;
const Trace = engine.air.component_prover.Trace;
const Domain = engine.air.accumulation.DomainEvaluationAccumulator;
const Components = core.air.components;
const canonic = core.poly.circle.canonic;
pub const ProjectionComponent = Component(false);
pub const AccessComponent = Component(true);

fn Component(comptime access: bool) type {
    return struct {
        inner: if (access) Old.AccessComponent else Old.ProjectionComponent,
        binding: Source.Binding,
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, engine.air.component_prover.ComponentProver, Trace, Domain);
        pub fn init(self: Self) !Self {
            _ = try self.inner.init();
            const logs = self.inner.inner.main_logs;
            const fixed = self.inner.inner.fixed_logs;
            const log = self.logSize();
            if (self.binding.log_size != log or self.binding.main_index < self.binding.native_main_count or
                self.binding.main_index >= logs.len or logs[self.binding.main_index] != log or
                self.binding.fixed_active_index >= fixed.len or fixed[self.binding.fixed_active_index] != log or
                self.offset() > self.binding.native_main_count or self.width() > self.binding.native_main_count - self.offset()) return error.InvalidCapacityFusedComponent;
            if (!access) {
                if (self.inner.inner.slot.n_rows != self.binding.n_rows) return error.InvalidCapacityFusedComponent;
            }
            return self;
        }
        fn logSize(self: *const Self) u32 {
            return if (access) self.inner.inner.log_size else self.inner.inner.slot.log_size;
        }
        fn offset(self: *const Self) usize {
            return if (access) self.inner.inner.main_offset else self.inner.inner.slot.main_offset;
        }
        fn width(self: *const Self) usize {
            return if (access) Opcode.nColumnsForFamily(self.inner.inner.family) else self.inner.inner.slot.width;
        }
        fn sourceActivity(self: *const Self, main: []const Q) !Q {
            return if (access) Source.opcodeActivity(self.inner.inner.family, main) else Source.activity(self.inner.inner.slot, main);
        }
        pub fn asProverComponent(self: *const Self) engine.air.component_prover.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) Components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.inner.nConstraints() + 1;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.inner.maxConstraintLogDegreeBound();
        }
        pub fn compositionLogSplit(self: *const Self) u32 {
            return self.inner.compositionLogSplit();
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index == self.inner.nConstraints()) return 1;
            return self.inner.constraintDegreeBound(index);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Components.TraceLogDegreeBounds {
            return self.inner.traceLogDegreeBounds(a);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !Components.MaskPoints {
            // Root-owner union includes every selector and original native
            // opening. Other components borrow its absolute-index samples;
            // no duplicate fixed/main ownership or mask column is introduced.
            var result = try self.inner.maskPoints(a, point, max_log);
            errdefer result.deinitDeep(a);
            if (self.inner.inner.root_owner) {
                if (result.items[1].len <= self.binding.main_index or result.items[1][self.binding.main_index].len != 1)
                    return error.MissingCapacityFusedSelectorMask;
            }
            return result;
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return self.inner.preprocessedColumnIndices(a);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const Components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            const trees_count: usize = if (access) 4 else if (self.inner.has_access_witness) 4 else 3;
            if (mask.items.len != trees_count or mask.items[0].len > 2 * Capacity.MAX_SHARDS or mask.items[0].len <= self.binding.fixed_active_index or
                mask.items[1].len <= self.binding.main_index or mask.items[1][self.binding.main_index].len != 1 or max_log < self.logSize()) return error.InvalidCapacityFusedMasks;
            var fixed: [2 * Capacity.MAX_SHARDS][]Q = undefined;
            @memcpy(fixed[0..mask.items[0].len], mask.items[0]);
            // Current sample only: legacy fixed masks are never previous-row
            // masks, whereas activity/count companion AIR remains native-only.
            fixed[self.binding.fixed_active_index] = mask.items[1][self.binding.main_index][0..1];
            var trees: [4][][]Q = undefined;
            @memcpy(trees[0..trees_count], mask.items);
            trees[0] = fixed[0..mask.items[0].len];
            trees[1] = mask.items[1][0..self.binding.native_main_count];
            const view = Components.MaskValues{ .items = trees[0..trees_count] };
            try self.inner.evaluateConstraintQuotientsAtPoint(point, &view, accumulator, max_log);
            var main: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
            for (main[0..self.width()], mask.items[1][self.offset()..][0..self.width()]) |*value, samples| {
                if (samples.len != 1) return error.InvalidCapacityFusedMasks;
                value.* = samples[0];
            }
            const link = (try self.sourceActivity(main[0..self.width()])).sub(mask.items[1][self.binding.main_index][0]);
            const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.logSize()).coset(), point.repeatedDouble(max_log - self.logSize())).inv();
            accumulator.accumulate(link.mul(inverse));
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const Trace, accumulator: *Domain) !void {
            const trees_count: usize = if (access) 4 else if (self.inner.has_access_witness) 4 else 3;
            if (trace.polys.items.len != trees_count or trace.polys.items[0].len > 2 * Capacity.MAX_SHARDS or trace.polys.items[0].len <= self.binding.fixed_active_index or trace.polys.items[1].len <= self.binding.main_index)
                return error.InvalidCapacityFusedTrees;
            var fixed: [2 * Capacity.MAX_SHARDS]Poly = undefined;
            @memcpy(fixed[0..trace.polys.items[0].len], trace.polys.items[0]);
            fixed[self.binding.fixed_active_index] = trace.polys.items[1][self.binding.main_index];
            var trees: [4][]const Poly = undefined;
            @memcpy(trees[0..trees_count], trace.polys.items);
            trees[0] = fixed[0..trace.polys.items[0].len];
            trees[1] = trace.polys.items[1][0..self.binding.native_main_count];
            const view = Trace{ .polys = .{ .items = trees[0..trees_count] } };
            try self.inner.evaluateConstraintQuotientsOnDomain(&view, accumulator);
            try self.activityOnDomain(trace, accumulator);
        }
        fn activityOnDomain(self: *const Self, trace: *const Trace, accumulator: *Domain) !void {
            const a = accumulator.allocator;
            const log = self.logSize();
            const split = self.compositionLogSplit();
            const eval_log = log + split;
            const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
            const count = self.width() + 1;
            const owned = try a.alloc([]M, count);
            defer a.free(owned);
            var initialized: usize = 0;
            defer for (owned[0..initialized]) |values| a.free(values);
            const values = try a.alloc([]const M, count);
            defer a.free(values);
            for (values, 0..) |*value, i| {
                const index = if (i == self.width()) self.binding.main_index else self.offset() + i;
                value.* = try @import("block_v5_program_request_component_v1.zig").domainValues(a, trace.polys.items[1][index], log, eval_log, domain.size(), owned, &initialized);
            }
            if (initialized != 0) {
                var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &twiddles);
                try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned[0..initialized], domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
            }
            const inverses = try a.alloc(M, @as(usize, 1) << @intCast(split));
            defer a.free(inverses);
            for (inverses, 0..) |*inverse, i| inverse.* = try core.constraints.cosetVanishing(M, canonic.CanonicCoset.new(log).coset(), domain.at(core.utils.bitReverseIndex(i, split))).inv();
            const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = 1 }});
            defer a.free(output);
            var result = output[0];
            for (0..domain.size()) |row| {
                var main: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
                for (main[0..self.width()], values[0..self.width()]) |*value, column| value.* = Q.fromBase(column[row]);
                const link = (try self.sourceActivity(main[0..self.width()])).sub(Q.fromBase(values[self.width()][row]));
                result.accumulate(row, result.random_coeff_powers[result.random_coeff_powers.len - 1].mul(link).mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(log))]));
            }
        }
    };
}
