//! Exact V3 gap AIR plus three range16 requests, borrowing six authenticated
//! native cells. Only three new MAIN columns and one LogUp plane are owned.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("block_v7_memory_relations_v1.zig");
const K = @import("block_v8_ram_clock_v3_kernel.zig");
const Q = R.Q;
const C = core.air.components;
const CP = engine.air.component_prover;
const DA = engine.air.accumulation.DomainEvaluationAccumulator;
const Point = core.circle.CirclePointQM31;
pub const native_columns = [6]usize{ 0, 23, 7, 39, 40, 41 };
pub fn term(comptime S: type, relation: R.Relation(S, 1), active: S, aux: [3]S) R.Term(S) {
    var denominators: [3]S = undefined;
    for (&denominators, aux) |*d, value| d.* = relation.combineSecure(.{value});
    return .{ .left = denominators[0].mul(denominators[1]).mul(denominators[2]), .wl = active.neg().mul(denominators[1].mul(denominators[2]).add(denominators[0].mul(denominators[2])).add(denominators[0].mul(denominators[1]))) };
}
pub fn equations(comptime S: type, relation: R.Relation(S, 1), active: S, main: [9]S, current: [4]S, previous: [4]S, normalized: S) [7]S {
    const store = main[3].add(main[4]).add(main[5]);
    const predecessor = main[1].add(store.mul(main[2].sub(main[1])));
    return K.constraints(S, active, main[0].mul(R.base(S, 4)).sub(S.one()), predecessor, main[6..9].*) ++
        R.interactionConstraints(S, 1, .{term(S, relation, active, main[6..9].*)}, current, previous, .{normalized});
}
pub const Spec = struct {
    pub const FIXED_COUNT = 1;
    pub const MAIN_COUNT = 9;
    pub const INTERACTION_COUNT = 4;
    pub const PREVIOUS_MAIN_MASK: [9]bool = @splat(false);
    pub const CONSTRAINT_COUNT = 7;
    pub const DEGREE = 4;
    pub const EXPANSION_BITS = 2;
    relation: R.Relation(Q, 1),
    sum: Q,
    pub const Domain = struct {
        relation: R.Relation(Q, 1),
        packed_relation: R.Relation(R.P, 1),
        normalized: Q,
        pub fn evaluate(self: Domain, fixed: [1]Q, row: [9]Q, prior: [9]Q, current: [4]Q, previous: [4]Q, size: u32) ![7]Q {
            _ = prior;
            _ = size;
            return equations(Q, self.relation, fixed[0], row, current, previous, self.normalized);
        }
        pub fn evaluatePacked(self: *const Domain, fixed: [1]R.P, row: [9]R.P, prior: [9]R.P, current: [4]R.P, previous: [4]R.P) [7]R.P {
            _ = prior;
            return equations(R.P, self.packed_relation, fixed[0], row, current, previous, R.P.splat(self.normalized));
        }
    };
    pub fn prepareDomain(self: Spec, size: u32) !Domain {
        var packed_relation: R.Relation(R.P, 1) = .{ .z = R.P.splat(self.relation.z), .powers = .{R.P.splat(self.relation.powers[0])} };
        _ = &packed_relation;
        return .{ .relation = self.relation, .packed_relation = packed_relation, .normalized = (try R.normalize(1, .{self.sum}, size))[0] };
    }
    pub fn evaluate(self: Spec, fixed: [1]Q, row: [9]Q, prior: [9]Q, current: [4]Q, previous: [4]Q, size: u32) ![7]Q {
        return (try self.prepareDomain(size)).evaluate(fixed, row, prior, current, previous, size);
    }
};
const View = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
pub const Component = struct {
    log_size: u32,
    active_column: usize,
    main_offset: usize,
    aux_offset: usize,
    interaction_offset: usize,
    relation: R.Relation(Q, 1),
    sum: Q,
    providers: []const C.Component,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, CP.ComponentProver, CP.Trace, DA);
    fn inner(self: *const Self) View {
        return .{ .log_size = self.log_size, .spec = .{ .relation = self.relation, .sum = self.sum } };
    }
    pub fn asProverComponent(self: *const Self) CP.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) C.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return 7;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Self) u32 {
        return 2;
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        return a.dupe(usize, &.{self.active_column});
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
        var view = self.inner();
        var logs = try view.traceLogDegreeBounds(a);
        errdefer logs.deinitDeep(a);
        const main = try a.alloc(u32, 3);
        @memset(main, self.log_size);
        a.free(logs.items[1]);
        logs.items[1] = main;
        return logs;
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
        // Native/HALT handles preceding this component must supply every borrowed cell.
        var offset: usize = 0;
        var covered: usize = 0;
        for (self.providers) |provider| {
            var masks = try provider.maskPoints(a, point, max_log);
            defer masks.deinitDeep(a);
            if (masks.items.len != 3) return error.InvalidDirectRamClockMask;
            for (masks.items[1], 0..) |column, i| for (native_columns) |index| {
                if (offset + i == self.main_offset + index) {
                    if (column.len != 1 or !std.meta.eql(column[0], point)) return error.InvalidDirectRamClockMask;
                    covered += 1;
                }
            };
            offset += masks.items[1].len;
        }
        if (covered != native_columns.len) return error.InvalidDirectRamClockMask;
        var view = self.inner();
        var masks = try view.maskPoints(a, point, max_log);
        errdefer masks.deinitDeep(a);
        const main = try a.dupe([]Point, masks.items[1][6..9]);
        for (masks.items[1][0..6]) |column| a.free(column);
        a.free(masks.items[1]);
        masks.items[1] = main;
        return masks;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const C.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3 or mask.items[0].len <= self.active_column or mask.items[1].len < self.aux_offset + 3 or mask.items[2].len < self.interaction_offset + 4) return error.InvalidDirectRamClockMask;
        var main: [9][]Q = undefined;
        for (native_columns, main[0..6]) |index, *out| out.* = mask.items[1][self.main_offset + index];
        @memcpy(main[6..9], mask.items[1][self.aux_offset..][0..3]);
        var fixed = [1][]Q{mask.items[0][self.active_column]};
        var items = [3][][]Q{ &fixed, &main, mask.items[2][self.interaction_offset..][0..4] };
        const mapped = C.MaskValues{ .items = &items };
        var view = self.inner();
        try view.evaluateConstraintQuotientsAtPoint(point, &mapped, acc, max_log);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, acc: *DA) !void {
        if (trace.polys.items.len != 3 or trace.polys.items[0].len <= self.active_column or trace.polys.items[1].len < self.aux_offset + 3 or trace.polys.items[2].len < self.interaction_offset + 4) return error.InvalidDirectRamClockMask;
        var main: [9]CP.Poly = undefined;
        for (native_columns, main[0..6]) |index, *out| out.* = trace.polys.items[1][self.main_offset + index];
        @memcpy(main[6..9], trace.polys.items[1][self.aux_offset..][0..3]);
        var fixed = [1]CP.Poly{trace.polys.items[0][self.active_column]};
        var items = [3][]const CP.Poly{ &fixed, &main, trace.polys.items[2][self.interaction_offset..][0..4] };
        var mapped = trace.*;
        mapped.polys = .initOwned(&items);
        var view = self.inner();
        try view.evaluateConstraintQuotientsOnDomain(&mapped, acc);
    }
};
