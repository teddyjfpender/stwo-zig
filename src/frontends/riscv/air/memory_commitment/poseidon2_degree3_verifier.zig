//! Native point-verification adapter for degree-three Poseidon equations.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const Relations = @import("../relation_challenges.zig").Relations;
const logup = @import("../logup_equations.zig");
const sampling = @import("hash_component_sampling.zig").Namespace(.{ .std = std, .M31 = M31, .QM31 = QM31, .CirclePointQM31 = Point });

pub fn Layout(comptime air: type) type {
    return struct {
        pub const N_CONSTRAINTS = air.N_CONSTRAINTS + air.N_SUMS;
        pub const ACTIVE = if (@hasDecl(air, "BINDS_ACTIVE_SELECTOR")) air.BINDS_ACTIVE_SELECTOR else true;
        pub const PP: usize = if (ACTIVE) 2 else 1;
    };
}

pub fn Component(comptime air: type) type {
    return struct {
        const Shared = Methods(@This(), air);
        log_size: u32,
        n_rows: u32,
        is_first_col_idx: usize,
        is_active_col_idx: usize,
        main_col_offset: usize,
        interaction_col_offset: usize,
        relations: *const Relations,
        claims: [air.N_SUMS]QM31,
        pub const validate = Shared.validate;
        pub const asVerifierComponent = Shared.asVerifierComponent;
        pub const nPreprocessedColumns = Shared.nPreprocessedColumns;
        pub const nConstraints = Shared.nConstraints;
        pub const maxConstraintLogDegreeBound = Shared.maxConstraintLogDegreeBound;
        pub const compositionLogSplit = Shared.compositionLogSplit;
        pub const traceLogDegreeBounds = Shared.traceLogDegreeBounds;
        pub const preprocessedColumnIndices = Shared.preprocessedColumnIndices;
        pub const maskPoints = Shared.maskPoints;
        pub const evaluateConstraintQuotientsAtPoint = Shared.evaluateConstraintQuotientsAtPoint;
        const constraints = Shared.constraints;
    };
}

pub fn Methods(comptime Self: type, comptime air: type) type {
    const Shape = Layout(air);
    const ACTIVE = Shape.ACTIVE;
    const PP = Shape.PP;
    const N_CONSTRAINTS = Shape.N_CONSTRAINTS;
    return struct {
        pub fn validate(self: *const Self) !void {
            if (self.log_size == 0 or self.log_size >= core.circle.M31_CIRCLE_LOG_ORDER - 1 or (ACTIVE and self.n_rows == 0) or @as(u64, self.n_rows) > @as(u64, 1) << @intCast(self.log_size)) return error.InvalidPoseidonNarrowComponentV1;
            _ = try std.math.add(usize, self.main_col_offset, air.N_MAIN_COLUMNS);
            _ = try std.math.add(usize, self.interaction_col_offset, air.N_INTERACTION_COLUMNS);
            if (ACTIVE and self.is_first_col_idx == self.is_active_col_idx) return error.InvalidPoseidonNarrowComponentV1;
        }

        pub fn asVerifierComponent(self: *const Self) components.Component {
            return core.air.derive.ComponentAdapter(Self, void, void, void).asVerifierComponent(self);
        }

        pub fn nPreprocessedColumns(_: *const Self) usize {
            return PP;
        }

        pub fn nConstraints(_: *const Self) usize {
            return N_CONSTRAINTS;
        }

        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }

        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }

        pub fn traceLogDegreeBounds(self: *const Self, allocator: std.mem.Allocator) !components.TraceLogDegreeBounds {
            try self.validate();
            const outer = try allocator.alloc([]u32, 3);
            var initialized: usize = 0;
            errdefer {
                for (outer[0..initialized]) |slice| allocator.free(slice);
                allocator.free(outer);
            }
            for (outer, [_]usize{ PP, air.N_MAIN_COLUMNS, air.N_INTERACTION_COLUMNS }) |*slice, count| {
                slice.* = try allocator.alloc(u32, count);
                @memset(slice.*, self.log_size);
                initialized += 1;
            }
            return components.TraceLogDegreeBounds.initOwned(outer);
        }

        pub fn preprocessedColumnIndices(self: *const Self, allocator: std.mem.Allocator) ![]usize {
            try self.validate();
            return allocator.dupe(usize, if (ACTIVE) &.{ self.is_first_col_idx, self.is_active_col_idx } else &.{self.is_first_col_idx});
        }

        pub fn maskPoints(self: *const Self, allocator: std.mem.Allocator, point: Point, max_log_degree_bound: u32) !components.MaskPoints {
            try self.validate();
            if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
            const pp = try sampling.currentPointColumns(allocator, PP, point);
            errdefer sampling.freePointColumns(allocator, pp);
            const main = try sampling.currentPointColumns(allocator, air.N_MAIN_COLUMNS, point);
            errdefer sampling.freePointColumns(allocator, main);
            const interaction = try sampling.currentAndPreviousPointColumns(allocator, air.N_INTERACTION_COLUMNS, point, logup.prevRowPoint(max_log_degree_bound, point));
            errdefer sampling.freePointColumns(allocator, interaction);
            return components.MaskPoints.initOwned(try allocator.dupe([][]Point, &.{ pp, main, interaction }));
        }

        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log_degree_bound: u32) !void {
            try self.validate();
            if (max_log_degree_bound < self.log_size or mask.items.len < 3) return error.InvalidProofShape;
            const pp = mask.items[0];
            if (pp.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or pp[self.is_first_col_idx].len != 1 or pp[self.is_active_col_idx].len != 1 or mask.items[2].len < self.interaction_col_offset + air.N_INTERACTION_COLUMNS) return error.InvalidProofShape;
            const main = try sampling.sampleMain(air.N_MAIN_COLUMNS, mask.items[1], self.main_col_offset);
            var sums: [air.N_SUMS]QM31 = undefined;
            var previous: [air.N_SUMS]QM31 = undefined;
            try sampling.sampleInteraction(air.N_SUMS, mask.items[2], self.interaction_col_offset, &sums, &previous);
            const inverse = try core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(self.log_size).coset(), point.repeatedDouble(max_log_degree_bound - self.log_size)).inv();
            for (constraints(self, main, pp[self.is_active_col_idx][0], pp[self.is_first_col_idx][0], sums, previous)) |constraint| accumulator.accumulate(constraint.mul(inverse));
        }

        pub fn constraints(self: *const Self, main: [air.N_MAIN_COLUMNS]QM31, active: QM31, first: QM31, sums: [air.N_SUMS]QM31, previous: [air.N_SUMS]QM31) [N_CONSTRAINTS]QM31 {
            var result: [N_CONSTRAINTS]QM31 = undefined;
            @memcpy(result[0..air.N_CONSTRAINTS], &(if (ACTIVE) air.evaluateGeneric(QM31, main, active) else air.evaluateGeneric(QM31, main)));
            @memcpy(result[air.N_CONSTRAINTS..], &air.interactionConstraintsGeneric(QM31, main, first, sums, previous, self.claims, self.relations));
            return result;
        }
    };
}
