//! Program-only LogUp quotient over original PCS-committed precompile callers.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const circle = core.circle;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const prover_component = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const logup = @import("../air/logup.zig");
const slots = @import("block_v5_program_extension_slots_v1.zig");
const source = @import("block_v5_program_extension_source_v1.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const MAX_MAIN = @max(sha.PHYSICAL_MAIN_COLUMN_COUNT + 4, @max(signer.Layout.main_columns + 2, keccak.Layout.main_columns + 2));
const universal = @import("../recursion/air/universal_challenges.zig");
const relation = @import("../air/lang/relation.zig");

pub const Projection = enum { program, state };
pub const Component = struct {
    projection: Projection = .program,
    slot: slots.Slot,
    fixed_logs: []const u32,
    main_logs: []const u32,
    root_owner: bool,
    fixed_open_mask: ?[]const bool = null,
    main_open_mask: ?[]const bool = null,
    interaction_offset: usize,
    interaction_logs: []const u32,
    claim: Q,
    relations: *const universal.UniversalRelations,

    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, prover_component.ComponentProver, prover_component.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn init(self: Self) !Self {
        const width = self.slot.main_columns;
        if (self.slot.log_size == 0 or self.slot.log_size > 24 or self.slot.main_offset + width > self.main_logs.len or
            self.interaction_offset + 4 > self.interaction_logs.len) return error.InvalidProgramRequestComponent;
        try slots.validate(self.slot, self.fixed_logs, self.main_logs);
        for (self.interaction_logs[self.interaction_offset..][0..4]) |log| if (log != self.slot.log_size) return error.InvalidProgramRequestComponent;
        try self.relations.validate();
        return self;
    }
    pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Self) usize {
        return 1;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.slot.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Self) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
        if (index != 0) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !components.TraceLogDegreeBounds {
        const fixed = try a.dupe(u32, if (self.root_owner) self.fixed_logs else &.{});
        errdefer a.free(fixed);
        const main = try a.dupe(u32, if (self.root_owner) self.main_logs else &.{});
        errdefer a.free(main);
        const interaction = try a.dupe(u32, &([_]u32{self.slot.log_size} ** 4));
        errdefer a.free(interaction);
        return components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: circle.CirclePointQM31, max_log: u32) !components.MaskPoints {
        if (max_log < self.slot.log_size) return error.InvalidProgramRequestMask;
        const fixed = try pointColumns(a, if (self.root_owner) self.fixed_logs.len else 0, &.{});
        errdefer freePoints(a, fixed);
        const main = try pointColumns(a, if (self.root_owner) self.main_logs.len else 0, &.{});
        errdefer freePoints(a, main);
        if (self.root_owner) {
            if (self.fixed_open_mask) |mask| {
                if (mask.len != fixed.len) return error.InvalidProgramRequestMask;
                for (fixed, mask) |*column, open| if (open) {
                    a.free(column.*);
                    column.* = try a.dupe(circle.CirclePointQM31, &.{point});
                };
            } else if (self.slot.fixed_selector_offset) |offset| {
                a.free(fixed[offset]);
                fixed[offset] = try a.dupe(circle.CirclePointQM31, &.{point});
            }
            if (self.main_open_mask) |mask| {
                if (mask.len != main.len) return error.InvalidProgramRequestMask;
                for (main, mask) |*column, open| if (open) {
                    a.free(column.*);
                    column.* = try a.dupe(circle.CirclePointQM31, &.{point});
                };
            } else for (main[self.slot.main_offset..][0..self.slot.main_columns]) |*column| {
                a.free(column.*);
                column.* = try a.dupe(circle.CirclePointQM31, &.{point});
            }
        }
        const interaction = try pointColumns(a, 4, &.{ point, logup.prevRowPoint(max_log, point) });
        errdefer freePoints(a, interaction);
        return components.MaskPoints.initOwned(try a.dupe([][]circle.CirclePointQM31, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        if (self.slot.fixed_selector_offset) |offset| return a.dupe(usize, &.{offset});
        return a.alloc(usize, 0);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: circle.CirclePointQM31, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        const width = self.slot.main_columns;
        if (mask.items.len < 3 or mask.items[1].len < self.slot.main_offset + width or
            mask.items[2].len < self.interaction_offset + 4) return error.InvalidProgramRequestMask;
        var fixed: [1]Q = undefined;
        const fixed_values: []const Q = if (self.slot.fixed_selector_offset) |offset| blk: {
            if (mask.items[0].len <= offset) return error.InvalidProgramRequestMask;
            fixed[0] = try pointAt(mask.items[0][offset], 0);
            break :blk &fixed;
        } else &.{};
        var main: [MAX_MAIN]Q = undefined;
        for (main[0..width], 0..) |*value, i| value.* = try pointAt(mask.items[1][self.slot.main_offset + i], 0);
        var current: [4]Q = undefined;
        var previous: [4]Q = undefined;
        for (&current, &previous, 0..) |*value, *prior, i| {
            value.* = try pointAt(mask.items[2][self.interaction_offset + i], 0);
            prior.* = try pointAt(mask.items[2][self.interaction_offset + i], 1);
        }
        const equation = try self.residual(fixed_values, main[0..width], current, previous);
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.slot.log_size).coset(), point.repeatedDouble(max_log - self.slot.log_size)).inv();
        accumulator.accumulate(equation.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const prover_component.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3) return error.InvalidProgramRequestTrees;
        const trees = trace.polys.items;
        const width = self.slot.main_columns;
        if (trees[1].len < self.slot.main_offset + width or trees[2].len < self.interaction_offset + 4) return error.InvalidProgramRequestColumns;
        if (self.slot.fixed_selector_offset) |offset| if (trees[0].len <= offset)
            return error.InvalidProgramRequestColumns;
        const a = accumulator.allocator;
        const eval_log = self.slot.log_size + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const eval_size = domain.size();
        const fixed_count: usize = @intFromBool(self.slot.fixed_selector_offset != null);
        const count = fixed_count + width + 4;
        const polys = try a.alloc(prover_component.Poly, count);
        defer a.free(polys);
        if (self.slot.fixed_selector_offset) |offset| polys[0] = trees[0][offset];
        for (0..width) |i| polys[fixed_count + i] = trees[1][self.slot.main_offset + i];
        for (0..4) |i| polys[fixed_count + width + i] = trees[2][self.interaction_offset + i];
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(poly.log_size != eval_log);
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        const values = try a.alloc([]const M, count);
        defer a.free(values);
        for (polys, values) |poly, *out| out.* = try @import("block_v5_program_request_component_v1.zig").domainValues(a, poly, self.slot.log_size, eval_log, eval_size, owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        var inverses: [4]M = undefined;
        const trace_coset = canonic.CanonicCoset.new(self.slot.log_size).coset();
        for (&inverses, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M, trace_coset, domain.at(core.utils.bitReverseIndex(i, 2))).inv();
        const output = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = 1 }});
        defer a.free(output);
        var result = output[0];
        const shift: std.math.Log2Int(usize) = @intCast(self.slot.log_size);
        for (0..eval_size) |row| {
            const prev_row = core.utils.previousBitReversedCircleDomainIndex(row, self.slot.log_size, eval_log);
            var fixed: [1]Q = undefined;
            if (fixed_count == 1) fixed[0] = Q.fromBase(values[0][row]);
            var main: [MAX_MAIN]Q = undefined;
            for (0..width) |i| main[i] = Q.fromBase(values[fixed_count + i][row]);
            var current: [4]Q = undefined;
            var previous: [4]Q = undefined;
            for (0..4) |i| {
                current[i] = Q.fromBase(values[fixed_count + width + i][row]);
                previous[i] = Q.fromBase(values[fixed_count + width + i][prev_row]);
            }
            const equation = try self.residual(fixed[0..fixed_count], main[0..width], current, previous);
            result.accumulate(row, result.random_coeff_powers[result.random_coeff_powers.len - 1].mul(equation).mulM31(inverses[row >> shift]));
        }
    }
    fn residual(self: *const Self, fixed: []const Q, main: []const Q, current: [4]Q, previous: [4]Q) !Q {
        return @import("block_v5_caller_fused_algebra_v1.zig").programResidual(Q, self.projection == .state, self.slot, fixed, main, current, previous, try self.claim.divM31(M.fromCanonical(@as(u32, 1) << @intCast(self.slot.log_size))), self.relations);
    }
};

fn pointAt(values: []const Q, index: usize) !Q {
    if (index >= values.len) return error.MissingProgramRequestPoint;
    return values[index];
}
fn pointColumns(a: std.mem.Allocator, count: usize, points: []const circle.CirclePointQM31) ![][]circle.CirclePointQM31 {
    const result = try a.alloc([]circle.CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| a.free(column);
        a.free(result);
    }
    for (result) |*column| {
        column.* = try a.dupe(circle.CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}
fn freePoints(a: std.mem.Allocator, columns: [][]circle.CirclePointQM31) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}
