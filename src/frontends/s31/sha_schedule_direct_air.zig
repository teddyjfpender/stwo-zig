//! Table-free SHA-256 message schedule AIR. Public mode pins the first 16
//! words; private mode commits them in main and requires joined word lookups.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const equations = @import("sha_schedule_direct_equations.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const Trace = prover.air.component_prover.Trace;
const DomainEvaluationAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const PointEvaluationAccumulator = core.air.accumulation.PointEvaluationAccumulator;
const Adapter = core.air.derive.ComponentAdapter(Component, prover.air.component_prover.ComponentProver, Trace, DomainEvaluationAccumulator);

pub const log_size: u32 = 7;
pub const rows: usize = 1 << log_size;
pub const active_rows: usize = equations.row_count;
pub const fixed_width: usize = 5; // Input/recur selectors, pinned low/high limbs, row index.
pub const main_width: usize = 36; // 32 word bits, two low-carry and two high-carry bits.
pub const n_constraints: usize = equations.constraint_count + 4 + 2 + main_width;
pub const max_constraint_log_degree: u32 = log_size + 2;
pub const Statement = struct { first_words: [16]u32 };
pub const BoundaryMode = enum { public_input, private_input };
pub const Row = equations.Row;
const offsets = [_]isize{ 0, -2, -7, -15, -16 };

fn field(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("schedule AIR requires M31 or QM31");
}

pub fn wordHalves(comptime F: type, row: Row(F)) [2]F {
    var out = [_]F{ field(F, 0), field(F, 0) };
    for (row.word_bits, 0..) |bit, i| {
        const side: usize = i / 16;
        out[side] = out[side].add(bit.mul(field(F, @as(u32, 1) << @intCast(i % 16))));
    }
    return out;
}

pub fn flatten(comptime F: type, row: Row(F)) [main_width]F {
    var out: [main_width]F = undefined;
    @memcpy(out[0..32], &row.word_bits);
    @memcpy(out[32..34], &row.carry_low_bits);
    @memcpy(out[34..36], &row.carry_high_bits);
    return out;
}

pub fn unflatten(comptime F: type, values: [main_width]F) Row(F) {
    return .{
        .word_bits = values[0..32].*,
        .carry_low_bits = values[32..34].*,
        .carry_high_bits = values[34..36].*,
    };
}

/// Window order is current, t-2, t-7, t-15, t-16. Every predecessor is
/// opened from the same committed trace; host array indices are not trusted.
pub fn evaluateMode(comptime F: type, window: [offsets.len]Row(F), fixed: [fixed_width]F, mode: BoundaryMode) [n_constraints]F {
    var source: [equations.row_count]Row(F) = undefined;
    source[16] = window[0];
    source[14] = window[1];
    source[9] = window[2];
    source[1] = window[3];
    source[0] = window[4];
    const local = equations.evaluate(F, &source, 16);
    var out: [n_constraints]F = undefined;
    @memcpy(out[0..36], local[0..36]);
    const input = fixed[0];
    const recur = fixed[1];
    out[36] = recur.mul(local[36]);
    out[37] = recur.mul(local[37]);
    for (window[0].carry_low_bits, 0..) |bit, i| out[38 + i] = input.mul(bit);
    for (window[0].carry_high_bits, 0..) |bit, i| out[40 + i] = input.mul(bit);
    const halves = wordHalves(F, window[0]);
    out[42] = if (mode == .public_input) input.mul(halves[0].sub(fixed[2])) else field(F, 0);
    out[43] = if (mode == .public_input) input.mul(halves[1].sub(fixed[3])) else field(F, 0);
    const pad = field(F, 1).sub(input).sub(recur);
    for (flatten(F, window[0]), 0..) |value, i| out[44 + i] = pad.mul(value);
    return out;
}

pub fn evaluate(comptime F: type, window: [offsets.len]Row(F), fixed: [fixed_width]F) [n_constraints]F {
    return evaluateMode(F, window, fixed, .public_input);
}

pub fn storageIndex(logical: usize) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log_size), log_size);
}

pub const Columns = struct {
    allocator: std.mem.Allocator,
    values: []ColumnEvaluation,
    pub fn deinit(self: *@This()) void {
        for (self.values) |column| self.allocator.free(column.values);
        self.allocator.free(self.values);
    }
};

fn allocateColumns(allocator: std.mem.Allocator, width: usize) !Columns {
    const values = try allocator.alloc(ColumnEvaluation, width);
    errdefer allocator.free(values);
    var ready: usize = 0;
    errdefer for (values[0..ready]) |column| allocator.free(column.values);
    for (values) |*column| {
        column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, rows) };
        @memset(@constCast(column.values), M31.zero());
        ready += 1;
    }
    return .{ .allocator = allocator, .values = values };
}

/// Private mode fixes only the row schedule and selectors. The first 16 word
/// values remain in the Boolean main trace and require a joined caller bus.
pub fn writeFixedPrivate(allocator: std.mem.Allocator) !Columns {
    const result = try allocateColumns(allocator, fixed_width);
    for (0..rows) |t| @constCast(result.values[4].values)[storageIndex(t)] = M31.fromCanonical(@intCast(t));
    for (0..16) |t| @constCast(result.values[0].values)[storageIndex(t)] = M31.one();
    for (16..active_rows) |t| @constCast(result.values[1].values)[storageIndex(t)] = M31.one();
    return result;
}

pub fn writeFixed(allocator: std.mem.Allocator, statement: Statement) !Columns {
    const result = try writeFixedPrivate(allocator);
    for (statement.first_words, 0..) |word, t| {
        const i = storageIndex(t);
        @constCast(result.values[2].values)[i] = M31.fromCanonical(word & 0xffff);
        @constCast(result.values[3].values)[i] = M31.fromCanonical(word >> 16);
    }
    return result;
}

pub fn writeMain(allocator: std.mem.Allocator, statement: Statement) !Columns {
    const result = try allocateColumns(allocator, main_width);
    const witness = equations.witness(statement.first_words);
    for (witness, 0..) |row, t| {
        const values = flatten(M31, row);
        const i = storageIndex(t);
        for (result.values, values) |column, value| @constCast(column.values)[i] = value;
    }
    return result;
}

pub const Component = struct {
    fixed_offset: usize = 0,
    main_offset: usize = 0,
    boundary_mode: BoundaryMode = .public_input,
    pub fn asVerifierComponent(self: *const @This()) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) prover.air.component_prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn nConstraints(_: *const @This()) usize {
        return n_constraints;
    }
    pub fn maxConstraintLogDegreeBound(_: *const @This()) u32 {
        return max_constraint_log_degree;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return max_constraint_log_degree - log_size;
    }
    pub fn traceLogDegreeBounds(_: *const @This(), allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        const fixed = try allocator.alloc(u32, fixed_width);
        errdefer allocator.free(fixed);
        @memset(fixed, log_size);
        const main = try allocator.alloc(u32, main_width);
        errdefer allocator.free(main);
        @memset(main, log_size);
        return .initOwned(try allocator.dupe([]u32, &.{ fixed, main }));
    }
    pub fn maskPoints(_: *const @This(), allocator: std.mem.Allocator, point: CirclePointQM31, bound: u32) !core.air.components.MaskPoints {
        if (bound < log_size) return error.InvalidShaScheduleTrace;
        const fixed = try allocator.alloc([]CirclePointQM31, fixed_width);
        var ready: usize = 0;
        errdefer {
            for (fixed[0..ready]) |column| allocator.free(column);
            allocator.free(fixed);
        }
        for (fixed) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{point});
            ready += 1;
        }
        const main = try allocator.alloc([]CirclePointQM31, main_width);
        ready = 0;
        errdefer {
            for (main[0..ready]) |column| allocator.free(column);
            allocator.free(main);
        }
        // OODS openings use the PCS-lifted trace domain. In a joined circuit
        // proof this can be wider than the schedule's 128 committed rows.
        // Domain evaluation below uses the corresponding local row index.
        const step = canonic.CanonicCoset.new(bound).coset_value.step;
        const lifted: CirclePointQM31 = .{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) };
        var points: [offsets.len]CirclePointQM31 = undefined;
        for (offsets, &points) |offset, *slot| slot.* = point.sub(lifted.mul(@intCast(-offset)));
        for (main) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &points);
            ready += 1;
        }
        return .initOwned(try allocator.dupe([][]CirclePointQM31, &.{ fixed, main }));
    }
    pub fn preprocessedColumnIndices(self: *const @This(), allocator: std.mem.Allocator) ![]usize {
        const indices = try allocator.alloc(usize, fixed_width);
        for (indices, 0..) |*i, n| i.* = self.fixed_offset + n;
        return indices;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *PointEvaluationAccumulator, bound: u32) !void {
        if (mask.items.len < 2 or mask.items[0].len < self.fixed_offset + fixed_width or mask.items[1].len < self.main_offset + main_width or bound < log_size) return error.InvalidShaScheduleTrace;
        var fixed: [fixed_width]QM31 = undefined;
        for (&fixed, mask.items[0][self.fixed_offset..][0..fixed_width]) |*value, column| {
            if (column.len != 1) return error.InvalidShaScheduleTrace;
            value.* = column[0];
        }
        var opened: [offsets.len][main_width]QM31 = undefined;
        for (mask.items[1][self.main_offset..][0..main_width], 0..) |column, j| {
            if (column.len != offsets.len) return error.InvalidShaScheduleTrace;
            for (0..offsets.len) |k| opened[k][j] = column[k];
        }
        var window: [offsets.len]Row(QM31) = undefined;
        for (&window, opened) |*slot, values| slot.* = unflatten(QM31, values);
        const constraints = evaluateMode(QM31, window, fixed, self.boundary_mode);
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 2 or trace.polys.items[0].len < self.fixed_offset + fixed_width or trace.polys.items[1].len < self.main_offset + main_width) return error.InvalidShaScheduleTrace;
        const allocator = accumulator.allocator;
        const eval_log = max_constraint_log_degree;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        const total = fixed_width + main_width;
        const evaluations = try allocator.alloc([]const M31, total);
        defer allocator.free(evaluations);
        var buffers: std.ArrayList([]M31) = .empty;
        defer {
            for (buffers.items) |buffer| allocator.free(buffer);
            buffers.deinit(allocator);
        }
        for (trace.polys.items[0][self.fixed_offset..][0..fixed_width], evaluations[0..fixed_width]) |poly, *slot| slot.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        for (trace.polys.items[1][self.main_offset..][0..main_width], evaluations[fixed_width..]) |poly, *slot| slot.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        if (buffers.items.len != 0) {
            var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
            defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
            const view = prover.poly.twiddles.TwiddleTree([]const M31).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(buffers.items, domain, view);
        }
        var inverse: [8]M31 = undefined;
        for (&inverse, 0..) |*slot, i| slot.* = try core.constraints.cosetVanishing(M31, canonic.CanonicCoset.new(log_size).coset(), domain.at(core.utils.bitReverseIndex(i, eval_log - log_size))).inv();
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = n_constraints }});
        defer allocator.free(columns);
        const column = &columns[0];
        for (0..n) |row_index| {
            var fixed: [fixed_width]QM31 = undefined;
            for (&fixed, evaluations[0..fixed_width]) |*value, source| value.* = QM31.fromBase(source[row_index]);
            var opened: [offsets.len][main_width]QM31 = undefined;
            for (evaluations[fixed_width..], 0..) |source, j| for (offsets, 0..) |offset, k| {
                const i = core.utils.offsetBitReversedCircleDomainIndex(row_index, log_size, eval_log, offset);
                opened[k][j] = QM31.fromBase(source[i]);
            };
            var window: [offsets.len]Row(QM31) = undefined;
            for (&window, opened) |*slot, values| slot.* = unflatten(QM31, values);
            const constraints = evaluateMode(QM31, window, fixed, self.boundary_mode);
            var sum = QM31.zero();
            for (constraints, 0..) |constraint, i| sum = sum.add(column.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            column.accumulate(row_index, sum.mulM31(inverse[row_index >> @intCast(log_size)]));
        }
    }
};

fn evaluationOnDomain(allocator: std.mem.Allocator, poly: prover.air.component_prover.Poly, eval_log: u32, n: usize, buffers: *std.ArrayList([]M31)) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidShaScheduleTrace;
    if (coefficients.logSize() != log_size) return error.InvalidShaScheduleTrace;
    const values = try allocator.alloc(M31, n);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

pub fn validateCommittedTraceMode(mode: BoundaryMode, fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    if (fixed.len != fixed_width or main.len != main_width) return error.InvalidShaScheduleTrace;
    for (0..rows) |storage| {
        var fv: [fixed_width]M31 = undefined;
        for (&fv, fixed) |*slot, col| slot.* = col.values[storage];
        var window: [offsets.len]Row(M31) = undefined;
        for (offsets, &window) |offset, *slot| {
            const i = core.utils.offsetBitReversedCircleDomainIndex(storage, log_size, log_size, offset);
            var mv: [main_width]M31 = undefined;
            for (&mv, main) |*value, col| value.* = col.values[i];
            slot.* = unflatten(M31, mv);
        }
        for (evaluateMode(M31, window, fv, mode)) |constraint| if (!constraint.isZero()) return error.InvalidShaScheduleConstraint;
    }
}

pub fn validateCommittedTrace(fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    return validateCommittedTraceMode(.public_input, fixed, main);
}
