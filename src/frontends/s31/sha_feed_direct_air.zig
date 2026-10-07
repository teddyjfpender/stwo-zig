//! Eight-row SHA-256 feed-forward AIR. Public mode pins initial, terminal,
//! and output words; private mode commits them in main for joined word lookup.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const sha = @import("s31_sha_provider").compression;
const equations = @import("sha_feed_direct_equations.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const Trace = prover.air.component_prover.Trace;
const DomainEvaluationAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const PointEvaluationAccumulator = core.air.accumulation.PointEvaluationAccumulator;
const Adapter = core.air.derive.ComponentAdapter(Component, prover.air.component_prover.ComponentProver, Trace, DomainEvaluationAccumulator);

pub const log_size: u32 = 3;
pub const rows: usize = equations.row_count;
pub const fixed_width: usize = 7; // Initial, terminal, output halves, then verifier-fixed row index.
pub const main_width: usize = 40; // Output bits, two carry bits, six private boundary halves.
pub const n_constraints: usize = equations.constraint_count + 2 + 6;
// The joined direct profile uses the common q2 composition split. Feed
// equations are at most quadratic, so this bound is conservative.
pub const max_constraint_log_degree: u32 = log_size + 2;

pub const Statement = struct {
    initial: sha.State,
    terminal: sha.State,
    output: sha.State,
};

fn field(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("feed AIR requires M31 or QM31");
}

fn half(comptime F: type, bits: [32]F, start: usize) F {
    var result = field(F, 0);
    for (0..16) |i| result = result.add(bits[start + i].mul(field(F, @as(u32, 1) << @intCast(i))));
    return result;
}

/// Word-bus view of one logical feed row. The caller assigns its fixed row
/// number to input address i, terminal address 2048+i, and output address
/// 24+i. Output halves are reconstructed from Boolean-constrained bits.
pub fn BusWords(comptime F: type) type {
    return struct { incoming: [2]F, terminal: [2]F, output: [2]F };
}

pub fn busWords(comptime F: type, fixed_values: [fixed_width]F, main_values: [main_width]F) BusWords(F) {
    _ = fixed_values;
    const row = mainAt(F, main_values);
    return .{
        .incoming = row.initial,
        .terminal = row.terminal,
        .output = .{ half(F, row.output_bits, 0), half(F, row.output_bits, 16) },
    };
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
    const columns = try allocator.alloc(ColumnEvaluation, width);
    errdefer allocator.free(columns);
    var ready: usize = 0;
    errdefer for (columns[0..ready]) |column| allocator.free(column.values);
    for (columns) |*column| {
        column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, rows) };
        @memset(@constCast(column.values), M31.zero());
        ready += 1;
    }
    return .{ .allocator = allocator, .values = columns };
}

fn split(value: u32) [2]M31 {
    return .{ M31.fromCanonical(value & 0xffff), M31.fromCanonical(value >> 16) };
}

/// Fixed columns are a verifier-pinned commitment to every 16-bit boundary.
pub fn writeFixed(allocator: std.mem.Allocator, statement: Statement) !Columns {
    const result = try allocateColumns(allocator, fixed_width);
    for (0..rows) |word| {
        const storage = storageIndex(word);
        const values = [_][2]M31{ split(statement.initial[word]), split(statement.terminal[word]), split(statement.output[word]) };
        for (values, 0..) |pair, group| for (pair, 0..) |limb, side| {
            @constCast(result.values[2 * group + side].values)[storage] = limb;
        };
        @constCast(result.values[6].values)[storage] = M31.fromCanonical(@intCast(word));
    }
    return result;
}

/// Fixed trace for private compression calls. It pins only the eight row
/// indices; all six boundary halves move to the committed main witness and
/// are authenticated by the word lookup closure.
pub fn writeFixedPrivate(allocator: std.mem.Allocator) !Columns {
    const result = try allocateColumns(allocator, fixed_width);
    for (0..rows) |word| @constCast(result.values[6].values)[storageIndex(word)] = M31.fromCanonical(@intCast(word));
    return result;
}

pub fn writeMain(allocator: std.mem.Allocator, statement: Statement) !Columns {
    const result = try allocateColumns(allocator, main_width);
    const witness_rows = equations.witness(statement.initial, statement.terminal);
    for (witness_rows, 0..) |row, word| {
        var actual: u32 = 0;
        for (row.output_bits, 0..) |bit, i| actual |= bit.toU32() << @intCast(i);
        if (actual != statement.output[word]) return error.InvalidShaFeedOutput;
        const storage = storageIndex(word);
        for (row.output_bits, 0..) |bit, i| @constCast(result.values[i].values)[storage] = bit;
        for (row.carry_bits, 0..) |bit, i| @constCast(result.values[32 + i].values)[storage] = bit;
        const boundary = [_][2]M31{ split(statement.initial[word]), split(statement.terminal[word]), split(statement.output[word]) };
        for (boundary, 0..) |pair, group| for (pair, 0..) |limb, side| {
            @constCast(result.values[34 + 2 * group + side].values)[storage] = limb;
        };
    }
    return result;
}

fn fixedAt(comptime F: type, values: [fixed_width]F) [3][2]F {
    return .{
        .{ values[0], values[1] },
        .{ values[2], values[3] },
        .{ values[4], values[5] },
    };
}

fn mainAt(comptime F: type, values: [main_width]F) equations.Row(F) {
    var result: equations.Row(F) = .{
        .initial = .{ values[34], values[35] },
        .terminal = .{ values[36], values[37] },
        .output_bits = undefined,
        .carry_bits = undefined,
    };
    @memcpy(&result.output_bits, values[0..32]);
    @memcpy(&result.carry_bits, values[32..34]);
    return result;
}

pub fn evaluate(comptime F: type, fixed_values: [fixed_width]F, main_values: [main_width]F, private_mode: bool) [n_constraints]F {
    const fixed = fixedAt(F, fixed_values);
    const row = mainAt(F, main_values);
    var out: [n_constraints]F = undefined;
    const local = equations.evaluate(F, row);
    @memcpy(out[0..equations.constraint_count], &local);
    out[equations.constraint_count] = half(F, row.output_bits, 0).sub(main_values[38]);
    out[equations.constraint_count + 1] = half(F, row.output_bits, 16).sub(main_values[39]);
    for (0..6) |i| out[equations.constraint_count + 2 + i] =
        if (private_mode) field(F, 0) else main_values[34 + i].sub(fixed[i / 2][i % 2]);
    return out;
}

pub fn validateCommittedTrace(fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    return validateCommittedTraceMode(fixed, main, false);
}

pub fn validateCommittedTraceMode(fixed: []const ColumnEvaluation, main: []const ColumnEvaluation, private_mode: bool) !void {
    if (fixed.len != fixed_width or main.len != main_width) return error.InvalidShaFeedTrace;
    for (0..rows) |storage| {
        var fv: [fixed_width]M31 = undefined;
        var mv: [main_width]M31 = undefined;
        for (&fv, fixed) |*slot, col| slot.* = col.values[storage];
        for (&mv, main) |*slot, col| slot.* = col.values[storage];
        for (evaluate(M31, fv, mv, private_mode)) |constraint|
            if (!constraint.isZero()) return error.InvalidShaFeedConstraint;
    }
}

pub const Component = struct {
    fixed_offset: usize = 0,
    main_offset: usize = 0,
    private_mode: bool = false,
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
    pub fn maskPoints(_: *const @This(), allocator: std.mem.Allocator, point: CirclePointQM31, max_log_degree_bound: u32) !core.air.components.MaskPoints {
        if (max_log_degree_bound < log_size) return error.InvalidShaFeedTrace;
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
        for (main) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{point});
            ready += 1;
        }
        return .initOwned(try allocator.dupe([][]CirclePointQM31, &.{ fixed, main }));
    }
    pub fn preprocessedColumnIndices(self: *const @This(), allocator: std.mem.Allocator) ![]usize {
        const indices = try allocator.alloc(usize, fixed_width);
        for (indices, 0..) |*i, n| i.* = self.fixed_offset + n;
        return indices;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *PointEvaluationAccumulator, max_log_degree_bound: u32) !void {
        if (mask.items.len < 2 or mask.items[0].len < self.fixed_offset + fixed_width or mask.items[1].len < self.main_offset + main_width or max_log_degree_bound < log_size) return error.InvalidShaFeedTrace;
        var fv: [fixed_width]QM31 = undefined;
        var mv: [main_width]QM31 = undefined;
        for (&fv, mask.items[0][self.fixed_offset..][0..fixed_width]) |*slot, col| {
            if (col.len != 1) return error.InvalidShaFeedTrace;
            slot.* = col[0];
        }
        for (&mv, mask.items[1][self.main_offset..][0..main_width]) |*slot, col| {
            if (col.len != 1) return error.InvalidShaFeedTrace;
            slot.* = col[0];
        }
        const constraints = evaluate(QM31, fv, mv, self.private_mode);
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(max_log_degree_bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 2 or trace.polys.items[0].len < self.fixed_offset + fixed_width or trace.polys.items[1].len < self.main_offset + main_width) return error.InvalidShaFeedTrace;
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
        var inverse: [1 << (max_constraint_log_degree - log_size)]M31 = undefined;
        for (&inverse, 0..) |*slot, i| slot.* = try core.constraints.cosetVanishing(M31, canonic.CanonicCoset.new(log_size).coset(), domain.at(core.utils.bitReverseIndex(i, eval_log - log_size))).inv();
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = n_constraints }});
        defer allocator.free(columns);
        const column = &columns[0];
        for (0..n) |row_index| {
            var fv: [fixed_width]QM31 = undefined;
            var mv: [main_width]QM31 = undefined;
            for (&fv, evaluations[0..fixed_width]) |*slot, source| slot.* = QM31.fromBase(source[row_index]);
            for (&mv, evaluations[fixed_width..]) |*slot, source| slot.* = QM31.fromBase(source[row_index]);
            const constraints = evaluate(QM31, fv, mv, self.private_mode);
            var sum = QM31.zero();
            for (constraints, 0..) |constraint, i| sum = sum.add(column.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            column.accumulate(row_index, sum.mulM31(inverse[row_index >> @intCast(log_size)]));
        }
    }
};

fn evaluationOnDomain(allocator: std.mem.Allocator, poly: prover.air.component_prover.Poly, eval_log: u32, n: usize, buffers: *std.ArrayList([]M31)) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidShaFeedTrace;
    if (coefficients.logSize() != log_size) return error.InvalidShaFeedTrace;
    const values = try allocator.alloc(M31, n);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}
