//! V4 tagged four-lane affine-square chip AIR for bounded 1..8 calls.
//! This distinct source keeps the V3 pair AIR and its source hash unchanged.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const old = @import("repeated_step_chip.zig");
const pair = @import("private_many_boundary.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const ComponentProver = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const DomainEvaluationAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const PointEvaluationAccumulator = core.air.accumulation.PointEvaluationAccumulator;
const Adapter = core.air.derive.ComponentAdapter(Component, ComponentProver, Trace, DomainEvaluationAccumulator);

pub const main_width = old.main_width;
pub const interaction_width = old.interaction_width;
pub const Base = old.Base;
pub const writeBase = old.writeBase;
pub const validateRounds = old.validateRounds;
pub const storageIndex = old.storageIndex;
pub const Elements = pair.Elements;

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    claimed_sum: QM31,

    pub fn deinit(self: *Interaction) void {
        for (self.columns) |column| self.allocator.free(column.values);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

pub fn writeInteraction(
    allocator: std.mem.Allocator,
    base: []const ColumnEvaluation,
    call_id: u32,
    z: QM31,
    alpha: QM31,
) !Interaction {
    if (call_id >= pair.n_calls) return error.NonCanonicalCallId;
    if (base.len != main_width) return error.InvalidManyChipShape;
    const log_size = base[0].log_size;
    if (log_size > old.max_log_size) return error.InvalidManyChipShape;
    const rounds: u32 = @as(u32, 1) << @intCast(log_size);
    _ = try validateRounds(rounds);
    for (base) |column|
        if (column.log_size != log_size or column.values.len != rounds)
            return error.InvalidManyChipShape;
    const context = FillContext{ .base = base, .call_id = call_id, .rounds = rounds, .elements = .init(z, alpha) };
    const output = try prover.air.logup_columns.build(allocator, log_size, 2, context, FillContext.fill);
    return .{ .allocator = allocator, .columns = output.columns, .claimed_sum = output.claimed_sum };
}

const FillContext = struct {
    base: []const ColumnEvaluation,
    call_id: u32,
    rounds: u32,
    elements: Elements,

    fn fill(self: @This(), row: usize, fractions: []prover.air.logup_columns.Fraction) !void {
        if (fractions.len != 2) return error.InvalidManyChipShape;
        const step = self.base[0].values[row].toU32();
        if (step >= self.rounds) return error.InvalidManyChipIndex;
        const input = [4]M31{
            self.base[1].values[row], self.base[2].values[row],
            self.base[3].values[row], self.base[4].values[row],
        };
        const output = [4]M31{
            self.base[5].values[row], self.base[6].values[row],
            self.base[7].values[row], self.base[8].values[row],
        };
        fractions[0] = .{ .numerator = QM31.one(), .denominator = self.elements.combine(pair.chipTuple(self.call_id, step, input)) };
        fractions[1] = .{ .numerator = QM31.one().neg(), .denominator = self.elements.combine(pair.chipTuple(self.call_id, step + 1, output)) };
    }
};

pub fn endpointSum(
    claimed_sum: QM31,
    elements: Elements,
    call_id: u32,
    rounds: u32,
    initial: [4]M31,
    final: [4]M31,
) !QM31 {
    if (call_id >= pair.n_calls) return error.NonCanonicalCallId;
    _ = try validateRounds(rounds);
    const first = elements.combine(pair.chipTuple(call_id, 0, initial));
    const last = elements.combine(pair.chipTuple(call_id, rounds, final));
    return claimed_sum.sub(try first.inv()).add(try last.inv());
}

pub const Component = struct {
    log_size: u32,
    call_id: u32,
    constant: M31,
    main_offset: usize,
    interaction_offset: usize,
    elements: Elements,
    claimed_sum: QM31,

    pub fn asVerifierComponent(self: *const @This()) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return pair.chip_n_constraints;
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(self: *const @This(), allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(allocator, main_width, self.log_size);
        errdefer allocator.free(main);
        const interaction = try filledLogs(allocator, interaction_width, self.log_size);
        errdefer allocator.free(interaction);
        return .initOwned(try allocator.dupe([]u32, &.{ preprocessed, main, interaction }));
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core.air.components.MaskPoints {
        if (self.log_size > max_log_degree_bound) return error.InvalidChipTraceShape;
        const preprocessed = try allocator.alloc([]CirclePointQM31, 0);
        errdefer allocator.free(preprocessed);
        const main = try currentPointColumns(allocator, main_width, point);
        errdefer freeMaskColumns(allocator, main);
        const interaction = try allocator.alloc([]CirclePointQM31, interaction_width);
        var ready: usize = 0;
        errdefer {
            for (interaction[0..ready]) |column| allocator.free(column);
            allocator.free(interaction);
        }
        for (interaction[0..4]) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{point});
            ready += 1;
        }
        const previous = previousRowPoint(max_log_degree_bound, point);
        for (interaction[4..8]) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{ previous, point });
            ready += 1;
        }
        return .initOwned(try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, interaction }));
    }

    pub fn preprocessedColumnIndices(_: *const @This(), allocator: std.mem.Allocator) ![]usize {
        return allocator.alloc(usize, 0);
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core.air.components.MaskValues,
        accumulator: *PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (mask.items.len < 3 or
            mask.items[1].len < self.main_offset + main_width or
            mask.items[2].len < self.interaction_offset + interaction_width or
            max_log_degree_bound < self.log_size)
            return error.InvalidChipTraceShape;
        const main = mask.items[1][self.main_offset..][0..main_width];
        const interaction = mask.items[2][self.interaction_offset..][0..interaction_width];
        for (main) |column| if (column.len != 1) return error.InvalidChipTraceShape;
        for (interaction[0..4]) |column| if (column.len != 1) return error.InvalidChipTraceShape;
        for (interaction[4..8]) |column| if (column.len != 2) return error.InvalidChipTraceShape;
        var values: [main_width]QM31 = undefined;
        for (main, &values) |column, *value| value.* = column[0];
        const first = try sampledSecure(interaction, 0, 0);
        const previous = try sampledSecure(interaction, 4, 0);
        const current = try sampledSecure(interaction, 4, 1);
        const constraints = try self.rowConstraints(values, first, previous, current);
        const fold = max_log_degree_bound - self.log_size;
        const denominator = core.constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(fold),
        );
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const Trace,
        accumulator: *DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3 or
            trace.polys.items[1].len < self.main_offset + main_width or
            trace.polys.items[2].len < self.interaction_offset + interaction_width)
            return error.InvalidChipTraceShape;
        const allocator = accumulator.allocator;
        const eval_log = self.log_size + 1;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        var evaluations: [main_width + interaction_width][]const M31 = undefined;
        var buffers: std.ArrayList([]M31) = .empty;
        defer {
            for (buffers.items) |buffer| allocator.free(buffer);
            buffers.deinit(allocator);
        }
        for (trace.polys.items[1][self.main_offset..][0..main_width], evaluations[0..main_width]) |poly, *values|
            values.* = try evaluationOnDomain(allocator, poly, self.log_size, eval_log, n, &buffers);
        for (trace.polys.items[2][self.interaction_offset..][0..interaction_width], evaluations[main_width..]) |poly, *values|
            values.* = try evaluationOnDomain(allocator, poly, self.log_size, eval_log, n, &buffers);
        if (buffers.items.len != 0) {
            var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
            defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
            const view = prover.poly.twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            );
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(buffers.items, domain, view);
        }
        const trace_coset = canonic.CanonicCoset.new(self.log_size).coset();
        const inverse = [_]M31{
            try core.constraints.cosetVanishing(M31, trace_coset, domain.at(0)).inv(),
            try core.constraints.cosetVanishing(M31, trace_coset, domain.at(1)).inv(),
        };
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = 6 }});
        defer allocator.free(columns);
        const column = &columns[0];
        if (column.random_coeff_powers.len != 6) return error.InvalidChipTraceShape;
        for (0..n) |row| {
            var values: [main_width]QM31 = undefined;
            for (&values, evaluations[0..main_width]) |*value, source| value.* = QM31.fromBase(source[row]);
            const previous_row = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
            const first = secureAt(evaluations[main_width..][0..4], row);
            const previous = secureAt(evaluations[main_width + 4 ..][0..4], previous_row);
            const current = secureAt(evaluations[main_width + 4 ..][0..4], row);
            const constraints = try self.rowConstraints(values, first, previous, current);
            var combined = QM31.zero();
            for (constraints, 0..) |constraint, i|
                combined = combined.add(column.random_coeff_powers[5 - i].mul(constraint));
            column.accumulate(row, combined.mulM31(inverse[row >> @intCast(self.log_size)]));
        }
    }

    fn rowConstraints(
        self: *const @This(),
        main: [main_width]QM31,
        first: QM31,
        previous: QM31,
        current: QM31,
    ) ![6]QM31 {
        if (self.call_id >= pair.n_calls) return error.NonCanonicalCallId;
        const domain = QM31.fromBase(M31.fromCanonical(pair.relation_id));
        const tag = QM31.fromBase(M31.fromCanonical(self.call_id));
        const input = [7]QM31{ domain, tag, main[0], main[1], main[2], main[3], main[4] };
        const output = [7]QM31{ domain, tag, main[0].add(QM31.one()), main[5], main[6], main[7], main[8] };
        const q_in = self.elements.combineSecure(input);
        const q_out = self.elements.combineSecure(output);
        var result: [6]QM31 = undefined;
        for (0..4) |lane|
            result[lane] = main[5 + lane].sub(main[1 + lane].square()).sub(QM31.fromBase(self.constant));
        result[4] = first.mul(q_in).sub(QM31.one());
        const count = M31.fromU64(@as(u64, 1) << @intCast(self.log_size));
        const shift = try self.claimed_sum.divM31(count);
        result[5] = current.sub(previous).sub(first).add(shift).mul(q_out).add(QM31.one());
        return result;
    }
};

fn sampledSecure(columns: [][]QM31, base: usize, point_index: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (0..4) |i| {
        const column = columns[base + i];
        if (column.len <= point_index) return error.InvalidChipTraceShape;
        coordinates[i] = column[point_index];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

fn evaluationOnDomain(
    allocator: std.mem.Allocator,
    poly: prover.air.component_prover.Poly,
    trace_log: u32,
    eval_log: u32,
    eval_size: usize,
    buffers: *std.ArrayList([]M31),
) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidChipTraceShape;
    if (coefficients.logSize() != trace_log) return error.InvalidChipTraceShape;
    const values = try allocator.alloc(M31, eval_size);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

fn filledLogs(allocator: std.mem.Allocator, n: usize, log_size: u32) ![]u32 {
    const logs = try allocator.alloc(u32, n);
    @memset(logs, log_size);
    return logs;
}

fn currentPointColumns(
    allocator: std.mem.Allocator,
    n: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const columns = try allocator.alloc([]CirclePointQM31, n);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        ready += 1;
    }
    return columns;
}

fn freeMaskColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn previousRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
}

test "V4 tagged chip accepts last canonical call ID and rejects overflow" {
    const a = std.testing.allocator;
    const initial = [4]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    const constant = M31.fromCanonical(7);
    var base = try writeBase(a, initial, constant, 16);
    defer base.deinit();
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    var interaction = try writeInteraction(a, base.columns, 7, z, alpha);
    defer interaction.deinit();
    try std.testing.expect((try endpointSum(interaction.claimed_sum, Elements.init(z, alpha), 7, 16, initial, base.final)).isZero());
    try std.testing.expectError(error.NonCanonicalCallId, writeInteraction(a, base.columns, 8, z, alpha));
}
