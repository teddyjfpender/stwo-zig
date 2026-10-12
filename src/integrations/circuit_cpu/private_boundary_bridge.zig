//! A private four-lane circuit/chip boundary in one LogUp closure.
//!
//! The circuit's authenticated preprocessed Gate multiplicities yield one
//! additional copy of each of eight fixed private variable addresses. This
//! component consumes those Gate tuples and supplies the opposite of the
//! repeated-step chip's two endpoint tuples. All values are committed base
//! columns before the common lookup challenges are drawn. The 16 rows each
//! carry 1/16 of every lookup; no endpoint value enters the public ABI.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const chip = @import("repeated_step_chip.zig");

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
const gate_relation = M31.fromCanonical(circuit.common.component_list.GATE_RELATION_ID);

pub const Boundary = circuit.common.direct_arithmetic.PrivateBoundary;
pub const log_size: u32 = 4;
pub const rows: usize = 1 << log_size;
pub const main_width: usize = 8;
pub const interaction_width: usize = 20;
pub const n_constraints: usize = 5;

pub const Base = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,

    pub fn deinit(self: *Base) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
};

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    claimed_sum: QM31,

    pub fn deinit(self: *Interaction) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
};

pub fn writeBase(allocator: std.mem.Allocator, values: []const QM31, boundary: Boundary) !Base {
    try boundary.validate(values.len);
    const columns = try allocator.alloc(ColumnEvaluation, main_width);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns, 0..) |*column, index| {
        const address = if (index < 4) boundary.input[index] else boundary.output[index - 4];
        const limbs = values[address].toM31Array();
        if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero())
            return error.NonCanonicalPrivateBoundary;
        column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, rows) };
        @memset(@constCast(column.values), limbs[0]);
        ready += 1;
    }
    return .{ .allocator = allocator, .columns = columns };
}

pub fn writeInteraction(
    allocator: std.mem.Allocator,
    base: []const ColumnEvaluation,
    boundary: Boundary,
    rounds: u32,
    z: QM31,
    alpha: QM31,
) !Interaction {
    if (base.len != main_width) return error.InvalidPrivateBridgeShape;
    _ = try chip.validateRounds(rounds);
    const context = FillContext{ .base = base, .boundary = boundary, .rounds = rounds, .elements = .init(z, alpha) };
    const out = try prover.air.logup_columns.build(allocator, log_size, 5, context, FillContext.fill);
    return .{ .allocator = allocator, .columns = out.columns, .claimed_sum = out.claimed_sum };
}

const FillContext = struct {
    base: []const ColumnEvaluation,
    boundary: Boundary,
    rounds: u32,
    elements: chip.Elements,

    fn fill(self: @This(), row: usize, fractions: []prover.air.logup_columns.Fraction) !void {
        if (fractions.len != 5) return error.InvalidPrivateBridgeShape;
        const inv_rows = try QM31.fromBase(M31.fromCanonical(rows)).inv();
        var words: [8]M31 = undefined;
        for (self.base, &words) |column, *word| word.* = column.values[row];
        for (0..4) |pair| {
            const a = pair * 2;
            const b = a + 1;
            const d0 = self.elements.combineBase(gateTuple(addressAt(self.boundary, a), words[a]));
            const d1 = self.elements.combineBase(gateTuple(addressAt(self.boundary, b), words[b]));
            fractions[pair] = .{
                .numerator = d0.add(d1).mul(inv_rows),
                .denominator = d0.mul(d1),
            };
        }
        const first = self.elements.combineBase(chipTuple(0, words[0..4].*));
        const last = self.elements.combineBase(chipTuple(self.rounds, words[4..8].*));
        fractions[4] = .{
            .numerator = first.sub(last).mul(inv_rows),
            .denominator = first.mul(last),
        };
    }
};

fn addressAt(boundary: Boundary, index: usize) u32 {
    return if (index < 4) boundary.input[index] else boundary.output[index - 4];
}

fn gateTuple(address: u32, value: M31) [6]M31 {
    return .{ gate_relation, M31.fromCanonical(address), value, M31.zero(), M31.zero(), M31.zero() };
}

fn chipTuple(index: u32, words: [4]M31) [6]M31 {
    return .{ M31.fromCanonical(chip.relation_id), M31.fromCanonical(index), words[0], words[1], words[2], words[3] };
}

pub const Component = struct {
    main_offset: usize,
    interaction_offset: usize,
    boundary: Boundary,
    rounds: u32,
    elements: chip.Elements,
    claimed_sum: QM31,

    pub fn asVerifierComponent(self: *const @This()) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return n_constraints;
    }

    pub fn maxConstraintLogDegreeBound(_: *const @This()) u32 {
        // A paired fraction multiplies two affine tuple denominators by a
        // running-sum column: degree three in trace polynomials.
        return log_size + 2;
    }

    pub fn traceLogDegreeBounds(_: *const @This(), allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(u32, 0);
        errdefer allocator.free(preprocessed);
        const main = try filledLogs(allocator, main_width);
        errdefer allocator.free(main);
        const interaction = try filledLogs(allocator, interaction_width);
        errdefer allocator.free(interaction);
        return .initOwned(try allocator.dupe([]u32, &.{ preprocessed, main, interaction }));
    }

    pub fn maskPoints(
        _: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core.air.components.MaskPoints {
        if (max_log_degree_bound < log_size) return error.InvalidPrivateBridgeShape;
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
        for (interaction[0 .. interaction_width - 4]) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{point});
            ready += 1;
        }
        const previous = previousRowPoint(max_log_degree_bound, point);
        for (interaction[interaction_width - 4 ..]) |*column| {
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
        if (mask.items.len < 3 or mask.items[1].len < self.main_offset + main_width or
            mask.items[2].len < self.interaction_offset + interaction_width or max_log_degree_bound < log_size)
            return error.InvalidPrivateBridgeShape;
        const main = mask.items[1][self.main_offset..][0..main_width];
        const interaction = mask.items[2][self.interaction_offset..][0..interaction_width];
        var words: [8]QM31 = undefined;
        for (main, &words) |column, *word| {
            if (column.len != 1) return error.InvalidPrivateBridgeShape;
            word.* = column[0];
        }
        var current: [5]QM31 = undefined;
        for (0..5) |i| current[i] = try sampledSecure(interaction, i * 4, if (i == 4) 1 else 0);
        const previous = try sampledSecure(interaction, 16, 0);
        const constraints = self.rowConstraints(words, current, previous);
        const denominator = core.constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - log_size),
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
            return error.InvalidPrivateBridgeShape;
        const allocator = accumulator.allocator;
        const eval_log = log_size + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        var evaluations: [main_width + interaction_width][]const M31 = undefined;
        var buffers: std.ArrayList([]M31) = .empty;
        defer {
            for (buffers.items) |buffer| allocator.free(buffer);
            buffers.deinit(allocator);
        }
        for (trace.polys.items[1][self.main_offset..][0..main_width], evaluations[0..main_width]) |poly, *values|
            values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        for (trace.polys.items[2][self.interaction_offset..][0..interaction_width], evaluations[main_width..]) |poly, *values|
            values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        if (buffers.items.len != 0) {
            var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
            defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
            const view = prover.poly.twiddles.TwiddleTree([]const M31).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(buffers.items, domain, view);
        }
        var inverse: [4]M31 = undefined;
        for (&inverse, 0..) |*slot, index|
            slot.* = try core.constraints.cosetVanishing(M31, canonic.CanonicCoset.new(log_size).coset(), domain.at(index)).inv();
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = n_constraints }});
        defer allocator.free(columns);
        const column = &columns[0];
        for (0..n) |row| {
            var words: [8]QM31 = undefined;
            for (&words, evaluations[0..8]) |*word, source| word.* = QM31.fromBase(source[row]);
            var current: [5]QM31 = undefined;
            for (0..5) |i| current[i] = secureAt(evaluations[8 + 4 * i ..][0..4], row);
            const previous_row = core.utils.previousBitReversedCircleDomainIndex(row, log_size, eval_log);
            const previous = secureAt(evaluations[8 + 16 ..][0..4], previous_row);
            const constraints = self.rowConstraints(words, current, previous);
            var combined = QM31.zero();
            for (constraints, 0..) |constraint, i|
                combined = combined.add(column.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            column.accumulate(row, combined.mulM31(inverse[row >> @intCast(log_size)]));
        }
    }

    fn rowConstraints(self: *const @This(), words: [8]QM31, current: [5]QM31, previous: QM31) [5]QM31 {
        const inv_rows = QM31.fromBase(M31.fromCanonical(rows)).inv() catch unreachable;
        var result: [5]QM31 = undefined;
        for (0..4) |pair| {
            const a = pair * 2;
            const b = a + 1;
            const d0 = self.elements.combineSecure(gateTupleSecure(addressAt(self.boundary, a), words[a]));
            const d1 = self.elements.combineSecure(gateTupleSecure(addressAt(self.boundary, b), words[b]));
            const delta = if (pair == 0) current[0] else current[pair].sub(current[pair - 1]);
            result[pair] = delta.mul(d0).mul(d1).sub(d0.add(d1).mul(inv_rows));
        }
        const first = self.elements.combineSecure(chipTupleSecure(0, words[0..4].*));
        const last = self.elements.combineSecure(chipTupleSecure(self.rounds, words[4..8].*));
        const shift = self.claimed_sum.mul(inv_rows);
        result[4] = current[4].sub(previous).sub(current[3]).add(shift)
            .mul(first).mul(last).sub(first.sub(last).mul(inv_rows));
        return result;
    }
};

fn gateTupleSecure(address: u32, value: QM31) [6]QM31 {
    return .{ QM31.fromBase(gate_relation), QM31.fromBase(M31.fromCanonical(address)), value, QM31.zero(), QM31.zero(), QM31.zero() };
}

fn chipTupleSecure(index: u32, words: [4]QM31) [6]QM31 {
    return .{ QM31.fromBase(M31.fromCanonical(chip.relation_id)), QM31.fromBase(M31.fromCanonical(index)), words[0], words[1], words[2], words[3] };
}

fn sampledSecure(columns: [][]QM31, base: usize, index: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (0..4) |i| {
        if (columns[base + i].len <= index) return error.InvalidPrivateBridgeShape;
        coordinates[i] = columns[base + i][index];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

fn evaluationOnDomain(allocator: std.mem.Allocator, poly: prover.air.component_prover.Poly, eval_log: u32, n: usize, buffers: *std.ArrayList([]M31)) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidPrivateBridgeShape;
    if (coefficients.logSize() != log_size) return error.InvalidPrivateBridgeShape;
    const values = try allocator.alloc(M31, n);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

fn filledLogs(allocator: std.mem.Allocator, n: usize) ![]u32 {
    const result = try allocator.alloc(u32, n);
    @memset(result, log_size);
    return result;
}

fn currentPointColumns(allocator: std.mem.Allocator, n: usize, point: CirclePointQM31) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, n);
    var ready: usize = 0;
    errdefer {
        for (result[0..ready]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        ready += 1;
    }
    return result;
}

fn freeMaskColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn previousRowPoint(max_log_degree_bound: u32, point: CirclePointQM31) CirclePointQM31 {
    _ = max_log_degree_bound;
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
}

fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

test "private boundary Gate and chip tuples close only for equal committed values" {
    const allocator = std.testing.allocator;
    const boundary = Boundary{ .input = .{ 7, 8, 9, 10 }, .output = .{ 11, 12, 13, 14 } };
    var values = [_]QM31{QM31.zero()} ** 15;
    const initial = [4]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    const final = try chip.direct(initial, M31.fromCanonical(7), 16);
    for (initial, 0..) |value, index| values[boundary.input[index]] = QM31.fromBase(value);
    for (final, 0..) |value, index| values[boundary.output[index]] = QM31.fromBase(value);
    var base = try writeBase(allocator, &values, boundary);
    defer base.deinit();
    var chip_base = try chip.writeBase(allocator, initial, M31.fromCanonical(7), 16);
    defer chip_base.deinit();
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    var bridge_interaction = try writeInteraction(allocator, base.columns, boundary, 16, z, alpha);
    defer bridge_interaction.deinit();
    var chip_interaction = try chip.writeInteraction(allocator, chip_base.columns, z, alpha);
    defer chip_interaction.deinit();
    const elements = chip.Elements.init(z, alpha);
    var circuit_extra = QM31.zero();
    for (boundary.input ++ boundary.output, 0..) |address, index| {
        const value = if (index < 4) initial[index] else final[index - 4];
        circuit_extra = circuit_extra.sub(try elements.combineBase(gateTuple(address, value)).inv());
    }
    try std.testing.expect(circuit_extra.add(bridge_interaction.claimed_sum).add(chip_interaction.claimed_sum).isZero());
    @constCast(base.columns[0].values)[0] = base.columns[0].values[0].add(M31.one());
    var altered = try writeInteraction(allocator, base.columns, boundary, 16, z, alpha);
    defer altered.deinit();
    try std.testing.expect(!circuit_extra.add(altered.claimed_sum).add(chip_interaction.claimed_sum).isZero());
}
