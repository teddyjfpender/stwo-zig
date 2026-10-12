//! One call's authenticated private circuit-to-tagged-chip bridge AIR.
//!
//! Eight committed endpoint columns each satisfy a cyclic row-to-row
//! equality. Five LogUp fractions consume the circuit's six-field Gate
//! yields and close the tagged seven-field chip endpoints. The verifier
//! must source this component's call plan and offsets from the trusted key.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const chip = @import("repeated_step_chip.zig");
const pair = @import("private_pair_boundary.zig");

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
pub const Boundary = pair.Call;
pub const log_size: u32 = pair.bridge_log_size;
pub const rows: usize = 1 << log_size;
pub const main_width: usize = pair.bridge_main_width;
pub const interaction_width: usize = pair.bridge_interaction_width;
pub const n_constraints: usize = pair.bridge_n_constraints;

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
    if (boundary.call_id >= pair.n_calls) return error.NonCanonicalCallId;
    _ = try chip.validateRounds(boundary.rounds);
    const columns = try allocator.alloc(ColumnEvaluation, main_width);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns, 0..) |*column, index| {
        const address = if (index < 4) boundary.input[index] else boundary.output[index - 4];
        if (address <= 2 or address >= values.len or address >= core.fields.m31.Modulus)
            return error.InvalidPairEndpoint;
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
    z: QM31,
    alpha: QM31,
) !Interaction {
    if (base.len != main_width) return error.InvalidPrivateBridgeShape;
    if (boundary.call_id >= pair.n_calls) return error.NonCanonicalCallId;
    _ = try chip.validateRounds(boundary.rounds);
    for (base) |column|
        if (column.log_size != log_size or column.values.len != rows)
            return error.InvalidPrivateBridgeShape;
    const context = FillContext{ .base = base, .boundary = boundary, .elements = .init(z, alpha) };
    const out = try prover.air.logup_columns.build(allocator, log_size, 5, context, FillContext.fill);
    return .{ .allocator = allocator, .columns = out.columns, .claimed_sum = out.claimed_sum };
}

const FillContext = struct {
    base: []const ColumnEvaluation,
    boundary: Boundary,
    elements: pair.Elements,

    fn fill(self: @This(), row: usize, fractions: []prover.air.logup_columns.Fraction) !void {
        if (fractions.len != 5) return error.InvalidPrivateBridgeShape;
        const inv_rows = try QM31.fromBase(M31.fromCanonical(rows)).inv();
        var words: [8]M31 = undefined;
        for (self.base, &words) |column, *word| word.* = column.values[row];
        for (0..4) |slot| {
            const a = slot * 2;
            const b = a + 1;
            const d0 = self.elements.combineGate(pair.gateTuple(addressAt(self.boundary, a), words[a]));
            const d1 = self.elements.combineGate(pair.gateTuple(addressAt(self.boundary, b), words[b]));
            fractions[slot] = .{
                .numerator = d0.add(d1).mul(inv_rows),
                .denominator = d0.mul(d1),
            };
        }
        const first = self.elements.combine(pair.chipTuple(self.boundary.call_id, 0, words[0..4].*));
        const last = self.elements.combine(pair.chipTuple(self.boundary.call_id, self.boundary.rounds, words[4..8].*));
        fractions[4] = .{
            .numerator = first.sub(last).mul(inv_rows),
            .denominator = first.mul(last),
        };
    }
};

fn addressAt(boundary: Boundary, index: usize) u32 {
    return if (index < 4) boundary.input[index] else boundary.output[index - 4];
}

pub const Component = struct {
    main_offset: usize,
    interaction_offset: usize,
    boundary: Boundary,
    elements: pair.Elements,
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
        const main = try currentAndNextPointColumns(allocator, main_width, point, max_log_degree_bound);
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
        var next_words: [8]QM31 = undefined;
        for (main, &words, &next_words) |column, *word, *next_word| {
            if (column.len != 2) return error.InvalidPrivateBridgeShape;
            word.* = column[0];
            next_word.* = column[1];
        }
        var current: [5]QM31 = undefined;
        for (0..5) |i| current[i] = try sampledSecure(interaction, i * 4, if (i == 4) 1 else 0);
        const previous = try sampledSecure(interaction, 16, 0);
        const constraints = self.rowConstraints(words, next_words, current, previous);
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
            var next_words: [8]QM31 = undefined;
            const next_row = core.utils.offsetBitReversedCircleDomainIndex(row, log_size, eval_log, 1);
            for (&words, evaluations[0..8]) |*word, source| word.* = QM31.fromBase(source[row]);
            for (&next_words, evaluations[0..8]) |*word, source| word.* = QM31.fromBase(source[next_row]);
            var current: [5]QM31 = undefined;
            for (0..5) |i| current[i] = secureAt(evaluations[8 + 4 * i ..][0..4], row);
            const previous_row = core.utils.previousBitReversedCircleDomainIndex(row, log_size, eval_log);
            const previous = secureAt(evaluations[8 + 16 ..][0..4], previous_row);
            const constraints = self.rowConstraints(words, next_words, current, previous);
            var combined = QM31.zero();
            for (constraints, 0..) |constraint, i|
                combined = combined.add(column.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            column.accumulate(row, combined.mulM31(inverse[row >> @intCast(log_size)]));
        }
    }

    fn rowConstraints(self: *const @This(), words: [8]QM31, next_words: [8]QM31, current: [5]QM31, previous: QM31) [n_constraints]QM31 {
        const inv_rows = QM31.fromBase(M31.fromCanonical(rows)).inv() catch unreachable;
        var result: [n_constraints]QM31 = undefined;
        for (0..8) |lane| result[lane] = words[lane].sub(next_words[lane]);
        for (0..4) |slot| {
            const a = slot * 2;
            const b = a + 1;
            const d0 = self.elements.combineGateSecure(gateTupleSecure(addressAt(self.boundary, a), words[a]));
            const d1 = self.elements.combineGateSecure(gateTupleSecure(addressAt(self.boundary, b), words[b]));
            const delta = if (slot == 0) current[0] else current[slot].sub(current[slot - 1]);
            result[8 + slot] = delta.mul(d0).mul(d1).sub(d0.add(d1).mul(inv_rows));
        }
        const first = self.elements.combineSecure(chipTupleSecure(self.boundary.call_id, 0, words[0..4].*));
        const last = self.elements.combineSecure(chipTupleSecure(self.boundary.call_id, self.boundary.rounds, words[4..8].*));
        const shift = self.claimed_sum.mul(inv_rows);
        result[12] = current[4].sub(previous).sub(current[3]).add(shift)
            .mul(first).mul(last).sub(first.sub(last).mul(inv_rows));
        return result;
    }
};

fn gateTupleSecure(address: u32, value: QM31) [6]QM31 {
    return .{ QM31.fromBase(M31.fromCanonical(@import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID)), QM31.fromBase(M31.fromCanonical(address)), value, QM31.zero(), QM31.zero(), QM31.zero() };
}

fn chipTupleSecure(call_id: u32, index: u32, words: [4]QM31) [7]QM31 {
    return .{ QM31.fromBase(M31.fromCanonical(pair.relation_id)), QM31.fromBase(M31.fromCanonical(call_id)), QM31.fromBase(M31.fromCanonical(index)), words[0], words[1], words[2], words[3] };
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

fn currentAndNextPointColumns(allocator: std.mem.Allocator, n: usize, point: CirclePointQM31, max_log_degree_bound: u32) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, n);
    var ready: usize = 0;
    errdefer {
        for (result[0..ready]) |column| allocator.free(column);
        allocator.free(result);
    }
    const next = nextRowPoint(max_log_degree_bound, point);
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{ point, next });
        ready += 1;
    }
    return result;
}

fn freeMaskColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn previousRowPoint(max_log_degree_bound: u32, point: CirclePointQM31) CirclePointQM31 {
    // Openings are on the lifted mask domain. Its step doubles to one
    // logical trace-row step before the trace polynomial is evaluated.
    const step = canonic.CanonicCoset.new(max_log_degree_bound).coset_value.step;
    return point.sub(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
}

fn nextRowPoint(max_log_degree_bound: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(max_log_degree_bound).coset_value.step;
    return point.add(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
}

fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

test "tagged pair bridge AIR closes repeated endpoints and constrains every row" {
    const allocator = std.testing.allocator;
    const tagged_chip = @import("tagged_pair_chip.zig");
    const call = Boundary{
        .call_id = 1,
        .rounds = 16,
        .constant = M31.fromCanonical(7),
        .input = .{ 7, 7, 9, 10 },
        .output = .{ 11, 11, 13, 14 },
    };
    var values = [_]QM31{QM31.zero()} ** 15;
    const initial = [4]M31{ M31.fromCanonical(1), M31.fromCanonical(1), M31.fromCanonical(3), M31.fromCanonical(4) };
    const final = try chip.direct(initial, call.constant, call.rounds);
    for (initial, 0..) |value, lane| values[call.input[lane]] = QM31.fromBase(value);
    for (final, 0..) |value, lane| values[call.output[lane]] = QM31.fromBase(value);
    var base = try writeBase(allocator, &values, call);
    defer base.deinit();
    var chip_base = try tagged_chip.writeBase(allocator, initial, call.constant, call.rounds);
    defer chip_base.deinit();
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    var interaction = try writeInteraction(allocator, base.columns, call, z, alpha);
    defer interaction.deinit();
    var chip_interaction = try tagged_chip.writeInteraction(allocator, chip_base.columns, call.call_id, z, alpha);
    defer chip_interaction.deinit();
    const elements = pair.Elements.init(z, alpha);
    var circuit_extra = QM31.zero();
    for (call.input ++ call.output) |address| {
        const value = values[address].toM31Array()[0];
        circuit_extra = circuit_extra.sub(try elements.combineGate(pair.gateTuple(address, value)).inv());
    }
    try std.testing.expect(circuit_extra.add(interaction.claimed_sum).add(chip_interaction.claimed_sum).isZero());
    var swapped_chip = try tagged_chip.writeInteraction(allocator, chip_base.columns, 0, z, alpha);
    defer swapped_chip.deinit();
    try std.testing.expect(!circuit_extra.add(interaction.claimed_sum).add(swapped_chip.claimed_sum).isZero());
    const component = Component{
        .main_offset = 0,
        .interaction_offset = 0,
        .boundary = call,
        .elements = elements,
        .claimed_sum = interaction.claimed_sum,
    };
    for (0..rows) |logical_row| {
        const row = chip.storageIndex(logical_row, log_size);
        const previous_row = chip.storageIndex((logical_row + rows - 1) % rows, log_size);
        const next_row = chip.storageIndex((logical_row + 1) % rows, log_size);
        var words: [8]QM31 = undefined;
        var next_words: [8]QM31 = undefined;
        for (&words, base.columns) |*word, source| word.* = QM31.fromBase(source.values[row]);
        for (&next_words, base.columns) |*word, source| word.* = QM31.fromBase(source.values[next_row]);
        var current: [5]QM31 = undefined;
        for (0..5) |slot| current[slot] = secureAtColumns(interaction.columns[4 * slot ..][0..4], row);
        const previous = secureAtColumns(interaction.columns[16..20], previous_row);
        const constraints = component.rowConstraints(words, next_words, current, previous);
        for (constraints) |constraint| try std.testing.expect(constraint.isZero());
    }
    @constCast(base.columns[0].values)[chip.storageIndex(5, log_size)] = M31.fromCanonical(2);
    const row = chip.storageIndex(4, log_size);
    const next_row = chip.storageIndex(5, log_size);
    var words: [8]QM31 = undefined;
    var next_words: [8]QM31 = undefined;
    for (&words, base.columns) |*word, source| word.* = QM31.fromBase(source.values[row]);
    for (&next_words, base.columns) |*word, source| word.* = QM31.fromBase(source.values[next_row]);
    const dummy = [_]QM31{QM31.zero()} ** 5;
    const constraints = component.rowConstraints(words, next_words, dummy, QM31.zero());
    try std.testing.expect(!constraints[0].isZero());
}

fn secureAtColumns(columns: []const ColumnEvaluation, row: usize) QM31 {
    return QM31.fromM31(
        columns[0].values[row],
        columns[1].values[row],
        columns[2].values[row],
        columns[3].values[row],
    );
}

test "tagged pair bridge row-varying quotient agrees with verifier point" {
    const allocator = std.testing.allocator;
    const circle_poly = prover.poly.circle.poly;
    const circle_eval = prover.poly.circle.evaluation;
    const Poly = prover.air.component_prover.Poly;
    const TraceType = prover.air.component_prover.Trace;
    const call = Boundary{
        .call_id = 0,
        .rounds = 16,
        .constant = M31.fromCanonical(3),
        .input = .{ 3, 4, 5, 6 },
        .output = .{ 7, 8, 9, 10 },
    };
    const initial = [4]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    const final = try chip.direct(initial, call.constant, call.rounds);
    var values = [_]QM31{QM31.zero()} ** 11;
    for (initial, 0..) |value, lane| values[call.input[lane]] = QM31.fromBase(value);
    for (final, 0..) |value, lane| values[call.output[lane]] = QM31.fromBase(value);
    var base = try writeBase(allocator, &values, call);
    defer base.deinit();
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    var interaction = try writeInteraction(allocator, base.columns, call, z, alpha);
    defer interaction.deinit();
    // This adversarial witness violates the row-to-row endpoint constraint.
    // Compare the rational quotient at the *same off-trace domain point*;
    // interpolation across a trace-domain pole would be invalid here.
    @constCast(base.columns[0].values)[chip.storageIndex(5, log_size)] = M31.fromCanonical(99);
    const trace_domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const eval_log = log_size + 2;
    const eval_domain = canonic.CanonicCoset.new(eval_log).circleDomain();
    var twiddles = try prover.poly.twiddles.precomputeM31(allocator, eval_domain.half_coset);
    defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
    const twiddle_view = prover.poly.twiddles.TwiddleTree([]const M31).init(
        twiddles.root_coset,
        twiddles.twiddles,
        twiddles.itwiddles,
    );
    var coeffs: [main_width + interaction_width]circle_poly.CircleCoefficients = undefined;
    var eval_values: [main_width + interaction_width][]const M31 = undefined;
    var polys: [main_width + interaction_width]Poly = undefined;
    var ready: usize = 0;
    defer {
        for (0..ready) |index| {
            allocator.free(@constCast(eval_values[index]));
            coeffs[index].deinit(allocator);
        }
    }
    for (0..polys.len) |index| {
        const source = if (index < main_width) base.columns[index] else interaction.columns[index - main_width];
        coeffs[index] = try circle_poly.interpolateFromEvaluation(
            allocator,
            try circle_eval.CircleEvaluation.init(trace_domain, source.values),
        );
        const extended = coeffs[index].evaluateWithTwiddles(allocator, eval_domain, twiddle_view) catch |err| {
            coeffs[index].deinit(allocator);
            return err;
        };
        eval_values[index] = extended.values;
        polys[index] = .{ .log_size = eval_log, .values = extended.values, .coefficients = coeffs[index] };
        ready += 1;
    }
    const empty_polys = [_]Poly{};
    var trees = [_][]const Poly{ &empty_polys, polys[0..main_width], polys[main_width..] };
    const trace = TraceType{ .polys = .{ .items = &trees } };
    const component = Component{
        .main_offset = 0,
        .interaction_offset = 0,
        .boundary = call,
        .elements = .init(z, alpha),
        .claimed_sum = interaction.claimed_sum,
    };
    const composition_log = component.maxConstraintLogDegreeBound();
    const mask_log = composition_log - component.asProverComponent().compositionLogSplit();
    try std.testing.expectEqual(eval_log, composition_log);
    try std.testing.expectEqual(log_size + 1, mask_log);
    const composition_domain = canonic.CanonicCoset.new(composition_log).circleDomain();
    const random = QM31.fromU32Unchecked(3, 5, 7, 11);
    var domain_accumulator = try prover.air.accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random,
        composition_log,
        n_constraints,
    );
    defer domain_accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &domain_accumulator);
    var quotient_evaluation = try domain_accumulator.finalize();
    defer quotient_evaluation.deinit(allocator);
    const sample_row = for (0..composition_domain.size()) |row| {
        if (!quotient_evaluation.at(row).isZero()) break row;
    } else return error.MissingAdversarialResidual;
    const base_point = composition_domain.at(core.utils.bitReverseIndex(sample_row, composition_log));
    const preimage_domain = canonic.CanonicCoset.new(composition_log + 1).circleDomain();
    const preimage = for (0..preimage_domain.size()) |index| {
        const candidate = preimage_domain.at(index);
        const doubled = candidate.double();
        if (doubled.x.eql(base_point.x) and doubled.y.eql(base_point.y)) break candidate;
    } else return error.MissingCompositionPreimage;
    const point = CirclePointQM31{ .x = QM31.fromBase(preimage.x), .y = QM31.fromBase(preimage.y) };
    var mask_points = try component.maskPoints(allocator, point, mask_log);
    defer mask_points.deinitDeep(allocator);
    var main_values: [main_width][2]QM31 = undefined;
    var main_slices: [main_width][]QM31 = undefined;
    var interaction_values: [interaction_width][2]QM31 = undefined;
    var interaction_slices: [interaction_width][]QM31 = undefined;
    for (mask_points.items[1], 0..) |points, index| {
        for (points, 0..) |masked_point, position|
            main_values[index][position] = coeffs[index].evalAtPoint(masked_point.repeatedDouble(mask_log - log_size));
        main_slices[index] = main_values[index][0..points.len];
    }
    for (mask_points.items[2], 0..) |points, index| {
        for (points, 0..) |masked_point, position|
            interaction_values[index][position] = coeffs[main_width + index].evalAtPoint(masked_point.repeatedDouble(mask_log - log_size));
        interaction_slices[index] = interaction_values[index][0..points.len];
    }
    const empty_masks = [_][]QM31{};
    var mask_trees = [_][][]QM31{ &empty_masks, &main_slices, &interaction_slices };
    const masks = core.air.components.MaskValues{ .items = &mask_trees };
    var point_accumulator = PointEvaluationAccumulator.init(random);
    try component.evaluateConstraintQuotientsAtPoint(point, &masks, &point_accumulator, mask_log);
    const domain_value = quotient_evaluation.at(sample_row);
    const point_value = point_accumulator.finalize();
    try std.testing.expect(!domain_value.isZero());
    try std.testing.expect(domain_value.eql(point_value));
}
