//! LogUp component over the committed table-free SHA round rows.
//!
//! This component only authenticates its own signed word events. A joint
//! private proof must close its claimed sum with caller, schedule, and feed
//! claims under the same challenge after all main commitments.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const round = @import("sha_round_direct_air.zig");
const bus = @import("sha_direct_word_bus.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const Trace = prover.air.component_prover.Trace;
const DomainEvaluationAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const PointEvaluationAccumulator = core.air.accumulation.PointEvaluationAccumulator;
const Adapter = core.air.derive.ComponentAdapter(Component, prover.air.component_prover.ComponentProver, Trace, DomainEvaluationAccumulator);

pub const event_slots: usize = 9;
pub const interaction_width: usize = event_slots * 4;
pub const n_constraints: usize = event_slots;
pub const log_size: u32 = round.log_size;
pub const rows: usize = round.rows;

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    claimed_sum: QM31,

    pub fn deinit(self: *@This()) void {
        for (self.columns) |column| self.allocator.free(column.values);
        self.allocator.free(self.columns);
    }
};

fn validateBase(fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    if (fixed.len != round.fixed_width or main.len != round.main_width) return error.InvalidShaRoundWordTrace;
    for (fixed) |column| if (column.log_size != log_size or column.values.len != rows) return error.InvalidShaRoundWordTrace;
    for (main) |column| if (column.log_size != log_size or column.values.len != rows) return error.InvalidShaRoundWordTrace;
}

fn readFixed(comptime F: type, columns: []const []const F, row: usize) round.Fixed(F) {
    var values: [round.fixed_width]F = undefined;
    for (&values, columns) |*value, column| value.* = column[row];
    return round.fixedAt(F, values);
}

fn readMain(comptime F: type, columns: []const []const F, row: usize) round.Row(F) {
    var values: [round.main_width]F = undefined;
    for (&values, columns) |*value, column| value.* = column[row];
    return round.unflatten(F, values);
}

const FillContext = struct {
    fixed: []const ColumnEvaluation,
    main: []const ColumnEvaluation,
    call_id: u32,
    elements: bus.Elements,

    fn fill(self: @This(), row_index: usize, fractions: []prover.air.logup_columns.Fraction) !void {
        if (fractions.len != event_slots) return error.InvalidShaRoundWordTrace;
        var fixed_values: [round.fixed_width]M31 = undefined;
        var main_values: [round.main_width]M31 = undefined;
        for (&fixed_values, self.fixed) |*value, column| value.* = column.values[row_index];
        for (&main_values, self.main) |*value, column| value.* = column.values[row_index];
        const fixed = round.fixedAt(M31, fixed_values);
        const main = round.unflatten(M31, main_values);
        const call_id = M31.fromCanonical(self.call_id);
        for (fractions, 0..) |*fraction, slot| {
            const expr = bus.roundEventExpr(M31, main, fixed, call_id, slot);
            fraction.* = .{ .numerator = QM31.fromBase(expr.weight), .denominator = self.elements.denominator(M31, expr.values) };
        }
    }
};

pub fn writeInteraction(
    allocator: std.mem.Allocator,
    fixed: []const ColumnEvaluation,
    main: []const ColumnEvaluation,
    call_id: u32,
    elements: bus.Elements,
) !Interaction {
    try validateBase(fixed, main);
    if (call_id == 0 or call_id >= core.fields.m31.Modulus) return error.InvalidShaCallId;
    const generated = try prover.air.logup_columns.build(allocator, log_size, event_slots, FillContext{ .fixed = fixed, .main = main, .call_id = call_id, .elements = elements }, FillContext.fill);
    return .{ .allocator = allocator, .columns = generated.columns, .claimed_sum = generated.claimed_sum };
}

pub const Component = struct {
    call_id: u32,
    elements: bus.Elements,
    claimed_sum: QM31,
    fixed_offset: usize = 0,
    main_offset: usize = 0,
    interaction_offset: usize = 0,

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
        // All components in one STARK share the round AIR's composition split.
        return round.max_constraint_log_degree;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return round.max_constraint_log_degree - log_size;
    }
    pub fn traceLogDegreeBounds(_: *const @This(), allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        // The round AIR owns these shared commitments. This component owns
        // only its interaction columns, while its equations read the round
        // fixed/main openings by their global indices.
        const fixed = try logs(allocator, 0);
        errdefer allocator.free(fixed);
        const main = try logs(allocator, 0);
        errdefer allocator.free(main);
        const interaction = try logs(allocator, interaction_width);
        errdefer allocator.free(interaction);
        return .initOwned(try allocator.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn maskPoints(_: *const @This(), allocator: std.mem.Allocator, point: CirclePointQM31, max_log_degree_bound: u32) !core.air.components.MaskPoints {
        if (max_log_degree_bound < log_size) return error.InvalidShaRoundWordTrace;
        const fixed = try points(allocator, 0, point);
        errdefer freePoints(allocator, fixed);
        const main = try points(allocator, 0, point);
        errdefer freePoints(allocator, main);
        const interaction = try points(allocator, interaction_width, point);
        errdefer freePoints(allocator, interaction);
        const step = canonic.CanonicCoset.new(max_log_degree_bound).coset_value.step;
        const previous = point.sub(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
        for (interaction[interaction_width - 4 ..]) |*column| {
            allocator.free(column.*);
            column.* = try allocator.dupe(CirclePointQM31, &.{ previous, point });
        }
        return .initOwned(try allocator.dupe([][]CirclePointQM31, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(_: *const @This(), allocator: std.mem.Allocator) ![]usize {
        return allocator.alloc(usize, 0);
    }

    fn rowConstraints(self: *const @This(), fixed: round.Fixed(QM31), main: round.Row(QM31), current: [event_slots]QM31, previous: QM31) [n_constraints]QM31 {
        const inv_rows = QM31.fromBase(M31.fromCanonical(rows)).inv() catch unreachable;
        const call_id = QM31.fromBase(M31.fromCanonical(self.call_id));
        var constraints: [n_constraints]QM31 = undefined;
        for (&constraints, 0..) |*constraint, slot| {
            const expr = bus.roundEventExpr(QM31, main, fixed, call_id, slot);
            const denominator = self.elements.denominator(QM31, expr.values);
            const delta = if (slot == 0) current[0] else if (slot == event_slots - 1)
                current[slot].sub(current[slot - 1]).sub(previous).add(self.claimed_sum.mul(inv_rows))
            else
                current[slot].sub(current[slot - 1]);
            constraint.* = delta.mul(denominator).sub(expr.weight);
        }
        return constraints;
    }

    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *PointEvaluationAccumulator, max_log_degree_bound: u32) !void {
        if (mask.items.len < 3 or mask.items[0].len < self.fixed_offset + round.fixed_width or mask.items[1].len < self.main_offset + round.main_width or mask.items[2].len < self.interaction_offset + interaction_width or max_log_degree_bound < log_size) return error.InvalidShaRoundWordTrace;
        var fixed_values: [round.fixed_width]QM31 = undefined;
        var main_values: [round.main_width]QM31 = undefined;
        var current: [event_slots]QM31 = undefined;
        for (&fixed_values, mask.items[0][self.fixed_offset..][0..round.fixed_width]) |*value, column| {
            if (column.len != 1) return error.InvalidShaRoundWordTrace;
            value.* = column[0];
        }
        for (&main_values, mask.items[1][self.main_offset..][0..round.main_width]) |*value, column| {
            // The round AIR also opens the next row of each shared main
            // column. This component uses only the current opening.
            if (column.len < 1) return error.InvalidShaRoundWordTrace;
            value.* = column[0];
        }
        for (&current, 0..) |*value, slot| value.* = try sampled(mask.items[2], self.interaction_offset + slot * 4, if (slot == event_slots - 1) 1 else 0);
        const previous = try sampled(mask.items[2], self.interaction_offset + interaction_width - 4, 0);
        const constraints = self.rowConstraints(round.fixedAt(QM31, fixed_values), round.unflatten(QM31, main_values), current, previous);
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(max_log_degree_bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 3 or trace.polys.items[0].len < self.fixed_offset + round.fixed_width or trace.polys.items[1].len < self.main_offset + round.main_width or trace.polys.items[2].len < self.interaction_offset + interaction_width) return error.InvalidShaRoundWordTrace;
        const allocator = accumulator.allocator;
        const eval_log = round.max_constraint_log_degree;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        const all = try allocator.alloc([]const M31, round.fixed_width + round.main_width + interaction_width);
        defer allocator.free(all);
        var buffers: std.ArrayList([]M31) = .empty;
        defer {
            for (buffers.items) |buffer| allocator.free(buffer);
            buffers.deinit(allocator);
        }
        for (trace.polys.items[0][self.fixed_offset..][0..round.fixed_width], all[0..round.fixed_width]) |poly, *values| values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        for (trace.polys.items[1][self.main_offset..][0..round.main_width], all[round.fixed_width..][0..round.main_width]) |poly, *values| values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        for (trace.polys.items[2][self.interaction_offset..][0..interaction_width], all[round.fixed_width + round.main_width ..]) |poly, *values| values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        if (buffers.items.len != 0) {
            var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
            defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
            const view = prover.poly.twiddles.TwiddleTree([]const M31).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(buffers.items, domain, view);
        }
        var inverse: [1 << (round.max_constraint_log_degree - log_size)]M31 = undefined;
        for (&inverse, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M31, canonic.CanonicCoset.new(log_size).coset(), domain.at(core.utils.bitReverseIndex(i, round.max_constraint_log_degree - log_size))).inv();
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = n_constraints }});
        defer allocator.free(columns);
        const quotient = &columns[0];
        for (0..n) |row_index| {
            var fixed_values: [round.fixed_width]QM31 = undefined;
            var main_values: [round.main_width]QM31 = undefined;
            var current: [event_slots]QM31 = undefined;
            for (&fixed_values, all[0..round.fixed_width]) |*value, source| value.* = QM31.fromBase(source[row_index]);
            for (&main_values, all[round.fixed_width..][0..round.main_width]) |*value, source| value.* = QM31.fromBase(source[row_index]);
            for (&current, 0..) |*value, slot| value.* = secureAt(all[round.fixed_width + round.main_width + 4 * slot ..][0..4], row_index);
            const previous_index = core.utils.previousBitReversedCircleDomainIndex(row_index, log_size, eval_log);
            const previous = secureAt(all[round.fixed_width + round.main_width + interaction_width - 4 ..][0..4], previous_index);
            const constraints = self.rowConstraints(round.fixedAt(QM31, fixed_values), round.unflatten(QM31, main_values), current, previous);
            var sum = QM31.zero();
            for (constraints, 0..) |constraint, i| sum = sum.add(quotient.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            quotient.accumulate(row_index, sum.mulM31(inverse[row_index >> @intCast(log_size)]));
        }
    }
};

fn logs(allocator: std.mem.Allocator, count: usize) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, log_size);
    return result;
}
fn points(allocator: std.mem.Allocator, count: usize, point: CirclePointQM31) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return result;
}
fn freePoints(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
fn sampled(columns: [][]QM31, base: usize, index: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (0..4) |i| {
        if (columns[base + i].len <= index) return error.InvalidShaRoundWordTrace;
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
    const coefficients = poly.coefficients orelse return error.InvalidShaRoundWordTrace;
    if (coefficients.logSize() != log_size) return error.InvalidShaRoundWordTrace;
    const values = try allocator.alloc(M31, n);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

pub fn validateCommittedTrace(component: *const Component, fixed: []const ColumnEvaluation, main: []const ColumnEvaluation, interaction: []const ColumnEvaluation) !void {
    try validateBase(fixed, main);
    if (interaction.len != interaction_width) return error.InvalidShaRoundWordTrace;
    for (0..rows) |storage| {
        var fixed_values: [round.fixed_width]QM31 = undefined;
        var main_values: [round.main_width]QM31 = undefined;
        var current: [event_slots]QM31 = undefined;
        for (&fixed_values, fixed) |*value, column| value.* = QM31.fromBase(column.values[storage]);
        for (&main_values, main) |*value, column| value.* = QM31.fromBase(column.values[storage]);
        for (&current, 0..) |*value, slot| value.* = secureAtColumns(interaction[4 * slot ..][0..4], storage);
        const previous = secureAtColumns(interaction[interaction_width - 4 ..], core.utils.previousBitReversedCircleDomainIndex(storage, log_size, log_size));
        for (component.rowConstraints(round.fixedAt(QM31, fixed_values), round.unflatten(QM31, main_values), current, previous)) |constraint| if (!constraint.isZero()) return error.InvalidShaRoundWordConstraint;
    }
}
fn secureAtColumns(columns: []const ColumnEvaluation, storage: usize) QM31 {
    return QM31.fromM31(columns[0].values[storage], columns[1].values[storage], columns[2].values[storage], columns[3].values[storage]);
}

test "round word LogUp trace derives committed W, state, addresses and signed claim" {
    const allocator = std.testing.allocator;
    const sha = @import("s31_sha_provider").compression;
    var block = [_]u8{0} ** 64;
    block[0] = 0x61;
    block[1] = 0x62;
    block[2] = 0x63;
    block[3] = 0x80;
    block[63] = 24;
    const witness = sha.witness(sha.initial_state, block);
    const statement = round.Statement{ .initial = sha.initial_state, .final = witness.states[64], .schedule = witness.schedule };
    var fixed = try round.writeFixed(allocator, statement.schedule);
    defer fixed.deinit();
    var main = try round.writeMain(allocator, statement);
    defer main.deinit();
    const elements = bus.Elements.init(QM31.fromU32Unchecked(17, 3, 5, 7), QM31.fromU32Unchecked(11, 13, 19, 23));
    var interaction = try writeInteraction(allocator, fixed.values, main.values, 1, elements);
    defer interaction.deinit();
    const component = Component{ .call_id = 1, .elements = elements, .claimed_sum = interaction.claimed_sum };
    try validateCommittedTrace(&component, fixed.values, main.values, interaction.columns);
    try std.testing.expect(!interaction.claimed_sum.isZero());
    const changed = main.values[0].values[round.storageIndex(0)];
    @constCast(main.values[0].values)[round.storageIndex(0)] = M31.one().sub(changed);
    try std.testing.expectError(error.InvalidShaRoundWordConstraint, validateCommittedTrace(&component, fixed.values, main.values, interaction.columns));
}
