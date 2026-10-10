//! Tagged four-lane affine-square chip AIR for the staged two-call profile.
//!
//! This is a real AIR component with the same nine committed state columns as
//! the one-call chip. The component's `call_id` is a constant in every
//! seven-field lookup tuple; it is never supplied by the witness. The future
//! verifier must derive that constant from the source-bound manifest. No pair proof API is
//! enabled until the two bridge AIRs, Gate compression, PCS roster, and verifier
//! reconstruction are complete.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const old = @import("repeated_step_chip.zig");
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
    if (base.len != main_width) return error.InvalidPairChipShape;
    const log_size = base[0].log_size;
    if (log_size > old.max_log_size) return error.InvalidPairChipShape;
    const rounds: u32 = @as(u32, 1) << @intCast(log_size);
    _ = try validateRounds(rounds);
    for (base) |column|
        if (column.log_size != log_size or column.values.len != rounds)
            return error.InvalidPairChipShape;
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
        if (fractions.len != 2) return error.InvalidPairChipShape;
        const step = self.base[0].values[row].toU32();
        if (step >= self.rounds) return error.InvalidPairChipIndex;
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

test "tagged pair chip AIR enforces both canonical call tags" {
    const allocator = std.testing.allocator;
    const initial = [4]M31{
        M31.fromCanonical(1), M31.fromCanonical(2),
        M31.fromCanonical(3), M31.fromCanonical(4),
    };
    const constant = M31.fromCanonical(7);
    var base = try writeBase(allocator, initial, constant, 16);
    defer base.deinit();
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    var sums: [2]QM31 = undefined;
    for (0..2) |call_id| {
        var interaction = try writeInteraction(allocator, base.columns, @intCast(call_id), z, alpha);
        defer interaction.deinit();
        sums[call_id] = interaction.claimed_sum;
        const elements = Elements.init(z, alpha);
        try std.testing.expect((try endpointSum(interaction.claimed_sum, elements, @intCast(call_id), 16, initial, base.final)).isZero());
        const component = Component{
            .log_size = 4,
            .call_id = @intCast(call_id),
            .constant = constant,
            .main_offset = 0,
            .interaction_offset = 0,
            .elements = elements,
            .claimed_sum = interaction.claimed_sum,
        };
        for (0..16) |coset_row| {
            const row = storageIndex(coset_row, 4);
            const previous_row = storageIndex((coset_row + 15) % 16, 4);
            var main: [main_width]QM31 = undefined;
            for (&main, base.columns) |*value, source| value.* = QM31.fromBase(source.values[row]);
            const first = secureAtColumns(interaction.columns[0..4], row);
            const previous = secureAtColumns(interaction.columns[4..8], previous_row);
            const current = secureAtColumns(interaction.columns[4..8], row);
            const constraints = try component.rowConstraints(main, first, previous, current);
            for (constraints) |constraint| try std.testing.expect(constraint.isZero());
        }
    }
    try std.testing.expect(!sums[0].eql(sums[1]));
    try std.testing.expectError(error.NonCanonicalCallId, writeInteraction(allocator, base.columns, 2, z, alpha));
    var bad = try writeInteraction(allocator, base.columns, 0, z, alpha);
    defer bad.deinit();
    const first_row = storageIndex(0, 4);
    const previous_row = storageIndex(15, 4);
    var main: [main_width]QM31 = undefined;
    for (&main, base.columns) |*value, source| value.* = QM31.fromBase(source.values[first_row]);
    const swapped_component = Component{
        .log_size = 4,
        .call_id = 1,
        .constant = constant,
        .main_offset = 0,
        .interaction_offset = 0,
        .elements = .init(z, alpha),
        .claimed_sum = bad.claimed_sum,
    };
    const swapped_constraints = try swapped_component.rowConstraints(
        main,
        secureAtColumns(bad.columns[0..4], first_row),
        secureAtColumns(bad.columns[4..8], previous_row),
        secureAtColumns(bad.columns[4..8], first_row),
    );
    try std.testing.expect(!swapped_constraints[4].isZero());
    @constCast(base.columns[0].values)[storageIndex(7, 4)] = M31.fromCanonical(16);
    try std.testing.expectError(error.InvalidPairChipIndex, writeInteraction(allocator, base.columns, 0, z, alpha));
}

test "tagged pair chip AIR-valid nonzero quotient agrees with verifier point" {
    const allocator = std.testing.allocator;
    const circle_poly = prover.poly.circle.poly;
    const circle_eval = prover.poly.circle.evaluation;
    const secure_poly = prover.poly.circle.secure_poly;
    const Poly = prover.air.component_prover.Poly;
    const TraceType = prover.air.component_prover.Trace;
    const initial = [4]M31{
        M31.fromCanonical(1), M31.fromCanonical(2),
        M31.fromCanonical(3), M31.fromCanonical(4),
    };
    const constant = M31.fromCanonical(7);
    var base = try writeBase(allocator, initial, constant, 16);
    defer base.deinit();
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    var interaction = try writeInteraction(allocator, base.columns, 1, z, alpha);
    defer interaction.deinit();

    const trace_log: u32 = 4;
    const eval_log: u32 = trace_log + 1;
    const trace_domain = canonic.CanonicCoset.new(trace_log).circleDomain();
    const eval_domain = canonic.CanonicCoset.new(eval_log).circleDomain();
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
        const lifted = allocator.alloc(M31, eval_domain.size()) catch |err| {
            coeffs[index].deinit(allocator);
            return err;
        };
        for (lifted, 0..) |*slot, row| {
            const circle_index = core.utils.bitReverseIndex(row, eval_log);
            const point = eval_domain.at(circle_index);
            const sampled = coeffs[index].evalAtPoint(.{
                .x = QM31.fromBase(point.x),
                .y = QM31.fromBase(point.y),
            }).toM31Array();
            if (!sampled[1].isZero() or !sampled[2].isZero() or !sampled[3].isZero())
                return error.InvalidLiftedTrace;
            slot.* = sampled[0];
        }
        eval_values[index] = lifted;
        polys[index] = .{ .log_size = eval_log, .values = lifted, .coefficients = coeffs[index] };
        ready += 1;
    }
    const empty_polys = [_]Poly{};
    var trees = [_][]const Poly{ &empty_polys, polys[0..main_width], polys[main_width..] };
    const trace = TraceType{ .polys = .{ .items = &trees } };
    const component = Component{
        .log_size = trace_log,
        .call_id = 1,
        .constant = constant,
        .main_offset = 0,
        .interaction_offset = 0,
        .elements = .init(z, alpha),
        .claimed_sum = interaction.claimed_sum,
    };
    const composition_log = component.maxConstraintLogDegreeBound();
    const mask_log = composition_log - component.asProverComponent().compositionLogSplit();
    try std.testing.expectEqual(eval_log, composition_log);
    try std.testing.expectEqual(trace_log, mask_log);
    const random = QM31.fromU32Unchecked(3, 5, 7, 11);
    var domain_accumulator = try prover.air.accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random,
        composition_log,
        component.nConstraints(),
    );
    defer domain_accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &domain_accumulator);
    var quotient_evaluation = try domain_accumulator.finalize();
    defer quotient_evaluation.deinit(allocator);
    var quotient_poly = try secure_poly.interpolateFromEvaluation(allocator, eval_domain, &quotient_evaluation);
    defer quotient_poly.deinit(allocator);

    var channel = @import("prove.zig").profiles.Blake2sM31MerkleChannel.Channel{};
    channel.mixU32s(&.{ 0x5041_4952, 0x4348_4950 });
    const point = core.circle.randomSecureFieldPoint(&channel);
    var mask_points = try component.maskPoints(allocator, point, mask_log);
    defer mask_points.deinitDeep(allocator);
    var main_values: [main_width][1]QM31 = undefined;
    var main_slices: [main_width][]QM31 = undefined;
    var interaction_values: [interaction_width][2]QM31 = undefined;
    var interaction_slices: [interaction_width][]QM31 = undefined;
    for (mask_points.items[1], 0..) |points, index| {
        for (points, 0..) |masked_point, position|
            main_values[index][position] = coeffs[index].evalAtPoint(masked_point.repeatedDouble(mask_log - trace_log));
        main_slices[index] = main_values[index][0..points.len];
    }
    for (mask_points.items[2], 0..) |points, index| {
        for (points, 0..) |masked_point, position|
            interaction_values[index][position] = coeffs[main_width + index].evalAtPoint(masked_point.repeatedDouble(mask_log - trace_log));
        interaction_slices[index] = interaction_values[index][0..points.len];
    }
    const empty_masks = [_][]QM31{};
    var mask_trees = [_][][]QM31{ &empty_masks, &main_slices, &interaction_slices };
    const masks = core.air.components.MaskValues{ .items = &mask_trees };
    var point_accumulator = PointEvaluationAccumulator.init(random);
    try component.evaluateConstraintQuotientsAtPoint(point, &masks, &point_accumulator, mask_log);
    const domain_value = quotient_poly.evalAtPoint(point);
    const point_value = point_accumulator.finalize();
    try std.testing.expect(!domain_value.isZero());
    try std.testing.expect(domain_value.eql(point_value));
}

fn secureAtColumns(columns: []const ColumnEvaluation, row: usize) QM31 {
    return QM31.fromM31(
        columns[0].values[row],
        columns[1].values[row],
        columns[2].values[row],
        columns[3].values[row],
    );
}
