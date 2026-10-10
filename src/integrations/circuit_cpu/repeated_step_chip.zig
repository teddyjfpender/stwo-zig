//! Four-lane indexed repeated-step AIR for S31's first hybrid proof profile.
//!
//! A row proves out[j] = in[j]^2 + constant and contributes
//! +1/(domain,index,in[0..4]) - 1/(domain,index+1,out[0..4]).
//! Public endpoint terms close the lookup. Since exactly R rows connect
//! index 0 to index R and R < M31 modulus, there is no room for a disjoint
//! cycle when tuple compression has no collision.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const ComponentProver = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const DomainEvaluationAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const PointEvaluationAccumulator = core.air.accumulation.PointEvaluationAccumulator;
const Adapter = core.air.derive.ComponentAdapter(
    Component,
    ComponentProver,
    Trace,
    DomainEvaluationAccumulator,
);

/// Distinct from every relation in the pinned eleven-component circuit AIR.
pub const relation_id: u32 = 0x53333102;
pub const main_width: usize = 9;
pub const interaction_width: usize = 8;
pub const min_log_size: u32 = 4;
pub const max_log_size: u32 = 15;
pub const profile_tag: u64 = 0x5333314859423201;

/// Domain-separate the hybrid transcript and bind the exact compiled source
/// and chip parameters before the first commitment. The v1 path never calls it.
pub fn mixProfile(channel: anytype, source_digest: [32]u8, rounds: u32, constant: M31) void {
    channel.mixU64(profile_tag);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i|
        word.* = std.mem.readInt(u32, source_digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    channel.mixU32s(&.{ rounds, constant.toU32() });
}

pub const Base = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    final: [4]M31,

    pub fn deinit(self: *Base) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }

    pub fn takeColumns(self: *Base) []ColumnEvaluation {
        const columns = self.columns;
        self.columns = &.{};
        return columns;
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

    pub fn takeColumns(self: *Interaction) []ColumnEvaluation {
        const columns = self.columns;
        self.columns = &.{};
        return columns;
    }
};

pub fn validateRounds(rounds: u32) !u32 {
    if (rounds < (@as(u32, 1) << min_log_size) or
        rounds > (@as(u32, 1) << max_log_size) or
        !std.math.isPowerOfTwo(rounds))
        return error.InvalidChipRounds;
    return std.math.log2_int(u32, rounds);
}

pub fn direct(initial: [4]M31, constant: M31, rounds: u32) ![4]M31 {
    _ = try validateRounds(rounds);
    var state = initial;
    for (0..rounds) |_| {
        for (&state) |*value| value.* = value.*.mul(value.*).add(constant);
    }
    return state;
}

/// The nine base columns are in bit-reversed circle-domain storage order.
pub fn writeBase(
    allocator: std.mem.Allocator,
    initial: [4]M31,
    constant: M31,
    rounds: u32,
) !Base {
    const log_size = try validateRounds(rounds);
    const columns = try allocator.alloc(ColumnEvaluation, main_width);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = .{
            .log_size = log_size,
            .values = try allocator.alloc(M31, rounds),
        };
        ready += 1;
    }
    var state = initial;
    for (0..rounds) |i| {
        const row = storageIndex(i, log_size);
        @constCast(columns[0].values)[row] = M31.fromU64(i);
        for (0..4) |lane| {
            @constCast(columns[1 + lane].values)[row] = state[lane];
            state[lane] = state[lane].mul(state[lane]).add(constant);
            @constCast(columns[5 + lane].values)[row] = state[lane];
        }
    }
    return .{ .allocator = allocator, .columns = columns, .final = state };
}

pub fn writeInteraction(
    allocator: std.mem.Allocator,
    base: []const ColumnEvaluation,
    z: QM31,
    alpha: QM31,
) !Interaction {
    if (base.len != main_width) return error.InvalidChipTraceShape;
    const log_size = base[0].log_size;
    _ = try validateRounds(@as(u32, 1) << @intCast(log_size));
    for (base) |column| if (column.log_size != log_size) return error.InvalidChipTraceShape;
    const context = FillContext{ .base = base, .elements = .init(z, alpha) };
    const output = try prover.air.logup_columns.build(allocator, log_size, 2, context, FillContext.fill);
    return .{
        .allocator = allocator,
        .columns = output.columns,
        .claimed_sum = output.claimed_sum,
    };
}

const FillContext = struct {
    base: []const ColumnEvaluation,
    elements: Elements,

    fn fill(self: @This(), row: usize, fractions: []prover.air.logup_columns.Fraction) !void {
        if (fractions.len != 2) return error.InvalidChipTraceShape;
        const input = inputTuple(self.base, row);
        const output = outputTuple(self.base, row);
        fractions[0] = .{ .numerator = QM31.one(), .denominator = self.elements.combineBase(input) };
        fractions[1] = .{ .numerator = QM31.one().neg(), .denominator = self.elements.combineBase(output) };
    }
};

pub const Elements = struct {
    z: QM31,
    powers: [6]QM31,

    pub fn init(z: QM31, alpha: QM31) Elements {
        var powers: [6]QM31 = undefined;
        var current = QM31.one();
        for (&powers) |*power| {
            power.* = current;
            current = current.mul(alpha);
        }
        return .{ .z = z, .powers = powers };
    }

    pub fn combineBase(self: Elements, tuple: [6]M31) QM31 {
        var total = QM31.zero();
        for (tuple, self.powers) |value, power| total = total.add(power.mulM31(value));
        return total.sub(self.z);
    }

    pub fn combineSecure(self: Elements, tuple: [6]QM31) QM31 {
        var total = QM31.zero();
        for (tuple, self.powers) |value, power| total = total.add(power.mul(value));
        return total.sub(self.z);
    }
};

pub fn endpointSum(
    claimed_sum: QM31,
    elements: Elements,
    rounds: u32,
    initial: [4]M31,
    final: [4]M31,
) !QM31 {
    _ = try validateRounds(rounds);
    const first = elements.combineBase(endpointTuple(0, initial));
    const last = elements.combineBase(endpointTuple(rounds, final));
    return claimed_sum.sub(try first.inv()).add(try last.inv());
}

fn endpointTuple(index: u32, values: [4]M31) [6]M31 {
    return .{ M31.fromCanonical(relation_id), M31.fromCanonical(index), values[0], values[1], values[2], values[3] };
}

fn inputTuple(base: []const ColumnEvaluation, row: usize) [6]M31 {
    return .{ M31.fromCanonical(relation_id), base[0].values[row], base[1].values[row], base[2].values[row], base[3].values[row], base[4].values[row] };
}

fn outputTuple(base: []const ColumnEvaluation, row: usize) [6]M31 {
    return .{ M31.fromCanonical(relation_id), base[0].values[row].add(M31.one()), base[5].values[row], base[6].values[row], base[7].values[row], base[8].values[row] };
}

pub fn storageIndex(coset_index: usize, log_size: u32) usize {
    const circle_index = core.utils.cosetIndexToCircleDomainIndex(coset_index, log_size);
    return core.utils.bitReverseIndex(circle_index, log_size);
}

fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

/// One additional component after the pinned circuit components.
pub const Component = struct {
    log_size: u32,
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
        return 6;
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
        const domain = QM31.fromBase(M31.fromCanonical(relation_id));
        const input = [6]QM31{ domain, main[0], main[1], main[2], main[3], main[4] };
        const output = [6]QM31{ domain, main[0].add(QM31.one()), main[5], main[6], main[7], main[8] };
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

test "indexed chip witness and endpoint LogUp balance" {
    const allocator = std.testing.allocator;
    const initial = [4]M31{
        M31.fromCanonical(1), M31.fromCanonical(2),
        M31.fromCanonical(3), M31.fromCanonical(4),
    };
    const constant = M31.fromCanonical(7);
    var base = try writeBase(allocator, initial, constant, 16);
    defer base.deinit();
    const final = try direct(initial, constant, 16);
    try std.testing.expectEqual(final, base.final);
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    var interaction = try writeInteraction(allocator, base.columns, z, alpha);
    defer interaction.deinit();
    const closure = try endpointSum(interaction.claimed_sum, .init(z, alpha), 16, initial, final);
    try std.testing.expect(closure.isZero());
    const component = Component{
        .log_size = 4,
        .constant = constant,
        .main_offset = 0,
        .interaction_offset = 0,
        .elements = .init(z, alpha),
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

fn secureAtColumns(columns: []const ColumnEvaluation, row: usize) QM31 {
    return QM31.fromM31(
        columns[0].values[row],
        columns[1].values[row],
        columns[2].values[row],
        columns[3].values[row],
    );
}
