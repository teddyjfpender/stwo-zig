//! Gate and direct-SHA word LogUps over the SAME committed 80-row caller main
//! columns. Eleven additional canonical fixed columns pin event metadata.
//! These claimed sums must be closed by circuit, schedule, round and feed
//! components under their matching independent challenges in one STARK.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const caller = @import("sha_caller_stream_air.zig");
const equations = @import("sha_caller_stream_equations.zig");
const word_bus = @import("sha_direct_word_bus.zig");
const gate_relation_id = @import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const Trace = prover.air.component_prover.Trace;
const DomainEvaluationAccumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const PointEvaluationAccumulator = core.air.accumulation.PointEvaluationAccumulator;
const Adapter = core.air.derive.ComponentAdapter(Component, prover.air.component_prover.ComponentProver, Trace, DomainEvaluationAccumulator);

pub const log_size: u32 = caller.log_size;
pub const rows: usize = caller.rows;
pub const fixed_width: usize = 11;
pub const gate_slots: usize = 2;
pub const word_slots: usize = 2;
pub const slots: usize = gate_slots + word_slots;
pub const interaction_width: usize = slots * 4;
pub const n_constraints: usize = slots;

const Meta = enum(usize) {
    gate_active,
    gate_address_0,
    gate_address_1,
    word_active_0,
    word_call_0,
    word_address_0,
    word_weight_0,
    word_active_1,
    word_call_1,
    word_address_1,
    word_weight_1,
};

fn field(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("caller LogUp uses M31 or QM31");
}
fn secure(comptime F: type, value: F) QM31 {
    return if (F == M31) QM31.fromBase(value) else value;
}
fn signed(weight: i8) M31 {
    return if (weight >= 0) M31.fromCanonical(@intCast(weight)) else M31.fromCanonical(@intCast(-weight)).neg();
}

fn emptyRow() equations.Row(M31) {
    return .{
        .gate_limbs = @splat(M31.zero()),
        .words = @splat(@splat(M31.zero())),
        .serialized_bits = @splat(M31.zero()),
    };
}

/// This is independent of the private witness. The verifier pins the Merkle
/// root of these columns as part of the preprocessed tree; changing even a
/// single role, call ID, Gate address or multiplicity changes that root.
pub fn metadataAt(logical: usize, config: equations.Config) [fixed_width]M31 {
    var values: [fixed_width]M31 = @splat(M31.zero());
    if (logical >= caller.active_rows) return values;
    const row = emptyRow();
    const gates = caller.gateBusEvents(M31, row, logical, config);
    if (gates[0] != null) {
        values[@intFromEnum(Meta.gate_active)] = M31.one();
        values[@intFromEnum(Meta.gate_address_0)] = M31.fromCanonical(gates[0].?.address);
        values[@intFromEnum(Meta.gate_address_1)] = M31.fromCanonical(gates[1].?.address);
    }
    const words = caller.wordBusEvents(M31, row, logical, config);
    inline for (0..word_slots) |slot| {
        if (words[slot]) |event| {
            const base: usize = if (slot == 0) @intFromEnum(Meta.word_active_0) else @intFromEnum(Meta.word_active_1);
            values[base] = M31.one();
            values[base + 1] = event.tuple[1];
            values[base + 2] = event.tuple[2];
            values[base + 3] = signed(event.weight);
        }
    }
    return values;
}

pub const Columns = struct {
    allocator: std.mem.Allocator,
    values: []ColumnEvaluation,
    pub fn deinit(self: *@This()) void {
        freeColumns(self.allocator, self.values);
    }
};

pub fn writeFixed(allocator: std.mem.Allocator, config: equations.Config) !Columns {
    try config.validate();
    const columns = try allocator.alloc(ColumnEvaluation, fixed_width);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, rows) };
        @memset(@constCast(column.values), M31.zero());
        ready += 1;
    }
    for (0..rows) |logical| {
        const metadata = metadataAt(logical, config);
        const storage = caller.storageIndex(logical);
        for (columns, metadata) |column, value| @constCast(column.values)[storage] = value;
    }
    return .{ .allocator = allocator, .values = columns };
}

fn validateColumns(fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    if (fixed.len != fixed_width or main.len != caller.main_width) return error.InvalidShaCallerBusTrace;
    for (fixed) |column| if (column.log_size != log_size or column.values.len != rows) return error.InvalidShaCallerBusTrace;
    for (main) |column| if (column.log_size != log_size or column.values.len != rows) return error.InvalidShaCallerBusTrace;
}

fn terms(comptime F: type, metadata: [fixed_width]F, main: equations.Row(F), slot: usize, gate_elements: word_bus.Elements, word_elements: word_bus.Elements) prover.air.logup_columns.Fraction {
    const one = QM31.one();
    if (slot < gate_slots) {
        const active = secure(F, metadata[@intFromEnum(Meta.gate_active)]);
        const tuple: [6]F = .{
            field(F, gate_relation_id),
            metadata[@intFromEnum(Meta.gate_address_0) + slot],
            main.gate_limbs[slot],
            field(F, 0),
            field(F, 0),
            field(F, 0),
        };
        const raw = gate_elements.denominator(F, tuple);
        return .{ .numerator = active, .denominator = one.add(active.mul(raw.sub(one))) };
    }
    const index = slot - gate_slots;
    const base = if (index == 0) @intFromEnum(Meta.word_active_0) else @intFromEnum(Meta.word_active_1);
    const active = secure(F, metadata[base]);
    const word = main.words[index];
    const tuple: [6]F = .{
        field(F, caller.word_relation_id), metadata[base + 1], metadata[base + 2],
        word[0],                           word[1],            field(F, 0),
    };
    const raw = word_elements.denominator(F, tuple);
    return .{
        .numerator = secure(F, metadata[base + 3]),
        .denominator = one.add(active.mul(raw.sub(one))),
    };
}

const FillContext = struct {
    fixed: []const ColumnEvaluation,
    main: []const ColumnEvaluation,
    gate_elements: word_bus.Elements,
    word_elements: word_bus.Elements,
    start_slot: usize,

    fn fill(self: @This(), storage: usize, fractions: []prover.air.logup_columns.Fraction) !void {
        if (fractions.len != 2) return error.InvalidShaCallerBusTrace;
        var metadata: [fixed_width]M31 = undefined;
        var values: [caller.main_width]M31 = undefined;
        for (&metadata, self.fixed) |*value, column| value.* = column.values[storage];
        for (&values, self.main) |*value, column| value.* = column.values[storage];
        const row = caller.unflatten(M31, values);
        for (fractions, 0..) |*fraction, i| fraction.* = terms(M31, metadata, row, self.start_slot + i, self.gate_elements, self.word_elements);
    }
};

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    gate_claimed_sum: QM31,
    word_claimed_sum: QM31,
    pub fn deinit(self: *@This()) void {
        freeColumns(self.allocator, self.columns);
    }
};

pub fn writeInteraction(allocator: std.mem.Allocator, fixed: []const ColumnEvaluation, main: []const ColumnEvaluation, config: equations.Config, gate_elements: word_bus.Elements, word_elements: word_bus.Elements) !Interaction {
    try config.validate();
    try validateColumns(fixed, main);
    const gate_context = FillContext{ .fixed = fixed, .main = main, .gate_elements = gate_elements, .word_elements = word_elements, .start_slot = 0 };
    const gate = try prover.air.logup_columns.build(allocator, log_size, gate_slots, gate_context, FillContext.fill);
    errdefer freeColumns(allocator, gate.columns);
    const word_context = FillContext{ .fixed = fixed, .main = main, .gate_elements = gate_elements, .word_elements = word_elements, .start_slot = gate_slots };
    const word = try prover.air.logup_columns.build(allocator, log_size, word_slots, word_context, FillContext.fill);
    errdefer freeColumns(allocator, word.columns);
    const columns = try allocator.alloc(ColumnEvaluation, interaction_width);
    @memcpy(columns[0 .. gate_slots * 4], gate.columns);
    @memcpy(columns[gate_slots * 4 ..], word.columns);
    allocator.free(gate.columns);
    allocator.free(word.columns);
    return .{ .allocator = allocator, .columns = columns, .gate_claimed_sum = gate.claimed_sum, .word_claimed_sum = word.claimed_sum };
}

pub const Component = struct {
    config: equations.Config,
    fixed_offset: usize = 0,
    main_offset: usize = 0,
    interaction_offset: usize = 0,
    gate_elements: word_bus.Elements,
    word_elements: word_bus.Elements,
    gate_claimed_sum: QM31,
    word_claimed_sum: QM31,

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
        return caller.max_constraint_log_degree;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return caller.max_constraint_log_degree - log_size;
    }
    pub fn traceLogDegreeBounds(_: *const @This(), allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        const fixed = try logs(allocator, fixed_width);
        errdefer allocator.free(fixed);
        const main = try logs(allocator, 0);
        errdefer allocator.free(main);
        const interaction = try logs(allocator, interaction_width);
        errdefer allocator.free(interaction);
        return .initOwned(try allocator.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn maskPoints(_: *const @This(), allocator: std.mem.Allocator, point: CirclePointQM31, max_log_degree_bound: u32) !core.air.components.MaskPoints {
        if (max_log_degree_bound < log_size) return error.InvalidShaCallerBusTrace;
        const fixed = try points(allocator, fixed_width, point);
        errdefer freePoints(allocator, fixed);
        const main = try points(allocator, 0, point);
        errdefer freePoints(allocator, main);
        const interaction = try points(allocator, interaction_width, point);
        errdefer freePoints(allocator, interaction);
        const step = canonic.CanonicCoset.new(max_log_degree_bound).coset_value.step;
        const previous = point.sub(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
        for ([_]usize{ gate_slots * 4 - 4, interaction_width - 4 }) |base| for (interaction[base..][0..4]) |*column| {
            allocator.free(column.*);
            column.* = try allocator.dupe(CirclePointQM31, &.{ previous, point });
        };
        return .initOwned(try allocator.dupe([][]CirclePointQM31, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const @This(), allocator: std.mem.Allocator) ![]usize {
        const indices = try allocator.alloc(usize, fixed_width);
        for (indices, 0..) |*index, i| index.* = self.fixed_offset + i;
        return indices;
    }

    fn rowConstraints(self: *const @This(), fixed: [fixed_width]QM31, main: equations.Row(QM31), current: [slots]QM31, gate_previous: QM31, word_previous: QM31) [n_constraints]QM31 {
        const inv_rows = QM31.fromBase(M31.fromCanonical(rows)).inv() catch unreachable;
        var result: [n_constraints]QM31 = undefined;
        for (&result, 0..) |*constraint, slot| {
            const fraction = terms(QM31, fixed, main, slot, self.gate_elements, self.word_elements);
            const delta = if (slot == 0) current[0] else if (slot == 1)
                current[1].sub(current[0]).sub(gate_previous).add(self.gate_claimed_sum.mul(inv_rows))
            else if (slot == 2) current[2] else current[3].sub(current[2]).sub(word_previous).add(self.word_claimed_sum.mul(inv_rows));
            constraint.* = delta.mul(fraction.denominator).sub(fraction.numerator);
        }
        return result;
    }

    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *PointEvaluationAccumulator, max_log_degree_bound: u32) !void {
        if (mask.items.len < 3 or mask.items[0].len < self.fixed_offset + fixed_width or mask.items[1].len < self.main_offset + caller.main_width or mask.items[2].len < self.interaction_offset + interaction_width or max_log_degree_bound < log_size) return error.InvalidShaCallerBusTrace;
        var fv: [fixed_width]QM31 = undefined;
        var mv: [caller.main_width]QM31 = undefined;
        var current: [slots]QM31 = undefined;
        for (&fv, mask.items[0][self.fixed_offset..][0..fixed_width]) |*value, column| {
            if (column.len != 1) return error.InvalidShaCallerBusTrace;
            value.* = column[0];
        }
        for (&mv, mask.items[1][self.main_offset..][0..caller.main_width]) |*value, column| {
            if (column.len < 1) return error.InvalidShaCallerBusTrace;
            value.* = column[0];
        }
        const interaction = mask.items[2][self.interaction_offset..][0..interaction_width];
        for (&current, 0..) |*value, slot| value.* = try sampled(interaction, slot * 4, if (slot == 1 or slot == 3) 1 else 0);
        const gate_previous = try sampled(interaction, gate_slots * 4 - 4, 0);
        const word_previous = try sampled(interaction, interaction_width - 4, 0);
        const constraints = self.rowConstraints(fv, caller.unflatten(QM31, mv), current, gate_previous, word_previous);
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(max_log_degree_bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 3 or trace.polys.items[0].len < self.fixed_offset + fixed_width or trace.polys.items[1].len < self.main_offset + caller.main_width or trace.polys.items[2].len < self.interaction_offset + interaction_width) return error.InvalidShaCallerBusTrace;
        const allocator = accumulator.allocator;
        const eval_log = caller.max_constraint_log_degree;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        const all = try allocator.alloc([]const M31, fixed_width + caller.main_width + interaction_width);
        defer allocator.free(all);
        var buffers: std.ArrayList([]M31) = .empty;
        defer {
            for (buffers.items) |buffer| allocator.free(buffer);
            buffers.deinit(allocator);
        }
        for (trace.polys.items[0][self.fixed_offset..][0..fixed_width], all[0..fixed_width]) |poly, *values| values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        for (trace.polys.items[1][self.main_offset..][0..caller.main_width], all[fixed_width..][0..caller.main_width]) |poly, *values| values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        for (trace.polys.items[2][self.interaction_offset..][0..interaction_width], all[fixed_width + caller.main_width ..]) |poly, *values| values.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        if (buffers.items.len != 0) {
            var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
            defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
            const view = prover.poly.twiddles.TwiddleTree([]const M31).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(buffers.items, domain, view);
        }
        var inverse: [1 << (caller.max_constraint_log_degree - log_size)]M31 = undefined;
        for (&inverse, 0..) |*value, i| value.* = try core.constraints.cosetVanishing(M31, canonic.CanonicCoset.new(log_size).coset(), domain.at(core.utils.bitReverseIndex(i, caller.max_constraint_log_degree - log_size))).inv();
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = n_constraints }});
        defer allocator.free(columns);
        const quotient = &columns[0];
        for (0..n) |storage| {
            var fv: [fixed_width]QM31 = undefined;
            var mv: [caller.main_width]QM31 = undefined;
            var current: [slots]QM31 = undefined;
            for (&fv, all[0..fixed_width]) |*value, source| value.* = QM31.fromBase(source[storage]);
            for (&mv, all[fixed_width..][0..caller.main_width]) |*value, source| value.* = QM31.fromBase(source[storage]);
            for (&current, 0..) |*value, slot| value.* = secureAt(all[fixed_width + caller.main_width + 4 * slot ..][0..4], storage);
            const previous_index = core.utils.previousBitReversedCircleDomainIndex(storage, log_size, eval_log);
            const gate_previous = secureAt(all[fixed_width + caller.main_width + gate_slots * 4 - 4 ..][0..4], previous_index);
            const word_previous = secureAt(all[fixed_width + caller.main_width + interaction_width - 4 ..][0..4], previous_index);
            const constraints = self.rowConstraints(fv, caller.unflatten(QM31, mv), current, gate_previous, word_previous);
            var sum = QM31.zero();
            for (constraints, 0..) |constraint, i| sum = sum.add(quotient.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            quotient.accumulate(storage, sum.mulM31(inverse[storage >> @intCast(log_size)]));
        }
    }
};

fn logs(allocator: std.mem.Allocator, n: usize) ![]u32 {
    const result = try allocator.alloc(u32, n);
    @memset(result, log_size);
    return result;
}
fn points(allocator: std.mem.Allocator, n: usize, point: CirclePointQM31) ![][]CirclePointQM31 {
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
fn freePoints(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}
fn sampled(columns: [][]QM31, base: usize, index: usize) !QM31 {
    var values: [4]QM31 = undefined;
    for (0..4) |i| {
        if (columns[base + i].len <= index) return error.InvalidShaCallerBusTrace;
        values[i] = columns[base + i][index];
    }
    return QM31.fromPartialEvals(values);
}
fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}
fn evaluationOnDomain(allocator: std.mem.Allocator, poly: prover.air.component_prover.Poly, eval_log: u32, n: usize, buffers: *std.ArrayList([]M31)) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidShaCallerBusTrace;
    if (coefficients.logSize() != log_size) return error.InvalidShaCallerBusTrace;
    const values = try allocator.alloc(M31, n);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

pub fn validateCommittedTrace(component: *const Component, fixed: []const ColumnEvaluation, main: []const ColumnEvaluation, interaction: []const ColumnEvaluation) !void {
    try component.config.validate();
    try validateColumns(fixed, main);
    if (interaction.len != interaction_width) return error.InvalidShaCallerBusTrace;
    for (0..rows) |logical| {
        const expected = metadataAt(logical, component.config);
        const storage = caller.storageIndex(logical);
        for (fixed, expected) |column, value| if (!column.values[storage].eql(value)) return error.InvalidShaCallerBusFixed;
    }
    for (0..rows) |storage| {
        var fv: [fixed_width]QM31 = undefined;
        var mv: [caller.main_width]QM31 = undefined;
        var current: [slots]QM31 = undefined;
        for (&fv, fixed) |*value, column| value.* = QM31.fromBase(column.values[storage]);
        for (&mv, main) |*value, column| value.* = QM31.fromBase(column.values[storage]);
        for (&current, 0..) |*value, slot| value.* = secureAtColumns(interaction, slot, storage);
        const previous = core.utils.previousBitReversedCircleDomainIndex(storage, log_size, log_size);
        for (component.rowConstraints(fv, caller.unflatten(QM31, mv), current, secureAtColumns(interaction, 1, previous), secureAtColumns(interaction, 3, previous))) |constraint|
            if (!constraint.isZero()) return error.InvalidShaCallerBusConstraint;
    }
}
fn secureAtColumns(columns: []const ColumnEvaluation, slot: usize, storage: usize) QM31 {
    return QM31.fromM31(
        columns[4 * slot].values[storage],
        columns[4 * slot + 1].values[storage],
        columns[4 * slot + 2].values[storage],
        columns[4 * slot + 3].values[storage],
    );
}
