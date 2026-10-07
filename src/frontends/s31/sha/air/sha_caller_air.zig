//! Committed S31 SHA256d caller AIR for one private 80-byte header.
//!
//! This component is only sound in a joint proof with the circuit Gate bus
//! and the packed SHA recursion_wire bus. Its 440 main columns commit the
//! 56 circuit limbs and 96 four-byte graph boundary words before either
//! relation's lookup challenges are sampled. The 264 caller equations and
//! 152 signed lookup uses are then evaluated by both prover and verifier.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const equations = @import("sha_caller_equations.zig");
const provider = @import("s31_sha_provider");

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

pub const log_size: u32 = 4;
pub const rows: usize = 1 << log_size;
pub const main_width: usize = equations.gate_limb_count + 3 * equations.word_count_per_call * 4;
pub const event_count: usize = equations.gate_limb_count + 3 * equations.word_count_per_call;
pub const gate_batch_count: usize = equations.gate_limb_count / 2;
pub const wire_batch_count: usize = 3 * equations.word_count_per_call / 2;
pub const batch_count: usize = event_count / 2;
pub const interaction_width: usize = batch_count * 4;
pub const n_constraints: usize = equations.constraint_count + batch_count;
pub const format_version: u32 = 1;

comptime {
    if (main_width != 440 or event_count != 152 or interaction_width != 304 or n_constraints != 340)
        @compileError("SHA caller AIR geometry changed");
}

/// These are verifier-owned addresses and namespaces. The circuit compiler
/// supplies the 40 header-u16 and 16 digest-u16 addresses in that order.
pub const Config = struct {
    gate_addresses: [equations.gate_limb_count]u32,
    first_call_id: u32,

    pub fn validate(self: Config) !void {
        for (self.gate_addresses, 0..) |address, index| {
            if (address <= 2 or address >= core.fields.m31.Modulus) return error.InvalidShaGateAddress;
            for (self.gate_addresses[0..index]) |earlier|
                if (earlier == address) return error.DuplicateShaGateAddress;
        }
        if (self.first_call_id == 0 or self.first_call_id > core.fields.m31.Modulus - 3)
            return error.InvalidShaCallId;
    }
};

/// Exactly the six-field polynomial used for both circuit Gate and SHA
/// recursion_wire lookups. The two buses must use independent z/alpha draws.
pub const Elements = struct {
    z: QM31,
    powers: [6]QM31,

    pub fn init(z: QM31, alpha: QM31) Elements {
        var powers: [6]QM31 = undefined;
        var current = QM31.one();
        for (&powers) |*slot| {
            slot.* = current;
            current = current.mul(alpha);
        }
        return .{ .z = z, .powers = powers };
    }

    pub fn combineBase(self: Elements, tuple: [6]M31) QM31 {
        var result = QM31.zero();
        for (tuple, self.powers) |value, power| result = result.add(power.mulM31(value));
        return result.sub(self.z);
    }

    pub fn combineSecure(self: Elements, tuple: [6]QM31) QM31 {
        var result = QM31.zero();
        for (tuple, self.powers) |value, power| result = result.add(power.mul(value));
        return result.sub(self.z);
    }
};

pub const Base = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    pub fn deinit(self: *Base) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
    pub fn takeColumns(self: *Base) []ColumnEvaluation {
        const result = self.columns;
        self.columns = &.{};
        return result;
    }
};

pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    gate_claimed_sum: QM31,
    sha_claimed_sum: QM31,
    pub fn deinit(self: *Interaction) void {
        freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
    pub fn takeColumns(self: *Interaction) []ColumnEvaluation {
        const result = self.columns;
        self.columns = &.{};
        return result;
    }
};

pub fn semanticDigest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@embedFile("sha_caller_air.zig"));
    hash.update(@embedFile("sha_caller_equations.zig"));
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

pub fn flatten(comptime F: type, row: equations.Row(F)) [main_width]F {
    var result: [main_width]F = undefined;
    var at: usize = 0;
    for (row.limbs) |value| {
        result[at] = value;
        at += 1;
    }
    for (row.calls) |call| {
        for (call.state) |word| for (word) |value| {
            result[at] = value;
            at += 1;
        };
        for (call.block) |word| for (word) |value| {
            result[at] = value;
            at += 1;
        };
        for (call.output) |word| for (word) |value| {
            result[at] = value;
            at += 1;
        };
    }
    std.debug.assert(at == main_width);
    return result;
}

pub fn unflatten(comptime F: type, values: [main_width]F) equations.Row(F) {
    var row: equations.Row(F) = undefined;
    var at: usize = 0;
    for (&row.limbs) |*value| {
        value.* = values[at];
        at += 1;
    }
    for (&row.calls) |*call| {
        for (&call.state) |*word| for (word) |*value| {
            value.* = values[at];
            at += 1;
        };
        for (&call.block) |*word| for (word) |*value| {
            value.* = values[at];
            at += 1;
        };
        for (&call.output) |*word| for (word) |*value| {
            value.* = values[at];
            at += 1;
        };
    }
    std.debug.assert(at == main_width);
    return row;
}

/// Writes a constant logical caller row over the minimum 16-row circle trace.
/// No host-side equation validation is trusted: invalid rows remain committed
/// and are rejected by the AIR after the challenge draw.
pub fn writeBase(allocator: std.mem.Allocator, row: equations.Row(M31)) !Base {
    const values = flatten(M31, row);
    const columns = try allocator.alloc(ColumnEvaluation, main_width);
    var ready: usize = 0;
    errdefer {
        for (columns[0..ready]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns, values) |*column, value| {
        column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, rows) };
        @memset(@constCast(column.values), value);
        ready += 1;
    }
    return .{ .allocator = allocator, .columns = columns };
}

pub fn writeInteraction(
    allocator: std.mem.Allocator,
    base: []const ColumnEvaluation,
    config: Config,
    gate_elements: Elements,
    wire_elements: Elements,
) !Interaction {
    try config.validate();
    try validateBase(base);
    const gate_context = FillContext{ .base = base, .config = config, .gate = gate_elements, .wire = wire_elements, .start = 0, .batches = gate_batch_count };
    const gate = try prover.air.logup_columns.build(allocator, log_size, gate_batch_count, gate_context, FillContext.fill);
    errdefer freeColumns(allocator, gate.columns);
    const wire_context = FillContext{ .base = base, .config = config, .gate = gate_elements, .wire = wire_elements, .start = equations.gate_limb_count, .batches = wire_batch_count };
    const wire = try prover.air.logup_columns.build(allocator, log_size, wire_batch_count, wire_context, FillContext.fill);
    errdefer freeColumns(allocator, wire.columns);
    const columns = try allocator.alloc(ColumnEvaluation, interaction_width);
    @memcpy(columns[0 .. gate_batch_count * 4], gate.columns);
    @memcpy(columns[gate_batch_count * 4 ..], wire.columns);
    allocator.free(gate.columns);
    allocator.free(wire.columns);
    return .{ .allocator = allocator, .columns = columns, .gate_claimed_sum = gate.claimed_sum, .sha_claimed_sum = wire.claimed_sum };
}

const FillContext = struct {
    base: []const ColumnEvaluation,
    config: Config,
    gate: Elements,
    wire: Elements,
    start: usize,
    batches: usize,

    fn fill(self: @This(), row: usize, fractions: []prover.air.logup_columns.Fraction) !void {
        if (fractions.len != self.batches) return error.InvalidShaCallerTrace;
        var values: [main_width]M31 = undefined;
        for (self.base, &values) |column, *value| value.* = column.values[row];
        const logical = unflatten(M31, values);
        const inv_rows = try QM31.fromBase(M31.fromCanonical(rows)).inv();
        for (0..self.batches) |batch| {
            const first = self.start + batch * 2;
            const a = eventDenominator(M31, logical, self.config, self.gate, self.wire, first);
            const b = eventDenominator(M31, logical, self.config, self.gate, self.wire, first + 1);
            const sa = eventSign(first);
            const sb = eventSign(first + 1);
            fractions[batch] = .{
                .numerator = signed(a, sb).add(signed(b, sa)).mul(inv_rows),
                .denominator = a.mul(b),
            };
        }
    }
};

fn signed(value: QM31, sign: i8) QM31 {
    return if (sign > 0) value else value.neg();
}
fn eventSign(index: usize) i8 {
    if (index < equations.gate_limb_count) return 1;
    return if ((index - equations.gate_limb_count) % equations.word_count_per_call < 24) 1 else -1;
}

fn eventDenominator(
    comptime F: type,
    row: equations.Row(F),
    config: Config,
    gate: Elements,
    wire: Elements,
    index: usize,
) QM31 {
    if (index < equations.gate_limb_count) {
        const tuple = gateTuple(F, config.gate_addresses[index], row.limbs[index]);
        return if (F == M31) gate.combineBase(tuple) else gate.combineSecure(tuple);
    }
    const offset = index - equations.gate_limb_count;
    const call_index = offset / equations.word_count_per_call;
    const word_index = offset % equations.word_count_per_call;
    const call = row.calls[call_index];
    const bytes = if (word_index < 8) call.state[word_index] else if (word_index < 24) call.block[word_index - 8] else call.output[word_index - 24];
    const id = config.first_call_id + @as(u32, @intCast(call_index));
    const wire_id = if (word_index < 24)
        provider.graph.input_boundary_offset + @as(u32, @intCast(word_index))
    else
        provider.topology.output[word_index - 24];
    const tuple = [6]F{ field(F, id), field(F, wire_id), bytes[0], bytes[1], bytes[2], bytes[3] };
    return if (F == M31) wire.combineBase(tuple) else wire.combineSecure(tuple);
}

fn field(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else QM31.fromBase(base);
}

fn gateTuple(comptime F: type, address: u32, value: F) [6]F {
    return .{ field(F, circuit.common.component_list.GATE_RELATION_ID), field(F, address), value, field(F, 0), field(F, 0), field(F, 0) };
}

fn validateBase(base: []const ColumnEvaluation) !void {
    if (base.len != main_width) return error.InvalidShaCallerTrace;
    for (base) |column| if (column.log_size != log_size or column.values.len != rows)
        return error.InvalidShaCallerTrace;
}

pub const Component = struct {
    main_offset: usize,
    interaction_offset: usize,
    config: Config,
    gate_elements: Elements,
    wire_elements: Elements,
    gate_claimed_sum: QM31,
    sha_claimed_sum: QM31,

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

    pub fn maskPoints(_: *const @This(), allocator: std.mem.Allocator, point: CirclePointQM31, max_log_degree_bound: u32) !core.air.components.MaskPoints {
        if (max_log_degree_bound < log_size) return error.InvalidShaCallerTrace;
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
        const previous = previousRowPoint(point);
        for (interaction, 0..) |*column, index| {
            const needs_previous = (index >= (gate_batch_count - 1) * 4 and index < gate_batch_count * 4) or
                index >= interaction_width - 4;
            column.* = if (needs_previous)
                try allocator.dupe(CirclePointQM31, &.{ previous, point })
            else
                try allocator.dupe(CirclePointQM31, &.{point});
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
            return error.InvalidShaCallerTrace;
        const main = mask.items[1][self.main_offset..][0..main_width];
        const interaction = mask.items[2][self.interaction_offset..][0..interaction_width];
        var values: [main_width]QM31 = undefined;
        for (main, &values) |column, *value| {
            if (column.len != 1) return error.InvalidShaCallerTrace;
            value.* = column[0];
        }
        var current: [batch_count]QM31 = undefined;
        for (&current, 0..) |*value, batch| value.* = try sampledSecure(interaction, batch * 4, if (batch + 1 == gate_batch_count or batch + 1 == batch_count) 1 else 0);
        const gate_previous = try sampledSecure(interaction, (gate_batch_count - 1) * 4, 0);
        const wire_previous = try sampledSecure(interaction, interaction_width - 4, 0);
        const constraints = self.rowConstraints(unflatten(QM31, values), current, gate_previous, wire_previous);
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(max_log_degree_bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 3 or trace.polys.items[1].len < self.main_offset + main_width or
            trace.polys.items[2].len < self.interaction_offset + interaction_width)
            return error.InvalidShaCallerTrace;
        const allocator = accumulator.allocator;
        const eval_log = log_size + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        const evaluations = try allocator.alloc([]const M31, main_width + interaction_width);
        defer allocator.free(evaluations);
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
        for (&inverse, 0..) |*slot, index| slot.* = try core.constraints.cosetVanishing(M31, canonic.CanonicCoset.new(log_size).coset(), domain.at(index)).inv();
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = n_constraints }});
        defer allocator.free(columns);
        const column = &columns[0];
        for (0..n) |row_index| {
            var values: [main_width]QM31 = undefined;
            for (&values, evaluations[0..main_width]) |*value, source| value.* = QM31.fromBase(source[row_index]);
            var current: [batch_count]QM31 = undefined;
            for (&current, 0..) |*value, batch| value.* = secureAt(evaluations[main_width + 4 * batch ..][0..4], row_index);
            const previous_index = core.utils.previousBitReversedCircleDomainIndex(row_index, log_size, eval_log);
            const gate_previous = secureAt(evaluations[main_width + (gate_batch_count - 1) * 4 ..][0..4], previous_index);
            const wire_previous = secureAt(evaluations[main_width + interaction_width - 4 ..][0..4], previous_index);
            const constraints = self.rowConstraints(unflatten(QM31, values), current, gate_previous, wire_previous);
            var combined = QM31.zero();
            for (constraints, 0..) |constraint, index|
                combined = combined.add(column.random_coeff_powers[n_constraints - 1 - index].mul(constraint));
            column.accumulate(row_index, combined.mulM31(inverse[row_index >> @intCast(log_size)]));
        }
    }

    fn rowConstraints(self: *const @This(), row: equations.Row(QM31), current: [batch_count]QM31, gate_previous: QM31, wire_previous: QM31) [n_constraints]QM31 {
        var result: [n_constraints]QM31 = undefined;
        const direct = equations.evaluate(QM31, row);
        @memcpy(result[0..equations.constraint_count], &direct);
        const inv_rows = QM31.fromBase(M31.fromCanonical(rows)).inv() catch unreachable;
        for (0..batch_count) |batch| {
            const a = eventDenominator(QM31, row, self.config, self.gate_elements, self.wire_elements, batch * 2);
            const b = eventDenominator(QM31, row, self.config, self.gate_elements, self.wire_elements, batch * 2 + 1);
            const numerator = signed(a, eventSign(batch * 2 + 1)).add(signed(b, eventSign(batch * 2))).mul(inv_rows);
            const delta = if (batch == 0) current[0] else if (batch + 1 == gate_batch_count)
                current[batch].sub(gate_previous).sub(current[batch - 1]).add(self.gate_claimed_sum.mul(inv_rows))
            else if (batch == gate_batch_count) current[batch] else if (batch + 1 == batch_count)
                current[batch].sub(wire_previous).sub(current[batch - 1]).add(self.sha_claimed_sum.mul(inv_rows))
            else
                current[batch].sub(current[batch - 1]);
            result[equations.constraint_count + batch] = delta.mul(a).mul(b).sub(numerator);
        }
        return result;
    }
};

fn sampledSecure(columns: [][]QM31, base: usize, index: usize) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (0..4) |i| {
        if (columns[base + i].len <= index) return error.InvalidShaCallerTrace;
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
    const coefficients = poly.coefficients orelse return error.InvalidShaCallerTrace;
    if (coefficients.logSize() != log_size) return error.InvalidShaCallerTrace;
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
fn previousRowPoint(point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
}
fn freeColumns(allocator: std.mem.Allocator, columns: []ColumnEvaluation) void {
    for (columns) |column| allocator.free(column.values);
    allocator.free(columns);
}

fn traceRow(base: []const ColumnEvaluation, index: usize) equations.Row(QM31) {
    var values: [main_width]QM31 = undefined;
    for (base, &values) |column, *value| value.* = QM31.fromBase(column.values[index]);
    return unflatten(QM31, values);
}

fn interactionAt(columns: []const ColumnEvaluation, batch: usize, index: usize) QM31 {
    return QM31.fromM31(
        columns[4 * batch + 0].values[index],
        columns[4 * batch + 1].values[index],
        columns[4 * batch + 2].values[index],
        columns[4 * batch + 3].values[index],
    );
}

fn expectValidCommittedTrace(component: *const Component, base: []const ColumnEvaluation, interaction: []const ColumnEvaluation) !void {
    for (0..rows) |index| {
        var current: [batch_count]QM31 = undefined;
        for (&current, 0..) |*value, batch| value.* = interactionAt(interaction, batch, index);
        const previous_index = core.utils.previousBitReversedCircleDomainIndex(index, log_size, log_size);
        const constraints = component.rowConstraints(
            traceRow(base, index),
            current,
            interactionAt(interaction, gate_batch_count - 1, previous_index),
            interactionAt(interaction, batch_count - 1, previous_index),
        );
        for (constraints, 0..) |constraint, equation_index| {
            if (!constraint.isZero()) {
                std.debug.print("SHA caller row {d}, equation {d} failed\n", .{ index, equation_index });
                return error.InvalidShaCallerConstraint;
            }
        }
    }
}

test "SHA caller AIR commits full row and rejects altered prechallenge trace" {
    const allocator = std.testing.allocator;
    const header = [_]u8{0} ** 80;
    const plan = @import("../config/sha_chip_plan.zig").prepare(header);
    const row = try equations.witness(header, plan);
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*address, index| address.* = @intCast(index + 3);
    const config = Config{ .gate_addresses = addresses, .first_call_id = 1 };
    var duplicate = config;
    duplicate.gate_addresses[1] = duplicate.gate_addresses[0];
    try std.testing.expectError(error.DuplicateShaGateAddress, duplicate.validate());
    duplicate = config;
    duplicate.gate_addresses[0] = 2;
    try std.testing.expectError(error.InvalidShaGateAddress, duplicate.validate());
    const gate = Elements.init(QM31.fromU32Unchecked(17, 2, 3, 5), QM31.fromU32Unchecked(11, 7, 13, 19));
    const wire = Elements.init(QM31.fromU32Unchecked(29, 3, 5, 7), QM31.fromU32Unchecked(23, 11, 17, 31));
    var base = try writeBase(allocator, row);
    defer base.deinit();
    var interaction = try writeInteraction(allocator, base.columns, config, gate, wire);
    defer interaction.deinit();
    const component = Component{ .main_offset = 0, .interaction_offset = 0, .config = config, .gate_elements = gate, .wire_elements = wire, .gate_claimed_sum = interaction.gate_claimed_sum, .sha_claimed_sum = interaction.sha_claimed_sum };
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    try expectValidCommittedTrace(&component, base.columns, interaction.columns);
    // All 264 equations hold on the committed row; the LogUp constraints
    // are independently checked in the full joined proof. A tampered limb
    // remains representable as a committed trace and violates the AIR.
    var committed: [main_width]M31 = undefined;
    for (base.columns, &committed) |column, *value| value.* = column.values[0];
    const honest = unflatten(M31, committed);
    for (equations.evaluate(M31, honest)) |constraint| try std.testing.expect(constraint.isZero());
    @constCast(base.columns[0].values)[0] = base.columns[0].values[0].add(M31.one());
    for (base.columns, &committed) |column, *value| value.* = column.values[0];
    const altered = equations.evaluate(M31, unflatten(M31, committed));
    try std.testing.expect(!altered[0].isZero());
    try std.testing.expectEqual(@as(usize, 340), component.nConstraints());
    try std.testing.expect(!std.mem.eql(u8, &semanticDigest(), &([_]u8{0} ** 32)));
}

test "SHA caller AIR keeps Gate and SHA lookup claims separate under precommitment substitutions" {
    const allocator = std.testing.allocator;
    const header = [_]u8{0x39} ** 80;
    const original = try equations.witness(header, @import("../config/sha_chip_plan.zig").prepare(header));
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*address, index| address.* = @intCast(index + 3);
    const config = Config{ .gate_addresses = addresses, .first_call_id = 41 };
    const gate = Elements.init(QM31.fromU32Unchecked(17, 2, 3, 5), QM31.fromU32Unchecked(11, 7, 13, 19));
    const wire = Elements.init(QM31.fromU32Unchecked(29, 3, 5, 7), QM31.fromU32Unchecked(23, 11, 17, 31));
    var base = try writeBase(allocator, original);
    defer base.deinit();
    var honest = try writeInteraction(allocator, base.columns, config, gate, wire);
    defer honest.deinit();
    const valid = Component{ .main_offset = 0, .interaction_offset = 0, .config = config, .gate_elements = gate, .wire_elements = wire, .gate_claimed_sum = honest.gate_claimed_sum, .sha_claimed_sum = honest.sha_claimed_sum };
    try expectValidCommittedTrace(&valid, base.columns, honest.columns);

    // Precommitment header substitution that keeps the local packing equation
    // valid still breaks both the circuit Gate and SHA graph closures.
    var changed = original;
    changed.calls[0].block[0][3] = changed.calls[0].block[0][3].add(M31.one());
    changed.limbs[0] = changed.limbs[0].add(M31.one());
    for (equations.evaluate(M31, changed)) |constraint| try std.testing.expect(constraint.isZero());
    var altered_base = try writeBase(allocator, changed);
    defer altered_base.deinit();
    var altered = try writeInteraction(allocator, altered_base.columns, config, gate, wire);
    defer altered.deinit();
    const altered_component = Component{ .main_offset = 0, .interaction_offset = 0, .config = config, .gate_elements = gate, .wire_elements = wire, .gate_claimed_sum = altered.gate_claimed_sum, .sha_claimed_sum = altered.sha_claimed_sum };
    try expectValidCommittedTrace(&altered_component, altered_base.columns, altered.columns);
    try std.testing.expect(!altered.gate_claimed_sum.eql(honest.gate_claimed_sum));
    try std.testing.expect(!altered.sha_claimed_sum.eql(honest.sha_claimed_sum));

    // A fabricated output byte and its matching u16 limb satisfy the local
    // linear equations but break the SHA provider's authenticated output.
    changed = original;
    changed.calls[2].output[0][3] = changed.calls[2].output[0][3].add(M31.one());
    changed.limbs[40] = changed.limbs[40].add(M31.one());
    for (equations.evaluate(M31, changed)) |constraint| try std.testing.expect(constraint.isZero());
    var output_base = try writeBase(allocator, changed);
    defer output_base.deinit();
    var output_interaction = try writeInteraction(allocator, output_base.columns, config, gate, wire);
    defer output_interaction.deinit();
    try std.testing.expect(!output_interaction.gate_claimed_sum.eql(honest.gate_claimed_sum));
    try std.testing.expect(!output_interaction.sha_claimed_sum.eql(honest.sha_claimed_sum));
}
