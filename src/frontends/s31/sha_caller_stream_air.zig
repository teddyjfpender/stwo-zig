//! Standalone 80-row SHA256d caller AIR. It proves local byte packing,
//! chaining, canonical IV/padding, and equality to a public digest. The
//! circuit Gate and SHA word events are committed here but are authenticated
//! only when a joint lookup argument closes both buses in the same proof.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const equations = @import("sha_caller_stream_equations.zig");

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
pub const fixed_width: usize = 8; // byte, chain, constant, digest, constant halves, digest halves.
pub const main_width: usize = 38; // two Gate limbs, four word halves, 32 serialized bits.
pub const n_constraints: usize = 40;
// The caller's largest constraint is a selector times a Boolean polynomial
// (degree three). The shared direct SHA proof uses a q2 composition split.
pub const max_constraint_log_degree: u32 = log_size + 2;
pub const word_relation_id: u32 = 0x5333_3103;

pub const Statement = struct {
    digest: [32]u8,
    config: equations.Config,

    pub fn validate(self: Statement) !void {
        try self.config.validate();
    }
};

pub fn Fixed(comptime F: type) type {
    return struct {
        byte: F,
        chain: F,
        constant: F,
        digest: F,
        constant_lo: F,
        constant_hi: F,
        digest_lo: F,
        digest_hi: F,
    };
}

fn field(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("SHA caller requires M31 or QM31");
}

pub fn flatten(comptime F: type, row: equations.Row(F)) [main_width]F {
    var values: [main_width]F = undefined;
    values[0] = row.gate_limbs[0];
    values[1] = row.gate_limbs[1];
    values[2] = row.words[0][0];
    values[3] = row.words[0][1];
    values[4] = row.words[1][0];
    values[5] = row.words[1][1];
    @memcpy(values[6..], &row.serialized_bits);
    return values;
}

pub fn unflatten(comptime F: type, values: [main_width]F) equations.Row(F) {
    var row: equations.Row(F) = .{
        .gate_limbs = .{ values[0], values[1] },
        .words = .{ .{ values[2], values[3] }, .{ values[4], values[5] } },
        .serialized_bits = undefined,
    };
    @memcpy(&row.serialized_bits, values[6..]);
    return row;
}

fn fixedAt(comptime F: type, values: [fixed_width]F) Fixed(F) {
    return .{
        .byte = values[0],
        .chain = values[1],
        .constant = values[2],
        .digest = values[3],
        .constant_lo = values[4],
        .constant_hi = values[5],
        .digest_lo = values[6],
        .digest_hi = values[7],
    };
}

fn packBits(comptime F: type, bits: [32]F, start: usize) F {
    var sum = field(F, 0);
    for (0..16) |i| sum = sum.add(bits[start + i].mul(field(F, @as(u32, 1) << @intCast(i))));
    return sum;
}

fn swappedHalf(comptime F: type, bits: [32]F, low_byte: usize, high_byte: usize) F {
    var sum = field(F, 0);
    for (0..8) |i| {
        sum = sum.add(bits[8 * low_byte + i].mul(field(F, @as(u32, 1) << @intCast(i))));
        sum = sum.add(bits[8 * high_byte + i].mul(field(F, @as(u32, 1) << @intCast(i + 8))));
    }
    return sum;
}

/// One polynomial list at trace, quotient domain, and OODS points. The
/// verifier-pinned fixed rows select all 80 semantic roles and 48 zero rows.
/// The public digest fixes the last eight SHA output words byte-exactly.
pub fn evaluate(comptime F: type, row: equations.Row(F), fixed: Fixed(F)) [n_constraints]F {
    var result: [n_constraints]F = undefined;
    const one = field(F, 1);
    const non_byte = one.sub(fixed.byte);
    const padding = one.sub(fixed.byte).sub(fixed.chain).sub(fixed.constant);
    for (row.serialized_bits, 0..) |bit, i| {
        result[i] = fixed.byte.mul(bit.mul(bit.sub(one))).add(non_byte.mul(bit));
    }
    result[32] = row.gate_limbs[0].sub(fixed.byte.mul(packBits(F, row.serialized_bits, 0)));
    result[33] = row.gate_limbs[1].sub(fixed.byte.mul(packBits(F, row.serialized_bits, 16)));
    const swapped = [2]F{
        swappedHalf(F, row.serialized_bits, 3, 2),
        swappedHalf(F, row.serialized_bits, 1, 0),
    };
    const constants = [2]F{ fixed.constant_lo, fixed.constant_hi };
    const digest = [2]F{ fixed.digest_lo, fixed.digest_hi };
    for (0..2) |i| {
        result[34 + i] = fixed.byte.mul(row.words[0][i].sub(swapped[i]))
            .add(fixed.constant.mul(row.words[0][i].sub(constants[i])))
            .add(padding.mul(row.words[0][i]));
        result[36 + i] = row.words[1][i].sub(fixed.chain.mul(row.words[0][i]));
        result[38 + i] = fixed.digest.mul(row.words[0][i].sub(digest[i]));
    }
    return result;
}

fn fixedValues(statement: Statement, index: usize) [fixed_width]M31 {
    var values: [fixed_width]M31 = @splat(M31.zero());
    if (index >= active_rows) return values;
    if (index < 28) {
        values[0] = M31.one();
        if (index >= 20) {
            values[3] = M31.one();
            const word = std.mem.readInt(u32, statement.digest[4 * (index - 20) ..][0..4], .big);
            values[6] = M31.fromCanonical(word & 0xffff);
            values[7] = M31.fromCanonical(word >> 16);
        }
    } else if (index < 44) {
        values[1] = M31.one();
    } else {
        values[2] = M31.one();
        const word: u32 = if (index < 52)
            @import("s31_sha_provider").compression.initial_state[index - 44]
        else if (index < 60)
            @import("s31_sha_provider").compression.initial_state[index - 52]
        else if (index < 72)
            if (index == 60) 0x8000_0000 else if (index == 71) 640 else 0
        else if (index == 72) 0x8000_0000 else if (index == 79) 256 else 0;
        values[4] = M31.fromCanonical(word & 0xffff);
        values[5] = M31.fromCanonical(word >> 16);
    }
    return values;
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

pub fn writeFixed(allocator: std.mem.Allocator, statement: Statement) !Columns {
    try statement.validate();
    const columns = try allocateColumns(allocator, fixed_width);
    for (0..rows) |logical| {
        const values = fixedValues(statement, logical);
        const storage = storageIndex(logical);
        for (columns.values, values) |column, value| @constCast(column.values)[storage] = value;
    }
    return columns;
}

pub fn writeMain(allocator: std.mem.Allocator, header: [80]u8) !Columns {
    const columns = try allocateColumns(allocator, main_width);
    const witness = equations.witness(header);
    for (witness, 0..) |row, logical| {
        const values = flatten(M31, row);
        const storage = storageIndex(logical);
        for (columns.values, values) |column, value| @constCast(column.values)[storage] = value;
    }
    return columns;
}

pub fn rowAt(main: []const ColumnEvaluation, logical: usize) !equations.Row(M31) {
    if (main.len != main_width or logical >= active_rows) return error.InvalidShaCallerTrace;
    const storage = storageIndex(logical);
    var values: [main_width]M31 = undefined;
    for (&values, main) |*value, column| {
        if (column.log_size != log_size or column.values.len != rows) return error.InvalidShaCallerTrace;
        value.* = column.values[storage];
    }
    return unflatten(M31, values);
}

pub fn WordBusEvent(comptime F: type) type {
    return struct { tuple: [6]F, weight: i8 };
}

/// A fixed, index-derived roster over committed row values. Caller state
/// inputs appear twice because round and feed each consume them; block input
/// appears once; a returned output is consumed once. The signed events become
/// authentication only after a joint LogUp closes their sum with the other
/// three direct-SHA components.
pub fn wordBusEvents(comptime F: type, row: equations.Row(F), logical: usize, config: equations.Config) [2]?WordBusEvent(F) {
    var result: [2]?WordBusEvent(F) = .{ null, null };
    const events = equations.wordEvents(F, row, logical, config.first_call_id);
    for (events, &result) |maybe_event, *slot| if (maybe_event) |event| {
        slot.* = .{
            .tuple = .{
                field(F, word_relation_id), field(F, event.call_id), field(F, event.word_id),
                event.lo,                   event.hi,                field(F, 0),
            },
            .weight = if (event.word_id < 8) 2 else if (event.word_id < 24) 1 else -1,
        };
    };
    return result;
}

pub fn gateBusEvents(comptime F: type, row: equations.Row(F), logical: usize, config: equations.Config) [2]?equations.GateEvent(F) {
    return equations.gateEvents(F, row, logical, config.gate_addresses);
}

pub const Component = struct {
    statement: Statement,
    fixed_offset: usize = 0,
    main_offset: usize = 0,

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
        if (max_log_degree_bound < log_size) return error.InvalidShaCallerTrace;
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
        for (indices, 0..) |*index, i| index.* = self.fixed_offset + i;
        return indices;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *PointEvaluationAccumulator, max_log_degree_bound: u32) !void {
        if (mask.items.len < 2 or mask.items[0].len < self.fixed_offset + fixed_width or mask.items[1].len < self.main_offset + main_width or max_log_degree_bound < log_size) return error.InvalidShaCallerTrace;
        var fv: [fixed_width]QM31 = undefined;
        var mv: [main_width]QM31 = undefined;
        for (&fv, mask.items[0][self.fixed_offset..][0..fixed_width]) |*value, column| {
            if (column.len != 1) return error.InvalidShaCallerTrace;
            value.* = column[0];
        }
        for (&mv, mask.items[1][self.main_offset..][0..main_width]) |*value, column| {
            if (column.len != 1) return error.InvalidShaCallerTrace;
            value.* = column[0];
        }
        const constraints = evaluate(QM31, unflatten(QM31, mv), fixedAt(QM31, fv));
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(max_log_degree_bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 2 or trace.polys.items[0].len < self.fixed_offset + fixed_width or trace.polys.items[1].len < self.main_offset + main_width) return error.InvalidShaCallerTrace;
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
        for (0..n) |storage| {
            var fv: [fixed_width]QM31 = undefined;
            var mv: [main_width]QM31 = undefined;
            for (&fv, evaluations[0..fixed_width]) |*value, source| value.* = QM31.fromBase(source[storage]);
            for (&mv, evaluations[fixed_width..]) |*value, source| value.* = QM31.fromBase(source[storage]);
            const constraints = evaluate(QM31, unflatten(QM31, mv), fixedAt(QM31, fv));
            var sum = QM31.zero();
            for (constraints, 0..) |constraint, i| sum = sum.add(column.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            column.accumulate(storage, sum.mulM31(inverse[storage >> @intCast(log_size)]));
        }
    }
};

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

pub fn validateCommittedTrace(statement: Statement, fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    if (fixed.len != fixed_width or main.len != main_width) return error.InvalidShaCallerTrace;
    // This host comparison is diagnostic only. The verifier pins fixed_root.
    for (0..rows) |logical| {
        const expected = fixedValues(statement, logical);
        const storage = storageIndex(logical);
        for (fixed, expected) |column, value| if (!column.values[storage].eql(value))
            return error.InvalidShaCallerFixedColumn;
    }
    for (0..rows) |storage| {
        var fv: [fixed_width]M31 = undefined;
        var mv: [main_width]M31 = undefined;
        for (&fv, fixed) |*value, column| value.* = column.values[storage];
        for (&mv, main) |*value, column| value.* = column.values[storage];
        for (evaluate(M31, unflatten(M31, mv), fixedAt(M31, fv))) |constraint|
            if (!constraint.isZero()) return error.InvalidShaCallerConstraint;
    }
}
