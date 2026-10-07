//! SHA-256 round AIR with two-word shift-register state and private word bus.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const sha = @import("s31_sha_provider").compression;

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
pub const active_rows: usize = 64;
pub const first_round_row: usize = 3;
pub const final_row: usize = 67;
pub const fixed_width: usize = 8; // active, input, terminal, padding, K halves, round index, state address.
pub const main_width: usize = 2 * 32 + 12 + 2; // a/e bits, four 3-bit carries, private W halves.
pub const n_constraints: usize = 64 + 4 + 12 + 4 + 4 + 2;
pub const max_constraint_log_degree: u32 = log_size + 2;

pub const Statement = struct {
    initial: sha.State,
    final: sha.State,
    schedule: [64]u32,
};

pub fn Row(comptime F: type) type {
    return struct {
        a: [32]F,
        e: [32]F,
        carry_bits: [12]F,
        w_lo: F,
        w_hi: F,
    };
}

pub fn Fixed(comptime F: type) type {
    return struct { active: F, input: F, terminal: F, padding: F, k_lo: F, k_hi: F, round_index: F, state_address: F };
}

fn field(comptime F: type, n: u32) F {
    const base = M31.fromCanonical(n);
    return if (F == M31) base else QM31.fromBase(base);
}

pub fn flatten(comptime F: type, row: Row(F)) [main_width]F {
    var result: [main_width]F = undefined;
    var at: usize = 0;
    for (row.a) |bit| {
        result[at] = bit;
        at += 1;
    }
    for (row.e) |bit| {
        result[at] = bit;
        at += 1;
    }
    for (row.carry_bits) |bit| {
        result[at] = bit;
        at += 1;
    }
    result[at] = row.w_lo;
    result[at + 1] = row.w_hi;
    return result;
}

pub fn unflatten(comptime F: type, values: [main_width]F) Row(F) {
    var result: Row(F) = undefined;
    var at: usize = 0;
    for (&result.a) |*bit| {
        bit.* = values[at];
        at += 1;
    }
    for (&result.e) |*bit| {
        bit.* = values[at];
        at += 1;
    }
    for (&result.carry_bits) |*bit| {
        bit.* = values[at];
        at += 1;
    }
    result.w_lo = values[at];
    result.w_hi = values[at + 1];
    return result;
}

pub fn fixedAt(comptime F: type, values: [fixed_width]F) Fixed(F) {
    return .{ .active = values[0], .input = values[1], .terminal = values[2], .padding = values[3], .k_lo = values[4], .k_hi = values[5], .round_index = values[6], .state_address = values[7] };
}

fn half(comptime F: type, bits: [32]F, start: usize) F {
    var sum = field(F, 0);
    for (0..16) |i| sum = sum.add(bits[start + i].mul(field(F, @as(u32, 1) << @intCast(i))));
    return sum;
}

fn xor3(comptime F: type, x: F, y: F, z: F) F {
    const xy = x.mul(y);
    const xz = x.mul(z);
    const yz = y.mul(z);
    return x.add(y).add(z).sub(field(F, 2).mul(xy.add(xz).add(yz))).add(field(F, 4).mul(xy.mul(z)));
}

fn sig(comptime F: type, bits: [32]F, comptime a: usize, comptime b: usize, comptime c: usize) [32]F {
    var out: [32]F = undefined;
    for (&out, 0..) |*slot, i| slot.* = xor3(F, bits[(i + a) % 32], bits[(i + b) % 32], bits[(i + c) % 32]);
    return out;
}

fn ch(comptime F: type, e: [32]F, f: [32]F, g: [32]F) [32]F {
    var out: [32]F = undefined;
    for (&out, e, f, g) |*slot, x, y, z| slot.* = x.mul(y).add(field(F, 1).sub(x).mul(z));
    return out;
}

fn maj(comptime F: type, a: [32]F, b: [32]F, c: [32]F) [32]F {
    var out: [32]F = undefined;
    for (&out, a, b, c) |*slot, x, y, z| slot.* = x.mul(y).add(x.mul(z)).add(y.mul(z)).sub(field(F, 2).mul(x.mul(y).mul(z)));
    return out;
}

/// The two direct next-e sums have six 16-bit addends and carries 0..5.
/// The two direct next-a sums have seven 16-bit addends and carries 0..6.
/// Three Boolean bits suffice for each carry; an accepted limb equation
/// cannot admit 6/7 for next-e or 7 for next-a because its integer sides
/// are below the M31 modulus and the output limb is range constrained.
fn carryValue(comptime F: type, bits: [12]F, index: usize) F {
    std.debug.assert(index < 4);
    var result = field(F, 0);
    for (0..3) |i| result = result.add(bits[3 * index + i].mul(field(F, @as(u32, 1) << @intCast(i))));
    return result;
}

/// Five openings of the same committed a/e columns reconstruct all eight
/// SHA state words. Fixed active rows 3..66 guard every nonlocal offset.
pub fn evaluate(comptime F: type, row: Row(F), prev1: Row(F), prev2: Row(F), prev3: Row(F), next: Row(F), fixed: Fixed(F)) [n_constraints]F {
    var out: [n_constraints]F = undefined;
    var at: usize = 0;
    const one = field(F, 1);
    const radix = field(F, 1 << 16);
    for (flatten(F, row)[0..64]) |value| {
        out[at] = value.mul(value.sub(one));
        at += 1;
    }
    const active = fixed.active;
    const s0 = sig(F, row.a, 2, 13, 22);
    const s1 = sig(F, row.e, 6, 11, 25);
    const choose = ch(F, row.e, prev1.e, prev2.e);
    const majority = maj(F, row.a, prev1.a, prev2.a);
    const a_lo = half(F, prev3.e, 0).add(half(F, s1, 0)).add(half(F, choose, 0)).add(fixed.k_lo).add(row.w_lo);
    const a_hi = half(F, prev3.e, 16).add(half(F, s1, 16)).add(half(F, choose, 16)).add(fixed.k_hi).add(row.w_hi);
    out[at] = active.mul(a_lo.add(half(F, prev3.a, 0)).sub(half(F, next.e, 0)).sub(radix.mul(carryValue(F, row.carry_bits, 0))));
    at += 1;
    out[at] = active.mul(a_hi.add(half(F, prev3.a, 16)).add(carryValue(F, row.carry_bits, 0)).sub(half(F, next.e, 16)).sub(radix.mul(carryValue(F, row.carry_bits, 1))));
    at += 1;
    out[at] = active.mul(a_lo.add(half(F, s0, 0)).add(half(F, majority, 0)).sub(half(F, next.a, 0)).sub(radix.mul(carryValue(F, row.carry_bits, 2))));
    at += 1;
    out[at] = active.mul(a_hi.add(half(F, s0, 16)).add(half(F, majority, 16)).add(carryValue(F, row.carry_bits, 2)).sub(half(F, next.a, 16)).sub(radix.mul(carryValue(F, row.carry_bits, 3))));
    at += 1;
    for (row.carry_bits) |bit| {
        out[at] = bit.mul(bit.sub(one));
        at += 1;
    }
    for ([_]usize{ 0, 16 }) |start| {
        out[at] = fixed.padding.mul(half(F, row.a, start));
        at += 1;
        out[at] = fixed.padding.mul(half(F, row.e, start));
        at += 1;
    }
    const no_round = one.sub(active);
    for (0..4) |i| {
        out[at] = no_round.mul(carryValue(F, row.carry_bits, i));
        at += 1;
    }
    out[at] = no_round.mul(row.w_lo);
    at += 1;
    out[at] = no_round.mul(row.w_hi);
    at += 1;
    std.debug.assert(at == n_constraints);
    return out;
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

pub fn writeFixed(allocator: std.mem.Allocator, schedule: [64]u32) !Columns {
    const result = try allocateColumns(allocator, fixed_width);
    for (0..active_rows) |t| {
        const i = storageIndex(t + first_round_row);
        @constCast(result.values[0].values)[i] = M31.one();
        const k = sha.round_constants[t];
        @constCast(result.values[4].values)[i] = M31.fromCanonical(k & 0xffff);
        @constCast(result.values[5].values)[i] = M31.fromCanonical(k >> 16);
        @constCast(result.values[6].values)[i] = M31.fromCanonical(@intCast(t));
    }
    for (0..4) |i| {
        @constCast(result.values[1].values)[storageIndex(i)] = M31.one();
        @constCast(result.values[2].values)[storageIndex(64 + i)] = M31.one();
        @constCast(result.values[7].values)[storageIndex(i)] = M31.fromCanonical(@intCast(3 - i));
        @constCast(result.values[7].values)[storageIndex(64 + i)] = M31.fromCanonical(@intCast(@import("sha_direct_word_bus.zig").terminal_base + 3 - i));
    }
    for (68..rows) |i| @constCast(result.values[3].values)[storageIndex(i)] = M31.one();
    _ = schedule;
    return result;
}

/// Canonical fixed trace for a private schedule: K, row selectors, and row
/// indices remain verifier-owned; the W halves are committed in main and
/// authenticated by the schedule/round word LogUp.
pub fn writeFixedPrivate(allocator: std.mem.Allocator) !Columns {
    return writeFixed(allocator, @splat(0));
}

fn setWord(bits: *[32]M31, value: u32) void {
    for (bits, 0..) |*bit, i| bit.* = M31.fromCanonical((value >> @intCast(i)) & 1);
}

pub fn writeMain(allocator: std.mem.Allocator, statement: Statement) !Columns {
    const result = try allocateColumns(allocator, main_width);
    var states: [65]sha.State = undefined;
    states[0] = statement.initial;
    for (statement.schedule, 0..) |word, t| states[t + 1] = sha.round(states[t], word, sha.round_constants[t]);
    if (!std.meta.eql(states[64], statement.final)) return error.InvalidShaRoundTerminal;
    for (0..final_row + 1) |r| {
        var row: Row(M31) = .{ .a = @splat(M31.zero()), .e = @splat(M31.zero()), .carry_bits = @splat(M31.zero()), .w_lo = M31.zero(), .w_hi = M31.zero() };
        const state = if (r < first_round_row) statement.initial else states[r - first_round_row];
        setWord(&row.a, if (r < first_round_row) statement.initial[3 - r] else state[0]);
        setWord(&row.e, if (r < first_round_row) statement.initial[7 - r] else state[4]);
        if (r >= first_round_row and r < first_round_row + active_rows) {
            const t = r - first_round_row;
            row.w_lo = M31.fromCanonical(statement.schedule[t] & 0xffff);
            row.w_hi = M31.fromCanonical(statement.schedule[t] >> 16);
            const s1 = sha.sigmaBig1(state[4]);
            const chv = sha.choose(state[4], state[5], state[6]);
            const sum_low = (state[7] & 0xffff) + (s1 & 0xffff) + (chv & 0xffff) + (sha.round_constants[t] & 0xffff) + (statement.schedule[t] & 0xffff);
            const sum_high = (state[7] >> 16) + (s1 >> 16) + (chv >> 16) + (sha.round_constants[t] >> 16) + (statement.schedule[t] >> 16);
            const s0 = sha.sigmaBig0(state[0]);
            const majv = sha.majority(state[0], state[1], state[2]);
            const e_low = sum_low + (state[3] & 0xffff);
            const e_high = sum_high + (state[3] >> 16) + (e_low >> 16);
            const a_low = sum_low + (s0 & 0xffff) + (majv & 0xffff);
            const a_high = sum_high + (s0 >> 16) + (majv >> 16) + (a_low >> 16);
            const carries = [_]u32{ e_low >> 16, e_high >> 16, a_low >> 16, a_high >> 16 };
            var bit_index: usize = 0;
            for (carries) |carry| {
                for (0..3) |i| {
                    row.carry_bits[bit_index] = M31.fromCanonical((carry >> @intCast(i)) & 1);
                    bit_index += 1;
                }
            }
        }
        const values = flatten(M31, row);
        const i = storageIndex(r);
        for (result.values, values) |column, value| @constCast(column.values)[i] = value;
    }
    return result;
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
        if (max_log_degree_bound < log_size) return error.InvalidShaShiftTrace;
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
        const step = canonic.CanonicCoset.new(max_log_degree_bound).coset_value.step;
        const shift = CirclePointQM31{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) };
        const prev1 = point.sub(shift);
        const prev2 = prev1.sub(shift);
        const prev3 = prev2.sub(shift);
        const next = point.add(shift);
        for (main, 0..) |*column, i| {
            column.* = if (i < 64)
                try allocator.dupe(CirclePointQM31, &.{ prev3, prev2, prev1, point, next })
            else
                try allocator.dupe(CirclePointQM31, &.{point});
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
        if (mask.items.len < 2 or mask.items[0].len < self.fixed_offset + fixed_width or mask.items[1].len < self.main_offset + main_width or max_log_degree_bound < log_size) return error.InvalidShaShiftTrace;
        var fixed_values: [fixed_width]QM31 = undefined;
        for (&fixed_values, mask.items[0][self.fixed_offset..][0..fixed_width]) |*value, col| {
            if (col.len != 1) return error.InvalidShaShiftTrace;
            value.* = col[0];
        }
        var current: [main_width]QM31 = undefined;
        var prev1: [main_width]QM31 = @splat(QM31.zero());
        var prev2: [main_width]QM31 = @splat(QM31.zero());
        var prev3: [main_width]QM31 = @splat(QM31.zero());
        var next: [main_width]QM31 = @splat(QM31.zero());
        for (mask.items[1][self.main_offset..][0..main_width], 0..) |col, i| {
            if (i < 64) {
                if (col.len != 5) return error.InvalidShaShiftTrace;
                prev3[i] = col[0];
                prev2[i] = col[1];
                prev1[i] = col[2];
                current[i] = col[3];
                next[i] = col[4];
            } else {
                if (col.len != 1) return error.InvalidShaShiftTrace;
                current[i] = col[0];
            }
        }
        const constraints = evaluate(QM31, unflatten(QM31, current), unflatten(QM31, prev1), unflatten(QM31, prev2), unflatten(QM31, prev3), unflatten(QM31, next), fixedAt(QM31, fixed_values));
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(max_log_degree_bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 2 or trace.polys.items[0].len < self.fixed_offset + fixed_width or trace.polys.items[1].len < self.main_offset + main_width) return error.InvalidShaShiftTrace;
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
            var fixed_values: [fixed_width]QM31 = undefined;
            var current: [main_width]QM31 = undefined;
            var prev1: [main_width]QM31 = @splat(QM31.zero());
            var prev2: [main_width]QM31 = @splat(QM31.zero());
            var prev3: [main_width]QM31 = @splat(QM31.zero());
            var next: [main_width]QM31 = @splat(QM31.zero());
            for (&fixed_values, evaluations[0..fixed_width]) |*value, source| value.* = QM31.fromBase(source[row_index]);
            for (&current, evaluations[fixed_width..]) |*slot, source| slot.* = QM31.fromBase(source[row_index]);
            for (0..64) |i| {
                const source = evaluations[fixed_width + i];
                prev1[i] = QM31.fromBase(source[core.utils.offsetBitReversedCircleDomainIndex(row_index, log_size, eval_log, -1)]);
                prev2[i] = QM31.fromBase(source[core.utils.offsetBitReversedCircleDomainIndex(row_index, log_size, eval_log, -2)]);
                prev3[i] = QM31.fromBase(source[core.utils.offsetBitReversedCircleDomainIndex(row_index, log_size, eval_log, -3)]);
                next[i] = QM31.fromBase(source[core.utils.offsetBitReversedCircleDomainIndex(row_index, log_size, eval_log, 1)]);
            }
            const constraints = evaluate(QM31, unflatten(QM31, current), unflatten(QM31, prev1), unflatten(QM31, prev2), unflatten(QM31, prev3), unflatten(QM31, next), fixedAt(QM31, fixed_values));
            var sum = QM31.zero();
            for (constraints, 0..) |constraint, i| sum = sum.add(column.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            column.accumulate(row_index, sum.mulM31(inverse[row_index >> @intCast(log_size)]));
        }
    }
};

fn evaluationOnDomain(allocator: std.mem.Allocator, poly: prover.air.component_prover.Poly, eval_log: u32, n: usize, buffers: *std.ArrayList([]M31)) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidShaShiftTrace;
    if (coefficients.logSize() != log_size) return error.InvalidShaShiftTrace;
    const values = try allocator.alloc(M31, n);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

pub fn validateCommittedTrace(statement: Statement, fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    _ = statement;
    if (fixed.len != fixed_width or main.len != main_width) return error.InvalidShaShiftTrace;
    for (0..rows) |storage| {
        var fv: [fixed_width]M31 = undefined;
        var mv: [main_width]M31 = undefined;
        var p1: [main_width]M31 = @splat(M31.zero());
        var p2: [main_width]M31 = @splat(M31.zero());
        var p3: [main_width]M31 = @splat(M31.zero());
        var nv: [main_width]M31 = @splat(M31.zero());
        for (&fv, fixed) |*slot, col| slot.* = col.values[storage];
        for (&mv, main) |*slot, col| slot.* = col.values[storage];
        for (0..64) |i| {
            p1[i] = main[i].values[core.utils.offsetBitReversedCircleDomainIndex(storage, log_size, log_size, -1)];
            p2[i] = main[i].values[core.utils.offsetBitReversedCircleDomainIndex(storage, log_size, log_size, -2)];
            p3[i] = main[i].values[core.utils.offsetBitReversedCircleDomainIndex(storage, log_size, log_size, -3)];
            nv[i] = main[i].values[core.utils.offsetBitReversedCircleDomainIndex(storage, log_size, log_size, 1)];
        }
        for (evaluate(M31, unflatten(M31, mv), unflatten(M31, p1), unflatten(M31, p2), unflatten(M31, p3), unflatten(M31, nv), fixedAt(M31, fv))) |constraint|
            if (!constraint.isZero()) return error.InvalidShaShiftConstraint;
    }
}
