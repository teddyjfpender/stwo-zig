//! Table-free SHA-256 compression-round AIR. This is an isolated, verifier-
//! supplied-schedule component; it does not yet authenticate a private caller.
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
pub const terminal_row: usize = 64;
pub const fixed_width: usize = 7; // active, first, terminal, W low/high, K low/high.
pub const main_width: usize = 8 * 32 + 32 + 6; // State bits, T1 bits, six carries.
pub const n_constraints: usize = 8 * 32 + 32 + 6 + 6 + 12 + 16 + 16 + 24;
pub const max_constraint_log_degree: u32 = log_size + 3;

pub const Statement = struct {
    initial: sha.State,
    final: sha.State,
    schedule: [64]u32,
};

pub fn Row(comptime F: type) type {
    return struct {
        state: [8][32]F,
        t1: [32]F,
        carries: [6]F,
    };
}

pub fn Fixed(comptime F: type) type {
    return struct { active: F, first: F, terminal: F, w_lo: F, w_hi: F, k_lo: F, k_hi: F };
}

fn field(comptime F: type, n: u32) F {
    const base = M31.fromCanonical(n);
    return if (F == M31) base else QM31.fromBase(base);
}

pub fn flatten(comptime F: type, row: Row(F)) [main_width]F {
    var result: [main_width]F = undefined;
    var at: usize = 0;
    for (row.state) |word| for (word) |bit| {
        result[at] = bit;
        at += 1;
    };
    for (row.t1) |bit| {
        result[at] = bit;
        at += 1;
    }
    for (row.carries) |carry| {
        result[at] = carry;
        at += 1;
    }
    return result;
}

pub fn unflatten(comptime F: type, values: [main_width]F) Row(F) {
    var result: Row(F) = undefined;
    var at: usize = 0;
    for (&result.state) |*word| for (word) |*bit| {
        bit.* = values[at];
        at += 1;
    };
    for (&result.t1) |*bit| {
        bit.* = values[at];
        at += 1;
    }
    for (&result.carries) |*carry| {
        carry.* = values[at];
        at += 1;
    }
    return result;
}

pub fn fixedAt(comptime F: type, values: [fixed_width]F) Fixed(F) {
    return .{ .active = values[0], .first = values[1], .terminal = values[2], .w_lo = values[3], .w_hi = values[4], .k_lo = values[5], .k_hi = values[6] };
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

fn carryRange(comptime F: type, carry: F, max: u32) F {
    var p = carry;
    for (1..max + 1) |i| p = p.mul(carry.sub(field(F, @intCast(i))));
    return p;
}

/// The same polynomial list is used at trace, quotient-domain, and OODS
/// points. Every 16-bit sum is below 2^19, so M31 cannot hide integer wrap.
pub fn evaluate(comptime F: type, row: Row(F), next: Row(F), fixed: Fixed(F), statement: Statement) [n_constraints]F {
    var out: [n_constraints]F = undefined;
    var at: usize = 0;
    const one = field(F, 1);
    const radix = field(F, 1 << 16);
    for (flatten(F, row)[0 .. 8 * 32 + 32]) |value| {
        out[at] = value.mul(value.sub(one));
        at += 1;
    }
    const active = fixed.active;
    const pad = one.sub(active).sub(fixed.terminal);
    const s0 = sig(F, row.state[0], 2, 13, 22);
    const s1 = sig(F, row.state[4], 6, 11, 25);
    const choose = ch(F, row.state[4], row.state[5], row.state[6]);
    const majority = maj(F, row.state[0], row.state[1], row.state[2]);
    const h = row.state[7];
    const t1 = row.t1;
    const next_a = next.state[0];
    const next_e = next.state[4];
    out[at] = active.mul(half(F, h, 0).add(half(F, s1, 0)).add(half(F, choose, 0)).add(fixed.k_lo).add(fixed.w_lo).sub(half(F, t1, 0)).sub(radix.mul(row.carries[0])));
    at += 1;
    out[at] = active.mul(half(F, h, 16).add(half(F, s1, 16)).add(half(F, choose, 16)).add(fixed.k_hi).add(fixed.w_hi).add(row.carries[0]).sub(half(F, t1, 16)).sub(radix.mul(row.carries[1])));
    at += 1;
    out[at] = active.mul(half(F, t1, 0).add(half(F, s0, 0)).add(half(F, majority, 0)).sub(half(F, next_a, 0)).sub(radix.mul(row.carries[2])));
    at += 1;
    out[at] = active.mul(half(F, t1, 16).add(half(F, s0, 16)).add(half(F, majority, 16)).add(row.carries[2]).sub(half(F, next_a, 16)).sub(radix.mul(row.carries[3])));
    at += 1;
    out[at] = active.mul(half(F, row.state[3], 0).add(half(F, t1, 0)).sub(half(F, next_e, 0)).sub(radix.mul(row.carries[4])));
    at += 1;
    out[at] = active.mul(half(F, row.state[3], 16).add(half(F, t1, 16)).add(row.carries[4]).sub(half(F, next_e, 16)).sub(radix.mul(row.carries[5])));
    at += 1;
    for (row.carries, 0..) |carry, i| {
        out[at] = active.mul(carryRange(F, carry, if (i < 2) 4 else if (i < 4) 2 else 1));
        at += 1;
    }
    const copied = [_]usize{ 0, 1, 2, 4, 5, 6 };
    const destinations = [_]usize{ 1, 2, 3, 5, 6, 7 };
    for (copied, destinations) |src, dst| for ([_]usize{ 0, 16 }) |start| {
        out[at] = active.mul(half(F, next.state[dst], start).sub(half(F, row.state[src], start)));
        at += 1;
    };
    for ([_]usize{ 0, 16 }) |start| for (0..8) |i| {
        out[at] = fixed.first.mul(half(F, row.state[i], start).sub(field(F, (statement.initial[i] >> @intCast(start)) & 0xffff)));
        at += 1;
    };
    for ([_]usize{ 0, 16 }) |start| for (0..8) |i| {
        out[at] = fixed.terminal.mul(half(F, row.state[i], start).sub(field(F, (statement.final[i] >> @intCast(start)) & 0xffff)));
        at += 1;
    };
    for ([_]usize{ 0, 16 }) |start| for (0..8) |i| {
        out[at] = pad.mul(half(F, row.state[i], start));
        at += 1;
    };
    const no_round = one.sub(active);
    for ([_]usize{ 0, 16 }) |start| {
        out[at] = no_round.mul(half(F, row.t1, start));
        at += 1;
    }
    for (row.carries) |carry| {
        out[at] = no_round.mul(carry);
        at += 1;
    }
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
        const i = storageIndex(t);
        @constCast(result.values[0].values)[i] = M31.one();
        @constCast(result.values[1].values)[i] = M31.fromCanonical(@intFromBool(t == 0));
        const w = schedule[t];
        const k = sha.round_constants[t];
        @constCast(result.values[3].values)[i] = M31.fromCanonical(w & 0xffff);
        @constCast(result.values[4].values)[i] = M31.fromCanonical(w >> 16);
        @constCast(result.values[5].values)[i] = M31.fromCanonical(k & 0xffff);
        @constCast(result.values[6].values)[i] = M31.fromCanonical(k >> 16);
    }
    @constCast(result.values[2].values)[storageIndex(terminal_row)] = M31.one();
    return result;
}

fn setWord(bits: *[32]M31, value: u32) void {
    for (bits, 0..) |*bit, i| bit.* = M31.fromCanonical((value >> @intCast(i)) & 1);
}

pub fn writeMain(allocator: std.mem.Allocator, statement: Statement) !Columns {
    const result = try allocateColumns(allocator, main_width);
    var state = statement.initial;
    for (0..terminal_row + 1) |t| {
        var row: Row(M31) = .{ .state = @splat(@splat(M31.zero())), .t1 = @splat(M31.zero()), .carries = @splat(M31.zero()) };
        for (&row.state, state) |*bits, value| setWord(bits, value);
        if (t < active_rows) {
            const s1 = sha.sigmaBig1(state[4]);
            const chv = sha.choose(state[4], state[5], state[6]);
            const t1 = state[7] +% s1 +% chv +% sha.round_constants[t] +% statement.schedule[t];
            setWord(&row.t1, t1);
            const low = (state[7] & 0xffff) + (s1 & 0xffff) + (chv & 0xffff) + (sha.round_constants[t] & 0xffff) + (statement.schedule[t] & 0xffff);
            const high = (state[7] >> 16) + (s1 >> 16) + (chv >> 16) + (sha.round_constants[t] >> 16) + (statement.schedule[t] >> 16) + (low >> 16);
            const s0 = sha.sigmaBig0(state[0]);
            const majv = sha.majority(state[0], state[1], state[2]);
            const alow = (t1 & 0xffff) + (s0 & 0xffff) + (majv & 0xffff);
            const ahigh = (t1 >> 16) + (s0 >> 16) + (majv >> 16) + (alow >> 16);
            const elow = (state[3] & 0xffff) + (t1 & 0xffff);
            const ehigh = (state[3] >> 16) + (t1 >> 16) + (elow >> 16);
            row.carries = .{ M31.fromCanonical(low >> 16), M31.fromCanonical(high >> 16), M31.fromCanonical(alow >> 16), M31.fromCanonical(ahigh >> 16), M31.fromCanonical(elow >> 16), M31.fromCanonical(ehigh >> 16) };
            state = sha.round(state, statement.schedule[t], sha.round_constants[t]);
        }
        const values = flatten(M31, row);
        const i = storageIndex(t);
        for (result.values, values) |column, value| @constCast(column.values)[i] = value;
    }
    if (!std.meta.eql(state, statement.final)) return error.InvalidShaRoundTerminal;
    return result;
}

pub const Component = struct {
    statement: Statement,
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
        if (max_log_degree_bound < log_size) return error.InvalidShaRoundTrace;
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
        const next = point.add(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
        for (main) |*column| {
            column.* = try allocator.dupe(CirclePointQM31, &.{ point, next });
            ready += 1;
        }
        return .initOwned(try allocator.dupe([][]CirclePointQM31, &.{ fixed, main }));
    }
    pub fn preprocessedColumnIndices(_: *const @This(), allocator: std.mem.Allocator) ![]usize {
        const indices = try allocator.alloc(usize, fixed_width);
        for (indices, 0..) |*i, n| i.* = n;
        return indices;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *PointEvaluationAccumulator, max_log_degree_bound: u32) !void {
        if (mask.items.len < 2 or mask.items[0].len != fixed_width or mask.items[1].len != main_width or max_log_degree_bound < log_size) return error.InvalidShaRoundTrace;
        var fixed_values: [fixed_width]QM31 = undefined;
        for (&fixed_values, mask.items[0]) |*value, col| {
            if (col.len != 1) return error.InvalidShaRoundTrace;
            value.* = col[0];
        }
        var current: [main_width]QM31 = undefined;
        var next: [main_width]QM31 = undefined;
        for (&current, &next, mask.items[1]) |*a, *b, col| {
            if (col.len != 2) return error.InvalidShaRoundTrace;
            a.* = col[0];
            b.* = col[1];
        }
        const constraints = evaluate(QM31, unflatten(QM31, current), unflatten(QM31, next), fixedAt(QM31, fixed_values), self.statement);
        const denominator = core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(max_log_degree_bound - log_size));
        const inverse = try denominator.inv();
        for (constraints) |constraint| accumulator.accumulate(constraint.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const Trace, accumulator: *DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len < 2 or trace.polys.items[0].len != fixed_width or trace.polys.items[1].len != main_width) return error.InvalidShaRoundTrace;
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
        for (trace.polys.items[0], evaluations[0..fixed_width]) |poly, *slot| slot.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        for (trace.polys.items[1], evaluations[fixed_width..]) |poly, *slot| slot.* = try evaluationOnDomain(allocator, poly, eval_log, n, &buffers);
        if (buffers.items.len != 0) {
            var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
            defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
            const view = prover.poly.twiddles.TwiddleTree([]const M31).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
            try prover.poly.circle.poly.evaluateBuffersWithTwiddles(buffers.items, domain, view);
        }
        var inverse: [8]M31 = undefined;
        for (&inverse, 0..) |*slot, i| slot.* = try core.constraints.cosetVanishing(M31, canonic.CanonicCoset.new(log_size).coset(), domain.at(core.utils.bitReverseIndex(i, eval_log - log_size))).inv();
        var columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = n_constraints }});
        defer allocator.free(columns);
        const column = &columns[0];
        for (0..n) |row_index| {
            var fixed_values: [fixed_width]QM31 = undefined;
            var current: [main_width]QM31 = undefined;
            var next: [main_width]QM31 = undefined;
            for (&fixed_values, evaluations[0..fixed_width]) |*value, source| value.* = QM31.fromBase(source[row_index]);
            const next_index = core.utils.offsetBitReversedCircleDomainIndex(row_index, log_size, eval_log, 1);
            for (&current, &next, evaluations[fixed_width..]) |*a, *b, source| {
                a.* = QM31.fromBase(source[row_index]);
                b.* = QM31.fromBase(source[next_index]);
            }
            const constraints = evaluate(QM31, unflatten(QM31, current), unflatten(QM31, next), fixedAt(QM31, fixed_values), self.statement);
            var sum = QM31.zero();
            for (constraints, 0..) |constraint, i| sum = sum.add(column.random_coeff_powers[n_constraints - 1 - i].mul(constraint));
            column.accumulate(row_index, sum.mulM31(inverse[row_index >> @intCast(log_size)]));
        }
    }
};

fn evaluationOnDomain(allocator: std.mem.Allocator, poly: prover.air.component_prover.Poly, eval_log: u32, n: usize, buffers: *std.ArrayList([]M31)) ![]const M31 {
    try poly.validate();
    if (poly.log_size == eval_log) return poly.values;
    const coefficients = poly.coefficients orelse return error.InvalidShaRoundTrace;
    if (coefficients.logSize() != log_size) return error.InvalidShaRoundTrace;
    const values = try allocator.alloc(M31, n);
    errdefer allocator.free(values);
    const source = coefficients.coefficients();
    @memcpy(values[0..source.len], source);
    @memset(values[source.len..], M31.zero());
    try buffers.append(allocator, values);
    return values;
}

pub fn validateCommittedTrace(statement: Statement, fixed: []const ColumnEvaluation, main: []const ColumnEvaluation) !void {
    if (fixed.len != fixed_width or main.len != main_width) return error.InvalidShaRoundTrace;
    for (0..rows) |storage| {
        const next_storage = core.utils.offsetBitReversedCircleDomainIndex(storage, log_size, log_size, 1);
        var fv: [fixed_width]M31 = undefined;
        var mv: [main_width]M31 = undefined;
        var nv: [main_width]M31 = undefined;
        for (&fv, fixed) |*slot, col| slot.* = col.values[storage];
        for (&mv, &nv, main) |*a, *b, col| {
            a.* = col.values[storage];
            b.* = col.values[next_storage];
        }
        for (evaluate(M31, unflatten(M31, mv), unflatten(M31, nv), fixedAt(M31, fv), statement)) |constraint|
            if (!constraint.isZero()) return error.InvalidShaRoundConstraint;
    }
}
