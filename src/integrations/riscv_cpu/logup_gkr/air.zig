//! Experimental mini-AIR for the LS scalar-range family (WGKR-LS-RANGE-v0).
//!
//! Components, in this order and therefore in this tree column order:
//!   consumer instance 0 (LS rows), optional consumer instance 1 (LS tail),
//!   range-hi table (2^hi_log rows), range-lo table (2^lo_log rows).
//! The consumer has two variants over the SAME MAIN columns:
//!   classic: 8 paired-inverse QM31 columns + 1 cyclic prefix (36 INTER cols),
//!            mirroring load_store_v2/local_lookup.zig;
//!   gkr:     eq column c and weighted-sum prefix S (8 INTER cols) that bind the
//!            GKR terminal claim delta to MAIN (design note section 5).
//! Tables are classic LogUp in both variants (inverse + cyclic prefix).
const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const circle = core.circle;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const utils = core.utils;
const engine = @import("stwo_prover_engine");
const prover_air_accumulation = engine.air.accumulation;
const prover_component = engine.air.component_prover;
const prover_circle = engine.poly.circle;
const prover_twiddles = engine.poly.twiddles;
const W = @import("witness.zig");
const MP = @import("mle_point.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const LANES = W.LANES;

pub const CLASSIC_PAIRS: usize = LANES / 2;
pub const CLASSIC_INTER: usize = 4 * CLASSIC_PAIRS + 4;
pub const GKR_INTER: usize = 8;
pub const TABLE_INTER: usize = 8;

pub const Variant = enum(u32) {
    classic = 0,
    gkr = 1,
    pub fn consumerInter(self: Variant) usize {
        return switch (self) {
            .classic => CLASSIC_INTER,
            .gkr => GKR_INTER,
        };
    }
};

/// Range relation challenges, drawn after MAIN is committed.
pub const Challenges = struct {
    z_hi: QM31,
    c_hi: QM31,
    z_lo: QM31,
    c_lo: QM31,
    pub fn draw(channel: anytype) Challenges {
        return .{ .z_hi = channel.drawSecureFelt(), .c_hi = channel.drawSecureFelt(), .z_lo = channel.drawSecureFelt(), .c_lo = channel.drawSecureFelt() };
    }
    pub fn offset(self: Challenges, lane: usize) QM31 {
        return if (lane < W.HI_LANES) self.z_hi else self.z_lo;
    }
    pub fn coefficient(self: Challenges, lane: usize) QM31 {
        return if (lane < W.HI_LANES) self.c_hi else self.c_lo;
    }
    /// D_j(v) = z_j - c_j * v
    pub fn denominator(self: Challenges, lane: usize, value: QM31) QM31 {
        return self.offset(lane).sub(self.coefficient(lane).mul(value));
    }
    pub fn denominatorBase(self: Challenges, lane: usize, value: M31) QM31 {
        return self.offset(lane).sub(self.coefficient(lane).mulM31(value));
    }
};

/// Column offsets shared by prover and receiver; derived from geometry only.
pub const Geometry = struct {
    statement: W.Statement,
    variant: Variant,
    pub fn mainOffset(_: Geometry, instance: usize) usize {
        return instance * LANES;
    }
    pub fn tableMainOffset(self: Geometry, hi: bool) usize {
        return self.statement.instanceCount() * LANES + @as(usize, if (hi) 0 else 1);
    }
    pub fn interOffset(self: Geometry, instance: usize) usize {
        return instance * self.variant.consumerInter();
    }
    pub fn tableInterOffset(self: Geometry, hi: bool) usize {
        return self.statement.instanceCount() * self.variant.consumerInter() + @as(usize, if (hi) 0 else TABLE_INTER);
    }
    pub fn mainLogs(self: Geometry, a: std.mem.Allocator) ![]u32 {
        var out = std.ArrayList(u32).empty;
        errdefer out.deinit(a);
        for (0..self.statement.instanceCount()) |i| try out.appendNTimes(a, self.statement.instanceLog(i), LANES);
        try out.append(a, self.statement.hi_log);
        try out.append(a, self.statement.lo_log);
        return out.toOwnedSlice(a);
    }
    pub fn interLogs(self: Geometry, a: std.mem.Allocator) ![]u32 {
        var out = std.ArrayList(u32).empty;
        errdefer out.deinit(a);
        for (0..self.statement.instanceCount()) |i| try out.appendNTimes(a, self.statement.instanceLog(i), self.variant.consumerInter());
        try out.appendNTimes(a, self.statement.hi_log, TABLE_INTER);
        try out.appendNTimes(a, self.statement.lo_log, TABLE_INTER);
        return out.toOwnedSlice(a);
    }
    pub fn preprocessedLogs(self: Geometry) [2]u32 {
        return .{ self.statement.hi_log, self.statement.lo_log };
    }
    pub fn interColumns(self: Geometry) usize {
        return self.statement.instanceCount() * self.variant.consumerInter() + 2 * TABLE_INTER;
    }
    pub fn interCells(self: Geometry) u64 {
        var total: u64 = 0;
        for (0..self.statement.instanceCount()) |i| total += self.variant.consumerInter() * (@as(u64, 1) << @intCast(self.statement.instanceLog(i)));
        total += TABLE_INTER * ((@as(u64, 1) << @intCast(self.statement.hi_log)) + (@as(u64, 1) << @intCast(self.statement.lo_log)));
        return total;
    }
};

// ---------------------------------------------------------------------------
// Classic consumer: 8 strict pair inverses + cyclic prefix.

pub const ClassicConsumer = struct {
    log_size: u32,
    main_offset: usize,
    inter_offset: usize,
    ch: Challenges,
    claim: QM31,

    pub const N_CONSTRAINTS: usize = CLASSIC_PAIRS + 1;
    const Adapter = core_air_derive.ComponentAdapter(@This(), prover_component.ComponentProver, prover_component.Trace, prover_air_accumulation.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn nConstraints(_: *const @This()) usize {
        return N_CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
        return logBounds(a, &.{}, LANES, self.log_size, CLASSIC_INTER, self.log_size);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: CirclePointQM31, max_log: u32) !core_air_components.MaskPoints {
        _ = self;
        var inter: [CLASSIC_INTER][]const isize = undefined;
        for (inter[0 .. 4 * CLASSIC_PAIRS]) |*o| o.* = &[_]isize{0};
        for (inter[4 * CLASSIC_PAIRS ..]) |*o| o.* = &[_]isize{ 0, -1 };
        return buildMask(a, point, max_log, 0, LANES, &inter);
    }
    pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
        return a.alloc(usize, 0);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core_air_components.MaskValues, acc: *core_air_accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidProofShape;
        const main = try maskSlice(mask.items[1], self.main_offset, LANES, 1);
        const inter = try maskSlice(mask.items[2], self.inter_offset, CLASSIC_INTER, 0);
        var m: [LANES]QM31 = undefined;
        for (&m, main) |*o, col| o.* = col[0];
        var inv: [CLASSIC_PAIRS]QM31 = undefined;
        for (&inv, 0..) |*o, k| o.* = try sampled(inter, 4 * k, 0);
        const s = try sampled(inter, 4 * CLASSIC_PAIRS, 0);
        const s_prev = try sampled(inter, 4 * CLASSIC_PAIRS, 1);
        const row = try self.rowConstraints(m, inv, s, s_prev);
        try accumulatePoint(acc, point, max_log, self.log_size, &row);
    }
    pub fn rowConstraints(self: *const @This(), m: [LANES]QM31, inv: [CLASSIC_PAIRS]QM31, s: QM31, s_prev: QM31) ![N_CONSTRAINTS]QM31 {
        var out: [N_CONSTRAINTS]QM31 = undefined;
        var contribution = QM31.zero();
        for (0..CLASSIC_PAIRS) |k| {
            const a = self.ch.denominator(2 * k, m[2 * k]);
            const b = self.ch.denominator(2 * k + 1, m[2 * k + 1]);
            out[k] = inv[k].mul(a).mul(b).sub(QM31.one());
            contribution = contribution.add(a.add(b).mul(inv[k]));
        }
        const shift = try self.claim.divM31(rowsM31(self.log_size));
        out[CLASSIC_PAIRS] = s.sub(s_prev).sub(contribution).add(shift);
        return out;
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const prover_component.Trace, accumulator: *prover_air_accumulation.DomainEvaluationAccumulator) !void {
        const a = accumulator.allocator;
        var ctx = try DomainContext.init(a, self.log_size);
        defer ctx.deinit();
        var main: [LANES][]const M31 = undefined;
        for (&main, 0..) |*o, j| o.* = try ctx.column(trace.polys.items[1][self.main_offset + j]);
        var inter: [CLASSIC_INTER][]const M31 = undefined;
        for (&inter, 0..) |*o, j| o.* = try ctx.column(trace.polys.items[2][self.inter_offset + j]);
        try ctx.extend();
        var cols = try accumulator.columns(a, &.{.{ .log_size = ctx.eval_log, .n_cols = N_CONSTRAINTS }});
        defer a.free(cols);
        const column = &cols[0];
        for (0..ctx.eval_size) |row| {
            const prev = utils.offsetBitReversedCircleDomainIndex(row, self.log_size, ctx.eval_log, -1);
            var m: [LANES]QM31 = undefined;
            for (&m, main) |*o, col| o.* = QM31.fromBase(col[row]);
            var inv: [CLASSIC_PAIRS]QM31 = undefined;
            for (&inv, 0..) |*o, k| o.* = secureAt(inter[4 * k ..][0..4], row);
            const s = secureAt(inter[4 * CLASSIC_PAIRS ..][0..4], row);
            const s_prev = secureAt(inter[4 * CLASSIC_PAIRS ..][0..4], prev);
            const values = try self.rowConstraints(m, inv, s, s_prev);
            ctx.accumulate(column, row, &values);
        }
    }
};

// ---------------------------------------------------------------------------
// GKR consumer: eq column + weighted prefix binding delta = Vtilde(r).

pub const GkrConsumer = struct {
    log_size: u32,
    main_offset: usize,
    inter_offset: usize,
    /// r_row (MSB-first over storage-index bits), receiver-derived.
    point: MP.MleEvalPoint,
    /// E(p) = k_const - sum_j u[j] * m_j(p)
    k_const: QM31,
    u: [LANES]QM31,
    /// Terminal denominator claim of this instance (from the GKR verifier).
    delta: QM31,

    pub const N_CONSTRAINTS: usize = 3;
    const Adapter = core_air_derive.ComponentAdapter(@This(), prover_component.ComponentProver, prover_component.Trace, prover_air_accumulation.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn nConstraints(_: *const @This()) usize {
        return N_CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
        return logBounds(a, &.{}, LANES, self.log_size, GKR_INTER, self.log_size);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: CirclePointQM31, max_log: u32) !core_air_components.MaskPoints {
        _ = self;
        var inter: [GKR_INTER][]const isize = undefined;
        for (inter[0..4]) |*o| o.* = &[_]isize{ 0, 2 };
        for (inter[4..]) |*o| o.* = &[_]isize{ 0, -1 };
        return buildMask(a, point, max_log, 0, LANES, &inter);
    }
    pub fn preprocessedColumnIndices(_: *const @This(), a: std.mem.Allocator) ![]usize {
        return a.alloc(usize, 0);
    }
    pub fn rowConstraints(self: *const @This(), m: [LANES]QM31, c: QM31, c_next2: QM31, s: QM31, s_prev: QM31, q: QM31, first: QM31, second: QM31) ![N_CONSTRAINTS]QM31 {
        var e = self.k_const;
        for (m, self.u) |v, w| e = e.sub(w.mul(v));
        const shift = try self.delta.divM31(rowsM31(self.log_size));
        return .{
            c.sub(self.point.eq0).mul(first).add(c.sub(self.point.eq1).mul(second)),
            c.sub(c_next2.mul(q)),
            s.sub(s_prev).sub(c.mul(e)).add(shift),
        };
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core_air_components.MaskValues, acc: *core_air_accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidProofShape;
        const main = try maskSlice(mask.items[1], self.main_offset, LANES, 1);
        const inter = try maskSlice(mask.items[2], self.inter_offset, GKR_INTER, 0);
        var m: [LANES]QM31 = undefined;
        for (&m, main) |*o, col| o.* = col[0];
        const folded = point.repeatedDouble(max_log - self.log_size);
        const q = try MP.evalCarryQuotient(&self.point, folded);
        const anchors = try MP.evalAnchors(self.log_size, folded);
        const row = try self.rowConstraints(m, try sampled(inter, 0, 0), try sampled(inter, 0, 1), try sampled(inter, 4, 0), try sampled(inter, 4, 1), q, anchors[0], anchors[1]);
        try accumulatePoint(acc, point, max_log, self.log_size, &row);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const prover_component.Trace, accumulator: *prover_air_accumulation.DomainEvaluationAccumulator) !void {
        const a = accumulator.allocator;
        var ctx = try DomainContext.init(a, self.log_size);
        defer ctx.deinit();
        var main: [LANES][]const M31 = undefined;
        for (&main, 0..) |*o, j| o.* = try ctx.column(trace.polys.items[1][self.main_offset + j]);
        var inter: [GKR_INTER][]const M31 = undefined;
        for (&inter, 0..) |*o, j| o.* = try ctx.column(trace.polys.items[2][self.inter_offset + j]);
        // Auxiliary verifier-succinct columns (never committed): q, is_first, is_second.
        const n = @as(usize, 1) << @intCast(self.log_size);
        const q_trace = try MP.genCarryQuotientCol(a, &self.point);
        defer a.free(q_trace);
        var aux: [6][]const M31 = undefined;
        for (0..4) |coord| {
            const values = try a.alloc(M31, n);
            defer a.free(values);
            for (q_trace, values) |v, *o| o.* = v.toM31Array()[coord];
            aux[coord] = try ctx.interpolated(values);
        }
        for (0..2) |k| {
            const values = try a.alloc(M31, n);
            defer a.free(values);
            @memset(values, M31.zero());
            values[MP.storageIndex(k, self.log_size)] = M31.one();
            aux[4 + k] = try ctx.interpolated(values);
        }
        try ctx.extend();
        var cols = try accumulator.columns(a, &.{.{ .log_size = ctx.eval_log, .n_cols = N_CONSTRAINTS }});
        defer a.free(cols);
        const column = &cols[0];
        for (0..ctx.eval_size) |row| {
            const prev = utils.offsetBitReversedCircleDomainIndex(row, self.log_size, ctx.eval_log, -1);
            const next2 = utils.offsetBitReversedCircleDomainIndex(row, self.log_size, ctx.eval_log, 2);
            var m: [LANES]QM31 = undefined;
            for (&m, main) |*o, col| o.* = QM31.fromBase(col[row]);
            const values = try self.rowConstraints(
                m,
                secureAt(inter[0..4], row),
                secureAt(inter[0..4], next2),
                secureAt(inter[4..8], row),
                secureAt(inter[4..8], prev),
                secureAt(aux[0..4], row),
                QM31.fromBase(aux[4][row]),
                QM31.fromBase(aux[5][row]),
            );
            ctx.accumulate(column, row, &values);
        }
    }
};

// ---------------------------------------------------------------------------
// Range table: preprocessed value, MAIN multiplicity, inverse + cyclic prefix.

pub const Table = struct {
    log_size: u32,
    preprocessed_index: usize,
    main_offset: usize,
    inter_offset: usize,
    /// Lane whose challenges this table uses (0 = hi, HI_LANES = lo).
    lane: usize,
    ch: Challenges,
    claim: QM31,

    pub const N_CONSTRAINTS: usize = 2;
    const Adapter = core_air_derive.ComponentAdapter(@This(), prover_component.ComponentProver, prover_component.Trace, prover_air_accumulation.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn nConstraints(_: *const @This()) usize {
        return N_CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
        return logBounds(a, &.{self.log_size}, 1, self.log_size, TABLE_INTER, self.log_size);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: CirclePointQM31, max_log: u32) !core_air_components.MaskPoints {
        _ = self;
        var inter: [TABLE_INTER][]const isize = undefined;
        for (inter[0..4]) |*o| o.* = &[_]isize{0};
        for (inter[4..]) |*o| o.* = &[_]isize{ 0, -1 };
        return buildMask(a, point, max_log, 1, 1, &inter);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        return a.dupe(usize, &.{self.preprocessed_index});
    }
    pub fn rowConstraints(self: *const @This(), value: QM31, mult: QM31, inv: QM31, s: QM31, s_prev: QM31) ![N_CONSTRAINTS]QM31 {
        const d = self.ch.denominator(self.lane, value);
        const shift = try self.claim.divM31(rowsM31(self.log_size));
        // contribution = -m / d
        return .{ inv.mul(d).sub(QM31.one()), s.sub(s_prev).add(mult.mul(inv)).add(shift) };
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: CirclePointQM31, mask: *const core_air_components.MaskValues, acc: *core_air_accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidProofShape;
        const pre = try maskSlice(mask.items[0], self.preprocessed_index, 1, 1);
        const main = try maskSlice(mask.items[1], self.main_offset, 1, 1);
        const inter = try maskSlice(mask.items[2], self.inter_offset, TABLE_INTER, 0);
        const row = try self.rowConstraints(pre[0][0], main[0][0], try sampled(inter, 0, 0), try sampled(inter, 4, 0), try sampled(inter, 4, 1));
        try accumulatePoint(acc, point, max_log, self.log_size, &row);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const prover_component.Trace, accumulator: *prover_air_accumulation.DomainEvaluationAccumulator) !void {
        const a = accumulator.allocator;
        var ctx = try DomainContext.init(a, self.log_size);
        defer ctx.deinit();
        const value = try ctx.column(trace.polys.items[0][self.preprocessed_index]);
        const mult = try ctx.column(trace.polys.items[1][self.main_offset]);
        var inter: [TABLE_INTER][]const M31 = undefined;
        for (&inter, 0..) |*o, j| o.* = try ctx.column(trace.polys.items[2][self.inter_offset + j]);
        try ctx.extend();
        var cols = try accumulator.columns(a, &.{.{ .log_size = ctx.eval_log, .n_cols = N_CONSTRAINTS }});
        defer a.free(cols);
        const column = &cols[0];
        for (0..ctx.eval_size) |row| {
            const prev = utils.offsetBitReversedCircleDomainIndex(row, self.log_size, ctx.eval_log, -1);
            const values = try self.rowConstraints(QM31.fromBase(value[row]), QM31.fromBase(mult[row]), secureAt(inter[0..4], row), secureAt(inter[4..8], row), secureAt(inter[4..8], prev));
            ctx.accumulate(column, row, &values);
        }
    }
};

// ---------------------------------------------------------------------------
// Shared helpers.

fn rowsM31(log_size: u32) M31 {
    return M31.fromU64(@as(u64, 1) << @intCast(log_size));
}

fn logBounds(a: std.mem.Allocator, pre: []const u32, n_main: usize, main_log: u32, n_inter: usize, inter_log: u32) !core_air_components.TraceLogDegreeBounds {
    const p = try a.dupe(u32, pre);
    errdefer a.free(p);
    const m = try a.alloc(u32, n_main);
    errdefer a.free(m);
    @memset(m, main_log);
    const i = try a.alloc(u32, n_inter);
    errdefer a.free(i);
    @memset(i, inter_log);
    return core_air_components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ p, m, i }));
}

fn offsetPoint(point: CirclePointQM31, max_log: u32, offset: isize) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(max_log).step().mulSigned(offset);
    return point.add(.{ .x = QM31.fromBase(step.x), .y = QM31.fromBase(step.y) });
}

fn pointColumns(a: std.mem.Allocator, point: CirclePointQM31, max_log: u32, offsets: []const []const isize) ![][]CirclePointQM31 {
    const cols = try a.alloc([]CirclePointQM31, offsets.len);
    var made: usize = 0;
    errdefer {
        for (cols[0..made]) |c| a.free(c);
        a.free(cols);
    }
    for (cols, offsets) |*c, offs| {
        c.* = try a.alloc(CirclePointQM31, offs.len);
        for (c.*, offs) |*p, o| p.* = if (o == 0) point else offsetPoint(point, max_log, o);
        made += 1;
    }
    return cols;
}

fn buildMask(a: std.mem.Allocator, point: CirclePointQM31, max_log: u32, n_pre: usize, n_main: usize, inter: []const []const isize) !core_air_components.MaskPoints {
    var current: [LANES][]const isize = undefined;
    for (&current) |*c| c.* = &[_]isize{0};
    const pre = try pointColumns(a, point, max_log, current[0..n_pre]);
    errdefer freeCols(a, pre);
    const main = try pointColumns(a, point, max_log, current[0..n_main]);
    errdefer freeCols(a, main);
    const it = try pointColumns(a, point, max_log, inter);
    errdefer freeCols(a, it);
    return core_air_components.MaskPoints.initOwned(try a.dupe([][]CirclePointQM31, &.{ pre, main, it }));
}

fn freeCols(a: std.mem.Allocator, cols: [][]CirclePointQM31) void {
    for (cols) |c| a.free(c);
    a.free(cols);
}

fn maskSlice(tree: [][]QM31, offset: usize, n: usize, exact_points: usize) ![][]QM31 {
    if (offset + n > tree.len) return error.InvalidProofShape;
    const out = tree[offset .. offset + n];
    if (exact_points != 0) for (out) |c| if (c.len != exact_points) return error.InvalidProofShape;
    return out;
}

fn sampled(cols: [][]QM31, base: usize, point_index: usize) !QM31 {
    var coords: [4]QM31 = undefined;
    for (0..4) |k| {
        const col = cols[base + k];
        if (col.len <= point_index) return error.InvalidProofShape;
        coords[k] = col[point_index];
    }
    return QM31.fromPartialEvals(coords);
}

fn secureAt(cols: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(cols[0][row], cols[1][row], cols[2][row], cols[3][row]);
}

fn accumulatePoint(acc: *core_air_accumulation.PointEvaluationAccumulator, point: CirclePointQM31, max_log: u32, log_size: u32, values: []const QM31) !void {
    const fold = max_log - log_size;
    const denom_inv = try core_constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(log_size).coset(), point.repeatedDouble(fold)).inv();
    for (values) |v| acc.accumulate(v.mul(denom_inv));
}

/// Per-component evaluation of committed and auxiliary columns on the
/// component's own 2x domain.
const DomainContext = struct {
    a: std.mem.Allocator,
    log_size: u32,
    eval_log: u32,
    eval_size: usize,
    buffers: std.ArrayList([]M31) = .empty,
    denom_inv: [2]M31,

    fn init(a: std.mem.Allocator, log_size: u32) !DomainContext {
        const eval_log = log_size + 1;
        const eval_domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const coset = canonic.CanonicCoset.new(log_size).coset();
        return .{
            .a = a,
            .log_size = log_size,
            .eval_log = eval_log,
            .eval_size = eval_domain.size(),
            .denom_inv = .{
                try core_constraints.cosetVanishing(M31, coset, eval_domain.at(0)).inv(),
                try core_constraints.cosetVanishing(M31, coset, eval_domain.at(1)).inv(),
            },
        };
    }
    fn deinit(self: *DomainContext) void {
        for (self.buffers.items) |b| self.a.free(b);
        self.buffers.deinit(self.a);
    }
    /// Committed column on the eval domain (LDE values or extended coefficients).
    fn column(self: *DomainContext, poly: prover_component.Poly) ![]const M31 {
        try poly.validate();
        if (poly.log_size == self.eval_log) return poly.values;
        const coefficients = poly.coefficients orelse return error.InvalidProofShape;
        if (coefficients.logSize() != self.log_size) return error.InvalidProofShape;
        return self.pushCoefficients(coefficients.coefficients());
    }
    /// Interpolates trace-domain storage-order values; extended by `extend`.
    fn interpolated(self: *DomainContext, values: []const M31) ![]const M31 {
        const domain = canonic.CanonicCoset.new(self.log_size).circleDomain();
        var coeffs = try prover_circle.poly.interpolateFromEvaluation(self.a, try prover_circle.evaluation.CircleEvaluation.init(domain, values));
        defer coeffs.deinit(self.a);
        return self.pushCoefficients(coeffs.coefficients());
    }
    fn pushCoefficients(self: *DomainContext, source: []const M31) ![]const M31 {
        const values = try self.a.alloc(M31, self.eval_size);
        errdefer self.a.free(values);
        @memcpy(values[0..source.len], source);
        @memset(values[source.len..], M31.zero());
        try self.buffers.append(self.a, values);
        return values;
    }
    fn extend(self: *DomainContext) !void {
        if (self.buffers.items.len == 0) return;
        const eval_domain = canonic.CanonicCoset.new(self.eval_log).circleDomain();
        var twiddles = try prover_twiddles.precomputeM31(self.a, eval_domain.half_coset);
        defer prover_twiddles.deinitM31(self.a, &twiddles);
        const view = prover_twiddles.TwiddleTree([]const M31).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles);
        try prover_circle.poly.evaluateBuffersWithTwiddles(self.buffers.items, eval_domain, view);
    }
    fn accumulate(self: *DomainContext, target: *prover_air_accumulation.ColumnAccumulator, row: usize, values: []const QM31) void {
        var combined = QM31.zero();
        for (values, 0..) |v, i| combined = combined.add(target.random_coeff_powers[values.len - 1 - i].mul(v));
        target.accumulate(row, combined.mulM31(self.denom_inv[row >> @intCast(self.log_size)]));
    }
};
