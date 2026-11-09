//! Bounded one-call physical arithmetic fixture, with explicit public input
//! authority and classic BYTE closure. It is not a production service adapter.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const S = @import("spec.zig");
const R = @import("row.zig");
const A = @import("air.zig");
const E = @import("../../evaluation.zig");
const G = @import("../../geometry.zig");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
pub const Q = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
const Air = core.air.components.ForField(Q);
const CP = engine.air.component_prover.ForField(Q);
const Acc = engine.air.accumulation.ForField(Q);
const Wire = @import("../curves/equations.zig").WireFor(Q);
pub const LOG: u32 = 8;
pub const ROWS = 256;
pub const KIND: u32 = 0x44454e53;
pub const Challenges = struct { byte: Q, wire: Wire };
pub fn draw(channel: anytype) Challenges {
    return .{ .byte = channel.drawSecureFelt(), .wire = Wire.draw(channel) };
}
pub fn Layout(comptime kind: S.Kind) type {
    return struct {
        pub const Row = R.Layout(kind);
        pub const BYTE_FRACTIONS = Row.BYTE_QUERIES + 1;
        pub const BATCHES = (BYTE_FRACTIONS + 1) / 2;
        pub const BYTE_LAST = 8 * (BATCHES - 1);
        pub const OUTPUT = 8 * BATCHES;
        pub const INTER = OUTPUT + 8;
        pub const CONSTRAINTS = A.constraints(kind) + BATCHES + 1;
    };
}
inline fn k(comptime F: type, v: u32) F {
    return E.qFor(F, v);
}
pub fn rangeFraction(comptime kind: S.Kind, comptime F: type, v: anytype, beta: Q, index: usize) struct { F, E.SecureFor(F) } {
    const L = Layout(kind);
    if (index < L.Row.BYTE_QUERIES) return .{ v.main(0), E.splatFor(F, beta).sub(E.liftFor(F, A.query(kind, F, v, index))) };
    if (index == L.Row.BYTE_QUERIES) return .{ v.main(L.Row.MULT).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(A.FIX_BYTE))) };
    return .{ F.zero(), E.SecureFor(F).one() };
}
pub fn outputDenominator(comptime kind: S.Kind, comptime F: type, v: anytype, ch: Challenges) E.SecureFor(F) {
    const L = Layout(kind);
    var tuple: [35]F = undefined;
    tuple[0] = k(F, KIND);
    tuple[1] = F.one();
    var coord = F.zero();
    inline for (0..12) |i| coord = coord.add(v.fixed(i).mul(k(F, i)));
    tuple[2] = coord;
    for (tuple[3..], 0..) |*x, i| x.* = v.main(L.Row.OUTPUT + i);
    return E.denominatorFor(F, ch.wire.offset, &ch.wire.coefficients, &tuple, true);
}
fn secure(comptime F: type, v: anytype, start: usize, previous: bool) E.SecureFor(F) {
    var c: [8]F = undefined;
    for (&c, 0..) |*x, i| x.* = if (previous) v.previous(start + i) else v.interaction(start + i);
    return E.secureFromCoordinatesForField(Q, F, c);
}
pub fn emit(comptime kind: S.Kind, comptime F: type, v: anytype, input: *const [S.inputs(kind)]u256, ch: Challenges, claim: Q, sink: *E.SinkFor(F)) void {
    const L = Layout(kind);
    A.emit(kind, F, v, input, sink);
    for (0..L.BATCHES) |b| {
        var delta = secure(F, v, 8 * b, false);
        if (b > 0) delta = delta.sub(secure(F, v, 8 * (b - 1), false)) else delta = delta.sub(secure(F, v, L.BYTE_LAST, true));
        const left = rangeFraction(kind, F, v, ch.byte, 2 * b);
        const right = rangeFraction(kind, F, v, ch.byte, 2 * b + 1);
        sink.emit(delta.mul(left[1]).mul(right[1]).sub(E.mulBaseFor(F, right[1], left[0])).sub(E.mulBaseFor(F, left[1], right[0])));
    }
    const inv_rows = Q.fromBase((M.fromCanonical(ROWS).inv() catch unreachable));
    const delta = secure(F, v, L.OUTPUT, false).sub(secure(F, v, L.OUTPUT, true)).add(E.splatFor(F, claim.mul(inv_rows)));
    sink.emit(delta.mul(outputDenominator(kind, F, v, ch)).sub(E.liftFor(F, v.main(0))));
}
pub fn Component(comptime kind: S.Kind) type {
    return struct {
        const Self = @This();
        pub const L = Layout(kind);
        const Point = core.circle.CirclePoint(Q);
        input: *const [S.inputs(kind)]u256,
        ch: Challenges,
        claim: Q,
        log_size: u32 = LOG,
        const Adapter = core.air.derive.ForField(Q).ComponentAdapter(Self, CP.ComponentProver, CP.Trace, Acc.DomainEvaluationAccumulator);
        pub fn validate(self: *const Self) !void {
            if (self.log_size != LOG) return error.DenseFixtureGeometry;
        }
        pub fn widths(_: *const Self) [3]usize {
            return .{ A.FIXED, L.Row.MAIN, L.INTER };
        }
        pub fn nConstraints(_: *const Self) usize {
            return L.CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(_: *const Self) u32 {
            return LOG + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= L.CONSTRAINTS) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn asProverComponent(self: *const Self) CP.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) Air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
            try self.validate();
            const result = try a.alloc([]u32, 3);
            errdefer a.free(result);
            var n: usize = 0;
            errdefer for (result[0..n]) |v| a.free(v);
            for (self.widths(), result) |w, *v| {
                v.* = try a.alloc(u32, w);
                @memset(v.*, LOG);
                n += 1;
            }
            return Air.TraceLogDegreeBounds.initOwned(result);
        }
        pub fn preprocessedColumnIndices(_: *const Self, a: std.mem.Allocator) ![]usize {
            const out = try a.alloc(usize, A.FIXED);
            for (out, 0..) |*v, i| v.* = i;
            return out;
        }
        pub fn previousColumn(c: usize) bool {
            return c >= L.BYTE_LAST and c < L.BYTE_LAST + 8 or c >= L.OUTPUT;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
            try self.validate();
            _ = try G.localPointFor(Q, point, global_log, LOG);
            const result = try a.alloc([][]Point, 3);
            errdefer a.free(result);
            var count: usize = 0;
            errdefer for (result[0..count]) |tree| {
                for (tree) |col| a.free(col);
                a.free(tree);
            };
            for (self.widths(), result, 0..) |width, *tree, t| {
                tree.* = try a.alloc([]Point, width);
                var n: usize = 0;
                errdefer {
                    for (tree.*[0..n]) |v| a.free(v);
                    a.free(tree.*);
                }
                for (tree.*, 0..) |*col, c| {
                    const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step;
                    col.* = if (t == 2 and previousColumn(c)) try a.dupe(Point, &.{ point, point.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) }) }) else try a.dupe(Point, &.{point});
                    n += 1;
                }
                count += 1;
            }
            return Air.MaskPoints.initOwned(result);
        }
        const Mask = struct {
            mask: *const Air.MaskValues,
            pub fn fixed(v: *const @This(), c: usize) Q {
                return v.mask.items[0][c][0];
            }
            pub fn main(v: *const @This(), c: usize) Q {
                return v.mask.items[1][c][0];
            }
            pub fn interaction(v: *const @This(), c: usize) Q {
                return v.mask.items[2][c][0];
            }
            pub fn previous(v: *const @This(), c: usize) Q {
                return v.mask.items[2][c][1];
            }
        };
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const Air.MaskValues, acc: *core.air.accumulation.ForField(Q).PointEvaluationAccumulator, global_log: u32) !void {
            try self.validate();
            if (mask.items.len < 3) return error.DenseFixtureMask;
            for (self.widths(), 0..) |w, t| {
                if (mask.items[t].len != w) return error.DenseFixtureMask;
                for (mask.items[t], 0..) |col, c| if (col.len != @as(usize, if (t == 2 and previousColumn(c)) 2 else 1)) return error.DenseFixtureMask;
            }
            var sink = E.SinkFor(Q){ .accumulator = acc, .scale = try G.denominatorInverseFor(Q, point, global_log, LOG) };
            const view = Mask{ .mask = mask };
            emit(kind, Q, &view, self.input, self.ch, self.claim, &sink);
            std.debug.assert(sink.count == L.CONSTRAINTS);
        }
        const F = E.PackedFields.BaseForField(Q);
        const Packed = struct {
            columns: []const []const M,
            start: usize,
            old: [16]F,
            pub fn fixed(v: *const @This(), c: usize) F {
                return F.load(v.columns[c].ptr + v.start);
            }
            pub fn main(v: *const @This(), c: usize) F {
                return F.load(v.columns[A.FIXED + c].ptr + v.start);
            }
            pub fn interaction(v: *const @This(), c: usize) F {
                return F.load(v.columns[A.FIXED + L.Row.MAIN + c].ptr + v.start);
            }
            pub fn previous(v: *const @This(), c: usize) F {
                return v.old[if (c >= L.OUTPUT) 8 + c - L.OUTPUT else c - L.BYTE_LAST];
            }
        };
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, acc: *Acc.DomainEvaluationAccumulator) !void {
            try self.validate();
            const a = acc.allocator;
            const total = A.FIXED + L.Row.MAIN + L.INTER;
            if (trace.polys.items.len != 3) return error.DenseFixtureTrace;
            const polys = try a.alloc(CP.Poly, total);
            defer a.free(polys);
            var at: usize = 0;
            for (self.widths(), 0..) |width, t| {
                if (trace.polys.items[t].len != width) return error.DenseFixtureTrace;
                @memcpy(polys[at..][0..width], trace.polys.items[t]);
                at += width;
            }
            const domain = core.poly.circle.canonic.CanonicCoset.new(LOG + 1).circleDomain();
            const n = domain.size();
            var owned_count: usize = 0;
            for (polys) |p| owned_count += @intFromBool(try support.sourceNeedsExtension(p, LOG, LOG + 1));
            const owned = try a.alloc([]M, owned_count);
            defer a.free(owned);
            var initialized: usize = 0;
            defer for (owned[0..initialized]) |v| a.free(v);
            const evals = try a.alloc([]const M, total);
            defer a.free(evals);
            for (polys, evals) |p, *v| v.* = try support.evaluationValues(a, p, LOG + 1, n, owned, &initialized);
            var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &tw);
            try @import("../../providers/domain_transform.zig").evaluate(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles), null);
            const inverses = try G.denominatorInverses(a, LOG, LOG + 1);
            defer a.free(inverses);
            const outputs = try acc.columns(a, &.{.{ .log_size = LOG + 1, .n_cols = L.CONSTRAINTS }});
            defer a.free(outputs);
            var output = outputs[0];
            var start: usize = 0;
            while (start < n) : (start += E.LANES) {
                var v = Packed{ .columns = evals, .start = start, .old = undefined };
                for (&v.old, 0..) |*old, j| {
                    var lanes: [E.LANES]M = undefined;
                    const c = if (j < 8) L.BYTE_LAST + j else L.OUTPUT + j - 8;
                    for (&lanes, 0..) |*x, i| x.* = evals[A.FIXED + L.Row.MAIN + c][core.utils.previousBitReversedCircleDomainIndex(start + i, LOG, LOG + 1)];
                    old.* = F.fromLanes(lanes);
                }
                var weighted = E.WeightedAccumulatorFor(F){ .powers = output.random_coeff_powers };
                var sink = E.SinkFor(F){ .weighted_accumulator = &weighted };
                emit(kind, F, &v, self.input, self.ch, self.claim, &sink);
                std.debug.assert(sink.count == L.CONSTRAINTS);
                if (@import("builtin").is_test and start == 0) {
                    const ScalarView = struct {
                        columns: []const []const M,
                        row: usize,
                        pub fn fixed(x: *const @This(), c: usize) Q {
                            return Q.fromBase(x.columns[c][x.row]);
                        }
                        pub fn main(x: *const @This(), c: usize) Q {
                            return Q.fromBase(x.columns[A.FIXED + c][x.row]);
                        }
                        pub fn interaction(x: *const @This(), c: usize) Q {
                            return Q.fromBase(x.columns[A.FIXED + L.Row.MAIN + c][x.row]);
                        }
                        pub fn previous(x: *const @This(), c: usize) Q {
                            return Q.fromBase(x.columns[A.FIXED + L.Row.MAIN + c][core.utils.previousBitReversedCircleDomainIndex(x.row, LOG, LOG + 1)]);
                        }
                    };
                    var coordinates: [8][E.LANES]M = undefined;
                    for (weighted.accumulation.coordinates(), &coordinates) |part, *lanes| part.store(lanes);
                    for (0..E.LANES) |lane| {
                        const scalar = ScalarView{ .columns = evals, .row = lane };
                        var check = E.WeightedAccumulatorFor(Q){ .powers = output.random_coeff_powers };
                        var check_sink = E.SinkFor(Q){ .weighted_accumulator = &check };
                        emit(kind, Q, &scalar, self.input, self.ch, self.claim, &check_sink);
                        var native: [8]M = undefined;
                        for (&native, 0..) |*x, c| x.* = coordinates[c][lane];
                        if (!Q.fromM31Array(native).eql(check.accumulation)) return error.DensePackedScalarMismatch;
                    }
                }
                var den: [E.LANES]M = undefined;
                for (&den, 0..) |*x, i| x.* = inverses[(start + i) >> LOG];
                const value = weighted.accumulation.mulBase(F.fromLanes(den));
                const coordinates = value.coordinates();
                if (output.next_fresh_index) |next| {
                    if (next == start) {
                        for (output.col.columns, coordinates) |column, part| part.store(column.ptr + start);
                        output.next_fresh_index = start + E.LANES;
                        continue;
                    }
                    output.next_fresh_index = null;
                }
                for (output.col.columns, coordinates) |column, part| @TypeOf(part).load(column.ptr + start).add(part).store(column.ptr + start);
            }
        }
    };
}
