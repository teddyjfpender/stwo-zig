//! Owned one-call witness. Public inputs are copied into independently pinned
//! verifier parameters; no production canonical-read inheritance is assumed.
const std = @import("std");
const C = @import("fixture_component.zig");
const A = @import("air.zig");
const S = @import("spec.zig");
const R = @import("row.zig");
const Physical = @import("../../memory/closed_ram/mod.zig").trace;
const Q = C.Q;
const M = C.M;
pub fn Trace(comptime kind: S.Kind) type {
    return TraceForLog(kind, C.LOG);
}
pub fn TraceForLog(comptime kind: S.Kind, comptime log: u32) type {
    if (log < 8 or log > 10) @compileError("closed dense fixture log must be8..10");
    return struct {
        pub const ROWS: usize = @as(usize, 1) << log;
        fn physical(row: usize) usize {
            return Physical.physical(row, log);
        }
        const Self = @This();
        const L = C.Layout(kind);
        const RL = R.Layout(kind);
        allocator: std.mem.Allocator,
        fixed: []M,
        main: []M,
        inter: []M,
        pub fn init(a: std.mem.Allocator, input: *const [S.inputs(kind)]u256) !Self {
            return initImpl(a, input, true);
        }
        pub fn initMainOnly(a: std.mem.Allocator, input: *const [S.inputs(kind)]u256) !Self {
            return initImpl(a, input, false);
        }
        fn initImpl(a: std.mem.Allocator, input: *const [S.inputs(kind)]u256, comptime with_inter: bool) !Self {
            const f = try fixedAlloc(a);
            errdefer a.free(f);
            const m = try a.alloc(M, RL.MAIN * ROWS);
            errdefer a.free(m);
            @memset(m, M.zero());
            const inter = try a.alloc(M, if (with_inter) L.INTER * ROWS else 0);
            errdefer a.free(inter);
            @memset(inter, M.zero());
            const out = Self{ .allocator = a, .fixed = f, .main = m, .inter = inter };
            inline for (0..12) |coord| {
                const row = RL.fill(coord, input);
                for (row, 0..) |v, col| m[col * ROWS + physical(coord)] = M.fromCanonical(v);
            }
            // Exact histogram of every active private range query. Provider weights are
            // physically committed MAIN, not metadata or a post-challenge hint.
            var histogram: [256]u32 = @splat(0);
            for (0..12) |r| {
                const v = out.view(r);
                for (0..RL.BYTE_QUERIES) |i| {
                    const x = A.query(kind, Q, &v, i).toM31Array();
                    if (x[0].v >= 256) return error.DenseFixtureRange;
                    for (x[1..]) |top| if (top.v != 0) return error.DenseFixtureRange;
                    histogram[x[0].v] += 1;
                }
            }
            for (histogram, 0..) |v, r| m[RL.MULT * ROWS + physical(r)] = M.fromCanonical(v);
            return out;
        }
        pub fn fixedAlloc(a: std.mem.Allocator) ![]M {
            const f = try a.alloc(M, A.FIXED * ROWS);
            @memset(f, M.zero());
            for (0..ROWS) |r| {
                f[(r % 12) * ROWS + physical(r)] = M.one();
                f[A.FIX_BYTE * ROWS + physical(r)] = M.fromCanonical(@intCast(r % 256));
                if (r < 12) f[A.FIX_ACTIVE * ROWS + physical(r)] = M.one();
            }
            return f;
        }
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.fixed);
            self.allocator.free(self.main);
            self.allocator.free(self.inter);
            self.* = undefined;
        }
        pub const View = struct {
            trace: *const Self,
            row: usize,
            pub fn fixed(v: *const @This(), col: usize) Q {
                return Q.fromBase(v.trace.fixed[col * ROWS + physical(v.row)]);
            }
            pub fn main(v: *const @This(), col: usize) Q {
                return Q.fromBase(v.trace.main[col * ROWS + physical(v.row)]);
            }
            pub fn interaction(v: *const @This(), col: usize) Q {
                return Q.fromBase(v.trace.inter[col * ROWS + physical(v.row)]);
            }
            pub fn previous(v: *const @This(), col: usize) Q {
                return Q.fromBase(v.trace.inter[col * ROWS + physical((v.row + ROWS - 1) % ROWS)]);
            }
        };
        pub fn view(self: *const Self, row: usize) View {
            return .{ .trace = self, .row = row };
        }
        fn store(self: *Self, col: usize, row: usize, value: Q) void {
            for (value.toM31Array(), 0..) |x, i| self.inter[(col + i) * ROWS + physical(row)] = x;
        }
        fn rangeFraction(self: *const Self, row: usize, index: usize, ch: C.Challenges) !Q {
            const v = self.view(row);
            if (index < RL.BYTE_QUERIES) {
                const n = v.main(0);
                if (n.isZero()) return Q.zero();
                return n.mul(try ch.byte.sub(A.query(kind, Q, &v, index)).inv());
            }
            if (index == RL.BYTE_QUERIES) return v.main(RL.MULT).neg().mul(try ch.byte.sub(v.fixed(A.FIX_BYTE)).inv());
            return Q.zero();
        }
        pub fn expectedClaim(ch: C.Challenges, expected: [12]u256) !Q {
            var claim = Q.zero();
            for (expected, 0..) |value, coord| {
                var tuple: [35]Q = undefined;
                tuple[0] = Q.fromBase(M.fromCanonical(C.KIND));
                tuple[1] = Q.one();
                tuple[2] = Q.fromBase(M.fromCanonical(@intCast(coord)));
                for (tuple[3..], 0..) |*x, i| x.* = Q.fromBase(M.fromCanonical(S.B.limbOf(value, i)));
                claim = claim.add(try ch.wire.denominator(&tuple).inv());
            }
            return claim;
        }
        pub fn generate(self: *Self, ch: C.Challenges, expected: [12]u256) !Q {
            if (self.inter.len != L.INTER * ROWS) return error.DenseClassicInteractionNotAllocated;
            const claim = try expectedClaim(ch, expected);
            var range = Q.zero();
            var output = Q.zero();
            const shift = claim.mul(Q.fromBase((M.fromCanonical(ROWS).inv() catch unreachable)));
            for (0..ROWS) |r| {
                for (0..L.BATCHES) |b| {
                    range = range.add(try self.rangeFraction(r, 2 * b, ch)).add(try self.rangeFraction(r, 2 * b + 1, ch));
                    self.store(8 * b, r, range);
                }
                if (r < 12) {
                    var tuple: [35]Q = undefined;
                    tuple[0] = Q.fromBase(M.fromCanonical(C.KIND));
                    tuple[1] = Q.one();
                    tuple[2] = Q.fromBase(M.fromCanonical(@intCast(r)));
                    for (tuple[3..], 0..) |*x, i| x.* = Q.fromBase(self.main[(RL.OUTPUT + i) * ROWS + physical(r)]);
                    output = output.add(try ch.wire.denominator(&tuple).inv());
                }
                output = output.sub(shift);
                self.store(L.OUTPUT, r, output);
            }
            if (!range.isZero()) return error.DenseFixtureRangeNotClosed;
            if (!output.isZero()) return error.DenseFixtureOutputNotClosed;
            return claim;
        }
    };
}
