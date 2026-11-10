const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = @import("equations.zig");
const S = C.S;
const W = C.W;
const M = C.M;
const O = C.O;
const Physical = A.memory.closed_ram.trace;
pub const ROWS = 256;
fn physical(row: usize) usize {
    return Physical.physical(row, 8);
}
pub const Trace = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    main: []M,
    inter: []M,
    pub fn deinit(t: *Trace) void {
        t.allocator.free(t.fixed);
        t.allocator.free(t.main);
        t.allocator.free(t.inter);
        t.* = undefined;
    }
    pub fn fixedAlloc(a: std.mem.Allocator, coefficients: W.Coefficients) ![]M {
        const fixed = try a.alloc(M, C.FIXED * ROWS);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        const f = try S.fixed(true, coefficients, @splat(1), 2, 0);
        for (f, 0..) |v, c| fixed[c * ROWS + physical(0)] = if (v < 0) M.fromCanonical(@intCast(-v)).neg() else M.fromCanonical(@intCast(v));
        for (0..ROWS) |r| fixed[C.FIX_BYTE * ROWS + physical(r)] = M.fromCanonical(@intCast(r));
        return fixed;
    }
    pub fn init(a: std.mem.Allocator, input: *const W.Inputs, coefficients: W.Coefficients, alias: bool) !Trace {
        const fixed = try fixedAlloc(a, coefficients);
        errdefer a.free(fixed);
        const main = try a.alloc(M, C.MAIN * ROWS);
        errdefer a.free(main);
        @memset(main, M.zero());
        const inter = try a.alloc(M, C.INTER * ROWS);
        errdefer a.free(inter);
        @memset(inter, M.zero());
        const row = if (alias) try W.aliasForTesting(input, coefficients) else try W.fill(input, coefficients);
        for (row, 0..) |v, c| main[c * ROWS + physical(0)] = M.fromCanonical(v);
        const out = Trace{ .allocator = a, .fixed = fixed, .main = main, .inter = inter };
        var histogram: [256]u32 = @splat(0);
        const v = out.view(0);
        for (0..S.BYTE_QUERIES) |i| {
            const x = S.byteQuery(O, &v, i).toM31Array();
            if (x[0].v >= 256) return error.Mac12FixtureRange;
            for (x[1..]) |top| if (top.v != 0) return error.Mac12FixtureRange;
            histogram[x[0].v] += 1;
        }
        for (histogram, 0..) |n, r| main[C.MULT * ROWS + physical(r)] = M.fromCanonical(n);
        return out;
    }
    pub const View = struct {
        trace: *const Trace,
        row: usize,
        pub fn fixed(v: *const @This(), c: usize) O {
            return O.fromBase(v.trace.fixed[c * ROWS + physical(v.row)]);
        }
        pub fn main(v: *const @This(), c: usize) O {
            return O.fromBase(v.trace.main[c * ROWS + physical(v.row)]);
        }
        pub fn interactionAt(v: *const @This(), c: usize, comptime shift: i32) O {
            const row = if (shift == 0) v.row else (v.row + ROWS - 1) % ROWS;
            return O.fromBase(v.trace.inter[c * ROWS + physical(row)]);
        }
    };
    pub fn view(t: *const Trace, row: usize) View {
        return .{ .trace = t, .row = row };
    }
    fn fraction(t: *const Trace, row: usize, index: usize, beta: O) !O {
        const v = t.view(row);
        const f = C.fraction(O, &v, beta, index);
        return f[0].mul(try f[1].inv());
    }
    pub fn generate(t: *Trace, beta: O) !void {
        var prefix = O.zero();
        for (0..ROWS) |row| for (0..C.BATCHES) |b| {
            prefix = prefix.add(try t.fraction(row, 2 * b, beta)).add(try t.fraction(row, 2 * b + 1, beta));
            for (prefix.toM31Array(), 0..) |x, i| t.inter[(8 * b + i) * ROWS + physical(row)] = x;
        };
        if (!prefix.isZero()) return error.Mac12FixtureRangeNotClosed;
    }
    pub fn columns(data: []const M, out: []engine.pcs.ColumnEvaluation) void {
        for (out, 0..) |*v, c| v.* = .{ .log_size = 8, .values = data[c * ROWS ..][0..ROWS] };
    }
};
