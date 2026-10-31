const std = @import("std");
const core = @import("stwo_core");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const M = core.fields.m31.M31;
const Q = T.Q;
pub fn physical(row: usize, log: u32) usize {
    return @import("../../witness.zig").physical(row, log);
}
pub fn word(out: []M, value: u64) void {
    for (out[0..4], 0..) |*v, i| v.* = M.fromCanonical(@as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
}
pub const Trace = struct {
    allocator: std.mem.Allocator,
    kind: L.Kind,
    log_size: u32,
    rows: u32,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    public_rows: ?T.PublicRows = null,
    pub fn init(a: std.mem.Allocator, kind: L.Kind, log: u32, rows: u32) !Trace {
        if (log < 5 or log > 16 or rows >= @as(u32, 1) << @intCast(log)) return error.InvalidClosedRamGeometry;
        if ((kind == .range16 and log != 16) or (kind == .range8 and log != 8)) return error.InvalidClosedRamGeometry;
        const n: usize = @as(usize, 1) << @intCast(log);
        const widths = L.widths(kind);
        const fixed = try a.alloc(M, widths[0] * n);
        errdefer a.free(fixed);
        const main = try a.alloc(M, widths[1] * n);
        errdefer a.free(main);
        @memset(fixed, M.zero());
        @memset(main, M.zero());
        const selectors = kind == .initial or kind == .terminal or kind == .owner;
        if (selectors and log != 5) return error.InvalidClosedRamGeometry;
        for (0..n) |row| {
            const pos = physical(row, log);
            if (selectors) fixed[row * n + pos] = M.one() else fixed[pos] = M.fromCanonical(@intCast(row));
        }
        fixed[(if (selectors) @as(usize, 32) else 1) * n + physical(0, log)] = M.one();
        fixed[(if (selectors) @as(usize, 33) else 2) * n + physical(n - 1, log)] = M.one();
        return .{ .allocator = a, .kind = kind, .log_size = log, .rows = rows, .fixed = fixed, .main = main };
    }
    pub fn size(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn put(self: *Trace, row: usize, values: []const M) void {
        const n = self.size();
        const pos = physical(row, self.log_size);
        for (values, 0..) |v, c| self.main[c * n + pos] = v;
    }
    pub fn bindPublic(self: *Trace, pubrows: T.PublicRows) void {
        self.public_rows = pubrows;
        for (pubrows, 0..) |values, row| self.put(row, &values);
    }
    pub fn countRanges(self: *const Trace, counts16: []u64, counts8: []u64) void {
        const n = self.size();
        const indices16: []const usize = switch (self.kind) {
            .transition => &L.T_U16,
            .initial, .terminal => &L.B_U16,
            else => &.{},
        };
        const indices8: []const usize = switch (self.kind) {
            .transition => &L.T_U8,
            .initial, .terminal => &L.B_U8,
            else => &.{},
        };
        for (indices16) |c| for (self.main[c * n ..][0..n]) |v| {
            if (v.v < counts16.len) counts16[v.v] += 1;
        };
        for (indices8) |c| for (self.main[c * n ..][0..n]) |v| {
            if (v.v < counts8.len) counts8[v.v] += 1;
        };
    }
    pub fn setCounts(self: *Trace, counts: []const u64) !void {
        if (counts.len != self.size()) return error.InvalidClosedRamCounts;
        for (counts, 0..) |v, row| {
            if (v >= core.fields.m31.Modulus) return error.ClosedRamMassOverflow;
            self.main[physical(row, self.log_size)] = M.fromCanonical(@intCast(v));
        }
    }
    pub fn generate(self: *Trace, ch: T.Challenges) !T.Claims {
        if (self.interaction.len != 0) return error.InvalidClosedRamPhase;
        const n = self.size();
        const width = L.widths(self.kind)[2];
        const output = try self.allocator.alloc(M, width * n);
        errdefer self.allocator.free(output);
        @memset(output, M.zero());
        var totals = T.Claims.zero();
        if (self.kind == .range16 or self.kind == .range8) {
            const rc = if (self.kind == .range16) ch.range16 else ch.range8;
            const input = try self.allocator.alloc(Q, n);
            defer self.allocator.free(input);
            const inverses = try self.allocator.alloc(Q, n);
            defer self.allocator.free(inverses);
            for (input, 0..) |*v, row| v.* = rc.denominatorFor(Q, Q.fromBase(M.fromCanonical(@intCast(row))));
            try core.fields.batchInverseInPlace(Q, input, inverses);
            var sum = Q.zero();
            for (inverses, 0..) |inverse, row| {
                const pos = physical(row, self.log_size);
                sum = sum.sub(inverse.mulM31(self.main[pos]));
                store(output, n, pos, 0, inverse);
                store(output, n, pos, 4, sum);
            }
            center(output, n, 4, sum);
            if (self.kind == .range16) totals.range16 = sum else totals.range8 = sum;
        } else {
            for (0..n) |row| {
                const pos = physical(row, self.log_size);
                var m: [28]Q = @splat(Q.zero());
                for (0..L.widths(self.kind)[1]) |c| m[c] = Q.fromBase(self.main[c * n + pos]);
                if (self.kind == .transition) {
                    const b = ch.ram.denominatorFor(Q, Eq.ramTuple(Q, self.kind, &m, false));
                    const after = ch.ram.denominatorFor(Q, Eq.ramTuple(Q, self.kind, &m, true));
                    const inv = try b.mul(after).inv();
                    store(output, n, pos, 0, inv);
                    totals.ram = totals.ram.add(after.sub(b).mul(inv).mul(m[0]));
                    store(output, n, pos, 4, totals.ram);
                    const oi = try ch.owner.denominatorFor(Q, Eq.ownerTuple(Q, &m)).inv();
                    store(output, n, pos, 8, oi);
                    totals.owner = totals.owner.add(oi.mul(m[0]));
                    store(output, n, pos, 12, totals.owner);
                    totals.range16 = totals.range16.add(try rangeRow(output, n, pos, &m, &L.T_U16, L.T_RANGE16, ch.range16));
                    store(output, n, pos, L.T_RANGE8 - 4, totals.range16);
                    totals.range8 = totals.range8.add(try rangeRow(output, n, pos, &m, &L.T_U8, L.T_RANGE8, ch.range8));
                    store(output, n, pos, L.TRANS_INTER - 4, totals.range8);
                } else if (self.kind == .owner) {
                    const inv = try ch.owner.denominatorFor(Q, m[0..13].*).inv();
                    store(output, n, pos, 0, inv);
                    totals.owner = totals.owner.sub(inv.mul(m[13]));
                    store(output, n, pos, 4, totals.owner);
                } else {
                    const inv = try ch.ram.denominatorFor(Q, Eq.ramTuple(Q, self.kind, &m, false)).inv();
                    store(output, n, pos, 0, inv);
                    const contribution = inv.mul(m[0]);
                    totals.ram = totals.ram.add(if (self.kind == .initial) contribution.neg() else contribution);
                    store(output, n, pos, 4, totals.ram);
                    totals.range16 = totals.range16.add(try rangeRow(output, n, pos, &m, &L.B_U16, L.B_RANGE16, ch.range16));
                    store(output, n, pos, L.B_RANGE8 - 4, totals.range16);
                    totals.range8 = totals.range8.add(try rangeRow(output, n, pos, &m, &L.B_U8, L.B_RANGE8, ch.range8));
                    store(output, n, pos, L.BOUND_INTER - 4, totals.range8);
                }
            }
            if (self.kind == .transition) {
                center(output, n, 4, totals.ram);
                center(output, n, 12, totals.owner);
                center(output, n, L.T_RANGE8 - 4, totals.range16);
                center(output, n, L.TRANS_INTER - 4, totals.range8);
            } else if (self.kind == .owner) center(output, n, 4, totals.owner) else {
                center(output, n, 4, totals.ram);
                center(output, n, L.B_RANGE8 - 4, totals.range16);
                center(output, n, L.BOUND_INTER - 4, totals.range8);
            }
        }
        self.interaction = output;
        return totals;
    }
};
pub fn store(data: []M, n: usize, row: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * n + row] = v;
}
pub fn center(data: []M, n: usize, start: usize, sum: Q) void {
    for (sum.toM31Array(), 0..) |v, c| {
        for (0..n) |r| data[(start + c) * n + r] = data[(start + c) * n + r].sub(v);
    }
}
pub fn rangeRow(output: []M, n: usize, pos: usize, m: []const Q, indices: []const usize, start: usize, ch: @import("../../providers/scalar_range.zig").Challenges) !Q {
    var sum = Q.zero();
    for (0..(indices.len + 1) / 2) |batch| {
        const d = ch.denominatorFor(Q, m[indices[2 * batch]]);
        var denominator = d;
        var numerator = Q.one();
        if (2 * batch + 1 < indices.len) {
            const e = ch.denominatorFor(Q, m[indices[2 * batch + 1]]);
            denominator = d.mul(e);
            numerator = d.add(e);
        }
        const inverse = try denominator.inv();
        store(output, n, pos, start + 4 * batch, inverse);
        sum = sum.add(numerator.mul(inverse));
    }
    return sum;
}
