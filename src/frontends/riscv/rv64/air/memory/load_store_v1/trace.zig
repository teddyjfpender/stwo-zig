//! Owned narrow-family physical columns. All tuples/multiplicities precommit;
//! native interaction construction is not an acceptance authority.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../closed_ram/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const Selection = @import("selection.zig");
const M = T.M;
const Q = T.Q;
const physical = R.trace.physical;
pub const Trace = struct {
    allocator: std.mem.Allocator,
    kind: L.Kind,
    log_size: u32,
    rows: u32,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    public_rows: ?T.OwnerRows = null,
    pub fn init(a: std.mem.Allocator, kind: L.Kind, log: u32, rows: u32) !Trace {
        if (log < 5 or log > 17 or rows >= @as(u32, 1) << @intCast(log) or (kind == .owner and log != L.OWNER_LOG) or (kind == .selection and log != L.TABLE_LOG)) return error.InvalidLoadStoreGeometry;
        const n = @as(usize, 1) << @intCast(log);
        const widths = L.widths(kind);
        const fixed = try a.alloc(M, widths[0] * n);
        errdefer a.free(fixed);
        const main = try a.alloc(M, widths[1] * n);
        errdefer a.free(main);
        @memset(fixed, M.zero());
        @memset(main, M.zero());
        for (0..n) |row| {
            const pos = physical(row, log);
            if (kind == .owner) fixed[row * n + pos] = M.one() else if (kind == .selection) {
                for (Selection.fixedFact(row), 0..) |value, c| fixed[c * n + pos] = M.fromCanonical(value);
            } else fixed[pos] = M.fromCanonical(@intCast(row));
        }
        const first: usize = switch (kind) {
            .ls => 1,
            .owner => 64,
            .selection => 4,
        };
        fixed[first * n + physical(0, log)] = M.one();
        fixed[(first + 1) * n + physical(n - 1, log)] = M.one();
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
    pub fn bindPublic(self: *Trace, rows: T.OwnerRows) void {
        self.public_rows = rows;
        for (rows, 0..) |row, i| self.put(i, &row);
    }
    pub fn count(self: *const Trace, range16: []u64, range8: []u64, selection: []u64) void {
        std.debug.assert(self.kind == .ls);
        const n = self.size();
        for (L.U16) |c| for (self.main[c * n ..][0..n]) |value| {
            if (value.v < range16.len) range16[value.v] += 1;
        };
        for (L.U8) |c| for (self.main[c * n ..][0..n]) |value| {
            if (value.v < range8.len) range8[value.v] += 1;
        };
        for (0..n) |pos| {
            const input = self.main[L.selected_limb * n + pos].v;
            var parity = M.zero();
            for ([_]usize{ 1, 3, 5, 7 }) |offset| parity = parity.add(self.main[(L.offsets + offset) * n + pos]);
            if (input < 65536 and parity.v < 2) selection[2 * input + parity.v] += 1;
        }
    }
    pub fn setCounts(self: *Trace, counts: []const u64) !void {
        if (self.kind != .selection or counts.len != 2 * self.size()) return error.InvalidLoadStoreCounts;
        const n = self.size();
        for (0..n) |row| {
            const pos = physical(row, self.log_size);
            for (0..2) |parity| {
                const multiplicity = counts[2 * row + parity];
                if (multiplicity >= core.fields.m31.Modulus) return error.LoadStoreMassExceeded;
                self.main[parity * n + pos] = M.fromCanonical(@intCast(multiplicity));
            }
        }
    }

    pub fn generate(self: *Trace, ch: T.Challenges) !T.Claims {
        if (self.interaction.len != 0) return error.InvalidLoadStorePhase;
        const n = self.size();
        const output = try self.allocator.alloc(M, L.widths(self.kind)[2] * n);
        errdefer self.allocator.free(output);
        @memset(output, M.zero());
        var totals = T.Claims.zero();
        if (self.kind == .selection) {
            const d = try self.allocator.alloc(Q, n);
            defer self.allocator.free(d);
            const inverse = try self.allocator.alloc(Q, n);
            defer self.allocator.free(inverse);
            for (d, 0..) |*v, row| {
                var fixed: [4]Q = undefined;
                for (Selection.fixedFact(row), &fixed) |value, *q| q.* = Q.fromBase(M.fromCanonical(value));
                v.* = ch.selection.denominatorFor(Q, Selection.tupleFor(Q, &fixed, 0)).mul(ch.selection.denominatorFor(Q, Selection.tupleFor(Q, &fixed, 1)));
            }
            try core.fields.batchInverseInPlace(Q, d, inverse);
            for (inverse, 0..) |inv, row| {
                const pos = physical(row, self.log_size);
                const m0 = self.main[pos];
                const m1 = self.main[n + pos];
                if (!m0.isZero() or !m1.isZero()) {
                    var fixed: [4]Q = undefined;
                    for (Selection.fixedFact(row), &fixed) |value, *q| q.* = Q.fromBase(M.fromCanonical(value));
                    const d0 = ch.selection.denominatorFor(Q, Selection.tupleFor(Q, &fixed, 0));
                    const d1 = ch.selection.denominatorFor(Q, Selection.tupleFor(Q, &fixed, 1));
                    totals.selection = totals.selection.sub(d1.mulM31(m0).add(d0.mulM31(m1)).mul(inv));
                }
                R.trace.store(output, n, pos, 0, inv);
                R.trace.store(output, n, pos, 4, totals.selection);
            }
            R.trace.center(output, n, 4, totals.selection);
        } else for (0..n) |row| {
            const pos = physical(row, self.log_size);
            var m: [79]Q = @splat(Q.zero());
            for (0..L.widths(self.kind)[1]) |c| m[c] = Q.fromBase(self.main[c * n + pos]);
            if (self.kind == .owner) {
                const inv = try ch.owner.denominatorFor(Q, m[0..21].*).inv();
                totals.owner = totals.owner.sub(inv.mul(m[21]));
                R.trace.store(output, n, pos, 0, inv);
                R.trace.store(output, n, pos, 4, totals.owner);
            } else {
                const before = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, m[0..28], false));
                const after = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, m[0..28], true));
                const inv = try before.mul(after).inv();
                totals.ram = totals.ram.add(after.sub(before).mul(inv).mul(m[0]));
                R.trace.store(output, n, pos, 0, inv);
                R.trace.store(output, n, pos, 4, totals.ram);
                const owner = try ch.owner.denominatorFor(Q, Eq.ownerTuple(Q, &m)).inv();
                totals.owner = totals.owner.add(owner.mul(m[0]));
                R.trace.store(output, n, pos, L.OWNER, owner);
                R.trace.store(output, n, pos, L.OWNER + 4, totals.owner);
                totals.range16 = totals.range16.add(try R.trace.rangeRow(output, n, pos, &m, &L.U16, L.RANGE16, ch.range16));
                R.trace.store(output, n, pos, L.RANGE8 - 4, totals.range16);
                totals.range8 = totals.range8.add(try R.trace.rangeRow(output, n, pos, &m, &L.U8, L.RANGE8, ch.range8));
                R.trace.store(output, n, pos, L.SELECTION - 4, totals.range8);
                const selected = try ch.selection.denominatorFor(Q, Eq.selectionTuple(Q, &m)).inv();
                totals.selection = totals.selection.add(selected);
                R.trace.store(output, n, pos, L.SELECTION, selected);
                R.trace.store(output, n, pos, L.SELECTION + 4, totals.selection);
            }
        }
        if (self.kind == .owner) R.trace.center(output, n, 4, totals.owner) else if (self.kind == .ls) {
            R.trace.center(output, n, 4, totals.ram);
            R.trace.center(output, n, L.OWNER + 4, totals.owner);
            R.trace.center(output, n, L.RANGE8 - 4, totals.range16);
            R.trace.center(output, n, L.SELECTION - 4, totals.range8);
            R.trace.center(output, n, L.SELECTION + 4, totals.selection);
        }
        self.interaction = output;
        return totals;
    }
};
