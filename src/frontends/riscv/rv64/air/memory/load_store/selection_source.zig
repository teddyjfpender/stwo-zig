//! Qualified paired table witness with histogram metadata separate from MAIN.
const std = @import("std");
const core = @import("stwo_core");
const V1 = @import("../load_store_v1/mod.zig");
const R = @import("../closed_ram/mod.zig");
const T = @import("types.zig");
const M = T.M;
const Q = T.Q;
pub const Source = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    counts: []const u64,
    log_size: u32 = 16,
    rows: u32 = 0,
    /// Histogram belongs to the LS Source and outlives this table. It never
    /// aliases the two committed MAIN columns, which may be retired at seal.
    pub fn init(a: std.mem.Allocator, counts: []const u64) !Source {
        var old = try V1.trace.Trace.init(a, .selection, 16, 0);
        errdefer old.deinit();
        try old.setCounts(counts);
        return .{ .allocator = a, .fixed = old.fixed, .main = old.main, .counts = counts };
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.allocator.free(self.fixed);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn generate(self: *Source, ch: T.Challenges) !T.Claims {
        if (self.interaction.len != 0 or self.counts.len != 131072) return error.InvalidSelectionPhase;
        const a = self.allocator;
        const n: usize = 65536;
        const output = try a.alloc(M, 8 * n);
        errdefer a.free(output);
        const input = try a.alloc(Q, n);
        defer a.free(input);
        const inverse = try a.alloc(Q, n);
        defer a.free(inverse);
        for (input, 0..) |*d, row| {
            var fixed: [4]Q = undefined;
            for (V1.selection.fixedFact(row), &fixed) |v, *q| q.* = Q.fromBase(M.fromCanonical(v));
            d.* = ch.selection.denominatorFor(Q, V1.selection.tupleFor(Q, &fixed, 0)).mul(ch.selection.denominatorFor(Q, V1.selection.tupleFor(Q, &fixed, 1)));
        }
        try core.fields.batchInverseInPlace(Q, input, inverse);
        var claims = T.Claims.zero();
        for (inverse, 0..) |inv, row| {
            const m0 = self.counts[2 * row];
            const m1 = self.counts[2 * row + 1];
            if (m0 >= core.fields.m31.Modulus or m1 >= core.fields.m31.Modulus) return error.InvalidSelectionCounts;
            var fixed: [4]Q = undefined;
            for (V1.selection.fixedFact(row), &fixed) |v, *q| q.* = Q.fromBase(M.fromCanonical(v));
            const d0 = ch.selection.denominatorFor(Q, V1.selection.tupleFor(Q, &fixed, 0));
            const d1 = ch.selection.denominatorFor(Q, V1.selection.tupleFor(Q, &fixed, 1));
            claims.selection = claims.selection.sub(d1.mulM31(M.fromCanonical(@intCast(m0))).add(d0.mulM31(M.fromCanonical(@intCast(m1)))).mul(inv));
            const pos = R.trace.physical(row, 16);
            R.trace.store(output, n, pos, 0, inv);
            R.trace.store(output, n, pos, 4, claims.selection);
        }
        R.trace.center(output, n, 4, claims.selection);
        self.interaction = output;
        return claims;
    }
};
