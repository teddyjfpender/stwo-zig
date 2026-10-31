//! Two independently closed projections over one immutable fixed ROM tree.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Eq = @import("equations.zig");
const A = @import("authority.zig");
const physical = @import("../word16_cpu/layout.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const Source = struct {
    allocator: std.mem.Allocator,
    authority: *const A.Authority,
    main: []M,
    interaction: []M = &.{},
    counts: [2][]const u64,
    dictionaries: [2][]Q = .{ &.{}, &.{} },
    claims: ?[2]Q = null,
    pub fn init(a: std.mem.Allocator, authority: *const A.Authority, decode_counts: []const u64, map_counts: []const u64) !Source {
        const n = @as(usize, 1) << @intCast(authority.log_size);
        if (decode_counts.len != n or map_counts.len != n) return error.InvalidIndexRomCounts;
        for ([2][]const u64{ decode_counts, map_counts }, 0..) |counts, family| {
            var mass: u64 = 0;
            for (counts, 0..) |count, row| {
                mass = std.math.add(u64, mass, count) catch return error.IndexRomMassExceeded;
                if (mass >= core.fields.m31.Modulus or (family == 0 and count != 0 and authority.fixed[row].isZero())) return error.InvalidIndexRomCounts;
            }
        }
        const main = try a.alloc(M, 2 * n);
        for ([2][]const u64{ decode_counts, map_counts }, 0..) |counts, family| for (counts, 0..) |count, row| {
            main[family * n + row] = M.fromCanonical(@intCast(count));
        };
        return .{ .allocator = a, .authority = authority, .main = main, .counts = .{ decode_counts, map_counts } };
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.allocator.free(self.interaction);
        for (self.dictionaries) |values| self.allocator.free(values);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn generate(self: *Source, ch: Eq.RomChallenges, map: Eq.MapChallenges) ![2]Q {
        if (self.interaction.len != 0 or self.claims != null) return error.InvalidIndexRomPhase;
        const a = self.allocator;
        const log = self.authority.log_size;
        const n = @as(usize, 1) << @intCast(log);
        const output = try a.alloc(M, 16 * n);
        errdefer a.free(output);
        const dictionary0 = try a.alloc(Q, n);
        errdefer a.free(dictionary0);
        const dictionary1 = try a.alloc(Q, n);
        errdefer a.free(dictionary1);
        const dictionaries = [2][]Q{ dictionary0, dictionary1 };
        const input = try a.alloc(Q, n);
        defer a.free(input);
        var claims: [2]Q = undefined;
        for (0..2) |family| {
            for (input, 0..) |*d, logical| {
                const pos = physical(logical, log);
                d.* = if (family == 0) ch.offset else map.offset;
                if (family == 0) {
                    for (ch.coefficients, 0..) |coefficient, c| d.* = d.sub(coefficient.mulM31(self.authority.fixed[c * n + pos]));
                } else {
                    d.* = d.sub(map.coefficients[0].mulM31(self.authority.fixed[n + pos]));
                    for (map.coefficients[1..], 0..) |coefficient, c| d.* = d.sub(coefficient.mulM31(self.authority.fixed[(A.RAW_PC + c) * n + pos]));
                }
            }
            try core.fields.batchInverseInPlace(Q, input, dictionaries[family]);
            var sum = Q.zero();
            for (0..n) |logical| {
                const pos = physical(logical, log);
                const inv = dictionaries[family][logical];
                sum = sum.sub(inv.mulM31(M.fromCanonical(@intCast(self.counts[family][pos]))));
                store(output, n, pos, 8 * family, inv);
                store(output, n, pos, 8 * family + 4, sum);
            }
            claims[family] = sum;
            for (sum.toM31Array(), 0..) |coordinate, c| for (0..n) |row| {
                output[(8 * family + 4 + c) * n + row] = output[(8 * family + 4 + c) * n + row].sub(coordinate);
            };
        }
        self.interaction = output;
        self.dictionaries = dictionaries;
        self.claims = claims;
        return claims;
    }
};
fn store(values: []M, n: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, c| values[(column + c) * n + row] = coordinate;
}
