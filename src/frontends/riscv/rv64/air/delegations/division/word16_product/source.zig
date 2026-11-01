//! Owned or borrowed narrow DIV MAIN with retained query advice. Product truth
//! belongs to the two mandatory MUL/MULHU requests and the joined FUNCTION bus.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const L = @import("layout.zig");
const A = @import("equations.zig");
const P = @import("lookup.zig");
const W = @import("witness.zig");
const physical = @import("../../../program/provider.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const Request = W.Request;
const WORDS = [_]usize{ L.A, L.B, L.C, L.ABS_A, L.ABS_B, L.QUOTIENT, L.REMAINDER, L.PRODUCT_LOW, L.GAP, L.OUT };
pub const MIN_LOG: u32 = 5;
pub const MAX_LOG: u32 = 22;
pub const Metadata = struct {
    words: [WORDS.len]u64,
    opcode: u8,
    signs: u8,
    fn capture(main: *const [L.MAIN]M, opcode: ?usize) !Metadata {
        var result: Metadata = .{ .words = undefined, .opcode = if (opcode) |op| @intCast(op) else 255, .signs = 0 };
        for (WORDS, &result.words) |start, *word| {
            word.* = 0;
            for (0..4) |i| {
                const value = main[start + i].v;
                if (value >= 65536) return error.InvalidDivisionQueryMetadata;
                word.* |= @as(u64, value) << @as(u6, @intCast(16 * i));
            }
        }
        for (0..3) |i| {
            const flag = main[L.SIGN_A + i].v;
            if (flag > 1) return error.InvalidDivisionQueryMetadata;
            result.signs |= @as(u8, @intCast(flag)) << @as(u3, @intCast(i));
        }
        return result;
    }
    /// Only lookup input fields are reconstructed; no normalization, product,
    /// inverse, carry or full witness computation is replayed after MAIN seal.
    pub fn queryRow(self: Metadata) [L.MAIN]Q {
        var result: [L.MAIN]Q = @splat(Q.zero());
        for (WORDS, self.words) |start, word| for (0..4) |i| {
            result[start + i] = E.q(@as(u16, @truncate(word >> @as(u6, @intCast(16 * i)))));
        };
        for (0..3) |i| result[L.SIGN_A + i] = E.q((self.signs >> @as(u3, @intCast(i))) & 1);
        if (self.opcode < L.OPCODES.len) result[L.SELECTORS + self.opcode] = Q.one();
        return result;
    }
};
comptime {
    std.debug.assert(@sizeOf(Metadata) == 88);
}
pub const Mass = struct { range16: u64, function_positive: u64 };
pub fn massForLog(log: u32) !Mass {
    if (log < MIN_LOG or log > MAX_LOG) return error.InvalidRv64DivisionShape;
    const n = @as(u64, 1) << @intCast(log);
    const result = Mass{ .range16 = L.RANGE_QUERIES * n, .function_positive = 2 * n };
    if (result.range16 >= core.fields.m31.Modulus or result.function_positive >= core.fields.m31.Modulus) return error.DivisionLookupMassExceeded;
    return result;
}
pub fn fixedColumnsForLog(a: std.mem.Allocator, log: u32) ![]M {
    _ = try massForLog(log);
    const n = @as(usize, 1) << @intCast(log);
    const data = try a.alloc(M, L.FIXED * n);
    @memset(data, M.zero());
    for (0..n) |i| {
        const p = physical(i, log);
        data[p] = M.fromCanonical(@intCast(i));
        data[n + p] = M.fromCanonical(@intFromBool(i == 0));
        data[2 * n + p] = M.fromCanonical(@intFromBool(i + 1 == n));
    }
    return data;
}
pub fn fixedColumns(a: std.mem.Allocator, count: usize, log: u32) ![]M {
    _ = try massForLog(log);
    if (count > (@as(usize, 1) << @intCast(log))) return error.InvalidRv64DivisionShape;
    return fixedColumnsForLog(a, log);
}
pub const Trace = Source;
pub const Source = struct {
    allocator: std.mem.Allocator,
    count: usize,
    log_size: u32,
    fixed: []M,
    main: []M,
    owns_main: bool = true,
    metadata: []Metadata,
    counts16: []u64,
    interaction: []M = &.{},
    pub fn init(a: std.mem.Allocator, requests: []const Request) !Source {
        return initWithLog(a, requests, @intCast(@max(MIN_LOG, std.math.log2_int_ceil(usize, @max(1, requests.len)))));
    }
    pub fn initWithLog(a: std.mem.Allocator, requests: []const Request, log: u32) !Source {
        return initStorage(a, requests, log, null);
    }
    pub fn initWithBorrowedMain(a: std.mem.Allocator, requests: []const Request, log: u32, main: []M) !Source {
        return initStorage(a, requests, log, main);
    }
    fn initStorage(a: std.mem.Allocator, requests: []const Request, log: u32, borrowed: ?[]M) !Source {
        _ = try massForLog(log);
        const n = @as(usize, 1) << @intCast(log);
        if (requests.len > n) return error.InvalidRv64DivisionShape;
        for (requests) |r| _ = try opcodeIndex(r.opcode);
        if (borrowed) |main| {
            const storage = @import("../../main_storage.zig");
            const slices = [_]storage.Slice{.{ .values = main, .cells = L.MAIN * n }};
            try storage.validate(&slices);
            try storage.exclude(&slices, std.mem.sliceAsBytes(requests));
        }
        const fixed = try fixedColumnsForLog(a, log);
        errdefer a.free(fixed);
        const metadata = try a.alloc(Metadata, n);
        errdefer a.free(metadata);
        const counts = try a.alloc(u64, 65536);
        errdefer a.free(counts);
        @memset(counts, 0);
        const main = borrowed orelse try a.alloc(M, L.MAIN * n);
        errdefer if (borrowed == null) a.free(main);
        for (0..n) |p| {
            const i = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, log), log);
            var row = if (i < requests.len) (try W.row(requests[i])).main else [_]M{M.zero()} ** L.MAIN;
            row[L.COUNT] = M.fromCanonical(@intCast(@min(i + 1, requests.len)));
            metadata[i] = try Metadata.capture(&row, if (i < requests.len) try opcodeIndex(requests[i].opcode) else null);
            for (row, 0..) |value, c| main[c * n + p] = value;
            const query_row = metadata[i].queryRow();
            for (A.rangeValuesFor(Q, &query_row)) |range| {
                const value = (try range.tryIntoM31()).v;
                if (value >= counts.len) return error.InvalidDivisionQueryMetadata;
                counts[value] = try std.math.add(u64, counts[value], 1);
            }
        }
        return .{ .allocator = a, .count = requests.len, .log_size = log, .fixed = fixed, .main = main, .owns_main = borrowed == null, .metadata = metadata, .counts16 = counts };
    }
    pub fn domainSize(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) !void {
        if (self.main.len != L.MAIN * self.domainSize()) return error.InvalidRv64ArithmeticMainPhase;
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn deinit(self: *Source) void {
        self.allocator.free(self.fixed);
        if (self.owns_main) self.allocator.free(self.main);
        self.allocator.free(self.metadata);
        self.allocator.free(self.counts16);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn generateInteraction(self: *Source, challenges: P.Challenges) !Q {
        const n = self.domainSize();
        if (self.interaction.len != 0 or self.metadata.len != n) return error.InvalidRv64DivisionPhase;
        const window: usize = @min(64, n);
        const denominators = try self.allocator.alloc(Q, L.INVERSES * window);
        defer self.allocator.free(denominators);
        const inverses = try self.allocator.alloc(Q, L.INVERSES * window);
        defer self.allocator.free(inverses);
        const records = try self.allocator.alloc(P.DenominatorsFor(Q), window);
        defer self.allocator.free(records);
        const values = try self.allocator.alloc(M, L.INTERACTION * n);
        errdefer self.allocator.free(values);
        var sum = Q.zero();
        var first: usize = 0;
        while (first < n) {
            const count: usize = @min(window, n - first);
            for (0..count) |j| {
                const row = self.metadata[first + j].queryRow();
                records[j] = P.denominatorsFor(Q, &row, challenges);
                denominators[j * L.INVERSES ..][0..L.INVERSES].* = P.inverseDenominatorsFor(Q, records[j]);
            }
            try core.fields.batchInverseInPlace(Q, denominators[0 .. count * L.INVERSES], inverses[0 .. count * L.INVERSES]);
            for (0..count) |j| {
                const row = physical(first + j, self.log_size);
                const inverse_row = inverses[j * L.INVERSES ..][0..L.INVERSES].*;
                for (inverse_row, 0..) |value, i| store(values, n, row, 4 * i, value);
                sum = sum.add(P.contributionFor(Q, records[j], inverse_row));
                store(values, n, row, L.PREFIX, sum);
            }
            first += count;
        }
        for (sum.toM31Array(), 0..) |correction, c| for (0..n) |r| {
            values[(L.PREFIX + c) * n + r] = values[(L.PREFIX + c) * n + r].sub(correction);
        };
        self.interaction = values;
        self.allocator.free(self.metadata);
        self.metadata = &.{};
        return sum;
    }
};
fn opcodeIndex(opcode: E.O) !usize {
    for (L.OPCODES, 0..) |op, i| if (opcode == op) return i;
    return error.InvalidProductDivisionOpcode;
}
fn store(data: []M, n: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(column + c) * n + row] = v;
}
