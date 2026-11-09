//! Eight-column CPU frontier, built once from independently captured calls.
//! Compact records survive MAIN ownership transfer; they contain no RAM data.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const F = A.crypto.keccak_sponge.serialized.frontier;
const Calls = A.crypto.keccak_sponge.types.Call;
pub const Record = struct { pointer: u64, epoch: u16, tick: u24 };
pub const Source = struct {
    allocator: std.mem.Allocator,
    log: u32,
    epoch: u16,
    ordinal: u32,
    records: []Record,
    main: []M,
    pub fn init(a: std.mem.Allocator, records: []const Record, calls: u32, log: u32, epoch: u16, ordinal: u32) !Source {
        try F.validatePublic(calls, log, epoch, ordinal);
        if (records.len != calls) return error.SpongeCpuCallCoverage;
        // Validate every record before allocating a wide column buffer.
        for (records, 0..) |record, i| {
            _ = try F.row(record.pointer, record.epoch, record.tick, epoch);
            if (i != 0 and record.tick <= records[i - 1].tick) return error.SpongeCpuCallOrder;
        }
        const owned = try a.dupe(Record, records);
        errdefer a.free(owned);
        const row_count = @as(usize, 1) << @intCast(log);
        const main = try a.alloc(M, try std.math.mul(usize, row_count, F.MAIN));
        errdefer a.free(main);
        @memset(main, M.zero());
        for (records, 0..) |record, i| {
            const values = try F.row(record.pointer, record.epoch, record.tick, epoch);
            const p = A.witness.physical(i, log);
            for (values, 0..) |value, c| main[c * row_count + p] = value;
        }
        return .{ .allocator = a, .log = log, .epoch = epoch, .ordinal = ordinal, .records = owned, .main = main };
    }
    pub fn initCalls(a: std.mem.Allocator, calls: []const Calls, count: u32, log: u32, epoch: u16, ordinal: u32) !Source {
        if (calls.len != count) return error.SpongeCpuCallCoverage;
        const records = try a.alloc(Record, calls.len);
        defer a.free(records);
        for (calls, records) |call, *record| record.* = .{ .pointer = call.pointer, .epoch = call.epoch, .tick = call.tick };
        return init(a, records, count, log, epoch, ordinal);
    }
    pub fn rows(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log);
    }
    pub fn row(self: *const Source, logical: usize) ![F.MAIN]M {
        if (logical >= self.rows()) return error.SpongeCpuRow;
        if (logical >= self.records.len) return @splat(M.zero());
        const r = self.records[logical];
        return F.row(r.pointer, r.epoch, r.tick, self.epoch);
    }
    pub fn takeMain(self: *Source) ![]M {
        if (self.main.len != self.rows() * F.MAIN) return error.SpongeCpuMainConsumed;
        const out = self.main;
        self.main = &.{};
        return out;
    }
    /// Atomic histogram admission. Both active and padded rows issue two unit
    /// clock queries; pointer limbs inherit canonicality through unit OWNER.
    pub fn mergeRanges(self: *const Source, counts16: []u64, counts8: []u64, main16: []M, main8: []M) !void {
        if (counts16.len != 65536 or counts8.len != 256 or main16.len != 65536 or main8.len != 256) return error.SpongeCpuRangeShape;
        const h16 = try self.allocator.alloc(u64, 65536);
        defer self.allocator.free(h16);
        const h8 = try self.allocator.alloc(u64, 256);
        defer self.allocator.free(h8);
        @memset(h16, 0);
        @memset(h8, 0);
        for (self.records) |r| {
            h16[@as(u16, @truncate(r.tick))] += 1;
            h8[r.tick >> 16] += 1;
        }
        h16[0] += self.rows() - self.records.len;
        h8[0] += self.rows() - self.records.len;
        // Check BOTH tables completely before any provider is mutated.
        inline for (.{ counts16, counts8 }, .{ h16, h8 }) |counts, histogram| {
            var mass: u64 = 0;
            for (counts, histogram) |v, extra| mass = try std.math.add(u64, mass, try std.math.add(u64, v, extra));
            if (mass >= core.fields.m31.Modulus) return error.SpongeCpuRangeMass;
        }
        inline for (.{ counts16, counts8 }, .{ h16, h8 }, .{ main16, main8 }, .{ @as(u32, 16), @as(u32, 8) }) |counts, histogram, main, log| {
            for (counts, histogram, 0..) |*v, extra, logical| {
                v.* += extra;
                main[A.witness.physical(logical, log)] = M.fromCanonical(@intCast(v.*));
            }
        }
    }
    pub fn mergeInto(self: *const Source, source: *@import("../../word16_global_execution/services/roster.zig").Sources) !void {
        if (source.sponge_plan != null or source.sponge[0] != null or source.sponge[1] != null) return error.SpongeCpuRequiresDetachedSetup;
        if (source.core.range16.interaction.len != 0 or source.core.range8.interaction.len != 0) return error.InvalidCombinedRangePhase;
        try self.mergeRanges(source.core.counts16, source.core.counts8, source.core.range16.main, source.core.range8.main);
    }
    pub fn deinit(self: *Source) void {
        self.allocator.free(self.main);
        self.allocator.free(self.records);
        self.* = undefined;
    }
};
test "sponge CPU frontier metadata survives ownership and range admission is atomic" {
    const a = std.testing.allocator;
    var source = try Source.init(a, &.{.{ .pointer = 4096, .epoch = 2, .tick = 65537 }}, 1, 5, 2, 1);
    defer source.deinit();
    const main = try source.takeMain();
    defer a.free(main);
    const row = try source.row(0);
    try std.testing.expectEqual(@as(u32, 1), row[F.c.active].v);
    try std.testing.expectEqual(@as(u32, 0), (try source.row(31))[F.c.active].v);
    try std.testing.expectError(error.SpongeCpuMainConsumed, source.takeMain());
    const c16 = try a.alloc(u64, 65536);
    defer a.free(c16);
    const c8 = try a.alloc(u64, 256);
    defer a.free(c8);
    const m16 = try a.alloc(M, 65536);
    defer a.free(m16);
    const m8 = try a.alloc(M, 256);
    defer a.free(m8);
    @memset(c16, 0);
    @memset(c8, 0);
    @memset(m16, M.zero());
    @memset(m8, M.zero());
    c8[255] = core.fields.m31.Modulus;
    try std.testing.expectError(error.SpongeCpuRangeMass, source.mergeRanges(c16, c8, m16, m8));
    try std.testing.expectEqual(@as(u64, 0), c16[0]);
    c8[255] = 0;
    try source.mergeRanges(c16, c8, m16, m8);
    try std.testing.expectEqual(@as(u64, 31), c16[0]);
    try std.testing.expectEqual(@as(u64, 31), c8[0]);
    try std.testing.expectEqual(@as(u64, 1), c16[1]);
    try std.testing.expectEqual(@as(u64, 1), c8[1]);
    try std.testing.expectError(error.SpongeCpuCallCoverage, Source.init(a, &.{}, 1, 5, 2, 1));
    try std.testing.expectError(error.SpongeFrontierRecord, Source.init(a, &.{.{ .pointer = 4096, .epoch = 1, .tick = 1 }}, 1, 5, 2, 1));
    try std.testing.expectError(error.SpongeCpuCallOrder, Source.init(a, &.{ .{ .pointer = 4096, .epoch = 2, .tick = 1 }, .{ .pointer = 4096, .epoch = 2, .tick = 1 } }, 2, 5, 2, 1));
}
