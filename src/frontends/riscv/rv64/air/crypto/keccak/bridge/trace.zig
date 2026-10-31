//! Narrow service witness, capturing previous clocks explicitly for RAM closure.
const std = @import("std");
const Storage = @import("../../main_storage.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const E = @import("equations.zig");
const physical = @import("../../../witness.zig").physical;
pub const Call = struct { call_id: u64, clock: u64, pointer: u64, before: [25]u64, after: [25]u64, previous_clocks: [25]u32 };
pub fn logSize(calls: usize) !u32 {
    _ = try @import("../layout.zig").admitRoster(&.{calls}, &.{});
    const rows = try std.math.mul(usize, calls, 25);
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(32, rows)));
    if (log > 26) return error.KeccakBridgeDomainTooLarge;
    _ = try @import("../layout.zig").admitRoster(&.{}, &.{40 * (@as(u64, 1) << @intCast(log))});
    return log;
}
pub fn validateGeometry(calls: usize, first_id: u32, log: u32) !void {
    const minimum = try logSize(calls);
    if (first_id == 0 or first_id >= core.fields.m31.Modulus or @as(u64, first_id) + calls > core.fields.m31.Modulus) return error.InvalidKeccakCallId;
    if (log < 5 or log > 26 or log < minimum) return error.InvalidKeccakBridgeGeometry;
    _ = try @import("../layout.zig").admitRoster(&.{calls}, &.{40 * (@as(u64, 1) << @intCast(log))});
}
pub fn fixedColumns(a: std.mem.Allocator, calls: usize, first_id: u32) ![]M {
    const log = try logSize(calls);
    try validateGeometry(calls, first_id, log);
    return fixedColumnsForLog(a, log);
}
pub fn fixedColumnsForLog(a: std.mem.Allocator, log: u32) ![]M {
    if (log < 5 or log > 26) return error.InvalidKeccakBridgeGeometry;
    _ = try @import("../layout.zig").admitRoster(&.{}, &.{40 * (@as(u64, 1) << @intCast(log))});
    const n = @as(usize, 1) << @intCast(log);
    const fixed = try a.alloc(M, L.FIXED * n);
    @memset(fixed, M.zero());
    fixed[L.FIRST * n + physical(0, log)] = M.one();
    const complete_rows = n / 25 * 25;
    for (0..n) |logical| {
        const r = physical(logical, log);
        fixed[L.COMPLETE_GROUP * n + r] = M.fromCanonical(@intFromBool(logical < complete_rows));
        fixed[L.LANE * n + r] = M.fromCanonical(@intCast(logical % 25));
        fixed[L.CALL_INDEX * n + r] = M.fromCanonical(@intCast(logical / 25));
        fixed[L.GROUP_FIRST * n + r] = M.fromCanonical(@intFromBool(logical % 25 == 0));
    }
    return fixed;
}
pub const Trace = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    calls: u32,
    first_id: u32,
    fixed: []M,
    main: []M,
    main_allocator: ?std.mem.Allocator = null,
    owns_main: bool = true,
    metadata: []Call = &.{},
    interaction: []M = &.{},
    byte_counts: [256]u64 = @splat(0),
    pub fn init(a: std.mem.Allocator, calls: []const Call, first_id: u32) !Trace {
        return initWithLog(a, calls, first_id, try logSize(calls.len));
    }
    pub fn initWithLog(a: std.mem.Allocator, calls: []const Call, first_id: u32, log: u32) !Trace {
        return initWithLogAndMainAllocator(a, a, calls, first_id, log);
    }
    pub fn initWithLogAndMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, calls: []const Call, first_id: u32, log: u32) !Trace {
        return build(a, .{ .owned = main_allocator }, calls, first_id, log);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, calls: []const Call, first_id: u32, log: u32, main: []M) !Trace {
        return build(a, .{ .borrowed = main }, calls, first_id, log);
    }
    fn build(a: std.mem.Allocator, storage: Storage.Buffer, calls: []const Call, first_id: u32, log: u32) !Trace {
        try validateGeometry(calls.len, first_id, log);
        const n = @as(usize, 1) << @intCast(log);
        try storage.validate(L.MAIN * n);
        if (storage == .borrowed) try Storage.exclude(&.{.{ .values = storage.borrowed, .cells = L.MAIN * n }}, std.mem.sliceAsBytes(calls));
        const fixed = try fixedColumnsForLog(a, log);
        errdefer a.free(fixed);
        const metadata = try a.dupe(Call, calls);
        errdefer a.free(metadata);
        const main = try storage.acquire(L.MAIN * n);
        errdefer storage.release(main);
        @memset(main, M.zero());
        var result = Trace{ .allocator = a, .log_size = log, .calls = @intCast(calls.len), .first_id = first_id, .fixed = fixed, .main = main, .main_allocator = storage.allocator(), .owns_main = storage == .owned, .metadata = metadata };
        for (calls, 0..) |call, i| {
            if (call.call_id != @as(u64, first_id) + i or call.clock == 0 or call.clock >= 1 << 22 or call.pointer & 7 != 0 or call.pointer > std.math.maxInt(u64) - 199) return error.InvalidKeccakBridgeCall;
            for (0..25) |lane| {
                const row = try rowFromCall(call, lane);
                const r = physical(25 * i + lane, log);
                for (row, 0..) |v, c| main[c * n + r] = v;
                for (L.RANGE_COLUMNS) |c| result.byte_counts[row[c].v] += 1;
            }
        }
        result.byte_counts[0] += L.RANGE_COUNT * (n - 25 * calls.len);
        return result;
    }
    pub fn validateMetadata(self: *const Trace) !void {
        try validateGeometry(self.calls, self.first_id, self.log_size);
        if (self.metadata.len != self.calls) return error.InvalidKeccakBridgeMetadata;
    }
    pub fn metadataRow(self: *const Trace, logical: usize) ![L.MAIN]M {
        const index = logical % self.size();
        return if (index / 25 < self.metadata.len) rowFromCall(self.metadata[index / 25], index % 25) else @splat(M.zero());
    }
    pub fn takeMain(self: *Trace) ![]M {
        if (!self.owns_main) return error.BorrowedCryptoMain;
        try self.validateMetadata();
        if (self.main.len != L.MAIN * self.size()) return error.InvalidKeccakMainPhase;
        const data = self.main;
        self.main = &.{};
        return data;
    }
    pub fn releaseMain(self: *Trace) !void {
        try self.validateMetadata();
        if (self.main.len != L.MAIN * self.size()) return error.InvalidCryptoMainPhase;
        if (self.owns_main) (self.main_allocator orelse self.allocator).free(self.main);
        self.main = &.{};
    }
    pub fn size(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        if (self.owns_main and self.main.len != 0) (self.main_allocator orelse self.allocator).free(self.main);
        self.allocator.free(self.metadata);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn generateInteraction(self: *Trace, ch: E.Challenges) !Q {
        if (self.interaction.len != 0) return error.KeccakInteractionAlreadyGenerated;
        try self.validateMetadata();
        const n = self.size();
        const data = try self.allocator.alloc(M, L.INTERACTION * n);
        errdefer self.allocator.free(data);
        var sum = Q.zero();
        const previous: [L.PREVIOUS_MAIN]Q = @splat(Q.zero());
        for (0..n) |logical| {
            const r = physical(logical, self.log_size);
            var fixed: [L.FIXED]Q = undefined;
            var main: [L.MAIN]Q = undefined;
            for (&fixed, 0..) |*v, c| v.* = Q.fromBase(self.fixed[c * n + r]);
            const base = try self.metadataRow(logical);
            for (&main, base) |*v, value| v.* = Q.fromBase(value);
            const row = E.Row{ .fixed = &fixed, .main = &main, .previous_main = &previous };
            for (0..L.BATCHES) |batch| {
                for (0..3) |j| {
                    const event = E.event(row, ch, 3 * batch + j);
                    sum = sum.add(event.coefficient.mul(try event.denominator.inv()));
                }
                for (sum.toM31Array(), 0..) |v, c| data[(4 * batch + c) * n + r] = v;
            }
        }
        self.interaction = data;
        return sum;
    }
};

pub fn rowFromCall(call: Call, lane: usize) ![L.MAIN]M {
    if (lane >= 25 or call.call_id == 0 or call.call_id >= core.fields.m31.Modulus or call.clock == 0 or call.clock >= 1 << 22 or call.pointer & 7 != 0 or call.pointer > std.math.maxInt(u64) - 199) return error.InvalidKeccakBridgeCall;
    const tick: u32 = @intCast(4 * call.clock);
    const prev = call.previous_clocks[lane];
    if (prev >= tick) return error.InvalidKeccakBridgeClock;
    var row: [L.MAIN]M = @splat(M.zero());
    word(&row, L.POINTER, call.pointer, 8);
    word(&row, L.ADDRESS, call.pointer + 8 * lane, 8);
    word(&row, L.TICK_BYTES, tick, 3);
    word(&row, L.PREVIOUS_BYTES, prev, 3);
    word(&row, L.GAP, tick - prev - 1, 3);
    word(&row, L.BEFORE, call.before[lane], 8);
    word(&row, L.AFTER, call.after[lane], 8);
    row[L.ACTIVE] = M.one();
    row[L.CALL_ID] = M.fromCanonical(@intCast(call.call_id));
    row[L.TICK] = M.fromCanonical(tick);
    row[L.PREVIOUS] = M.fromCanonical(prev);
    for (0..5) |bit| row[L.ALIGNED + bit] = M.fromCanonical(@intCast((call.pointer >> @as(u6, @intCast(bit + 3))) & 1));
    var carry: u64 = 0;
    for (0..7) |byte| {
        const v = ((call.pointer >> @as(u6, @intCast(8 * byte))) & 255) + (if (byte == 0) 8 * lane else carry);
        carry = v >> 8;
        row[L.CARRY + byte] = M.fromCanonical(@intCast(carry));
    }
    return row;
}
fn word(row: *[L.MAIN]M, column: usize, value: u64, bytes: usize) void {
    for (0..bytes) |i| row[column + i] = M.fromCanonical(@intCast((value >> @as(u6, @intCast(8 * i))) & 255));
}
