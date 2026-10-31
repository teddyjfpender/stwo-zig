//! Narrow service witness, capturing previous clocks explicitly for RAM closure.
const std = @import("std");
const Storage = @import("../../main_storage.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const L = @import("layout.zig");
const E = @import("equations.zig");
const physical = @import("../../../witness.zig").physical;
const P = @import("../program.zig");
pub const Call = struct { call_id: u64, clock: u64, pointer: u64, before: [24]u64, after: [24]u64, previous_clocks: [24]u32, writable: [24]bool = @splat(true) };
pub fn logSize(program: *const P.Program, calls: usize) !u32 {
    const rows = try std.math.mul(usize, calls, program.inputs);
    const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(32, try std.math.add(usize, rows, 1))));
    try validateGeometry(program, calls, 1, log);
    return log;
}
pub fn validateGeometry(program: *const P.Program, calls: usize, first_id: u32, log: u32) !void {
    if (first_id == 0 or first_id >= core.fields.m31.Modulus or @as(u64, first_id) + calls > core.fields.m31.Modulus) return error.InvalidSecpCallSpan;
    if (log < 5 or log > 22 or try std.math.mul(usize, calls, program.inputs) >= (@as(usize, 1) << @intCast(log))) return error.InvalidSecpBridgeGeometry;
    if (try std.math.mul(u64, L.RANGE_COUNT, @as(u64, 1) << @intCast(log)) >= core.fields.m31.Modulus) return error.SecpLookupMassExceeded;
}
pub fn fixedColumnsForLog(a: std.mem.Allocator, program: *const P.Program, log: u32) ![]M {
    try validateGeometry(program, 0, 1, log);
    const n = @as(usize, 1) << @intCast(log);
    const per = program.inputs;
    const fixed = try a.alloc(M, L.FIXED * n);
    @memset(fixed, M.zero());
    for (0..n) |logical| {
        const r = physical(logical, log);
        const coord = logical % per;
        fixed[L.COMPLETE_GROUP * n + r] = M.fromCanonical(@intFromBool(logical < n / per * per));
        fixed[L.COORD * n + r] = M.fromCanonical(@intCast(coord));
        fixed[L.CALL_INDEX * n + r] = M.fromCanonical(@intCast(logical / per));
        fixed[L.FIRST * n + r] = M.fromCanonical(@intFromBool(logical == 0));
        fixed[L.GROUP_FIRST * n + r] = M.fromCanonical(@intFromBool(coord == 0));
        fixed[L.IS_OUTPUT * n + r] = M.fromCanonical(@intFromBool(coord < 3));
        fixed[L.OUTPUT_WIRE * n + r] = M.fromCanonical(if (coord < 3) program.outputs[coord] else 0);
    }
    return fixed;
}
pub const Trace = struct {
    allocator: std.mem.Allocator,
    program: *const P.Program,
    packet_format: E.PacketFormat = .big_endian_bytes_v1,
    log_size: u32,
    calls: u32,
    first_id: u32,
    fixed: []const M,
    owns_fixed: bool = true,
    main: []M,
    main_allocator: ?std.mem.Allocator = null,
    owns_main: bool = true,
    metadata: []Call = &.{},
    interaction: []M = &.{},
    byte_counts: [256]u64 = @splat(0),
    pub fn init(a: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32) !Trace {
        return initWithFormat(a, program, calls, first_id, .big_endian_bytes_v1);
    }
    pub fn initWithFormat(a: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32, format: E.PacketFormat) !Trace {
        return initWithLogAndFormat(a, program, calls, first_id, try logSize(program, calls.len), format);
    }
    pub fn initWithLog(a: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32, log: u32) !Trace {
        return initWithLogAndFormat(a, program, calls, first_id, log, .big_endian_bytes_v1);
    }
    pub fn initWithLogAndFormat(a: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32, log: u32, format: E.PacketFormat) !Trace {
        return initWithFixed(a, .{ .owned = a }, program, calls, first_id, log, format, null);
    }
    pub fn initWithPreparedFixed(a: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32, log: u32, format: E.PacketFormat, fixed: []const M) !Trace {
        return initWithFixed(a, .{ .owned = a }, program, calls, first_id, log, format, fixed);
    }
    pub fn initWithLogAndFormatAndMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32, log: u32, format: E.PacketFormat) !Trace {
        return initWithFixed(a, .{ .owned = main_allocator }, program, calls, first_id, log, format, null);
    }
    pub fn initWithPreparedFixedAndMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32, log: u32, format: E.PacketFormat, fixed: []const M) !Trace {
        return initWithFixed(a, .{ .owned = main_allocator }, program, calls, first_id, log, format, fixed);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, program: *const P.Program, calls: []const Call, first_id: u32, log: u32, format: E.PacketFormat, fixed: ?[]const M, main: []M) !Trace {
        return initWithFixed(a, .{ .borrowed = main }, program, calls, first_id, log, format, fixed);
    }
    fn initWithFixed(a: std.mem.Allocator, storage: Storage.Buffer, program: *const P.Program, calls: []const Call, first_id: u32, log: u32, format: E.PacketFormat, borrowed: ?[]const M) !Trace {
        try validateGeometry(program, calls.len, first_id, log);
        const n = @as(usize, 1) << @intCast(log);
        try storage.validate(L.MAIN * n);
        if (storage == .borrowed) try Storage.exclude(&.{.{ .values = storage.borrowed, .cells = L.MAIN * n }}, std.mem.sliceAsBytes(calls));
        if (storage == .borrowed and borrowed != null) try Storage.exclude(&.{.{ .values = storage.borrowed, .cells = L.MAIN * n }}, std.mem.sliceAsBytes(borrowed.?));
        const fixed = if (borrowed) |data| data else try fixedColumnsForLog(a, program, log);
        errdefer if (borrowed == null) a.free(fixed);
        if (fixed.len != L.FIXED * n) return error.InvalidSecpFixedShape;
        const metadata = try a.dupe(Call, calls);
        errdefer a.free(metadata);
        const main = try storage.acquire(L.MAIN * n);
        errdefer storage.release(main);
        @memset(main, M.zero());
        var result = Trace{ .allocator = a, .program = program, .packet_format = format, .log_size = log, .calls = @intCast(calls.len), .first_id = first_id, .fixed = fixed, .owns_fixed = borrowed == null, .main = main, .main_allocator = storage.allocator(), .owns_main = storage == .owned, .metadata = metadata };
        for (calls, 0..) |call, i| {
            const words = @as(usize, program.inputs) * 4;
            if (call.call_id != @as(u64, first_id) + i or call.clock == 0 or call.clock >= 1 << 22 or call.pointer & 31 != 0 or call.pointer > std.math.maxInt(u64) - (words * 8 - 1)) return error.InvalidSecpBridgeCall;
            for (0..program.inputs) |coord| {
                const row = try rowFromCall(program, call, coord);
                const r = physical(@as(usize, program.inputs) * i + coord, log);
                for (row, 0..) |v, c| main[c * n + r] = v;
                for (L.RANGE_COLUMNS) |c| result.byte_counts[row[c].v] += 1;
            }
            for (words..24) |index| if (call.before[index] != 0 or call.after[index] != 0) return error.InvalidSecpBridgePadding;
        }
        result.byte_counts[0] += L.RANGE_COUNT * (n - @as(usize, program.inputs) * calls.len);
        return result;
    }
    pub fn validateMetadata(self: *const Trace) !void {
        try validateGeometry(self.program, self.calls, self.first_id, self.log_size);
        if (self.metadata.len != self.calls or self.fixed.len != L.FIXED * self.size()) return error.InvalidSecpBridgeMetadata;
    }
    pub fn metadataRow(self: *const Trace, logical: usize) ![L.MAIN]M {
        if (self.metadata.len != self.calls) return error.InvalidSecpBridgeMetadata;
        const per = self.program.inputs;
        return if (logical / per < self.metadata.len) rowFromCall(self.program, self.metadata[logical / per], logical % per) else @splat(M.zero());
    }
    pub fn takeMain(self: *Trace) ![]M {
        if (!self.owns_main) return error.BorrowedCryptoMain;
        try self.validateMetadata();
        if (self.main.len != L.MAIN * self.size()) return error.InvalidSecpSourcePhase;
        const values = self.main;
        self.main = &.{};
        return values;
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
        if (self.owns_fixed) self.allocator.free(self.fixed);
        if (self.owns_main and self.main.len != 0) (self.main_allocator orelse self.allocator).free(self.main);
        self.allocator.free(self.metadata);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn generateInteraction(self: *Trace, ch: E.Challenges) !Q {
        if (self.interaction.len != 0) return error.SecpInteractionAlreadyGenerated;
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
            const row = E.Row{ .packet_format = self.packet_format, .fixed = &fixed, .main = &main, .previous_main = &previous };
            for (0..L.BATCHES) |batch| {
                for (0..3) |j| {
                    const event = E.event(self.program, row, ch, 3 * batch + j);
                    sum = sum.add(event.coefficient.mul(try event.denominator.inv()));
                }
                for (sum.toM31Array(), 0..) |v, c| data[(4 * batch + c) * n + r] = v;
            }
        }
        self.interaction = data;
        return sum;
    }
};

pub fn rowFromCall(program: *const P.Program, call: Call, coord: usize) ![L.MAIN]M {
    const words = @as(usize, program.inputs) * 4;
    if (coord >= program.inputs or call.call_id == 0 or call.call_id >= core.fields.m31.Modulus or call.clock == 0 or call.clock >= 1 << 22 or call.pointer & 31 != 0 or call.pointer > std.math.maxInt(u64) - (words * 8 - 1)) return error.InvalidSecpBridgeCall;
    const tick: u32 = @intCast(4 * call.clock);
    var row: [L.MAIN]M = @splat(M.zero());
    word(&row, L.POINTER, call.pointer, 8);
    word(&row, L.ADDRESS, call.pointer + 32 * coord, 8);
    word(&row, L.TICK_BYTES, tick, 3);
    row[L.ACTIVE] = M.one();
    row[L.CALL_ID] = M.fromCanonical(@intCast(call.call_id));
    row[L.TICK] = M.fromCanonical(tick);
    for (0..3) |bit| row[L.ALIGNED + bit] = M.fromCanonical(@intCast((call.pointer >> @as(u6, @intCast(bit + 5))) & 1));
    var carry: u64 = 0;
    for (0..7) |byte| {
        const value = ((call.pointer >> @as(u6, @intCast(8 * byte))) & 255) + (if (byte == 0) 32 * coord else carry);
        carry = value >> 8;
        row[L.CARRY + byte] = M.fromCanonical(@intCast(carry));
    }
    for (0..4) |lane| {
        const index = 4 * coord + lane;
        const previous = call.previous_clocks[index];
        if (previous >= tick) return error.InvalidSecpBridgeClock;
        if (coord < 3 and !call.writable[index]) return error.InvalidSecpBridgePermission;
        if (coord >= 3 and call.before[index] != call.after[index]) return error.InvalidSecpBridgeRhsMutation;
        word(&row, L.BEFORE + 8 * lane, call.before[index], 8);
        word(&row, L.AFTER + 8 * lane, call.after[index], 8);
        row[L.PREVIOUS + lane] = M.fromCanonical(previous);
        word(&row, L.PREVIOUS_BYTES + 3 * lane, previous, 3);
        word(&row, L.GAP + 3 * lane, tick - previous - 1, 3);
        row[L.WRITABLE + lane] = M.fromCanonical(@intFromBool(call.writable[index]));
    }
    return row;
}
fn word(row: *[L.MAIN]M, column: usize, value: u64, bytes: usize) void {
    for (0..bytes) |i| row[column + i] = M.fromCanonical(@intCast((value >> @as(u6, @intCast(8 * i))) & 255));
}
