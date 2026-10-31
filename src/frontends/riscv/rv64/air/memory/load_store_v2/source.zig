//! Main is written once. Lookup inputs survive MAIN adoption as82B metadata.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("../closed_ram/mod.zig");
const NativeFill = @import("native_fill.zig");
const T = @import("types.zig");
const L = @import("layout.zig");
const Native = @import("native.zig");
const M = T.M;
pub const Event = Native.Event;
pub const MainBuffers = struct { main: []M };
pub const Metadata = struct {
    range16: [35]u16,
    range8: [5]u8,
    selection_words: [2]u16,
    opcode: u8,
    flags: u8,
    pub fn selectionIndex(self: @This()) u32 {
        return @as(u32, self.selection_words[0]) | (@as(u32, self.selection_words[1]) << 16);
    }
    pub fn active(self: @This()) M {
        return M.fromCanonical(self.flags & 1);
    }
    pub fn ramTuple(self: @This(), after: bool) [14]M {
        var tuple: [14]M = @splat(M.zero());
        tuple[0] = M.one();
        for (0..4) |i| tuple[1 + i] = M.fromCanonical(self.range16[i]);
        tuple[5] = M.fromCanonical(self.range16[if (after) 5 else 4]);
        tuple[6] = M.fromCanonical(self.range16[if (after) 7 else 6]);
        tuple[7] = M.fromCanonical(self.range8[if (after) 1 else 0]);
        for (0..4) |i| tuple[8 + i] = M.fromCanonical(self.range16[(if (after) @as(usize, 12) else 8) + i]);
        tuple[12] = M.fromCanonical((self.flags >> 1) & 1);
        tuple[13] = M.fromCanonical((self.flags >> 2) & 1);
        return tuple;
    }
    pub fn ownerTuple(self: @This()) [19]M {
        var tuple: [19]M = undefined;
        tuple[0] = M.fromCanonical(self.opcode);
        for (0..16) |i| tuple[1 + i] = M.fromCanonical(self.range16[18 + i]);
        tuple[17] = M.fromCanonical(self.range16[5]);
        tuple[18] = M.fromCanonical(@as(u32, self.range16[7]) + 65536 * @as(u32, self.range8[1]));
        return tuple;
    }
};
comptime {
    std.debug.assert(@sizeOf(Metadata) == 82);
}
pub fn sizeForLog(log: u32) !usize {
    if (log < 5 or log > 22) return error.InvalidLsGeometry;
    return @as(usize, 1) << @intCast(log);
}
pub fn fixed(a: std.mem.Allocator, log: u32) ![]M {
    const n = try sizeForLog(log);
    const data = try a.alloc(M, 3 * n);
    @memset(data, M.zero());
    for (0..n) |i| data[R.trace.physical(i, log)] = M.fromCanonical(@intCast(i));
    data[n + R.trace.physical(0, log)] = M.one();
    data[2 * n + R.trace.physical(n - 1, log)] = M.one();
    return data;
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    rows: u32,
    fixed: []M,
    main: []M,
    owns_main: bool,
    interaction: []M = &.{},
    metadata: []Metadata,
    counts16: []u64,
    counts8: []u64,
    selection_counts: []u64,
    pub fn init(a: std.mem.Allocator, events: []const Event, log: u32) !Source {
        return initInternal(a, events, log, null, engine.work_pool.currentScopedPool(), null);
    }
    pub fn initWithMainBuffers(a: std.mem.Allocator, events: []const Event, log: u32, buffers: MainBuffers) !Source {
        return initInternal(a, events, log, buffers, engine.work_pool.currentScopedPool(), null);
    }
    fn initInternal(a: std.mem.Allocator, events: []const Event, log: u32, buffers: ?MainBuffers, pool: ?*engine.work_pool.WorkPool, fail_after: ?usize) !Source {
        const n = try sizeForLog(log);
        if (events.len >= n) return error.LsCapacityExceeded;
        _ = try @import("../../word16_v1/function_bus.zig").admitPositiveMass(&.{ 35 * @as(u64, @intCast(n)), 5 * @as(u64, @intCast(n)), @as(u64, @intCast(n)) });
        if (buffers) |b| {
            if (b.main.len != L.MAIN * n) return error.InvalidLsMain;
            const x = @intFromPtr(b.main.ptr);
            const y = @intFromPtr(events.ptr);
            const xe = std.math.add(usize, x, std.mem.sliceAsBytes(b.main).len) catch return error.InvalidMemoryInputSpan;
            const ye = std.math.add(usize, y, std.mem.sliceAsBytes(events).len) catch return error.InvalidMemoryInputSpan;
            if (events.len != 0 and x < ye and y < xe) return error.OverlappingLsInputs;
        }
        for (events) |e| try Native.validate(e);
        const geometry = try fixed(a, log);
        errdefer a.free(geometry);
        const c16 = try a.alloc(u64, 65536);
        errdefer a.free(c16);
        const c8 = try a.alloc(u64, 256);
        errdefer a.free(c8);
        const cs = try a.alloc(u64, 131072);
        errdefer a.free(cs);
        const metadata = try a.alloc(Metadata, n);
        errdefer a.free(metadata);
        const main = if (buffers) |b| b.main else try a.alloc(M, L.MAIN * n);
        errdefer if (buffers == null) a.free(main);
        @memset(c16, 0);
        @memset(c8, 0);
        @memset(cs, 0);
        const fill = NativeFill.Fill{ .events = events, .log = log, .main = main, .metadata = metadata };
        if (comptime @import("builtin").is_test) {
            if (fail_after) |after| {
                try NativeFill.testing.failSubmission(fill, a, c16, c8, cs, pool orelse return error.ExpectedLsNativePool, after);
            } else try fill.run(a, c16, c8, cs, pool);
        } else try fill.run(a, c16, c8, cs, pool);
        return .{ .allocator = a, .log_size = log, .rows = @intCast(events.len), .fixed = geometry, .main = main, .owns_main = buffers == null, .metadata = metadata, .counts16 = c16, .counts8 = c8, .selection_counts = cs };
    }
    pub const testing = if (@import("builtin").is_test) struct {
        pub fn initSerial(a: std.mem.Allocator, events: []const Event, log: u32) !Source {
            return initInternal(a, events, log, null, null, null);
        }
        pub fn failSubmission(a: std.mem.Allocator, events: []const Event, log: u32, buffers: MainBuffers, pool: *engine.work_pool.WorkPool, after: usize) !Source {
            return initInternal(a, events, log, buffers, pool, after);
        }
    } else struct {};
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) void {
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    pub fn takeMainForCommit(self: *Source) ![]M {
        if (!self.owns_main or self.main.len == 0) return error.LsMainNotOwned;
        const m = self.main;
        self.main = &.{};
        self.owns_main = false;
        return m;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.interaction);
        a.free(self.metadata);
        a.free(self.counts16);
        a.free(self.counts8);
        a.free(self.selection_counts);
        self.* = undefined;
    }
    pub fn generate(self: *Source, ch: T.Challenges, dict16: []const T.Q, dict8: []const T.Q) !T.Claims {
        return @import("interaction.zig").generate(self, ch, dict16, dict8);
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const values = switch (tree) {
            0 => self.fixed,
            1 => if (self.main.len != 0) self.main else return error.LsMainUnavailable,
            2 => if (self.interaction.len != 0) self.interaction else return error.LsInteractionUnavailable,
            else => return error.InvalidLsTree,
        };
        const n = self.size();
        const headers = try a.alloc(engine.pcs.ColumnEvaluation, values.len / n);
        for (headers, 0..) |*h, i| h.* = .{ .log_size = self.log_size, .values = values[i * n ..][0..n] };
        return headers;
    }
};
