//! Independently reconstructed owner rows for one bounded shared Keccak shard.
//! This is fixed geometry, not execution or proof authority. Both control and
//! frame-aware RAM projections must consume these exact fixed selectors.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Geometry = @import("../air/guest_precompile/keccakf_authority.zig").geometry;
const Trace = @import("../air/guest_precompile/keccakf_trace.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Order = @import("../recursion/air/framework_interaction.zig");
const M = core.fields.m31.M31;
pub const Window = struct { index: u32, frame: Frame, calls: u32 };
pub const Limits = struct {
    max_windows: usize = 16,
    max_calls: usize = Trace.maximum_calls_per_shard,
    max_fixed_bytes: usize = 64 << 20,
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    windows: []Window,
    first_call: []usize,
    calls: usize,
    log_size: u32,
    selector_bytes: usize,
    fixed_bytes: usize,
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.first_call);
        self.allocator.free(self.windows);
        self.* = undefined;
    }
    pub fn derive(a: std.mem.Allocator, windows: []const Window, limits: Limits) !Owned {
        if (limits.max_windows == 0 or limits.max_windows > 64 or windows.len == 0 or windows.len > limits.max_windows or limits.max_calls == 0 or limits.max_calls > Trace.maximum_calls_per_shard or limits.max_fixed_bytes == 0) return error.InvalidKeccakBatchLimit;
        var total: usize = 0;
        var end: u64 = 0;
        for (windows, 0..) |window, i| {
            if (window.frame.clock_frame != .leaf_local or window.calls == 0 or window.calls > window.frame.cycle_count or (i != 0 and (window.index <= windows[i - 1].index or window.frame.global_first_cycle <= end))) return error.InvalidKeccakWindow;
            _ = try Integer.baseClockFromPublicFrame(window.frame);
            end = try std.math.add(u64, window.frame.global_first_cycle - 1, window.frame.cycle_count);
            _ = try std.math.mul(u64, end, 4);
            total = try std.math.add(usize, total, window.calls);
            if (total > limits.max_calls) return error.KeccakBatchCallLimit;
        }
        const slots = try std.math.divCeil(usize, total, Geometry.operations_per_slot);
        const rows = try std.math.mul(usize, slots, Geometry.rows_per_slot);
        const log: u32 = @max(Trace.minimum_log_size, std.math.log2_int_ceil(usize, rows));
        if (log > Trace.maximum_log_size) return error.KeccakBatchCallLimit;
        const bytes = try std.math.mul(usize, try std.math.mul(usize, windows.len, @as(usize, 1) << @intCast(log)), @sizeOf(M));
        const clock_bytes = try std.math.mul(usize, @as(usize, 8) << @intCast(log), @sizeOf(M));
        const fixed_bytes = try std.math.add(usize, bytes, clock_bytes);
        if (fixed_bytes > limits.max_fixed_bytes) return error.KeccakSelectorBudgetExceeded;
        const copy = try a.dupe(Window, windows);
        errdefer a.free(copy);
        const first = try a.alloc(usize, windows.len);
        var at: usize = 0;
        for (windows, first) |window, *offset| {
            offset.* = at;
            at += window.calls;
        }
        return .{ .allocator = a, .windows = copy, .first_call = first, .calls = total, .log_size = log, .selector_bytes = bytes, .fixed_bytes = fixed_bytes };
    }
    /// Logical row of the original paired trace's caller input. The paired
    /// operation may belong to another window; no slot-wide owner is assumed.
    pub fn callerRow(call: usize) usize {
        return (call / Geometry.operations_per_slot) * Geometry.rows_per_slot + call % Geometry.operations_per_slot;
    }
    pub fn selected(self: *const Owned, window: usize, logical_row: usize) bool {
        if (window >= self.windows.len) return false;
        const group = logical_row % Geometry.rows_per_slot;
        if (group >= Geometry.operations_per_slot) return false;
        const call = (logical_row / Geometry.rows_per_slot) * Geometry.operations_per_slot + group;
        return call >= self.first_call[window] and call - self.first_call[window] < self.windows[window].calls;
    }
    pub fn fixed(self: *const Owned, a: std.mem.Allocator) ![]Column {
        const out = try a.alloc(Column, self.windows.len);
        errdefer a.free(out);
        var ready: usize = 0;
        errdefer for (out[0..ready]) |column| a.free(column.values);
        const size = @as(usize, 1) << @intCast(self.log_size);
        for (out, 0..) |*column, window| {
            const values = try a.alloc(M, size);
            column.* = .{ .log_size = self.log_size, .values = values };
            ready += 1;
            for (0..size) |logical| values[Order.committedRow(logical, self.log_size)] = M.fromCanonical(@intFromBool(self.selected(window, logical)));
        }
        return out;
    }
    pub fn freeFixed(a: std.mem.Allocator, columns: []Column) void {
        for (columns) |column| a.free(column.values);
        a.free(columns);
    }
    /// One shared RAM bridge uses the original caller enabler, without an
    /// owner multiplier. These fixed bytes choose its independently admitted
    /// frame. The per-window control selectors use exactly this same schedule.
    pub fn clockAt(self: *const Owned, logical_row: usize) !u64 {
        for (self.windows, 0..) |window, i| if (self.selected(i, logical_row)) return Integer.baseClockFromPublicFrame(window.frame);
        return 0;
    }
    pub fn clockFixed(self: *const Owned, a: std.mem.Allocator) ![]Column {
        const out = try a.alloc(Column, 8);
        errdefer a.free(out);
        var ready: usize = 0;
        errdefer for (out[0..ready]) |column| a.free(column.values);
        const size = @as(usize, 1) << @intCast(self.log_size);
        for (out) |*column| {
            const values = try a.alloc(M, size);
            column.* = .{ .log_size = self.log_size, .values = values };
            ready += 1;
        }
        for (0..size) |logical| {
            const clock = try self.clockAt(logical);
            const physical = Order.committedRow(logical, self.log_size);
            for (out, 0..) |column, i| @constCast(column.values)[physical] = M.fromCanonical(@as(u8, @truncate(clock >> @intCast(8 * i))));
        }
        return out;
    }
    pub fn requireClockFixed(self: *const Owned, columns: []const Column) !void {
        if (columns.len != 8) return error.InvalidKeccakClockSelectors;
        const size = @as(usize, 1) << @intCast(self.log_size);
        for (columns) |column| if (column.log_size != self.log_size or column.values.len != size) return error.InvalidKeccakClockSelectors;
        for (0..size) |logical| {
            const clock = try self.clockAt(logical);
            const physical = Order.committedRow(logical, self.log_size);
            for (columns, 0..) |column, i| if (column.values[physical].toU32() != @as(u8, @truncate(clock >> @intCast(8 * i)))) return error.InvalidKeccakClockSelectors;
        }
    }
    /// The verifier calls this on fixed columns reconstructed from independently
    /// admitted window metadata, never on a producer-selected owner schedule.
    pub fn requireFixed(self: *const Owned, columns: []const Column) !void {
        if (columns.len != self.windows.len) return error.InvalidKeccakOwnerSelectors;
        const size = @as(usize, 1) << @intCast(self.log_size);
        for (columns, 0..) |column, window| {
            if (column.log_size != self.log_size or column.values.len != size) return error.InvalidKeccakOwnerSelectors;
            for (0..size) |logical| if (column.values[Order.committedRow(logical, self.log_size)].toU32() != @intFromBool(self.selected(window, logical))) return error.InvalidKeccakOwnerSelectors;
        }
    }
};
test "Keccak owner selectors separate paired operations and reject reassignment" {
    const a = std.testing.allocator;
    const windows = [_]Window{
        .{ .index = 1, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 10 }, .calls = 1 },
        .{ .index = 3, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 101, .cycle_count = 10 }, .calls = 2 },
    };
    var owner = try Owned.derive(a, &windows, .{});
    defer owner.deinit();
    try std.testing.expect(owner.selected(0, 0));
    try std.testing.expect(!owner.selected(0, 1));
    try std.testing.expect(owner.selected(1, 1));
    try std.testing.expect(owner.selected(1, Geometry.rows_per_slot));
    try std.testing.expect(!owner.selected(1, Geometry.rows_per_slot + 1));
    try std.testing.expect(!owner.selected(1, 27));
    const fixed = try owner.fixed(a);
    defer Owned.freeFixed(a, fixed);
    try owner.requireFixed(fixed);
    const row = Order.committedRow(1, owner.log_size);
    @constCast(fixed[0].values)[row] = M.one();
    @constCast(fixed[1].values)[row] = M.zero();
    try std.testing.expectError(error.InvalidKeccakOwnerSelectors, owner.requireFixed(fixed));
}
test "Keccak owner layout rejects overlapping windows and bounds fixed storage" {
    var windows = [_]Window{
        .{ .index = 1, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 10 }, .calls = 1 },
        .{ .index = 2, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 10, .cycle_count = 10 }, .calls = 1 },
    };
    try std.testing.expectError(error.InvalidKeccakWindow, Owned.derive(std.testing.allocator, &windows, .{}));
    windows[1].frame.global_first_cycle = 11;
    try std.testing.expectError(error.KeccakSelectorBudgetExceeded, Owned.derive(std.testing.allocator, &windows, .{ .max_fixed_bytes = 1 }));
    try std.testing.expectError(error.KeccakBatchCallLimit, Owned.derive(std.testing.allocator, &windows, .{ .max_calls = 1 }));
}

test "Keccak shared clock columns equal the original owner-selector polynomial" {
    const a = std.testing.allocator;
    const windows = [_]Window{
        .{ .index = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 10 }, .calls = 1 },
        .{ .index = 1, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = (1 << 32) + 101, .cycle_count = 10 }, .calls = 2 },
    };
    var owner = try Owned.derive(a, &windows, .{});
    defer owner.deinit();
    const selectors = try owner.fixed(a);
    defer Owned.freeFixed(a, selectors);
    const clocks = try owner.clockFixed(a);
    defer Owned.freeFixed(a, clocks);
    try owner.requireClockFixed(clocks);
    // Exact equality on the same complete interpolation domain establishes
    // the polynomial identity; no Boolean assumption is made at OODS points.
    const size = @as(usize, 1) << @intCast(owner.log_size);
    for (0..size) |physical| for (clocks, 0..) |column, byte| {
        var sum = M.zero();
        for (windows, selectors) |window, selector| {
            const clock = try Integer.baseClockFromPublicFrame(window.frame);
            sum = sum.add(selector.values[physical].mul(M.fromCanonical(@as(u8, @truncate(clock >> @intCast(8 * byte))))));
        }
        try std.testing.expect(sum.eql(column.values[physical]));
    };
    // Move the second paired operation to another frame while retaining the
    // control selector; the independently reconstructed fixed root rejects it.
    @constCast(clocks[4].values)[Order.committedRow(1, owner.log_size)] = M.zero();
    try std.testing.expectError(error.InvalidKeccakClockSelectors, owner.requireClockFixed(clocks));
}
