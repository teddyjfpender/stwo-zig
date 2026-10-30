//! Experimental shared SHA arithmetic rows. This prepares witnesses only;
//! native window admission and proof-verified caller provenance remain required.
const std = @import("std");
const core = @import("stwo_core");
const Provider = @import("../air/guest_precompile/sha256_compression_rows.zig");
const Caller = @import("../air/guest_precompile/sha256_global_wire_caller_v1.zig");
const Original = @import("../air/guest_precompile/sha256_memory_rows.zig");
const Entry = @import("../runner/guest_precompile/sha256_compression_v1.zig").Entry;
const Frame = @import("../air/block/memory_event.zig").Frame;
const M = core.fields.m31.M31;
pub const Window = struct { index: u32, frame: Frame, entries: []const Entry };
pub const Admission = struct { index: u32, frame: Frame, calls: u32 };
pub const Limits = struct { max_windows: usize = 16, max_calls: usize = 4096 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    compression: Provider.Rows,
    callers: [][]Caller.Row,
    admissions: []Admission,
    offsets: []M,
    pub fn deinit(self: *Owned) void {
        self.compression.deinit();
        for (self.callers) |rows| self.allocator.free(rows);
        self.allocator.free(self.callers);
        self.allocator.free(self.admissions);
        self.allocator.free(self.offsets);
        self.* = undefined;
    }
};
pub fn validate(admissions: []const Admission, limits: Limits) !usize {
    if (limits.max_windows == 0 or limits.max_windows > 64 or limits.max_calls == 0 or admissions.len == 0 or admissions.len > limits.max_windows) return error.InvalidShaBatchLimit;
    var total: usize = 0;
    var previous_end: u64 = 0;
    for (admissions, 0..) |item, i| {
        _ = try Caller.offsetForFrame(item.frame);
        if (item.calls == 0 or item.calls > item.frame.cycle_count or (i != 0 and (item.index <= admissions[i - 1].index or item.frame.global_first_cycle <= previous_end))) return error.InvalidShaBatchWindow;
        previous_end = try std.math.add(u64, item.frame.global_first_cycle - 1, item.frame.cycle_count);
        total = try std.math.add(usize, total, item.calls);
        if (total > limits.max_calls) return error.ShaBatchCallLimit;
    }
    return total;
}
pub fn prepare(a: std.mem.Allocator, windows: []const Window, limits: Limits) !Owned {
    if (windows.len == 0 or windows.len > limits.max_windows) return error.InvalidShaBatchLimit;
    const admissions = try a.alloc(Admission, windows.len);
    errdefer a.free(admissions);
    for (windows, admissions) |window, *admitted| admitted.* = .{ .index = window.index, .frame = window.frame, .calls = std.math.cast(u32, window.entries.len) orelse return error.ShaBatchCallLimit };
    const count = try validate(admissions, limits);
    const records = try a.alloc(Provider.Call, count);
    defer a.free(records);
    const offsets = try a.alloc(M, windows.len);
    errdefer a.free(offsets);
    const callers = try a.alloc([]Caller.Row, windows.len);
    errdefer a.free(callers);
    var ready: usize = 0;
    errdefer for (callers[0..ready]) |rows| a.free(rows);
    var at: usize = 0;
    for (windows, offsets, callers) |window, *offset, *rows| {
        try Original.preflight(window.entries, window.frame.cycle_count);
        offset.* = try Caller.offsetForFrame(window.frame);
        const log = try @import("../air/guest_precompile/sha256_component_profile.zig").callerLog(window.entries.len);
        rows.* = try a.alloc(Caller.Row, @as(usize, 1) << @intCast(log));
        ready += 1;
        @memset(rows.*, @splat(M.zero()));
        // Parameters remain exact even for inactive rows; no source row can
        // choose a different frame than the independently admitted component.
        for (rows.*) |*row| row[Caller.LOGICAL_INPUT_COUNT - 1] = offset.*;
        for (window.entries, rows.*[0..window.entries.len]) |entry, *row| {
            row.* = try Caller.row(entry.call, offset.*);
            records[at] = .{ .execution_clock = try std.math.add(u32, offset.toU32(), entry.call.execution_clock), .state = entry.call.state, .block = entry.call.block };
            at += 1;
        }
    }
    const compression = try Provider.prepare(a, records);
    return .{ .allocator = a, .compression = compression, .callers = callers, .admissions = admissions, .offsets = offsets };
}
