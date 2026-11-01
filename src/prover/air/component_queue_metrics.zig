//! Optional per-component allocation telemetry for cooperative composition.
const std = @import("std");

/// Diagnostic pass-through allocator recording live and peak bytes.
pub const PeakCounter = struct {
    parent: std.mem.Allocator,
    live: std.atomic.Value(isize) = .init(0),
    peak: std.atomic.Value(isize) = .init(0),

    pub fn allocator(self: *PeakCounter) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }
    const vtable = std.mem.Allocator.VTable{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    fn from(context: *anyopaque) *PeakCounter {
        return @ptrCast(@alignCast(context));
    }
    fn add(self: *PeakCounter, delta: isize) void {
        const value = self.live.fetchAdd(delta, .monotonic) + delta;
        var observed = self.peak.load(.monotonic);
        while (value > observed) {
            observed = self.peak.cmpxchgWeak(observed, value, .monotonic, .monotonic) orelse break;
        }
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self = from(context);
        const result = self.parent.rawAlloc(len, alignment, ret) orelse return null;
        self.add(@intCast(len));
        return result;
    }
    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const self = from(context);
        if (!self.parent.rawResize(memory, alignment, new_len, ret)) return false;
        self.add(@as(isize, @intCast(new_len)) - @as(isize, @intCast(memory.len)));
        return true;
    }
    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const self = from(context);
        const result = self.parent.rawRemap(memory, alignment, new_len, ret) orelse return null;
        self.add(@as(isize, @intCast(new_len)) - @as(isize, @intCast(memory.len)));
        return result;
    }
    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self = from(context);
        self.parent.rawFree(memory, alignment, ret);
        self.add(-@as(isize, @intCast(memory.len)));
    }
};
