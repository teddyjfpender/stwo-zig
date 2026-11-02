//! Opt-in host allocation diagnostics. Failed allocations report their exact
//! request and call site; successful allocations and all ownership semantics
//! pass through unchanged. This wrapper has no allocation-backed bookkeeping.
const std = @import("std");
pub const Diagnostic = struct {
    child: std.mem.Allocator,
    pub fn allocator(self: *Diagnostic) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, caller: usize) ?[*]u8 {
        const self: *Diagnostic = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, caller) orelse {
            std.debug.print("RV64_ALLOCATION_FAILURE bytes={d} alignment={d} caller=0x{x}\n", .{ len, alignment.toByteUnits(), caller });
            std.debug.dumpCurrentStackTrace(caller);
            return null;
        };
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, caller: usize) bool {
        const self: *Diagnostic = @ptrCast(@alignCast(ctx));
        return self.child.rawResize(memory, alignment, len, caller);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, caller: usize) ?[*]u8 {
        const self: *Diagnostic = @ptrCast(@alignCast(ctx));
        return self.child.rawRemap(memory, alignment, len, caller);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, caller: usize) void {
        const self: *Diagnostic = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, caller);
    }
};
