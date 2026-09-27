//! Movable graph ownership with a stable allocator control address. The child
//! allocator remains borrowed and must outlive every graph allocation.
const std = @import("std");
pub const Owned = struct {
    child_allocator: std.mem.Allocator,
    control: *std.heap.ArenaAllocator,
    pub fn init(child: std.mem.Allocator) !Owned {
        const control = try child.create(std.heap.ArenaAllocator);
        control.* = std.heap.ArenaAllocator.init(child);
        return .{ .child_allocator = child, .control = control };
    }
    pub fn allocator(self: *const Owned) std.mem.Allocator {
        return self.control.allocator();
    }
    pub fn deinit(self: *Owned) void {
        self.control.deinit();
        self.child_allocator.destroy(self.control);
        self.* = undefined;
    }
};
