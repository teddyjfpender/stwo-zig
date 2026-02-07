pub const accumulation = @import("accumulation.zig");
pub const components = @import("components.zig");
pub const Component = components.Component;
pub const Components = components.Components;

pub const AirVTable = struct {
    components: *const fn (ctx: *const anyopaque, allocator: @import("std").mem.Allocator) anyerror![]Component,
};

pub const Air = struct {
    ctx: *const anyopaque,
    vtable: *const AirVTable,

    pub inline fn components(self: Air, allocator: @import("std").mem.Allocator) anyerror![]Component {
        return self.vtable.components(self.ctx, allocator);
    }
};
