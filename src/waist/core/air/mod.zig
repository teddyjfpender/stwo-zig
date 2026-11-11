pub const accumulation = @import("accumulation.zig");
pub const components = @import("components.zig");
pub const derive = @import("derive.zig");
pub const trace = @import("trace/mod.zig");
pub const lookup_data = @import("lookup_data/mod.zig");
pub const utils = @import("utils.zig");
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
