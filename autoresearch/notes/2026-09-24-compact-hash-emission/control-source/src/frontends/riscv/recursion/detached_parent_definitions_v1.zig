//! Shared definition lifecycle for producer and verifier parent collections.
//! The containing owner must keep this storage stable while components borrow it.
const std = @import("std");
const catalog = @import("air/detached_parent_catalog_v1.zig");
const range = @import("air/range_check_8_8_contract.zig");

fn DefinitionTuple() type {
    var types: [catalog.LOGICAL_ROWS.len]type = undefined;
    for (catalog.LOGICAL_ROWS, 0..) |entry, index| types[index] = entry.Air.Definition;
    return std.meta.Tuple(&types);
}

pub const Definitions = struct {
    allocator: std.mem.Allocator,
    logical: DefinitionTuple() = undefined,
    initialized: [catalog.LOGICAL_ROWS.len]bool = @splat(false),
    range_definition: range.Definition = undefined,
    range_initialized: bool = false,

    pub fn init(allocator: std.mem.Allocator) Definitions {
        return .{ .allocator = allocator };
    }

    pub fn initLogical(self: *Definitions, comptime index: usize) !void {
        std.debug.assert(!self.initialized[index]);
        const entry = catalog.LOGICAL_ROWS[index];
        self.logical[index] = if (entry.requires_location)
            try entry.Air.build(self.allocator, .generated)
        else
            try entry.Air.build(self.allocator);
        self.initialized[index] = true;
    }

    pub fn initRange(self: *Definitions) !void {
        std.debug.assert(!self.range_initialized);
        self.range_definition = try range.build(self.allocator);
        self.range_initialized = true;
    }

    pub fn deinit(self: *Definitions) void {
        inline for (0..catalog.LOGICAL_ROWS.len) |index| {
            if (self.initialized[index]) self.logical[index].deinit();
        }
        if (self.range_initialized) self.range_definition.deinit();
        self.* = undefined;
    }
};
