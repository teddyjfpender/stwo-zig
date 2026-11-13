//! Append-only diagnostics for the typed arena-plan origin; never arbitrary error names.
const std = @import("std");
const Entry = @import("stwo_core").error_codes.Entry;
pub const ArenaPlanError = @import("arena_plan.zig").Error || std.mem.Allocator.Error;

pub const table = [_]Entry{
    .{ .tag = "EmptySchedule", .code = 0x2001, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "DuplicateLogicalId", .code = 0x2002, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "UnsortedBindings", .code = 0x2003, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidAlignment", .code = 0x2004, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidTick", .code = 0x2005, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidUseOrder", .code = 0x2006, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "SizeOverflow", .code = 0x2007, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "BudgetExceeded", .code = 0x2008, .class = .resource_exhausted, .since = "1.0.0-rc.2" },
    .{ .tag = "AliasOverlap", .code = 0x2009, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "UnknownBinding", .code = 0x200a, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "BindingOutOfBounds", .code = 0x200b, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "NarrowAddressOverflow", .code = 0x200c, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "OutOfMemory", .code = 0x200d, .class = .resource_exhausted, .since = "1.0.0-rc.2" },
};

pub fn fromArena(err: ArenaPlanError) Entry {
    return switch (err) {
        error.EmptySchedule => table[0],
        error.DuplicateLogicalId => table[1],
        error.UnsortedBindings => table[2],
        error.InvalidAlignment => table[3],
        error.InvalidTick => table[4],
        error.InvalidUseOrder => table[5],
        error.SizeOverflow => table[6],
        error.BudgetExceeded => table[7],
        error.AliasOverlap => table[8],
        error.UnknownBinding => table[9],
        error.BindingOutOfBounds => table[10],
        error.NarrowAddressOverflow => table[11],
        error.OutOfMemory => table[12],
    };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}
