//! Typed filters for local SM83 corpus feedback.

const std = @import("std");
const isa = @import("isa/mod.zig");

pub const Filter = union(enum) {
    all,
    opcode: u16,
    family: isa.Family,

    pub fn includes(self: Filter, instruction: isa.Instruction, raw_opcode: u16) bool {
        return switch (self) {
            .all => true,
            .opcode => |wanted| wanted == raw_opcode,
            .family => |wanted| wanted == instruction.family(),
        };
    }
};

pub fn parseOpcode(value: []const u8) error{InvalidOpcode}!Filter {
    if (value.len == 2) {
        return .{ .opcode = std.fmt.parseInt(u8, value, 16) catch
            return error.InvalidOpcode };
    }
    if (value.len == 5 and
        std.ascii.eqlIgnoreCase(value[0..3], "cb:"))
    {
        const suffix = std.fmt.parseInt(u8, value[3..5], 16) catch
            return error.InvalidOpcode;
        return .{ .opcode = 0xcb00 | @as(u16, suffix) };
    }
    return error.InvalidOpcode;
}

pub fn parseFamily(value: []const u8) error{InvalidFamily}!Filter {
    const family = std.meta.stringToEnum(isa.Family, value) orelse
        return error.InvalidFamily;
    if (family == .illegal) return error.InvalidFamily;
    return .{ .family = family };
}

test "corpus scope parses base, CB, and family filters" {
    try std.testing.expectEqual(
        @as(u16, 0x80),
        (try parseOpcode("80")).opcode,
    );
    try std.testing.expectEqual(
        @as(u16, 0xcb11),
        (try parseOpcode("CB:11")).opcode,
    );
    try std.testing.expectEqual(
        isa.Family.alu8,
        (try parseFamily("alu8")).family,
    );
    try std.testing.expectError(error.InvalidOpcode, parseOpcode("0x80"));
    try std.testing.expectError(error.InvalidFamily, parseFamily("unknown"));
    try std.testing.expectError(error.InvalidFamily, parseFamily("illegal"));
}

test "corpus scope matches only the requested work" {
    const instruction = isa.base_table[0x80];
    try std.testing.expect((try parseOpcode("80")).includes(instruction, 0x80));
    try std.testing.expect(!(try parseOpcode("81")).includes(instruction, 0x80));
    try std.testing.expect((try parseFamily("alu8")).includes(instruction, 0x80));
    try std.testing.expect(!(try parseFamily("load8")).includes(instruction, 0x80));
}
