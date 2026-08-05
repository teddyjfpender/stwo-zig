//! Canonical identity of the Sail-authoritative opcode witness layout.

const std = @import("std");
const trace = @import("runner/trace.zig");
const layouts = @import("air/trace_columns.zig");

pub const Family = trace.OpcodeFamily;

pub const canonical_families = [_]Family{
    .auipc,
    .base_alu_imm,
    .base_alu_reg,
    .branch_eq,
    .branch_lt,
    .div,
    .jal,
    .jalr,
    .load_store,
    .lt_imm,
    .lt_reg,
    .lui,
    .mul,
    .mulh,
    .shifts_imm,
    .shifts_reg,
    .fence,
};

pub fn LayoutFor(comptime family: Family) type {
    return switch (family) {
        .base_alu_reg => layouts.BaseAluRegColumns,
        .base_alu_imm => layouts.BaseAluImmColumns,
        .shifts_reg => layouts.ShiftsRegColumns,
        .shifts_imm => layouts.ShiftsImmColumns,
        .lt_reg => layouts.LtRegColumns,
        .lt_imm => layouts.LtImmColumns,
        .branch_eq => layouts.BranchEqColumns,
        .branch_lt => layouts.BranchLtColumns,
        .lui => layouts.LuiColumns,
        .auipc => layouts.AuipcColumns,
        .jalr => layouts.JalrColumns,
        .jal => layouts.JalColumns,
        .load_store => layouts.LoadStoreColumns,
        .mul => layouts.MulColumns,
        .mulh => layouts.MulhColumns,
        .div => layouts.DivColumns,
        .fence => layouts.FenceColumns,
    };
}

/// Exact physical column names in committed order. The returned slices point
/// at compile-time storage owned by this module.
pub fn columnNames(family: Family) []const []const u8 {
    return switch (family) {
        inline else => |comptime_family| &Names(
            LayoutFor(comptime_family),
        ).values,
    };
}

/// Hash the exact byte contract consumed by the live CP-11 witness boundary.
pub fn digest() [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (canonical_families) |family| updateFamily(&hasher, family);
    return hasher.finalResult();
}

fn updateFamily(hasher: *std.crypto.hash.sha2.Sha256, comptime family: Family) void {
    const Layout = LayoutFor(family);
    const names = Names(Layout).values;
    var prefix: [96]u8 = undefined;
    const rendered = std.fmt.bufPrint(
        &prefix,
        "family={s} columns={d}\nnames=",
        .{ @tagName(family), names.len },
    ) catch unreachable;
    hasher.update(rendered);
    for (names, 0..) |name, index| {
        if (index != 0) hasher.update(",");
        hasher.update(name);
    }
    hasher.update("\n");
}

fn Names(comptime Layout: type) type {
    const fields = @typeInfo(Layout).@"struct".fields;
    return struct {
        const values: [fields.len][]const u8 = blk: {
            var names: [fields.len][]const u8 = undefined;
            for (fields, &names) |field, *name| name.* = field.name;
            break :blk names;
        };
    };
}

test "witness layout digest matches the Sail-authoritative schema receipt" {
    const expected = "2163899f40e1bffb7f5d355b600ee4e013e7e4f63c205cedd01f6feb9d88f4f5";
    const actual = std.fmt.bytesToHex(digest(), .lower);
    try std.testing.expectEqualStrings(expected, &actual);
}

test "witness layout exposes every reflected physical name in order" {
    inline for (@typeInfo(Family).@"enum".fields) |family_field| {
        const family: Family = @enumFromInt(family_field.value);
        const fields = @typeInfo(LayoutFor(family)).@"struct".fields;
        const names = columnNames(family);
        try std.testing.expectEqual(fields.len, names.len);
        inline for (fields, 0..) |field, index| {
            try std.testing.expectEqualStrings(field.name, names[index]);
        }
    }
}
