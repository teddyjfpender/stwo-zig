//! Authenticated module-global capabilities carried by the Native AOT pack.

pub const Requirement = enum(u32) {
    none = 0,
    pedersen_w18_columns_rows_v1 = 1,

    pub fn wire(self: Requirement) []const u8 {
        return switch (self) {
            .none => "none",
            .pedersen_w18_columns_rows_v1 => "pedersen_w18_columns_rows_v1",
        };
    }
};

pub const pedersen_w18_column_count: u32 = 56;
pub const pedersen_w18_row_count: u32 = 1 << 23;

pub fn parse(encoded: []const u8) ?Requirement {
    inline for (std.meta.fields(Requirement)) |field| {
        const requirement: Requirement = @enumFromInt(field.value);
        if (std.mem.eql(u8, encoded, requirement.wire()))
            return requirement;
    }
    return null;
}

const std = @import("std");

test "module-global requirements have one canonical wire spelling" {
    inline for (std.meta.fields(Requirement)) |field| {
        const requirement: Requirement = @enumFromInt(field.value);
        try std.testing.expectEqual(
            requirement,
            parse(requirement.wire()).?,
        );
    }
    try std.testing.expect(parse("pedersen") == null);
}
