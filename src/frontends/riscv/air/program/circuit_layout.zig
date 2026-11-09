//! Closed algorithm layouts; profile admission and wire identity are owned above.
const std = @import("std");
const program = @import("interaction.zig");

pub const PoseidonLayoutV1 = enum(u8) { legacy_v1 = 0, narrow_degree3_v1 = 1 };

pub const CircuitLayout = enum(u1) {
    ordinary_sparse = 0,
    fixed_decoded_narrow = 1,

    pub fn programPolicy(self: @This()) program.Policy {
        return switch (self) {
            .ordinary_sparse => .sparse_merkle_v1,
            .fixed_decoded_narrow => .fixed_decoded_table_v1,
        };
    }
    pub fn poseidonLayout(self: @This()) PoseidonLayoutV1 {
        return switch (self) {
            .ordinary_sparse => .legacy_v1,
            .fixed_decoded_narrow => .narrow_degree3_v1,
        };
    }
};

test "circuit layout: the closed pair set preserves program and Poseidon geometry" {
    try std.testing.expectEqual(@as(usize, 2), @typeInfo(CircuitLayout).@"enum".fields.len);
    try std.testing.expectEqual(program.Policy.sparse_merkle_v1, CircuitLayout.ordinary_sparse.programPolicy());
    try std.testing.expectEqual(PoseidonLayoutV1.legacy_v1, CircuitLayout.ordinary_sparse.poseidonLayout());
    try std.testing.expectEqual(program.Policy.fixed_decoded_table_v1, CircuitLayout.fixed_decoded_narrow.programPolicy());
    try std.testing.expectEqual(PoseidonLayoutV1.narrow_degree3_v1, CircuitLayout.fixed_decoded_narrow.poseidonLayout());
}
