const std = @import("std");
const A = @import("../../mod.zig");
const R = @import("../registry.zig");
test "delegation arithmetic routing preserves exact raw ISA opcode namespace" {
    for (0..256) |raw| {
        const expected: ?R.Family = switch (raw) {
            49...52, 57 => .multiplication,
            53...56, 58...61 => .division,
            else => null,
        };
        try std.testing.expectEqual(expected, R.arithmeticFamily(@intCast(raw)));
    }
}
test "delegation move preserves legacy component type identity and implemented geometry" {
    for (std.enums.values(R.Family)) |family| {
        const shape = R.widths(family);
        try std.testing.expect(shape.fixed != 0 and shape.main != 0 and shape.interaction != 0);
    }
    comptime {
        if (A.crypto.keccak.component.Component != A.delegations.keccak.component.Component) @compileError("Keccak alias changed");
        if (A.crypto.secp256k1.component.Component != A.delegations.secp256k1.component.Component) @compileError("secp alias changed");
        if (A.arithmetic.division.component.Component != A.delegations.division.component.Component) @compileError("DIV alias changed");
        if (A.arithmetic.multiplication.component.Component != A.delegations.multiplication.component.Component) @compileError("MUL alias changed");
    }
}
