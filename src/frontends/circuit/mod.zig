//! `stwo_circuit_frontend`: the call-order-exact Zig port of StarkWare's
//! circuit recursion stage (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). See README.md for the map.

const std = @import("std");

/// `crates/circuit_common`: finalization sizing, preprocessing, circuit hash
/// and the shared component list.
pub const common = @import("common/mod.zig");
/// `crates/stark_verifier`: the in-circuit STARK verifier.
pub const stark_verifier = @import("stark_verifier/mod.zig");
/// `crates/circuit_verifier` and `crates/circuit_multiverifier` statements.
pub const statements = @import("statements/mod.zig");

test "api signature: circuit facade exposes the ported crates" {
    try std.testing.expect(@hasDecl(common, "preprocessed"));
    try std.testing.expect(@hasDecl(common, "circuit_hash"));
    try std.testing.expect(@hasDecl(stark_verifier, "proof"));
    try std.testing.expect(@hasDecl(statements, "multiverifier"));
    const layout_fn: fn (common.finalize.ComponentSizes) common.preprocessed.Error!common.preprocessed.ColumnLayout =
        common.preprocessed.ColumnLayout.fromComponentSizes;
    _ = layout_fn;
}

test "invariant: every preprocessed layout has the 45 circuit columns" {
    const layout = try common.preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = 16,
        .qm31_ops = 16,
        .m31_to_u32 = 16,
        .triple_xor = 16,
        .blake_g_gate = 16,
    });
    try std.testing.expectEqual(@as(usize, 45), layout.entries.len);
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
