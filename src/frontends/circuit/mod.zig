//! `stwo_circuit_frontend`: the call-order-exact Zig port of StarkWare's
//! circuit recursion stage (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). See README.md for the map and
//! `design/starknet-proving-pipeline/recursion/02-design.md` §2.2.
//!
//! This package must not depend on `stwo_cairo_frontend`; Cairo facts come
//! from the committed compiled-AIR projection.

const std = @import("std");

/// `crates/circuit_common`: finalization sizing, preprocessing, circuit hash
/// and the shared component list.
pub const common = @import("common/mod.zig");
/// `crates/stark_verifier`: the in-circuit STARK verifier.
pub const stark_verifier = @import("stark_verifier/mod.zig");
/// `crates/circuit_verifier` and `crates/circuit_multiverifier` statements.
pub const statements = @import("statements/mod.zig");
/// The in-circuit constraint evaluators, interpreted from the compiled-AIR
/// projection (design §5.4).
pub const air_eval = @import("air_eval/mod.zig");

test "api signature: circuit facade exposes the ported crates" {
    try std.testing.expect(@hasDecl(common, "preprocessed"));
    try std.testing.expect(@hasDecl(common, "circuit_hash"));
    try std.testing.expect(@hasDecl(stark_verifier, "proof"));
    try std.testing.expect(@hasDecl(statements, "multiverifier"));
    const layout_fn: fn (common.finalize.ComponentSizes) common.preprocessed.Error!common.preprocessed.ColumnLayout =
        common.preprocessed.ColumnLayout.fromComponentSizes;
    _ = layout_fn;
}

test "api signature: evaluator tables are built from a parsed projection" {
    const parse: fn (std.mem.Allocator, []const u8) air_eval.projection.Error!air_eval.projection.Projection =
        air_eval.projection.parse;
    const build_cairo: fn (std.mem.Allocator, *const air_eval.projection.Projection) air_eval.component_table.BuildError!air_eval.component_table.Table =
        air_eval.cairo_components.build;
    const build_circuit: fn (std.mem.Allocator, *const air_eval.projection.Projection) air_eval.component_table.BuildError!air_eval.component_table.Table =
        air_eval.circuit_components.build;
    _ = .{ parse, build_cairo, build_circuit };
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

test "invariant: projection reader rejects bad magic, other versions and truncation" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.BadMagic, air_eval.projection.parse(gpa, "NOTMAGIC\x02\x00\x00\x00"));
    try std.testing.expectError(error.UnsupportedVersion, air_eval.projection.parse(gpa, "STWOCAIR\x01\x00\x00\x00"));
    try std.testing.expectError(error.UnsupportedVersion, air_eval.projection.parse(gpa, "STWOCAIR\x03\x00\x00\x00"));
    try std.testing.expectError(error.Truncated, air_eval.projection.parse(gpa, "STWOCAIR\x02\x00"));
    // One string whose declared length runs past the end.
    try std.testing.expectError(error.Truncated, air_eval.projection.parse(gpa, "STWOCAIR\x02\x00\x00\x00\x01\x00\x00\x00\x09\x00\x00\x00ab"));
    // A header naming a string index that does not exist.
    try std.testing.expectError(error.StringIndexOutOfRange, air_eval.projection.parse(gpa, "STWOCAIR\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
