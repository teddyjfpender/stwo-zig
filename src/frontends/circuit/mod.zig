//! `stwo_circuit_frontend`: Zig port of StarkWare's circuit recursion stage
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). See
//! `design/starknet-proving-pipeline/recursion/02-design.md` §2.2.
//!
//! This package must not depend on `stwo_cairo_frontend`; Cairo facts come
//! from the committed compiled-AIR projection.

const std = @import("std");

pub const air_eval = @import("air_eval/mod.zig");
pub const stark_verifier = @import("stark_verifier/mod.zig");
pub const common = @import("common/mod.zig");

test {
    _ = air_eval;
    _ = stark_verifier;
    _ = common;
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

test "projection reader rejects bad magic and truncation" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.BadMagic, air_eval.projection.parse(gpa, "NOTMAGIC\x01\x00\x00\x00"));
    try std.testing.expectError(error.UnsupportedVersion, air_eval.projection.parse(gpa, "STWOCAIR\x02\x00\x00\x00"));
    try std.testing.expectError(error.Truncated, air_eval.projection.parse(gpa, "STWOCAIR\x01\x00"));
    // One string whose declared length runs past the end.
    try std.testing.expectError(error.Truncated, air_eval.projection.parse(gpa, "STWOCAIR\x01\x00\x00\x00\x01\x00\x00\x00\x09\x00\x00\x00ab"));
    // A header naming a string index that does not exist.
    try std.testing.expectError(error.StringIndexOutOfRange, air_eval.projection.parse(gpa, "STWOCAIR\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
}
