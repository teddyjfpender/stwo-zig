//! Typed AIR authoring kernel.
//!
//! This module is intentionally isolated while the logical IR earns its
//! production boundary. Test inventory imports it directly; no shipped AIR,
//! witness, runner, prover, or formal-export path depends on it yet.

const std = @import("std");

pub const types = @import("types.zig");
pub const source = @import("source.zig");
pub const expr = @import("expr.zig");
pub const program = @import("program.zig");
pub const ir = @import("ir.zig");
pub const validate = @import("validate.zig");
pub const manifest = @import("manifest.zig");
pub const relation = @import("relation.zig");
pub const functions = @import("functions.zig");
pub const hint_recipe = @import("hint_recipe.zig");
pub const hints = @import("hints.zig");

/// Logical schema version for the pre-production authoring kernel.
///
/// This is not an artifact or proof-protocol version. It lets focused tests
/// reject accidental reuse of a future incompatible logical representation.
pub const LOGICAL_SCHEMA_VERSION = manifest.logical_schema_version;

test "typed AIR language: isolated kernel has an explicit logical version" {
    try std.testing.expectEqual(@as(u16, 2), LOGICAL_SCHEMA_VERSION);
}
