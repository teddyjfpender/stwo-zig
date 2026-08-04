//! Typed AIR authoring kernel.
//!
//! This module is intentionally isolated while the logical IR earns its
//! production boundary. Test inventory imports it directly; no shipped AIR,
//! witness, runner, prover, or formal-export path depends on it yet.

const std = @import("std");

/// Logical schema version for the pre-production authoring kernel.
///
/// This is not an artifact or proof-protocol version. It lets focused tests
/// reject accidental reuse of a future incompatible logical representation.
pub const LOGICAL_SCHEMA_VERSION: u16 = 0;

test "typed AIR language: isolated kernel has an explicit logical version" {
    try std.testing.expectEqual(@as(u16, 0), LOGICAL_SCHEMA_VERSION);
}
