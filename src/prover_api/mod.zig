//! Stable frontend/backend contracts for the prover engine.
//!
//! This package owns transaction types and observability schemas that callers
//! may depend on without importing commitment, quotient, FRI, or orchestration
//! implementations.

const std = @import("std");

pub const column = @import("column.zig");
pub const engine = @import("engine.zig");
pub const stage_profile = @import("stage_profile.zig");

pub const ColumnEvaluation = column.ColumnEvaluation;
pub const ColumnSource = column.ColumnSource;
pub const QuotientOpsError = column.QuotientOpsError;
pub const ProveOptions = engine.ProveOptions;
pub const assertProverEngine = engine.assertProverEngine;

test {
    std.testing.refAllDecls(@This());
}
