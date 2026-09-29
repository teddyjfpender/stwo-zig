//! Port of `crates/stark_verifier`, one Zig file per Rust file (design §5.1).
//! Only the evaluator-facing files exist so far (written by stream M4).

pub const constraint_eval = @import("constraint_eval.zig");
pub const logup = @import("logup.zig");
pub const test_utils = @import("test_utils.zig");
