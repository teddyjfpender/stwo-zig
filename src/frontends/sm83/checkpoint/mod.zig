//! External machine-checkpoint ingestion.
//!
//! Checkpoint formats are adapters at the frontend boundary. They do not
//! select a proof backend and do not contain game-specific state layouts.

pub const sameboy = @import("sameboy.zig");

test {
    _ = sameboy;
    _ = @import("sameboy_test.zig");
}
