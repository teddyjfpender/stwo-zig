//! Backend-neutral Cairo proof-input construction.

pub const base_trace = @import("base_trace.zig");
pub const interaction_trace = @import("interaction_trace.zig");
pub const air = @import("air/mod.zig");
pub const transaction = @import("transaction.zig");
pub const transcript = @import("transcript.zig");

test {
    _ = air;
    _ = base_trace;
    _ = interaction_trace;
    _ = transaction;
    _ = transcript;
}
