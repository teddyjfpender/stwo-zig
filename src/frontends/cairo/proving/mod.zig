//! Backend-neutral Cairo proof-input construction.

pub const base_trace = @import("base_trace.zig");
pub const interaction_trace = @import("interaction_trace.zig");
pub const transcript = @import("transcript.zig");

test {
    _ = base_trace;
    _ = interaction_trace;
    _ = transcript;
}
