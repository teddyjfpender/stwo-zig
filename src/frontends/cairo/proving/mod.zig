//! Backend-neutral Cairo proof-input construction.

pub const base_trace = @import("base_trace.zig");
pub const feed_geometry_oracle = @import("feed_geometry_oracle.zig");
pub const interaction_trace = @import("interaction_trace.zig");
pub const air = @import("air/mod.zig");
pub const trace_arena = @import("trace_arena.zig");
pub const transaction = @import("transaction.zig");
pub const transcript = @import("transcript.zig");

test {
    _ = air;
    _ = base_trace;
    _ = feed_geometry_oracle;
    _ = interaction_trace;
    _ = trace_arena;
    _ = transaction;
    _ = transcript;
}
