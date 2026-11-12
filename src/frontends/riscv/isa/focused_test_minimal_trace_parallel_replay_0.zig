//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("runner/cpu.zig");
    _ = @import("runner/decode.zig");
    _ = @import("runner/memory.zig");
    _ = @import("runner/memory_state.zig");
    _ = @import("runner/state_chain.zig");
}
