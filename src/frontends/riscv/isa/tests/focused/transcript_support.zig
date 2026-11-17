//! Explicit original transcript support cases at their canonical owner.
test {
    _ = @import("access_clock.zig");
    _ = @import("bulk_memcpy_candidate.zig");
    _ = @import("custom0.zig");
    _ = @import("decode.zig");
    _ = @import("execution_profile.zig");
    _ = @import("opcode_manifest.zig");
    _ = @import("profile.zig");
    _ = @import("runner/cpu.zig");
    _ = @import("runner/memory.zig");
    _ = @import("runner/memory_state.zig");
    _ = @import("runner/state_chain.zig");
    _ = @import("sha256_compression.zig");
}
