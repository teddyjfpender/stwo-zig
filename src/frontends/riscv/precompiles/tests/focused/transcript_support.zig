//! Explicit original transcript support cases at their canonical owner.
test {
    _ = @import("air/sha256_compression.zig");
    _ = @import("recovery_abi.zig");
    _ = @import("runner/call_buffer.zig");
    _ = @import("runner/secp256k1_recover_call_buffer.zig");
}
