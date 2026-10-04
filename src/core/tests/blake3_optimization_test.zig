//! Focused qualification for native short-message hashing and framed transcripts.
comptime {
    _ = @import("../vcs/blake3_hash.zig");
    _ = @import("../channel/blake3.zig");
    _ = @import("../vcs_lifted/blake3_merkle.zig");
}
