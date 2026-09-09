//! Selected Ethereum transcript admission and fixed-zero routing. Artifact
//! replay tests remain opt-in through exact filters and independently pinned keys.
comptime {
    _ = @import("ethereum_wrapper_detached_transcript_v1.zig");
    _ = @import("recursive_secure_transcript_program_v1.zig");
    _ = @import("recursive_secure_transcript_rows_v1.zig");
}
