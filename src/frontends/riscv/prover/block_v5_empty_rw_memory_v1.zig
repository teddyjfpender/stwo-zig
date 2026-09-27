//! Explicit zero-RW protocol. There is no synthetic memory trace or STARK.
//! Fresh execution slot census and native/caller register closure remain
//! mandatory in the enclosing private kernel.
const std = @import("std");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
pub fn planDigest() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-zig/block-v5/empty-rw-memory/v1\x00");
    h.update(&protocol.abiId());
    // Version, native-window mode, event/instance/range-shard census.
    h.update(&.{ 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    return h.finalResult();
}
