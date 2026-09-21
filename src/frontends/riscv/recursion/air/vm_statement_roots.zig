//! Canonical statement coordinates used by the incremental-memory bridge.
//! These are input coordinates, not root values or circuit constants.
const layout = @import("../span_statement.zig").canonical_layout;

/// Native sparse-tree continuation roots are distinct from the span's full
/// snapshot digests. Their canonical joins publish this separate namespace.
pub const NATIVE_CONTINUATION_SCOPE: u32 = 6;

pub const word_indices = [2]u32{
    layout.entry_state_start + layout.machine_state_rw_digest_start_offset,
    layout.exit_state_start + layout.machine_state_rw_digest_start_offset,
};

pub fn contains(word_index: u32) bool {
    return word_index == word_indices[0] or word_index == word_indices[1];
}

/// Appended only for the opt-in profile; all default preimages stay frozen.
pub fn hashProfileExtension(hash: anytype, count: u32) void {
    if (count == 0) return;
    for ([_]u32{ 0x564d_5352, count }) |word| {
        var bytes: [4]u8 = undefined;
        @import("std").mem.writeInt(u32, &bytes, word, .little);
        hash.update(&bytes);
    }
}

/// The native-root mode is disjoint from legacy snapshot-word inputs.
pub fn hashNativeProfileExtension(hash: anytype, enabled: bool) void {
    if (!enabled) return;
    for ([_]u32{ 0x4e43_5254, NATIVE_CONTINUATION_SCOPE }) |word| {
        var bytes: [4]u8 = undefined;
        @import("std").mem.writeInt(u32, &bytes, word, .little);
        hash.update(&bytes);
    }
}
