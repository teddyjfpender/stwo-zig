//! Canonical stwo.blake3.experimental.v1, fully resident explicit-stream ABI.
//! Hash and progressive state types are deliberately distinct from Blake2s.
const std = @import("std");
pub const Hash = extern struct { words: [8]u32 };
pub const State = extern struct {
    cv: [8]u32,
    block: [16]u32,
    stack: [25][8]u32,
    filled: u32,
    block_index: u32,
    chunk_counter: u32,
    stack_len: u32,
};
pub const Channel = extern struct { digest: [8]u32, counter: [2]u32, error_code: u32 };
pub const MixedSegment = extern struct { columns: [*]const u32, stride_words: usize, capacity_words: usize, source_size: u32, reserved: u32 = 0 };
pub const max_mixed_segments = 96;
pub const Operation = enum(u32) { init = 0, words = 1, felts = 2, integer = 3, root = 4, secure = 5, raw = 9 };
pub extern "c" fn stwo_blake3_contiguous_leaf_on(size: u32, columns: [*]const u32, stride: usize, capacity: usize, output: [*]Hash, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_mixed_leaf_on(size: u32, count: u32, segments: [*]const MixedSegment, output: [*]Hash, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_mixed_seeded_on(size: u32, count: u32, segments: [*]const MixedSegment, absorbed_before: u32, seed_size: u32, seed: ?[*]const State, prefix: ?[*]State, output: ?[*]Hash, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_progressive_init_on(size: u32, state: [*]State, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_progressive_absorb_lifted_on(size: u32, source_size: u32, absorbed_before: u32, columns: [*]const u32, stride: usize, capacity: usize, state: [*]State, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_progressive_finalize_on(size: u32, absorbed: u32, state: [*]const State, output: [*]Hash, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_layer_on(input: [*]const Hash, count: u32, output: [*]Hash, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_fri_leaf_on(size: u32, coordinates: [*]const u32, stride: usize, capacity: usize, fold_log: u32, output: [*]Hash, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_framed_words_on(count: u32, words: [*]const u32, stride: usize, capacity: usize, length: u32, domain: u32, output: [*]Hash, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_channel_on(state: *Channel, data: ?[*]u32, capacity: usize, count: u32, operation: u32, max_draw_blocks: u32, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_pow_range_on(state: *const Channel, bits: u32, first: u64, count: u32, minimum: *u64, stream: *anyopaque) c_int;
test "BLAKE3 resident ABI has distinct exact state layouts" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(Hash));
    try std.testing.expectEqual(@as(usize, 912), @sizeOf(State));
    try std.testing.expectEqual(@as(usize, 44), @sizeOf(Channel));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(MixedSegment));
}
pub extern "c" fn stwo_blake3_query_on(state: *Channel, log_domain: u32, count: u32, queries: [*]u32, capacity: usize, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_grind_on(state: *Channel, bits: u32, end_exclusive: u64, blocks: u32, nonce: *u64, stream: *anyopaque) c_int;
pub extern "c" fn stwo_blake3_channel_verdict_on(states: [*]const Channel, count: u32, terminal_verdict: *u32, stream: *anyopaque) c_int;
