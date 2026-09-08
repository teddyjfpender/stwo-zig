//! Shared canonical V1 field preimage for VM graph bindings.
//! The new statement-root profile needs its own field admission; it must not
//! silently extend either frozen V1 publisher's protocol.
const graph = @import("air/composition_circuit.zig");

pub fn encode(encoder: anytype, binding: graph.VmInputBinding) !void {
    var tag: u32 = undefined;
    var first: u32 = 0;
    var second: u32 = 0;
    switch (binding.source) {
        .statement_word, .native_continuation_root => return error.StatementRootsRequireNewFieldEncoding,
        .segment_selector => tag = 1,
        .sampled_value => |coordinate| {
            tag = 2;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
        .claimed_sum => |coordinate| {
            tag = 3;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
        .relation_challenge => |coordinate| {
            tag = 4;
            first = coordinate.challenge;
            second = coordinate.word_index;
        },
        .composition_randomness => |word_index| {
            tag = 5;
            first = word_index;
        },
        .oods_point => |word_index| {
            tag = 6;
            first = word_index;
        },
        .transcript_claimed_sum => |coordinate| {
            tag = 7;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
    }
    try encoder.word(binding.node_id);
    try encoder.word(tag);
    try encoder.word(first);
    try encoder.word(second);
}
