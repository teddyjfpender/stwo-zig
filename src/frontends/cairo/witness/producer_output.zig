//! Owned subcomponent and lookup feeds retained from one Cairo witness writer.

const std = @import("std");

pub const ProducerOutput = struct {
    label: []const u8,
    row_count: u32,
    active_rows: u32,
    words_per_row: u32,
    words: []u32,
    lookup_words_per_row: u32,
    lookup_words: []u32,

    pub fn deinit(self: ProducerOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.lookup_words);
        allocator.free(self.words);
    }
};
