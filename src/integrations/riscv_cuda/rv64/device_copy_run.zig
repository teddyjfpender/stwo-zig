//! Merge only adjacent physical columns from the SAME scoped allocation.
//! The consumer must validate the resulting full run against the native proof
//! namespace before copying. Shape metadata never grants device authority.
const std = @import("std");
pub const Run = struct {
    source: usize,
    target_word: usize,
    words: usize,
    context_token: u64,
    generation: u64,
    pub fn init(source: usize, target_word: usize, words: usize, context_token: u64, generation: u64) !Run {
        if (source == 0 or source % 4 != 0 or words == 0 or context_token == 0 or generation == 0) return error.InvalidCopyRun;
        _ = try std.math.add(usize, source, try std.math.mul(usize, words, 4));
        _ = try std.math.add(usize, target_word, words);
        return .{ .source = source, .target_word = target_word, .words = words, .context_token = context_token, .generation = generation };
    }
    /// Failure does not mutate either run. A new lease/namespace is always a
    /// boundary, even if the allocator reused the same numerical address.
    pub fn append(self: *Run, next: Run) !bool {
        if (self.context_token != next.context_token or self.generation != next.generation) return false;
        if (try std.math.add(usize, self.source, try std.math.mul(usize, self.words, 4)) != next.source or try std.math.add(usize, self.target_word, self.words) != next.target_word) return false;
        const words = try std.math.add(usize, self.words, next.words);
        _ = try std.math.add(usize, self.source, try std.math.mul(usize, words, 4));
        _ = try std.math.add(usize, self.target_word, words);
        self.words = words;
        return true;
    }
};
test "resident copy runs merge adjacent mixed-log columns without copying metadata" {
    var run = try Run.init(4096, 0, 32, 7, 11);
    try std.testing.expect(try run.append(try Run.init(4096 + 128, 32, 64, 7, 11)));
    try std.testing.expect(try run.append(try Run.init(4096 + 384, 96, 16, 7, 11)));
    try std.testing.expectEqual(@as(usize, 112), run.words);
    try std.testing.expectEqual(@as(usize, 4096), run.source);
}
test "resident copy runs do not cross generation context or source target gaps" {
    const original = try Run.init(4096, 0, 32, 7, 11);
    const next = try Run.init(4096 + 128, 32, 32, 7, 11);
    for (0..4) |mutation| {
        var run = original;
        var bad = next;
        switch (mutation) {
            0 => bad.generation += 1,
            1 => bad.context_token += 1,
            2 => bad.source += 4,
            3 => bad.target_word += 1,
            else => unreachable,
        }
        try std.testing.expect(!try run.append(bad));
        try std.testing.expectEqualDeep(original, run);
    }
}
test "resident copy run arithmetic and ownership fail closed" {
    try std.testing.expectError(error.InvalidCopyRun, Run.init(4096, 0, 0, 7, 11));
    try std.testing.expectError(error.InvalidCopyRun, Run.init(4096, 0, 32, 0, 11));
    try std.testing.expectError(error.InvalidCopyRun, Run.init(4096, 0, 32, 7, 0));
    try std.testing.expectError(error.InvalidCopyRun, Run.init(4097, 0, 32, 7, 11));
    try std.testing.expectError(error.Overflow, Run.init(std.math.maxInt(usize) - 3, 0, 32, 7, 11));
    try std.testing.expectError(error.Overflow, Run.init(4096, std.math.maxInt(usize), 32, 7, 11));
}
