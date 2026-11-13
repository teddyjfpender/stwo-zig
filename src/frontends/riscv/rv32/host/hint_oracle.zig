//! Preimage hint oracle for guest↔host communication.
//!
//! Holds a queue of pre-computed hint byte arrays. The guest consumes
//! hints sequentially via HINT_LEN / HINT_READ syscalls. For Ethereum
//! block proving, hints typically contain MPT (Merkle Patricia Trie)
//! nodes provided by the host.

const std = @import("std");

/// A sequential queue of hint byte arrays.
///
/// The guest reads hints one at a time: first queries the length with
/// HINT_LEN, then reads bytes with HINT_READ. After fully consuming
/// a hint, the oracle advances to the next one.
pub const HintOracle = struct {
    /// Pre-populated hint data. Each entry is one complete hint response.
    hints: []const []const u8,
    /// Index of the current hint being read.
    current_idx: usize,
    /// Byte cursor within the current hint.
    cursor: usize,

    /// Create a hint oracle with the given pre-computed hints.
    pub fn init(hints: []const []const u8) HintOracle {
        return .{
            .hints = hints,
            .current_idx = 0,
            .cursor = 0,
        };
    }

    /// Returns the total length of the current hint, or 0 if exhausted.
    pub fn currentLen(self: *const HintOracle) usize {
        if (self.current_idx >= self.hints.len) return 0;
        return self.hints[self.current_idx].len;
    }

    /// Returns the number of unread bytes remaining in the current hint.
    pub fn remaining(self: *const HintOracle) usize {
        if (self.current_idx >= self.hints.len) return 0;
        return self.hints[self.current_idx].len - self.cursor;
    }

    /// Read up to `buf.len` bytes from the current hint into `buf`.
    /// Returns the number of bytes actually read.
    pub fn read(self: *HintOracle, buf: []u8) usize {
        if (self.current_idx >= self.hints.len) return 0;

        const hint = self.hints[self.current_idx];
        const avail = hint.len - self.cursor;
        const n = @min(buf.len, avail);

        @memcpy(buf[0..n], hint[self.cursor..][0..n]);
        self.cursor += n;

        // Auto-advance to next hint when fully consumed.
        if (self.cursor >= hint.len) {
            self.current_idx += 1;
            self.cursor = 0;
        }

        return n;
    }

    /// Manually advance to the next hint, discarding any unread bytes.
    pub fn advance(self: *HintOracle) void {
        if (self.current_idx < self.hints.len) {
            self.current_idx += 1;
            self.cursor = 0;
        }
    }

    /// Returns true if all hints have been consumed.
    pub fn exhausted(self: *const HintOracle) bool {
        return self.current_idx >= self.hints.len;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "HintOracle: basic read" {
    const hint1 = "hello";
    const hint2 = "world";
    const hints = [_][]const u8{ hint1, hint2 };
    var oracle = HintOracle.init(&hints);

    try std.testing.expectEqual(@as(usize, 5), oracle.currentLen());
    try std.testing.expect(!oracle.exhausted());

    var buf: [5]u8 = undefined;
    const n = oracle.read(&buf);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualSlices(u8, "hello", &buf);

    // Should have auto-advanced to hint2.
    try std.testing.expectEqual(@as(usize, 5), oracle.currentLen());

    const n2 = oracle.read(&buf);
    try std.testing.expectEqual(@as(usize, 5), n2);
    try std.testing.expectEqualSlices(u8, "world", &buf);

    try std.testing.expect(oracle.exhausted());
}

test "HintOracle: partial read" {
    const hint = "abcdef";
    const hints = [_][]const u8{hint};
    var oracle = HintOracle.init(&hints);

    var buf: [3]u8 = undefined;
    const n1 = oracle.read(&buf);
    try std.testing.expectEqual(@as(usize, 3), n1);
    try std.testing.expectEqualSlices(u8, "abc", &buf);
    try std.testing.expectEqual(@as(usize, 3), oracle.remaining());

    const n2 = oracle.read(&buf);
    try std.testing.expectEqual(@as(usize, 3), n2);
    try std.testing.expectEqualSlices(u8, "def", &buf);

    try std.testing.expect(oracle.exhausted());
}

test "HintOracle: empty" {
    const hints = [_][]const u8{};
    var oracle = HintOracle.init(&hints);

    try std.testing.expectEqual(@as(usize, 0), oracle.currentLen());
    try std.testing.expect(oracle.exhausted());

    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), oracle.read(&buf));
}

test "HintOracle: manual advance" {
    const hint1 = "skip";
    const hint2 = "keep";
    const hints = [_][]const u8{ hint1, hint2 };
    var oracle = HintOracle.init(&hints);

    oracle.advance(); // skip hint1

    var buf: [4]u8 = undefined;
    const n = oracle.read(&buf);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualSlices(u8, "keep", &buf);
}
