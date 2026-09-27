//! Allocation-free comparison of original mix calls with an owned first frame.
//! Exact framing is a consistency check, never a fresh-proof receipt or token.
//! The frame and authority remain immutable during this synchronous comparison.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Canonical = @import("universal_provider_relations.zig");

pub const Limits = struct {
    max_words: usize = 1 << 20,
    max_felts: usize = 32768,
    max_steps: usize = 1 << 20,
};
/// Independently supplied auxiliary coordinates, not inferred from the frame.
/// Sources whose original recorder does not use them explicitly pass zeroes.
pub const Offsets = struct { sealed_offset: u32, roots_offset: [3]u32 };

pub const Comparator = struct {
    frame: *const Frames.Statement,
    word_position: usize = 0,
    felt_position: usize = 0,
    step_position: usize = 0,
    failure: ?anyerror = null,

    /// Empty claims are part of this first-only interface's exact grammar.
    /// Every size is checked before inspecting any borrowed array element.
    pub fn initFirst(frame: *const Frames.Statement, limits: Limits, offsets: Offsets) !Comparator {
        if (limits.max_words == 0 or limits.max_felts == 0 or limits.max_steps == 0 or
            frame.words.len > limits.max_words or frame.felts.len > limits.max_felts or
            frame.first.len > limits.max_steps or frame.claims.len > limits.max_steps - frame.first.len or
            frame.words.len > std.math.maxInt(u32) or frame.felts.len > std.math.maxInt(u32))
            return error.RecursiveStatementFrameLimit;
        if (frame.claims.len != 0 or frame.sealed_offset != offsets.sealed_offset or
            !std.meta.eql(frame.roots_offset, offsets.roots_offset))
            return error.InvalidRecursiveStatementFrames;
        return .{ .frame = frame };
    }
    pub fn check(self: *const Comparator) !void {
        if (self.failure) |err| return err;
    }
    pub fn finish(self: *const Comparator) !void {
        try self.check();
        if (self.step_position != self.frame.first.len or self.word_position != self.frame.words.len or self.felt_position != self.frame.felts.len)
            return error.InvalidRecursiveStatementFrames;
    }
    fn next(self: *const Comparator) !Frames.Step {
        if (self.step_position >= self.frame.first.len) return error.InvalidRecursiveStatementFrames;
        return self.frame.first[self.step_position];
    }
    fn takeWords(self: *Comparator, first: u32, values: []const u32) !void {
        if (first != self.word_position or self.word_position > self.frame.words.len or
            values.len > self.frame.words.len - self.word_position)
            return error.InvalidRecursiveStatementFrames;
        if (!std.mem.eql(u32, self.frame.words[self.word_position..][0..values.len], values))
            return error.InvalidRecursiveStatementFrames;
        self.word_position += values.len;
        self.step_position += 1;
    }
    fn words(self: *Comparator, values: []const u32) !void {
        const step = try self.next();
        if (step != .words or step.words.len != values.len) return error.InvalidRecursiveStatementFrames;
        try self.takeWords(step.words.first, values);
    }
    pub fn mixU32s(self: *Comparator, values: []const u32) void {
        if (self.failure != null) return;
        self.words(values) catch |err| {
            self.failure = err;
        };
    }
    fn root(self: *Comparator, value: [32]u8) !void {
        const step = try self.next();
        if (step != .root) return error.InvalidRecursiveStatementFrames;
        var words_: [8]u32 = undefined;
        for (&words_, 0..) |*word, index| word.* = std.mem.readInt(u32, value[4 * index ..][0..4], .little);
        try self.takeWords(step.root, &words_);
    }
    pub fn mixRoot(self: *Comparator, value: [32]u8) void {
        if (self.failure != null) return;
        self.root(value) catch |err| {
            self.failure = err;
        };
    }
    fn integer(self: *Comparator, value: u64) !void {
        const step = try self.next();
        if (step != .integer) return error.InvalidRecursiveStatementFrames;
        try self.takeWords(step.integer, &.{ @truncate(value), @truncate(value >> 32) });
    }
    pub fn mixU64(self: *Comparator, value: u64) void {
        if (self.failure != null) return;
        self.integer(value) catch |err| {
            self.failure = err;
        };
    }
    fn felts(self: *Comparator, values: []const Q) !void {
        const step = try self.next();
        if (step != .felts or step.felts.first != self.felt_position or step.felts.len != values.len or
            self.felt_position > self.frame.felts.len or values.len > self.frame.felts.len - self.felt_position)
            return error.InvalidRecursiveStatementFrames;
        for (self.frame.felts[self.felt_position..][0..values.len], values) |expected, actual| {
            if (!Canonical.secureIsCanonical(&expected) or !Canonical.secureIsCanonical(&actual) or
                !Canonical.secureEql(&expected, &actual))
                return error.InvalidRecursiveStatementFrames;
        }
        self.felt_position += values.len;
        self.step_position += 1;
    }
    pub fn mixFelts(self: *Comparator, values: []const Q) void {
        if (self.failure != null) return;
        self.felts(values) catch |err| {
            self.failure = err;
        };
    }
};

/// Re-run the ORIGINAL admission's mix calls; neither this helper nor its
/// cursor supplies or caches authority. Original admission/fresh/term checks
/// remain the caller's obligation, as do independently derived coordinates.
pub fn compareFirst(frame: *const Frames.Statement, limits: Limits, offsets: Offsets, authority: anytype) !void {
    var comparator = try Comparator.initFirst(frame, limits, offsets);
    try authority.mix(&comparator);
    try comparator.finish();
}
