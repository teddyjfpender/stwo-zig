//! Bounded owning recording of original channel mix calls. Hash framing and
//! operation boundaries are retained exactly; this conveys no proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
pub const Span = struct { first: u32, len: u32 };
pub const Step = union(enum) { words: Span, root: u32, integer: u32, felts: Span };
pub const Statement = struct {
    allocator: std.mem.Allocator,
    words: []u32,
    felts: []Q,
    first: []Step,
    claims: []Step,
    sealed_offset: u32,
    roots_offset: [3]u32,
    pub fn deinit(self: *Statement) void {
        self.allocator.free(self.words);
        self.allocator.free(self.felts);
        self.allocator.free(self.first);
        self.allocator.free(self.claims);
        self.* = undefined;
    }
    pub fn clone(self: *const Statement, a: std.mem.Allocator) !Statement {
        const words = try a.dupe(u32, self.words);
        errdefer a.free(words);
        const felts = try a.dupe(Q, self.felts);
        errdefer a.free(felts);
        const first = try a.dupe(Step, self.first);
        errdefer a.free(first);
        const claims = try a.dupe(Step, self.claims);
        var result = self.*;
        result.allocator = a;
        result.words = words;
        result.felts = felts;
        result.first = first;
        result.claims = claims;
        return result;
    }
    pub fn digest(self: *const Statement, offset: u32) ![32]u8 {
        const words = try self.wordSpan(.{ .first = offset, .len = 8 });
        var value: [32]u8 = undefined;
        for (words, 0..) |word, i| std.mem.writeInt(u32, value[4 * i ..][0..4], word, .little);
        return value;
    }
    pub fn replay(self: *const Statement, channel: anytype, steps: []const Step) !void {
        for (steps) |step| switch (step) {
            .words => |span| channel.mixU32s(try self.wordSpan(span)),
            .root => |offset| channel.mixRoot(try self.digest(offset)),
            .integer => |offset| channel.mixU64(try self.integerAt(offset)),
            .felts => |span| channel.mixFelts(try self.fieldSpan(span)),
        };
    }
    pub fn recordAt(self: *const Statement, r: anytype, steps: []const Step, circuit: u32) !void {
        const fields_base = std.math.cast(u32, self.words.len) orelse return error.InvalidRecursiveStatementFrames;
        for (steps) |step| switch (step) {
            .words => |span| r.mixPublicWords(.{ .circuit = circuit, .first_wire = span.first }, try self.wordSpan(span)),
            .root => |offset| r.mixPublicRoot(.{ .circuit = circuit, .first_wire = offset }, try self.digest(offset)),
            .integer => |offset| r.mixPublicInteger(.{ .circuit = circuit, .first_wire = offset }, try self.integerAt(offset)),
            .felts => |span| r.mixPublicFelts(.{ .circuit = circuit, .first_wire = try std.math.add(u32, fields_base, try std.math.mul(u32, 4, span.first)) }, try self.fieldSpan(span)),
        };
        try r.check();
    }
    fn wordSpan(self: *const Statement, span: Span) ![]const u32 {
        if (span.first > self.words.len or span.len > self.words.len - span.first) return error.InvalidRecursiveStatementFrames;
        return self.words[span.first..][0..span.len];
    }
    fn fieldSpan(self: *const Statement, span: Span) ![]const Q {
        if (span.first > self.felts.len or span.len > self.felts.len - span.first) return error.InvalidRecursiveStatementFrames;
        return self.felts[span.first..][0..span.len];
    }
    fn integerAt(self: *const Statement, offset: u32) !u64 {
        const words = try self.wordSpan(.{ .first = offset, .len = 2 });
        return @as(u64, words[0]) | (@as(u64, words[1]) << 32);
    }
};
pub const Builder = struct {
    allocator: std.mem.Allocator,
    max_words: usize = 1 << 20,
    max_felts: usize = 32768,
    data: std.ArrayList(u32) = .empty,
    fields: std.ArrayList(Q) = .empty,
    steps: std.ArrayList(Step) = .empty,
    // Native statement extractors need this bounded offset inventory. Public
    // aggregate transcripts need only the fully retained root steps/words and
    // may explicitly disable offset tracking without relaxing framing bounds.
    track_root_offsets: bool = true,
    root_offsets: [32]u32 = undefined,
    root_count: usize = 0,
    failure: ?anyerror = null,
    pub fn deinit(self: *Builder) void {
        self.data.deinit(self.allocator);
        self.fields.deinit(self.allocator);
        self.steps.deinit(self.allocator);
    }
    pub fn check(self: *const Builder) !void {
        if (self.failure) |err| return err;
    }
    fn words(self: *Builder, values: []const u32) !u32 {
        if (self.data.items.len > self.max_words or values.len > self.max_words - self.data.items.len) return error.RecursiveStatementFrameLimit;
        const first = std.math.cast(u32, self.data.items.len) orelse return error.RecursiveStatementFrameLimit;
        try self.data.appendSlice(self.allocator, values);
        return first;
    }
    pub fn digestWords(self: *Builder, value: [32]u8) !u32 {
        var words_: [8]u32 = undefined;
        for (&words_, 0..) |*word, i| word.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
        return self.words(&words_);
    }
    pub fn mixU32s(self: *Builder, values: []const u32) void {
        if (self.failure != null) return;
        const first = self.words(values) catch |err| {
            self.failure = err;
            return;
        };
        self.steps.append(self.allocator, .{ .words = .{ .first = first, .len = @intCast(values.len) } }) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixRoot(self: *Builder, value: [32]u8) void {
        if (self.failure != null) return;
        if (self.track_root_offsets and self.root_count >= self.root_offsets.len) {
            self.failure = error.RecursiveStatementFrameLimit;
            return;
        }
        const first = self.digestWords(value) catch |err| {
            self.failure = err;
            return;
        };
        if (self.track_root_offsets) self.root_offsets[self.root_count] = first;
        self.root_count += 1;
        self.steps.append(self.allocator, .{ .root = first }) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixU64(self: *Builder, value: u64) void {
        if (self.failure != null) return;
        const first = self.words(&.{ @truncate(value), @truncate(value >> 32) }) catch |err| {
            self.failure = err;
            return;
        };
        self.steps.append(self.allocator, .{ .integer = first }) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixFelts(self: *Builder, values: []const Q) void {
        if (self.failure != null) return;
        if (self.fields.items.len > self.max_felts or values.len > self.max_felts - self.fields.items.len) {
            self.failure = error.RecursiveStatementFrameLimit;
            return;
        }
        for (values) |value| if (!@import("universal_provider_relations.zig").secureIsCanonical(&value)) {
            self.failure = error.InvalidRecursiveStatementFrames;
            return;
        };
        const first: u32 = @intCast(self.fields.items.len);
        self.fields.appendSlice(self.allocator, values) catch |err| {
            self.failure = err;
            return;
        };
        self.steps.append(self.allocator, .{ .felts = .{ .first = first, .len = @intCast(values.len) } }) catch |err| {
            self.failure = err;
        };
    }
};
