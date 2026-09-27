//! Bounded exact original Admission.mix recording. The claim location uses
//! original immutable slice identity and an exact invocation counter, never
//! equal-value search. This normalizer supplies no verification authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
const Count = @import("block_v5_memory_source_page_forest_algebra_v1.zig").CLAIM_COUNT;
pub const Limits = struct { max_words: usize = 32768, max_felts: usize = 1024, max_steps: usize = 512, max_terms: usize = 1048576 };
const Writer = struct {
    builder: *Frames.Builder,
    target: []const Q,
    claim_offset: u32,
    located: ?u32 = null,
    matches: usize = 0,
    target_words: ?[]const u32 = null,
    word_first: ?u32 = null,
    word_matches: usize = 0,
    pub fn mixU32s(self: *@This(), values: []const u32) void {
        if (self.target_words) |target| if (values.ptr == target.ptr and values.len == target.len) {
            self.word_matches += 1;
            self.word_first = std.math.cast(u32, self.builder.data.items.len) orelse {
                self.builder.failure = error.PageForestSourceLimit;
                return;
            };
        };
        self.builder.mixU32s(values);
    }
    pub fn mixRoot(self: *@This(), value: [32]u8) void {
        self.builder.mixRoot(value);
    }
    pub fn mixU64(self: *@This(), value: u64) void {
        self.builder.mixU64(value);
    }
    pub fn mixFelts(self: *@This(), values: []const Q) void {
        if (values.ptr == self.target.ptr and values.len == self.target.len) {
            self.matches += 1;
            self.located = std.math.add(u32, std.math.cast(u32, self.builder.fields.items.len) orelse {
                self.builder.failure = error.PageForestSourceLimit;
                return;
            }, self.claim_offset) catch {
                self.builder.failure = error.PageForestSourceLimit;
                return;
            };
        }
        self.builder.mixFelts(values);
    }
};
pub const Normalized = struct {
    frame: Frames.Statement,
    claim_first: u32,
    word_first: ?u32,
    pub fn init(a: std.mem.Allocator, admission: anytype, claim_frame: []const Q, claim_offset: u32, limits: Limits) !Normalized {
        return initWithWords(a, admission, claim_frame, claim_offset, null, limits);
    }
    pub fn initWithWords(a: std.mem.Allocator, admission: anytype, claim_frame: []const Q, claim_offset: u32, target_words: ?[]const u32, limits: Limits) !Normalized {
        if (limits.max_words == 0 or limits.max_felts == 0 or limits.max_steps == 0 or claim_offset > claim_frame.len or Count > claim_frame.len - claim_offset) return error.PageForestSourceLimit;
        var builder = Frames.Builder{ .allocator = a, .max_words = limits.max_words, .max_felts = limits.max_felts };
        defer builder.deinit();
        var writer = Writer{ .builder = &builder, .target = claim_frame, .claim_offset = claim_offset, .target_words = target_words };
        try admission.mix(&writer);
        try builder.check();
        if (writer.matches != 1 or (target_words != null and writer.word_matches != 1) or builder.steps.items.len > limits.max_steps) return error.UntrustedPageForestClaimLayout;
        const located = writer.located orelse return error.UntrustedPageForestClaimLayout;
        const words = try builder.data.toOwnedSlice(a);
        errdefer a.free(words);
        const felts = try builder.fields.toOwnedSlice(a);
        errdefer a.free(felts);
        const steps = try builder.steps.toOwnedSlice(a);
        errdefer a.free(steps);
        const claims = try a.alloc(Frames.Step, 0);
        errdefer a.free(claims);
        const first = try std.math.add(u32, std.math.cast(u32, words.len) orelse return error.PageForestSourceLimit, try std.math.mul(u32, 4, located));
        return .{ .frame = .{ .allocator = a, .words = words, .felts = felts, .first = steps, .claims = claims, .sealed_offset = 0, .roots_offset = @splat(0) }, .claim_first = first, .word_first = writer.word_first };
    }
    pub fn deinit(self: *Normalized) void {
        self.frame.deinit();
        self.* = undefined;
    }
    pub fn require(self: *const Normalized, a: std.mem.Allocator, admission: anytype, claim_frame: []const Q, claim_offset: u32, limits: Limits) !void {
        try self.requireWithWords(a, admission, claim_frame, claim_offset, null, limits);
    }
    pub fn requireWithWords(self: *const Normalized, a: std.mem.Allocator, admission: anytype, claim_frame: []const Q, claim_offset: u32, target_words: ?[]const u32, limits: Limits) !void {
        var expected = try initWithWords(a, admission, claim_frame, claim_offset, target_words, limits);
        defer expected.deinit();
        if (self.claim_first != expected.claim_first or self.word_first != expected.word_first or !std.mem.eql(u32, self.frame.words, expected.frame.words) or self.frame.first.len != expected.frame.first.len or self.frame.felts.len != expected.frame.felts.len) return error.MutatedPageForestSource;
        for (self.frame.first, expected.frame.first) |x, y| if (!std.meta.eql(x, y)) return error.MutatedPageForestSource;
        for (self.frame.felts, expected.frame.felts) |x, y| if (!x.eql(y)) return error.MutatedPageForestSource;
    }
    pub fn cell(self: *const Normalized, coordinate: u32) ![4]M {
        const total = try std.math.add(usize, self.frame.words.len, try std.math.mul(usize, 4, self.frame.felts.len));
        if (coordinate >= total) return error.InvalidPageForestCell;
        const raw = if (coordinate < self.frame.words.len) self.frame.words[coordinate] else self.frame.felts[(coordinate - self.frame.words.len) / 4].toM31Array()[(coordinate - self.frame.words.len) % 4].v;
        var out: [4]M = undefined;
        for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((raw >> @as(u5, @intCast(8 * part))) & 255);
        return out;
    }
    pub fn replay(self: *const Normalized, recorder: *@import("air/blake3_native_recorder.zig").Recorder, circuit: u32) void {
        self.frame.recordAt(recorder, self.frame.first, circuit) catch |err| {
            recorder.failure = err;
        };
    }
};
