//! Independently reconstructed, once-per-job input policy and bounded original
//! BLAKE3 frontier public statement. These values are NOT proof acceptance.
const std = @import("std");
const core = @import("stwo_core");
const Tail = @import("blake3_words_tail_v1.zig");
const File = @import("../prover/block_v5_global_expected_public_file_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42355450; // B5TP: actual new input-tail public statement.
pub const PREFIX_WORDS: usize = Tail.FIRST_INPUT_BYTES / 4;
pub const MAX_CELLS: usize = 512;
comptime {
    if (Tail.FIRST_INPUT_BYTES % 4 != 0 or PREFIX_WORDS != 239) @compileError("original word-tail public layout changed");
}
pub const Pin = struct { root: [32]u8, word_count: u32 };
pub const Limits = struct { max_words: usize = 16 << 20, max_hash_calls: usize = 1 << 20 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: ?*Budget,
    references: std.atomic.Value(usize),
    job: *File.Owned,
    pin: Pin,
    geometry: Tail.Geometry,
    frontier: [][8]u32,
    prefix_words: [PREFIX_WORDS]u32,
    prefix_count: usize,
    statement_id: [32]u8,
    pub fn init(a: std.mem.Allocator, job: *File.Owned, limits: Limits) !*Owned {
        const words = job.expected().input_words;
        const geometry = try Tail.Geometry.init(words.len);
        const blocks = geometry.frame_bytes / 64 + @intFromBool(geometry.frame_bytes % 64 != 0);
        const calls = try std.math.add(usize, blocks, geometry.chunks - 1);
        if (words.len > limits.max_words or words.len > std.math.maxInt(u32) or calls > limits.max_hash_calls) return error.InputTailResourceLimit;
        const budget = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
        errdefer if (budget) |owner| owner.destroy();
        const owned = try a.create(Owned);
        errdefer a.destroy(owned);
        var scalar = try Tail.ScalarTail.init(a, words);
        errdefer scalar.deinit();
        const root = (core.channel.blake3.framing.Frame{ .words = .{ .state = Tail.DOMAIN_STATE, .values = words } }).hash();
        var prefix_words: [PREFIX_WORDS]u32 = @splat(0);
        const count = @min(words.len, prefix_words.len);
        @memcpy(prefix_words[0..count], words[0..count]);
        const retained = try job.retain();
        errdefer retained.deinit();
        owned.* = .{ .allocator = a, .budget = budget, .references = std.atomic.Value(usize).init(1), .job = retained, .pin = .{ .root = root, .word_count = @intCast(words.len) }, .geometry = geometry, .frontier = scalar.cvs, .prefix_words = prefix_words, .prefix_count = count, .statement_id = undefined };
        owned.statement_id = try owned.computeStatementId();
        scalar.cvs = &.{};
        return owned;
    }
    pub fn retain(self: *Owned) *Owned {
        const previous = self.references.fetchAdd(1, .monotonic);
        if (previous >= std.math.maxInt(usize) / 2) @panic("too many input-tail policy leases");
        return self;
    }
    pub fn deinit(self: *Owned) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        const a = self.allocator;
        const budget = self.budget;
        a.free(self.frontier);
        self.job.deinit();
        a.destroy(self);
        if (budget) |owner| owner.destroy();
    }
    pub fn require(self: *const Owned, independent: Pin) !void {
        if (!std.meta.eql(self.pin, independent) or self.pin.word_count != self.job.expected().input_words.len or self.prefix_count != @min(PREFIX_WORDS, self.job.expected().input_words.len) or self.frontier.len != self.geometry.range_count) return error.UntrustedInputTailPublic;
        try self.geometry.require(self.pin.word_count);
        if (!std.mem.eql(u32, self.prefix_words[0..self.prefix_count], self.job.expected().input_words[0..self.prefix_count]) or !std.meta.eql(try self.computeStatementId(), self.statement_id)) return error.UntrustedInputTailPublic;
    }
    pub fn prefix(self: *const Owned) []const u32 {
        return self.prefix_words[0..self.prefix_count];
    }
    pub fn mix(self: *const Owned, channel: anytype) void {
        if (@hasDecl(@TypeOf(channel.*), "beginInputTailPublic")) channel.beginInputTailPublic();
        channel.mixU32s(&.{ TAG, VERSION, self.pin.word_count, @intCast(self.prefix_count), @intCast(self.frontier.len) });
        channel.mixRoot(Tail.DOMAIN_STATE);
        channel.mixRoot(self.pin.root);
        channel.mixU32s(self.prefix());
        for (self.frontier, self.geometry.frontier()) |cv, range| {
            // Counter/range geometry is public and normative, not a received
            // digest annotation. The receiver derives it from exact length.
            channel.mixU32s(&.{ @intCast(range.first), @intCast(range.count) });
            channel.mixU32s(&cv);
        }
    }
    pub fn computeStatementId(self: *const Owned) ![32]u8 {
        if (self.frontier.len != self.geometry.range_count or self.prefix_count > self.prefix_words.len) return error.UntrustedInputTailPublic;
        var channel = core.channel.blake3.Channel{};
        self.mix(&channel);
        return channel.digestBytes();
    }
};

/// Locate a CV inside the ORIGINAL full hash graph, not a separately invented
/// tree. Every range must be one exact original canonical subtree.
pub fn outputCall(geometry: *const Tail.Geometry, range: Tail.Range) !usize {
    try geometry.require(geometry.words);
    return find(geometry, 0, geometry.chunks, 0, range);
}
fn callsIn(geometry: *const Tail.Geometry, first: usize, count: usize) !usize {
    if (count == 0 or first >= geometry.chunks or count > geometry.chunks - first) return error.UntrustedInputTailRange;
    var blocks = try std.math.mul(usize, count, 16);
    if (first + count == geometry.chunks) {
        const final_len = geometry.frame_bytes - (geometry.chunks - 1) * 1024;
        const final_blocks = final_len / 64 + @intFromBool(final_len % 64 != 0);
        blocks -= 16 - final_blocks;
    }
    return std.math.add(usize, blocks, count - 1);
}
fn find(geometry: *const Tail.Geometry, first: usize, count: usize, offset: usize, range: Tail.Range) anyerror!usize {
    if (range.count == 0 or range.first < first or range.first - first >= count or range.count > count - (range.first - first)) return error.UntrustedInputTailRange;
    if (range.first == first and range.count == count) return offset + try callsIn(geometry, first, count) - 1;
    if (count == 1) return error.UntrustedInputTailRange;
    const left = @as(usize, 1) << @intCast(std.math.log2_int(usize, count - 1));
    if (range.first < first + left) {
        if (range.count > first + left - range.first) return error.UntrustedInputTailRange;
        return find(geometry, first, left, offset, range);
    }
    return find(geometry, first + left, count - left, offset + try callsIn(geometry, first, left), range);
}
