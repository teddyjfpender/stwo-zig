//! Original B5PD public preimage, plus independently derived public boundary
//! tuple/window coordinates. Input words are borrowed from immutable admitted
//! job data; this owner never copies a block-sized input for each execution.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Public = @import("../air/public_data.zig");
const Decode = @import("../air/program/decode.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { max_words: usize = 16 << 20, max_metadata_bytes: usize = 64 << 20 };
pub const Chunk = struct { first: u32, words: []const u32, owned: bool };
pub const Layout = struct {
    pc_clock: u32,
    initial: u32,
    final: u32,
    clocks: u32,
    completion: u32,
    decoded: u32,
    cycles: u32,
};
pub const Fields = struct {
    allocator: std.mem.Allocator,
    chunks: []Chunk,
    hashed_chunks: usize,
    word_count: u32,
    layout: Layout,
    profile: Decode.ExecutionProfile,
    first_cycle: u64,
    last_cycle: u64,
    source_digest: [32]u8,
    /// Borrows the SAME immutable input used by independently admitted shape.
    borrowed_input: []const u32,
    pub fn deinit(self: *Fields) void {
        for (self.chunks) |chunk| if (chunk.owned) self.allocator.free(chunk.words);
        self.allocator.free(self.chunks);
        self.* = undefined;
    }
    pub fn word(self: *const Fields, coordinate: u32) !u32 {
        for (self.chunks) |chunk| if (coordinate >= chunk.first and coordinate - chunk.first < chunk.words.len) return chunk.words[coordinate - chunk.first];
        return error.InvalidGlobalPublicCoordinate;
    }
    pub fn bytes(self: *const Fields, coordinate: u32) ![4]M {
        const value = try self.word(coordinate);
        var out: [4]M = undefined;
        for (&out, 0..) |*byte, part| byte.* = M.fromCanonical((value >> @as(u5, @intCast(part * 8))) & 255);
        return out;
    }
    /// Every final receiver reconstructs the exact original public framing and
    /// canonical PUBLIC decoder. No private dynamic decode is claimed here.
    pub fn validate(self: *const Fields, data: *const Public.Blake3PublicData, profile: Decode.ExecutionProfile, first_cycle: u64, last_cycle: u64) !void {
        try data.validate();
        // Validate extents before replay indexes any descriptor. These are
        // public metadata, so a changed count must reject rather than trap.
        const required_chunks = std.math.add(usize, self.hashed_chunks, 2) catch return error.UntrustedGlobalPublicFields;
        if (self.hashed_chunks < 13 or self.chunks.len != required_chunks) return error.UntrustedGlobalPublicFields;
        if (self.borrowed_input.ptr != data.io_entries.input_words.ptr or self.borrowed_input.len != data.io_entries.input_words.len or data.clock == 0 or self.profile != profile or self.first_cycle != first_cycle or self.last_cycle != last_cycle or first_cycle == 0 or last_cycle < first_cycle or last_cycle - first_cycle != @as(u64, data.clock) - 1 or
            !std.meta.eql(self.source_digest, @import("../prover/block_v5_native_public_admission_v1.zig").publicDigest(data))) return error.UntrustedGlobalPublicFields;
        var comparison = Compare{ .fields = self };
        comparison.mixU32s(&.{ 0x42355044, 1 });
        data.mixInto(&comparison);
        try comparison.check();
        if (comparison.at != self.hashed_chunks) return error.UntrustedGlobalPublicFields;
        const completion = data.completion orelse return error.MissingCompletion;
        const decoded: [4]u32 = if (completion.kind == .halt_flag) @splat(0) else try Decode.decodeProgramWordForProfile(profile, completion.value);
        for (decoded, 0..) |expected, limb| if (try self.word(self.layout.decoded + @as(u32, @intCast(limb))) != expected) return error.UntrustedGlobalPublicDecode;
        const cycles = [_]u32{ @truncate(first_cycle), @truncate(first_cycle >> 32), @truncate(last_cycle), @truncate(last_cycle >> 32) };
        for (cycles, 0..) |expected, limb| if (try self.word(self.layout.cycles + @as(u32, @intCast(limb))) != expected) return error.UntrustedGlobalPublicFields;
        if (try std.math.add(u32, comparison.word_count, 8) != self.word_count) return error.UntrustedGlobalPublicFields;
        if (self.chunks[self.hashed_chunks].first != self.layout.decoded or self.chunks[self.hashed_chunks].words.len != 4 or self.chunks[self.hashed_chunks + 1].first != self.layout.cycles or self.chunks[self.hashed_chunks + 1].words.len != 4) return error.UntrustedGlobalPublicFields;
        if (self.layout.pc_clock != self.chunks[2].first or self.layout.initial != self.chunks[3].first or self.layout.final != self.chunks[4].first or self.layout.clocks != self.chunks[5].first or self.layout.completion != self.chunks[10].first or self.layout.decoded != comparison.word_count or self.layout.cycles != comparison.word_count + 4) return error.UntrustedGlobalPublicFields;
    }
};
const Collector = struct {
    allocator: std.mem.Allocator,
    input: []const u32,
    limits: Limits,
    chunks: std.ArrayList(Chunk) = .empty,
    words: usize = 0,
    owned_bytes: usize = 0,
    failure: ?anyerror = null,
    fn deinit(self: *Collector) void {
        for (self.chunks.items) |chunk| if (chunk.owned) self.allocator.free(chunk.words);
        self.chunks.deinit(self.allocator);
    }
    pub fn mixU32s(self: *Collector, values: []const u32) void {
        if (self.failure != null) return;
        self.append(values) catch |err| {
            self.failure = err;
        };
    }
    fn append(self: *Collector, values: []const u32) !void {
        const end = try std.math.add(usize, self.words, values.len);
        if (end > self.limits.max_words or end >= core.fields.m31.Modulus) return error.GlobalPublicResourceLimit;
        // Only the original immutable input span is borrowed. Temporary header
        // and output record arrays emitted by mixInto are always owned.
        const borrowed = self.chunks.items.len == 12 and values.len != 0 and values.len == self.input.len and values.ptr == self.input.ptr;
        const extra = if (borrowed) 0 else try std.math.mul(usize, values.len, @sizeOf(u32));
        const extent = try std.math.add(usize, self.owned_bytes, try std.math.add(usize, extra, @sizeOf(Chunk)));
        if (extent > self.limits.max_metadata_bytes) return error.GlobalPublicResourceLimit;
        const stored = if (borrowed) values else try self.allocator.dupe(u32, values);
        errdefer if (!borrowed) self.allocator.free(stored);
        try self.chunks.ensureTotalCapacityPrecise(self.allocator, try std.math.add(usize, self.chunks.items.len, 1));
        self.chunks.appendAssumeCapacity(.{ .first = @intCast(self.words), .words = stored, .owned = !borrowed });
        self.words = end;
        self.owned_bytes = extent;
    }
};
const Compare = struct {
    fields: *const Fields,
    at: usize = 0,
    word_count: u32 = 0,
    failure: ?anyerror = null,
    pub fn mixU32s(self: *Compare, values: []const u32) void {
        if (self.failure != null) return;
        if (self.at >= self.fields.hashed_chunks) {
            self.failure = error.UntrustedGlobalPublicFields;
            return;
        }
        const chunk = self.fields.chunks[self.at];
        if (chunk.first != self.word_count or !std.mem.eql(u32, values, chunk.words)) {
            self.failure = error.UntrustedGlobalPublicFields;
            return;
        }
        self.word_count = std.math.add(u32, self.word_count, @intCast(values.len)) catch |err| {
            self.failure = err;
            return;
        };
        self.at += 1;
    }
    fn check(self: *const Compare) !void {
        if (self.failure) |err| return err;
    }
};
pub fn init(a: std.mem.Allocator, data: *const Public.Blake3PublicData, profile: Decode.ExecutionProfile, first_cycle: u64, last_cycle: u64, limits: Limits) !Fields {
    try data.validate();
    if (data.clock == 0 or first_cycle == 0 or last_cycle < first_cycle or last_cycle - first_cycle != @as(u64, data.clock) - 1 or limits.max_words == 0 or limits.max_metadata_bytes == 0) return error.UntrustedGlobalPublicFields;
    var collector = Collector{ .allocator = a, .input = data.io_entries.input_words, .limits = limits };
    defer collector.deinit();
    collector.mixU32s(&.{ 0x42355044, 1 });
    data.mixInto(&collector);
    if (collector.failure) |err| return err;
    const hashed_chunks = collector.chunks.items.len;
    // Original PublicData mix order: B5PD; version; PC/clock; three register
    // vectors; presence; three roots; completion. IO follows unchanged.
    if (hashed_chunks < 13) return error.UntrustedGlobalPublicFields;
    const decoded: [4]u32 = if (data.completion.?.kind == .halt_flag) @splat(0) else try Decode.decodeProgramWordForProfile(profile, data.completion.?.value);
    for (decoded) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalProgramField;
    const decoded_first: u32 = @intCast(collector.words);
    try collector.append(&decoded);
    const cycles_first: u32 = @intCast(collector.words);
    try collector.append(&.{ @as(u32, @truncate(first_cycle)), @as(u32, @truncate(first_cycle >> 32)), @as(u32, @truncate(last_cycle)), @as(u32, @truncate(last_cycle >> 32)) });
    const layout = Layout{ .pc_clock = collector.chunks.items[2].first, .initial = collector.chunks.items[3].first, .final = collector.chunks.items[4].first, .clocks = collector.chunks.items[5].first, .completion = collector.chunks.items[10].first, .decoded = decoded_first, .cycles = cycles_first };
    const chunks = try collector.chunks.toOwnedSlice(a);
    errdefer {
        for (chunks) |chunk| if (chunk.owned) a.free(chunk.words);
        a.free(chunks);
    }
    var result = Fields{ .allocator = a, .chunks = chunks, .hashed_chunks = hashed_chunks, .word_count = @intCast(collector.words), .layout = layout, .profile = profile, .first_cycle = first_cycle, .last_cycle = last_cycle, .source_digest = @import("../prover/block_v5_native_public_admission_v1.zig").publicDigest(data), .borrowed_input = data.io_entries.input_words };
    try result.validate(data, profile, first_cycle, last_cycle);
    return result;
}
