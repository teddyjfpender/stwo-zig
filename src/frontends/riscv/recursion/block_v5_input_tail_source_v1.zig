//! Genuine fresh tail-provider -> bounded ORIGINAL public byte coordinates.
//! At the common ancestor, verify this provider once and request these exact
//! cells for each independently admitted window consumer. No H/clock adapter.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Public = @import("block_v5_input_tail_public_v1.zig");
const Protocol = @import("block_v5_input_tail_protocol_v1.zig");
const Receiver = @import("block_v5_input_tail_receiver_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Recorder = @import("air/blake3_native_recorder.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_300_250;
pub const Coordinate = struct { first_cell: u32, word_count: u32 };
pub const Normalized = struct {
    words: [Public.MAX_CELLS]u32 = undefined,
    count: u32 = 0,
    public_first: ?u32 = null,
    failure: ?anyerror = null,
    pub fn beginInputTailPublic(self: *Normalized) void {
        if (self.public_first != null) self.failure = error.InvalidInputTailPublicLayout else self.public_first = self.count;
    }
    pub fn mixU32s(self: *Normalized, words: []const u32) void {
        if (self.failure != null) return;
        const end = std.math.add(usize, self.count, words.len) catch {
            self.failure = error.InputTailCellLimit;
            return;
        };
        if (end > self.words.len) {
            self.failure = error.InputTailCellLimit;
            return;
        }
        @memcpy(self.words[self.count..end], words);
        self.count = @intCast(end);
    }
    pub fn mixRoot(self: *Normalized, value: [32]u8) void {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
        self.mixU32s(&words);
    }
    pub fn mixFelts(self: *Normalized, values: []const Q) void {
        for (values) |value| {
            var words: [4]u32 = undefined;
            for (&words, value.toM31Array()) |*word, limb| word.* = limb.v;
            self.mixU32s(&words);
        }
    }
    pub fn mixU64(self: *Normalized, value: u64) void {
        self.mixU32s(&.{ @as(u32, @truncate(value)), @as(u32, @truncate(value >> 32)) });
    }
    pub fn fromAdmission(admission: *const Protocol.Admission) !Normalized {
        var normalized = Normalized{};
        try admission.mix(&normalized);
        if (normalized.failure) |failure| return failure;
        if (normalized.public_first == null) return error.InvalidInputTailPublicLayout;
        return normalized;
    }
    pub fn cell(self: *const Normalized, index: u32) ![4]M {
        if (self.failure) |failure| return failure;
        if (index >= self.count) return error.InvalidInputTailPublicCell;
        const word = self.words[index];
        var result: [4]M = undefined;
        for (&result, 0..) |*byte, i| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
        return result;
    }
};
const Routed = struct {
    recorder: *Recorder.Recorder,
    cursor: u32 = 0,
    fn source(self: *Routed, count: usize) @import("air/blake3_transcript_witness.zig").Caller {
        const first = self.cursor;
        const length = std.math.cast(u32, count) orelse {
            self.recorder.failure = error.InputTailCellLimit;
            return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
        };
        self.cursor = std.math.add(u32, self.cursor, length) catch {
            self.recorder.failure = error.InputTailCellLimit;
            return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
        };
        return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
    }
    pub fn mixU32s(self: *Routed, words: []const u32) void {
        self.recorder.mixPublicWords(self.source(words.len), words);
    }
    pub fn mixRoot(self: *Routed, value: [32]u8) void {
        self.recorder.mixPublicRoot(self.source(8), value);
    }
    pub fn mixFelts(self: *Routed, values: []const Q) void {
        const count = std.math.mul(usize, values.len, 4) catch {
            self.recorder.failure = error.InputTailCellLimit;
            return;
        };
        self.recorder.mixPublicFelts(self.source(count), values);
    }
    pub fn mixU64(self: *Routed, value: u64) void {
        self.recorder.mixPublicInteger(self.source(2), value);
    }
};
pub const Source = struct {
    /// Fresh owns its expected-public and budget leases; it must outlive this
    /// source and every nested row reader. There is no proof-capture clone.
    fresh: *const Receiver.Fresh,
    normalized: Normalized,
    terms: []const @import("block_v5_open_child_frames_v2.zig").Term = &.{},
    public_input_digest: [32]u8,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn init(fresh: *const Receiver.Fresh) !Source {
        try fresh.validate();
        const admitted = try fresh.authority();
        return .{ .fresh = fresh, .normalized = try Normalized.fromAdmission(&admitted), .public_input_digest = try admitted.publicInputIdentity() };
    }
    pub fn validate(self: *const Source) !void {
        try self.fresh.validate();
        const admitted = try self.fresh.authority();
        const expected = try Normalized.fromAdmission(&admitted);
        if (self.normalized.count != expected.count or self.normalized.public_first != expected.public_first or self.normalized.failure != null or !std.mem.eql(u32, self.normalized.words[0..self.normalized.count], expected.words[0..expected.count]) or !std.meta.eql(self.public_input_digest, try admitted.publicInputIdentity()) or self.terms.len != 0) return error.UntrustedInputTailSource;
    }
    pub fn cell(self: *const Source, index: u32) ![4]M {
        return self.normalized.cell(index);
    }
    pub fn inputRoot(self: *const Source) Coordinate {
        return .{ .first_cell = self.normalized.public_first.? + 13, .word_count = 8 };
    }
    pub fn inputLength(self: *const Source) Coordinate {
        return .{ .first_cell = self.normalized.public_first.? + 2, .word_count = 1 };
    }
    pub fn inputPrefix(self: *const Source) Coordinate {
        return .{ .first_cell = self.normalized.public_first.? + 21, .word_count = @intCast(self.fresh.policy.public.prefix_count) };
    }
    pub fn frontier(self: *const Source, ordinal: usize) !Coordinate {
        if (ordinal >= self.fresh.policy.public.frontier.len) return error.InvalidInputTailPublicCell;
        return .{ .first_cell = self.inputPrefix().first_cell + @as(u32, @intCast(self.fresh.policy.public.prefix_count + 10 * ordinal + 2)), .word_count = 8 };
    }
    pub fn mix(self: *const Source, channel: anytype) !void {
        const admitted = try self.fresh.authority();
        try admitted.mix(channel);
    }
    pub fn replayPublic(self: *const Source, recorder: *Recorder.Recorder) void {
        var routed = Routed{ .recorder = recorder };
        const admitted = self.fresh.authority() catch |failure| {
            recorder.failure = failure;
            return;
        };
        admitted.mix(&routed) catch |failure| {
            recorder.failure = failure;
            return;
        };
        if (routed.cursor != self.normalized.count) recorder.failure = error.UntrustedInputTailSource;
    }
};
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Source,
    key: Base.Key,
    expected_id: [32]u8,
    pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
    pub fn init(source: *const Source) Admission {
        return .{ .source = source, .key = source.fresh.policy.key.geometry(), .expected_id = source.fresh.policy.expected_id };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        const expected = init(self.source);
        if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedInputTailSource;
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        const actual = try self.source.fresh.authority();
        try actual.admitRoot(root);
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        return self.source.public_input_digest;
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        try self.source.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        const actual = try self.source.fresh.authority();
        try actual.mixClaims(channel, claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
        try self.validate();
        const actual = try self.source.fresh.authority();
        try actual.validateClaimsForRelations(claims, relations);
    }
};
