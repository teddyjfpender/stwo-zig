//! Exact fixed-size V2 identity preimages. Native hashing and recursive hash
//! rows share this field order. Emission does not authenticate its inputs.
const std = @import("std");
const contract = @import("segment_statement_v2_contract.zig");
const span = @import("span_statement.zig");
const M31 = contract.M31;
const Digest = contract.Digest;

pub const Phase = enum { job, base_statement, position, entry_lineage, exit_lineage, lineage };
pub const Position = struct {
    session_id: Digest,
    job_id: Digest,
    segment_index: u32,
    segment_count: u32,
    range: contract.RangeV2,
    slots: span.SlotSpan,
};
pub const Boundary = struct {
    session_id: Digest,
    job_id: Digest,
    boundary_index: u32,
    cycle: u32,
    machine_words: *const [span.MACHINE_STATE_CANONICAL_WORDS]M31,
    snapshot: contract.SnapshotIdentity,
    register_clocks: [32]u32,
    memory_clock_id: Digest,
    memory_clock_count: u32,
};
pub const Lineage = struct {
    session_id: Digest,
    job_id: Digest,
    position_id: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    base_statement_id: Digest,
};
pub const Input = union(Phase) {
    job: *const contract.BaseStatementWords,
    base_statement: *const contract.BaseStatementWords,
    position: Position,
    entry_lineage: Boundary,
    exit_lineage: Boundary,
    lineage: Lineage,
};

pub fn domain(phase: Phase) u32 {
    return switch (phase) {
        .job => contract.JOB_ID_DOMAIN,
        .base_statement => contract.protocol.STATEMENT_ID_DOMAIN,
        .position => contract.POSITION_ID_DOMAIN,
        .entry_lineage, .exit_lineage => contract.BOUNDARY_LINEAGE_ID_DOMAIN,
        .lineage => contract.SEGMENT_LINEAGE_ID_DOMAIN,
    };
}

pub fn wordCount(phase: Phase) usize {
    return switch (phase) {
        .job => span.canonical_layout.slot_start - span.canonical_layout.job_start,
        .base_statement => span.SPAN_STATEMENT_CANONICAL_WORDS,
        .position => 1 + 16 + 8 + 4 + 1 + 4,
        .entry_lineage, .exit_lineage => 1 + 16 + 4 + span.MACHINE_STATE_CANONICAL_WORDS + 8 + 2 + 1 + 64 + 8 + 2,
        .lineage => 1 + 6 * 8,
    };
}

/// The sink implements scalar(u32) void. All integer splitting occurs here;
/// callers cannot accidentally hash unrestricted u32 values as field words.
pub fn emit(sink: anytype, input: Input) void {
    switch (input) {
        inline else => |value, phase| emitPhase(phase, sink, value),
    }
}

/// Shared native/symbolic field order. Symbolic u32 values expose two limbs;
/// symbolic slot integers expose four limbs. The sink owns authentication.
pub fn emitPhase(comptime phase: Phase, sink: anytype, value: anytype) void {
    switch (phase) {
        .job => fields(sink, value[span.canonical_layout.job_start..span.canonical_layout.slot_start]),
        .base_statement => fields(sink, value),
        .position => {
            sink.scalar(contract.FORMAT_VERSION);
            digest(sink, value.session_id);
            digest(sink, value.job_id);
            u32Words(sink, value.segment_index);
            u32Words(sink, value.segment_count);
            u32Words(sink, value.range.start);
            u32Words(sink, value.range.end);
            u64Words(sink, value.slots.first);
            sink.scalar(value.slots.height);
            u64Words(sink, value.slots.nodeIndex());
        },
        .entry_lineage, .exit_lineage => {
            sink.scalar(contract.FORMAT_VERSION);
            digest(sink, value.session_id);
            digest(sink, value.job_id);
            u32Words(sink, value.boundary_index);
            u32Words(sink, value.cycle);
            fields(sink, value.machine_words);
            digest(sink, value.snapshot.id);
            u32Words(sink, value.snapshot.count);
            sink.scalar(value.snapshot.root);
            for (value.register_clocks) |clock| u32Words(sink, clock);
            digest(sink, value.memory_clock_id);
            u32Words(sink, value.memory_clock_count);
        },
        .lineage => {
            sink.scalar(contract.FORMAT_VERSION);
            digest(sink, value.session_id);
            digest(sink, value.job_id);
            digest(sink, value.position_id);
            digest(sink, value.entry_lineage_id);
            digest(sink, value.exit_lineage_id);
            digest(sink, value.base_statement_id);
        },
    }
}

/// Canonical retained-section framing. Callers admit section geometry and
/// canonical u16 payload words before using this identity-only emitter.
pub fn retainedWordCount(entry_count: usize) usize {
    return 3 + contract.RETAINED_ENTRY_WORDS * entry_count;
}
pub fn emitRetainedSection(sink: anytype, count: anytype, payload: anytype) void {
    sink.scalar(contract.FORMAT_VERSION);
    u32Words(sink, count);
    fields(sink, payload);
}

/// A caller-owned exact-size buffer is convenient for the existing recursive
/// public-hash row generator. Native callers emit directly into their hasher.
pub fn write(input: Input, destination: []u32) error{InvalidIdentityPreimageLength}!void {
    if (destination.len != wordCount(std.meta.activeTag(input)))
        return error.InvalidIdentityPreimageLength;
    var writer = WordWriter{ .words = destination };
    emit(&writer, input);
    std.debug.assert(writer.at == destination.len);
}

const WordWriter = struct {
    words: []u32,
    at: usize = 0,
    pub fn scalar(self: *WordWriter, value: u32) void {
        std.debug.assert(value < contract.m31.Modulus);
        self.words[self.at] = value;
        self.at += 1;
    }
};
fn fields(sink: anytype, words: anytype) void {
    for (words) |word| sink.scalar(if (@TypeOf(word) == M31) word.toU32() else word);
}
fn digest(sink: anytype, words: anytype) void {
    for (words) |word| sink.scalar(word);
}
fn u32Words(sink: anytype, value: anytype) void {
    if (@typeInfo(@TypeOf(value)) == .int or @typeInfo(@TypeOf(value)) == .comptime_int) {
        const integer: u32 = value;
        sink.scalar(integer & 0xffff);
        sink.scalar(integer >> 16);
    } else for (value.limbs) |limb| sink.scalar(limb);
}
fn u64Words(sink: anytype, value: anytype) void {
    if (@typeInfo(@TypeOf(value)) == .int or @typeInfo(@TypeOf(value)) == .comptime_int) {
        const integer: u64 = value;
        inline for (0..4) |limb| sink.scalar(@as(u32, @intCast((integer >> (16 * limb)) & 0xffff)));
    } else for (value) |limb| sink.scalar(limb);
}

test "segment statement V2 shared identity preimages preserve native job base and position digests" {
    var base: contract.BaseStatementWords = undefined;
    for (&base, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(index + 1));
    var words: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    try write(.{ .base_statement = &base }, &words);
    for (words, 0..) |word, index| try std.testing.expectEqual(@as(u32, @intCast(index + 1)), word);
    try std.testing.expectEqual(contract.protocol.statementId(&words), contract.baseStatementIdAssumeCanonical(&base));
    const job_expected = contract.channel.hashCanonicalWords(
        base[span.canonical_layout.job_start..span.canonical_layout.slot_start],
        contract.JOB_ID_DOMAIN,
    );
    try std.testing.expectEqual(job_expected, contract.jobIdAssumeCanonical(&base));
    var job_words: [wordCount(.job)]u32 = undefined;
    try write(.{ .job = &base }, &job_words);
    try std.testing.expectEqualSlices(u32, words[span.canonical_layout.job_start..span.canonical_layout.slot_start], &job_words);
    try std.testing.expectError(error.InvalidIdentityPreimageLength, write(.{ .job = &base }, &words));

    const position = Position{
        .session_id = .{ 10, 11, 12, 13, 14, 15, 16, 17 },
        .job_id = .{ 20, 21, 22, 23, 24, 25, 26, 27 },
        .segment_index = 0x1234_5678,
        .segment_count = 0x7654_3210,
        .range = .{ .start = 0x1111_2222, .end = 0x3333_4444 },
        .slots = try span.SlotSpan.init(0x1000_0040, 4),
    };
    const expected = [_]u32{
        2,      10,     11,     12,     13,     14,     15,     16,     17,     20,     21, 22, 23, 24, 25,     26, 27,
        0x5678, 0x1234, 0x3210, 0x7654, 0x2222, 0x1111, 0x4444, 0x3333, 0x0040, 0x1000, 0,  0,  4,  4,  0x0100, 0,  0,
    };
    var position_words: [wordCount(.position)]u32 = undefined;
    try write(.{ .position = position }, &position_words);
    try std.testing.expectEqualSlices(u32, &expected, &position_words);
    try std.testing.expectEqual(
        contract.channel.hashCanonicalU32s(&expected, contract.POSITION_ID_DOMAIN),
        contract.derivePositionId(position.session_id, position.job_id, position.segment_index, position.segment_count, position.range, position.slots),
    );
    try std.testing.expectEqual(@as(u32, 0x5354_4d54), domain(.base_statement));
}

test "segment statement V2 shared identity preimages preserve boundary and segment lineage digests" {
    var machine: [span.MACHINE_STATE_CANONICAL_WORDS]M31 = undefined;
    for (&machine, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(100 + index));
    var clocks: [32]u32 = undefined;
    for (&clocks, 0..) |*clock, index| clock.* = 0x1234_0000 + @as(u32, @intCast(index));
    const boundary = Boundary{
        .session_id = .{ 10, 11, 12, 13, 14, 15, 16, 17 },
        .job_id = .{ 20, 21, 22, 23, 24, 25, 26, 27 },
        .boundary_index = 0x1111_2222,
        .cycle = 0x3333_4444,
        .machine_words = &machine,
        .snapshot = .{ .id = .{ 30, 31, 32, 33, 34, 35, 36, 37 }, .count = 0x5555_6666, .root = 70 },
        .register_clocks = clocks,
        .memory_clock_id = .{ 40, 41, 42, 43, 44, 45, 46, 47 },
        .memory_clock_count = 0x7777_8888,
    };
    var expected: [wordCount(.entry_lineage)]u32 = undefined;
    const prefix = [_]u32{ 2, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 25, 26, 27, 0x2222, 0x1111, 0x4444, 0x3333 };
    @memcpy(expected[0..prefix.len], &prefix);
    for (0..machine.len) |index| expected[prefix.len + index] = @intCast(100 + index);
    const snapshot_at = prefix.len + machine.len;
    @memcpy(expected[snapshot_at..][0..11], &[_]u32{ 30, 31, 32, 33, 34, 35, 36, 37, 0x6666, 0x5555, 70 });
    for (0..32) |index| {
        expected[snapshot_at + 11 + 2 * index] = @intCast(index);
        expected[snapshot_at + 12 + 2 * index] = 0x1234;
    }
    @memcpy(expected[snapshot_at + 75 ..][0..10], &[_]u32{ 40, 41, 42, 43, 44, 45, 46, 47, 0x8888, 0x7777 });
    var words: [wordCount(.entry_lineage)]u32 = undefined;
    try write(.{ .entry_lineage = boundary }, &words);
    try std.testing.expectEqualSlices(u32, &expected, &words);
    try write(.{ .exit_lineage = boundary }, &words);
    try std.testing.expectEqualSlices(u32, &expected, &words);
    try std.testing.expectEqual(domain(.entry_lineage), domain(.exit_lineage));
    const expected_digest = contract.channel.hashCanonicalU32s(&expected, contract.BOUNDARY_LINEAGE_ID_DOMAIN);
    try std.testing.expectEqual(expected_digest, contract.deriveBoundaryLineageId(
        boundary.session_id,
        boundary.job_id,
        boundary.boundary_index,
        boundary.cycle,
        &machine,
        boundary.snapshot,
        clocks,
        boundary.memory_clock_id,
        boundary.memory_clock_count,
    ));
    const lineage = Lineage{
        .session_id = boundary.session_id,
        .job_id = boundary.job_id,
        .position_id = .{ 30, 31, 32, 33, 34, 35, 36, 37 },
        .entry_lineage_id = .{ 40, 41, 42, 43, 44, 45, 46, 47 },
        .exit_lineage_id = .{ 50, 51, 52, 53, 54, 55, 56, 57 },
        .base_statement_id = .{ 60, 61, 62, 63, 64, 65, 66, 67 },
    };
    var lineage_expected: [49]u32 = undefined;
    lineage_expected[0] = 2;
    for (0..6) |group| {
        for (0..8) |limb| lineage_expected[1 + group * 8 + limb] = @intCast(10 + group * 10 + limb);
    }
    var lineage_words: [wordCount(.lineage)]u32 = undefined;
    try write(.{ .lineage = lineage }, &lineage_words);
    try std.testing.expectEqualSlices(u32, &lineage_expected, &lineage_words);
    try std.testing.expectEqual(
        contract.channel.hashCanonicalU32s(&lineage_expected, contract.SEGMENT_LINEAGE_ID_DOMAIN),
        contract.deriveSegmentLineageId(lineage.session_id, lineage.job_id, lineage.position_id, lineage.entry_lineage_id, lineage.exit_lineage_id, lineage.base_statement_id),
    );
}
