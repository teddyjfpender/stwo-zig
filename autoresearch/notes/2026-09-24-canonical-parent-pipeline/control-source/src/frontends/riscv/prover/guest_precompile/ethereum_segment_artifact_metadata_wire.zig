//! Fixed-width codec for the authenticated global-position V3 sidecar.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const segment_v2 = @import("../../recursion/segment_statement_v2.zig");
const span = @import("../../recursion/span_statement.zig");
const runner_result = @import("../../runner/result.zig");
const base_wire = @import("proof_artifact_wire.zig");

pub const schema_version: u16 = 1;
pub const encoded_size: usize = 2111;
pub const clock_frame_offset: usize = 4 * @sizeOf(u16);

pub fn encode(writer: anytype, value: *const global_v3.MetadataV3) !void {
    try value.validate();
    try base_wire.writeInt(writer, u16, schema_version);
    try base_wire.writeInt(writer, u16, value.format_version);
    try base_wire.writeInt(writer, u16, value.schema_version);
    try base_wire.writeInt(writer, u16, value.flags);
    try base_wire.writeInt(writer, u16, @intFromEnum(value.clock_frame));
    try writeM31s(writer, &value.base_statement_words);
    try base_wire.writeInt(writer, u32, value.segment_index);
    try base_wire.writeInt(writer, u32, value.segment_count);
    try base_wire.writeInt(writer, u64, value.global_cycle_start);
    try base_wire.writeInt(writer, u64, value.global_cycle_end);
    try base_wire.writeInt(writer, u32, value.local_cycle_count);
    try encodeBoundary(writer, value.entry);
    try encodeBoundary(writer, value.exit);
    if (value.completion) |completion| {
        try writer.writeByte(1);
        try base_wire.writeInt(writer, u32, @intFromEnum(completion.kind));
        try base_wire.writeInt(writer, u32, completion.address);
        try base_wire.writeInt(writer, u32, completion.value);
        try base_wire.writeInt(writer, u32, completion.clock);
    } else {
        try writer.writeByte(0);
        inline for (0..4) |_| try base_wire.writeInt(writer, u32, 0);
    }
}

pub fn decode(bytes: []const u8) !global_v3.MetadataV3 {
    if (bytes.len != encoded_size) return error.InvalidMetadataLength;
    var cursor = base_wire.Cursor.init(bytes);
    if (try cursor.readInt(u16) != schema_version)
        return error.UnsupportedMetadataVersion;
    var result: global_v3.MetadataV3 = undefined;
    result.format_version = try cursor.readInt(u16);
    result.schema_version = try cursor.readInt(u16);
    result.flags = try cursor.readInt(u16);
    result.clock_frame = try knownClockFrame(try cursor.readInt(u16));
    try readM31s(&cursor, &result.base_statement_words);
    result.segment_index = try cursor.readInt(u32);
    result.segment_count = try cursor.readInt(u32);
    result.global_cycle_start = try cursor.readInt(u64);
    result.global_cycle_end = try cursor.readInt(u64);
    result.local_cycle_count = try cursor.readInt(u32);
    result.entry = try decodeBoundary(&cursor);
    result.exit = try decodeBoundary(&cursor);
    const completion_tag = try cursor.readByte();
    const completion_kind = try cursor.readInt(u32);
    const completion_address = try cursor.readInt(u32);
    const completion_value = try cursor.readInt(u32);
    const completion_clock = try cursor.readInt(u32);
    result.completion = switch (completion_tag) {
        0 => blk: {
            if (completion_kind != 0 or completion_address != 0 or
                completion_value != 0 or completion_clock != 0)
            {
                return error.NonCanonicalAbsentCompletion;
            }
            break :blk null;
        },
        1 => .{
            .kind = try knownCompletionKind(completion_kind),
            .address = completion_address,
            .value = completion_value,
            .clock = completion_clock,
        },
        else => return error.InvalidOptionTag,
    };
    try cursor.requireDone();
    try result.validate();
    _ = try result.identity();
    return result;
}

fn encodeBoundary(writer: anytype, value: global_v3.BoundaryV3) !void {
    try writeDigest(writer, value.snapshot_id);
    try base_wire.writeInt(writer, u32, value.snapshot_count);
    try base_wire.writeInt(writer, u32, value.continuation_root);
    for (value.register_clocks) |clock|
        try base_wire.writeInt(writer, u32, clock);
    try writeDigest(writer, value.memory_clock_id);
    try base_wire.writeInt(writer, u32, value.memory_clock_count);
}

fn decodeBoundary(cursor: *base_wire.Cursor) !global_v3.BoundaryV3 {
    var result: global_v3.BoundaryV3 = undefined;
    try readDigest(cursor, &result.snapshot_id);
    result.snapshot_count = try cursor.readInt(u32);
    result.continuation_root = try cursor.readInt(u32);
    for (&result.register_clocks) |*clock|
        clock.* = try cursor.readInt(u32);
    try readDigest(cursor, &result.memory_clock_id);
    result.memory_clock_count = try cursor.readInt(u32);
    return result;
}

fn writeDigest(writer: anytype, digest: segment_v2.Digest) !void {
    for (digest) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalDigest;
        try base_wire.writeInt(writer, u32, word);
    }
}

fn readDigest(cursor: *base_wire.Cursor, digest: *segment_v2.Digest) !void {
    for (digest) |*word| {
        word.* = try cursor.readInt(u32);
        if (word.* >= m31.Modulus) return error.NonCanonicalDigest;
    }
}

fn writeM31s(writer: anytype, words: []const M31) !void {
    for (words) |word| try base_wire.writeInt(writer, u32, word.toU32());
}

fn readM31s(cursor: *base_wire.Cursor, words: []M31) !void {
    for (words) |*word| {
        const raw = try cursor.readInt(u32);
        if (raw >= m31.Modulus) return error.NonCanonicalM31;
        word.* = M31.fromCanonical(raw);
    }
}

fn knownCompletionKind(raw: u32) !segment_v2.CompletionKindV2 {
    inline for (std.meta.fields(segment_v2.CompletionKindV2)) |field| {
        if (raw == field.value) return @enumFromInt(raw);
    }
    return error.InvalidEnumTag;
}

fn knownClockFrame(raw: u16) !runner_result.SegmentClockFrame {
    inline for (std.meta.fields(runner_result.SegmentClockFrame)) |field| {
        if (raw == field.value) return @enumFromInt(@as(u8, @intCast(raw)));
    }
    return error.InvalidEnumTag;
}

comptime {
    const boundary_size = 2 * 8 * @sizeOf(u32) +
        3 * @sizeOf(u32) + 32 * @sizeOf(u32);
    const calculated = 5 * @sizeOf(u16) +
        span.SPAN_STATEMENT_CANONICAL_WORDS * @sizeOf(u32) +
        3 * @sizeOf(u32) + 2 * @sizeOf(u64) +
        2 * boundary_size + 1 + 4 * @sizeOf(u32);
    if (calculated != encoded_size or clock_frame_offset != 8)
        @compileError("Ethereum segment metadata wire size drifted");
}
