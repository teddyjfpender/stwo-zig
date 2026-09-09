//! Canonical transport for the complete leaf-local MetadataV3 sidecar.
//!
//! Kept separate from `SpanStatement`: the latter is the frozen 412-word
//! execution statement and intentionally omits sparse-boundary/clock custody.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const recursion = frontend.recursion;
const global_v3 = recursion.segment_leaf_local_authority_v3;
const segment_v2 = recursion.segment_statement_v2;
const span = recursion.span_statement;
const M31 = core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ENCODED_BYTE_COUNT: usize = 2112;
const IDENTITY_DOMAIN =
    "stwo-zig/typed-air/recursive-node-public-metadata/v2\x00";

pub fn encode(
    metadata: *const global_v3.MetadataV3,
) ![ENCODED_BYTE_COUNT]u8 {
    try metadata.validate();
    var result: [ENCODED_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &result };
    writer.u16Value(metadata.format_version);
    writer.u16Value(metadata.schema_version);
    writer.u16Value(metadata.flags);
    writer.u8Value(@intFromEnum(metadata.clock_frame));
    writer.u8Value(0);
    for (metadata.base_statement_words) |word| writer.u32Value(word.toU32());
    writer.u32Value(metadata.segment_index);
    writer.u32Value(metadata.segment_count);
    writer.u64Value(metadata.global_cycle_start);
    writer.u64Value(metadata.global_cycle_end);
    writer.u32Value(metadata.local_cycle_count);
    writeBoundary(&writer, metadata.entry);
    writeBoundary(&writer, metadata.exit);
    if (metadata.completion) |completion| {
        writer.u8Value(1);
        writer.bytesValue(&.{ 0, 0, 0 });
        writer.u32Value(@intFromEnum(completion.kind));
        writer.u32Value(completion.address);
        writer.u32Value(completion.value);
        writer.u32Value(completion.clock);
    } else {
        writer.u8Value(0);
        writer.bytesValue(&.{ 0, 0, 0 });
        writer.u32Value(0);
        writer.u32Value(0);
        writer.u32Value(0);
        writer.u32Value(0);
    }
    std.debug.assert(writer.at == result.len);
    return result;
}

pub fn decode(bytes: []const u8) !global_v3.MetadataV3 {
    if (bytes.len != ENCODED_BYTE_COUNT)
        return error.InvalidNodePublicMetadata;
    var reader = Reader{ .bytes = bytes };
    const format_version = reader.u16Value();
    const schema_version = reader.u16Value();
    const flags = reader.u16Value();
    const clock_frame = std.meta.intToEnum(
        @TypeOf(@as(global_v3.MetadataV3, undefined).clock_frame),
        reader.u8Value(),
    ) catch return error.InvalidNodePublicMetadata;
    if (reader.u8Value() != 0) return error.InvalidNodePublicMetadata;
    var statement_words: span.StatementWords = undefined;
    for (&statement_words) |*word| word.* = try reader.m31Value();
    const segment_index = reader.u32Value();
    const segment_count = reader.u32Value();
    const global_cycle_start = reader.u64Value();
    const global_cycle_end = reader.u64Value();
    const local_cycle_count = reader.u32Value();
    const entry = try readBoundary(&reader);
    const exit = try readBoundary(&reader);
    const completion_present = reader.u8Value();
    if (!std.mem.allEqual(u8, reader.take(3), 0) or completion_present > 1)
        return error.InvalidNodePublicMetadata;
    const completion_kind = reader.u32Value();
    const completion_address = reader.u32Value();
    const completion_value = reader.u32Value();
    const completion_clock = reader.u32Value();
    const completion: ?segment_v2.CompletionV2 = if (completion_present == 1)
        .{
            .kind = std.meta.intToEnum(
                segment_v2.CompletionKindV2,
                completion_kind,
            ) catch return error.InvalidNodePublicMetadata,
            .address = completion_address,
            .value = completion_value,
            .clock = completion_clock,
        }
    else blk: {
        if (completion_kind != 0 or completion_address != 0 or
            completion_value != 0 or completion_clock != 0)
        {
            return error.InvalidNodePublicMetadata;
        }
        break :blk null;
    };
    const result = global_v3.MetadataV3{
        .format_version = format_version,
        .schema_version = schema_version,
        .flags = flags,
        .clock_frame = clock_frame,
        .base_statement_words = statement_words,
        .segment_index = segment_index,
        .segment_count = segment_count,
        .global_cycle_start = global_cycle_start,
        .global_cycle_end = global_cycle_end,
        .local_cycle_count = local_cycle_count,
        .entry = entry,
        .exit = exit,
        .completion = completion,
    };
    try result.validate();
    if (reader.at != bytes.len) return error.InvalidNodePublicMetadata;
    const canonical = try encode(&result);
    if (!std.mem.eql(u8, bytes, &canonical))
        return error.InvalidNodePublicMetadata;
    return result;
}

pub fn identitySha256(
    metadata: *const global_v3.MetadataV3,
) ![32]u8 {
    const bytes = try encode(metadata);
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hash.update(&bytes);
    return hash.finalResult();
}

fn writeBoundary(writer: *Writer, boundary: global_v3.BoundaryV3) void {
    writer.digest(boundary.snapshot_id);
    writer.u32Value(boundary.snapshot_count);
    writer.u32Value(boundary.continuation_root);
    for (boundary.register_clocks) |clock| writer.u32Value(clock);
    writer.digest(boundary.memory_clock_id);
    writer.u32Value(boundary.memory_clock_count);
}

fn readBoundary(reader: *Reader) !global_v3.BoundaryV3 {
    var result = global_v3.BoundaryV3{
        .snapshot_id = reader.digest(),
        .snapshot_count = reader.u32Value(),
        .continuation_root = reader.u32Value(),
        .register_clocks = undefined,
        .memory_clock_id = undefined,
        .memory_clock_count = undefined,
    };
    for (&result.register_clocks) |*clock| clock.* = reader.u32Value();
    result.memory_clock_id = reader.digest();
    result.memory_clock_count = reader.u32Value();
    return result;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
    fn u64Value(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.at..][0..8], value, .little);
        self.at += 8;
    }
    fn digest(self: *Writer, value: recursion.poseidon2_channel.Digest) void {
        for (value) |word| self.u32Value(word);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) []const u8 {
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }
    fn u8Value(self: *Reader) u8 {
        return self.take(1)[0];
    }
    fn u16Value(self: *Reader) u16 {
        return std.mem.readInt(u16, self.take(2)[0..2], .little);
    }
    fn u32Value(self: *Reader) u32 {
        return std.mem.readInt(u32, self.take(4)[0..4], .little);
    }
    fn u64Value(self: *Reader) u64 {
        return std.mem.readInt(u64, self.take(8)[0..8], .little);
    }
    fn m31Value(self: *Reader) !M31 {
        const value = self.u32Value();
        if (value >= core.fields.m31.Modulus)
            return error.InvalidNodePublicMetadata;
        return M31.fromCanonical(value);
    }
    fn digest(self: *Reader) recursion.poseidon2_channel.Digest {
        var result: recursion.poseidon2_channel.Digest = undefined;
        for (&result) |*word| word.* = self.u32Value();
        return result;
    }
};

comptime {
    if (ENCODED_BYTE_COUNT != 2112)
        @compileError("node-public MetadataV3 transport geometry drifted");
}
