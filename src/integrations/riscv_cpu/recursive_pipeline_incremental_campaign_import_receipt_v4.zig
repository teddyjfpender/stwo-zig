//! Canonical controller handoff for a sealed V4 campaign CAS import.
//!
//! The receipt contains only the Zig Store's typed STWCIT04 `BlobRefV1`.
//! Filesystem paths, timings, and live capabilities never enter these bytes.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const table = @import("recursive_pipeline_incremental_campaign_table_v4.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'C', 'I', 'R', '0', '4' };
pub const ENCODED_BYTE_COUNT: usize = MAGIC.len + 2 * @sizeOf(u16) +
    2 * @sizeOf(u32) + artifact_store.BlobRefV1.canonical_size + 32;

const identity_domain =
    "stwo-zig/recursive-pipeline-incremental-campaign-import-receipt/v4\x00";

pub const Error = error{
    IncrementalCampaignImportReceiptCodecMismatchV4,
    InvalidIncrementalCampaignImportReceiptV4,
};

pub const ReceiptV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    segment_count: u32,
    table_ref: artifact_store.BlobRefV1,
    content_sha256: [32]u8,

    pub fn seal(value: ReceiptV4) Error!ReceiptV4 {
        var result = value;
        result.content_sha256 = contentIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const ReceiptV4) Error!void {
        self.table_ref.validate() catch
            return error.InvalidIncrementalCampaignImportReceiptV4;
        _ = table.TopologyV4.derive(self.segment_count) catch
            return error.InvalidIncrementalCampaignImportReceiptV4;
        const expected_byte_count = std.math.cast(
            u64,
            table.encodedByteCount(self.segment_count) catch
                return error.InvalidIncrementalCampaignImportReceiptV4,
        ) orelse return error.InvalidIncrementalCampaignImportReceiptV4;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.table_ref.kind != table.ARTIFACT_KIND or
            self.table_ref.format_version != 1 or
            self.table_ref.schema_version != table.CAS_SCHEMA_VERSION or
            self.table_ref.byte_count != expected_byte_count or
            !std.mem.eql(
                u8,
                &self.content_sha256,
                &contentIdentity(self),
            )) return error.InvalidIncrementalCampaignImportReceiptV4;
    }

    pub fn topology(self: *const ReceiptV4) Error!table.TopologyV4 {
        try self.validate();
        return table.TopologyV4.derive(self.segment_count) catch
            return error.InvalidIncrementalCampaignImportReceiptV4;
    }
};

pub fn encode(value: *const ReceiptV4) Error![ENCODED_BYTE_COUNT]u8 {
    try value.validate();
    var bytes: [ENCODED_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    writer.raw(&MAGIC);
    writer.int(u16, value.format_version);
    writer.int(u16, value.schema_version);
    writer.int(u32, 0);
    writer.int(u32, value.segment_count);
    writer.blob(value.table_ref);
    writer.raw(&value.content_sha256);
    if (writer.failed or writer.at != bytes.len)
        return error.IncrementalCampaignImportReceiptCodecMismatchV4;
    return bytes;
}

pub fn decode(bytes: []const u8) Error!ReceiptV4 {
    if (bytes.len != ENCODED_BYTE_COUNT)
        return error.IncrementalCampaignImportReceiptCodecMismatchV4;
    var reader = Reader{ .bytes = bytes };
    if (!std.mem.eql(u8, reader.take(MAGIC.len), &MAGIC))
        return error.IncrementalCampaignImportReceiptCodecMismatchV4;
    const result = ReceiptV4{
        .format_version = reader.int(u16),
        .schema_version = reader.int(u16),
        .segment_count = blk: {
            if (reader.int(u32) != 0)
                return error.IncrementalCampaignImportReceiptCodecMismatchV4;
            break :blk reader.int(u32);
        },
        .table_ref = reader.blob(),
        .content_sha256 = reader.array(32),
    };
    if (reader.failed or reader.at != bytes.len)
        return error.IncrementalCampaignImportReceiptCodecMismatchV4;
    try result.validate();
    const canonical = try encode(&result);
    if (!std.mem.eql(u8, bytes, &canonical))
        return error.IncrementalCampaignImportReceiptCodecMismatchV4;
    return result;
}

fn contentIdentity(value: *const ReceiptV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.segment_count);
    hashBlob(&hash, value.table_ref);
    return hash.finalResult();
}

fn hashBlob(
    hash: *std.crypto.hash.sha2.Sha256,
    value: artifact_store.BlobRefV1,
) void {
    hashInt(hash, u32, @intFromEnum(value.kind));
    hashInt(hash, u16, value.format_version);
    hashInt(hash, u16, value.schema_version);
    hashInt(hash, u64, value.byte_count);
    hash.update(&value.sha256);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,
    failed: bool = false,

    fn raw(self: *Writer, value: []const u8) void {
        const end = std.math.add(usize, self.at, value.len) catch {
            self.failed = true;
            return;
        };
        if (end > self.bytes.len) {
            self.failed = true;
            return;
        }
        @memcpy(self.bytes[self.at..end], value);
        self.at = end;
    }

    fn int(self: *Writer, comptime T: type, value: T) void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .little);
        self.raw(&encoded);
    }

    fn blob(self: *Writer, value: artifact_store.BlobRefV1) void {
        const encoded = value.canonicalBytes() catch {
            self.failed = true;
            return;
        };
        self.raw(&encoded);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    failed: bool = false,

    fn take(self: *Reader, count: usize) []const u8 {
        const end = std.math.add(usize, self.at, count) catch {
            self.failed = true;
            return &.{};
        };
        if (end > self.bytes.len) {
            self.failed = true;
            return &.{};
        }
        defer self.at = end;
        return self.bytes[self.at..end];
    }

    fn int(self: *Reader, comptime T: type) T {
        const bytes = self.take(@sizeOf(T));
        if (bytes.len != @sizeOf(T)) return 0;
        const fixed: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
        return std.mem.readInt(T, fixed, .little);
    }

    fn array(self: *Reader, comptime count: usize) [count]u8 {
        var result = [_]u8{0} ** count;
        const bytes = self.take(count);
        if (bytes.len == count) @memcpy(&result, bytes);
        return result;
    }

    fn blob(self: *Reader) artifact_store.BlobRefV1 {
        return artifact_store.BlobRefV1.decodeCanonical(
            self.take(artifact_store.BlobRefV1.canonical_size),
        ) catch {
            self.failed = true;
            return .{
                .kind = @enumFromInt(0),
                .schema_version = 0,
                .byte_count = 0,
                .sha256 = [_]u8{0} ** 32,
            };
        };
    }
};
