//! Path-free, Zig-minted description of one fully cold-validated STWCIT04.
//!
//! This is controller metadata, not proof admission.  A description can only
//! be minted from the canonical STWCIR04 receipt which names the exact table
//! object.  The command owner performs the Store rehash and complete transitive
//! campaign validation before calling `mint`.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const receipt_mod =
    @import("recursive_pipeline_incremental_campaign_import_receipt_v4.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");

pub const FORMAT =
    "stwo.recursive-pipeline.incremental-campaign-cold-description.v4";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const MAX_CANONICAL_JSON_BYTE_COUNT: usize = 1024;

const validation_domain =
    "stwo-zig/recursive-pipeline-incremental-campaign-cold-validation/v4\x00";

pub const Error = error{
    IncrementalCampaignColdDescriptionCodecMismatchV4,
    InvalidIncrementalCampaignColdDescriptionV4,
};

pub const DescriptionV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    table_ref: artifact_store.BlobRefV1,
    authenticated_segment_count: u32,
    topology: table_mod.TopologyV4,
    import_receipt_identity_sha256: [32]u8,
    validation_receipt_identity_sha256: [32]u8,

    /// Called only after the exact table ref has been Store-opened and the
    /// complete table has passed `coldValidateCampaignTable`.
    pub fn mint(
        receipt: *const receipt_mod.ReceiptV4,
        authenticated_table_ref: artifact_store.BlobRefV1,
        authenticated_segment_count: u32,
    ) Error!DescriptionV4 {
        receipt.validate() catch
            return error.InvalidIncrementalCampaignColdDescriptionV4;
        if (!artifact_store.BlobRefV1.eql(
            receipt.table_ref,
            authenticated_table_ref,
        ) or receipt.segment_count != authenticated_segment_count) {
            return error.InvalidIncrementalCampaignColdDescriptionV4;
        }
        var result = DescriptionV4{
            .table_ref = authenticated_table_ref,
            .authenticated_segment_count = authenticated_segment_count,
            .topology = receipt.topology() catch
                return error.InvalidIncrementalCampaignColdDescriptionV4,
            .import_receipt_identity_sha256 = receipt.content_sha256,
            .validation_receipt_identity_sha256 = undefined,
        };
        result.validation_receipt_identity_sha256 = validationIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const DescriptionV4) Error!void {
        self.table_ref.validate() catch
            return error.InvalidIncrementalCampaignColdDescriptionV4;
        self.topology.validate() catch
            return error.InvalidIncrementalCampaignColdDescriptionV4;
        const expected_byte_count = std.math.cast(
            u64,
            table_mod.encodedByteCount(
                self.authenticated_segment_count,
            ) catch return error.InvalidIncrementalCampaignColdDescriptionV4,
        ) orelse return error.InvalidIncrementalCampaignColdDescriptionV4;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.table_ref.kind != table_mod.ARTIFACT_KIND or
            self.table_ref.format_version != 1 or
            self.table_ref.schema_version != table_mod.CAS_SCHEMA_VERSION or
            self.table_ref.byte_count != expected_byte_count or
            self.topology.leaf_count != self.authenticated_segment_count or
            artifact_store.encoding.isZeroDigest(
                self.import_receipt_identity_sha256,
            ) or
            !std.mem.eql(
                u8,
                &self.validation_receipt_identity_sha256,
                &validationIdentity(self),
            ))
        {
            return error.InvalidIncrementalCampaignColdDescriptionV4;
        }
    }
};

const JsonBlobRefV1 = struct {
    byte_count: u64,
    format_version: u16,
    kind: u32,
    schema_version: u16,
    sha256: []const u8,
};

const JsonTopologyV4 = struct {
    empty_leaf_count: u32,
    fold_count: u32,
    leaf_count: u32,
    padded_leaf_count: u32,
};

/// Fields are declared in lexical order so Zig's struct stringifier emits the
/// same compact canonical JSON order as the Python controller protocol.
const JsonDescriptionV4 = struct {
    authenticated_segment_count: u32,
    format: []const u8,
    import_receipt_identity_sha256: []const u8,
    schema_version: u16,
    table_ref: JsonBlobRefV1,
    topology: JsonTopologyV4,
    validation_receipt_identity_sha256: []const u8,
};

pub fn encodeCanonicalJsonAlloc(
    allocator: std.mem.Allocator,
    value: *const DescriptionV4,
) ![]u8 {
    try value.validate();
    const table_sha256 = std.fmt.bytesToHex(value.table_ref.sha256, .lower);
    const import_sha256 = std.fmt.bytesToHex(
        value.import_receipt_identity_sha256,
        .lower,
    );
    const validation_sha256 = std.fmt.bytesToHex(
        value.validation_receipt_identity_sha256,
        .lower,
    );
    const projection = JsonDescriptionV4{
        .authenticated_segment_count = value.authenticated_segment_count,
        .format = FORMAT,
        .import_receipt_identity_sha256 = &import_sha256,
        .schema_version = value.schema_version,
        .table_ref = .{
            .byte_count = value.table_ref.byte_count,
            .format_version = value.table_ref.format_version,
            .kind = @intFromEnum(value.table_ref.kind),
            .schema_version = value.table_ref.schema_version,
            .sha256 = &table_sha256,
        },
        .topology = .{
            .empty_leaf_count = value.topology.empty_leaf_count,
            .fold_count = value.topology.fold_count,
            .leaf_count = value.topology.leaf_count,
            .padded_leaf_count = value.topology.padded_leaf_count,
        },
        .validation_receipt_identity_sha256 = &validation_sha256,
    };
    const encoded = try std.json.Stringify.valueAlloc(
        allocator,
        projection,
        .{},
    );
    errdefer allocator.free(encoded);
    if (encoded.len + 1 > MAX_CANONICAL_JSON_BYTE_COUNT)
        return error.IncrementalCampaignColdDescriptionCodecMismatchV4;
    const canonical = try allocator.realloc(encoded, encoded.len + 1);
    canonical[canonical.len - 1] = '\n';
    return canonical;
}

pub fn decodeCanonicalJson(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !DescriptionV4 {
    if (bytes.len == 0 or bytes.len > MAX_CANONICAL_JSON_BYTE_COUNT or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.IncrementalCampaignColdDescriptionCodecMismatchV4;
    }
    var parsed = std.json.parseFromSlice(
        JsonDescriptionV4,
        allocator,
        bytes,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = false },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.IncrementalCampaignColdDescriptionCodecMismatchV4,
    };
    defer parsed.deinit();
    const canonical_without_lf = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical_without_lf);
    if (canonical_without_lf.len + 1 != bytes.len or
        !std.mem.eql(
            u8,
            canonical_without_lf,
            bytes[0..canonical_without_lf.len],
        ))
    {
        return error.IncrementalCampaignColdDescriptionCodecMismatchV4;
    }
    if (!std.mem.eql(u8, parsed.value.format, FORMAT))
        return error.InvalidIncrementalCampaignColdDescriptionV4;
    const result = DescriptionV4{
        .format_version = FORMAT_VERSION,
        .schema_version = parsed.value.schema_version,
        .table_ref = .{
            .kind = @enumFromInt(parsed.value.table_ref.kind),
            .format_version = parsed.value.table_ref.format_version,
            .schema_version = parsed.value.table_ref.schema_version,
            .byte_count = parsed.value.table_ref.byte_count,
            .sha256 = try decodeDigest(parsed.value.table_ref.sha256),
        },
        .authenticated_segment_count = parsed.value.authenticated_segment_count,
        .topology = .{
            .leaf_count = parsed.value.topology.leaf_count,
            .padded_leaf_count = parsed.value.topology.padded_leaf_count,
            .empty_leaf_count = parsed.value.topology.empty_leaf_count,
            .fold_count = parsed.value.topology.fold_count,
        },
        .import_receipt_identity_sha256 = try decodeDigest(
            parsed.value.import_receipt_identity_sha256,
        ),
        .validation_receipt_identity_sha256 = try decodeDigest(
            parsed.value.validation_receipt_identity_sha256,
        ),
    };
    try result.validate();
    return result;
}

fn validationIdentity(value: *const DescriptionV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(validation_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    const table_ref_bytes = value.table_ref.canonicalBytes() catch unreachable;
    hash.update(&table_ref_bytes);
    hashInt(&hash, u32, value.authenticated_segment_count);
    hashInt(&hash, u32, value.topology.leaf_count);
    hashInt(&hash, u32, value.topology.padded_leaf_count);
    hashInt(&hash, u32, value.topology.empty_leaf_count);
    hashInt(&hash, u32, value.topology.fold_count);
    hash.update(&value.import_receipt_identity_sha256);
    return hash.finalResult();
}

fn decodeDigest(encoded: []const u8) Error![32]u8 {
    if (encoded.len != 64) return error.IncrementalCampaignColdDescriptionCodecMismatchV4;
    for (encoded) |byte| if (!std.ascii.isDigit(byte) and
        (byte < 'a' or byte > 'f'))
    {
        return error.IncrementalCampaignColdDescriptionCodecMismatchV4;
    };
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.IncrementalCampaignColdDescriptionCodecMismatchV4;
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
