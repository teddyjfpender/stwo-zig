//! Canonical path-free Stage101 planner projection for one validated STWCIT04.
//!
//! This is non-admitting controller metadata. Each row repeats the exact
//! recipe/input refs from the table and carries a Zig-recomputed semantic
//! projection. Proof and live verifier capabilities remain outside this wire.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const custody_mod =
    @import("recursive_pipeline_incremental_campaign_cold_description_v4.zig");
const namespace_mod =
    @import("recursive_pipeline_campaign_namespace_v1.zig");
const recipe_mod =
    @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

pub const FORMAT =
    "stwo.recursive-pipeline.incremental-campaign-worker-description.v4";
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 4;
pub const MAX_ROW_CANONICAL_JSON_BYTE_COUNT: usize = 4096;
pub const FIXED_CANONICAL_JSON_BYTE_COUNT: usize = 4096;
const max_segment_count_usize = std.math.cast(
    usize,
    table_mod.MAX_SEGMENT_COUNT,
) orelse @compileError("campaign segment maximum does not fit usize");
pub const MAX_CANONICAL_JSON_BYTE_COUNT: usize = max: {
    const rows = std.math.mul(
        usize,
        max_segment_count_usize,
        MAX_ROW_CANONICAL_JSON_BYTE_COUNT,
    ) catch @compileError("campaign worker-description size overflow");
    break :max std.math.add(
        usize,
        FIXED_CANONICAL_JSON_BYTE_COUNT,
        rows,
    ) catch @compileError("campaign worker-description size overflow");
};

const validation_domain =
    "stwo-zig/recursive-pipeline-incremental-campaign-worker-validation/v4\x00";

pub const Error = error{
    IncrementalCampaignWorkerDescriptionCodecMismatchV4,
    InvalidIncrementalCampaignWorkerDescriptionV4,
};

pub const RowV4 = struct {
    segment_index: u32,
    recipe_ref: artifact_store.BlobRefV1,
    stage_inputs: [table_mod.STAGE_INPUT_COUNT]artifact_store.InputRefV1,
    campaign_namespace_sha256: artifact_store.Digest,
    local_task_identity_sha256: artifact_store.Digest,
    semantic_authorities: protocol.SemanticAuthorities,
};

pub const DescriptionV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    campaign_namespace_sha256: artifact_store.Digest,
    custody: custody_mod.DescriptionV4,
    rows: []const RowV4,
    validation_receipt_identity_sha256: artifact_store.Digest,

    pub fn validate(self: *const DescriptionV4) Error!void {
        self.custody.validate() catch
            return error.InvalidIncrementalCampaignWorkerDescriptionV4;
        const count = std.math.cast(
            usize,
            self.custody.authenticated_segment_count,
        ) orelse return error.InvalidIncrementalCampaignWorkerDescriptionV4;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.rows.len != count or
            artifact_store.encoding.isZeroDigest(
                self.campaign_namespace_sha256,
            ))
        {
            return error.InvalidIncrementalCampaignWorkerDescriptionV4;
        }
        for (self.rows, 0..) |row, ordinal| {
            row.recipe_ref.validate() catch
                return error.InvalidIncrementalCampaignWorkerDescriptionV4;
            for (row.stage_inputs) |input| input.validate() catch
                return error.InvalidIncrementalCampaignWorkerDescriptionV4;
            if (row.segment_index != @as(u32, @intCast(ordinal)) or
                row.recipe_ref.kind != .capture_transport or
                row.recipe_ref.format_version !=
                    artifact_store.types.format_version_v1 or
                row.recipe_ref.schema_version != recipe_mod.SCHEMA_VERSION or
                row.recipe_ref.byte_count != recipe_mod.ENCODED_BYTE_COUNT or
                !artifact_store.BlobRefV1.eql(
                    row.recipe_ref,
                    row.stage_inputs[2].blob,
                ))
            {
                return error.InvalidIncrementalCampaignWorkerDescriptionV4;
            }
            const expected = worker.semanticProjection(
                row.segment_index,
                self.custody.authenticated_segment_count,
                &row.stage_inputs,
                self.campaign_namespace_sha256,
            ) catch return error.InvalidIncrementalCampaignWorkerDescriptionV4;
            if (!std.mem.eql(
                u8,
                &row.campaign_namespace_sha256,
                &self.campaign_namespace_sha256,
            ) or !std.mem.eql(
                u8,
                &row.local_task_identity_sha256,
                &expected.local_task_identity_sha256,
            ) or !std.meta.eql(
                row.semantic_authorities,
                expected.authorities,
            )) return error.InvalidIncrementalCampaignWorkerDescriptionV4;
        }
        if (!std.mem.eql(
            u8,
            &self.validation_receipt_identity_sha256,
            &validationIdentity(self),
        )) return error.InvalidIncrementalCampaignWorkerDescriptionV4;
    }

    pub fn validateAgainstTable(
        self: *const DescriptionV4,
        allocator: std.mem.Allocator,
        table: *const table_mod.CampaignTableV4,
    ) !void {
        try self.validate();
        table.validate() catch
            return error.InvalidIncrementalCampaignWorkerDescriptionV4;
        const canonical = try table_mod.encodeAlloc(allocator, table);
        defer allocator.free(canonical);
        const canonical_digest = artifact_store.digestBytes(canonical);
        const expected_namespace = namespace_mod.fromValidatedTable(table) catch
            return error.InvalidIncrementalCampaignWorkerDescriptionV4;
        if (table.segment_count !=
            self.custody.authenticated_segment_count or
            table.records.len != self.rows.len or
            self.custody.table_ref.byte_count != canonical.len or
            !std.mem.eql(
                u8,
                &self.custody.table_ref.sha256,
                &canonical_digest,
            ) or !std.mem.eql(
            u8,
            &self.campaign_namespace_sha256,
            &expected_namespace,
        )) {
            return error.InvalidIncrementalCampaignWorkerDescriptionV4;
        }
        for (self.rows, table.records) |row, record| {
            if (row.segment_index != record.segment_index or
                !artifact_store.BlobRefV1.eql(row.recipe_ref, record.recipe) or
                !std.meta.eql(row.stage_inputs, record.stage_inputs))
            {
                return error.InvalidIncrementalCampaignWorkerDescriptionV4;
            }
        }
    }
};

pub const OwnedDescriptionV4 = struct {
    allocator: std.mem.Allocator,
    value: DescriptionV4,

    pub fn deinit(self: *OwnedDescriptionV4) void {
        self.allocator.free(self.value.rows);
        self.* = undefined;
    }
};

pub fn mintAlloc(
    allocator: std.mem.Allocator,
    custody: custody_mod.DescriptionV4,
    table: *const table_mod.CampaignTableV4,
) !OwnedDescriptionV4 {
    try custody.validate();
    try table.validate();
    if (table.segment_count != custody.authenticated_segment_count)
        return error.InvalidIncrementalCampaignWorkerDescriptionV4;
    const campaign_namespace_sha256 =
        try namespace_mod.fromValidatedTable(table);
    const rows = try allocator.alloc(RowV4, table.records.len);
    errdefer allocator.free(rows);
    for (table.records, rows) |record, *row| {
        const semantic = try worker.semanticProjection(
            record.segment_index,
            table.segment_count,
            &record.stage_inputs,
            campaign_namespace_sha256,
        );
        row.* = .{
            .segment_index = record.segment_index,
            .recipe_ref = record.recipe,
            .stage_inputs = record.stage_inputs,
            .campaign_namespace_sha256 = campaign_namespace_sha256,
            .local_task_identity_sha256 = semantic.local_task_identity_sha256,
            .semantic_authorities = semantic.authorities,
        };
    }
    var result = OwnedDescriptionV4{
        .allocator = allocator,
        .value = .{
            .campaign_namespace_sha256 = campaign_namespace_sha256,
            .custody = custody,
            .rows = rows,
            .validation_receipt_identity_sha256 = undefined,
        },
    };
    result.value.validation_receipt_identity_sha256 =
        validationIdentity(&result.value);
    try result.value.validateAgainstTable(allocator, table);
    return result;
}

pub fn encodeCanonicalJsonAlloc(
    allocator: std.mem.Allocator,
    value: *const DescriptionV4,
) ![]u8 {
    try value.validate();
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const writer = output.writer(allocator);
    try writer.print(
        "{{\"authenticated_segment_count\":{}," ++
            "\"campaign_namespace_sha256\":",
        .{value.custody.authenticated_segment_count},
    );
    try writeDigest(writer, value.campaign_namespace_sha256);
    try writer.writeAll(",\"custody_validation_receipt_identity_sha256\":");
    try writeDigest(
        writer,
        value.custody.validation_receipt_identity_sha256,
    );
    try writer.writeAll(",\"format\":");
    try writeString(writer, FORMAT);
    try writer.writeAll(",\"import_receipt_identity_sha256\":");
    try writeDigest(writer, value.custody.import_receipt_identity_sha256);
    try writer.writeAll(",\"rows\":[");
    for (value.rows, 0..) |row, ordinal| {
        if (ordinal != 0) try writer.writeByte(',');
        try writeRow(writer, row);
    }
    try writer.print(
        "],\"schema_version\":{},\"table_ref\":",
        .{value.schema_version},
    );
    try writeBlobRef(writer, value.custody.table_ref);
    try writer.print(
        ",\"topology\":{{\"empty_leaf_count\":{}," ++
            "\"fold_count\":{},\"leaf_count\":{}," ++
            "\"padded_leaf_count\":{}}}," ++
            "\"validation_receipt_identity_sha256\":",
        .{
            value.custody.topology.empty_leaf_count,
            value.custody.topology.fold_count,
            value.custody.topology.leaf_count,
            value.custody.topology.padded_leaf_count,
        },
    );
    try writeDigest(writer, value.validation_receipt_identity_sha256);
    try writer.writeAll("}\n");
    if (output.items.len > MAX_CANONICAL_JSON_BYTE_COUNT)
        return error.IncrementalCampaignWorkerDescriptionCodecMismatchV4;
    return output.toOwnedSlice(allocator);
}

const JsonBlobRefV1 = struct {
    byte_count: u64,
    format_version: u16,
    kind: u32,
    schema_version: u16,
    sha256: []const u8,
};

const JsonInputRefV1 = struct {
    blob: JsonBlobRefV1,
    ordinal: u32,
    role: u32,
};

const JsonAuthoritiesV4 = struct {
    layout_identity_sha256: []const u8,
    pcs_identity_sha256: []const u8,
    profile_identity_sha256: []const u8,
    program_identity_sha256: []const u8,
    protocol_identity_sha256: []const u8,
    provider_identity_sha256: []const u8,
    registry_identity_sha256: []const u8,
    security_identity_sha256: []const u8,
    statement_identity_sha256: []const u8,
};

const JsonRowV4 = struct {
    campaign_namespace_sha256: []const u8,
    local_task_identity_sha256: []const u8,
    recipe_ref: JsonBlobRefV1,
    segment_index: u32,
    semantic_authorities: JsonAuthoritiesV4,
    stage_inputs: [table_mod.STAGE_INPUT_COUNT]JsonInputRefV1,
};

const JsonTopologyV4 = struct {
    empty_leaf_count: u32,
    fold_count: u32,
    leaf_count: u32,
    padded_leaf_count: u32,
};

const JsonDescriptionV4 = struct {
    authenticated_segment_count: u32,
    campaign_namespace_sha256: []const u8,
    custody_validation_receipt_identity_sha256: []const u8,
    format: []const u8,
    import_receipt_identity_sha256: []const u8,
    rows: []const JsonRowV4,
    schema_version: u16,
    table_ref: JsonBlobRefV1,
    topology: JsonTopologyV4,
    validation_receipt_identity_sha256: []const u8,
};

pub fn decodeCanonicalJsonAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedDescriptionV4 {
    if (bytes.len == 0 or bytes.len > MAX_CANONICAL_JSON_BYTE_COUNT or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.IncrementalCampaignWorkerDescriptionCodecMismatchV4;
    }
    var parsed = std.json.parseFromSlice(
        JsonDescriptionV4,
        allocator,
        bytes,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = false },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.IncrementalCampaignWorkerDescriptionCodecMismatchV4,
    };
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.format, FORMAT) or
        parsed.value.rows.len > max_segment_count_usize)
    {
        return error.InvalidIncrementalCampaignWorkerDescriptionV4;
    }
    const rows = try allocator.alloc(RowV4, parsed.value.rows.len);
    errdefer allocator.free(rows);
    for (parsed.value.rows, rows) |source, *destination| {
        var stage_inputs: [table_mod.STAGE_INPUT_COUNT]artifact_store.InputRefV1 =
            undefined;
        for (source.stage_inputs, &stage_inputs) |input, *decoded|
            decoded.* = try decodeInputRef(input);
        destination.* = .{
            .segment_index = source.segment_index,
            .recipe_ref = try decodeBlobRef(source.recipe_ref),
            .stage_inputs = stage_inputs,
            .campaign_namespace_sha256 = try decodeDigest(
                source.campaign_namespace_sha256,
            ),
            .local_task_identity_sha256 = try decodeDigest(
                source.local_task_identity_sha256,
            ),
            .semantic_authorities = try decodeAuthorities(
                source.semantic_authorities,
            ),
        };
    }
    const result = OwnedDescriptionV4{
        .allocator = allocator,
        .value = .{
            .format_version = FORMAT_VERSION,
            .schema_version = parsed.value.schema_version,
            .campaign_namespace_sha256 = try decodeDigest(
                parsed.value.campaign_namespace_sha256,
            ),
            .custody = .{
                .table_ref = try decodeBlobRef(parsed.value.table_ref),
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
                    parsed.value
                        .custody_validation_receipt_identity_sha256,
                ),
            },
            .rows = rows,
            .validation_receipt_identity_sha256 = try decodeDigest(
                parsed.value.validation_receipt_identity_sha256,
            ),
        },
    };
    try result.value.validate();
    const canonical = try encodeCanonicalJsonAlloc(allocator, &result.value);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical))
        return error.IncrementalCampaignWorkerDescriptionCodecMismatchV4;
    return result;
}

fn validationIdentity(value: *const DescriptionV4) artifact_store.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(validation_domain);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.campaign_namespace_sha256);
    hash.update(&value.custody.validation_receipt_identity_sha256);
    hashInt(&hash, u32, @as(u32, @intCast(value.rows.len)));
    for (value.rows) |row| {
        hashInt(&hash, u32, row.segment_index);
        hashBlob(&hash, row.recipe_ref);
        for (row.stage_inputs) |input| hashInput(&hash, input);
        hash.update(&row.campaign_namespace_sha256);
        hash.update(&row.local_task_identity_sha256);
        hashAuthorities(&hash, row.semantic_authorities);
    }
    return hash.finalResult();
}

fn writeRow(writer: anytype, row: RowV4) !void {
    try writer.writeAll("{\"campaign_namespace_sha256\":");
    try writeDigest(writer, row.campaign_namespace_sha256);
    try writer.writeAll(",\"local_task_identity_sha256\":");
    try writeDigest(writer, row.local_task_identity_sha256);
    try writer.writeAll(",\"recipe_ref\":");
    try writeBlobRef(writer, row.recipe_ref);
    try writer.print(
        ",\"segment_index\":{},\"semantic_authorities\":",
        .{row.segment_index},
    );
    try writeAuthorities(writer, row.semantic_authorities);
    try writer.writeAll(",\"stage_inputs\":[");
    for (row.stage_inputs, 0..) |input, ordinal| {
        if (ordinal != 0) try writer.writeByte(',');
        try writeInputRef(writer, input);
    }
    try writer.writeAll("]}");
}

fn writeAuthorities(
    writer: anytype,
    value: protocol.SemanticAuthorities,
) !void {
    try writer.writeAll("{\"layout_identity_sha256\":");
    try writeDigest(writer, value.layout_identity_sha256);
    try writer.writeAll(",\"pcs_identity_sha256\":");
    try writeDigest(writer, value.pcs_identity_sha256);
    try writer.writeAll(",\"profile_identity_sha256\":");
    try writeDigest(writer, value.profile_identity_sha256);
    try writer.writeAll(",\"program_identity_sha256\":");
    try writeDigest(writer, value.program_identity_sha256);
    try writer.writeAll(",\"protocol_identity_sha256\":");
    try writeDigest(writer, value.protocol_identity_sha256);
    try writer.writeAll(",\"provider_identity_sha256\":");
    try writeDigest(writer, value.provider_identity_sha256);
    try writer.writeAll(",\"registry_identity_sha256\":");
    try writeDigest(writer, value.registry_identity_sha256);
    try writer.writeAll(",\"security_identity_sha256\":");
    try writeDigest(writer, value.security_identity_sha256);
    try writer.writeAll(",\"statement_identity_sha256\":");
    try writeDigest(writer, value.statement_identity_sha256);
    try writer.writeByte('}');
}

fn writeInputRef(writer: anytype, value: artifact_store.InputRefV1) !void {
    try writer.writeAll("{\"blob\":");
    try writeBlobRef(writer, value.blob);
    try writer.print(
        ",\"ordinal\":{},\"role\":{}}}",
        .{ value.ordinal, @intFromEnum(value.role) },
    );
}

fn writeBlobRef(writer: anytype, value: artifact_store.BlobRefV1) !void {
    try writer.print(
        "{{\"byte_count\":{},\"format_version\":{}," ++
            "\"kind\":{},\"schema_version\":{},\"sha256\":",
        .{
            value.byte_count,
            value.format_version,
            @intFromEnum(value.kind),
            value.schema_version,
        },
    );
    try writeDigest(writer, value.sha256);
    try writer.writeByte('}');
}

fn writeDigest(writer: anytype, value: artifact_store.Digest) !void {
    const encoded = std.fmt.bytesToHex(value, .lower);
    try writer.print("\"{s}\"", .{encoded});
}

fn writeString(writer: anytype, value: []const u8) !void {
    try writer.print("\"{s}\"", .{value});
}

fn decodeInputRef(value: JsonInputRefV1) !artifact_store.InputRefV1 {
    const result = artifact_store.InputRefV1{
        .role = @enumFromInt(value.role),
        .ordinal = value.ordinal,
        .blob = try decodeBlobRef(value.blob),
    };
    try result.validate();
    return result;
}

fn decodeBlobRef(value: JsonBlobRefV1) !artifact_store.BlobRefV1 {
    const result = artifact_store.BlobRefV1{
        .kind = @enumFromInt(value.kind),
        .format_version = value.format_version,
        .schema_version = value.schema_version,
        .byte_count = value.byte_count,
        .sha256 = try decodeDigest(value.sha256),
    };
    try result.validate();
    return result;
}

fn decodeAuthorities(value: JsonAuthoritiesV4) !protocol.SemanticAuthorities {
    return .{
        .protocol_identity_sha256 = try decodeDigest(
            value.protocol_identity_sha256,
        ),
        .program_identity_sha256 = try decodeDigest(
            value.program_identity_sha256,
        ),
        .profile_identity_sha256 = try decodeDigest(
            value.profile_identity_sha256,
        ),
        .pcs_identity_sha256 = try decodeDigest(value.pcs_identity_sha256),
        .security_identity_sha256 = try decodeDigest(
            value.security_identity_sha256,
        ),
        .statement_identity_sha256 = try decodeDigest(
            value.statement_identity_sha256,
        ),
        .provider_identity_sha256 = try decodeDigest(
            value.provider_identity_sha256,
        ),
        .layout_identity_sha256 = try decodeDigest(
            value.layout_identity_sha256,
        ),
        .registry_identity_sha256 = try decodeDigest(
            value.registry_identity_sha256,
        ),
    };
}

fn decodeDigest(encoded: []const u8) Error!artifact_store.Digest {
    if (encoded.len != 64)
        return error.IncrementalCampaignWorkerDescriptionCodecMismatchV4;
    for (encoded) |byte| if (!std.ascii.isDigit(byte) and
        (byte < 'a' or byte > 'f'))
    {
        return error.IncrementalCampaignWorkerDescriptionCodecMismatchV4;
    };
    var result: artifact_store.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch
        return error.IncrementalCampaignWorkerDescriptionCodecMismatchV4;
    return result;
}

fn hashAuthorities(
    hash: *std.crypto.hash.sha2.Sha256,
    value: protocol.SemanticAuthorities,
) void {
    hash.update(&value.protocol_identity_sha256);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.profile_identity_sha256);
    hash.update(&value.pcs_identity_sha256);
    hash.update(&value.security_identity_sha256);
    hash.update(&value.statement_identity_sha256);
    hash.update(&value.provider_identity_sha256);
    hash.update(&value.layout_identity_sha256);
    hash.update(&value.registry_identity_sha256);
}

fn hashInput(
    hash: *std.crypto.hash.sha2.Sha256,
    value: artifact_store.InputRefV1,
) void {
    hashInt(hash, u32, @intFromEnum(value.role));
    hashInt(hash, u32, value.ordinal);
    hashBlob(hash, value.blob);
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
