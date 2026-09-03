//! Durable stage manifests and typed receipt references.

const std = @import("std");
const encoding = @import("encoding.zig");
const types = @import("types.zig");

pub const Digest = encoding.Digest;
pub const stage_manifest_domain = "stwo-zig/artifact-store/stage-manifest/v1\x00";

pub const StagePhaseV1 = enum(u16) {
    planned = 1,
    produced = 2,
    validated = 3,
    published = 4,
    _,
};

pub const StageStatusV1 = enum(u16) {
    complete = 1,
    failed = 2,
    _,
};

/// Durable evidence and an index for later cold validation. Possessing or
/// reopening this receipt never mints its authority and never substitutes for
/// a verifier-owned live capability. A new process must cold-open and validate
/// the receipt; a live process may separately retain an owned verifier lease.
pub const ValidationReceiptRefV1 = struct {
    validator_kind: u32,
    validator_schema_version: u16,
    reserved: u16 = 0,
    authority_identity: Digest,
    validator_identity: Digest,
    blob: types.BlobRefV1,

    pub fn validate(self: ValidationReceiptRefV1) !void {
        if (self.validator_kind == 0 or self.validator_schema_version == 0 or
            self.reserved != 0 or self.blob.kind != .validation_receipt)
        {
            return error.InvalidValidationReceiptRef;
        }
        try encoding.requireNonzeroDigest(self.authority_identity);
        try encoding.requireNonzeroDigest(self.validator_identity);
        try self.blob.validate();
    }

    fn writeCanonical(self: ValidationReceiptRefV1, encoder: *encoding.Encoder) !void {
        try self.validate();
        try encoder.writeInt(u32, self.validator_kind);
        try encoder.writeInt(u16, self.validator_schema_version);
        try encoder.writeInt(u16, self.reserved);
        try encoder.writeDigest(self.authority_identity);
        try encoder.writeDigest(self.validator_identity);
        const blob_bytes = try self.blob.canonicalBytes();
        try encoder.writeFixed(&blob_bytes);
    }

    pub fn readCanonical(reader: *encoding.Reader) !ValidationReceiptRefV1 {
        const result = ValidationReceiptRefV1{
            .validator_kind = try reader.readInt(u32),
            .validator_schema_version = try reader.readInt(u16),
            .reserved = try reader.readInt(u16),
            .authority_identity = try reader.readDigest(),
            .validator_identity = try reader.readDigest(),
            .blob = try types.BlobRefV1.decodeCanonical(
                try reader.take(types.BlobRefV1.canonical_size),
            ),
        };
        try result.validate();
        return result;
    }
};

pub const ProfileReceiptRefV1 = struct {
    profile_kind: u32,
    profile_schema_version: u16,
    reserved: u16 = 0,
    profile_identity: Digest,
    issuer_identity: Digest,
    blob: types.BlobRefV1,

    pub fn validate(self: ProfileReceiptRefV1) !void {
        if (self.profile_kind == 0 or self.profile_schema_version == 0 or
            self.reserved != 0 or self.blob.kind != .profile_receipt)
        {
            return error.InvalidProfileReceiptRef;
        }
        try encoding.requireNonzeroDigest(self.profile_identity);
        try encoding.requireNonzeroDigest(self.issuer_identity);
        try self.blob.validate();
    }

    fn writeCanonical(self: ProfileReceiptRefV1, encoder: *encoding.Encoder) !void {
        try self.validate();
        try encoder.writeInt(u32, self.profile_kind);
        try encoder.writeInt(u16, self.profile_schema_version);
        try encoder.writeInt(u16, self.reserved);
        try encoder.writeDigest(self.profile_identity);
        try encoder.writeDigest(self.issuer_identity);
        const blob_bytes = try self.blob.canonicalBytes();
        try encoder.writeFixed(&blob_bytes);
    }

    pub fn readCanonical(reader: *encoding.Reader) !ProfileReceiptRefV1 {
        const result = ProfileReceiptRefV1{
            .profile_kind = try reader.readInt(u32),
            .profile_schema_version = try reader.readInt(u16),
            .reserved = try reader.readInt(u16),
            .profile_identity = try reader.readDigest(),
            .issuer_identity = try reader.readDigest(),
            .blob = try types.BlobRefV1.decodeCanonical(
                try reader.take(types.BlobRefV1.canonical_size),
            ),
        };
        try result.validate();
        return result;
    }
};

pub const StageManifestFieldsV1 = struct {
    stage_kind: types.StageKindV1,
    stage_schema_version: u16,
    node_identity: Digest,
    semantic_key_identity: Digest,
    execution_key_identity: Digest,
    phase: StagePhaseV1,
    status: StageStatusV1,
    ordered_dependency_manifest_ids: []const Digest,
    ordered_inputs: []const types.InputRefV1,
    ordered_outputs: []const types.BlobRefV1,
    validation_receipts: []const ValidationReceiptRefV1 = &.{},
    profile_receipts: []const ProfileReceiptRefV1 = &.{},
};

pub const StageManifestV1 = struct {
    fields: StageManifestFieldsV1,
    identity: Digest,

    pub fn create(
        allocator: std.mem.Allocator,
        fields: StageManifestFieldsV1,
    ) !StageManifestV1 {
        try validateFields(fields);
        const bytes = try canonicalFieldsAlloc(allocator, fields);
        defer allocator.free(bytes);
        return .{ .fields = fields, .identity = encoding.digestBytes(bytes) };
    }

    pub fn validate(self: StageManifestV1, allocator: std.mem.Allocator) !void {
        const expected = try StageManifestV1.create(allocator, self.fields);
        if (!std.mem.eql(u8, &expected.identity, &self.identity))
            return error.InvalidStageManifestIdentity;
    }

    pub fn validateAgainstKeys(
        self: StageManifestV1,
        allocator: std.mem.Allocator,
        semantic: types.SemanticKeyV1,
        execution: types.ExecutionKeyV1,
    ) !void {
        try self.validate(allocator);
        try semantic.validate(allocator);
        try execution.validate();
        if (!std.mem.eql(u8, &semantic.identity, &self.fields.semantic_key_identity) or
            !std.mem.eql(u8, &execution.identity, &self.fields.execution_key_identity) or
            !std.mem.eql(u8, &semantic.identity, &execution.fields.semantic_key_identity))
        {
            return error.StageManifestKeyMismatch;
        }
    }

    pub fn canonicalBytesAlloc(
        self: StageManifestV1,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        try self.validate(allocator);
        return canonicalFieldsAlloc(allocator, self.fields);
    }
};

fn validateFields(fields: StageManifestFieldsV1) !void {
    if (@intFromEnum(fields.stage_kind) == 0 or fields.stage_schema_version == 0 or
        @intFromEnum(fields.phase) == 0 or @intFromEnum(fields.status) == 0)
    {
        return error.InvalidStageManifest;
    }
    try encoding.requireNonzeroDigest(fields.node_identity);
    try encoding.requireNonzeroDigest(fields.semantic_key_identity);
    try encoding.requireNonzeroDigest(fields.execution_key_identity);
    if (fields.ordered_dependency_manifest_ids.len > std.math.maxInt(u32) or
        fields.ordered_outputs.len > std.math.maxInt(u32) or
        fields.validation_receipts.len > std.math.maxInt(u32) or
        fields.profile_receipts.len > std.math.maxInt(u32))
    {
        return error.ArtifactEncodingTooLarge;
    }
    try types.validateOrderedInputs(fields.ordered_inputs);
    for (fields.ordered_dependency_manifest_ids) |dependency| {
        try encoding.requireNonzeroDigest(dependency);
    }
    for (fields.ordered_outputs) |output| try output.validate();
    for (fields.validation_receipts) |receipt| try receipt.validate();
    for (fields.profile_receipts) |receipt| try receipt.validate();
    switch (fields.status) {
        .complete => if (fields.ordered_outputs.len == 0)
            return error.CompletedStageHasNoOutputs,
        .failed => if (fields.phase == .published)
            return error.FailedStageCannotBePublished,
        else => {},
    }
}

fn canonicalFieldsAlloc(
    allocator: std.mem.Allocator,
    fields: StageManifestFieldsV1,
) ![]u8 {
    try validateFields(fields);
    var encoder = try encoding.Encoder.init(allocator, stage_manifest_domain);
    defer encoder.deinit();
    try encoder.writeInt(u16, types.format_version_v1);
    try encoder.writeInt(u32, @intFromEnum(fields.stage_kind));
    try encoder.writeInt(u16, fields.stage_schema_version);
    try encoder.writeInt(u16, @intFromEnum(fields.phase));
    try encoder.writeInt(u16, @intFromEnum(fields.status));
    try encoder.writeDigest(fields.node_identity);
    try encoder.writeDigest(fields.semantic_key_identity);
    try encoder.writeDigest(fields.execution_key_identity);
    try encoder.writeCount(fields.ordered_dependency_manifest_ids.len);
    for (fields.ordered_dependency_manifest_ids) |dependency|
        try encoder.writeDigest(dependency);
    try encoder.writeCount(fields.ordered_inputs.len);
    for (fields.ordered_inputs) |input| try input.writeCanonical(&encoder);
    try encoder.writeCount(fields.ordered_outputs.len);
    for (fields.ordered_outputs) |output| {
        const bytes = try output.canonicalBytes();
        try encoder.writeFixed(&bytes);
    }
    try encoder.writeCount(fields.validation_receipts.len);
    for (fields.validation_receipts) |receipt| try receipt.writeCanonical(&encoder);
    try encoder.writeCount(fields.profile_receipts.len);
    for (fields.profile_receipts) |receipt| try receipt.writeCanonical(&encoder);
    return encoder.finish();
}
