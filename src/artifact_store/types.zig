//! Stable typed identities for reusable artifact-pipeline stages.
//!
//! Digests name bytes and semantic work. They never prove that those bytes
//! passed a cryptographic verifier; durable verifier evidence is represented
//! separately by `ValidationReceiptRefV1` in `manifest.zig`.

const std = @import("std");
const encoding = @import("encoding.zig");

pub const Digest = encoding.Digest;
pub const format_version_v1: u16 = 1;

pub const blob_ref_domain = "stwo-zig/artifact-store/blob-ref/v1\x00";
pub const semantic_key_domain = "stwo-zig/artifact-store/semantic-key/v1\x00";
pub const execution_key_domain = "stwo-zig/artifact-store/execution-key/v1\x00";

/// Stable cross-package allocation. Application-specific values may use the
/// non-exhaustive portion without changing the artifact-store package.
pub const ArtifactKindV1 = enum(u32) {
    raw = 1,
    semantic_key = 2,
    execution_key = 3,
    stage_manifest = 4,
    validation_receipt = 5,
    profile_receipt = 6,
    execution_artifact = 7,
    proof_artifact = 8,
    /// Canonical replay/input transport only. This is never a verifier-owned
    /// proof capture, live lease, freshness authority, or admission capability.
    capture_transport = 9,
    recursion_node = 10,
    journal = 11,
    statement = 12,
    program = 13,
    source = 14,
    _,
};

pub const StageKindV1 = enum(u32) {
    execute = 1,
    prove = 2,
    verify = 3,
    fold = 4,
    publish = 5,
    profile = 6,
    transform = 7,
    _,
};

pub const InputRoleV1 = enum(u32) {
    direct = 1,
    statement = 2,
    program = 3,
    profile = 4,
    witness = 5,
    child_left = 6,
    child_right = 7,
    proof = 8,
    capture = 9,
    journal = 10,
    _,
};

/// Content identity is deliberately independent of artifact role and schema.
/// The store deduplicates the same raw bytes while this tuple prevents a caller
/// from reopening them under an unbound interpretation.
pub const BlobRefV1 = struct {
    kind: ArtifactKindV1,
    format_version: u16 = format_version_v1,
    schema_version: u16,
    byte_count: u64,
    sha256: Digest,

    pub const canonical_size: usize = 48;

    pub fn create(
        kind: ArtifactKindV1,
        schema_version: u16,
        byte_count: u64,
        sha256: Digest,
    ) !BlobRefV1 {
        const result = BlobRefV1{
            .kind = kind,
            .schema_version = schema_version,
            .byte_count = byte_count,
            .sha256 = sha256,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: BlobRefV1) !void {
        if (@intFromEnum(self.kind) == 0 or
            self.format_version != format_version_v1 or self.schema_version == 0)
        {
            return error.InvalidBlobRef;
        }
        try encoding.requireNonzeroDigest(self.sha256);
    }

    pub fn canonicalBytes(self: BlobRefV1) ![canonical_size]u8 {
        try self.validate();
        var result: [canonical_size]u8 = undefined;
        std.mem.writeInt(u32, result[0..4], @intFromEnum(self.kind), .little);
        std.mem.writeInt(u16, result[4..6], self.format_version, .little);
        std.mem.writeInt(u16, result[6..8], self.schema_version, .little);
        std.mem.writeInt(u64, result[8..16], self.byte_count, .little);
        @memcpy(result[16..48], &self.sha256);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) !BlobRefV1 {
        if (bytes.len < canonical_size) return error.TruncatedArtifactEncoding;
        if (bytes.len != canonical_size) return error.NonCanonicalArtifactEncoding;
        var reader = encoding.Reader{ .bytes = bytes };
        const result = BlobRefV1{
            .kind = @enumFromInt(try reader.readInt(u32)),
            .format_version = try reader.readInt(u16),
            .schema_version = try reader.readInt(u16),
            .byte_count = try reader.readInt(u64),
            .sha256 = try reader.readDigest(),
        };
        try reader.expectEnd();
        try result.validate();
        return result;
    }

    pub fn identity(self: BlobRefV1) !Digest {
        const bytes = try self.canonicalBytes();
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(blob_ref_domain);
        hasher.update(&bytes);
        return hasher.finalResult();
    }

    pub fn eql(a: BlobRefV1, b: BlobRefV1) bool {
        return a.kind == b.kind and a.format_version == b.format_version and
            a.schema_version == b.schema_version and a.byte_count == b.byte_count and
            std.mem.eql(u8, &a.sha256, &b.sha256);
    }
};

pub const InputRefV1 = struct {
    role: InputRoleV1,
    ordinal: u32,
    blob: BlobRefV1,

    pub const canonical_size = 8 + BlobRefV1.canonical_size;

    pub fn validate(self: InputRefV1) !void {
        if (@intFromEnum(self.role) == 0) return error.InvalidArtifactInputRole;
        try self.blob.validate();
    }

    pub fn writeCanonical(self: InputRefV1, encoder: *encoding.Encoder) !void {
        try self.validate();
        try encoder.writeInt(u32, @intFromEnum(self.role));
        try encoder.writeInt(u32, self.ordinal);
        const blob_bytes = try self.blob.canonicalBytes();
        try encoder.writeFixed(&blob_bytes);
    }

    pub fn readCanonical(reader: *encoding.Reader) !InputRefV1 {
        const result = InputRefV1{
            .role = @enumFromInt(try reader.readInt(u32)),
            .ordinal = try reader.readInt(u32),
            .blob = try BlobRefV1.decodeCanonical(try reader.take(BlobRefV1.canonical_size)),
        };
        try result.validate();
        return result;
    }
};

/// `campaign_namespace` is a stable namespace, never a whole-run or whole-leaf
/// inventory digest. `local_task_identity` binds only this node's topology and
/// role. Ordered inputs contain direct dependencies only. Legacy whole-plan
/// identities belong in a remintable validation envelope, not this cache key.
pub const SemanticKeyFieldsV1 = struct {
    stage_kind: StageKindV1,
    stage_schema_version: u16,
    campaign_namespace: Digest,
    local_task_identity: Digest,
    protocol_identity: Digest,
    program_identity: Digest,
    profile_identity: Digest,
    pcs_identity: Digest,
    security_identity: Digest,
    statement_identity: Digest = [_]u8{0} ** 32,
    provider_identity: Digest = [_]u8{0} ** 32,
    layout_identity: Digest = [_]u8{0} ** 32,
    registry_identity: Digest = [_]u8{0} ** 32,
    semantic_options_identity: Digest = [_]u8{0} ** 32,
    ordered_inputs: []const InputRefV1,
};

pub const SemanticKeyV1 = struct {
    fields: SemanticKeyFieldsV1,
    identity: Digest,

    pub fn create(allocator: std.mem.Allocator, fields: SemanticKeyFieldsV1) !SemanticKeyV1 {
        try validateSemanticFields(fields);
        const bytes = try semanticBytesAlloc(allocator, fields);
        defer allocator.free(bytes);
        return .{ .fields = fields, .identity = encoding.digestBytes(bytes) };
    }

    pub fn validate(self: SemanticKeyV1, allocator: std.mem.Allocator) !void {
        const expected = try SemanticKeyV1.create(allocator, self.fields);
        if (!std.mem.eql(u8, &expected.identity, &self.identity))
            return error.InvalidSemanticKeyIdentity;
    }

    pub fn canonicalBytesAlloc(self: SemanticKeyV1, allocator: std.mem.Allocator) ![]u8 {
        try self.validate(allocator);
        return semanticBytesAlloc(allocator, self.fields);
    }
};

pub const ExecutionKeyFieldsV1 = struct {
    semantic_key_identity: Digest,
    producer_identity: Digest,
    verifier_identity: Digest,
    source_identity: Digest,
    build_identity: Digest,
    executable_identity: Digest,
    toolchain_identity: Digest,
    backend_identity: Digest,
    optimization_identity: Digest,
    worker_policy_identity: Digest,
    memory_policy_identity: Digest,
    retention_policy_identity: Digest,
    timeout_policy_identity: Digest,
};

pub const ExecutionKeyV1 = struct {
    fields: ExecutionKeyFieldsV1,
    identity: Digest,

    pub fn create(fields: ExecutionKeyFieldsV1) !ExecutionKeyV1 {
        inline for (@typeInfo(ExecutionKeyFieldsV1).@"struct".fields) |field| {
            try encoding.requireNonzeroDigest(@field(fields, field.name));
        }
        const bytes = try executionCanonicalBytes(fields);
        return .{
            .fields = fields,
            .identity = encoding.digestBytes(&bytes),
        };
    }

    pub fn validate(self: ExecutionKeyV1) !void {
        const expected = try ExecutionKeyV1.create(self.fields);
        if (!std.mem.eql(u8, &expected.identity, &self.identity))
            return error.InvalidExecutionKeyIdentity;
    }

    pub fn canonicalBytes(self: ExecutionKeyV1) ![execution_canonical_size]u8 {
        try self.validate();
        return executionCanonicalBytes(self.fields);
    }
};

pub const execution_canonical_size = execution_key_domain.len + 2 +
    @typeInfo(ExecutionKeyFieldsV1).@"struct".fields.len * 32;

pub fn validateOrderedInputs(inputs: []const InputRefV1) !void {
    if (inputs.len > std.math.maxInt(u32)) return error.ArtifactEncodingTooLarge;
    for (inputs, 0..) |input, index| {
        try input.validate();
        for (inputs[0..index]) |previous| {
            if (previous.role == input.role and previous.ordinal == input.ordinal)
                return error.DuplicateArtifactInputRole;
        }
    }
}

fn validateSemanticFields(fields: SemanticKeyFieldsV1) !void {
    if (@intFromEnum(fields.stage_kind) == 0 or fields.stage_schema_version == 0)
        return error.InvalidSemanticKey;
    try encoding.requireNonzeroDigest(fields.campaign_namespace);
    try encoding.requireNonzeroDigest(fields.local_task_identity);
    try encoding.requireNonzeroDigest(fields.protocol_identity);
    try encoding.requireNonzeroDigest(fields.program_identity);
    try encoding.requireNonzeroDigest(fields.profile_identity);
    try encoding.requireNonzeroDigest(fields.pcs_identity);
    try encoding.requireNonzeroDigest(fields.security_identity);
    try validateOrderedInputs(fields.ordered_inputs);
}

fn semanticBytesAlloc(
    allocator: std.mem.Allocator,
    fields: SemanticKeyFieldsV1,
) ![]u8 {
    try validateSemanticFields(fields);
    var encoder = try encoding.Encoder.init(allocator, semantic_key_domain);
    defer encoder.deinit();
    try encoder.writeInt(u16, format_version_v1);
    try encoder.writeInt(u32, @intFromEnum(fields.stage_kind));
    try encoder.writeInt(u16, fields.stage_schema_version);
    try encoder.writeDigest(fields.campaign_namespace);
    try encoder.writeDigest(fields.local_task_identity);
    try encoder.writeDigest(fields.protocol_identity);
    try encoder.writeDigest(fields.program_identity);
    try encoder.writeDigest(fields.profile_identity);
    try encoder.writeDigest(fields.pcs_identity);
    try encoder.writeDigest(fields.security_identity);
    try encoder.writeDigest(fields.statement_identity);
    try encoder.writeDigest(fields.provider_identity);
    try encoder.writeDigest(fields.layout_identity);
    try encoder.writeDigest(fields.registry_identity);
    try encoder.writeDigest(fields.semantic_options_identity);
    try encoder.writeCount(fields.ordered_inputs.len);
    for (fields.ordered_inputs) |input| try input.writeCanonical(&encoder);
    return encoder.finish();
}

fn executionCanonicalBytes(fields: ExecutionKeyFieldsV1) ![execution_canonical_size]u8 {
    inline for (@typeInfo(ExecutionKeyFieldsV1).@"struct".fields) |field| {
        try encoding.requireNonzeroDigest(@field(fields, field.name));
    }
    var result: [execution_canonical_size]u8 = undefined;
    var index: usize = 0;
    @memcpy(result[index..][0..execution_key_domain.len], execution_key_domain);
    index += execution_key_domain.len;
    std.mem.writeInt(u16, result[index..][0..2], format_version_v1, .little);
    index += 2;
    inline for (@typeInfo(ExecutionKeyFieldsV1).@"struct".fields) |field| {
        const identity: Digest = @field(fields, field.name);
        @memcpy(result[index..][0..32], &identity);
        index += 32;
    }
    std.debug.assert(index == result.len);
    return result;
}
