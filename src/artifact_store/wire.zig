//! Exact canonical decoders for artifact keys and stage manifests.

const std = @import("std");
const encoding = @import("encoding.zig");
const types = @import("types.zig");
const manifest = @import("manifest.zig");

const maximum_collection_items: u32 = 1 << 20;

pub const OwnedSemanticKeyV1 = struct {
    value: types.SemanticKeyV1,
    ordered_inputs: []types.InputRefV1,

    pub fn deinit(self: *OwnedSemanticKeyV1, allocator: std.mem.Allocator) void {
        allocator.free(self.ordered_inputs);
        self.* = undefined;
    }
};

pub fn decodeSemanticKeyAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedSemanticKeyV1 {
    var reader = try encoding.Reader.init(bytes, types.semantic_key_domain);
    if (try reader.readInt(u16) != types.format_version_v1)
        return error.UnsupportedArtifactEncodingVersion;
    const stage_kind: types.StageKindV1 = @enumFromInt(try reader.readInt(u32));
    const stage_schema_version = try reader.readInt(u16);
    const campaign_namespace = try reader.readDigest();
    const local_task_identity = try reader.readDigest();
    const protocol_identity = try reader.readDigest();
    const program_identity = try reader.readDigest();
    const profile_identity = try reader.readDigest();
    const pcs_identity = try reader.readDigest();
    const security_identity = try reader.readDigest();
    const statement_identity = try reader.readDigest();
    const provider_identity = try reader.readDigest();
    const layout_identity = try reader.readDigest();
    const registry_identity = try reader.readDigest();
    const semantic_options_identity = try reader.readDigest();
    const count = try readCount(&reader);
    const ordered_inputs = try allocator.alloc(types.InputRefV1, count);
    errdefer allocator.free(ordered_inputs);
    for (ordered_inputs) |*input| input.* = try types.InputRefV1.readCanonical(&reader);
    try reader.expectEnd();
    const value = try types.SemanticKeyV1.create(allocator, .{
        .stage_kind = stage_kind,
        .stage_schema_version = stage_schema_version,
        .campaign_namespace = campaign_namespace,
        .local_task_identity = local_task_identity,
        .protocol_identity = protocol_identity,
        .program_identity = program_identity,
        .profile_identity = profile_identity,
        .pcs_identity = pcs_identity,
        .security_identity = security_identity,
        .statement_identity = statement_identity,
        .provider_identity = provider_identity,
        .layout_identity = layout_identity,
        .registry_identity = registry_identity,
        .semantic_options_identity = semantic_options_identity,
        .ordered_inputs = ordered_inputs,
    });
    return .{ .value = value, .ordered_inputs = ordered_inputs };
}

pub fn decodeExecutionKey(bytes: []const u8) !types.ExecutionKeyV1 {
    var reader = try encoding.Reader.init(bytes, types.execution_key_domain);
    if (try reader.readInt(u16) != types.format_version_v1)
        return error.UnsupportedArtifactEncodingVersion;
    var fields: types.ExecutionKeyFieldsV1 = undefined;
    inline for (@typeInfo(types.ExecutionKeyFieldsV1).@"struct".fields) |field| {
        @field(fields, field.name) = try reader.readDigest();
    }
    try reader.expectEnd();
    return types.ExecutionKeyV1.create(fields);
}

pub const OwnedStageManifestV1 = struct {
    value: manifest.StageManifestV1,
    dependencies: []encoding.Digest,
    inputs: []types.InputRefV1,
    outputs: []types.BlobRefV1,
    validation_receipts: []manifest.ValidationReceiptRefV1,
    profile_receipts: []manifest.ProfileReceiptRefV1,

    pub fn deinit(self: *OwnedStageManifestV1, allocator: std.mem.Allocator) void {
        allocator.free(self.dependencies);
        allocator.free(self.inputs);
        allocator.free(self.outputs);
        allocator.free(self.validation_receipts);
        allocator.free(self.profile_receipts);
        self.* = undefined;
    }
};

pub fn decodeStageManifestAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !OwnedStageManifestV1 {
    var reader = try encoding.Reader.init(bytes, manifest.stage_manifest_domain);
    if (try reader.readInt(u16) != types.format_version_v1)
        return error.UnsupportedArtifactEncodingVersion;
    const stage_kind: types.StageKindV1 = @enumFromInt(try reader.readInt(u32));
    const stage_schema_version = try reader.readInt(u16);
    const phase: manifest.StagePhaseV1 = @enumFromInt(try reader.readInt(u16));
    const status: manifest.StageStatusV1 = @enumFromInt(try reader.readInt(u16));
    const node_identity = try reader.readDigest();
    const semantic_key_identity = try reader.readDigest();
    const execution_key_identity = try reader.readDigest();

    const dependencies = try allocator.alloc(encoding.Digest, try readCount(&reader));
    errdefer allocator.free(dependencies);
    for (dependencies) |*dependency| dependency.* = try reader.readDigest();

    const inputs = try allocator.alloc(types.InputRefV1, try readCount(&reader));
    errdefer allocator.free(inputs);
    for (inputs) |*input| input.* = try types.InputRefV1.readCanonical(&reader);

    const outputs = try allocator.alloc(types.BlobRefV1, try readCount(&reader));
    errdefer allocator.free(outputs);
    for (outputs) |*output| {
        output.* = try types.BlobRefV1.decodeCanonical(
            try reader.take(types.BlobRefV1.canonical_size),
        );
    }

    const validation_receipts = try allocator.alloc(
        manifest.ValidationReceiptRefV1,
        try readCount(&reader),
    );
    errdefer allocator.free(validation_receipts);
    for (validation_receipts) |*receipt|
        receipt.* = try manifest.ValidationReceiptRefV1.readCanonical(&reader);

    const profile_receipts = try allocator.alloc(
        manifest.ProfileReceiptRefV1,
        try readCount(&reader),
    );
    errdefer allocator.free(profile_receipts);
    for (profile_receipts) |*receipt|
        receipt.* = try manifest.ProfileReceiptRefV1.readCanonical(&reader);
    try reader.expectEnd();

    const value = try manifest.StageManifestV1.create(allocator, .{
        .stage_kind = stage_kind,
        .stage_schema_version = stage_schema_version,
        .node_identity = node_identity,
        .semantic_key_identity = semantic_key_identity,
        .execution_key_identity = execution_key_identity,
        .phase = phase,
        .status = status,
        .ordered_dependency_manifest_ids = dependencies,
        .ordered_inputs = inputs,
        .ordered_outputs = outputs,
        .validation_receipts = validation_receipts,
        .profile_receipts = profile_receipts,
    });
    return .{
        .value = value,
        .dependencies = dependencies,
        .inputs = inputs,
        .outputs = outputs,
        .validation_receipts = validation_receipts,
        .profile_receipts = profile_receipts,
    };
}

fn readCount(reader: *encoding.Reader) !usize {
    const count = try reader.readInt(u32);
    if (count > maximum_collection_items) return error.ArtifactEncodingTooLarge;
    return @intCast(count);
}
