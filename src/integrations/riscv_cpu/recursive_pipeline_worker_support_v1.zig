//! Typed validation and manifest helpers for the persistent worker.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const storage = @import("recursive_pipeline_worker_storage_v1.zig");

const maximum_small_artifact_bytes: usize = 16 * 1024 * 1024;
pub const stage_manifest_schema_version: u16 = 1;

pub fn requireAdapter(comptime Adapter: type, node: protocol.Node) !void {
    if (!Adapter.acceptsNodeAdapter(node.adapter))
        return error.UnsupportedRecursivePipelineAdapter;
}

pub fn createSemanticKey(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    inputs: []const artifact_store.InputRefV1,
    campaign_namespace: artifact_store.Digest,
) !artifact_store.SemanticKeyV1 {
    const options_identity = try protocol.canonicalDigest(
        allocator,
        node.semantic_options,
    );
    return artifact_store.SemanticKeyV1.create(allocator, .{
        .stage_kind = node.stage_kind,
        .stage_schema_version = node.stage_schema_version,
        .campaign_namespace = campaign_namespace,
        .local_task_identity = node.local_task_identity_sha256,
        .protocol_identity = node.semantic_authorities.protocol_identity_sha256,
        .program_identity = node.semantic_authorities.program_identity_sha256,
        .profile_identity = node.semantic_authorities.profile_identity_sha256,
        .pcs_identity = node.semantic_authorities.pcs_identity_sha256,
        .security_identity = node.semantic_authorities.security_identity_sha256,
        .statement_identity = node.semantic_authorities.statement_identity_sha256,
        .provider_identity = node.semantic_authorities.provider_identity_sha256,
        .layout_identity = node.semantic_authorities.layout_identity_sha256,
        .registry_identity = node.semantic_authorities.registry_identity_sha256,
        .semantic_options_identity = options_identity,
        .ordered_inputs = inputs,
    });
}

pub fn validateKeys(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    inputs: []const artifact_store.InputRefV1,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
) !void {
    try validateNodeInputs(node, inputs);
    const expected = try createSemanticKey(
        allocator,
        node,
        inputs,
        semantic.fields.campaign_namespace,
    );
    if (!std.mem.eql(u8, &expected.identity, &semantic.identity) or
        !std.mem.eql(
            u8,
            &execution.fields.semantic_key_identity,
            &semantic.identity,
        ))
    {
        return error.WorkerKeyAuthorityMismatch;
    }
}

pub fn validateNodeInputs(
    node: protocol.Node,
    inputs: []const artifact_store.InputRefV1,
) !void {
    if (node.semantic_options != .object or
        inputs.len != node.external_inputs.len + node.dependencies.len)
    {
        return error.WorkerNodeInputMismatch;
    }
    for (node.external_inputs) |external| {
        const observed = findInput(
            inputs,
            @intFromEnum(external.role),
            external.ordinal,
        ) orelse return error.WorkerNodeInputMismatch;
        if (!artifact_store.BlobRefV1.eql(observed.blob, external.blob))
            return error.WorkerNodeInputMismatch;
    }
    for (node.dependencies) |dependency| {
        _ = findInput(inputs, dependency.role, dependency.ordinal) orelse
            return error.WorkerNodeInputMismatch;
    }
}

pub fn findInput(
    inputs: []const artifact_store.InputRefV1,
    role: u32,
    ordinal: u32,
) ?artifact_store.InputRefV1 {
    for (inputs) |input| {
        if (@intFromEnum(input.role) == role and input.ordinal == ordinal)
            return input;
    }
    return null;
}

pub fn createStageManifest(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    inputs: []const artifact_store.InputRefV1,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    ordered_outputs: []const artifact_store.BlobRefV1,
    dependency_refs: []const artifact_store.BlobRefV1,
) !artifact_store.StageManifestV1 {
    if (ordered_outputs.len != 1)
        return error.WorkerStageManifestOutputMismatch;
    const dependency_ids = try allocator.alloc(
        artifact_store.Digest,
        dependency_refs.len,
    );
    for (dependency_refs, dependency_ids) |ref, *identity| {
        identity.* = ref.sha256;
    }
    return artifact_store.StageManifestV1.create(allocator, .{
        .stage_kind = node.stage_kind,
        .stage_schema_version = node.stage_schema_version,
        .node_identity = node.local_task_identity_sha256,
        .semantic_key_identity = semantic.identity,
        .execution_key_identity = execution.identity,
        .phase = .published,
        .status = .complete,
        .ordered_dependency_manifest_ids = dependency_ids,
        .ordered_inputs = inputs,
        .ordered_outputs = ordered_outputs,
    });
}

pub fn validateDependencyManifests(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    node: protocol.Node,
    refs: []const artifact_store.BlobRefV1,
) !void {
    if (refs.len != node.dependencies.len)
        return error.WorkerDependencyManifestMismatch;
    for (refs) |ref| {
        if (ref.kind != .stage_manifest or
            ref.schema_version != stage_manifest_schema_version)
        {
            return error.WorkerDependencyManifestMismatch;
        }
        const bytes = try storage.readSmallRefAlloc(
            allocator,
            store,
            ref,
            maximum_small_artifact_bytes,
        );
        defer store.allocator.free(bytes);
        var manifest = try artifact_store.decodeStageManifestAlloc(
            allocator,
            bytes,
        );
        defer manifest.deinit(allocator);
        if (!std.mem.eql(u8, &manifest.value.identity, &ref.sha256) or
            manifest.value.fields.phase != .published or
            manifest.value.fields.status != .complete)
        {
            return error.WorkerDependencyManifestMismatch;
        }
    }
}

pub fn validateExistingStageManifest(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    ref: artifact_store.BlobRefV1,
    node: protocol.Node,
    inputs: []const artifact_store.InputRefV1,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    output_ref: artifact_store.BlobRefV1,
    supplied_dependencies: []const artifact_store.BlobRefV1,
    mode: []const u8,
) !void {
    if (ref.kind != .stage_manifest or
        ref.schema_version != stage_manifest_schema_version)
    {
        return error.WorkerStageManifestMismatch;
    }
    const bytes = try storage.readSmallRefAlloc(
        allocator,
        store,
        ref,
        maximum_small_artifact_bytes,
    );
    defer store.allocator.free(bytes);
    var owned = try artifact_store.decodeStageManifestAlloc(allocator, bytes);
    defer owned.deinit(allocator);
    const fields = owned.value.fields;
    if (!std.mem.eql(u8, &owned.value.identity, &ref.sha256) or
        fields.stage_kind != node.stage_kind or
        fields.stage_schema_version != node.stage_schema_version or
        !std.mem.eql(u8, &fields.node_identity, &node.local_task_identity_sha256) or
        !std.mem.eql(u8, &fields.semantic_key_identity, &semantic.identity) or
        !std.mem.eql(u8, &fields.execution_key_identity, &execution.identity) or
        fields.phase != .published or fields.status != .complete or
        fields.ordered_dependency_manifest_ids.len != node.dependencies.len or
        fields.ordered_inputs.len != inputs.len or
        fields.ordered_outputs.len != 1 or
        !artifact_store.BlobRefV1.eql(fields.ordered_outputs[0], output_ref))
    {
        return error.WorkerStageManifestMismatch;
    }
    for (fields.ordered_inputs, inputs) |observed, expected| {
        if (!std.meta.eql(observed, expected))
            return error.WorkerStageManifestMismatch;
    }
    if (supplied_dependencies.len != 0) {
        if (supplied_dependencies.len !=
            fields.ordered_dependency_manifest_ids.len)
        {
            return error.WorkerDependencyManifestMismatch;
        }
        for (
            supplied_dependencies,
            fields.ordered_dependency_manifest_ids,
        ) |dependency, expected| {
            if (!std.mem.eql(u8, &dependency.sha256, &expected))
                return error.WorkerDependencyManifestMismatch;
        }
    }
    const transitive = std.mem.eql(u8, mode, "root");
    for (fields.ordered_dependency_manifest_ids) |identity| {
        try validateManifestClosure(
            allocator,
            store,
            identity,
            0,
            transitive,
        );
    }
}

fn validateManifestClosure(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    identity: artifact_store.Digest,
    depth: u16,
    transitive: bool,
) !void {
    if (depth >= 1024) return error.WorkerManifestClosureTooDeep;
    const ref = try storage.refForDigest(
        allocator,
        store,
        .stage_manifest,
        stage_manifest_schema_version,
        identity,
    );
    const bytes = try storage.readSmallRefAlloc(
        allocator,
        store,
        ref,
        maximum_small_artifact_bytes,
    );
    defer store.allocator.free(bytes);
    var owned = try artifact_store.decodeStageManifestAlloc(allocator, bytes);
    defer owned.deinit(allocator);
    if (!std.mem.eql(u8, &owned.value.identity, &identity) or
        owned.value.fields.phase != .published or
        owned.value.fields.status != .complete)
    {
        return error.WorkerDependencyManifestMismatch;
    }
    if (transitive) {
        for (owned.value.fields.ordered_dependency_manifest_ids) |dependency| {
            try validateManifestClosure(
                allocator,
                store,
                dependency,
                depth + 1,
                true,
            );
        }
    }
}

pub fn parseBlobRefArray(
    allocator: std.mem.Allocator,
    value: protocol.Json,
) ![]artifact_store.BlobRefV1 {
    if (value != .array) return error.InvalidWorkerFields;
    const refs = try allocator.alloc(
        artifact_store.BlobRefV1,
        value.array.items.len,
    );
    for (value.array.items, refs) |item, *ref| {
        ref.* = try protocol.parseBlobRef(item);
    }
    return refs;
}

pub fn stringArray(
    allocator: std.mem.Allocator,
    value: protocol.Json,
) ![][]const u8 {
    if (value != .array) return error.InvalidWorkerFields;
    const result = try allocator.alloc([]const u8, value.array.items.len);
    for (value.array.items, result) |item, *output| {
        if (item != .string or item.string.len == 0)
            return error.InvalidWorkerField;
        output.* = item.string;
    }
    return result;
}

pub fn stringsValue(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) !protocol.Json {
    var result = protocol.array(allocator);
    for (values) |value| {
        try protocol.append(&result, protocol.string(value));
    }
    return result;
}

pub fn bytesHexAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const output = try allocator.alloc(u8, bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

pub fn validateMode(mode: []const u8) !void {
    inline for (.{ "shallow", "cold", "fresh", "root" }) |valid| {
        if (std.mem.eql(u8, mode, valid)) return;
    }
    return error.InvalidWorkerValidationMode;
}

pub fn validateDistinctPaths(
    a: []const u8,
    b: []const u8,
    c: []const u8,
) !void {
    if (!std.fs.path.isAbsolute(a) or !std.fs.path.isAbsolute(b) or
        !std.fs.path.isAbsolute(c) or std.mem.eql(u8, a, b) or
        std.mem.eql(u8, a, c) or std.mem.eql(u8, b, c))
    {
        return error.InvalidWorkerOutputPath;
    }
}

pub fn shutdownPayload(
    allocator: std.mem.Allocator,
    payload: protocol.Json,
) !protocol.Json {
    const object = try protocol.objectValue(payload);
    try protocol.exactKeys(object, &.{});
    return protocol.jsonObject(allocator);
}
