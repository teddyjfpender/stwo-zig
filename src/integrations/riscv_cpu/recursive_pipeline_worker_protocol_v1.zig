//! Canonical JSONL wire owned by the persistent recursive pipeline worker.
//!
//! JSON is a controller transport only. Production BlobRefs and cache keys are
//! decoded into, and re-encoded from, the host-neutral Zig artifact package.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const json = @import("recursive_pipeline_worker_json_v1.zig");

pub const request_schema = "stwo.recursive-pipeline-worker-request.v1";
pub const response_schema = "stwo.recursive-pipeline-worker-response.v1";
pub const description_schema =
    "stwo.recursive-pipeline-stage-description.v1";
pub const semantic_schema = "stwo.recursive-pipeline-semantic-key.v1";
pub const execution_schema = "stwo.recursive-pipeline-execution-key.v1";
pub const candidate_ref_schema =
    "stwo.recursive-pipeline-worker-candidate-ref.v1";
pub const max_frame_bytes: usize = 16 * 1024 * 1024;

pub const Json = json.Json;
pub const Digest = artifact_store.Digest;

pub const canonicalAlloc = json.canonicalAlloc;
pub const canonicalDigest = json.canonicalDigest;
pub const sealObject = json.sealObject;
pub const validateSeal = json.validateSeal;
pub const jsonObject = json.jsonObject;
pub const array = json.array;
pub const string = json.string;
pub const integer = json.integer;
pub const integerU64 = json.integerU64;
pub const put = json.put;
pub const append = json.append;
pub const stringField = json.stringField;
pub const unsignedField = json.unsignedField;
pub const positiveField = json.positiveField;
pub const objectValue = json.objectValue;
pub const objectPointer = json.objectPointer;
pub const exactKeys = json.exactKeys;
pub const digestField = json.digestField;
pub const hexAlloc = json.hexAlloc;
pub const putDigest = json.putDigest;

pub const Action = enum {
    describe,
    derive,
    build,
    cold_open,
    close_lease,
    shutdown,

    pub fn wireName(self: Action) []const u8 {
        return switch (self) {
            .describe => "describe",
            .derive => "derive",
            .build => "build",
            .cold_open => "coldOpen",
            .close_lease => "closeLease",
            .shutdown => "shutdown",
        };
    }

    pub fn parse(value: []const u8) !Action {
        inline for (std.meta.tags(Action)) |candidate| {
            if (std.mem.eql(u8, value, candidate.wireName())) return candidate;
        }
        return error.UnsupportedWorkerAction;
    }
};

pub const Request = struct {
    sequence: u64,
    action: Action,
    payload: Json,
};

pub const ParsedRequest = struct {
    parsed: std.json.Parsed(Json),
    request: Request,

    pub fn deinit(self: *ParsedRequest) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub const Dependency = struct {
    node_id: []const u8,
    role: u32,
    ordinal: u32,
};

pub const SemanticAuthorities = struct {
    protocol_identity_sha256: Digest,
    program_identity_sha256: Digest,
    profile_identity_sha256: Digest,
    pcs_identity_sha256: Digest,
    security_identity_sha256: Digest,
    statement_identity_sha256: Digest,
    provider_identity_sha256: Digest,
    layout_identity_sha256: Digest,
    registry_identity_sha256: Digest,
};

pub const ExecutionAuthorities = struct {
    producer_identity_sha256: Digest,
    verifier_identity_sha256: Digest,
    source_identity_sha256: Digest,
    build_identity_sha256: Digest,
    executable_identity_sha256: Digest,
    toolchain_identity_sha256: Digest,
    backend_identity_sha256: Digest,
    optimization_identity_sha256: Digest,
    worker_policy_identity_sha256: Digest,
    memory_policy_identity_sha256: Digest,
    retention_policy_identity_sha256: Digest,
    timeout_policy_identity_sha256: Digest,

    pub fn fields(
        self: ExecutionAuthorities,
        semantic_identity: Digest,
    ) artifact_store.ExecutionKeyFieldsV1 {
        return .{
            .semantic_key_identity = semantic_identity,
            .producer_identity = self.producer_identity_sha256,
            .verifier_identity = self.verifier_identity_sha256,
            .source_identity = self.source_identity_sha256,
            .build_identity = self.build_identity_sha256,
            .executable_identity = self.executable_identity_sha256,
            .toolchain_identity = self.toolchain_identity_sha256,
            .backend_identity = self.backend_identity_sha256,
            .optimization_identity = self.optimization_identity_sha256,
            .worker_policy_identity = self.worker_policy_identity_sha256,
            .memory_policy_identity = self.memory_policy_identity_sha256,
            .retention_policy_identity = self.retention_policy_identity_sha256,
            .timeout_policy_identity = self.timeout_policy_identity_sha256,
        };
    }
};

pub const Node = struct {
    node_id: []const u8,
    stage_kind: artifact_store.StageKindV1,
    stage_schema_version: u16,
    adapter: []const u8,
    dependencies: []Dependency,
    external_inputs: []artifact_store.InputRefV1,
    local_task_identity_sha256: Digest,
    semantic_authorities: SemanticAuthorities,
    semantic_options: Json,
    cpu_tokens: u64,
    rss_tokens: u64,
    output_kind: artifact_store.ArtifactKindV1,
    output_schema_version: u16,
};

pub const StageDescription = struct {
    stage_kind: artifact_store.StageKindV1,
    stage_schema_version: u16,
    output_kind: artifact_store.ArtifactKindV1,
    output_schema_version: u16,
    minimum_cpu_tokens: u64,
    minimum_rss_tokens: u64,
    root_cold_open_transitive: bool,
};

pub fn parseRequest(
    allocator: std.mem.Allocator,
    line: []const u8,
    expected_sequence: u64,
) !ParsedRequest {
    if (line.len == 0 or line.len > max_frame_bytes)
        return error.InvalidWorkerFrame;
    var parsed = std.json.parseFromSlice(Json, allocator, line, .{
        .parse_numbers = true,
    }) catch return error.NonCanonicalWorkerFrame;
    errdefer parsed.deinit();
    const canonical = try canonicalAlloc(allocator, parsed.value, false);
    defer allocator.free(canonical);
    if (canonical.len != line.len + 1 or
        !std.mem.eql(u8, canonical[0..line.len], line) or
        canonical[line.len] != '\n')
    {
        return error.NonCanonicalWorkerFrame;
    }
    const root_object = try objectValue(parsed.value);
    try exactKeys(root_object, &.{
        "schema",
        "sequence",
        "action",
        "payload",
        "content_sha256",
    });
    try expectString(root_object, "schema", request_schema);
    try validateSeal(allocator, root_object);
    const sequence = try unsignedField(u64, root_object, "sequence");
    if (sequence != expected_sequence) return error.InvalidWorkerSequence;
    const action = try Action.parse(try stringField(root_object, "action"));
    const payload = root_object.get("payload") orelse
        return error.MissingWorkerField;
    _ = try objectValue(payload);
    return .{
        .parsed = parsed,
        .request = .{ .sequence = sequence, .action = action, .payload = payload },
    };
}

pub fn parseNode(
    allocator: std.mem.Allocator,
    value: Json,
) !Node {
    const node_object = try objectValue(value);
    try exactKeys(node_object, &.{
        "node_id",
        "stage_kind",
        "stage_schema_version",
        "adapter",
        "dependencies",
        "external_inputs",
        "local_task_identity_sha256",
        "semantic_authorities",
        "semantic_options",
        "cpu_tokens",
        "rss_tokens",
        "output_kind",
        "output_schema_version",
    });
    const node_id = try stringField(node_object, "node_id");
    try validateNodeId(node_id);
    const adapter = try stringField(node_object, "adapter");
    if (adapter.len == 0) return error.InvalidWorkerNode;
    const dependencies_value = node_object.get("dependencies") orelse
        return error.MissingWorkerField;
    if (dependencies_value != .array) return error.InvalidWorkerNode;
    const dependencies = try allocator.alloc(
        Dependency,
        dependencies_value.array.items.len,
    );
    for (dependencies_value.array.items, 0..) |item, index| {
        const dependency = try objectValue(item);
        try exactKeys(dependency, &.{ "node_id", "role", "ordinal" });
        dependencies[index] = .{
            .node_id = try stringField(dependency, "node_id"),
            .role = try positiveField(u32, dependency, "role"),
            .ordinal = try unsignedField(u32, dependency, "ordinal"),
        };
        try validateNodeId(dependencies[index].node_id);
    }
    try validateDependencyUniqueness(dependencies);
    const external_value = node_object.get("external_inputs") orelse
        return error.MissingWorkerField;
    const external_inputs = try parseInputRefs(allocator, external_value);
    return .{
        .node_id = node_id,
        .stage_kind = @enumFromInt(try positiveField(u32, node_object, "stage_kind")),
        .stage_schema_version = try positiveField(
            u16,
            node_object,
            "stage_schema_version",
        ),
        .adapter = adapter,
        .dependencies = dependencies,
        .external_inputs = external_inputs,
        .local_task_identity_sha256 = try digestField(
            node_object,
            "local_task_identity_sha256",
            true,
        ),
        .semantic_authorities = try parseSemanticAuthorities(
            node_object.get("semantic_authorities") orelse
                return error.MissingWorkerField,
        ),
        .semantic_options = node_object.get("semantic_options") orelse
            return error.MissingWorkerField,
        .cpu_tokens = try positiveField(u64, node_object, "cpu_tokens"),
        .rss_tokens = try positiveField(u64, node_object, "rss_tokens"),
        .output_kind = @enumFromInt(try positiveField(
            u32,
            node_object,
            "output_kind",
        )),
        .output_schema_version = try positiveField(
            u16,
            node_object,
            "output_schema_version",
        ),
    };
}

pub fn parseInputRefs(
    allocator: std.mem.Allocator,
    value: Json,
) ![]artifact_store.InputRefV1 {
    if (value != .array) return error.InvalidWorkerInputReferences;
    const result = try allocator.alloc(
        artifact_store.InputRefV1,
        value.array.items.len,
    );
    for (value.array.items, 0..) |item, index| {
        const input_object = try objectValue(item);
        try exactKeys(input_object, &.{ "role", "ordinal", "blob" });
        result[index] = .{
            .role = @enumFromInt(try positiveField(u32, input_object, "role")),
            .ordinal = try unsignedField(u32, input_object, "ordinal"),
            .blob = try parseBlobRef(input_object.get("blob") orelse
                return error.MissingWorkerField),
        };
    }
    try artifact_store.types.validateOrderedInputs(result);
    return result;
}

pub fn parseBlobRef(value: Json) !artifact_store.BlobRefV1 {
    const ref_object = try objectValue(value);
    try exactKeys(ref_object, &.{
        "kind",
        "format_version",
        "schema_version",
        "byte_count",
        "sha256",
    });
    const result = artifact_store.BlobRefV1{
        .kind = @enumFromInt(try positiveField(u32, ref_object, "kind")),
        .format_version = try positiveField(u16, ref_object, "format_version"),
        .schema_version = try positiveField(u16, ref_object, "schema_version"),
        .byte_count = try unsignedField(u64, ref_object, "byte_count"),
        .sha256 = try digestField(ref_object, "sha256", true),
    };
    try result.validate();
    return result;
}

pub fn parseExecutionAuthorities(value: Json) !ExecutionAuthorities {
    const authority_object = try objectValue(value);
    try exactKeysForStruct(ExecutionAuthorities, authority_object);
    var result: ExecutionAuthorities = undefined;
    inline for (@typeInfo(ExecutionAuthorities).@"struct".fields) |field| {
        @field(result, field.name) = try digestField(
            authority_object,
            field.name,
            true,
        );
    }
    return result;
}

pub fn parseSemanticKey(
    allocator: std.mem.Allocator,
    value: Json,
) !artifact_store.SemanticKeyV1 {
    const object = try objectValue(value);
    try exactKeys(object, &.{
        "schema",
        "format_version",
        "campaign_namespace_sha256",
        "stage_kind",
        "stage_schema_version",
        "local_task_identity_sha256",
        "protocol_identity_sha256",
        "program_identity_sha256",
        "profile_identity_sha256",
        "pcs_identity_sha256",
        "security_identity_sha256",
        "statement_identity_sha256",
        "provider_identity_sha256",
        "layout_identity_sha256",
        "registry_identity_sha256",
        "ordered_inputs",
        "semantic_options_identity_sha256",
        "identity_sha256",
    });
    try expectString(object, "schema", semantic_schema);
    const fields = artifact_store.SemanticKeyFieldsV1{
        .stage_kind = @enumFromInt(try positiveField(u32, object, "stage_kind")),
        .stage_schema_version = try positiveField(
            u16,
            object,
            "stage_schema_version",
        ),
        .campaign_namespace = try digestField(
            object,
            "campaign_namespace_sha256",
            true,
        ),
        .local_task_identity = try digestField(
            object,
            "local_task_identity_sha256",
            true,
        ),
        .protocol_identity = try digestField(
            object,
            "protocol_identity_sha256",
            true,
        ),
        .program_identity = try digestField(
            object,
            "program_identity_sha256",
            true,
        ),
        .profile_identity = try digestField(
            object,
            "profile_identity_sha256",
            true,
        ),
        .pcs_identity = try digestField(object, "pcs_identity_sha256", true),
        .security_identity = try digestField(
            object,
            "security_identity_sha256",
            true,
        ),
        .statement_identity = try digestField(
            object,
            "statement_identity_sha256",
            false,
        ),
        .provider_identity = try digestField(
            object,
            "provider_identity_sha256",
            false,
        ),
        .layout_identity = try digestField(
            object,
            "layout_identity_sha256",
            false,
        ),
        .registry_identity = try digestField(
            object,
            "registry_identity_sha256",
            false,
        ),
        .semantic_options_identity = try digestField(
            object,
            "semantic_options_identity_sha256",
            false,
        ),
        .ordered_inputs = try parseInputRefs(
            allocator,
            object.get("ordered_inputs") orelse return error.MissingWorkerField,
        ),
    };
    if (try positiveField(u16, object, "format_version") !=
        artifact_store.types.format_version_v1)
    {
        return error.InvalidWorkerSemanticKey;
    }
    const result = artifact_store.SemanticKeyV1{
        .fields = fields,
        .identity = try digestField(object, "identity_sha256", true),
    };
    try result.validate(allocator);
    return result;
}

pub fn parseExecutionKey(value: Json) !artifact_store.ExecutionKeyV1 {
    const object = try objectValue(value);
    try exactKeys(object, &.{
        "schema",
        "format_version",
        "semantic_key_identity_sha256",
        "producer_identity_sha256",
        "verifier_identity_sha256",
        "source_identity_sha256",
        "build_identity_sha256",
        "executable_identity_sha256",
        "toolchain_identity_sha256",
        "backend_identity_sha256",
        "optimization_identity_sha256",
        "worker_policy_identity_sha256",
        "memory_policy_identity_sha256",
        "retention_policy_identity_sha256",
        "timeout_policy_identity_sha256",
        "identity_sha256",
    });
    try expectString(object, "schema", execution_schema);
    if (try positiveField(u16, object, "format_version") !=
        artifact_store.types.format_version_v1)
    {
        return error.InvalidWorkerExecutionKey;
    }
    const authorities = try parseExecutionAuthoritiesFromObject(object);
    const result = artifact_store.ExecutionKeyV1{
        .fields = authorities.fields(try digestField(
            object,
            "semantic_key_identity_sha256",
            true,
        )),
        .identity = try digestField(object, "identity_sha256", true),
    };
    try result.validate();
    return result;
}

pub fn semanticProjection(
    allocator: std.mem.Allocator,
    value: artifact_store.SemanticKeyV1,
) !Json {
    var result = jsonObject(allocator);
    try put(&result, "schema", string(semantic_schema));
    try put(
        &result,
        "format_version",
        integer(artifact_store.types.format_version_v1),
    );
    try putDigest(allocator, &result, "campaign_namespace_sha256", value.fields.campaign_namespace);
    try put(&result, "stage_kind", integer(@intFromEnum(value.fields.stage_kind)));
    try put(&result, "stage_schema_version", integer(value.fields.stage_schema_version));
    try putDigest(allocator, &result, "local_task_identity_sha256", value.fields.local_task_identity);
    try putDigest(allocator, &result, "protocol_identity_sha256", value.fields.protocol_identity);
    try putDigest(allocator, &result, "program_identity_sha256", value.fields.program_identity);
    try putDigest(allocator, &result, "profile_identity_sha256", value.fields.profile_identity);
    try putDigest(allocator, &result, "pcs_identity_sha256", value.fields.pcs_identity);
    try putDigest(allocator, &result, "security_identity_sha256", value.fields.security_identity);
    try putDigest(allocator, &result, "statement_identity_sha256", value.fields.statement_identity);
    try putDigest(allocator, &result, "provider_identity_sha256", value.fields.provider_identity);
    try putDigest(allocator, &result, "layout_identity_sha256", value.fields.layout_identity);
    try putDigest(allocator, &result, "registry_identity_sha256", value.fields.registry_identity);
    try put(&result, "ordered_inputs", try inputRefsValue(allocator, value.fields.ordered_inputs));
    try putDigest(allocator, &result, "semantic_options_identity_sha256", value.fields.semantic_options_identity);
    try putDigest(allocator, &result, "identity_sha256", value.identity);
    return result;
}

pub fn executionProjection(
    allocator: std.mem.Allocator,
    value: artifact_store.ExecutionKeyV1,
) !Json {
    var result = jsonObject(allocator);
    try put(&result, "schema", string(execution_schema));
    try put(&result, "format_version", integer(1));
    try putDigest(allocator, &result, "semantic_key_identity_sha256", value.fields.semantic_key_identity);
    inline for (.{
        .{ "producer_identity_sha256", value.fields.producer_identity },
        .{ "verifier_identity_sha256", value.fields.verifier_identity },
        .{ "source_identity_sha256", value.fields.source_identity },
        .{ "build_identity_sha256", value.fields.build_identity },
        .{ "executable_identity_sha256", value.fields.executable_identity },
        .{ "toolchain_identity_sha256", value.fields.toolchain_identity },
        .{ "backend_identity_sha256", value.fields.backend_identity },
        .{ "optimization_identity_sha256", value.fields.optimization_identity },
        .{ "worker_policy_identity_sha256", value.fields.worker_policy_identity },
        .{ "memory_policy_identity_sha256", value.fields.memory_policy_identity },
        .{ "retention_policy_identity_sha256", value.fields.retention_policy_identity },
        .{ "timeout_policy_identity_sha256", value.fields.timeout_policy_identity },
    }) |field| try putDigest(allocator, &result, field[0], field[1]);
    try putDigest(allocator, &result, "identity_sha256", value.identity);
    return result;
}

pub fn blobRefValue(
    allocator: std.mem.Allocator,
    value: artifact_store.BlobRefV1,
) !Json {
    var result = jsonObject(allocator);
    try put(&result, "kind", integer(@intFromEnum(value.kind)));
    try put(&result, "format_version", integer(value.format_version));
    try put(&result, "schema_version", integer(value.schema_version));
    try put(
        &result,
        "byte_count",
        try integerU64(allocator, value.byte_count),
    );
    try putDigest(allocator, &result, "sha256", value.sha256);
    return result;
}

/// Canonical request-side projection paired with `parseNode`. Slices remain
/// borrowed by the JSON arena and no process-local lease payload enters it.
pub fn nodeValue(
    allocator: std.mem.Allocator,
    node: Node,
) !Json {
    var result = jsonObject(allocator);
    try put(&result, "node_id", string(node.node_id));
    try put(&result, "stage_kind", integer(@intFromEnum(node.stage_kind)));
    try put(
        &result,
        "stage_schema_version",
        integer(node.stage_schema_version),
    );
    try put(&result, "adapter", string(node.adapter));
    var dependencies = array(allocator);
    for (node.dependencies) |dependency| {
        var value = jsonObject(allocator);
        try put(&value, "node_id", string(dependency.node_id));
        try put(&value, "role", integer(dependency.role));
        try put(&value, "ordinal", integer(dependency.ordinal));
        try append(&dependencies, value);
    }
    try put(&result, "dependencies", dependencies);
    try put(
        &result,
        "external_inputs",
        try inputRefsValue(allocator, node.external_inputs),
    );
    try putDigest(
        allocator,
        &result,
        "local_task_identity_sha256",
        node.local_task_identity_sha256,
    );
    try put(
        &result,
        "semantic_authorities",
        try semanticAuthoritiesValue(allocator, node.semantic_authorities),
    );
    try put(&result, "semantic_options", node.semantic_options);
    try put(
        &result,
        "cpu_tokens",
        try integerU64(allocator, node.cpu_tokens),
    );
    try put(
        &result,
        "rss_tokens",
        try integerU64(allocator, node.rss_tokens),
    );
    try put(
        &result,
        "output_kind",
        integer(@intFromEnum(node.output_kind)),
    );
    try put(
        &result,
        "output_schema_version",
        integer(node.output_schema_version),
    );
    return result;
}

pub fn semanticAuthoritiesValue(
    allocator: std.mem.Allocator,
    value: SemanticAuthorities,
) !Json {
    var result = jsonObject(allocator);
    inline for (.{
        .{ "protocol_identity_sha256", value.protocol_identity_sha256 },
        .{ "program_identity_sha256", value.program_identity_sha256 },
        .{ "profile_identity_sha256", value.profile_identity_sha256 },
        .{ "pcs_identity_sha256", value.pcs_identity_sha256 },
        .{ "security_identity_sha256", value.security_identity_sha256 },
        .{ "statement_identity_sha256", value.statement_identity_sha256 },
        .{ "provider_identity_sha256", value.provider_identity_sha256 },
        .{ "layout_identity_sha256", value.layout_identity_sha256 },
        .{ "registry_identity_sha256", value.registry_identity_sha256 },
    }) |field| try putDigest(allocator, &result, field[0], field[1]);
    return result;
}

pub fn descriptionValue(
    allocator: std.mem.Allocator,
    value: StageDescription,
) !Json {
    var result = jsonObject(allocator);
    try put(&result, "schema", string(description_schema));
    try put(&result, "stage_kind", integer(@intFromEnum(value.stage_kind)));
    try put(&result, "stage_schema_version", integer(value.stage_schema_version));
    try put(&result, "output_kind", integer(@intFromEnum(value.output_kind)));
    try put(&result, "output_schema_version", integer(value.output_schema_version));
    try put(
        &result,
        "minimum_cpu_tokens",
        try integerU64(allocator, value.minimum_cpu_tokens),
    );
    try put(
        &result,
        "minimum_rss_tokens",
        try integerU64(allocator, value.minimum_rss_tokens),
    );
    try put(&result, "root_cold_open_transitive", .{ .bool = value.root_cold_open_transitive });
    try sealObject(allocator, &result);
    return result;
}

pub fn writeResponse(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    sequence: u64,
    action: Action,
    status: []const u8,
    payload: Json,
) !void {
    var result = jsonObject(allocator);
    try put(&result, "schema", string(response_schema));
    try put(&result, "sequence", try integerU64(allocator, sequence));
    try put(&result, "action", string(action.wireName()));
    try put(&result, "status", string(status));
    try put(&result, "payload", payload);
    try sealObject(allocator, &result);
    const encoded = try canonicalAlloc(allocator, result, false);
    defer allocator.free(encoded);
    try writer.writeAll(encoded);
    try writer.flush();
}

pub fn errorPayload(
    allocator: std.mem.Allocator,
    err: anyerror,
) !Json {
    var result = jsonObject(allocator);
    try put(&result, "error", string(@errorName(err)));
    try put(&result, "consumed_lease_ids", array(allocator));
    return result;
}

fn parseSemanticAuthorities(value: Json) !SemanticAuthorities {
    const object_map = try objectValue(value);
    try exactKeysForStruct(SemanticAuthorities, object_map);
    var result: SemanticAuthorities = undefined;
    inline for (@typeInfo(SemanticAuthorities).@"struct".fields) |field| {
        @field(result, field.name) = try digestField(
            object_map,
            field.name,
            false,
        );
    }
    return result;
}

fn parseExecutionAuthoritiesFromObject(
    object_map: std.json.ObjectMap,
) !ExecutionAuthorities {
    var result: ExecutionAuthorities = undefined;
    inline for (@typeInfo(ExecutionAuthorities).@"struct".fields) |field| {
        @field(result, field.name) = try digestField(
            object_map,
            field.name,
            true,
        );
    }
    return result;
}

fn exactKeysForStruct(
    comptime T: type,
    object_map: std.json.ObjectMap,
) !void {
    const fields = @typeInfo(T).@"struct".fields;
    if (object_map.count() != fields.len) return error.InvalidWorkerFields;
    inline for (fields) |field| if (!object_map.contains(field.name))
        return error.InvalidWorkerFields;
}

fn expectString(
    object_map: std.json.ObjectMap,
    name: []const u8,
    expected: []const u8,
) !void {
    if (!std.mem.eql(u8, try stringField(object_map, name), expected))
        return error.InvalidWorkerField;
}

pub fn inputRefsValue(
    allocator: std.mem.Allocator,
    values: []const artifact_store.InputRefV1,
) !Json {
    var result = array(allocator);
    for (values) |value| {
        var item = jsonObject(allocator);
        try put(&item, "role", integer(@intFromEnum(value.role)));
        try put(&item, "ordinal", integer(value.ordinal));
        try put(&item, "blob", try blobRefValue(allocator, value.blob));
        try append(&result, item);
    }
    return result;
}

fn validateDependencyUniqueness(values: []const Dependency) !void {
    for (values, 0..) |value, index| {
        for (values[0..index]) |previous| {
            if (std.mem.eql(u8, value.node_id, previous.node_id) or
                (value.role == previous.role and value.ordinal == previous.ordinal))
            {
                return error.InvalidWorkerDependencies;
            }
        }
    }
}

fn validateNodeId(value: []const u8) !void {
    if (value.len == 0 or !std.ascii.isAlphanumeric(value[0]))
        return error.InvalidWorkerNode;
    for (value[1..]) |byte| if (!std.ascii.isAlphanumeric(byte) and
        byte != '_' and byte != '/' and byte != '-')
    {
        return error.InvalidWorkerNode;
    };
}

comptime {
    if (artifact_store.BlobRefV1.canonical_size != 48 or
        @intFromEnum(artifact_store.ArtifactKindV1.stage_manifest) != 4)
    {
        @compileError("recursive pipeline worker artifact contract drifted");
    }
}
