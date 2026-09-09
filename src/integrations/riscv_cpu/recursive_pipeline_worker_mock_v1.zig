//! Test-only recursive stage adapter for the persistent worker.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

pub const adapter_name = "mock";
pub const output_schema = "stwo.recursive-pipeline-mock-output.v1";
pub const profile_schema = "stwo.recursive-pipeline-mock-profile.v1";
pub const validation_schema = "stwo.recursive-pipeline-mock-validation.v1";

pub const Adapter = struct {
    pub const name = adapter_name;
    pub const production = false;
    pub const available = true;

    /// Test analogue of a verifier-owned fresh capability. The production
    /// adapters retain their actual decoded proof/capture owners here.
    pub const LeasePayload = struct {
        semantic_key_identity: artifact_store.Digest,
        node_identity: artifact_store.Digest,
    };

    pub fn acceptsNodeAdapter(value: []const u8) bool {
        return std.mem.eql(u8, value, adapter_name) or
            std.mem.eql(u8, value, "zig-worker-v1");
    }

    pub fn describe(
        stage_kind: artifact_store.StageKindV1,
        stage_schema_version: u16,
    ) !protocol.StageDescription {
        const output_kind: artifact_store.ArtifactKindV1 = switch (stage_schema_version) {
            1 => if (stage_kind == .prove or stage_kind == .fold)
                .recursion_node
            else
                return error.UnsupportedRecursivePipelineStage,
            101, 105 => if (stage_kind == .prove or stage_kind == .verify)
                .proof_artifact
            else
                return error.UnsupportedRecursivePipelineStage,
            102, 103 => if (stage_kind == .prove)
                .recursion_node
            else
                return error.UnsupportedRecursivePipelineStage,
            104 => if (stage_kind == .fold)
                .recursion_node
            else
                return error.UnsupportedRecursivePipelineStage,
            106, 107 => if (stage_kind == .verify)
                .recursion_node
            else
                return error.UnsupportedRecursivePipelineStage,
            else => return error.UnsupportedRecursivePipelineStage,
        };
        return .{
            .stage_kind = stage_kind,
            .stage_schema_version = stage_schema_version,
            .output_kind = output_kind,
            .output_schema_version = if (output_kind == .recursion_node)
                2
            else
                1,
            .minimum_cpu_tokens = 1,
            .minimum_rss_tokens = 1,
            .root_cold_open_transitive = true,
        };
    }

    pub fn buildOutput(
        allocator: std.mem.Allocator,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
        candidate_ordinal: u64,
    ) ![]u8 {
        try validateNode(node);
        var value = protocol.jsonObject(allocator);
        try protocol.put(&value, "schema", protocol.string(output_schema));
        try protocol.put(&value, "node_id", protocol.string(node.node_id));
        try protocol.putDigest(
            allocator,
            &value,
            "semantic_key_sha256",
            semantic.identity,
        );
        try protocol.put(
            &value,
            "candidate_ordinal",
            try protocol.integerU64(allocator, candidate_ordinal),
        );
        var input_digests = protocol.array(allocator);
        for (ordered_inputs) |input| {
            try protocol.append(
                &input_digests,
                protocol.string(try protocol.hexAlloc(
                    allocator,
                    input.blob.sha256,
                )),
            );
        }
        try protocol.put(&value, "ordered_input_sha256", input_digests);
        return protocol.canonicalAlloc(allocator, value, false);
    }

    pub fn buildOutputWithLeases(
        allocator: std.mem.Allocator,
        _: *artifact_store.Store,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
        candidate_ordinal: u64,
        dependency_leases: []const *const LeasePayload,
    ) ![]u8 {
        if (dependency_leases.len != node.dependencies.len)
            return error.InvalidMockRecursiveLeaseShape;
        for (dependency_leases) |lease| {
            if (std.mem.allEqual(u8, &lease.semantic_key_identity, 0) or
                std.mem.allEqual(u8, &lease.node_identity, 0))
            {
                return error.InvalidMockRecursiveLease;
            }
        }
        return buildOutput(
            allocator,
            node,
            semantic,
            ordered_inputs,
            candidate_ordinal,
        );
    }

    pub fn profileValue(
        allocator: std.mem.Allocator,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        execution: artifact_store.ExecutionKeyV1,
        candidate_ordinal: u64,
    ) !protocol.Json {
        var value = protocol.jsonObject(allocator);
        try protocol.put(&value, "schema", protocol.string(profile_schema));
        try protocol.put(&value, "node_id", protocol.string(node.node_id));
        try protocol.putDigest(
            allocator,
            &value,
            "semantic_key_sha256",
            semantic.identity,
        );
        try protocol.putDigest(
            allocator,
            &value,
            "execution_key_sha256",
            execution.identity,
        );
        try protocol.put(&value, "wall_ns", protocol.integer(1));
        try protocol.put(&value, "user_ns", protocol.integer(0));
        try protocol.put(&value, "system_ns", protocol.integer(0));
        try protocol.put(
            &value,
            "peak_rss_bytes",
            try protocol.integerU64(allocator, node.rss_tokens),
        );
        try protocol.put(
            &value,
            "cpu_tokens",
            try protocol.integerU64(allocator, node.cpu_tokens),
        );
        try protocol.put(&value, "cache_status", protocol.string("executed"));
        try protocol.put(
            &value,
            "candidate_ordinal",
            try protocol.integerU64(allocator, candidate_ordinal),
        );
        try protocol.sealObject(allocator, &value);
        return value;
    }

    pub fn validateOutput(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
    ) !void {
        try validateNode(node);
        var parsed = try std.json.parseFromSlice(
            protocol.Json,
            allocator,
            bytes,
            .{ .parse_numbers = true },
        );
        defer parsed.deinit();
        const canonical = try protocol.canonicalAlloc(
            allocator,
            parsed.value,
            false,
        );
        defer allocator.free(canonical);
        if (!std.mem.eql(u8, canonical, bytes))
            return error.InvalidMockRecursiveOutput;
        const object = try protocol.objectValue(parsed.value);
        try protocol.exactKeys(object, &.{
            "schema",
            "node_id",
            "semantic_key_sha256",
            "candidate_ordinal",
            "ordered_input_sha256",
        });
        const observed_semantic = try protocol.digestField(
            object,
            "semantic_key_sha256",
            true,
        );
        _ = try protocol.positiveField(u64, object, "candidate_ordinal");
        if (!std.mem.eql(
            u8,
            try protocol.stringField(object, "schema"),
            output_schema,
        ) or !std.mem.eql(
            u8,
            try protocol.stringField(object, "node_id"),
            node.node_id,
        ) or !std.mem.eql(u8, &observed_semantic, &semantic.identity)) {
            return error.InvalidMockRecursiveOutput;
        }
        const digests = object.get("ordered_input_sha256") orelse
            return error.InvalidMockRecursiveOutput;
        if (digests != .array or digests.array.items.len != ordered_inputs.len)
            return error.InvalidMockRecursiveOutput;
        for (digests.array.items, ordered_inputs) |item, input| {
            if (item != .string or item.string.len != 64)
                return error.InvalidMockRecursiveOutput;
            var observed: artifact_store.Digest = undefined;
            _ = std.fmt.hexToBytes(&observed, item.string) catch
                return error.InvalidMockRecursiveOutput;
            if (!std.mem.eql(u8, &observed, &input.blob.sha256))
                return error.InvalidMockRecursiveOutput;
        }
    }

    pub fn coldOpenLease(
        allocator: std.mem.Allocator,
        _: *artifact_store.Store,
        bytes: []const u8,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
    ) !LeasePayload {
        try validateOutput(
            allocator,
            bytes,
            node,
            semantic,
            ordered_inputs,
        );
        return .{
            .semantic_key_identity = semantic.identity,
            .node_identity = artifact_store.digestBytes(node.node_id),
        };
    }

    pub fn deinitLeasePayload(
        payload: *LeasePayload,
        _: std.mem.Allocator,
    ) void {
        payload.* = undefined;
    }

    pub fn testingLeasePayload() LeasePayload {
        return .{
            .semantic_key_identity = artifact_store.digestBytes(
                "mock-semantic-key",
            ),
            .node_identity = artifact_store.digestBytes("mock-node"),
        };
    }

    pub fn validationValue(
        allocator: std.mem.Allocator,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        output_ref: artifact_store.BlobRefV1,
        validator_version: u32,
        mode: []const u8,
    ) !protocol.Json {
        var value = protocol.jsonObject(allocator);
        try protocol.put(&value, "schema", protocol.string(validation_schema));
        try protocol.put(&value, "node_id", protocol.string(node.node_id));
        try protocol.putDigest(
            allocator,
            &value,
            "semantic_key_sha256",
            semantic.identity,
        );
        try protocol.putDigest(
            allocator,
            &value,
            "output_sha256",
            output_ref.sha256,
        );
        try protocol.put(
            &value,
            "validator_version",
            protocol.integer(validator_version),
        );
        try protocol.put(&value, "mode", protocol.string(mode));
        try protocol.put(&value, "valid", .{ .bool = true });
        try protocol.sealObject(allocator, &value);
        return value;
    }

    fn validateNode(node: protocol.Node) !void {
        const description = try describe(
            node.stage_kind,
            node.stage_schema_version,
        );
        if (node.output_kind != description.output_kind or
            node.output_schema_version != description.output_schema_version or
            !acceptsNodeAdapter(node.adapter))
        {
            return error.InvalidMockRecursiveNode;
        }
    }
};
