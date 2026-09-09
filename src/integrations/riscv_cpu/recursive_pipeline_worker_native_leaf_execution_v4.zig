//! ExecutionKey-aware additive Stage-101 worker adapter.
//!
//! The legacy native-leaf adapter and its proof bytes remain unchanged. This
//! wrapper requires a process-local execution-policy provider, binds that
//! policy to the full canonical ExecutionKey and node resource reservation,
//! then passes one strict CPU request to the existing Stage-101 producer.
//! Cold verification remains policy-independent and always remints freshness.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const prover_api = @import("stwo_prover_api");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const native = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const EXECUTION_KEY_REQUIRED = true;
pub const STRICT_CPU_REQUEST_REQUIRED = true;

pub const Error = error{
    NativeLeafStage101ExecutionAuthorityUnavailableV4,
    NativeLeafStage101ExecutionAuthorityMismatchV4,
    NativeLeafStage101ExecutionResourceOverflowV4,
};

pub fn AdapterFor(
    comptime Engine: type,
    comptime PolicyProvider: type,
) type {
    assertPolicyProvider(PolicyProvider);
    const Base = native.AdapterForEngine(Engine);
    return struct {
        pub const available = false;
        pub const production = PRODUCTION_ACTIVATION;
        pub const execution_path_ready = Base.available and
            PolicyProvider.available;
        pub const LeasePayload = Base.LeasePayload;
        pub const maximum_output_bytes = Base.maximum_output_bytes;

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return Base.acceptsNodeAdapter(value);
        }

        pub fn unavailable() error{NativeLeafStage101ExecutionAuthorityUnavailableV4} {
            return error.NativeLeafStage101ExecutionAuthorityUnavailableV4;
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            return Base.describe(stage_kind, stage_schema_version);
        }

        pub fn buildOutputWithLeases(
            _: std.mem.Allocator,
            _: *artifact_store.Store,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
            _: []const *const LeasePayload,
        ) ![]u8 {
            return error.NativeLeafStage101ExecutionAuthorityUnavailableV4;
        }

        pub fn buildOutputWithExecutionAndLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            _: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            if (dependency_leases.len != 0)
                return error.NativeLeafStage101ExecutionAuthorityMismatchV4;
            const request = try executionRequest(
                PolicyProvider,
                allocator,
                node,
                semantic,
                execution,
            );
            return native.buildOutputWithExecutionForEngine(
                Engine,
                allocator,
                store,
                node,
                semantic,
                ordered_inputs,
                .{ .cpu = request },
            );
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            const request = try executionRequest(
                PolicyProvider,
                allocator,
                node,
                semantic,
                execution,
            );
            var value = protocol.jsonObject(allocator);
            try protocol.put(
                &value,
                "schema",
                protocol.string(native.profile_schema),
            );
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
            try protocol.putDigest(
                allocator,
                &value,
                "worker_policy_sha256",
                execution.fields.worker_policy_identity,
            );
            try protocol.putDigest(
                allocator,
                &value,
                "memory_policy_sha256",
                execution.fields.memory_policy_identity,
            );
            try protocol.put(
                &value,
                "worker_count",
                try protocol.integerU64(
                    allocator,
                    @as(u64, @intCast(request.worker_count)),
                ),
            );
            try protocol.put(
                &value,
                "host_byte_budget",
                try protocol.integerU64(
                    allocator,
                    @as(u64, @intCast(request.host_byte_budget)),
                ),
            );
            try protocol.put(
                &value,
                "candidate_ordinal",
                try protocol.integerU64(allocator, candidate_ordinal),
            );
            try protocol.put(&value, "vm_reexecution", .{ .bool = false });
            try protocol.put(&value, "production", .{ .bool = false });
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
            return Base.validateOutput(
                allocator,
                bytes,
                node,
                semantic,
                ordered_inputs,
            );
        }

        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            return Base.coldOpenLease(
                allocator,
                store,
                bytes,
                node,
                semantic,
                ordered_inputs,
            );
        }

        pub fn validationValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            output_ref: artifact_store.BlobRefV1,
            validator_version: u32,
            mode: []const u8,
        ) !protocol.Json {
            return Base.validationValue(
                allocator,
                node,
                semantic,
                output_ref,
                validator_version,
                mode,
            );
        }

        pub fn deinitLeasePayload(
            payload: *LeasePayload,
            allocator: std.mem.Allocator,
        ) void {
            Base.deinitLeasePayload(payload, allocator);
        }
    };
}

fn executionRequest(
    comptime Provider: type,
    allocator: std.mem.Allocator,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
) !prover_api.CpuCompositionExecutionRequest {
    try semantic.validate(allocator);
    try execution.validate();
    if (!std.mem.eql(
        u8,
        &execution.fields.semantic_key_identity,
        &semantic.identity,
    )) return error.NativeLeafStage101ExecutionAuthorityMismatchV4;
    const policy = try Provider.policyForExecution(execution);
    try policy.validateAgainstExecution(execution);
    if (node.cpu_tokens != @as(u64, policy.cpu_tokens_per_node) or
        node.rss_tokens != policy.rss_bytes_per_node)
    {
        return error.NativeLeafStage101ExecutionAuthorityMismatchV4;
    }
    return .{
        .worker_count = try policy.engineWorkerCount(),
        .host_byte_budget = std.math.cast(
            usize,
            policy.rss_bytes_per_node,
        ) orelse return error.NativeLeafStage101ExecutionResourceOverflowV4,
        .contention_policy = .strict,
    };
}

fn assertPolicyProvider(comptime Provider: type) void {
    inline for (.{ "available", "policyForExecution" }) |name|
        if (!@hasDecl(Provider, name))
            @compileError("native Stage101 execution provider missing " ++ name);
}

pub const UnavailableExecutionPolicyProviderV4 = struct {
    pub const available = false;

    pub fn policyForExecution(
        _: artifact_store.ExecutionKeyV1,
    ) error{NativeLeafStage101ExecutionAuthorityUnavailableV4}!policy_mod.PolicyV2 {
        return error.NativeLeafStage101ExecutionAuthorityUnavailableV4;
    }
};

pub const testing = struct {
    pub const executionRequestV4 = executionRequest;
};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !EXECUTION_KEY_REQUIRED or
        !STRICT_CPU_REQUEST_REQUIRED)
    {
        @compileError("native Stage101 execution adapter drifted");
    }
}
