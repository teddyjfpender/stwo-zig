//! Advertised but deliberately unavailable production omitted-leaf adapter.
//!
//! The compact execution-to-prover bridge is not frozen yet. Describing this
//! stage lets the scheduler fail before allocating work for an unsupported
//! shape, while build and cold-open can never fabricate an admission result.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

pub const adapter_name = "native_omitted_leaf";

pub const Adapter = struct {
    pub const name = adapter_name;
    pub const production = false;
    pub const available = false;
    pub const LeasePayload = struct {};

    pub fn acceptsNodeAdapter(value: []const u8) bool {
        return std.mem.eql(u8, value, adapter_name) or
            std.mem.eql(u8, value, "zig-worker-v1");
    }

    pub fn describe(
        stage_kind: artifact_store.StageKindV1,
        stage_schema_version: u16,
    ) !protocol.StageDescription {
        if (stage_kind != .prove or
            (stage_schema_version != 1 and stage_schema_version != 101))
            return error.UnsupportedRecursivePipelineStage;
        return .{
            .stage_kind = stage_kind,
            .stage_schema_version = stage_schema_version,
            .output_kind = .proof_artifact,
            .output_schema_version = 1,
            .minimum_cpu_tokens = 1,
            .minimum_rss_tokens = 1,
            .root_cold_open_transitive = true,
        };
    }

    pub fn unavailable() error{NativeOmittedLeafBridgeUnavailable} {
        return error.NativeOmittedLeafBridgeUnavailable;
    }

    pub fn buildOutput(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
    ) ![]u8 {
        return unavailable();
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
        return unavailable();
    }

    pub fn profileValue(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.ExecutionKeyV1,
        _: u64,
    ) !protocol.Json {
        return unavailable();
    }

    pub fn validateOutput(
        _: std.mem.Allocator,
        _: []const u8,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
    ) !void {
        return unavailable();
    }

    pub fn coldOpenLease(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: []const u8,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
    ) !LeasePayload {
        return unavailable();
    }

    pub fn deinitLeasePayload(
        _: *LeasePayload,
        _: std.mem.Allocator,
    ) void {}

    pub fn validationValue(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.BlobRefV1,
        _: u32,
        _: []const u8,
    ) !protocol.Json {
        return unavailable();
    }
};

comptime {
    if (Adapter.production)
        @compileError("native omitted-leaf bridge is not production-admitted");
}
