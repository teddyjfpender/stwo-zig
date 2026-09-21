//! Additive build-callback dispatch for execution-aware worker adapters.
//!
//! Legacy adapters keep their frozen callback. New campaign adapters receive
//! the Zig-sealed ExecutionKey so they can validate execution-only CPU/RSS
//! policy before choosing prover workers. No execution field enters semantic
//! key derivation or proof authority through this helper.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

pub fn build(
    comptime Adapter: type,
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    inputs: []const artifact_store.InputRefV1,
    candidate_ordinal: u64,
    dependency_payloads: []const *const Adapter.LeasePayload,
) ![]u8 {
    if (comptime @hasDecl(Adapter, "buildOutputWithExecutionAndLeases")) {
        return Adapter.buildOutputWithExecutionAndLeases(
            allocator,
            store,
            node,
            semantic,
            execution,
            inputs,
            candidate_ordinal,
            dependency_payloads,
        );
    }
    return Adapter.buildOutputWithLeases(
        allocator,
        store,
        node,
        semantic,
        inputs,
        candidate_ordinal,
        dependency_payloads,
    );
}

/// Gate-only counterpart to `build`. The adapter must expose an exact-body
/// execution-aware callback returning its production output type. This helper
/// does not provide a legacy fallback: a genuine gate may bypass a release
/// boolean, but it may not bypass the sealed ExecutionKey authority.
pub fn buildForGenuineGate(
    comptime Adapter: type,
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    inputs: []const artifact_store.InputRefV1,
    candidate_ordinal: u64,
    dependency_payloads: []const *const Adapter.LeasePayload,
) ![]u8 {
    if (comptime !@hasDecl(
        Adapter,
        "buildOutputWithExecutionAndLeasesForGenuineGate",
    )) {
        @compileError(
            "genuine-gate worker adapter lacks exact execution-aware build",
        );
    }
    return Adapter.buildOutputWithExecutionAndLeasesForGenuineGate(
        allocator,
        store,
        node,
        semantic,
        execution,
        inputs,
        candidate_ordinal,
        dependency_payloads,
    );
}
