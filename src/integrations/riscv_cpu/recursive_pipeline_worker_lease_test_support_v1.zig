//! Allocation-owning adapter used only by the worker lease lifecycle test.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

pub const Adapter = struct {
    pub const LeasePayload = struct {
        allocation: []u8,
        releases: *usize,
    };

    pub fn buildOutputWithLeases(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
        _: []const *const LeasePayload,
    ) ![]u8 {
        return error.TestAdapterBuildUnavailable;
    }

    pub fn coldOpenLease(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: []const u8,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
    ) !LeasePayload {
        return error.TestAdapterColdOpenUnavailable;
    }

    pub fn deinitLeasePayload(
        payload: *LeasePayload,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(payload.allocation);
        payload.releases.* += 1;
        payload.* = undefined;
    }
};
