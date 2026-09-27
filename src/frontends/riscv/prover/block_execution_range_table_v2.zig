//! Structural closure for the execution-only 8x8 table family. Call this only
//! with receipts returned by fresh sidecar and table STARK verifiers under the
//! same independently pinned SourceSeal.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const seal_mod = @import("block_memory_source_seal_v2.zig");
const shards = @import("block_execution_range_shard_v2.zig");
const sidecar = @import("block_execution_sidecar_batch_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");

pub fn closed(a: std.mem.Allocator, plan: *const shards.Plan, sealed: seal_mod.SourceSeal, tables: []const table.VerifiedTableReceipt, executions: []const sidecar.VerifiedExecutionReceipt) !void {
    if (!sealed.bound_rosters or executions.len != sealed.execution_instance_count or
        executions.len != plan.event_counts.len or tables.len != plan.shards.len)
        return error.InvalidExecutionRangeReceiptCensus;
    const counts = try a.alloc(u64, executions.len);
    defer a.free(counts);
    var channel = sealed.sharedChannel();
    const digest = channel.digestBytes();
    for (executions, counts, 0..) |receipt, *count, index| {
        if (receipt.instance_index != index or !std.meta.eql(receipt.sealed_channel_digest, digest))
            return error.InvalidExecutionRangeReceipt;
        count.* = receipt.event_count;
    }
    try shards.admit(plan, counts);
    for (tables, plan.shards) |receipt, shard| {
        if (!std.meta.eql(receipt.shard, shard) or !std.meta.eql(receipt.sealed_channel_digest, digest))
            return error.InvalidExecutionRangeTableReceipt;
        var sum = receipt.claim;
        for (executions[shard.first_instance..][0..shard.instance_count]) |execution| {
            for (execution.range_claims) |claims| for (claims) |claim| { sum = sum.add(claim); };
        }
        if (!sum.isZero()) return error.UnclosedExecutionRangeRelation;
    }
}

pub fn summedRequests(executions: []const sidecar.VerifiedExecutionReceipt) Q {
    var sum = Q.zero();
    for (executions) |execution| for (execution.range_claims) |claims| for (claims) |claim| { sum = sum.add(claim); };
    return sum;
}
