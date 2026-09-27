//! Fresh execution byte-table verification and exact request closure.
const std = @import("std");
const core = @import("stwo_core");
const statement_mod = @import("block_memory_batch_statement_v2.zig");
const wire = @import("block_memory_batch_wire_v3.zig");
const execution_shard = @import("block_execution_range_shard_v2.zig");
const execution_range_table = @import("block_execution_range_table_v2.zig");
const execution_sidecar = @import("block_execution_sidecar_batch_v2.zig");
const table_proof = @import("block_memory_shared_table_proof_v2.zig");

pub fn verify(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: statement_mod.PinnedStatement,
    entries: []const wire.SerializedTableProof,
    executions: []const execution_sidecar.VerifiedExecutionReceipt,
    config: core.pcs.PcsConfig,
) !void {
    try statement.requireExecutionSidecars(a);
    var plan = try execution_shard.plan(a, statement.execution_active_counts);
    defer plan.deinit(a);
    if (entries.len != plan.shards.len)
        return error.InvalidExecutionRangeTableProofCensus;
    if (plan.shards.len == 0) {
        // A native-only precompile segment has no opcode byte requests and
        // therefore no table proof. Require the freshly verified receipts to
        // carry no hidden requests before the empty closure below.
        for (executions) |receipt| {
            if (receipt.event_count != 0 or receipt.range_claims.len != 0)
                return error.UnclosedExecutionRangeRelation;
        }
        if (!execution_range_table.summedRequests(executions).isZero())
            return error.UnclosedExecutionRangeRelation;
    }
    const receipts = try a.alloc(table_proof.VerifiedTableReceipt, plan.shards.len);
    defer a.free(receipts);
    const api = table_proof.ForBackend(Backend);
    for (entries, plan.shards, statement.execution_range_table_roots) |entry, shard, roots| {
        const stark = try wire.decodeStark(a, entry.stark_bytes);
        receipts[shard.index] = try api.verifyOwned(a, .{ .stark = stark, .claim = entry.claim }, shard, statement.seal, roots, config);
    }
    try execution_range_table.closed(a, &plan, statement.seal, receipts, executions);
}
