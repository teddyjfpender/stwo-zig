//! Fresh SHA/Keccak caller sidecars and their independent byte-table family.
//! This grants no authority alone: the caller must retain the freshly verified
//! opcode receipts and verify the recursive forest against those same receipts.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const statement_mod = @import("block_memory_batch_statement_v2.zig");
const wire_mod = @import("block_memory_batch_wire_v3.zig");
const source = @import("block_execution_external_trace_v2.zig");
const external = @import("block_execution_external_batch_v2.zig");
const receiver_mod = @import("block_execution_external_receiver_v2.zig");
const opcode = @import("block_execution_sidecar_batch_v2.zig");
const execution_receipt = @import("block_memory_execution_proof_v2.zig");
const memory = @import("block_memory_proof_v2.zig");
const initial_fallback = @import("block_memory_public_rw_fallback_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const closure = @import("block_memory_core_closure_v3.zig");
const shard_mod = @import("block_execution_range_shard_v2.zig");

/// Cheap public-geometry gate before any memory/native PCS verification.
pub fn preflight(a: std.mem.Allocator, statement: statement_mod.PinnedStatement, wire: wire_mod.SerializedBatch, execution_pins: anytype) !shard_mod.Plan {
    var plan = try statement.requireExecutionExtensions(a);
    errdefer plan.deinit(a);
    if (execution_pins.len != statement.seal.execution_instance_count or
        wire.execution.len != execution_pins.len or
        wire.execution_extensions.len != statement.execution_extension_roots.len or
        wire.execution_extension_range_tables.len != plan.shards.len)
        return error.InvalidExecutionExtensionProofCensus;
    var next_extension: usize = 0;
    for (execution_pins, statement.execution_extension_active_counts, 0..) |pin, count, index| {
        if (try source.expectedEventCount(&pin.prepared.extension) != count)
            return error.UnsealedExecutionExtensionCensus;
        if (count == 0) continue;
        if (next_extension >= wire.execution_extensions.len or
            wire.execution_extensions[next_extension].instance_index != index or
            statement.execution_extension_roots[next_extension].index != index)
            return error.InvalidExecutionExtensionProofOrder;
        next_extension += 1;
    }
    if (next_extension != wire.execution_extensions.len)
        return error.ExtraExecutionExtensionProof;
    return plan;
}

pub fn verifyAndClose(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: statement_mod.PinnedStatement,
    wire: wire_mod.SerializedBatch,
    execution_pins: anytype,
    opcodes: []const opcode.VerifiedExecutionReceipt,
    memories: []const memory.VerifiedMemoryReceipt,
    initial: initial_fallback.Result,
    config: core.pcs.PcsConfig,
) !void {
    var plan = try preflight(a, statement, wire, execution_pins);
    defer plan.deinit(a);
    if (opcodes.len != statement.seal.execution_instance_count or
        execution_pins.len != opcodes.len)
        return error.InvalidExecutionExtensionProofCensus;

    const extensions = try a.alloc(external.VerifiedReceipt, wire.execution_extensions.len);
    var verified_count: usize = 0;
    defer {
        for (extensions[0..verified_count]) |*receipt| receipt.deinit(a);
        a.free(extensions);
    }
    const projected = try a.alloc(execution_receipt.VerifiedExecutionReceipt, opcodes.len);
    defer a.free(projected);
    const api = receiver_mod.ForEthereumShaBackend(Backend);
    var next_extension: usize = 0;
    var channel = statement.seal.sharedChannel();
    const expected_digest = channel.digestBytes();
    for (execution_pins, opcodes, projected, 0..) |pin, opcode_receipt, *combined, index| {
        const expected = try source.expectedEventCount(&pin.prepared.extension);
        if (expected != statement.execution_extension_active_counts[index] or
            opcode_receipt.instance_index != index or
            !std.meta.eql(opcode_receipt.native_key_id, pin.expected_key_id) or
            !std.meta.eql(opcode_receipt.native_roots, statement.execution_roots[index]) or
            !std.meta.eql(opcode_receipt.sealed_channel_digest, expected_digest))
            return error.UnsealedExecutionExtensionCensus;
        combined.* = opcode_receipt.closureReceipt();
        if (expected == 0) continue;
        if (next_extension >= wire.execution_extensions.len)
            return error.MissingExecutionExtensionProof;
        const proof = wire.execution_extensions[next_extension];
        const trusted = statement.execution_extension_roots[next_extension];
        if (proof.instance_index != index or trusted.index != index)
            return error.InvalidExecutionExtensionProofOrder;
        const external_wire = receiver_mod.SidecarWire{
            .external_stark = proof.stark_bytes,
            .external_claims = proof.claims,
        };
        extensions[next_extension] = try api.verifyAfterVerifiedOpcode(a, external_wire, pin.prepared, pin.expected_key_id, pin.statement, statement.seal, @intCast(index), &opcodes[index], trusted.roots[0], config);
        const receipt = &extensions[next_extension];
        verified_count += 1;
        if (receipt.instance_index != index or receipt.event_count != expected or
            !std.meta.eql(receipt.native_roots, opcode_receipt.native_roots) or
            !std.meta.eql(receipt.native_key_id, opcode_receipt.native_key_id) or
            !std.meta.eql(receipt.witness_root, trusted.roots[0]) or
            !std.meta.eql(receipt.sealed_channel_digest, opcode_receipt.sealed_channel_digest))
            return error.UnsealedExecutionExtensionReceipt;
        combined.event_count = try std.math.add(u64, combined.event_count, receipt.event_count);
        combined.transition_sum = combined.transition_sum.add(receipt.transition_sum);
        next_extension += 1;
    }
    if (next_extension != wire.execution_extensions.len)
        return error.ExtraExecutionExtensionProof;
    try verifyTables(Backend, a, statement, wire, &plan, extensions, config);
    try closure.checkProjected(a, statement, memories, projected, initial);
}

fn verifyTables(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: statement_mod.PinnedStatement,
    wire: wire_mod.SerializedBatch,
    plan: *const shard_mod.Plan,
    extensions: []const external.VerifiedReceipt,
    config: core.pcs.PcsConfig,
) !void {
    if (extensions.len == 0) return error.EmptyExecutionExtensionRoster;
    const receipts = try a.alloc(table.VerifiedTableReceipt, plan.shards.len);
    defer a.free(receipts);
    const api = table.ForBackend(Backend);
    for (wire.execution_extension_range_tables, plan.shards, statement.execution_extension_range_table_roots, receipts) |proof, shard, roots, *receipt| {
        const stark = try wire_mod.decodeStark(a, proof.stark_bytes);
        receipt.* = try api.verifyOwned(a, .{ .stark = stark, .claim = proof.claim }, shard, statement.seal, roots, config);
    }
    var next_extension: usize = 0;
    for (receipts, plan.shards) |receipt, shard| {
        if (!std.meta.eql(receipt.shard, shard) or
            !std.meta.eql(receipt.sealed_channel_digest, extensions[0].sealed_channel_digest))
            return error.UnsealedExecutionExtensionTable;
        var sum = receipt.claim;
        const end = @as(usize, shard.first_instance) + shard.instance_count;
        while (next_extension < extensions.len and extensions[next_extension].instance_index < end) : (next_extension += 1) {
            const extension = extensions[next_extension];
            if (extension.instance_index < shard.first_instance)
                return error.InvalidExecutionExtensionProofOrder;
            for (extension.range_claims) |claims| for (claims) |claim| {
                sum = sum.add(claim);
            };
        }
        if (!sum.eql(Q.zero())) return error.UnclosedExecutionExtensionRangeRelation;
    }
    if (next_extension != extensions.len) return error.InvalidExecutionExtensionProofCensus;
}
