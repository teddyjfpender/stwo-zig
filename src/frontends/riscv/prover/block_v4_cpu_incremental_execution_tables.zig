//! Shared opcode and extension byte-table closure after every execution
//! receipt has passed its fresh native/sidecar verifier.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const opcode_mod = @import("block_execution_sidecar_batch_v2.zig");
const external_mod = @import("block_execution_external_batch_v2.zig");
const opcode_tables = @import("block_memory_execution_range_verify_v3.zig");
const table_proof = @import("block_memory_shared_table_proof_v2.zig");
const wire_mod = @import("block_memory_batch_wire_v3.zig");

pub fn verify(a: std.mem.Allocator, product: product_mod.Product, opcodes: []const opcode_mod.VerifiedExecutionReceipt, externals: []const external_mod.VerifiedReceipt, config: core.pcs.PcsConfig) !void {
    const statement = product.statement;
    try opcode_tables.verify(Cpu, a, statement, product.opcode_tables.wires, opcodes, config);
    if (!statement.seal.extension_rosters_bound) {
        if (externals.len != 0 or product.external_tables != null)
            return error.UnboundIncrementalExtensionTable;
        return;
    }
    var plan = try statement.requireExecutionExtensions(a);
    defer plan.deinit(a);
    const staged = product.external_tables orelse return error.MissingIncrementalExtensionTables;
    if (staged.wires.len != plan.shards.len or
        statement.execution_extension_range_table_roots.len != plan.shards.len or
        externals.len != statement.execution_extension_roots.len)
        return error.InvalidIncrementalExtensionTableCensus;
    const api = table_proof.ForBackend(Cpu);
    var next: usize = 0;
    var channel = statement.seal.sharedChannel();
    const sealed_digest = channel.digestBytes();
    for (plan.shards, staged.wires, statement.execution_extension_range_table_roots) |part, wire, roots| {
        const stark = try wire_mod.decodeStark(a, wire.stark_bytes);
        const receipt = try api.verifyOwned(a, .{ .stark = stark, .claim = wire.claim }, part, statement.seal, roots, config);
        if (!std.meta.eql(receipt.shard, part) or
            !std.meta.eql(receipt.sealed_channel_digest, sealed_digest))
            return error.UnsealedIncrementalExtensionTable;
        var sum = receipt.claim;
        const end = @as(usize, part.first_instance) + part.instance_count;
        while (next < externals.len and externals[next].instance_index < end) : (next += 1) {
            const ext = externals[next];
            if (ext.instance_index < part.first_instance)
                return error.InvalidIncrementalExtensionOrder;
            for (ext.range_claims) |claims| for (claims) |claim| {
                sum = sum.add(claim);
            };
        }
        if (!sum.eql(Q.zero())) return error.UnclosedIncrementalExtensionRange;
    }
    if (next != externals.len) return error.InvalidIncrementalExtensionTableCensus;
}
