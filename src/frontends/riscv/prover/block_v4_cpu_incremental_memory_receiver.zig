//! Fresh memory/table verification with one staged Postcard proof resident at
//! a time. Receipt arrays contain only fixed-size claims and trusted roots.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const batch = @import("block_memory_batch_verify_v2.zig");
const capture_mod = @import("block_v4_cpu_staged_capture.zig");
const memory_proof = @import("block_memory_proof_v2.zig");
const instance_proof = @import("block_memory_shared_instance_proof_v2.zig");
const table_proof = @import("block_memory_shared_table_proof_v2.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");

pub fn verify(a: std.mem.Allocator, statement: batch.PinnedStatement, staged: *capture_mod.Capture, config: core.pcs.PcsConfig) !batch.VerifiedMemoryRange {
    var plan = try statement.validate(a);
    errdefer plan.deinit(a);
    if (staged.memory.len != statement.memory_instances.len or
        staged.tables.len != plan.shards.len)
        return error.InvalidStagedBlockMemoryCensus;
    const receipts = try a.alloc(memory_proof.VerifiedMemoryReceipt, staged.memory.len);
    errdefer a.free(receipts);
    const claims = try a.alloc(range.Claims, staged.memory.len);
    errdefer a.free(claims);
    const tables = try a.alloc(table_proof.VerifiedTableReceipt, staged.tables.len);
    errdefer a.free(tables);

    const instance_api = instance_proof.ForBackend(Cpu);
    for (statement.memory_instances, receipts, claims, 0..) |pin, *receipt, *claim, index| {
        const wire = try staged.loadMemory(index);
        // Capture owns the file buffer; verifier allocations use `a`.
        defer staged.a.free(wire.stark_bytes);
        const stark = try batch.decodeStark(a, wire.stark_bytes);
        const verified = try instance_api.verifyOwned(a, .{
            .stark = stark,
            .relation = wire.interaction_claim,
            .range_claims = wire.range_claims,
        }, pin.claim, statement.seal, @intCast(index), pin.roots, config);
        receipt.* = verified.memory;
        claim.* = verified.range_claims;
    }
    try memory_proof.admitMemoryReceipts(a, statement.seal, receipts, statement.expected_events);

    const table_api = table_proof.ForBackend(Cpu);
    for (plan.shards, statement.range_table_roots, tables, 0..) |part, roots, *receipt, index| {
        const wire = try staged.loadTable(index);
        defer staged.a.free(wire.stark_bytes);
        const stark = try batch.decodeStark(a, wire.stark_bytes);
        receipt.* = try table_api.verifyOwned(a, .{ .stark = stark, .claim = wire.claim }, part, statement.seal, roots, config);
    }
    try table_proof.closed(&plan, statement.seal, tables, claims);
    return .{ .plan = plan, .memory = receipts, .requests = claims, .tables = tables };
}
