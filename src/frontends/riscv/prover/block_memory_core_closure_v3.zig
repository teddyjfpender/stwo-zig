//! Algebraic closure over receipts obtained by the private fresh verifier
//! path. This helper itself grants no proof authority.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const statement_mod = @import("block_memory_batch_statement_v2.zig");
const memory_proof = @import("block_memory_proof_v2.zig");
const execution_sidecar = @import("block_execution_sidecar_batch_v2.zig");
const execution_receipt = @import("block_memory_execution_proof_v2.zig");
const global_closure = @import("../air/block/memory_global_closure.zig");
const initial_fallback = @import("block_memory_public_rw_fallback_v2.zig");

pub fn check(
    a: std.mem.Allocator,
    statement: statement_mod.PinnedStatement,
    memories: []const memory_proof.VerifiedMemoryReceipt,
    executions: []const execution_sidecar.VerifiedExecutionReceipt,
    initial: initial_fallback.Result,
) !void {
    const projected = try a.alloc(execution_receipt.VerifiedExecutionReceipt, executions.len);
    defer a.free(projected);
    for (executions, projected) |*source, *destination| destination.* = source.closureReceipt();
    try checkProjected(a, statement, memories, projected, initial);
}

pub fn checkProjected(
    a: std.mem.Allocator,
    statement: statement_mod.PinnedStatement,
    memories: []const memory_proof.VerifiedMemoryReceipt,
    executions: []const execution_receipt.VerifiedExecutionReceipt,
    initial: initial_fallback.Result,
) !void {
    try global_closure.checkStructuralBlockMemoryClosure(a, statement.seal, memories, executions, statement.expected_events);
    try checkInitial(memories, initial);
}

pub fn checkInitial(memories: []const memory_proof.VerifiedMemoryReceipt, initial: initial_fallback.Result) !void {
    var initial_sum = initial.initial_sum.add(initial.register_sum);
    for (memories) |receipt| initial_sum = initial_sum.add(receipt.relation.initial_sum);
    if (!initial_sum.eql(Q.zero())) return error.UnclosedInitialMemoryRelation;
}
