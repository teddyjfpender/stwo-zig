//! Admission of already-verified block-v2 memory and execution receipts.
//! This is an algebraic closure check, not a proof verifier: callers must
//! obtain each receipt from its fresh PCS verifier under the same SourceSeal.
const std = @import("std");
const core = @import("stwo_core");
const memory_proof = @import("../../prover/block_memory_proof_v2.zig");
const execution_proof = @import("../../prover/block_memory_execution_proof_v2.zig");
const source_seal = @import("../../prover/block_memory_source_seal_v2.zig");

pub fn checkStructuralBlockMemoryClosure(
    allocator: std.mem.Allocator,
    sealed: source_seal.SourceSeal,
    memory_receipts: []const memory_proof.VerifiedMemoryReceipt,
    execution_receipts: []const execution_proof.VerifiedExecutionReceipt,
    expected_events: u64,
) !void {
    // This checks exact memory cardinality, ordinal-link cancellation and
    // source-seal equality before any cross-component cancellation is used.
    try memory_proof.admitMemoryReceipts(allocator, sealed, memory_receipts, expected_events);
    if (execution_receipts.len != @as(usize, sealed.execution_instance_count)) return error.InvalidBlockExecutionReceiptCensus;
    var channel = sealed.sharedChannel();
    const expected_digest = channel.digestBytes();
    var actual_events: u64 = 0;
    var transition_sum = core.fields.qm31.QM31.zero();
    for (execution_receipts, 0..) |receipt, index| {
        if (@as(usize, receipt.instance_index) != index or !std.meta.eql(receipt.sealed_channel_digest, expected_digest))
            return error.InvalidBlockExecutionReceiptCensus;
        actual_events = std.math.add(u64, actual_events, receipt.event_count) catch
            return error.InvalidBlockExecutionReceiptCensus;
        transition_sum = transition_sum.add(receipt.transition_sum);
    }
    if (actual_events != expected_events) return error.InvalidBlockExecutionEventCensus;
    for (memory_receipts) |receipt| transition_sum = transition_sum.add(receipt.relation.transition_sum);
    if (!transition_sum.isZero()) return error.UnclosedBlockMemoryTransition;
    // Initial-value requests intentionally remain open here. They close only
    // against fresh proofs of RW/program/register source providers.
}
