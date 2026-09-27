//! Private incremental block-v4 core admission from staged proof files.
//! This receiver itself reconstructs each native verifier from pinned public
//! execution by one bounded guest replay, then fresh-verifies its proof. The
//! replay is a temporary shape source, not proof authority or a succinct
//! verification path. No caller-created receipt enters the closure checks.
const std = @import("std");
const core = @import("stwo_core");
const batch = @import("block_memory_batch_verify_v2.zig");
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const source_roster = @import("block_memory_source_roster_v2.zig");
const fallback = @import("block_memory_public_rw_fallback_v2.zig");
const memory_receiver = @import("block_v4_cpu_incremental_memory_receiver.zig");
const execution_receiver = @import("block_v4_cpu_incremental_execution_receiver.zig");
const closure = @import("block_memory_core_closure_v3.zig");
const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const segment_public = @import("blake3_segment_public.zig");

pub const Verified = struct {
    core: batch.VerifiedCoreOwned,
    leaves: []span.SpanStatement,
    public_data: []segment_public.Owned,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        self.core.deinit(a);
        for (self.public_data) |*item| item.deinit();
        a.free(self.public_data);
        a.free(self.leaves);
        self.* = undefined;
    }
};

/// The returned receipts exist only after every staged native/sidecar,
/// memory, byte-table and public-initial claim has freshly verified and the
/// global transition/initial relations have closed. Recursive root proof
/// verification is a separate, still mandatory admission step.
pub fn verify(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig) !Verified {
    return verifyInternal(a, product, trusted, config, null);
}

/// Internal producer path: stage provisional recursive artifacts while each
/// freshly verified native leaf is resident. Observer output cannot alter the
/// returned core authority, which is issued only after global closure.
pub fn verifyWithLeafObserver(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig, observer: execution_receiver.FreshLeafObserver) !Verified {
    return verifyInternal(a, product, trusted, config, observer);
}

fn verifyInternal(a: std.mem.Allocator, product: product_mod.Product, trusted: trusted_mod.Trusted, config: core.pcs.PcsConfig, observer: ?execution_receiver.FreshLeafObserver) !Verified {
    const statement = product.statement;
    const count = trusted.native_key_ids.len;
    if (count == 0 or count != product.first.entries.len or
        count != product.executions.entries.len or
        count != statement.seal.execution_instance_count or
        count != trusted.job.segment_count or
        !std.meta.eql(statement.seal.base, trusted.base_seal) or
        !std.meta.eql(product.source.job, trusted.job))
        return error.UntrustedIncrementalBlockSchedule;
    try trusted.job.validate();
    var public_plan = try statement.validate(a);
    defer public_plan.deinit(a);
    try statement.requireExecutionSidecars(a);
    const complete = try statement.requireCompletePins(product.public.pin.initial_rw_root.bytes);
    if (!std.meta.eql(complete.expected_job, trusted.job) or
        !std.meta.eql(complete.outer_recursive_key_id, trusted.outer_key_id) or
        !std.meta.eql(complete.forest_roster_digest, trusted.forest_roster_digest) or
        !std.meta.eql(complete.expected_job.complete.protocol_id, v3.protocolIdentity(config)) or
        !std.meta.eql(product.public.registers, trusted.job.complete.initial_state.registers) or
        !std.meta.eql(complete.program_root, trusted.job.complete.program.bytes) or
        statement.expected_events != product.first.event_count)
        return error.UntrustedIncrementalBlockJob;

    // Admit the exact public source roster before relation challenge use.
    // Each hash descriptor is rechecked against a freshly reconstructed
    // PreparedVerifier while the corresponding leaf proof verifies below.
    const rw_digest = try fallback.digestRoster(product.public.pin, product.public.files());
    const hashes = try a.alloc([32]u8, count);
    defer a.free(hashes);
    for (product.first.entries, hashes, trusted.native_key_ids, 0..) |entry, *hash, key, index| {
        if (!std.meta.eql(entry.hash_pin.key_id, key))
            return error.UntrustedIncrementalNativeKeyRoster;
        hash.* = source_roster.hashDescriptor(@intCast(index), entry.hash_pin.plan_id, key);
    }
    const programs = [_][32]u8{source_roster.programDescriptor(complete.program_root)};
    try source_roster.admitExpected(product.public.entries, &programs, hashes);
    try source_roster.admit(statement.seal, product.public.entries, rw_digest);
    const initial = try fallback.verifyMainnetAggregated(a, product.public.pin, product.public.files(), statement.seal, product.public.registers, product.public.entries);
    if (initial.total_first_touches > statement.expected_events)
        return error.InvalidIncrementalFirstTouchCensus;

    var memories = try memory_receiver.verify(a, statement, product.memories, config);
    var owns_memories = true;
    defer if (owns_memories) memories.deinit(a);
    var executions = try execution_receiver.verifyObserved(a, product, trusted, config, observer);
    var owns_executions = true;
    defer if (owns_executions) executions.deinit(a);
    try closure.checkProjected(a, statement, memories.memory, executions.projected, initial);

    // The projected and external receipts have served global closure. Keep
    // only the verified opcode receipts needed for recursive leaf binding.
    a.free(executions.projected);
    for (executions.externals) |*receipt| receipt.deinit(a);
    a.free(executions.externals);
    owns_executions = false;
    owns_memories = false;
    var channel = statement.seal.sharedChannel();
    return .{ .core = .{
        .summary = .{ .event_count = statement.expected_events, .first_touch_count = initial.total_first_touches, .initial_rw_anchor = complete.initial_rw_anchor, .sealed_channel_digest = channel.digestBytes() },
        .memories = memories,
        .executions = executions.opcodes,
        .initial = initial,
    }, .leaves = executions.leaves, .public_data = executions.public_data };
}
