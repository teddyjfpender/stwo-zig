//! Fresh block memory/execution receiver. The complete-block entry point is
//! `block_memory_complete_receiver_v3.zig`; the legacy stub remains closed.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../air/block/memory_component.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const execution_sidecar = @import("block_execution_sidecar_batch_v2.zig");
const execution_range_verify = @import("block_memory_execution_range_verify_v3.zig");
const extension_verify = @import("block_memory_execution_extension_verify_v4.zig");
const external_source = @import("block_execution_external_trace_v2.zig");
const core_closure = @import("block_memory_core_closure_v3.zig");
const initial_fallback = @import("block_memory_public_rw_fallback_v2.zig");
const execution_wire = @import("block_execution_batch_receiver_v2.zig");
const source_roster = @import("block_memory_source_roster_v2.zig");
const source_admission = @import("block_memory_source_roster_admission_v2.zig");
const ethereum_sha = @import("blake3_ethereum_sha_proof.zig");
const span = @import("../recursion/span_statement_blake3.zig");
const v3_leaf = @import("../recursion/blake3_block_execution_span_v3.zig");
const memory_proof = @import("block_memory_proof_v2.zig");
const instance_proof = @import("block_memory_shared_instance_proof_v2.zig");
const table_proof = @import("block_memory_shared_table_proof_v2.zig");
const statement_mod = @import("block_memory_batch_statement_v2.zig");
const wire_mod = @import("block_memory_batch_wire_v3.zig");
pub const Digest = statement_mod.Digest;
pub const Roots = statement_mod.Roots;
pub const MemoryPin = statement_mod.MemoryPin;
pub const CompletePins = statement_mod.CompletePins;
pub const PinnedStatement = statement_mod.PinnedStatement;
pub const MAX_STARK_BYTES = wire_mod.MAX_STARK_BYTES;

pub const SerializedMemoryProof = wire_mod.SerializedMemoryProof;
pub const SerializedTableProof = wire_mod.SerializedTableProof;
pub const SerializedExternalProof = wire_mod.SerializedExternalProof;
pub const SerializedBatch = wire_mod.SerializedBatch;

pub fn EthereumShaExecutionPin(comptime Backend: type) type {
    return struct {
        prepared: *ethereum_sha.ForBackend(Backend).PreparedVerifier,
        expected_key_id: Digest,
        statement: span.SpanStatement,
    };
}

pub const PublicInitialSource = struct {
    pin: initial_fallback.Pin,
    registers: [32]u32,
    files: initial_fallback.Files,
    roster: []const source_roster.Entry,
};

/// This receipt covers fresh native Ethereum-SHA execution, same-root access
/// sidecars, sorted memory, both byte-table families, and initial-value bus
/// closure. The recursive forest/root remains a separate required proof.
pub const VerifiedBlockCore = struct {
    memory_execution_initial_range_verified: void = {},
    event_count: u64,
    first_touch_count: u64,
    initial_rw_anchor: Digest,
    sealed_channel_digest: Digest,
};

/// Internal-use ownership bridge for the complete receiver. Only fresh
/// `verifyCoreOwned` results may be passed to the recursive leaf linker.
pub const VerifiedCoreOwned = struct {
    summary: VerifiedBlockCore,
    memories: VerifiedMemoryRange,
    executions: []execution_sidecar.VerifiedExecutionReceipt,
    initial: initial_fallback.Result,
    pub fn deinit(self: *VerifiedCoreOwned, a: std.mem.Allocator) void {
        self.memories.deinit(a);
        for (self.executions) |*receipt| receipt.deinit(a);
        a.free(self.executions);
        self.* = undefined;
    }
};

/// Freshly verified component proofs before the cross-component transition
/// relation closes. This is deliberately not a `VerifiedBlockCore` result.
const UnclosedCoreOwned = struct {
    memories: VerifiedMemoryRange,
    executions: []execution_sidecar.VerifiedExecutionReceipt,
    initial: initial_fallback.Result,
    expected_events: u64,
    initial_rw_anchor: Digest,
    sealed_channel_digest: Digest,
    pub fn deinit(self: *UnclosedCoreOwned, a: std.mem.Allocator) void {
        self.memories.deinit(a);
        for (self.executions) |*receipt| receipt.deinit(a);
        a.free(self.executions);
        self.* = undefined;
    }
    /// Call only after the v3 or v4 global transition closure succeeds.
    fn promote(self: *UnclosedCoreOwned) VerifiedCoreOwned {
        const result = VerifiedCoreOwned{ .memories = self.memories, .executions = self.executions, .initial = self.initial, .summary = .{ .event_count = self.expected_events, .first_touch_count = self.initial.total_first_touches, .initial_rw_anchor = self.initial_rw_anchor, .sealed_channel_digest = self.sealed_channel_digest } };
        self.* = undefined;
        return result;
    }
};

pub fn verifyBlockCoreEthereumSha(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: PinnedStatement,
    wire: SerializedBatch,
    execution_pins: []const EthereumShaExecutionPin(Backend),
    public_initial: PublicInitialSource,
    config: core.pcs.PcsConfig,
) !VerifiedBlockCore {
    var owned = try verifyCoreOwned(Backend, a, statement, wire, execution_pins, public_initial, config);
    defer owned.deinit(a);
    return owned.summary;
}

pub fn verifyCoreOwned(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: PinnedStatement,
    wire: SerializedBatch,
    execution_pins: []const EthereumShaExecutionPin(Backend),
    public_initial: PublicInitialSource,
    config: core.pcs.PcsConfig,
) !VerifiedCoreOwned {
    if (statement.seal.extension_rosters_bound or wire.execution_extensions.len != 0 or
        wire.execution_extension_range_tables.len != 0)
        return error.ExecutionExtensionRequiresV4Receiver;
    for (execution_pins) |pin| {
        if (try external_source.expectedEventCount(&pin.prepared.extension) != 0)
            return error.UnprovedExecutionExtensionAccesses;
    }
    var unclosed = try verifyCorePreclosure(Backend, a, statement, wire, execution_pins, public_initial, config);
    errdefer unclosed.deinit(a);
    try core_closure.check(a, statement, unclosed.memories.memory, unclosed.executions, unclosed.initial);
    return unclosed.promote();
}

/// Extension-bound core path; opcode receipts remain intact for v3 leaf binding.
pub fn verifyCoreOwnedWithExtension(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: PinnedStatement,
    wire: SerializedBatch,
    execution_pins: []const EthereumShaExecutionPin(Backend),
    public_initial: PublicInitialSource,
    config: core.pcs.PcsConfig,
) !VerifiedCoreOwned {
    if (!statement.seal.extension_rosters_bound)
        return error.UnboundExecutionExtensionRoster;
    var extension_plan = try extension_verify.preflight(a, statement, wire, execution_pins);
    defer extension_plan.deinit(a);
    var unclosed = try verifyCorePreclosure(Backend, a, statement, wire, execution_pins, public_initial, config);
    errdefer unclosed.deinit(a);
    try extension_verify.verifyAndClose(Backend, a, statement, wire, execution_pins, unclosed.executions, unclosed.memories.memory, unclosed.initial, config);
    return unclosed.promote();
}

/// Shared fresh proof path; callers must close relations before promotion.
fn verifyCorePreclosure(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: PinnedStatement,
    wire: SerializedBatch,
    execution_pins: []const EthereumShaExecutionPin(Backend),
    public_initial: PublicInitialSource,
    config: core.pcs.PcsConfig,
) !UnclosedCoreOwned {
    if (execution_pins.len != statement.seal.execution_instance_count or
        wire.execution.len != execution_pins.len)
        return error.InvalidExecutionProofCensus;
    if (wire.initial_sources.len != 0 or statement.provider_roots.len != 0)
        return error.UnverifiedInitialProviderInPublicFallback;
    try statement.requireExecutionSidecars(a);
    const complete = try statement.requireCompletePins(public_initial.pin.initial_rw_root.bytes);
    if (!std.meta.eql(public_initial.registers, complete.expected_job.complete.initial_state.registers) or
        !std.meta.eql(complete.expected_job.complete.protocol_id, v3_leaf.protocolIdentity(config)))
        return error.UntrustedBlockCoreJob;
    const source_pins = try a.alloc(source_admission.EthereumShaPin(Backend), execution_pins.len);
    defer a.free(source_pins);
    for (execution_pins, source_pins, 0..) |pin, *source_pin, index| {
        if (!std.meta.eql(pin.statement.job, complete.expected_job) or
            pin.statement.body != .executed or pin.statement.body.executed.first_segment != @as(u32, @intCast(index)))
            return error.InvalidBlockExecutionSpanRoster;
        source_pin.* = .{ .prepared = pin.prepared, .expected_key_id = pin.expected_key_id };
    }
    const rw_digest = try initial_fallback.digestRoster(public_initial.pin, public_initial.files);
    try source_admission.admitEthereumSha(Backend, a, statement.seal, public_initial.roster, rw_digest, complete.program_root, source_pins, config);
    const initial = try initial_fallback.verifyMainnetAggregated(a, public_initial.pin, public_initial.files, statement.seal, public_initial.registers, public_initial.roster);
    if (initial.total_first_touches > statement.expected_events) return error.InvalidFirstTouchCensus;

    var memories = try verifyMemoryRangeReceipts(Backend, a, statement, wire, config);
    errdefer memories.deinit(a);
    const executions = try a.alloc(execution_sidecar.VerifiedExecutionReceipt, execution_pins.len);
    var verified_count: usize = 0;
    errdefer {
        for (executions[0..verified_count]) |*receipt| receipt.deinit(a);
        a.free(executions);
    }
    const receiver = execution_wire.ForEthereumShaBackend(Backend);
    for (execution_pins, wire.execution, executions, 0..) |pin, proof, *receipt, index| {
        receipt.* = try receiver.verify(a, proof, pin.prepared, pin.expected_key_id, pin.statement, statement.seal, @intCast(index), statement.execution_sidecar_roots[index][0], config);
        verified_count += 1;
        if (!std.meta.eql(receipt.native_roots, statement.execution_roots[index]) or
            !std.meta.eql(receipt.witness_root, statement.execution_sidecar_roots[index][0]) or
            receipt.event_count != statement.execution_active_counts[index])
            return error.UnsealedExecutionProofReceipt;
    }
    try execution_range_verify.verify(Backend, a, statement, wire.execution_range_tables, executions, config);
    var channel = statement.seal.sharedChannel();
    return .{ .memories = memories, .executions = executions, .initial = initial, .expected_events = statement.expected_events, .initial_rw_anchor = complete.initial_rw_anchor, .sealed_channel_digest = channel.digestBytes() };
}

pub const decodeStark = wire_mod.decodeStark;

/// Qualifies only the sorted-memory instances and one shared byte table per
/// field-safe shard. This never issues complete-block authority.
pub fn verifyMemoryRangeOnly(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: PinnedStatement,
    batch: SerializedBatch,
    config: core.pcs.PcsConfig,
) !void {
    var verified = try verifyMemoryRangeReceipts(Backend, a, statement, batch, config);
    verified.deinit(a);
}

pub const VerifiedMemoryRange = struct {
    plan: shard_mod.Plan,
    memory: []memory_proof.VerifiedMemoryReceipt,
    requests: []range.Claims,
    tables: []table_proof.VerifiedTableReceipt,
    pub fn deinit(self: *VerifiedMemoryRange, a: std.mem.Allocator) void {
        self.plan.deinit(a);
        a.free(self.memory);
        a.free(self.requests);
        a.free(self.tables);
        self.* = undefined;
    }
};

/// Private receipt source for the complete receiver. Every returned memory
/// and table receipt was produced by a fresh PCS/FRI verification below.
fn verifyMemoryRangeReceipts(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: PinnedStatement,
    batch: SerializedBatch,
    config: core.pcs.PcsConfig,
) !VerifiedMemoryRange {
    var plan = try statement.validate(a);
    errdefer plan.deinit(a);
    if (batch.memory.len != statement.memory_instances.len or
        batch.range_tables.len != plan.shards.len) return error.InvalidBlockProofCensus;
    const memory_receipts = try a.alloc(memory_proof.VerifiedMemoryReceipt, batch.memory.len);
    errdefer a.free(memory_receipts);
    const request_claims = try a.alloc(range.Claims, batch.memory.len);
    errdefer a.free(request_claims);
    const table_receipts = try a.alloc(table_proof.VerifiedTableReceipt, batch.range_tables.len);
    errdefer a.free(table_receipts);
    const instance_api = instance_proof.ForBackend(Backend);
    for (batch.memory, statement.memory_instances, 0..) |wire, pin, index| {
        const stark = try decodeStark(a, wire.stark_bytes);
        const verified = try instance_api.verifyOwned(a, .{
            .stark = stark,
            .relation = wire.interaction_claim,
            .range_claims = wire.range_claims,
        }, pin.claim, statement.seal, @intCast(index), pin.roots, config);
        memory_receipts[index] = verified.memory;
        request_claims[index] = verified.range_claims;
    }
    try memory_proof.admitMemoryReceipts(a, statement.seal, memory_receipts, statement.expected_events);
    const table_api = table_proof.ForBackend(Backend);
    for (batch.range_tables, plan.shards, statement.range_table_roots, 0..) |wire, shard, roots, index| {
        const stark = try decodeStark(a, wire.stark_bytes);
        table_receipts[index] = try table_api.verifyOwned(a, .{ .stark = stark, .claim = wire.claim }, shard, statement.seal, roots, config);
    }
    try table_proof.closed(&plan, statement.seal, table_receipts, request_claims);
    return .{ .plan = plan, .memory = memory_receipts, .requests = request_claims, .tables = table_receipts };
}

pub const CompleteBlock = enum { complete_block_verified };

/// The only prospective complete-block API. No caller-provided receipt can
/// bypass this boundary; all serialized proofs must be freshly verified here.
pub fn verifyCompleteBlock(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: PinnedStatement,
    batch: SerializedBatch,
    config: core.pcs.PcsConfig,
) !CompleteBlock {
    if (batch.execution.len != statement.execution_roots.len or
        batch.initial_sources.len != statement.provider_roots.len)
        return error.InvalidBlockProofCensus;
    try verifyMemoryRangeOnly(Backend, a, statement, batch, config);
    // Next: fresh execution/initial-provider verifiers, execution↔sorted
    // transition closure, initial-state closure, and source-roster admission.
    return error.ExecutionAndInitialProofVerifiersUnimplemented;
}
