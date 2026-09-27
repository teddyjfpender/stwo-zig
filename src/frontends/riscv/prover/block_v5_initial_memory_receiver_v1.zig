//! Scoped v5 receiver: fresh sorted-memory and range-table proofs, then the
//! independently pinned register/input/RW first-touch relation. Execution and
//! ROM relations remain separate proof families in the complete block gate.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../air/block/memory_component.zig");
const instance = @import("block_memory_shared_instance_proof_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const sources = @import("block_v5_initial_sources_v1.zig");
const source_receiver = @import("block_v5_initial_source_receiver_v1.zig");
const v5 = @import("block_v5_source_seal_v1.zig");
const Digest = core.proof_suites.Blake3.Hasher.Hash;

/// Adapter only: the v2 memory AIR and byte table consume a seal through
/// sharedChannel(). Their quotient and relation ABI are unchanged.
pub const MemorySeal = struct {
    source: v5.Sealed,
    memory_instance_count: u32,
    range_shard_digest: [32]u8,
    bound_rosters: bool = true,

    pub fn sharedChannel(self: MemorySeal) core.proof_suites.Blake3.Channel {
        return self.source.sharedChannel();
    }
};

pub const Pinned = struct {
    sources: sources.Pins,
    v5_pins: v5.Pins,
    expected_seal_digest: [32]u8,
    first_round: []const v5.Entry,
    memory_claim: memory.Claim,
    expected_memory_roots: [2]Digest,
    expected_table_roots: [2]Digest,
};

pub const Wire = struct {
    memory_proof: *instance.Proof,
    table_proof: *table.Proof,
    public_input: []const u8,
    files: sources.Files,
};

pub const MemoryInitialRangeReceipt = struct {
    memory_initial_range_verified: void = {},
    event_count: u64,
    first_touch_count: u64,
    register_touches: u64,
    input_touches: u64,
    rw_touches: u64,
    initial_rw_root: [32]u8,
    sealed_channel_digest: [32]u8,
};

/// Proof pointers are consumed when fresh verification begins. The caller
/// retains ownership if any public preflight fails before that point.
pub fn verifyOne(comptime Backend: type, a: std.mem.Allocator, pinned: Pinned, wire: Wire, sealed: v5.Sealed) !MemoryInitialRangeReceipt {
    if (!std.meta.eql(sealed.digest, pinned.expected_seal_digest))
        return error.UntrustedBlockV5SourceSeal;
    try sealed.require(pinned.v5_pins, pinned.first_round);
    if (pinned.v5_pins.counts[@intFromEnum(v5.Family.memory) - 1] != 1 or
        pinned.v5_pins.counts[@intFromEnum(v5.Family.memory_range) - 1] != 1)
        return error.UnsupportedV5MemorySliceCensus;
    const memory_entry = findOne(pinned.first_round, .memory) orelse return error.MissingV5MemoryRoot;
    const table_entry = findOne(pinned.first_round, .memory_range) orelse return error.MissingV5RangeRoot;
    if (!std.meta.eql(memory_entry.roots, pinned.expected_memory_roots) or
        !std.meta.eql(table_entry.roots, pinned.expected_table_roots))
        return error.UntrustedV5MemoryFirstRound;
    var plan = try shard_mod.plan(a, &.{pinned.memory_claim}, pinned.memory_claim.rows);
    defer plan.deinit(a);
    if (plan.shards.len != 1 or !std.meta.eql(table_entry.instance_id, plan.digest))
        return error.UntrustedV5MemoryRangePlan;
    const source_claim = try source_receiver.check(a, pinned.sources, wire.public_input, wire.files, pinned.v5_pins, pinned.first_round, sealed);
    if (source_claim.first_touch_count > pinned.memory_claim.rows)
        return error.InvalidV5FirstTouchCensus;
    const adapter = MemorySeal{ .source = sealed, .memory_instance_count = 1, .range_shard_digest = plan.digest };
    const memory_proof = wire.memory_proof.*;
    wire.memory_proof.* = undefined;
    const memory_receipt = try instance.ForBackend(Backend).verifyOwned(a, memory_proof, pinned.memory_claim, adapter, 0, pinned.expected_memory_roots, pinned.v5_pins.config);
    const table_proof = wire.table_proof.*;
    wire.table_proof.* = undefined;
    const table_receipt = try table.ForBackend(Backend).verifyOwned(a, table_proof, plan.shards[0], adapter, pinned.expected_table_roots, pinned.v5_pins.config);
    try table.closed(&plan, adapter, &.{table_receipt}, &.{memory_receipt.range_claims});
    if (!std.meta.eql(memory_receipt.memory.sealed_channel_digest, source_claim.sealed_channel_digest))
        return error.InvalidV5MemorySeal;
    if (!memory_receipt.memory.relation.initial_sum.add(source_claim.initial_sum).eql(core.fields.qm31.QM31.zero()))
        return error.UnclosedV5InitialRelation;
    return .{
        .event_count = pinned.memory_claim.rows,
        .first_touch_count = source_claim.first_touch_count,
        .register_touches = source_claim.register_touches,
        .input_touches = source_claim.input_touches,
        .rw_touches = source_claim.rw_touches,
        .initial_rw_root = pinned.sources.initial_rw_root,
        .sealed_channel_digest = source_claim.sealed_channel_digest,
    };
}

fn findOne(entries: []const v5.Entry, family: v5.Family) ?v5.Entry {
    for (entries) |entry| if (entry.family == family) return entry;
    return null;
}
