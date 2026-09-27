//! Scoped fresh receiver for the memory, byte-range, and initial-value buses.
//! This deliberately does not attest execution or a complete Ethereum block.
const std = @import("std");
const core = @import("stwo_core");
const batch = @import("block_memory_batch_verify_v2.zig");
const fallback = @import("block_memory_public_rw_fallback_v2.zig");
const source_roster = @import("block_memory_source_roster_v2.zig");
const Q = core.fields.qm31.QM31;

pub const IndependentlyPinnedInitialState = struct {
    rw: fallback.Pin,
    registers: [32]u32,
};
pub const AggregatedSourcePins = struct {
    entries: []const source_roster.Entry,
    expected_program: []const [32]u8,
    expected_hash: []const [32]u8,
};

pub const MemoryInitialRange = struct {
    memory_initial_range_verified: void = {},
    first_touches: u64,
    rw_first_touches: u64,
    register_first_touches: u64,
    initial_rw_root: [32]u8,
    sealed_roster_digest: [32]u8,
};

/// This check has no proof authority by itself; callers must first fresh-
/// verify every sorted-memory claim from which `sorted_initial_sum` is formed.
pub fn checkInitialClosure(sorted_initial_sum: Q, rw_sum: Q, register_sum: Q) !void {
    if (!sorted_initial_sum.add(rw_sum).add(register_sum).eql(Q.zero()))
        return error.UnclosedInitialMemoryRelation;
}

/// `initial` must be independently pinned from the job statement. The roster
/// is public and directly sealed into SourceSeal v3 before challenge draw.
/// Program first touches are rejected until a separate program provider is
/// fresh-verified. The batch receiver verifies every memory/table STARK from
/// serialized bytes and closes link/range before initial claims are admitted.
pub fn verifyMemoryInitialRange(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    config: core.pcs.PcsConfig,
    initial: IndependentlyPinnedInitialState,
    files: fallback.Files,
) !MemoryInitialRange {
    return verifyInternal(Backend, a, statement, wire, config, initial, files, null);
}

/// Same scoped authority, with the production source-roster aggregate. The
/// expected descriptor digests must be derived independently from the public
/// job/program/hash capability statement by the caller.
pub fn verifyMemoryInitialRangeAggregated(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    config: core.pcs.PcsConfig,
    initial: IndependentlyPinnedInitialState,
    files: fallback.Files,
    sources: AggregatedSourcePins,
) !MemoryInitialRange {
    return verifyInternal(Backend, a, statement, wire, config, initial, files, sources);
}

fn verifyInternal(
    comptime Backend: type,
    a: std.mem.Allocator,
    statement: batch.PinnedStatement,
    wire: batch.SerializedBatch,
    config: core.pcs.PcsConfig,
    initial: IndependentlyPinnedInitialState,
    files: fallback.Files,
    sources: ?AggregatedSourcePins,
) !MemoryInitialRange {
    if (wire.execution.len != 0 or wire.initial_sources.len != 0)
        return error.UnverifiedBlockProofFamilyInScopedBatch;
    const public_initial = if (sources) |aggregate| blk: {
        try source_roster.admitExpected(aggregate.entries, aggregate.expected_program, aggregate.expected_hash);
        break :blk try fallback.verifyMainnetAggregated(a, initial.rw, files, statement.seal, initial.registers, aggregate.entries);
    } else try fallback.verifyMainnetDirectBound(a, initial.rw, files, statement.seal, initial.registers);
    if (public_initial.total_first_touches > statement.expected_events)
        return error.InvalidFirstTouchCensus;
    try batch.verifyMemoryRangeOnly(Backend, a, statement, wire, config);
    var sorted_sum = Q.zero();
    for (wire.memory) |item| sorted_sum = sorted_sum.add(item.interaction_claim.initial_sum);
    try checkInitialClosure(sorted_sum, public_initial.initial_sum, public_initial.register_sum);
    return .{
        .first_touches = public_initial.total_first_touches,
        .rw_first_touches = public_initial.rw_first_touches,
        .register_first_touches = public_initial.register_first_touches,
        .initial_rw_root = initial.rw.initial_rw_root.bytes,
        .sealed_roster_digest = public_initial.roster_digest,
    };
}
