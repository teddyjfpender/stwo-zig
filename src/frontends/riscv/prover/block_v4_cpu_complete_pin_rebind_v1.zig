//! Provisional complete-pin finalization after staged core and exact forest.
//! This copies public metadata only. Canonical fresh verification remains the
//! sole path that can return `complete_block_verified`.
const std = @import("std");
const product_mod = @import("block_v4_cpu_streaming_produce.zig");
const incremental = @import("block_v4_cpu_incremental_core_receiver.zig");
const manifest_mod = @import("block_v4_cpu_trusted_manifest_v1.zig");
const trusted_mod = @import("block_v4_cpu_multi_segment_assembly.zig");
const linked = @import("../recursion/blake3_exact_root_receiver_v3.zig");
const parent = @import("../recursion/blake3_execution_parent_protocol.zig");

pub const Provisional = struct {
    /// Borrows every staged file handle and roster slice in the original
    /// Product, plus the final manifest's key slice. Use before either owner
    /// is deinitialized, and pass only to the fresh canonical receiver.
    product: product_mod.Product,
    trusted: trusted_mod.Trusted,
};

/// Candidate and final manifest files must each have been loaded with an
/// out-of-band SHA-256 pin. Only outer key and forest digest may change.
/// The exact forest root descriptors must come from fresh recursive proof
/// checks; this structural gate is not a substitute for the final receiver.
pub fn finalizeCompletePins(
    a: std.mem.Allocator,
    product: product_mod.Product,
    candidate: *const manifest_mod.Owned,
    final: *const manifest_mod.Owned,
    closed_core: *const incremental.Verified,
    forest_roots: []const linked.Descriptor,
    outer_admission: parent.Admission,
) !Provisional {
    const from = candidate.trusted();
    const to = final.trusted();
    try admitPolicyTransition(from, candidate.sourcePins(), to, final.sourcePins());
    const before = product.statement;
    _ = try before.requireCompletePins(product.public.pin.initial_rw_root.bytes);
    const original_pins = before.complete_pins orelse return error.MissingCompleteBlockPublicPins;
    if (!std.meta.eql(before.seal.base, from.base_seal) or
        !std.meta.eql(product.source.job, from.job) or
        before.seal.execution_instance_count != from.job.segment_count or
        !std.meta.eql(original_pins.expected_job, from.job) or
        !std.meta.eql(original_pins.outer_recursive_key_id, from.outer_key_id) or
        !std.meta.eql(original_pins.forest_roster_digest, from.forest_roster_digest) or
        closed_core.core.summary.event_count != before.expected_events or
        closed_core.core.executions.len != from.native_key_ids.len or
        closed_core.leaves.len != from.native_key_ids.len or
        !std.meta.eql(closed_core.core.summary.initial_rw_anchor, product.public.pin.initial_rw_root.bytes))
        return error.UnclosedProvisionalBlockCore;
    var channel = before.seal.sharedChannel();
    if (!std.meta.eql(channel.digestBytes(), closed_core.core.summary.sealed_channel_digest))
        return error.UnclosedProvisionalBlockCore;
    const expected_forest = try linked.verifiedForestDigest(to.job, forest_roots);
    if (!std.meta.eql(expected_forest, to.forest_roster_digest))
        return error.UntrustedFinalForestRoster;
    try outer_admission.validate();
    const exact = outer_admission.key.context.exact_aggregation orelse
        return error.UntrustedFinalOuterKey;
    if (outer_admission.key.profile != .csp_q70_pow26 or
        !std.meta.eql(outer_admission.expected_id, to.outer_key_id) or
        !std.meta.eql(exact.roster_digest, expected_forest) or
        @as(usize, exact.child_count) != forest_roots.len)
        return error.UntrustedFinalOuterKey;

    var rebound = product;
    rebound.statement.complete_pins = .{
        .expected_job = to.job,
        .initial_rw_anchor = product.public.pin.initial_rw_root.bytes,
        .program_root = to.job.complete.program.bytes,
        .outer_recursive_key_id = to.outer_key_id,
        .forest_roster_digest = to.forest_roster_digest,
    };
    const original_digest = try before.firstRoundDigest(a);
    const rebound_digest = try rebound.statement.firstRoundDigest(a);
    if (!std.meta.eql(before.seal, rebound.statement.seal) or
        !std.meta.eql(original_digest, rebound_digest) or
        !std.meta.eql(original_digest, before.seal.first_round_roster_digest))
        return error.ChangedBlockFirstRoundAfterFinalPins;
    _ = try rebound.statement.requireCompletePins(product.public.pin.initial_rw_root.bytes);
    return .{ .product = rebound, .trusted = to };
}

/// All nonrecursive public policy remains identical. Source-file hashes and
/// exact schedule hash cannot change while complete pins are finalized.
pub fn admitPolicyTransition(from: trusted_mod.Trusted, from_source: @import("block_v4_cpu_runner_source.zig").Pins, to: trusted_mod.Trusted, to_source: @import("block_v4_cpu_runner_source.zig").Pins) !void {
    if (!std.meta.eql(from.job, to.job) or
        !std.meta.eql(from.base_seal, to.base_seal) or
        !std.mem.eql([32]u8, from.native_key_ids, to.native_key_ids) or
        !std.meta.eql(from_source, to_source))
        return error.ChangedBlockPolicyDuringFinalization;
}

test "block-v4 final pins may change only outer key and exact forest digest" {
    const span = @import("../recursion/span_statement_blake3.zig");
    const anchor = span.Digest{ .bytes = @splat(1) };
    const regs: [32]u32 = @splat(0);
    const initial = try span.MachineState.init(4, regs, anchor, .{ .bytes = @splat(0) });
    const exit = try span.MachineState.init(8, regs, anchor, .{ .bytes = @splat(0) });
    const complete = try span.CompleteExecution.init(@import("../recursion/blake3_block_execution_span_v3.zig").protocolIdentity(parent.Profile.csp_q70_pow26.config()), .{ .bytes = @splat(2) }, initial, exit, .{ .bytes = @splat(3) }, .{ .bytes = @splat(4) }, 1);
    const job = try span.JobContext.init(complete, 1);
    const keys = [_][32]u8{@splat(5)};
    const candidate = trusted_mod.Trusted{ .job = job, .base_seal = .{ .digest = @splat(6), .instance_count = 1 }, .native_key_ids = &keys, .outer_key_id = @splat(7), .forest_roster_digest = @splat(8) };
    const source = @import("block_v4_cpu_runner_source.zig").Pins{
        .elf_sha256 = @splat(9),
        .input_sha256 = @splat(10),
        .oracle_sha256 = @splat(11),
        .initial_rw_root = anchor,
        .program_root = complete.program,
        .schedule_json_sha256 = @splat(12),
        .expected_job = job,
    };
    var final = candidate;
    final.outer_key_id = @splat(13);
    final.forest_roster_digest = @splat(14);
    try admitPolicyTransition(candidate, source, final, source);
    final.base_seal.digest[0] ^= 1;
    try std.testing.expectError(error.ChangedBlockPolicyDuringFinalization, admitPolicyTransition(candidate, source, final, source));
    final = candidate;
    var changed_source = source;
    var changed_schedule = changed_source.schedule_json_sha256.?;
    changed_schedule[0] ^= 1;
    changed_source.schedule_json_sha256 = changed_schedule;
    try std.testing.expectError(error.ChangedBlockPolicyDuringFinalization, admitPolicyTransition(candidate, source, final, changed_source));

    // Exercise the full function's compilation through its earliest gate.
    const a = std.testing.allocator;
    const candidate_json = try std.json.Stringify.valueAlloc(a, manifest_mod.Wire{ .format_version = 1, .trusted = candidate, .source = source }, .{});
    defer a.free(candidate_json);
    var candidate_owned = manifest_mod.Owned{ .parsed = try std.json.parseFromSlice(manifest_mod.Wire, a, candidate_json, .{ .allocate = .alloc_always }), .sha256 = @splat(0) };
    defer candidate_owned.deinit();
    const final_json = try std.json.Stringify.valueAlloc(a, manifest_mod.Wire{ .format_version = 1, .trusted = blk: {
        var changed = candidate;
        changed.base_seal.digest[0] ^= 1;
        break :blk changed;
    }, .source = source }, .{});
    defer a.free(final_json);
    var final_owned = manifest_mod.Owned{ .parsed = try std.json.parseFromSlice(manifest_mod.Wire, a, final_json, .{ .allocate = .alloc_always }), .sha256 = @splat(0) };
    defer final_owned.deinit();
    var never_read_core: incremental.Verified = undefined;
    try std.testing.expectError(error.ChangedBlockPolicyDuringFinalization, finalizeCompletePins(a, undefined, &candidate_owned, &final_owned, &never_read_core, &.{}, undefined));
}
