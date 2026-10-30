const std = @import("std");
test "v7 compact lookup complete recursive lifecycle codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_lookup_compact_fixed_roster_v1.zig").Owned.derive);
    std.mem.doNotOptimizeAway(&@import("block_v7_lookup_compact_preparation_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("block_v7_lookup_compact_receiver_v1.zig").verify);
}

const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const CompactLookup = @import("../prover/block_v7_lookup_compact_proof_v1.zig");
const Profile = @import("block_v7_lookup_compact_fixed_profile_v1.zig");
test "v7 compact lookup original proof to independently keyed detached parent" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var counters = try @import("../air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    for (&counters.counters) |*counter| {
        counter.values[0] = core.fields.m31.M31.fromCanonical(3);
        counter.values[counter.values.len - 1] = core.fields.m31.M31.one().neg();
    }
    const plan = @import("../prover/block_v5_native_lookup_plan_v1.zig").Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(4) };
    var stage = try CompactLookup.For(Cpu).Stage.init(a, &counters, plan, config, null, .{});
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    const entries = [_]E.Entry{ try E.Entry.init(.native, 0, @splat(7), &.{ @splat(1), @splat(2) }), try stage.entry() };
    var counts: E.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try E.Epoch.init(@splat(71), config, counts, &entries, entries.len);
    const policy = stage.policy(epoch, &entries);
    var original = try stage.prove(epoch, &entries);
    var original_live = true;
    defer if (original_live) original.deinit(a);
    stage.deinit();
    stage_live = false;
    var captured = try CompactLookup.For(Cpu).verifyAndCapture(a, &original, policy, .{});
    var captured_live = true;
    defer if (captured_live) captured.deinit();
    const input = Profile.Input{ .policy = policy, .claims = original.claims };
    original.deinit(a);
    original_live = false;
    const profile = try Profile.Owned.derive(a, input, .{});
    defer profile.deinit();
    var changed_entries = entries;
    changed_entries[1].roots[1][0] ^= 1;
    var changed = input;
    changed.policy.roots[1][0] ^= 1;
    changed.policy.entries = &changed_entries;
    changed.policy.epoch = try E.Epoch.init(@splat(72), config, counts, &changed_entries, entries.len);
    changed.claims[0] = changed.claims[0].add(Q.one());
    const alternate = try Profile.Owned.derive(a, changed, .{});
    defer alternate.deinit();
    const Cold = @import("block_v7_lookup_compact_fixed_transcript_v1.zig");
    var before = try Cold.derive(a, profile, 2, .{});
    defer before.deinit();
    var after = try Cold.derive(a, alternate, 2, .{});
    defer after.deinit();
    try std.testing.expectEqualDeep(before.id, after.id);
    try std.testing.expect(!std.meta.eql(profile.seal, alternate.seal));
    captured_live = false; // qualify takes ownership, including failure cleanup.
    try qualify(a, input, profile, &captured);
}
fn qualify(a: std.mem.Allocator, input: Profile.Input, profile: *const Profile.Owned, capture: *CompactLookup.VerifiedCapture) !void {
    var capture_live = true;
    defer if (capture_live) capture.deinit();
    const expected_claims = capture.receipt.claims;
    const ColdRoster = @import("block_v7_lookup_compact_fixed_roster_v1.zig");
    const Prepare = @import("block_v7_lookup_compact_preparation_v1.zig");
    const Parent = @import("blake3_execution_parent_proof.zig");
    const Protocol = @import("block_v7_lookup_compact_parent_protocol_v1.zig");
    const Receive = @import("block_v7_lookup_compact_receiver_v1.zig");
    const parent_profile = @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0;
    var cold = ColdRoster.Owned.derive(a, input, 2, .{}) catch |err| {
        std.debug.print("LOOKUP_COMPACT_PARENT phase=cold_roster error={s}\n", .{@errorName(err)});
        return err;
    };
    std.debug.print("LOOKUP_COMPACT_PARENT phase=cold_roster done=true\n", .{});
    defer cold.deinit();
    const expected_base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, parent_profile);
    const roster = [_]Protocol.Bus.Expected{.{ .profile = profile.seal, .epoch = input.policy.epoch.digest, .roots = input.policy.roots }};
    const key = try Protocol.Key.fromGeometry(expected_base, cold.wires, &roster);
    var ready = Prepare.prepare(a, profile, capture, 2, .{}) catch |err| {
        std.debug.print("LOOKUP_COMPACT_PARENT phase=live_prepare error={s}\n", .{@errorName(err)});
        return err;
    };
    std.debug.print("LOOKUP_COMPACT_PARENT phase=live_prepare done=true\n", .{});
    var ready_live = true;
    defer if (ready_live) ready.deinit();
    capture.deinit();
    capture_live = false;
    try ready.recursive.rows.partitionHashRows();
    try cold.namespace.validateLive(&ready.recursive.rows);
    try std.testing.expectEqualDeep(cold.context, ready.recursive.context);
    try std.testing.expectEqualDeep(cold.wires, ready.wires);
    inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| try std.testing.expectEqualDeep(cold.fixed[i], ready.recursive.rows.fixed[i]);
    const row_storage = &ready.recursive.rows;
    var g_rows: usize = row_storage.fixed[0].len;
    inline for (20..23) |i| g_rows += row_storage.fixed[i].len;
    std.debug.print("V7_LOOKUP_COMPACT_CENSUS q=8 retained_bytes={d} g_rows={d} xor_rows={d} arithmetic_rows={d} inverse_rows={d} readonly_rows={d}\n", .{ try row_storage.retainedBytes(), g_rows, row_storage.fixed[1].len, row_storage.fixed[3].len, row_storage.fixed[4].len, row_storage.fixed[16].len });
    const live_base = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &ready.recursive, parent_profile);
    try std.testing.expectEqualDeep(expected_base, live_base);
    const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, .{ .children = &.{ready.values} }, &roster);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.init(a, &ready.recursive.rows, admission);
    var plan_live = true;
    defer if (plan_live) plan.deinit();
    var proof = try plan.prove(a, &ready.recursive.rows);
    var proof_live = true;
    defer if (proof_live) proof.deinit();
    const bytes = try Parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    proof.deinit();
    proof_live = false;
    plan.deinit();
    plan_live = false;
    ready.deinit();
    ready_live = false;
    var verified = try Receive.verify(a, bytes, profile, key, cold.wires);
    defer verified.deinit();
    try std.testing.expectEqualDeep(verified.open.claims, expected_claims);
    // A well-formed changed physical claim retains geometry but cannot be
    // supplied to the same original-verifier proof.
    var forged_input = input;
    forged_input.claims[0] = input.claims[0].add(Q.one());
    const forged_profile = try Profile.Owned.derive(a, forged_input, .{});
    defer forged_profile.deinit();
    try std.testing.expectEqualDeep(profile.seal, forged_profile.seal);
    try std.testing.expectError(error.InvalidProviderBatchPublicClosure, Receive.verify(a, bytes, forged_profile, key, cold.wires));
    // Exact public-frame reconstruction rejects a changed root-coordinate map.
    const Public = @import("block_v7_lookup_compact_public_v1.zig");
    var canonical = try Public.reconstruct(a, profile);
    defer canonical.deinit();
    var changed = try canonical.clone(a);
    defer changed.deinit();
    changed.statement.roots_offset[0] += 1;
    try std.testing.expectError(error.UntrustedCompactLookupPublicFrame, Public.requireSameFrame(changed, canonical));
    // The separately selected key itself cannot be changed to match a proof.
    var bad_key = key;
    bad_key.preprocessed_root[0] ^= 1;
    if (Receive.verify(a, bytes, profile, bad_key, cold.wires)) |ok| {
        var bad = ok;
        bad.deinit();
        return error.AcceptedChangedCompactLookupParentKey;
    } else |_| {}
    std.debug.print("V7_LOOKUP_COMPACT_PARENT cold_live_key=true cold_live_rows=true detached_verify=true open_lookup_only=true proof_bytes={d} producer_rows=0\n", .{bytes.len});
}
