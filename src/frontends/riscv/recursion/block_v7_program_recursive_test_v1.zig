const std = @import("std");
test "v7 ROM independent recursive pieces codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_program_fixed_roster_v1.zig").Owned.derive);
    std.mem.doNotOptimizeAway(&@import("block_v7_program_preparation_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("block_v7_program_receiver_v1.zig").verify);
}

const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const Program = @import("../prover/block_v7_program_provider_v1.zig");
const Profile = @import("block_v7_program_fixed_profile_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
test "v7 ROM original proof to independently keyed detached parent" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    const leaves = [_]Tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 }, .{ .index = 4, .value = 5 }, .{ .index = 5, .value = 6 }, .{ .index = 6, .value = 7 }, .{ .index = 7, .value = 8 } };
    const rom = @import("../prover/block_v5_program_table_v1.zig").Plan{ .program_root = try Tree.TreeHasher.init(.program).root(&leaves), .leaves = &leaves, .multiplicities = &.{ 3, 2 }, .expected_fetches = 5, .log_size = 7 };
    var first = try Program.ForBackend(Cpu).commit(a, rom, config);
    var first_live = true;
    defer if (first_live) first.deinit(a);
    const entries = [_]E.Entry{try Program.firstEntry(rom, first.roots)};
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.program)] = 1;
    const epoch = try E.Epoch.init(@splat(71), config, counts, &entries, 1);
    const policy = Program.Policy{ .plan = rom, .expected_program_root = rom.program_root, .roots = first.roots, .epoch = epoch, .entries = &entries };
    var original = try Program.ForBackend(Cpu).prove(a, &first, policy);
    var original_live = true;
    defer if (original_live) original.deinit(a);
    first.deinit(a);
    first_live = false;
    var captured = try Program.ForBackend(Cpu).verifyAndCapture(a, &original, policy);
    defer captured.deinit();
    const input = Profile.Input{ .policy = policy, .claim = original.claim };
    original.deinit(a);
    original_live = false;
    const profile = try Profile.Owned.derive(a, input, .{});
    defer profile.deinit();
    // Different public epoch/roots/claim values must not select verifier
    // constants. The original proof does not purport to verify this mutation.
    var changed_entries = entries;
    changed_entries[0].roots[1][0] ^= 1;
    var changed = input;
    changed.policy.roots[1][0] ^= 1;
    changed.policy.entries = &changed_entries;
    changed.policy.epoch = try E.Epoch.init(@splat(72), config, counts, &changed_entries, 1);
    changed.claim = changed.claim.add(Q.one());
    const alternate = try Profile.Owned.derive(a, changed, .{});
    defer alternate.deinit();
    const Cold = @import("block_v7_program_fixed_transcript_v1.zig");
    var before = try Cold.derive(a, profile, 2, .{});
    defer before.deinit();
    var after = try Cold.derive(a, alternate, 2, .{});
    defer after.deinit();
    try std.testing.expectEqualDeep(before.id, after.id);
    try std.testing.expect(!std.meta.eql(profile.seal, alternate.seal));
    try qualify(a, input, profile, &captured);
}
fn qualify(a: std.mem.Allocator, input: Profile.Input, profile: *const Profile.Owned, capture: *const Program.VerifiedCapture) !void {
    const ColdRoster = @import("block_v7_program_fixed_roster_v1.zig");
    const Prepare = @import("block_v7_program_preparation_v1.zig");
    const Parent = @import("blake3_execution_parent_proof.zig");
    const Protocol = @import("block_v7_program_parent_protocol_v1.zig");
    const Receive = @import("block_v7_program_receiver_v1.zig");
    const parent_profile = @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0;
    var cold = ColdRoster.Owned.derive(a, input, 2, .{}) catch |err| {
        std.debug.print("ROM_PARENT phase=cold_roster error={s}\n", .{@errorName(err)});
        return err;
    };
    std.debug.print("ROM_PARENT phase=cold_roster done=true\n", .{});
    defer cold.deinit();
    const expected_base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, parent_profile);
    const roster = [_]Protocol.Bus.Expected{.{ .profile = profile.seal, .epoch = input.policy.epoch.digest, .roots = input.policy.roots }};
    const key = try Protocol.Key.fromGeometry(expected_base, cold.wires, &roster);
    var ready = Prepare.prepare(a, profile, capture, 2, .{}) catch |err| {
        std.debug.print("ROM_PARENT phase=live_prepare error={s}\n", .{@errorName(err)});
        return err;
    };
    std.debug.print("ROM_PARENT phase=live_prepare done=true\n", .{});
    var ready_live = true;
    defer if (ready_live) ready.deinit();
    try ready.recursive.rows.partitionHashRows();
    try cold.namespace.validateLive(&ready.recursive.rows);
    try std.testing.expectEqualDeep(cold.context, ready.recursive.context);
    try std.testing.expectEqualDeep(cold.wires, ready.wires);
    inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| try std.testing.expectEqualDeep(cold.fixed[i], ready.recursive.rows.fixed[i]);
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
    try std.testing.expect(verified.open.claim.eql(capture.receipt.claim));
    try std.testing.expectEqual(capture.receipt.fetch_count, verified.open.fetch_count);
    // A well-formed changed physical claim retains geometry but cannot be
    // supplied to the same original-verifier proof.
    var forged_input = input;
    forged_input.claim = input.claim.add(Q.one());
    const forged_profile = try Profile.Owned.derive(a, forged_input, .{});
    defer forged_profile.deinit();
    try std.testing.expectEqualDeep(profile.seal, forged_profile.seal);
    try std.testing.expectError(error.InvalidProviderBatchPublicClosure, Receive.verify(a, bytes, forged_profile, key, cold.wires));
    // Exact public-frame reconstruction rejects a changed root-coordinate map.
    const Public = @import("block_v7_program_public_v1.zig");
    var canonical = try Public.reconstruct(a, profile);
    defer canonical.deinit();
    var changed = try canonical.clone(a);
    defer changed.deinit();
    changed.statement.roots_offset[0] += 1;
    try std.testing.expectError(error.UntrustedProgramPublicFrame, Public.requireSameFrame(changed, canonical));
    // The separately selected key itself cannot be changed to match a proof.
    var bad_key = key;
    bad_key.preprocessed_root[0] ^= 1;
    if (Receive.verify(a, bytes, profile, bad_key, cold.wires)) |ok| {
        var bad = ok;
        bad.deinit();
        return error.AcceptedChangedProgramParentKey;
    } else |_| {}
    std.debug.print("V7_ROM_PARENT cold_live_key=true cold_live_rows=true detached_verify=true open_rom_only=true proof_bytes={d} producer_rows=0\n", .{bytes.len});
}

test "v7 ROM profile rejects mutable scalar geometry aliases" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    const leaves = [_]Tree.Leaf{ .{ .index = 0, .value = 1 }, .{ .index = 1, .value = 2 }, .{ .index = 2, .value = 3 }, .{ .index = 3, .value = 4 } };
    const rom = @import("../prover/block_v5_program_table_v1.zig").Plan{ .program_root = try Tree.TreeHasher.init(.program).root(&leaves), .leaves = &leaves, .multiplicities = &.{1}, .expected_fetches = 1, .log_size = 7 };
    const roots = [2][32]u8{ @splat(2), @splat(3) };
    const entries = [_]E.Entry{try Program.firstEntry(rom, roots)};
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.program)] = 1;
    const epoch = try E.Epoch.init(@splat(4), config, counts, &entries, 1);
    const p = try Profile.Owned.derive(a, .{ .policy = .{ .plan = rom, .expected_program_root = rom.program_root, .roots = roots, .epoch = epoch, .entries = &entries }, .claim = Q.zero() }, .{});
    defer p.deinit();
    p.config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedProgramFixedProfile, p.validate());
    p.config.pow_bits -= 1;
    p.lifting_log += 1;
    try std.testing.expectError(error.UntrustedProgramFixedProfile, p.validate());
    p.lifting_log -= 1;
    inline for (.{ "mask_log", "composition_log", "split" }) |field| {
        @field(p.shape, field) += 1;
        try std.testing.expectError(error.UntrustedProgramFixedProfile, p.validate());
        @field(p.shape, field) -= 1;
    }
    try p.validate();
}
