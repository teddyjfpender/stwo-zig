//! Complete source-owned two-CPU gate for the new pure-P2 OP native suite.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("pure_p2_worker_protocol.zig");
const W = Protocol.W;
const Key = @import("pure_p2_fixed_key.zig").Key;
const Worker = @import("pure_p2_cpu_worker.zig");
const Inventory = @import("pure_p2_cpu_inventory.zig").Inventory;
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const F = @import("../word16_global_execution/services/jumpdest_fixture.zig");
const M = @import("pure_p2_manifest.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
pub fn exercise(comptime Hook: type) !void {
    return exerciseWithAllocator(std.testing.allocator, Hook);
}
pub fn exerciseWithAllocator(a: std.mem.Allocator, comptime Hook: type) !void {
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    const profile = Protocol.Profile.op_target_b4_q72_p0_fold4_v1;
    var setups: [2]R.CpuSetup = undefined;
    var fresh: [2]R.CpuSetup = undefined;
    var setup_count: usize = 0;
    defer for (setups[0..setup_count], fresh[0..setup_count]) |*setup, *receiver| {
        setup.deinit();
        receiver.deinit();
    };
    for (&setups, &fresh, 0..) |*setup, *receiver, i| {
        const geometry = try captured.native[i].geometry();
        setup.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, F.bridges[i]);
        receiver.* = R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, geometry, F.bridges[i]) catch |err| {
            setup.deinit();
            return err;
        };
        setup_count += 1;
    }
    const setup_ptrs = [_]*const R.CpuSetup{ &setups[0], &setups[1] };
    const receiver_ptrs = [_]*const R.CpuSetup{ &fresh[0], &fresh[1] };
    var keys: [2]Key = undefined;
    var receiver_keys: [2]Key = undefined;
    var key_count: usize = 0;
    defer for (keys[0..key_count], receiver_keys[0..key_count]) |*key, *receiver| {
        key.deinit();
        receiver.deinit();
    };
    for (&keys, &receiver_keys, 0..) |*key, *receiver, i| {
        key.* = try Key.init(a, setup_ptrs[i], profile);
        receiver.* = Key.init(a, receiver_ptrs[i], profile) catch |err| {
            key.deinit();
            return err;
        };
        key_count += 1;
        try std.testing.expectEqualSlices(u8, &key.root, &receiver.root);
        try std.testing.expectEqualSlices(u8, &key.identity, &receiver.identity);
    }
    const natives = [_]*@import("../word16_global_execution/services/../../word16_execution/prepared.zig").Prepared{ &captured.native[0], &captured.native[1] };
    var requests: [2]P.Request = undefined;
    for (&requests, 0..) |*request, i| request.* = try Coordinator.requestView(&natives, &captured.advice, i);
    const expected = F.expectedFor(captured.program.identity);
    var inventory = try Inventory.init(a, &setup_ptrs, &requests, expected, &keys, profile);
    defer inventory.deinit();
    var receiver_inventory = try Inventory.init(a, &receiver_ptrs, &requests, expected, &receiver_keys, profile);
    defer receiver_inventory.deinit();
    try std.testing.expectEqualSlices(u8, &inventory.execution_identity, &receiver_inventory.execution_identity);
    var workers: [2]Worker.Worker = undefined;
    var made: usize = 0;
    defer for (workers[0..made]) |*worker| worker.deinit();
    var stages: [2]M.StageOne = undefined;
    for (&workers, &stages, 0..) |*worker, *stage, i| {
        var source = try @import("../word16_global_execution/services/pipeline.zig").buildCpuSource(a, setup_ptrs[i], requests[i], natives[i], &captured.advice, i, inventory.first_ids[i], false, null);
        worker.* = Worker.Worker.init(a, setup_ptrs[i], requests[i], source, inventory.workers[i], inventory.first_ids[i], &keys[i]) catch |err| {
            source.deinit();
            return err;
        };
        made += 1;
        stage.* = try worker.seal(a);
    }
    var sender = try M.verifyAndSeal(a, inventory.execution_identity, inventory.workers, &stages);
    defer sender.deinit(a);
    // Independent source setup/key/endpoint admission and child transcript replay.
    // Durable manifest framing and a fresh-process receiver remain separate gates.
    var receiver = try M.verifyAndSeal(a, receiver_inventory.execution_identity, receiver_inventory.workers, &stages);
    defer receiver.deinit(a);
    var proofs: [2]Worker.Encoded = undefined;
    var proof_count: usize = 0;
    defer for (proofs[0..proof_count]) |*proof| proof.deinit(a);
    var claims: [2]M.Claims = undefined;
    var capture: core.pcs.ForField(W.O).verifier.VerifiedProofCapture(W.H) = undefined;
    var owns_capture = false;
    defer if (owns_capture) capture.deinit(a);
    for (&proofs, &claims, 0..) |*proof, *claim, i| {
        proof.* = try workers[i].complete(a, &sender, i);
        proof_count += 1;
        if (i == 0) {
            claim.* = try Worker.verify(a, receiver_ptrs[i], requests[i], receiver_inventory.workers[i], receiver_inventory.first_ids[i], &receiver, i, &receiver_keys[i], proof, &capture);
            owns_capture = true;
        } else claim.* = try Worker.verify(a, receiver_ptrs[i], requests[i], receiver_inventory.workers[i], receiver_inventory.first_ids[i], &receiver, i, &receiver_keys[i], proof, null);
    }
    try receiver.checkGlobalClosure(&claims);
    var wrong_source = receiver_inventory.workers[0];
    wrong_source.fixed_identity[0] ^= 1;
    try std.testing.expectError(error.PoseidonNativeFixedAuthorityMismatch, Worker.verify(a, receiver_ptrs[0], requests[0], wrong_source, receiver_inventory.first_ids[0], &receiver, 0, &receiver_keys[0], &proofs[0], null));
    var changed = try W.Wire.decodeProofBytesBinary(a, proofs[0].bytes);
    defer changed.deinit(a);
    changed.commitment_scheme_proof.commitments.items[1][32] ^= 1;
    const changed_bytes = try W.Wire.encodeProofBytesBinary(a, changed);
    defer a.free(changed_bytes);
    var forged = proofs[0];
    forged.bytes = changed_bytes;
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, Worker.verify(a, receiver_ptrs[0], requests[0], receiver_inventory.workers[0], receiver_inventory.first_ids[0], &receiver, 0, &receiver_keys[0], &forged, null));
    if (comptime @hasDecl(Hook, "run")) try Hook.run(a, &receiver_ptrs, &requests, &receiver_keys, &receiver_inventory, &receiver, &proofs, &capture);
    var hashes: [2][32]u8 = undefined;
    for (proofs, &hashes) |proof, *hash| std.crypto.hash.sha2.Sha256.hash(proof.bytes, hash, .{});
    std.debug.print("OP_PURE_P2_CPU_PHYSICAL workers=2 steps=5 local_gkr=P2v2 manifest=P2v2 physical=P2v2 profile={s} fresh_source_receiver=true global_RAM_KIO_Wire_closed=true proofs_bytes=[{},{}] sha256={s},{s} recursive_execution_acceptance=false\n", .{ @tagName(profile), proofs[0].bytes.len, proofs[1].bytes.len, std.fmt.bytesToHex(hashes[0], .lower), std.fmt.bytesToHex(hashes[1], .lower) });
}
test "OP pure P2 complete CPU physical fixture source terminal and global closure" {
    try exercise(struct {});
}
