//! Complete two-CPU RV64 fixture under the explicitly mixed P2 physical suite.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Protocol = @import("worker_protocol.zig");
const W = Protocol.W;
const Key = @import("fixed_key.zig").Key;
const Worker = @import("cpu_worker.zig");
const Inventory = @import("inventory.zig").Inventory;
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const F = @import("../jumpdest_fixture.zig");
const M = @import("../gkr_local/manifest.zig");
const MW = @import("../gkr_local/manifest_wire.zig");
const Coordinator = @import("../gkr_local/coordinator.zig");
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
    const profile = Protocol.Profile.fixture_b4_q54_p0_fold4;
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
    const natives = [_]*@import("../../../word16_execution/prepared.zig").Prepared{ &captured.native[0], &captured.native[1] };
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
        var source = try @import("../pipeline.zig").buildCpuSource(a, setup_ptrs[i], requests[i], natives[i], &captured.advice, i, inventory.first_ids[i], false, null);
        worker.* = Worker.Worker.init(a, setup_ptrs[i], requests[i], source, inventory.workers[i], inventory.first_ids[i], &keys[i]) catch |err| {
            source.deinit();
            return err;
        };
        made += 1;
        stage.* = try worker.seal(a);
    }
    const manifest_bytes = try MW.encode(a, inventory.execution_identity, inventory.workers, &stages);
    defer a.free(manifest_bytes);
    var sender = try M.verifyAndSealFor(.flat, a, inventory.execution_identity, inventory.workers, &stages);
    defer sender.deinit(a);
    var decoded = try MW.decode(a, receiver_inventory.execution_identity, receiver_inventory.workers, manifest_bytes);
    defer decoded.deinit();
    var receiver = try M.verifyAndSealFor(.flat, a, receiver_inventory.execution_identity, receiver_inventory.workers, decoded.stages);
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
    // Cross-hash/version, canonical-root, ninth-limb and proof/public mutants.
    try std.testing.expectError(error.UnsupportedBinaryVersion, @import("stwo_proof_wire").ForField(W.O).decodeProofBytesBinary(a, proofs[0].bytes));
    const tree = try W.Wire.decodeProofBytesBinary(a, proofs[0].bytes);
    var native = tree;
    defer native.deinit(a);
    const last_root = Protocol.scopeRoot(profile, .main, native.commitment_scheme_proof.commitments.items[1]);
    var last_limb_mutation = native.commitment_scheme_proof.commitments.items[1];
    last_limb_mutation[32] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &last_root, &Protocol.scopeRoot(profile, .main, last_limb_mutation)));
    for (0..3) |case| {
        var mutated = try W.Wire.decodeProofBytesBinary(a, proofs[0].bytes);
        defer mutated.deinit(a);
        if (case == 0) mutated.commitment_scheme_proof.config.fri_config.n_queries -= 1 else if (case == 1) mutated.commitment_scheme_proof.commitments.items[1][32] ^= 1 else mutated.commitment_scheme_proof.proof_of_work = 1;
        const bytes = try W.Wire.encodeProofBytesBinary(a, mutated);
        defer a.free(bytes);
        var encoded = proofs[0];
        encoded.bytes = bytes;
        if (Worker.verify(a, receiver_ptrs[0], requests[0], receiver_inventory.workers[0], receiver_inventory.first_ids[0], &receiver, 0, &receiver_keys[0], &encoded, null)) |_| return error.PoseidonNativeAcceptedMutation else |_| {}
    }
    const Container = @import("wire.zig");
    const container_bytes = try Container.encode(a, profile, 0, &proofs[0]);
    defer a.free(container_bytes);
    var reloaded = try Container.decode(a, profile, 0, container_bytes);
    defer reloaded.deinit(a);
    _ = try Worker.verify(a, receiver_ptrs[0], requests[0], receiver_inventory.workers[0], receiver_inventory.first_ids[0], &receiver, 0, &receiver_keys[0], &reloaded, null);
    for ([_]usize{ 0, 8, 40, 44, container_bytes.len - 1 }) |at| {
        const bad = try a.dupe(u8, container_bytes);
        defer a.free(bad);
        bad[at] ^= 1;
        if (Container.decode(a, profile, 0, bad)) |value| {
            var owned = value;
            defer owned.deinit(a);
            if (Worker.verify(a, receiver_ptrs[0], requests[0], receiver_inventory.workers[0], receiver_inventory.first_ids[0], &receiver, 0, &receiver_keys[0], &owned, null)) |_| return error.PoseidonNativeContainerMutationAccepted else |_| {}
        } else |_| {}
    }
    try Hook.run(a, &receiver_ptrs, &requests, &receiver_keys, &receiver_inventory, &receiver, &proofs, &native, &capture);
    if (std.posix.getenv("STWO_RV64_P2_NATIVE_OUT_DIR")) |path| {
        var dir = try std.fs.cwd().makeOpenPath(path, .{ .iterate = true });
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "manifest.raw-blake.binary", .data = manifest_bytes });
        for (proofs, 0..) |proof, i| {
            var name_buf: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "cpu-{}.p2v2.binary", .{i});
            try dir.writeFile(.{ .sub_path = name, .data = proof.bytes });
            const container = try Container.encode(a, profile, @intCast(i), &proof);
            defer a.free(container);
            const container_name = try std.fmt.bufPrint(&name_buf, "cpu-{}.worker.binary", .{i});
            try dir.writeFile(.{ .sub_path = container_name, .data = container });
        }
        const metadata = try std.json.Stringify.valueAlloc(a, .{ .status = "fixtureP0;mixedPCS-P2v2/localGKR-manifest-rawBlake;no128claim", .profile = profile, .identity = profile.identity(), .execution = inventory.execution_identity, .requests = requests, .expected = .{ .total_steps = expected.total_steps, .max_total_steps = expected.max_total_steps, .final_pc = expected.final_pc, .final_registers = expected.final_registers, .program_identity = expected.program_identity, .image_identity = expected.admission.image_identity }, .fixed_roots = .{ keys[0].root, keys[1].root }, .fixed_ids = .{ keys[0].identity, keys[1].identity }, .workers = inventory.workers, .claims = .{ proofs[0].claims, proofs[1].claims } }, .{});
        defer a.free(metadata);
        try dir.writeFile(.{ .sub_path = "source-publics.json", .data = metadata });
    }
    std.debug.print("P2_NATIVE_FULL_CPU_FIXTURE physical=2 steps=5 hash_words=9 local_gkr=rawBlake manifest=rawBlake physical_fs=P2v2 beta=2 q=54 pow=0 fresh_receiver=true global_closure=true capture=true mutants=4 bytes=[{},{}] certified=false\n", .{ proofs[0].bytes.len, proofs[1].bytes.len });
}
test "P2 native complete CPU fixture fresh receiver closure and capture" {
    try exercise(struct {
        pub fn run(_: std.mem.Allocator, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype, _: anytype) !void {}
    });
}
