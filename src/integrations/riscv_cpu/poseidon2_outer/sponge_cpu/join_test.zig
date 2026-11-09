//! Complete closed two-CPU + detached sponge + Keccak truth physical join.
//! Real execution, one MAIN manifest, fresh source keys, all shared buses close.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const Fixture = @import("../../word16_global_execution/services/sponge_fixture.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const G = @import("../../word16_global_execution/protocol.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Pipeline = @import("../../word16_global_execution/services/pipeline.zig");
const Source = @import("source.zig");
const CPU = @import("worker.zig");
const Key = @import("key.zig").Key;
const Detached = @import("../sponge_local_gkr/worker.zig");
const DAuthority = @import("../sponge_local_gkr/authority.zig");
const DKey = @import("../sponge_local_gkr/key.zig").Key;
const Truth = @import("../pure_p2_truth_worker.zig");
const KR = @import("../../word16_global_execution/keccak/shared/roster.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const Base = @import("../pure_p2_native.zig");
const Profile = @import("../pure_p2_worker_protocol.zig").Profile;
const Kio = @import("kio_plan.zig");
const Kind = enum(u32) { sponge_cpu = 0x53504350, detached = 0x53504753, keccak = 1 };
const Authority = struct { kind: Kind, global_relations: Manifest.Relations, mass: @import("../../word16_global_execution/services/gkr_local/manifest.zig").Mass, profile: Profile, fixed_identity: [32]u8 };
const Entry = struct { authority: Authority, scope: Base.Scope, local: ?struct { digest: [36]u8 } };
fn close(claims: []const Manifest.Claims) !void {
    var sum = Manifest.Claims{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() };
    for (claims) |c| {
        sum.ram = sum.ram.add(c.ram);
        sum.kio = sum.kio.add(c.kio);
        sum.wire = sum.wire.add(c.wire);
    }
    if (!sum.ram.isZero()) return error.SpongeJoinRam;
    if (!sum.kio.isZero()) return error.SpongeJoinKio;
    if (!sum.wire.isZero()) return error.SpongeJoinWire;
}
test "sponge CPU complete two-shard detached physical join fresh keys and all global closure" {
    try exerciseWithHook(false, void);
}
test "sponge CPU interleaved-retirement KIO hole physical join uses canonical proof order" {
    try exerciseWithHook(true, void);
}
pub fn exerciseWithHook(comptime hole: bool, comptime Hook: type) !void {
    return exerciseWithHookBacking(hole, Hook, std.testing.allocator);
}
/// A caller may bound independent outer qualification allocations with a
/// common ancestor. This native fixture always retains its unchanged4GiB cap.
pub fn exerciseWithHookBacking(comptime hole: bool, comptime Hook: type, backing: std.mem.Allocator) !void {
    const parent = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, 4 << 30);
    defer parent.destroy();
    const a = parent.allocator();
    var full_timer = try std.time.Timer.start();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    var captured = if (hole) try Fixture.Captured.initForOpWithDirectSecond(a) else try Fixture.Captured.initForOp(a);
    const program_words = if (hole) &Fixture.HOLE_WORDS else &Fixture.WORDS;
    const execution_steps: u32 = @intCast(program_words.len);
    defer captured.deinit();
    const profile = Profile.op_target_b4_q72_p0_fold4_v1;
    var setups: [2]R.CpuSetup = undefined;
    var keys: [2]Key = undefined;
    var workers: [2]CPU.Worker = undefined;
    var made: [3]usize = @splat(0);
    defer {
        for (workers[0..made[2]]) |*worker| worker.deinit();
        for (keys[0..made[1]]) |*key| key.deinit();
        for (setups[0..made[0]]) |*setup| setup.deinit();
    }
    var requests: [2]P.Request = undefined;
    var first_ids: [2][T.FAMILIES]u32 = @splat(@splat(1));
    for (&requests, 0..) |*request, ordinal| request.* = try Coordinator.requestView(&.{ &captured.native[0], &captured.native[1] }, &captured.advice, ordinal);
    try Coordinator.assignSpongeIds(&requests);
    var kio = try Kio.Plan.init(a, &requests, .{});
    defer kio.deinit();
    try kio.requireRequests(&requests);
    try kio.validateAdvice(&captured.advice);
    for (&first_ids, kio.direct) |*ids, span| ids[0] = span.first;
    try kio.requireFirstIds(&first_ids);
    try kio.requireTruthCoverage(&.{.{ .first = 1, .count = kio.total() }});
    var stages: [2]CPU.StageOne = undefined;
    for (&captured.native, &setups, &keys, &workers, &requests, &stages, 0..) |*prepared, *setup, *key, *worker, *request, *stage, ordinal| {
        var geometry = try prepared.geometry();
        geometry.boundary_log = Fixture.BOUNDARY_LOG;
        setup.* = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = program_words }, geometry, .{ .keccak = if (requests[ordinal].calls[0] != 0) 5 else null });
        made[0] += 1;
        key.* = try Key.init(a, setup, profile, 5);
        made[1] += 1;
        var frontier = try Source.Source.initCalls(a, captured.advice.sponge[ordinal].calls, request.sponge.calls, 5, @intCast(ordinal + 1), @intCast(ordinal));
        var owns_frontier = true;
        defer if (owns_frontier) frontier.deinit();
        var source = try Pipeline.buildCpuSourceForOp(a, setup, request.*, .{}, prepared, &captured.advice, ordinal, first_ids[ordinal], false, null);
        var owns_source = true;
        defer if (owns_source) source.deinit();
        worker.* = try CPU.Worker.init(a, setup, request.*, .{}, first_ids[ordinal], @intCast(ordinal), key, source, frontier, .{ .gkr_bytes = 1 << 30, .global_bytes = 128 << 20 });
        owns_frontier = false;
        owns_source = false;
        made[2] += 1;
        stage.* = try worker.seal();
        if (comptime Hook != void and @hasDecl(Hook, "cpu")) try Hook.cpu(a, worker, stage.*);
    }
    const expected = Fixture.expectedForSteps(captured.program.identity, captured.loaded, execution_steps);
    const materials = [_]*const @import("../../word16_execution/setup.zig").Materials{ &setups[0].materials, &setups[1].materials };
    const base_requests = [_]G.Old.Request{ requests[0].base, requests[1].base };
    try G.validateMaterials(&materials, &base_requests, expected);
    // Retirement-order hole in the second fixture: its later direct Keccak
    // call still gets proof ID2, before BOTH detached Sponge runs (IDs3..7).
    try std.testing.expectEqual(@as(u32, if (hole) 3 else 2), requests[0].sponge.first_id);
    try std.testing.expectEqual(@as(u32, if (hole) 6 else 5), requests[1].sponge.first_id);
    try std.testing.expectEqual(@as(u32, 1), requests[0].calls[0]);
    try std.testing.expectEqual(@as(u32, @intFromBool(hole)), requests[1].calls[0]);
    const geometry = DAuthority.Geometry{ .calls = 3, .permutations = 5, .first_id = kio.detached_first, .detached = true };
    var calls: [3]A.crypto.keccak_sponge.types.Call = undefined;
    const words = try a.alloc(A.crypto.keccak_sponge.types.State, captured.advice.sponge[0].words.len + captured.advice.sponge[1].words.len);
    defer a.free(words);
    var call_at: usize = 0;
    var word_at: u32 = 0;
    var perm_at: u32 = 0;
    for (captured.advice.sponge) |shard| {
        for (shard.calls) |original| {
            calls[call_at] = original;
            calls[call_at].first_word += word_at;
            calls[call_at].first_perm += perm_at;
            call_at += 1;
        }
        @memcpy(words[word_at..][0..shard.words.len], shard.words);
        word_at += @intCast(shard.words.len);
        perm_at += @intCast(shard.inputs.len);
    }
    try std.testing.expectEqual(@as(usize, geometry.calls), call_at);
    try std.testing.expectEqual(geometry.permutations, perm_at);
    var detached_key = try DKey.init(a, profile, geometry);
    defer detached_key.deinit();
    var detached = try Detached.Worker.init(a, geometry, &detached_key, 2, &calls, words, 128 << 20);
    defer detached.deinit();
    const detached_main = try detached.seal();
    var truth_setup = try KR.TruthSetup.init(a, Fixture.KECCAK_LOG);
    defer truth_setup.deinit();
    const truth = R.Truth{ .keccak = .{ .setup = &truth_setup, .first_id = 1, .calls = kio.total() } };
    var truth_key = try Truth.Key.init(a, truth, profile);
    defer truth_key.deinit();
    const truth_expected = try truth_key.expected(truth, 3);
    var truth_worker = try Truth.Worker.init(a, &truth_key, truth, Truth.SourceBuilder.fromAdvice(&captured.advice), truth_expected, .{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 16 << 20 });
    defer truth_worker.deinit();
    const truth_stage = try truth_worker.seal();
    var entries: [4]Entry = undefined;
    for (workers, stages, entries[0..2], 0..) |worker, stage, *entry, ordinal| entry.* = .{ .authority = .{ .kind = .sponge_cpu, .global_relations = .{ .ram = true, .kio = requests[ordinal].calls[0] != 0, .wire = true }, .mass = .{ .ram = 65536, .kio = 65536, .wire = requests[ordinal].sponge.calls }, .profile = profile, .fixed_identity = worker.key.identity }, .scope = .{ .statement = worker.expected.statement, .fixed = worker.key.root, .main = stage.main, .ordinal = @intCast(ordinal) }, .local = .{ .digest = stage.receipt } };
    entries[2] = .{ .authority = .{ .kind = .detached, .global_relations = .{ .ram = true, .kio = true, .wire = true }, .mass = .{ .ram = 65536, .kio = 65536, .wire = geometry.calls }, .profile = profile, .fixed_identity = detached_key.identity }, .scope = .{ .statement = detached.expected.statement, .fixed = detached_key.root, .main = detached_main, .ordinal = 2 }, .local = null };
    entries[3] = .{ .authority = .{ .kind = .keccak, .global_relations = truth_expected.global_relations, .mass = truth_expected.mass, .profile = profile, .fixed_identity = truth_key.identity }, .scope = .{ .statement = truth_expected.statement, .fixed = truth_key.root, .main = truth_stage.main, .ordinal = 3 }, .local = null };
    var execution_hash = std.crypto.hash.sha2.Sha256.init(.{});
    execution_hash.update("op-detached-sponge-two-cpu-closed-join/v1");
    execution_hash.update(&captured.program.identity);
    var plan_writer = Base.ReceiptWriter{};
    kio.emit(&plan_writer);
    const kio_policy = try plan_writer.finish();
    execution_hash.update(&kio_policy);
    for (entries) |entry| execution_hash.update(&entry.scope.statement);
    var writer = Base.ReceiptWriter{};
    try Manifest.emit(execution_hash.finalResult(), &entries, &writer);
    const manifest = try writer.finish();
    // Every MAIN is committed before any shared RAM/KIO/Wire challenge.
    var encoded: [2]CPU.Encoded = undefined;
    var encoded_made: usize = 0;
    defer for (encoded[0..encoded_made]) |*proof| proof.deinit(a);
    var phase_timer = try std.time.Timer.start();
    var cpu_ns: [2]u64 = undefined;
    for (&workers, &encoded, &cpu_ns) |*worker, *proof, *ns| {
        proof.* = try worker.complete(manifest);
        ns.* = phase_timer.lap();
        encoded_made += 1;
    }
    var fragment = try detached.complete(manifest);
    const detached_ns = phase_timer.lap();
    defer fragment.deinit(a);
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, truth_worker.completeSealed(.{ .manifest = manifest, .main = Base.hashWords(&.{ 991, 3 }) }));
    var truth_proof = try truth_worker.completeSealed(.{ .manifest = manifest, .main = truth_stage.main });
    defer truth_proof.deinit(a);
    const truth_ns = phase_timer.lap();
    const production_ns = full_timer.read();
    if (std.posix.getenv("STWO_OP_SPONGE_CPU_ARTIFACT_DIR")) |base_path| {
        const path = if (hole) try std.fs.path.join(a, &.{ base_path, "retirement-hole" }) else try a.dupe(u8, base_path);
        defer a.free(path);
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
        for (encoded, 0..) |proof, i| {
            const name = try std.fmt.allocPrint(a, "cpu-{d}.bin", .{i});
            defer a.free(name);
            try write(dir, name, proof.bytes);
            const local_name = try std.fmt.allocPrint(a, "cpu-{d}.local.bin", .{i});
            defer a.free(local_name);
            try write(dir, local_name, proof.local);
        }
        try write(dir, "detached.bin", fragment.bytes);
        try write(dir, "detached.local.bin", fragment.local);
        try write(dir, "keccak.bin", truth_proof.bytes);
        const data = try std.json.Stringify.valueAlloc(a, .{
            .scope = "two_real_CPU_shards_detached_sponge_Keccak_pending_production_admission",
            .security_qualified = false,
            .profile = @tagName(profile),
            .execution_steps = execution_steps,
            .interleaved_retirement_hole = hole,
            .kio_policy = kio_policy,
            .direct_spans = kio.direct,
            .sponge_spans = kio.sponge,
            .manifest = manifest,
            .entries = entries,
            .cpu_claims = .{ encoded[0].claims, encoded[1].claims },
            .detached_claims = fragment.claims,
            .keccak_claims = truth_proof.claims,
            .cpu_receipts = .{ encoded[0].receipt, encoded[1].receipt },
            .detached_receipt = fragment.receipt,
            .proof_bytes = .{ encoded[0].bytes.len, encoded[1].bytes.len, fragment.bytes.len, truth_proof.bytes.len },
            .cpu_columns = .{
                .{ setups[0].columnCount(0) + 3, setups[0].columnCount(1) + 8, workers[0].plan.inter_columns + 24 },
                .{ setups[1].columnCount(0) + 3, setups[1].columnCount(1) + 8, workers[1].plan.inter_columns + 24 },
            },
            .cpu_native_cells = .{ try cpuCells(a, &setups[0], 5), try cpuCells(a, &setups[1], 5) },
            .detached_geometry = geometry,
            .proof_sha256 = .{ hash(encoded[0].bytes), hash(encoded[1].bytes), hash(fragment.bytes), hash(truth_proof.bytes) },
            .cpu_proving_ns = cpu_ns,
            .detached_proving_ns = detached_ns,
            .truth_proving_ns = truth_ns,
            .producer_total_ns = production_ns,
            .requested_peak_bytes = parent.snapshot().peak_live_bytes,
        }, .{});
        defer a.free(data);
        try write(dir, "join-metadata.json", data);
    }
    var claims: [4]Manifest.Claims = undefined;
    for (&setups, requests, first_ids, stages, &encoded, claims[0..2], 0..) |*setup, request, ids, stage, *proof, *claim, ordinal| {
        var fresh = try R.CpuSetup.initForOpProgram(a, .{ .base = 4096, .words = program_words }, setup.materials.geometry, setup.bridges);
        defer fresh.deinit();
        var key = try Key.init(a, &fresh, profile, 5);
        defer key.deinit();
        try std.testing.expectEqualSlices(u8, &setup.materials.program.identity, &fresh.materials.program.identity);
        if (comptime Hook != void and @hasDecl(Hook, "verified")) {
            var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(@import("../pure_p2_worker_protocol.zig").W.H) = undefined;
            claim.* = try CPU.verifyWithCapture(a, &fresh, request, .{}, ids, @intCast(ordinal), &key, manifest, stage.main, proof, &capture);
            defer capture.deinit(a);
            try Hook.verified(a, &fresh, request, ids, @intCast(ordinal), &key, manifest, stage.main, proof, &capture);
        } else claim.* = try CPU.verify(a, &fresh, request, .{}, ids, @intCast(ordinal), &key, manifest, stage.main, proof);
        const previous = proof.claims[proof.claims.len - 1];
        proof.claims[proof.claims.len - 1] = previous.add(O.one());
        try std.testing.expectError(error.OodsNotMatching, CPU.verify(a, &fresh, request, .{}, ids, @intCast(ordinal), &key, manifest, stage.main, proof));
        proof.claims[proof.claims.len - 1] = previous;
    }
    var fresh_detached = try DKey.init(a, profile, geometry);
    defer fresh_detached.deinit();
    claims[2] = try Detached.verify(a, geometry, &fresh_detached, 2, manifest, detached_main, &fragment);
    var fresh_truth_setup = try KR.TruthSetup.init(a, Fixture.KECCAK_LOG);
    defer fresh_truth_setup.deinit();
    const fresh_truth = R.Truth{ .keccak = .{ .setup = &fresh_truth_setup, .first_id = 1, .calls = kio.total() } };
    var fresh_truth_key = try Truth.Key.init(a, fresh_truth, profile);
    defer fresh_truth_key.deinit();
    claims[3] = try Truth.verifySealed(a, &fresh_truth_key, fresh_truth, try fresh_truth_key.expected(fresh_truth, 3), .{ .manifest = manifest, .main = truth_stage.main }, &truth_proof);
    try close(&claims);
    var changed_scope = Truth.SealedScope{ .manifest = manifest, .main = Base.hashWords(&.{ 991, 3 }) };
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, Truth.verifySealed(a, &fresh_truth_key, fresh_truth, try fresh_truth_key.expected(fresh_truth, 3), changed_scope, &truth_proof));
    changed_scope = .{ .manifest = Base.hashWords(&.{ 992, 4 }), .main = truth_stage.main };
    if (Truth.verifySealed(a, &fresh_truth_key, fresh_truth, try fresh_truth_key.expected(fresh_truth, 3), changed_scope, &truth_proof)) |_| return error.AcceptedChangedTruthManifest else |_| {}
    var wrong_key = fresh_truth_key; // Borrowed test view; do not deinit twice.
    wrong_key.identity[0] ^= 1;
    if (Truth.verifySealed(a, &wrong_key, fresh_truth, try wrong_key.expected(fresh_truth, 3), .{ .manifest = manifest, .main = truth_stage.main }, &truth_proof)) |_| return error.AcceptedSubstitutedTruthKey else |_| {}
    var wrong_family = try fresh_truth_key.expected(fresh_truth, 3);
    wrong_family.kind = .secp_add;
    try std.testing.expectError(error.OpTruthExpected, Truth.verifySealed(a, &fresh_truth_key, fresh_truth, wrong_family, .{ .manifest = manifest, .main = truth_stage.main }, &truth_proof));
    // Opposed debt preserves the numeric sum but cannot alter either committed
    // physical proof. Coverage/closure alone never authenticates components.
    var balanced = claims;
    balanced[0].wire = balanced[0].wire.add(O.one());
    balanced[2].wire = balanced[2].wire.sub(O.one());
    try close(&balanced);
    var missing = claims;
    missing[2].wire = O.zero();
    try std.testing.expectError(error.SpongeJoinWire, close(&missing));
    var wrong_requests = base_requests;
    wrong_requests[1].cpu.initial_pc += 4;
    try std.testing.expectError(error.GlobalCpuBoundaryMismatch, G.validateMaterials(&materials, &wrong_requests, expected));
    const old = fragment.claims[0][2];
    fragment.claims[0][2] = old.sub(O.one());
    const rejected = Detached.verify(a, geometry, &fresh_detached, 2, manifest, detached_main, &fragment);
    if (rejected) |_| return error.AcceptedDetachedBalancedWireForgery else |_| {}
    fragment.claims[0][2] = old;
    std.debug.print("OP_DETACHED_CPU_JOIN {{\"retirement_hole\":{},\"cpu_proving_ns\":{any},\"detached_ns\":{d},\"truth_ns\":{d},\"producer_total_ns\":{d},\"peak_requested_bytes\":{d},\"RAM_KIO_Wire_closed\":true,\"production_admission\":false}}\n", .{ hole, cpu_ns, detached_ns, truth_ns, production_ns, parent.snapshot().peak_live_bytes });
}
fn hash(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn cpuCells(a: std.mem.Allocator, setup: *const R.CpuSetup, log: u32) !u64 {
    var plan = try @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Plan.initForOp(a, setup);
    defer plan.deinit();
    var cells: u64 = @as(u64, 8 + 24) << @intCast(log);
    for (1..3) |tree| {
        const logs = if (tree == 1) try setup.logs(a, tree) else try plan.interLogs(a);
        defer a.free(logs);
        for (logs) |value| cells += @as(u64, 1) << @intCast(value);
    }
    return cells;
}
