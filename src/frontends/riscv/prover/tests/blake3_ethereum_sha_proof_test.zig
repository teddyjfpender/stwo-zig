//! Complete admitted SHA/Keccak guest through the shared canonical leaf API.
const std = @import("std");
const core = @import("stwo_core");
const runner = @import("../../runner/mod.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Proof = @import("../blake3_ethereum_sha_proof.zig");
const Api = Proof.ForBackend(Cpu);
const Profile = @import("../blake3_ethereum_sha_profile.zig");

test "SHA combined canonical production leaf serializes and freshly verifies" {
    try check(false, false);
}
test "SHA combined canonical compact production leaf serializes and freshly verifies" {
    try check(true, false);
}
test "SHA combined canonical recursive parent freshly verifies" {
    try check(true, true);
}
fn check(comptime compact: bool, comptime recurse: bool) !void {
    const a = std.testing.allocator;
    const work = @import("stwo_prover_engine").work_pool;
    var pool: work.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try work.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    var timer = try std.time.Timer.start();
    const fixture = @import("../../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(16);
    defer run.deinit();
    var owner = if (compact) try Profile.Witness.initCompactRun(a, &run) else try Profile.Witness.initRun(a, &run);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    if (compact) {
        const Contract = @import("../compact_extension_contract.zig").ForProfile(Profile);
        var probe = std.testing.FailingAllocator.init(a, .{});
        const contract = Contract{ .allocator = probe.allocator(), .native = &owner.native.statement, .extension = &owner.statement, .ranges = owner.native.compact_ranges.?.plan };
        _ = try contract.validate(try owner.admission(), owner.hashes.logs);
        var bounded = std.testing.FailingAllocator.init(a, .{ .fail_index = probe.alloc_index });
        var channel = core.proof_suites.Blake3.Channel{};
        var once = contract;
        once.allocator = bounded.allocator();
        try once.mix(&channel, config, try owner.admission(), owner.hashes.logs);
        try std.testing.expectEqual(probe.alloc_index, bounded.alloc_index);
    }
    const key = if (compact) try Api.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan) else try Api.PreparedVerifier.init(a, &owner.native.statement, owner.statement, try owner.admission(), config);
    var key_alive = true;
    defer if (key_alive) key.deinit();
    var metadata: [Profile.ExtensionWire.extension_encoded_size]u8 = undefined;
    var metadata_stream = std.io.fixedBufferStream(&metadata);
    try Profile.ExtensionWire.encodeExtension(metadata_stream.writer(), &owner.statement);
    try std.testing.expectEqual(metadata.len, metadata_stream.pos);
    const statement = try Profile.ExtensionWire.decodeExtension(&metadata);
    try std.testing.expectEqualDeep(owner.statement, statement);
    const fresh = if (compact) try Api.PreparedVerifier.initCompact(a, &owner.native.statement, statement, try owner.admission(), config, owner.native.compact_ranges.?.plan) else try Api.PreparedVerifier.init(a, &owner.native.statement, statement, try owner.admission(), config);
    defer fresh.deinit();
    try std.testing.expectEqualDeep(key.id, fresh.id);
    const expected = fresh.id;
    // Exercise bounded census/replay: discard the first PCS before proving.
    // No interaction witness or caller-selected randomness crosses this barrier.
    const census_roots = blk: {
        var first = try Api.commitFirstRound(a, &owner, key, expected);
        defer first.deinit(a);
        try std.testing.expect(!owner.native.interaction_ready);
        try std.testing.expectEqual(@as(u64, 0), first.channel.n_draws);
        try std.testing.expectEqualDeep(key.root, first.roots[0]);
        try first.admitReplay(first.roots);
        inline for (0..2) |i| {
            var foreign = first.roots;
            foreign[i][0] ^= 1;
            try std.testing.expectError(error.CommitmentReplayMismatch, first.admitReplay(foreign));
        }
        break :blk first.roots;
    };
    if (compact and !recurse) {
        var foreign = census_roots;
        foreign[1][0] ^= 1;
        try std.testing.expectError(error.CommitmentReplayMismatch, Api.proveReplaying(a, &owner, key, expected, foreign, &pool));
        try std.testing.expect(!owner.native.interaction_ready);
    }
    var proved = try Api.proveReplaying(a, &owner, key, expected, census_roots, &pool);
    var proved_alive = true;
    defer if (proved_alive) proved.proof.deinit(a);
    try std.testing.expectEqualDeep(census_roots, proved.proof.stark.commitment_scheme_proof.commitments.items[0..2].*);
    const artifact = @import("../blake3_profile_artifact.zig").ForExecutionProfile(.rv32im_zkvm_ethereum_sha_v1);
    const published = try artifact.encode(a, &proved.proof, key, &elf, &.{}, .{});
    defer a.free(published.bytes);
    const raw = try Proof.codec.encode(a, &proved.proof, key, expected);
    proved.proof.deinit(a);
    proved_alive = false;
    defer a.free(raw);
    owner.deinit();
    owner_alive = false;
    key.deinit();
    key_alive = false;
    var tampered = try Proof.codec.decode(a, raw, fresh, expected);
    tampered.extension_claims.sha[0] = tampered.extension_claims.sha[0].add(core.fields.qm31.QM31.one());
    if (Api.verifyOwned(a, tampered, fresh, expected)) |_| return error.AcceptedWrongShaClaim else |_| {}
    const digest = try Api.verifyOwned(a, try Proof.codec.decode(a, raw, fresh, expected), fresh, expected);
    try std.testing.expectEqualDeep(proved.transcript_digest, digest);
    const source_digest = try artifact.ForBackend(Cpu).verify(a, published.bytes, published.statement_id, config, &elf, &.{}, .{});
    try std.testing.expectEqualDeep(digest, source_digest);
    var capture = try Api.verifyCaptureOwned(a, try Proof.codec.decode(a, raw, fresh, expected), fresh, expected);
    defer capture.deinit();
    if (recurse) {
        binding.deinit();
        binding_alive = false;
        try @import("../blake3_extension_parent_test_support.zig").check(true, a, fresh, &capture, expected, &pool);
    } else try @import("../blake3_extension_replay_test_support.zig").check(a, fresh, &capture, expected);
    std.debug.print("SHA_COMBINED_LEAF verified=true compact={any} source_artifact_verified=true sha_calls=2 keccak_calls=1 queries=70 pow_bits=26 artifact_bytes={d} elapsed_ns={d} witness_released=true fresh_key=true recursion_verified={any}\n", .{ compact, raw.len, timer.read(), recurse });
}

test "SHA joint block manifest drives a real canonical leaf transcript" {
    const a = std.testing.allocator;
    const engine = @import("stwo_prover_engine");
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    var binding_alive = true;
    defer if (binding_alive) binding.deinit();
    const fixture = @import("../../runner/guest_precompile/test_elf.zig");
    const diagnostic = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = fixture.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try runner.EthereumShaExecutionSession.initLegacy(a, &elf, .{});
    defer session.deinit();
    var run = try session.runLegacy(16);
    defer run.deinit();
    var owner = try Profile.Witness.initRun(a, &run);
    var owner_alive = true;
    defer if (owner_alive) owner.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const key = try Api.PreparedVerifier.init(a, &owner.native.statement, owner.statement, try owner.admission(), config);
    var key_alive = true;
    defer if (key_alive) key.deinit();
    const fresh = try Api.PreparedVerifier.init(a, &owner.native.statement, owner.statement, try owner.admission(), config);
    defer fresh.deinit();
    const expected = fresh.id;
    const roots = blk: {
        var round = try Api.commitFirstRound(a, &owner, key, expected);
        defer round.deinit(a);
        break :blk round.roots;
    };
    const manifest_mod = @import("../block_commitment_manifest.zig");
    const planned = @import("../block_component_plan.zig");
    var rows: [@typeInfo(planned.Kind).@"enum".fields.len]u64 = @splat(0);
    rows[@intFromEnum(planned.Kind.execution)] = 1;
    const context: manifest_mod.Context = .{ .job_id = expected, .relation_abi_id = @import("../../air/lang/relation.zig").registryOrderDigest(), .config = config, .rows = rows };
    const admission = manifest_mod.Admission{
        .instance = .{ .index = 0, .kind = .execution, .first_row = 0, .rows = 1, .log_rows = 1, .source_bytes = 8 },
        .air_id = expected,
        .key_id = expected,
        .statement_id = expected,
        .geometry_id = expected,
        .fixed_root = roots[0],
    };
    var builder = try manifest_mod.Builder.init(context, &.{admission});
    try builder.append(0, roots);
    const manifest = try builder.seal();
    var proved = try Api.proveWithManifest(a, &owner, key, expected, roots, manifest, &pool);
    defer proved.proof.deinit(a);
    try std.testing.expectEqualDeep(roots, proved.proof.stark.commitment_scheme_proof.commitments.items[0..2].*);
    const raw = try Proof.codec.encode(a, &proved.proof, key, expected);
    defer a.free(raw);
    owner.deinit();
    owner_alive = false;
    key.deinit();
    key_alive = false;
    if (Api.verifyOwned(a, try Proof.codec.decode(a, raw, fresh, expected), fresh, expected)) |_| return error.AcceptedJointProofAsLocal else |_| {}
    var foreign = manifest;
    foreign.digest[0] ^= 1;
    if (Api.verifyWithManifestOwned(a, try Proof.codec.decode(a, raw, fresh, expected), fresh, expected, roots, foreign)) |_| return error.AcceptedForeignManifest else |_| {}
    var foreign_roots = roots;
    foreign_roots[1][0] ^= 1;
    try std.testing.expectError(error.CommitmentReplayMismatch, Api.verifyWithManifestOwned(a, try Proof.codec.decode(a, raw, fresh, expected), fresh, expected, foreign_roots, manifest));
    const digest = try Api.verifyWithManifestOwned(a, try Proof.codec.decode(a, raw, fresh, expected), fresh, expected, roots, manifest);
    try std.testing.expectEqualDeep(proved.transcript_digest, digest);
    var capture = try Api.verifyCaptureWithManifestOwned(a, try Proof.codec.decode(a, raw, fresh, expected), fresh, expected, roots, manifest);
    defer capture.deinit();
    try capture.validate(fresh, expected);
    binding.deinit();
    binding_alive = false;
    try @import("../blake3_extension_parent_test_support.zig").check(true, a, fresh, &capture, expected, &pool);
    std.debug.print("SHA_JOINT_LEAF verified=true queries=70 pow_bits=26 manifest_bound=true wrong_manifest_rejected=true\n", .{});
}

test "two real SHA segments share manifest relation challenges" {
    const a = std.testing.allocator;
    const engine = @import("stwo_prover_engine");
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const fixture = @import("../../runner/guest_precompile/test_elf.zig");
    const elf = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    var session = try runner.EthereumShaExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var first = try session.startSegment(4);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 100);
    defer second.deinit();
    const Owner = @import("../blake3_ethereum_witness.zig").ShaOwner;
    var left = try Owner.initCompactSegment(a, &first);
    defer left.deinit();
    var right = try Owner.initCompactSegment(a, &second);
    defer right.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const lk = try Api.PreparedVerifier.initCompact(a, &left.native.statement, left.statement, try left.admission(), config, left.native.compact_ranges.?.plan);
    defer lk.deinit();
    const rk = try Api.PreparedVerifier.initCompact(a, &right.native.statement, right.statement, try right.admission(), config, right.native.compact_ranges.?.plan);
    defer rk.deinit();
    const roots = blk: {
        var l = try Api.commitFirstRound(a, &left, lk, lk.id);
        defer l.deinit(a);
        var r = try Api.commitFirstRound(a, &right, rk, rk.id);
        defer r.deinit(a);
        break :blk [2][2][32]u8{ l.roots, r.roots };
    };
    const span = @import("../../recursion/span_statement_blake3.zig");
    const segment = @import("../blake3_segment_statement.zig");
    const job = try segment.initJob(a, config, &first.base, &second.base, &left.native.statement.public_data, &right.native.statement.public_data);
    const statement = try segment.leaf(a, job, &first.base);
    const words = try statement.canonicalWords();
    const job_id = (try span.identity.hash(&words, .job)).bytes;
    const manifest_mod = @import("../block_commitment_manifest.zig");
    const planned = @import("../block_component_plan.zig");
    var rows: [@typeInfo(planned.Kind).@"enum".fields.len]u64 = @splat(0);
    rows[@intFromEnum(planned.Kind.execution)] = 2;
    const admissions = [2]manifest_mod.Admission{
        .{ .instance = .{ .index = 0, .kind = .execution, .first_row = 0, .rows = 1, .log_rows = 1, .source_bytes = 8 }, .air_id = lk.id, .key_id = lk.id, .statement_id = lk.id, .geometry_id = lk.id, .fixed_root = roots[0][0] },
        .{ .instance = .{ .index = 1, .kind = .execution, .first_row = 1, .rows = 1, .log_rows = 1, .source_bytes = 8 }, .air_id = rk.id, .key_id = rk.id, .statement_id = rk.id, .geometry_id = rk.id, .fixed_root = roots[1][0] },
    };
    const context = manifest_mod.Context{ .job_id = job_id, .relation_abi_id = @import("../../air/lang/relation.zig").registryOrderDigest(), .config = config, .rows = rows };
    var builder = try manifest_mod.Builder.init(context, &admissions);
    try builder.append(0, roots[0]);
    try builder.append(1, roots[1]);
    const manifest = try builder.seal();
    var lp = try Api.proveWithManifest(a, &left, lk, lk.id, roots[0], manifest, &pool);
    defer lp.proof.deinit(a);
    var rp = try Api.proveWithManifest(a, &right, rk, rk.id, roots[1], manifest, &pool);
    defer rp.proof.deinit(a);
    const codec = @import("../blake3_ethereum_sha_proof.zig").codec;
    const lb = try codec.encode(a, &lp.proof, lk, lk.id);
    defer a.free(lb);
    const rb = try codec.encode(a, &rp.proof, rk, rk.id);
    defer a.free(rb);
    var lv = try Api.verifyCaptureWithManifestOwned(a, try codec.decode(a, lb, lk, lk.id), lk, lk.id, roots[0], manifest);
    defer lv.deinit();
    var rv = try Api.verifyCaptureWithManifestOwned(a, try codec.decode(a, rb, rk, rk.id), rk, rk.id, roots[1], manifest);
    defer rv.deinit();
    try lv.validate(lk, lk.id);
    try rv.validate(rk, rk.id);
    try std.testing.expectEqualDeep(lv.relations, rv.relations);
    try std.testing.expectEqualDeep(lv.extension_draws, rv.extension_draws);
    try std.testing.expectEqualDeep(roots[0], lv.proof.commitments[0..2].*);
    try std.testing.expectEqualDeep(roots[1], rv.proof.commitments[0..2].*);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var file = try tmp.dir.createFile("left.proof", .{ .exclusive = true });
        defer file.close();
        try file.writeAll(lb);
    }
    {
        var file = try tmp.dir.createFile("right.proof", .{ .exclusive = true });
        defer file.close();
        try file.writeAll(rb);
    }
    const Receiver = @import("../block_manifest_receiver.zig").ForProfileBackend(Profile, Cpu);
    const keys = [_]*Api.PreparedVerifier{ lk, rk };
    const paths = [_][]const u8{ "left.proof", "right.proof" };
    var receipt = try Receiver.verifyPaths(a, tmp.dir, context, &admissions, &keys, &paths);
    defer receipt.deinit();
    try std.testing.expectEqualDeep(manifest, receipt.manifest);
    try std.testing.expectEqualDeep([_]core.channel.blake3.Digest{ lp.transcript_digest, rp.transcript_digest }, receipt.transcript_digests[0..2].*);
    try std.testing.expectError(error.InvalidComponentCensus, Receiver.verifyPaths(a, tmp.dir, context, &admissions, &keys, paths[0..1]));
    if (Receiver.verifyPaths(a, tmp.dir, context, &admissions, &keys, &.{ paths[1], paths[0] })) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.AcceptedReorderedBlockProofs;
    } else |_| {}
    if (Receiver.verifyPaths(a, tmp.dir, context, &admissions, &keys, &.{ paths[0], paths[0] })) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.AcceptedDuplicateBlockProof;
    } else |_| {}
    std.debug.print("SHA_JOINT_SEGMENTS verified=true segments=2 shared_relations=true job_admitted=true queries=70 pow_bits=26\n", .{});
}
