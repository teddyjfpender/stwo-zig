//! Real complete modern services fixture at the exact production target
//! profile. Frame authentication itself belongs to the outer recursive root.
const std = @import("std");
const core = @import("stwo_core");
const V = @import("mod.zig");
const C = V.common;
const Root = @import("services_root.zig");
const CF = @import("../../word16_global_execution/services/gkr_local/coordinator_fixture.zig");
const Fixture = @import("../../word16_global_execution/services/fixture.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Row = @import("../../word16_global_execution/secp/row_roster.zig");
const Coordinator = @import("../../word16_global_execution/services/gkr_local/coordinator.zig");
const Execution = @import("../../word16_global_execution/services/gkr_local/execution.zig");
const MW = @import("../../word16_global_execution/services/gkr_local/manifest_wire.zig");
const Fixed = @import("../../word16_global_execution/services/gkr_local/fixed_authority.zig");
const FixedSet = @import("../../word16_global_execution/services/gkr_local/fixed_authority_set.zig").Set;
const W = @import("../../word16_global_execution/services/gkr_local/worker_protocol.zig");
const Cpu = @import("cpu_leaf.zig");
const a = std.testing.allocator;
test "OM31 services root metadata closes exact q108 P20 fold4 modern full fixture and rejects mutations" {
    var captured = try Fixture.Captured.init(a);
    defer captured.deinit();
    var keys = try CF.Keys.init(a);
    defer keys.deinit();
    var add = try Row.TruthSetup.init(a, .add, 8);
    defer add.deinit();
    var double = try Row.TruthSetup.init(a, .double, 8);
    defer double.deinit();
    const cpus = keys.pointers();
    const truths = [_]R.Truth{ .{ .keccak = .{ .setup = keys.keccak, .first_id = 1, .calls = 1 } }, .{ .secp_row = .{ .setup = &add, .first_id = 1, .calls = 1 } }, .{ .secp_row = .{ .setup = &double, .first_id = 1, .calls = 1 } } };
    const config = W.Candidate.configFor(.conjectured128_b2_q108_p20_fold4);
    var cache = try Fixed.Fixed.Cache.init(a, 1 << 30);
    defer cache.deinit();
    var fixed = try FixedSet.init(a, &cache, &cpus, &truths, config);
    defer fixed.deinit();
    const expected = Fixture.expectedFor(captured.program.identity);
    var bundle = try Coordinator.produceWithAuthority(a, &cpus, &truths, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, config, .{ .gkr_budget = 2 << 30 }, &fixed);
    defer bundle.deinit(a);
    _ = try bundle.verifyWithAuthority(a, &cpus, &truths, expected, config, &fixed);
    var inventory = try Execution.Inventory.initWithAuthority(a, &cpus, &truths, bundle.requests, expected, config, &fixed);
    defer inventory.deinit();
    var stages = try MW.decode(a, inventory.execution_identity, inventory.workers, bundle.stage_one_bytes);
    defer stages.deinit();
    var native_manifest = try stages.verifyAndSeal(a, inventory.execution_identity, inventory.workers);
    defer native_manifest.deinit(a);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var cpu_frames: [2]Root.CpuFrame = undefined;
    for (&cpu_frames, bundle.cpus, 0..) |*frame, encoded, i| frame.* = .{
        .words = try Cpu.expectedWords(scratch, cpus[i], bundle.requests[i], inventory.first_ids[i], inventory.workers[i], native_manifest.digest, stages.stages[i].main, native_manifest.entries[i].local.?.digest, encoded.claims),
        .physical_claims = encoded.claims,
        .terminal_marginals = native_manifest.entries[i].local.?.artifact.claims_to_verify_by_instance,
    };
    var truth_frames: [3][]const u32 = undefined;
    for (&truth_frames, truths, bundle.truths, 0..) |*frame, truth, encoded, i| {
        const ordinal = cpus.len + i;
        if (truth == .keccak) {
            var claims = [_]C.O{C.O.zero()} ** 5;
            @memcpy(claims[0..encoded.claims.len], encoded.claims);
            const words = V.keccak_leaf.statementWords(truth, .{ .ordinal = @intCast(ordinal), .statement = inventory.workers[ordinal].statement, .manifest = native_manifest.digest, .claims = claims }, stages.stages[ordinal].main);
            frame.* = try scratch.dupe(u32, &words);
        } else {
            const words = V.truth_leaf.statementWords(truth, .{ .ordinal = @intCast(ordinal), .statement = inventory.workers[ordinal].statement, .manifest = native_manifest.digest, .claim = encoded.claims[0] }, stages.stages[ordinal].main);
            frame.* = try scratch.dupe(u32, &words);
        }
    }
    const frames = Root.Frames{ .cpus = &cpu_frames, .truths = &truth_frames };
    const metadata = try Root.check(a, &cpus, &truths, bundle.requests, expected, config, &fixed, bundle.stage_one_bytes, frames, .{});
    try std.testing.expectEqual(native_manifest.digest, metadata.manifest.digest);
    try std.testing.expectEqual(@as(usize, 5), metadata.workers);
    // A caller cannot substitute a public frame, marginal or global claim.
    const bad_words = try scratch.dupe(u32, cpu_frames[0].words);
    bad_words[0] += 1;
    var bad = cpu_frames;
    bad[0].words = bad_words;
    try std.testing.expectError(error.ServicesRootCpuFrameMismatch, Root.check(a, &cpus, &truths, bundle.requests, expected, config, &fixed, bundle.stage_one_bytes, .{ .cpus = &bad, .truths = &truth_frames }, .{}));
    const bad_marginals = try scratch.dupe([]const C.O, cpu_frames[0].terminal_marginals);
    const bad_pair = try scratch.dupe(C.O, bad_marginals[0]);
    bad_pair[1] = bad_pair[1].add(C.O.one());
    bad_marginals[0] = bad_pair;
    bad = cpu_frames;
    bad[0].terminal_marginals = bad_marginals;
    try std.testing.expectError(error.ServicesRootReceiptMismatch, Root.check(a, &cpus, &truths, bundle.requests, expected, config, &fixed, bundle.stage_one_bytes, .{ .cpus = &bad, .truths = &truth_frames }, .{}));
    try std.testing.expectError(error.ServicesRootSidecarLimit, Root.check(a, &cpus, &truths, bundle.requests, expected, config, &fixed, bundle.stage_one_bytes, frames, .{ .max_public_words = 1 }));
    var wrong_truths = truth_frames;
    const tw = try scratch.dupe(u32, truth_frames[1]);
    tw[V.truth_leaf.Words.manifest] ^= 1;
    wrong_truths[1] = tw;
    try std.testing.expectError(error.TruthLeafStatementMismatch, Root.check(a, &cpus, &truths, bundle.requests, expected, config, &fixed, bundle.stage_one_bytes, .{ .cpus = &cpu_frames, .truths = &wrong_truths }, .{}));
    // Physical CPU target-profile circuit: Binding profile and FIXED identity
    // follow the same original native transcript as the real target route.
    var native = try V.cpu_capture.verify(a, cpus[0], bundle.requests[0], inventory.workers[0], inventory.first_ids[0], &native_manifest, 0, config, &bundle.cpus[0], fixed.at(0));
    defer native.deinit(a);
    const shape = try V.cpu_capture.geometry(scratch, cpus[0], config);
    const values = try V.proof.fromNative(scratch, &native.proof, &native.capture, &shape);
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    C.lane.begin(&ctx);
    var active = true;
    defer if (active) C.lane.finish() catch {};
    const proof = try V.proof.guess(&ctx, &values, &shape);
    var frame = V.frame.Frame.init(&ctx);
    const binding = fixed.at(0);
    var statement = try Cpu.Statement.init(&frame, cpus[0], bundle.requests[0], inventory.first_ids[0], inventory.workers[0], native_manifest.digest, bundle.cpus[0].claims, &proof, stages.stages[0].local.?.proof, config, .{ .identity = binding.fixed_identity, .root = binding.fixed_root, .profile = binding.profile });
    defer statement.deinit(&ctx);
    const verified = try V.verify(&ctx, &shape, &proof, &statement);
    try std.testing.expectEqual(native.channel.digestBytes(), verified.channel.raw.inner.debugDigest(&ctx));
    try std.testing.expectEqual(cpu_frames[0].words.len, frame.free_words.items.len);
    for (cpu_frames[0].words, frame.free_words.items) |word, wire| try std.testing.expectEqual(word, @import("stwo_circuit_frontend").builder.ivalue.unpackU32(C.Q, ctx.get(wire.get())));
    _ = try frame.finish();
    try C.lane.finish();
    active = false;
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    std.debug.print("CPU_TARGET_OM31_LEAF profile=q108/P20/fold4 vars={} gates={any}\n", .{ ctx.circuit.n_vars, ctx.gate_counts });
}
