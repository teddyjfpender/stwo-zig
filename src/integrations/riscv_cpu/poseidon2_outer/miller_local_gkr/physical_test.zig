//! Closed one-call physical qualification; not a production worker/receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const N = A.crypto.bn254_tower.narrow;
const Native = @import("native.zig");
const Inputs = @import("source_inputs.zig");
const Binding = @import("witness.zig");
const Global = @import("global_witness.zig");
const Component = @import("component.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const Classic = @import("../pure_p2_tower_worker.zig");
const Manifest = @import("../pure_p2_manifest.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
fn columns(data: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) void {
    const rows = @as(usize, 1) << @intCast(log);
    std.debug.assert(out.len * rows == data.len);
    for (out, 0..) |*column, c| column.* = .{ .log_size = log, .values = data[c * rows ..][0..rows] };
}
fn mix(channel: *W.Channel, manifest: [36]u8, receipt: [36]u8, claims: [2]O) void {
    channel.mixU32s(&.{ 0x4f504d47, 2, 8, 9, 2 });
    channel.mixRoot(manifest);
    channel.mixRoot(receipt);
    channel.mixFelts(&claims);
}
test "Miller local GKR complete physical source binding and fresh receiver" {
    const owner = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
    defer owner.destroy();
    const a = owner.allocator();
    const profile = Protocol.Profile.op_target_b4_q72_p0_fold4_v1;
    const geometry = @import("authority.zig").Geometry{ .calls = 1, .first_id = 7, .frontier_log = 8, .arithmetic_log = 15 };
    var fixed = try Classic.Key.init(a, profile, 8, 15);
    defer fixed.deinit();
    // Reuse the immutable fixed tree, but never its classic-interaction key id.
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@import("authority.zig").DOMAIN);
    hash.update(&fixed.identity);
    const identity = hash.finalResult();
    var expected = try fixed.expected(.{ .calls = 1, .first_id = 7 }, 0);
    expected.fixed_identity = identity;
    hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(@import("authority.zig").DOMAIN);
    hash.update(&expected.statement);
    expected.statement = hash.finalResult();
    const input = [_]N.trace.Input{@splat(1)};
    var frontier = try N.trace.SourceForField(.frontier, O).initWithoutFixed(a, &input, 7, 8);
    defer frontier.deinit();
    var arithmetic = try N.trace.SourceForField(.arithmetic, O).initWithoutFixed(a, &input, 7, 15);
    defer arithmetic.deinit();
    var scheme = try W.Prover.init(a, profile.config());
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    var channel = Protocol.begin(profile, expected, identity, fixed.root);
    var shared_tree = fixed.tree.retainShared();
    scheme.appendCommittedTree(a, shared_tree, &channel) catch |err| {
        shared_tree.deinit(a);
        return err;
    };
    var main: [403]engine.pcs.ColumnEvaluation = undefined;
    columns(frontier.main, 8, main[0..33]);
    columns(arithmetic.main, 15, main[33..]);
    try scheme.commitBorrowedStreaming(a, &main, 64, &channel);
    const moved_front = try frontier.takeMain();
    a.free(moved_front);
    const moved_arith = try arithmetic.takeMain();
    a.free(moved_arith);
    const scope = Native.Scope{ .statement = expected.statement, .fixed = fixed.root, .main = scheme.trees.items[1].root(), .manifest = @import("../pure_p2_native.zig").hashWords(&.{ 17, 20, 32 }), .ordinal = 0 };
    const provider = Inputs.Provider{ .frontier = &frontier, .arithmetic = &arithmetic };
    var child = try Native.proveUnboundWithOptions(a, scope, geometry, provider, .{ .coefficient_encoding = .fixed4 });
    defer child.deinit(a);
    var ch = child.challenges;
    ch.wire = (try Manifest.drawShared(scope.manifest)).wire;
    var binding = try Binding.Witness.init(a, geometry, &child.challenges, provider, &child.result.artifact, child.eta);
    defer binding.deinit();
    var front_global = try Global.generate(.frontier, a, &frontier, ch, 1 << 20);
    defer front_global.deinit();
    var arith_global = try Global.generate(.arithmetic, a, &arithmetic, ch, 2 << 20);
    defer arith_global.deinit();
    const claims = [2]O{ front_global.claim, arith_global.claim };
    var fd = try Component.Data(.frontier).init(a, geometry, child.terminal());
    defer fd.deinit();
    var ad = try Component.Data(.arithmetic).init(a, geometry, child.terminal());
    defer ad.deinit();
    const front = Component.Component(.frontier){ .log_size = 8, .public = .{ .calls = 1, .first_id = 7 }, .data = &fd, .challenges = ch, .global_claim = claims[0] };
    const arith = Component.Component(.arithmetic){ .log_size = 15, .public = .{ .calls = 1, .first_id = 7 }, .data = &ad, .challenges = ch, .global_claim = claims[1], .offsets = .{ N.source.FIXED, 33, 24 } };
    var inter: [80]engine.pcs.ColumnEvaluation = undefined;
    columns(binding.columns[3], 8, inter[0..16]);
    columns(front_global.data, 8, inter[16..24]);
    for (0..3) |index| columns(binding.columns[index], 15, inter[24 + 16 * index ..][0..16]);
    columns(arith_global.data, 15, inter[72..80]);
    mix(&channel, scope.manifest, child.digest, claims);
    try scheme.commitBorrowedStreaming(a, &inter, 64, &channel);
    const handles = [_]engine.air.component_prover.ForField(O).ComponentProver{ front.asProverComponent(), arith.asProverComponent() };
    owns_scheme = false;
    var proof = try W.Prover.prove(a, &handles, &channel, scheme, .{});
    defer proof.deinit(a);
    // Fresh fixed setup and fresh local-child verification independently derive
    // both source-terminal component authorities before native PCS acceptance.
    var receiver_key = try Classic.Key.init(a, profile, 8, 15);
    defer receiver_key.deinit();
    try std.testing.expectEqualSlices(u8, &fixed.root, &receiver_key.root);
    const wire_child = try Native.encode(a, geometry, &child.result.proof);
    defer a.free(wire_child);
    var parsed = try Native.decode(a, geometry, wire_child);
    defer parsed.deinit();
    var pending = try Native.verifyPending(a, scope, geometry, &parsed.proof, child.digest);
    defer pending.deinit(a);
    var rfd = try Component.Data(.frontier).init(a, geometry, pending.terminal());
    defer rfd.deinit();
    var rad = try Component.Data(.arithmetic).init(a, geometry, pending.terminal());
    defer rad.deinit();
    var receiver_front = front;
    receiver_front.data = &rfd;
    var receiver_arith = arith;
    receiver_arith.data = &rad;
    try verifyPhysical(a, profile, expected, identity, receiver_key.root, scope.manifest, pending.digest, claims, receiver_front, receiver_arith, &proof.proof);
    var forged_claims = claims;
    forged_claims[0] = forged_claims[0].add(O.one());
    forged_claims[1] = forged_claims[1].sub(O.one());
    // Even balanced external Wire debts must be authenticated by each proof.
    if (verifyPhysical(a, profile, expected, identity, receiver_key.root, scope.manifest, pending.digest, forged_claims, receiver_front, receiver_arith, &proof.proof)) |_| return error.ForgedBalancedWireClaimsAccepted else |_| {}
    const native_bytes = try W.Wire.encodeProofBytesBinary(a, proof.proof);
    defer a.free(native_bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(native_bytes, &digest, .{});
    std.debug.print("OP_MILLER_GKR_ARTIFACT native_bytes={d} local_bytes={d} sha256={s} requested_peak={d}\n", .{ native_bytes.len, wire_child.len, std.fmt.bytesToHex(digest, .lower), owner.snapshot().peak_live_bytes });
    std.debug.print("OP_MILLER_GKR_PHYSICAL calls=1 frontier_log=8 arithmetic_log=15 native_proof=true source_gkr=true fresh_receiver=true execution_accepted=false\n", .{});
}

fn verifyPhysical(a: std.mem.Allocator, profile: Protocol.Profile, expected: Manifest.Expected, identity: [32]u8, fixed_root: [36]u8, manifest: [36]u8, receipt: [36]u8, claims: [2]O, front_source: Component.Component(.frontier), arith_source: Component.Component(.arithmetic), proof: anytype) !void {
    var front = front_source;
    var arith = arith_source;
    front.global_claim = claims[0];
    arith.global_claim = claims[1];
    var receive = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, profile.config());
    defer receive.deinit(a);
    var receive_channel = Protocol.begin(profile, expected, identity, fixed_root);
    const roots = proof.commitment_scheme_proof.commitments.items;
    for (0..3) |tree| {
        if (tree == 2) mix(&receive_channel, manifest, receipt, claims);
        const widths = if (tree == 0) [2]usize{ N.source.FIXED, N.source.FIXED } else if (tree == 1) [2]usize{ 33, 370 } else [2]usize{ 24, 56 };
        const logs = try a.alloc(u32, widths[0] + widths[1]);
        defer a.free(logs);
        @memset(logs[0..widths[0]], 8);
        @memset(logs[widths[0]..], 15);
        try receive.commit(a, roots[tree], logs, &receive_channel);
    }
    const verify_handles = [_]core.air.components.ForField(O).Component{ front.asVerifierComponent(), arith.asVerifierComponent() };
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &verify_handles, &receive_channel, &receive, proof, &capture);
    defer capture.deinit(a);
}
