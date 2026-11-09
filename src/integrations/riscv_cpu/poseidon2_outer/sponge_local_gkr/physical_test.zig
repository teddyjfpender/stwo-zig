//! Closed standalone native PCS + GKR fixture. No execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("authority.zig");
const Source = @import("source.zig");
const Native = @import("native.zig");
const Fr = @import("fractions.zig");
const Eq = @import("equations.zig");
const Binding = @import("witness.zig");
const Global = @import("global_witness.zig");
const Component = @import("component.zig");
const Key = @import("key.zig").Key;
const Boundary = @import("boundary.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const W = Protocol.W;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Kind = enum(u32) { sponge_fragment = 0x53504752, detached_sponge_fragment = 0x53504753 };
const Expected = struct { kind: Kind = .sponge_fragment, ordinal: u32 = 0, statement: [32]u8 };
fn columns(data: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) void {
    const rows = @as(usize, 1) << @intCast(log);
    std.debug.assert(data.len == rows * out.len);
    for (out, 0..) |*c, i| c.* = .{ .log_size = log, .values = data[i * rows ..][0..rows] };
}
fn tupleTypes(comptime Data: bool, comptime detached: bool) type {
    comptime var types: [8]type = undefined;
    inline for (comptime R.rolesFor(detached), 0..) |role, i| types[i] = if (Data) Component.Data(role) else Component.Component(role);
    return std.meta.Tuple(&types);
}
fn globalDraw(manifest: [36]u8) !Eq.GlobalFor(O) {
    const shared = try @import("../pure_p2_manifest.zig").drawShared(manifest);
    return .{ .ram = .{ .offset = shared.ram.offset, .coefficients = shared.ram.coefficients }, .io = .{ .offset = shared.kio.offset, .coefficients = shared.kio.coefficients }, .wire = shared.wire };
}
fn mix(channel: *W.Channel, scope: anytype, receipt: [36]u8, owner: O, claims: [8][3]O) void {
    const detached = comptime !@hasField(@TypeOf(scope), "boundary");
    channel.mixU32s(if (detached) &.{ 0x53504753, 1, 9, 24 } else &.{ 0x53504752, 1, 9, 17 });
    channel.mixRoot(scope.manifest);
    channel.mixRoot(receipt);
    if (!detached) channel.mixFelts(&.{owner});
    for (claims) |pair| channel.mixFelts(pair[0..if (detached) 3 else 2]);
}
fn totalWidth(tree: usize, comptime detached: bool) usize {
    var count: usize = 0;
    inline for (comptime R.rolesFor(detached)) |role| count += switch (tree) {
        0 => R.fixedWidth(role),
        1 => R.mainWidth(role),
        else => R.interactionWidth(role),
    };
    return count;
}
test "serialized sponge complete physical source binding and fresh receiver" {
    try exercise(false);
}
test "serialized sponge detached physical source binding and Wire claim" {
    try exercise(true);
}
fn exercise(comptime detached: bool) !void {
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const profile = Protocol.Profile.op_target_b4_q72_p0_fold4_v1;
    const geometry = R.Geometry{ .calls = 1, .permutations = 1, .first_id = 1, .detached = detached };
    const instances = try geometry.instances();
    const expected_calls = [_]Boundary.Call{.{ .pointer = 0x4000, .epoch = 1, .tick = 4 }};
    const boundary = Boundary.Boundary{ .calls = &expected_calls };
    const boundary_digest = try boundary.digest();
    var key = try Key.init(a, profile, geometry);
    defer key.deinit();
    const expected = Expected{ .kind = if (detached) .detached_sponge_fragment else .sponge_fragment, .statement = if (detached) try key.statementDetached(geometry) else try key.statement(geometry, boundary_digest) };
    var source = try Source.Source.init(a, geometry, &.{@import("fixture.zig").call()}, &.{});
    defer source.deinit();
    var recorder = engine.stage_profile.Recorder.initWithOptions(a, "cpu", "serialized_sponge_fragment", .{ .capture_tasks = false, .capture_process_usage = true });
    defer recorder.deinit();
    var timer = try std.time.Timer.start();
    var scheme = try W.Prover.init(a, profile.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    var channel = Protocol.begin(profile, expected, key.identity, key.root);
    var shared = key.tree.retainShared();
    scheme.appendCommittedTree(a, shared, &channel) catch |err| {
        shared.deinit(a);
        return err;
    };
    var main_columns: [totalWidth(1, detached)]engine.pcs.ColumnEvaluation = undefined;
    var next: usize = 0;
    inline for (comptime R.rolesFor(detached), 0..) |role, i| {
        columns(source.main[i], instances[i].row_log, main_columns[next..][0..R.mainWidth(role)]);
        next += R.mainWidth(role);
    }
    try scheme.commitBorrowedStreamingWithRecorder(a, &main_columns, 64, &recorder, &channel);
    const scope = if (detached) Native.DetachedScope{ .statement = expected.statement, .fixed = key.root, .main = scheme.trees.items[1].root(), .manifest = @import("../pure_p2_native.zig").hashWords(&.{ 53, 17, 9 }), .ordinal = 0 } else Native.Scope{ .statement = expected.statement, .fixed = key.root, .main = scheme.trees.items[1].root(), .manifest = @import("../pure_p2_native.zig").hashWords(&.{ 53, 17, 9 }), .ordinal = 0, .boundary = boundary_digest };
    const provider = Fr.Provider{ .source = &source };
    var child = if (detached) try Native.proveDetachedUnboundWithOptions(a, scope, geometry, provider, .{ .coefficient_encoding = .fixed4 }) else try Native.proveUnboundWithOptions(a, scope, geometry, provider, boundary, .{ .coefficient_encoding = .fixed4 });
    defer child.deinit(a);
    var binding = try Binding.Witness.init(a, geometry, &child.challenges, provider, &child.result.artifact, child.eta);
    defer binding.deinit();
    const global = try globalDraw(scope.manifest);
    var data: tupleTypes(true, detached) = undefined;
    var components: tupleTypes(false, detached) = undefined;
    var globals: [8]Global.Witness = undefined;
    var initialized: usize = 0;
    defer inline for (0..8) |i| if (i < initialized) {
        data[i].deinit();
        globals[i].deinit();
    };
    var claims: [8][3]O = undefined;
    var inter_columns: [totalWidth(2, detached)]engine.pcs.ColumnEvaluation = undefined;
    next = 0;
    var offsets: [3]usize = @splat(0);
    inline for (comptime R.rolesFor(detached), 0..) |role, i| {
        globals[i] = try Global.generate(role, a, &source, global, 64 << 20);
        errdefer globals[i].deinit();
        data[i] = try Component.Data(role).init(a, geometry, child.terminal());
        initialized += 1;
        claims[i] = globals[i].claims;
        components[i] = .{ .log_size = instances[i].row_log, .public = .{ .calls = geometry.calls, .permutations = geometry.permutations, .first_id = geometry.first_id }, .data = &data[i], .challenges = child.challenges, .global_challenges = global, .global_claims = claims[i], .offsets = offsets };
        columns(binding.columns[i], instances[i].row_log, inter_columns[next..][0..16]);
        columns(globals[i].data, instances[i].row_log, inter_columns[next + 16 ..][0 .. R.interactionWidth(role) - 16]);
        next += R.interactionWidth(role);
        offsets[0] += R.fixedWidth(role);
        offsets[1] += R.mainWidth(role);
        offsets[2] += R.interactionWidth(role);
    }
    if (comptime detached) {
        const Frontier = A.crypto.keccak_sponge.serialized.frontier;
        const raw = try Frontier.row(0x4000, 1, 4, 1);
        var row: [Frontier.MAIN]O = undefined;
        for (raw, &row) |v, *x| x.* = O.fromBase(v);
        const tuple = Frontier.wireTuple(O, O.zero(), Frontier.owner(O, &row));
        const expected_consumer = (try A.evaluation.denominatorFor(O, global.wire.offset, &global.wire.coefficients, &tuple, true).inv()).neg();
        try std.testing.expect(claims[0][2].eql(expected_consumer));
        var residual: [1]O = undefined;
        var sink = A.evaluation.SinkFor(O){ .values = &residual };
        Frontier.emitWireFor(false, O, &row, O.zero(), O.one(), O.zero(), O.zero(), expected_consumer.neg(), global.wire, &sink);
        try std.testing.expect(residual[0].isZero());
    }
    const owner_claim = if (detached) O.zero() else try boundary.ownerClaim(child.challenges);
    mix(&channel, scope, child.digest, owner_claim, claims);
    try scheme.commitBorrowedStreamingWithRecorder(a, &inter_columns, 64, &recorder, &channel);
    var handles: [8]engine.air.component_prover.ForField(O).ComponentProver = undefined;
    inline for (0..8) |i| handles[i] = components[i].asProverComponent();
    owns = false;
    var proof = try W.Prover.prove(a, &handles, &channel, scheme, .{ .recorder = &recorder });
    defer proof.deinit(a);
    const encoded = try W.Wire.encodeProofBytesBinary(a, proof.proof);
    defer a.free(encoded);
    const produce_ns = timer.read();
    const local = try Native.encode(a, geometry, &child.result.proof);
    defer a.free(local);
    const artifact_dir = std.posix.getenv("STWO_OP_SPONGE_ARTIFACT_DIR");
    if (artifact_dir) |path| {
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
        try write(dir, "fragment.bin", encoded);
        try write(dir, "local.bin", local);
        var snapshot = try recorder.snapshot(a);
        defer snapshot.deinit(a);
        const json = try std.json.Stringify.valueAlloc(a, snapshot, .{});
        defer a.free(json);
        try write(dir, "stages.json", json);
    }
    // Fresh fixed tree, freshly parsed child and independently derived bindings.
    var receive_key = try Key.init(a, profile, geometry);
    defer receive_key.deinit();
    try std.testing.expectEqualSlices(u8, &key.identity, &receive_key.identity);
    try std.testing.expectEqualSlices(u8, &key.root, &receive_key.root);
    const receive_scope = if (detached) Native.DetachedScope{ .statement = try receive_key.statementDetached(geometry), .fixed = receive_key.root, .main = proof.proof.commitment_scheme_proof.commitments.items[1], .manifest = scope.manifest, .ordinal = 0 } else Native.Scope{ .statement = try receive_key.statement(geometry, try boundary.digest()), .fixed = receive_key.root, .main = proof.proof.commitment_scheme_proof.commitments.items[1], .manifest = scope.manifest, .ordinal = 0, .boundary = try boundary.digest() };
    var wrong_mode = geometry;
    wrong_mode.detached = !detached;
    try std.testing.expectError(error.SpongeLocalFixedGeometry, receive_key.require(wrong_mode));
    try std.testing.expectError(error.LocalGkrWireProfile, Native.decode(a, wrong_mode, local));
    var parsed = try Native.decode(a, geometry, local);
    defer parsed.deinit();
    var pending = if (detached) try Native.verifyDetachedPending(a, receive_scope, geometry, &parsed.proof, child.digest) else try Native.verifyPending(a, receive_scope, geometry, &parsed.proof, child.digest, boundary);
    defer pending.deinit(a);
    var receive_data: tupleTypes(true, detached) = undefined;
    var ndata: usize = 0;
    defer inline for (0..8) |i| if (i < ndata) receive_data[i].deinit();
    var receive_components: tupleTypes(false, detached) = undefined;
    var receive_offsets: [3]usize = @splat(0);
    const receive_global = try globalDraw(receive_scope.manifest);
    inline for (comptime R.rolesFor(detached), 0..) |role, i| {
        receive_data[i] = try Component.Data(role).init(a, geometry, pending.terminal());
        ndata += 1;
        receive_components[i] = .{ .log_size = instances[i].row_log, .public = .{ .calls = geometry.calls, .permutations = geometry.permutations, .first_id = geometry.first_id }, .data = &receive_data[i], .challenges = pending.challenges, .global_challenges = receive_global, .global_claims = claims[i], .offsets = receive_offsets };
        receive_offsets[0] += R.fixedWidth(role);
        receive_offsets[1] += R.mainWidth(role);
        receive_offsets[2] += R.interactionWidth(role);
    }
    try verify(detached, a, &receive_key, geometry, expected, scope, pending.digest, if (detached) O.zero() else try boundary.ownerClaim(pending.challenges), claims, &receive_components, &proof.proof);
    var wrong_geometry = geometry;
    wrong_geometry.first_id += 1;
    try std.testing.expectError(error.SpongeStatementAuthority, verify(detached, a, &receive_key, wrong_geometry, expected, scope, pending.digest, if (detached) O.zero() else try boundary.ownerClaim(pending.challenges), claims, &receive_components, &proof.proof));
    if (comptime !detached) {
        var forbidden = claims;
        forbidden[0][2] = O.one();
        try std.testing.expectError(error.SpongeNonexistentGlobalClaim, verify(detached, a, &receive_key, geometry, expected, scope, pending.digest, owner_claim, forbidden, &receive_components, &proof.proof));
    }
    if (comptime detached) {
        var wire_lie = claims;
        wire_lie[0][2] = wire_lie[0][2].add(O.one());
        if (verify(detached, a, &receive_key, geometry, expected, scope, pending.digest, O.zero(), wire_lie, &receive_components, &proof.proof)) |_| return error.SpongeFalseWireAccepted else |_| {}
    }
    var forged = claims;
    forged[0][0] = forged[0][0].add(O.one());
    forged[1][0] = forged[1][0].sub(O.one());
    if (verify(detached, a, &receive_key, geometry, expected, scope, pending.digest, if (detached) O.zero() else try boundary.ownerClaim(pending.challenges), forged, &receive_components, &proof.proof)) |_| return error.SpongeBalancedGlobalClaimsAccepted else |_| {}
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &sha, .{});
    if (comptime !detached) {
        var golden: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&golden, "7b664a04002cb4f5321614a5366474822ca820ebe59424c7bedfd58959b70b11");
        try std.testing.expectEqualSlices(u8, &golden, &sha);
        try std.testing.expectEqual(@as(usize, 409328), encoded.len);
    }
    if (artifact_dir) |path| {
        var dir = try std.fs.cwd().openDir(path, .{});
        defer dir.close();
        const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-serialized-sponge-physical-v1", .geometry = geometry, .profile = @tagName(profile), .source_identity = std.fmt.bytesToHex(key.identity, .lower), .fixed = std.fmt.bytesToHex(key.root, .lower), .main = std.fmt.bytesToHex(scope.main, .lower), .manifest = std.fmt.bytesToHex(scope.manifest, .lower), .boundary = if (detached) @as(?[64]u8, null) else std.fmt.bytesToHex(boundary_digest, .lower), .detached = detached, .receipt = std.fmt.bytesToHex(pending.digest, .lower), .native_bytes = encoded.len, .local_bytes = local.len, .sha256 = std.fmt.bytesToHex(sha, .lower), .produce_ns = produce_ns, .requested_peak = budget.snapshot().peak_live_bytes, .fresh_source = true, .balanced_global_claims_rejected = true, .geometry_alias_rejected = true, .complete_execution = false, .production_admission = false, .security_qualified = false }, .{});
        defer a.free(json);
        try @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive(dir, "fragment.json", json);
        try std.posix.fsync(dir.fd);
    }
    std.debug.print("OP_SERIALIZED_SPONGE_PHYSICAL native_bytes={d} local_bytes={d} sha256={s} requested_peak={d} execution_accepted=false\n", .{ encoded.len, local.len, std.fmt.bytesToHex(sha, .lower), budget.snapshot().peak_live_bytes });
}
fn verify(comptime detached: bool, a: std.mem.Allocator, key: *const Key, g: R.Geometry, expected: Expected, scope: anytype, receipt: [36]u8, owner: O, claims: [8][3]O, components: *tupleTypes(false, detached), proof: anytype) !void {
    try key.require(g);
    if (!std.mem.eql(u8, &(if (detached) try key.statementDetached(g) else try key.statement(g, scope.boundary)), &expected.statement)) return error.SpongeStatementAuthority;
    var scheme = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(W.H, W.MC).init(a, key.profile.config());
    defer scheme.deinit(a);
    var channel = Protocol.begin(key.profile, expected, key.identity, key.root);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4 or !std.mem.eql(u8, &roots[0], &key.root) or !std.mem.eql(u8, &roots[1], &scope.main)) return error.SpongePhysicalRoots;
    const instances = try g.instances();
    for (0..3) |tree| {
        if (tree == 2) mix(&channel, scope, receipt, owner, claims);
        const logs = try a.alloc(u32, totalWidth(tree, detached));
        defer a.free(logs);
        var start: usize = 0;
        inline for (comptime R.rolesFor(detached), 0..) |role, i| {
            const width = switch (tree) {
                0 => R.fixedWidth(role),
                1 => R.mainWidth(role),
                else => R.interactionWidth(role),
            };
            @memset(logs[start..][0..width], instances[i].row_log);
            start += width;
        }
        try scheme.commit(a, roots[tree], logs, &channel);
    }
    var handles: [8]core.air.components.ForField(O).Component = undefined;
    inline for (0..8) |i| {
        components[i].global_claims = claims[i];
        try components[i].validate();
        handles[i] = components[i].asVerifierComponent();
    }
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(W.H) = undefined;
    try core.verifier.ForField(O).verifyBorrowedWithProofCapture(W.H, W.MC, a, &handles, &channel, &scheme, proof, &capture);
    defer capture.deinit(a);
}
