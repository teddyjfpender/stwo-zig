//! Numerical gates for the new OP local P2 transcript. These are pending
//! lookup obligations, not execution acceptance or production activation.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const Native = @import("pure_p2_native.zig");
const Child = @import("full_p2_child.zig");
const C = @import("../rv64_recursion/om31_poseidon/common.zig");
const G = @import("../logup_gkr/om31_circuit_verifier.zig");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const B = circuit.builder;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
const instances = [_]Frame.Instance{
    .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 2, .fixed_offset = 0, .main_offset = 0 },
    .{ .origin = .{ .core = .binary }, .row_log = 6, .terms = 1, .fixed_offset = 123, .main_offset = 456 },
};
const Provider = struct {
    pub fn emit(_: @This(), instance: Frame.Instance, row: usize, sink: anytype) !void {
        for (0..instance.terms) |term| sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast(row / 2 + 137 * term))}, if (row & 1 == 0) M.one() else M.one().neg());
    }
};
fn scope() Native.Scope {
    return .{ .statement = [_]u8{0xa3} ** 32, .fixed = Native.hashWords(&.{ 0, 123, std.math.maxInt(u32) }), .main = Native.hashWords(&.{ 42, 17 }), .ordinal = 7 };
}
fn root(ctx: *C.Context, bytes: Native.Digest) !C.Hash {
    var wires: C.Hash = undefined;
    for (&wires, try core.crypto.poseidon2_m31_sponge.decode(bytes)) |*wire, value| wire.* = try ctx.guess(Q.fromBase(value));
    return wires;
}
fn digest(ctx: *C.Context, bytes: [32]u8) ![8]B.wrappers.U32Wrapper(C.Var) {
    var wires: [8]B.wrappers.U32Wrapper(C.Var) = undefined;
    for (&wires, 0..) |*wire, i| wire.* = try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, std.mem.readInt(u32, bytes[4 * i ..][0..4], .little)));
    return wires;
}
test "OP pure P2 numerical local GKR transcript receipt and eta match constrained verifier" {
    const native_scope = scope();
    var produced = try Native.proveUnbound(a, native_scope, &instances, Provider{});
    defer produced.deinit(a);
    var verified = try Native.verifyPending(a, native_scope, &instances, &produced.result.proof, produced.digest);
    defer verified.deinit(a);
    try std.testing.expect(produced.eta.eql(verified.eta));
    try std.testing.expectEqualSlices(C.O, produced.result.artifact.ood_point, verified.artifact.ood_point);

    var owner = try C.PoseidonContext.init(a, 9);
    defer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const ctx = owner.algebra();
    const child_scope = Child.Scope{ .statement = try digest(ctx, native_scope.statement), .fixed = try root(ctx, native_scope.fixed), .main = try root(ctx, native_scope.main), .ordinal = try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, native_scope.ordinal)) };
    const wire = try G.wireProof(ctx, &produced.result.proof);
    var pending = try Child.verify(ctx, child_scope, &instances, &wire);
    defer pending.artifact.deinit(a);
    try std.testing.expect(pending.eta.value().eql(verified.eta));
    for (pending.artifact.ood_point, verified.artifact.ood_point) |actual, expected| try std.testing.expect(actual.value().eql(expected));
    for (pending.artifact.claims_to_verify_by_instance, verified.artifact.claims_to_verify_by_instance) |actual, expected|
        for (actual, expected) |x, y| try std.testing.expect(x.value().eql(y));
    for (pending.receipt, try core.crypto.poseidon2_m31_sponge.decode(produced.digest)) |actual, expected| try std.testing.expect(ctx.get(actual).eql(Q.fromBase(expected)));
    try C.finish();
    active = false;
    try owner.setOutputs(&pending.receipt);
    try owner.finalize();
    try std.testing.expect(try owner.isCircuitValid());
    try std.testing.expectEqual(@as(usize, 0), ctx.circuit.blake_g_gate.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.circuit.triple_xor.items.len);
    const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "local_GKR_only_pending_physical_binding", .permutations = owner.calls.items.len, .raw = try owner.rawCounts(), .classic = try owner.census(false), .native_transcript_exact = true }, .{});
    defer a.free(json);
    std.debug.print("OP_PURE_P2_LOCAL_PARITY {s}\n", .{json});
    const changed = owner.calls.items[owner.calls.items.len / 2].outputs[0];
    ctx.value_table.items[changed] = ctx.get(.{ .idx = changed }).add(Q.one());
    try std.testing.expect(!try owner.isCircuitValid());
}
test "OP pure P2 local receipt and scope mutations reject without execution admission" {
    const original = scope();
    var produced = try Native.proveUnbound(a, original, &instances, Provider{});
    defer produced.deinit(a);
    var forged = produced.digest;
    forged[32] ^= 1; // The ninth coordinate is authenticated too.
    try std.testing.expectError(error.LocalGkrReceiptMismatch, Native.verifyPending(a, original, &instances, &produced.result.proof, forged));
    var noncanonical = original;
    std.mem.writeInt(u32, noncanonical.main[32..36], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalPoseidonDigest, Native.begin(noncanonical, &instances));
    var other = original;
    other.ordinal += 1;
    if (Native.verifyPending(a, other, &instances, &produced.result.proof, produced.digest)) |value| {
        var owned = value;
        owned.deinit(a);
        return error.UnexpectedScopeAdmission;
    } else |err| try std.testing.expect(err != error.OutOfMemory);
    try std.testing.expect(!std.mem.eql(u8, &Native.hashWords(&.{0}), &Native.hashWords(&.{core.fields.m31.Modulus})));
    try std.testing.expect(!std.mem.eql(u8, &Native.hashBytes(&.{0}), &Native.hashBytes(&.{ 0, 0 })));
}
test "OP pure P2 typed framing preserves u32 u64 external IDs roots and vector boundaries" {
    var low = Native.ReceiptWriter{};
    low.integer(0);
    var high = Native.ReceiptWriter{};
    high.integer(@as(u64, 1) << 32);
    try std.testing.expect(!std.mem.eql(u8, &try low.finish(), &try high.finish()));
    for ([_]u32{ core.fields.m31.Modulus, 1 << 31, std.math.maxInt(u32) }) |value| {
        var raw: [32]u8 = @splat(0);
        var plain = Native.ReceiptWriter{};
        plain.rawDigest(raw);
        std.mem.writeInt(u32, raw[28..32], value, .little);
        var changed = Native.ReceiptWriter{};
        changed.rawDigest(raw);
        try std.testing.expect(!std.mem.eql(u8, &try plain.finish(), &try changed.finish()));
    }
    var bad = C.O.zero();
    bad.c1.c1.b = M.fromU32Unchecked(core.fields.m31.Modulus);
    var writer = Native.ReceiptWriter{};
    try std.testing.expectError(error.NoncanonicalLocalGkrCoordinate, writer.field(bad));
    const original = scope();
    var produced = try Native.proveUnbound(a, original, &instances, Provider{});
    defer produced.deinit(a);
    const marginals = produced.result.artifact.claims_to_verify_by_instance;
    try std.testing.expectError(error.LocalGkrReceiptShape, Native.receipt(original, &.{}, &produced.result.proof, marginals));
    try std.testing.expectError(error.LocalGkrReceiptShape, Native.receipt(original, &instances, &produced.result.proof, marginals[0..1]));
    var truncated = produced.result.proof;
    truncated.layer_masks_by_instance = truncated.layer_masks_by_instance[0..1];
    try std.testing.expectError(error.LocalGkrReceiptShape, Native.receipt(original, &instances, &truncated, marginals));
}
fn localGraph(produced: *const Native.Unbound, native_scope: Native.Scope, trace_only: bool) !C.PoseidonContext {
    var owner = if (trace_only) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
    errdefer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const ctx = owner.algebra();
    const child_scope = Child.Scope{ .statement = try digest(ctx, native_scope.statement), .fixed = try root(ctx, native_scope.fixed), .main = try root(ctx, native_scope.main), .ordinal = try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, native_scope.ordinal)) };
    const wire = try G.wireProof(ctx, &produced.result.proof);
    var pending = try Child.verify(ctx, child_scope, &instances, &wire);
    defer pending.artifact.deinit(a);
    try C.finish();
    active = false;
    try owner.setOutputs(&pending.receipt);
    try owner.finalize();
    return owner;
}
test "OP pure P2 local verifier physical proof freshly verifies target profile and rejects tamper" {
    const Proof = @import("proof.zig");
    const Authority = @import("authority.zig").Authority;
    const profile = @import("op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    const native_scope = scope();
    var produced = try Native.proveUnbound(a, native_scope, &instances, Provider{});
    defer produced.deinit(a);
    var outputs: [9]Q = undefined;
    for (&outputs, try core.crypto.poseidon2_m31_sponge.decode(produced.digest)) |*wire, value| wire.* = Q.fromBase(value);
    var identity: [32]u8 = undefined;
    var timer = try std.time.Timer.start();
    const encoded = blk: {
        var producer = try localGraph(&produced, native_scope, false);
        defer producer.deinit();
        try std.testing.expect(try producer.isCircuitValid());
        var key = try Authority.initForProfile(a, &producer, profile);
        defer key.deinit();
        identity = key.identity;
        break :blk Proof.prove(a, &producer, &key, &outputs) catch |err| {
            std.debug.print("OP_P2_PHYSICAL_PHASE prove error={s} logs={any}\n", .{ @errorName(err), key.logs });
            if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
            return err;
        };
    };
    defer a.free(encoded);
    const produce_ns = timer.lap();
    var source = try localGraph(&produced, native_scope, true);
    defer source.deinit();
    var receiver = try Authority.initForProfile(a, &source, profile);
    defer receiver.deinit();
    try std.testing.expectEqualSlices(u8, &identity, &receiver.identity);
    try Proof.verify(a, &receiver, &outputs, encoded);
    const receive_ns = timer.lap();
    var wrong = outputs;
    wrong[8] = wrong[8].add(Q.one());
    try std.testing.expectError(error.PoseidonGlobalLookupSum, Proof.verify(a, &receiver, &wrong, encoded));
    const mutated = try a.dupe(u8, encoded);
    defer a.free(mutated);
    mutated[40] ^= 1;
    try std.testing.expectError(error.PoseidonGlobalLookupSum, Proof.verify(a, &receiver, &outputs, mutated));
    var other = try Authority.initForProfile(a, &source, .op_control_b2_q144_p0_fold4_v1);
    defer other.deinit();
    try std.testing.expectError(error.InvalidPoseidonFiveAuthority, Proof.verify(a, &other, &outputs, encoded));
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &proof_digest, .{});
    const proof_sha256 = std.fmt.bytesToHex(proof_digest, .lower);
    std.debug.print("OP_PURE_P2_LOCAL_PHYSICAL bytes={} produce_ns={} fresh_receive_ns={} rows={any} profile={s} sha256={s} native_execution_acceptance=false\n", .{ encoded.len, produce_ns, receive_ns, receiver.rows, @tagName(profile), proof_sha256 });
}
