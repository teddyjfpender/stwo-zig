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

test "OP pure P2 packed leaves nodes continuation and lifting match scalar" {
    const H = core.vcs.poseidon2_m31_merkle.Poseidon2M31MerkleHasherV2;
    const modulus = core.fields.m31.Modulus;
    var values: [497][4]M = undefined;
    var columns: [497]struct { values: []const M, log_size: u32 } = undefined;
    var bytes: [4][497 * 4]u8 = undefined;
    for (&values, &columns, 0..) |*row, *column, i| {
        for (row, 0..) |*value, lane| {
            value.* = M.fromCanonical(@intCast((i * 1234567 + lane * 999999 + if (lane == 3) @as(u64, modulus - 1) else 0) % modulus));
            std.mem.writeInt(u32, bytes[lane][4 * i ..][0..4], value.v, .little);
        }
        column.* = .{ .values = row, .log_size = 2 };
    }
    var children: [8]H.Hash = undefined;
    for ([_]usize{ 0, 1, 11, 12, 13, 24, 53, 128, 497 }) |count| {
        var messages: [4][]const u8 = undefined;
        for (&messages, 0..) |*message, lane| message.* = bytes[lane][0 .. 4 * count];
        const actual = H.hashPackedLeavesWithSeed4(H.leafSeed(), &messages);
        var continued = [_]H{H.defaultWithInitialState()} ** 4;
        for (0..count) |i| H.updateM31Columns4(&continued, columns[i..][0..1], 0);
        const finished = H.finalize4(&continued);
        for (0..4) |lane| {
            var scalar = H.defaultWithInitialState();
            for (0..count) |i| scalar.updateLeaf(values[i][lane..][0..1]);
            try std.testing.expectEqualSlices(u8, &scalar.finalize(), &actual[lane]);
            try std.testing.expectEqualSlices(u8, &actual[lane], &finished[lane]);
            children[2 * lane] = actual[lane];
            children[2 * lane + 1] = finished[(lane + 1) % 4];
        }
        const nodes = H.hashChildrenWithSeed4(H.nodeSeed(), &children);
        for (0..4) |lane| try std.testing.expectEqualSlices(u8, &H.hashChildren(.{ .left = children[2 * lane], .right = children[2 * lane + 1] }), &nodes[lane]);
    }
    // Mixed offsets exercise the scalar fallback without altering each stream.
    var mixed = [_]H{H.defaultWithInitialState()} ** 4;
    for (0..4) |lane| mixed[lane].updateLeaf(values[0][0..lane]);
    var expected = mixed;
    H.updateM31Columns4(&mixed, columns[1..3], 0);
    for (0..4) |lane| for (1..3) |i| expected[lane].updateLeaf(values[i][lane..][0..1]);
    const mixed_final = H.finalize4(&mixed);
    for (0..4) |lane| try std.testing.expectEqualSlices(u8, &expected[lane].finalize(), &mixed_final[lane]);
    // Lower-height columns repeat lifted pairs, not adjacent scalar rows.
    columns[0].log_size = 1;
    const lifted = H.hashDirectLiftedM31LeavesWithSeed4(H.leafSeed(), columns[0..3], 0, 2);
    for (0..4) |lane| {
        var scalar = H.defaultWithInitialState();
        for (columns[0..3]) |column| {
            const shift: std.math.Log2Int(usize) = @intCast(2 - column.log_size + 1);
            const index = ((lane >> shift) << 1) + (lane & 1);
            scalar.updateLeaf(column.values[index..][0..1]);
        }
        try std.testing.expectEqualSlices(u8, &scalar.finalize(), &lifted[lane]);
    }
}

test "OP pure P2 manifest authenticates full roots source roster and shared draws" {
    const Manifest = @import("pure_p2_manifest.zig");
    const MCircuit = @import("pure_p2_manifest_circuit.zig");
    const Old = @import("../word16_global_execution/services/gkr_local/manifest.zig");
    const s = Native.Scope{ .statement = scope().statement, .fixed = scope().fixed, .main = scope().main, .ordinal = 0 };
    var produced = try Native.proveUnbound(a, s, &instances, Provider{});
    defer produced.deinit(a);
    const expected = [_]Manifest.Expected{.{ .kind = .cpu, .ordinal = 0, .global_relations = .{ .ram = true, .kio = true, .wire = true }, .mass = .{ .ram = 10, .kio = 10, .wire = 10 }, .statement = s.statement, .fixed_identity = [_]u8{0xde} ** 32, .fixed = s.fixed, .profile = .op_target_b4_q72_p0_fold4_v1, .local_instances = &instances }};
    const stages = [_]Manifest.StageOne{.{ .main = s.main, .local = .{ .proof = &produced.result.proof, .receipt = produced.digest } }};
    const execution = [_]u8{0xf7} ** 32;
    var sealed = try Manifest.verifyAndSeal(a, execution, &expected, &stages);
    defer sealed.deinit(a);
    try sealed.checkPhysicalRoots(0, s.fixed, s.main);
    const zero = C.O.zero();
    try sealed.checkGlobalClosure(&.{.{ .ram = zero, .kio = zero, .wire = zero }});
    try std.testing.expectError(error.UnclosedGlobalGkrRam, sealed.checkGlobalClosure(&.{.{ .ram = C.O.one(), .kio = zero, .wire = zero }}));
    var wrong = s.main;
    wrong[32] ^= 1;
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, sealed.checkPhysicalRoots(0, s.fixed, wrong));
    var forged_expected = expected;
    forged_expected[0].fixed = wrong;
    try std.testing.expectError(error.InvalidSumcheck, Manifest.verifyAndSeal(a, execution, &forged_expected, &stages));
    forged_expected = expected;
    forged_expected[0].mass.ram = core.fields.m31.Modulus;
    try std.testing.expectError(error.GlobalGkrCharacteristicBound, Manifest.verifyAndSeal(a, execution, &forged_expected, &stages));
    // Full roster accounting is relation-separated, including truth workers.
    var roster = [_]Manifest.Expected{ expected[0], expected[0], expected[0] };
    roster[1].kind = .keccak;
    roster[1].ordinal = 1;
    roster[1].local_instances = null;
    roster[1].global_relations = .{ .ram = false, .kio = true, .wire = false };
    roster[1].mass = .{ .ram = 0, .kio = 10, .wire = 0 };
    roster[2].kind = .secp_add;
    roster[2].ordinal = 2;
    roster[2].local_instances = null;
    roster[2].global_relations = .{ .ram = false, .kio = false, .wire = true };
    roster[2].mass = .{ .ram = 0, .kio = 0, .wire = 10 };
    const all_stages = [_]Manifest.StageOne{ stages[0], .{ .main = Native.hashWords(&.{77}), .local = null }, .{ .main = Native.hashWords(&.{88}), .local = null } };
    var complete = try Manifest.verifyAndSeal(a, execution, &roster, &all_stages);
    defer complete.deinit(a);
    const one = C.O.one();
    try complete.checkGlobalClosure(&.{ .{ .ram = zero, .kio = one, .wire = one }, .{ .ram = zero, .kio = one.neg(), .wire = zero }, .{ .ram = zero, .kio = zero, .wire = one.neg() } });
    try std.testing.expectError(error.NonzeroAbsentGlobalGkrClaim, complete.checkGlobalClosure(&.{ .{ .ram = zero, .kio = one, .wire = zero }, .{ .ram = one.neg(), .kio = zero, .wire = zero }, .{ .ram = zero, .kio = zero, .wire = zero } }));
    try std.testing.expectError(error.GlobalGkrManifestRoster, Manifest.verifyAndSeal(a, execution, &roster, all_stages[0..2]));
    std.mem.swap(Manifest.Expected, &roster[1], &roster[2]);
    try std.testing.expectError(error.GlobalGkrManifestOrdinal, Manifest.verifyAndSeal(a, execution, &roster, &all_stages));
    var owner = try C.PoseidonContext.init(a, 9);
    defer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const ctx = owner.algebra();
    const wire_scope = Child.Scope{ .statement = try digest(ctx, s.statement), .fixed = try root(ctx, s.fixed), .main = try root(ctx, s.main), .ordinal = try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, 0)) };
    const wire = try G.wireProof(ctx, &produced.result.proof);
    var child = try Child.verify(ctx, wire_scope, &instances, &wire);
    defer child.artifact.deinit(a);
    // Native receiver owns non-witness metadata; public ports carry full IDs
    // and roots. A future complete leaf must bind these to its physical proof.
    const AuthorityView = struct { kind: Old.Kind, global_relations: Old.Relations, mass: Old.Mass, profile: @import("op_profile.zig").Profile, fixed_identity: @import("full_p2_frame.zig").Digest };
    const CircuitEntry = struct { authority: AuthorityView, scope: Child.Scope, local: ?struct { digest: C.Hash } };
    const views = [_]CircuitEntry{.{ .authority = .{ .kind = .cpu, .global_relations = expected[0].global_relations, .mass = expected[0].mass, .profile = expected[0].profile, .fixed_identity = try digest(ctx, expected[0].fixed_identity) }, .scope = wire_scope, .local = .{ .digest = child.receipt } }};
    const manifest_root = try MCircuit.digest(ctx, try digest(ctx, execution), &views);
    for (manifest_root, try core.crypto.poseidon2_m31_sponge.decode(sealed.digest)) |actual, value| try std.testing.expect(ctx.get(actual).eql(Q.fromBase(value)));
    const shared = try MCircuit.drawShared(ctx, manifest_root);
    try std.testing.expect(shared.ram.offset.value().eql(sealed.shared.ram.offset));
    for (shared.ram.coefficients, sealed.shared.ram.coefficients) |actual, value| try std.testing.expect(actual.value().eql(value));
    inline for (.{ "kio", "wire" }) |name| {
        const actual = @field(shared, name);
        const value = @field(sealed.shared, name);
        inline for (std.meta.fields(@TypeOf(value))) |field| {
            const left = @field(actual, field.name);
            const right = @field(value, field.name);
            if (@typeInfo(@TypeOf(right)) == .array) {
                for (left, right) |x, y| try std.testing.expect(x.value().eql(y));
            } else try std.testing.expect(left.value().eql(right));
        }
    }
    try C.finish();
    active = false;
    try owner.setOutputs(&manifest_root);
    try owner.finalize();
    try std.testing.expect(try owner.isCircuitValid());
    try std.testing.expectEqual(@as(usize, 0), ctx.circuit.blake_g_gate.items.len);
    std.debug.print("OP_PURE_P2_MANIFEST_PARITY permutations={} roster_cases=cpu_keccak_secp all_RAM_KIO_Wire_coordinates_exact=true native_execution_acceptance=false\n", .{owner.calls.items.len});
}

test "OP pure P2 checked terminal view preserves legacy data and owns copied points" {
    const Legacy = @import("../word16_global_execution/services/gkr_local/child.zig");
    const Role = @import("../word16_global_execution/services/gkr_local/role.zig");
    const View = @import("../word16_global_execution/services/gkr_local/terminal_view.zig").Checked;
    const legacy_scope = @import("../word16_global_execution/services/gkr_local/receipt.zig").Scope{ .statement = [_]u8{3} ** 32, .fixed = [_]u8{4} ** 32, .main = [_]u8{5} ** 32, .ordinal = 0 };
    const produced = try Legacy.Unbound.prove(a, 64 << 20, legacy_scope, &instances, Provider{});
    defer produced.deinit();
    var pending = try Legacy.verifyPending(a, legacy_scope, &instances, &produced.result.proof, produced.digest);
    var live = true;
    defer if (live) pending.deinit(a);
    const checked = View{ .artifact = &pending.artifact, .challenges = pending.challenges, .eta = pending.eta };
    const legacy = try Role.Data.init(instances[0], &pending, 0);
    const next = try Role.Data.initChecked(instances[0], checked, 0);
    try std.testing.expect(std.meta.eql(legacy.instance, next.instance));
    try std.testing.expect(legacy.target_per_row.eql(next.target_per_row));
    try std.testing.expect(legacy.eta.eql(next.eta));
    try std.testing.expect(std.meta.eql(legacy.challenges, next.challenges));
    try std.testing.expectEqual(legacy.point.n, next.point.n);
    for (legacy.point.p[0..legacy.point.n], next.point.p[0..next.point.n]) |x, y| try std.testing.expect(x.eql(y));
    for (legacy.point.hc0[0..legacy.point.n], next.point.hc0[0..next.point.n]) |x, y| try std.testing.expect(x.eql(y));
    for (legacy.point.hc1[0..legacy.point.n], next.point.hc1[0..next.point.n]) |x, y| try std.testing.expect(x.eql(y));
    for (legacy.lane_weights[0..legacy.lane_count], next.lane_weights[0..next.lane_count]) |x, y| try std.testing.expect(x.eql(y));
    var malformed = pending.artifact;
    malformed.n_variables_by_instance = malformed.n_variables_by_instance[0..0];
    try std.testing.expectError(error.LocalGkrProjectionShape, Role.Data.initChecked(instances[0], .{ .artifact = &malformed, .challenges = pending.challenges, .eta = pending.eta }, 0));
    const before = next.point.eq0.add(next.point.eq1).add(next.point.hc0[0]).add(next.lane_weights[0]).add(next.target_per_row);
    pending.deinit(a);
    live = false;
    // The view is now invalid; the Data is not. No pointer to artifact-owned
    // row/terminal vectors survives the checked projection constructor.
    const after = next.point.eq0.add(next.point.eq1).add(next.point.hc0[0]).add(next.lane_weights[0]).add(next.target_per_row);
    try std.testing.expect(before.eql(after));
}
