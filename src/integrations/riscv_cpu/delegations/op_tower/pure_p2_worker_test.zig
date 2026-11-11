//! Physical fragment gate; deliberately not an execution-admission fixture.
const std = @import("std");
const core = @import("stwo_core");
const T = @import("../../poseidon2_outer/pure_p2_tower_worker.zig");
const M = @import("../../poseidon2_outer/pure_p2_manifest.zig");
const O = core.fields.om31.OM31;
const F = core.fields.m31.M31;
const a = std.testing.allocator;
fn expectedWire(shared: M.Shared, packet: [20]u256, id: u32) !O {
    var sum = O.zero();
    for (0..32) |i| {
        const output = i >= 20;
        const coordinate = if (output) i - 20 else i;
        const value: u256 = if (!output) packet[coordinate] else if (coordinate == 0) 9 else if (coordinate == 6) 10 else if (coordinate == 8) 7 else 0;
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, value, .little);
        var tuple: [35]O = undefined;
        tuple[0] = O.fromBase(F.fromCanonical(12));
        tuple[1] = O.fromBase(F.fromCanonical(id));
        tuple[2] = O.fromBase(F.fromCanonical(@intCast(i)));
        for (tuple[3..], bytes) |*word, byte| word.* = O.fromBase(F.fromCanonical(byte));
        const inverse = try shared.wire.denominator(&tuple).inv();
        sum = if (output) sum.add(inverse) else sum.sub(inverse);
    }
    return sum;
}
pub fn exercise(comptime Hook: type) !void {
    return exerciseMode(Hook, false);
}
fn exerciseMode(comptime Hook: type, comptime sealed_parity: bool) !void {
    const profile = @import("../../poseidon2_outer/op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
    var key = try T.Key.init(a, profile, 8, 15);
    defer key.deinit();
    var fresh = try T.Key.init(a, profile, 8, 15);
    defer fresh.deinit();
    const span = T.Span{ .calls = 1, .first_id = 7 };
    const authority = try key.expected(span, 0);
    const trusted = try fresh.expected(span, 0);
    var packet: [20]u256 = @splat(0);
    packet[0] = 1;
    packet[12] = 3;
    packet[14] = 5;
    packet[16] = 7;
    packet[18] = 2;
    packet[19] = 3;
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OpTowerBudgetExceeded, T.Worker.init(fail.allocator(), &key, span, authority, &.{packet}, .{ .live_bytes = 1, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 1 << 20 }));
    try std.testing.expect(!fail.has_induced_failure);
    var worker = try T.Worker.init(a, &key, span, authority, &.{packet}, .{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 1 << 20 });
    defer worker.deinit();
    const stage = try worker.seal();
    try std.testing.expectEqual(@as(usize, 0), worker.frontier.main.len);
    try std.testing.expectEqual(@as(usize, 0), worker.arithmetic.main.len);
    try std.testing.expectEqual(@as(usize, 0), worker.arithmetic.fixed.len);
    // The manifest receiver rightly refuses a truth-only execution roster.
    // This hand-built test view exercises fragment proving only; the complete
    // CPU inventory gate must use verifyAndSeal and close its returned debt.
    try std.testing.expectError(error.GlobalGkrManifestRoster, M.validateExpected(&.{authority}));
    var entries = [_]M.Entry{.{ .authority = trusted, .scope = .{ .statement = trusted.statement, .fixed = trusted.fixed, .main = stage.main, .ordinal = 0 }, .local = null, .global_relations = trusted.global_relations }};
    const digest = try M.digest(@splat(3), &entries);
    var pending = M.Pending{ .entries = &entries, .digest = digest, .shared = try M.drawShared(digest) };
    const retained_advice = worker.frontier.retainedAdviceBytes() + worker.arithmetic.retainedAdviceBytes();
    var produced = try worker.complete(&pending, 0);
    try std.testing.expectEqual(@as(usize, 0), worker.arithmetic.interaction.len);
    try std.testing.expectEqual(@as(usize, 0), worker.arithmetic.inputs.len);
    defer produced.deinit(a);
    const framed = try T.encode(a, &produced);
    defer a.free(framed);
    var restored = try T.decode(a, framed, framed.len);
    defer restored.deinit(a);
    var capture: core.pcs.ForField(O).verifier.VerifiedProofCapture(@import("../../poseidon2_outer/pure_p2_worker_protocol.zig").W.H) = undefined;
    const claim = try T.verifyWithCapture(a, &fresh, span, trusted, &pending, 0, &restored, &capture);
    defer capture.deinit(a);
    if (sealed_parity) {
        const sealed = T.SealedScope{ .manifest = digest, .main = stage.main };
        const checked = try T.verifySealed(a, &fresh, span, trusted, sealed, &restored);
        try std.testing.expectEqualDeep(claim, checked);
        var other = try T.Worker.init(a, &key, span, authority, &.{packet}, .{ .live_bytes = 1 << 30, .main_bytes = 128 << 20, .interaction_bytes = 128 << 20, .advice_bytes = 1 << 20 });
        defer other.deinit();
        const second_stage = try other.seal();
        try std.testing.expectEqualSlices(u8, &stage.main, &second_stage.main);
        var bad = sealed;
        bad.main = @import("../../poseidon2_outer/pure_p2_native.zig").hashWords(&.{777});
        try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, other.completeSealed(bad));
        var bad_pending = pending;
        bad_pending.shared.wire.offset = bad_pending.shared.wire.offset.add(O.one());
        try std.testing.expectError(error.OpTowerManifestMismatch, other.complete(&bad_pending, 0));
        try std.testing.expect(!other.consumed);
        var second = try other.completeSealed(sealed);
        defer second.deinit(a);
        try std.testing.expectError(error.OpTowerPhase, other.completeSealed(sealed));
        try std.testing.expectEqualSlices(u8, produced.bytes, second.bytes);
        try std.testing.expectEqualDeep(produced.claims, second.claims);
        try std.testing.expectEqual(@as(usize, 0), other.budget.snapshot().live_bytes);
        try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, T.verifySealed(a, &fresh, span, trusted, bad, &restored));
        bad = sealed;
        bad.manifest = @import("../../poseidon2_outer/pure_p2_native.zig").hashWords(&.{778});
        try std.testing.expect(std.meta.isError(T.verifySealed(a, &fresh, span, trusted, bad, &restored)));
        try std.testing.expectError(error.OpTowerManifestMismatch, T.verify(a, &fresh, span, trusted, &bad_pending, 0, &restored));
        const changed_span = T.Span{ .calls = 1, .first_id = 8 };
        try std.testing.expectError(error.OpTowerStatementMismatch, T.verifySealed(a, &fresh, changed_span, trusted, sealed, &restored));
        try std.testing.expect(std.meta.isError(T.verifySealed(a, &fresh, changed_span, try fresh.expected(changed_span, 0), sealed, &restored)));
        var wrong_key = fresh; // Borrowed tree; never deinit this view.
        wrong_key.identity[0] ^= 1;
        try std.testing.expectError(error.OpTowerStatementMismatch, T.verifySealed(a, &wrong_key, span, trusted, sealed, &restored));
        try std.testing.expect(std.meta.isError(T.verifySealed(a, &wrong_key, span, try wrong_key.expected(span, 0), sealed, &restored)));
        std.debug.print("OP_MILLER_SEALED classic=true exact_bytes=true fresh_key=true phase_cleanup=true negative_MAIN_manifest_span_key_shared=true\n", .{});
    }
    if (comptime @hasDecl(Hook, "run")) try Hook.run(a, &fresh, span, trusted, &pending, &restored, &capture);
    try std.testing.expect(claim.wire.eql(try expectedWire(pending.shared, packet, 7)));
    try std.testing.expectError(error.UnclosedGlobalGkrWire, pending.checkGlobalClosure(&.{claim}));
    try std.testing.expectError(error.OpTowerEnvelope, T.decode(a, framed, framed.len - 1));
    try std.testing.expectError(error.OpTowerEnvelope, T.decode(a, framed[0 .. framed.len - 1], framed.len));
    try std.testing.expectError(error.OpTowerStatementMismatch, T.verify(a, &fresh, .{ .calls = 1, .first_id = 8 }, trusted, &pending, 0, &restored));
    var changed = trusted;
    changed.mass.wire += 1;
    try std.testing.expectError(error.OpTowerStatementMismatch, T.verify(a, &fresh, span, changed, &pending, 0, &restored));
    restored.claims[0] = restored.claims[0].add(O.one());
    restored.claims[2] = restored.claims[2].sub(O.one());
    try std.testing.expect(std.meta.isError(T.verify(a, &fresh, span, trusted, &pending, 0, &restored)));
    restored.claims = produced.claims;
    restored.bytes[restored.bytes.len - 1] ^= 1;
    try std.testing.expect(std.meta.isError(T.verify(a, &fresh, span, trusted, &pending, 0, &restored)));
    const budget = worker.budget.snapshot();
    try std.testing.expect(budget.peak_live_bytes <= budget.limit and !budget.exceeded);
    std.debug.print("OP_TOWER_BUDGET {any}\n", .{budget});
    std.debug.print("OP_PURE_P2_TOWER_WORKER bytes={} retained_advice={} active_calls=1 field=OM31 profile=target fragment_only=true\n", .{ framed.len, retained_advice });
}

test "OP pure P2 tower worker releases MAIN and freshly verifies a framed physical fragment" {
    try exercise(struct {});
}

test "OP Miller sealed pending classic fragment exact physical parity and authority guards" {
    try exerciseMode(struct {}, true);
}
