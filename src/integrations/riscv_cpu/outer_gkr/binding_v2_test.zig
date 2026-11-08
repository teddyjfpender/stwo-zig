const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("binding_v2.zig");
const Legacy = @import("binding.zig");
const MP = @import("../logup_gkr/mle_point.zig");
const Public = @import("../word16_global_execution/services/gkr_local/public_aux.zig");
const Lane = @import("../rv64_recursion/om31_circuit_lane.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;

test "outer GKR v2 OODS hook derives auxiliaries and refuses unbound class versions" {
    const P = @import("profile.zig");
    const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
    const class = P.TEST_SMALL.withBindingV2();
    const component = P.Component.blake_g_gate;
    const log: u32 = class.row_logs[@intFromEnum(component)];
    var z: [MP.MAX_VARIABLES]O = undefined;
    rowPoint(class.layers(), 23, &z);
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const global = try core.circle.randomSecureFieldPointFor(O, &channel);
    const local = global.repeatedDouble(3);
    const aux = try B.auxFor(O, z[class.layers() - log .. class.layers()], local);
    const masks = B.MaskFor(O){ .eq = channel.drawSecureFelt(), .eq_next2 = channel.drawSecureFelt(), .prefix = channel.drawSecureFelt(), .prefix_previous = channel.drawSecureFelt() };
    const projection = channel.drawSecureFelt();
    const target = channel.drawSecureFelt();
    const expected = B.residualsFor(O, masks, aux, projection, target.mulM31(try M.fromU64(@as(u64, 1) << @intCast(log)).inv()));
    var values: [3]O = undefined;
    var sink = E.SinkFor(O){ .values = &values };
    try B.evaluateFor(O, &class, component, z[0..class.layers()], global, log + 3, masks, projection, target, &sink);
    try std.testing.expectEqual(@as(usize, 3), sink.count);
    for (values, expected) |actual, wanted| try std.testing.expect(actual.eql(wanted));
    try std.testing.expectError(error.OuterGkrBindingVersion, B.evaluateFor(O, &P.TEST_SMALL, component, z[0..class.layers()], global, log + 3, masks, projection, target, &sink));
    try std.testing.expectError(error.OuterGkrBindingShape, B.evaluateFor(O, &class, component, z[0..class.layers()], global, log - 1, masks, projection, target, &sink));
}

fn rowPoint(log: u32, seed: u32, out: []O) void {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    channel.mixU32s(&.{ 0x4f474232, log, seed });
    for (out[0..log]) |*z| z.* = channel.drawSecureFelt();
}

test "corpus OG01 outer GKR succinct OM31 auxiliaries equal interpolated public columns" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    for (1..11) |l| {
        const log: u32 = @intCast(l);
        var z: [MP.MAX_VARIABLES]O = undefined;
        rowPoint(log, log, &z);
        const mle = try MP.MleEvalPointFor(O).init(z[0..log]);
        var polys = try Public.init(a, &mle, log, null);
        defer for (&polys) |*poly| poly.deinit(a);
        for (0..3) |_| {
            const point = try core.circle.randomSecureFieldPointFor(O, &channel);
            const aux = try B.auxFor(O, z[0..log], point);
            var carry = O.zero();
            for (polys[0..8], 0..) |poly, c| {
                var basis: [8]M = @splat(M.zero());
                basis[c] = M.one();
                carry = carry.add(poly.evalAtPointFor(O, point).mul(O.fromM31Array(basis)));
            }
            try std.testing.expect(carry.eql(aux.carry));
            try std.testing.expect(polys[8].evalAtPointFor(O, point).eql(aux.first));
            try std.testing.expect(polys[9].evalAtPointFor(O, point).eql(aux.second));
            try std.testing.expect(mle.eq0.eql(aux.eq0) and mle.eq1.eql(aux.eq1));
        }
    }
}

test "corpus OG01 outer GKR circuit auxiliaries equal native at production logs" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    for ([_]u32{ 1, 2, 4, 8, 16, 23 }) |log| {
        var z: [MP.MAX_VARIABLES]O = undefined;
        rowPoint(log, 999, &z);
        const point = try core.circle.randomSecureFieldPointFor(O, &channel);
        const native = try B.auxFor(O, z[0..log], point);
        var ctx = try Lane.Context.init(a, 0);
        defer ctx.deinit();
        Lane.begin(&ctx);
        var open = true;
        defer if (open) Lane.finish() catch {};
        var wires: [MP.MAX_VARIABLES]Lane.Lane = undefined;
        for (wires[0..log], z[0..log]) |*wire, value| wire.* = try Lane.Lane.guess(&ctx, value);
        const result = try B.auxFor(Lane.Lane, wires[0..log], .{ .x = try Lane.Lane.guess(&ctx, point.x), .y = try Lane.Lane.guess(&ctx, point.y) });
        inline for (std.meta.fields(@TypeOf(native))) |field| {
            const actual = @field(result, field.name);
            try ctx.eq(actual.c0.v, try ctx.constant(@field(native, field.name).c0));
            try ctx.eq(actual.c1.v, try ctx.constant(@field(native, field.name).c1));
        }
        open = false;
        try Lane.finish();
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

fn residuals(cols: *const B.Columns, projection: []const O, z: []const O, target: O, k: usize) ![3]O {
    const log: u32 = @intCast(z.len);
    const n = cols.eq.len;
    const point = try MP.MleEvalPointFor(O).init(z);
    const p = MP.storageIndex(k, log);
    const t: usize = @ctz(~(k / 2));
    return B.residualsFor(O, .{
        .eq = cols.eq[p],
        .eq_next2 = cols.eq[MP.storageIndex((k + 2) % n, log)],
        .prefix = cols.prefix[p],
        .prefix_previous = cols.prefix[MP.storageIndex((k + n - 1) % n, log)],
    }, .{
        .first = if (k == 0) O.one() else O.zero(),
        .second = if (k == 1) O.one() else O.zero(),
        .carry = if (k % 2 == 0) point.hc0[t] else point.hc1[t],
        .eq0 = point.eq0,
        .eq1 = point.eq1,
    }, projection[p], target.mulM31(try M.fromU64(n).inv()));
}
fn valid(cols: *const B.Columns, projection: []const O, z: []const O, target: O) !bool {
    for (0..cols.eq.len) |k| for (try residuals(cols, projection, z, target, k)) |r| {
        if (!r.isZero()) return false;
    };
    return true;
}

test "corpus DW10 outer GKR forged E with Pre recomputed violates anchored Eq recurrence" {
    for (2..9) |l| {
        const log: u32 = @intCast(l);
        const n = @as(usize, 1) << @intCast(log);
        var z: [MP.MAX_VARIABLES]O = undefined;
        rowPoint(log, 10, &z);
        const eq = try Legacy.eqTable(a, z[0..log]);
        defer a.free(eq);
        const projection = try a.alloc(O, n);
        defer a.free(projection);
        var target = O.zero();
        for (projection, eq, 0..) |*value, e, i| {
            value.* = O.fromBase(M.fromU64(17 * i + 1));
            target = target.add(e.mul(value.*));
        }
        var cols = try B.columns(a, z[0..log], projection, target);
        defer cols.deinit(a);
        try std.testing.expect(try valid(&cols, projection, z[0..log], target));
        // Recompute a perfectly cyclic prefix using a forged all-zero E and
        // zero projection. The old unconstrained-E rule accepted this while
        // the v2 endpoint equations reject it even when recurrence is zero.
        @memset(cols.eq, O.zero());
        @memset(cols.prefix, O.zero());
        @memset(projection, O.zero());
        try std.testing.expect(!try valid(&cols, projection, z[0..log], O.zero()));
        // An interior mutation preserves BOTH endpoint equations. With a
        // zero projection the honest zero cyclic prefix still satisfies its
        // equation, so rejection here specifically exercises recurrence.
        @memcpy(cols.eq, eq);
        const interior = MP.storageIndex(2, log);
        cols.eq[interior] = cols.eq[interior].add(O.one());
        const interior_residuals = try residuals(&cols, projection, z[0..log], O.zero(), 2);
        try std.testing.expect(interior_residuals[0].isZero());
        try std.testing.expect(!interior_residuals[1].isZero());
        try std.testing.expect(interior_residuals[2].isZero());
        try std.testing.expect(!try valid(&cols, projection, z[0..log], O.zero()));
        // Scaling a real Eq table preserves its homogeneous recurrence, so
        // the endpoint equations must additionally pin its normalization.
        for (cols.eq, eq) |*value, e| value.* = e.add(e);
        try std.testing.expect(!try valid(&cols, projection, z[0..log], O.zero()));
    }
}

test "corpus DW11 outer GKR non-cyclic prefix edge and wrong terminal target reject" {
    const log: u32 = 5;
    var z: [MP.MAX_VARIABLES]O = undefined;
    rowPoint(log, 11, &z);
    const eq = try Legacy.eqTable(a, z[0..log]);
    defer a.free(eq);
    var projection: [32]O = undefined;
    var target = O.zero();
    for (&projection, eq, 0..) |*p, e, i| {
        p.* = O.fromBase(M.fromU64(i * i + 1));
        target = target.add(e.mul(p.*));
    }
    try std.testing.expectError(error.OuterGkrTerminalMismatch, B.columns(a, z[0..log], &projection, target.add(O.one())));
    var cols = try B.columns(a, z[0..log], &projection, target);
    defer cols.deinit(a);
    try std.testing.expect(try valid(&cols, &projection, z[0..log], target));
    // Break only the wrap edge: all other recurrence rows still satisfy.
    const last = MP.storageIndex(31, log);
    cols.prefix[last] = cols.prefix[last].add(O.one());
    const wrap = try residuals(&cols, &projection, z[0..log], target, 0);
    try std.testing.expect(!wrap[2].isZero());
    try std.testing.expect(!try valid(&cols, &projection, z[0..log], target));
}

test "corpus OG02 outer GKR degenerate row coordinates rejected natively and in circuit" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const point = try core.circle.randomSecureFieldPointFor(O, &channel);
    for ([_]O{ O.zero(), O.one() }) |bad| {
        const z = [_]O{ channel.drawSecureFelt(), bad, channel.drawSecureFelt() };
        try std.testing.expectError(error.DegenerateEvalPoint, B.auxFor(O, &z, point));
        var ctx = try Lane.Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        Lane.begin(&ctx);
        var open = true;
        defer if (open) Lane.finish() catch {};
        var wires: [3]Lane.Lane = undefined;
        for (&wires, z) |*wire, value| wire.* = try Lane.Lane.guess(&ctx, value);
        _ = try B.auxFor(Lane.Lane, &wires, .{ .x = try Lane.Lane.guess(&ctx, point.x), .y = try Lane.Lane.guess(&ctx, point.y) });
        open = false;
        try Lane.finish();
        try ctx.finalize(false);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}

test "corpus OG07 outer GKR binding v2 section has a distinct transcript and rejects v1" {
    const P = @import("profile.zig");
    const S = @import("section.zig");
    const CG = @import("circuit.zig");
    const v2 = P.TEST_SMALL.withBindingV2();
    const start = S.benchChannel();
    var inputs = try S.synthetic(a, &v2, 7, true);
    defer inputs.deinit(a);
    var section = try S.proveCpu(a, &start, &v2, &inputs);
    defer section.deinit(a);
    const words = try S.encode(a, &section);
    defer a.free(words);
    try std.testing.expectEqual(@as(u32, 2), words[1]);
    try std.testing.expect(!std.mem.eql(u8, &P.identityFor(.legacy_v1), &P.identityFor(.cyclic_eq_v2)));
    try std.testing.expectError(error.MalformedOuterGkrSection, S.decode(a, &P.TEST_SMALL, words));
    var native_ch = start;
    var verified = try S.verify(a, &native_ch, &section);
    defer verified.deinit(a);
    try S.requireClosure(&verified, O.zero());
    const expected = try S.terminalExpected(a, &inputs, &verified);
    defer a.free(expected);
    try S.requireTerminal(&verified, expected);
    var late_channel = S.StrictChannel{ .inner = native_ch };
    const late = Legacy.drawChallenges(&late_channel, v2.instances.len);
    try std.testing.expect(!late_channel.rejected);
    for (0..P.N_COMPONENTS) |ci| {
        const component: P.Component = @enumFromInt(ci);
        if (!P.gkrBound(component)) continue;
        const projection = try B.projectFromInputs(a, &v2, component, verified.artifact.ood_point, &inputs, &late);
        defer a.free(projection);
        const packed_projection = try @import("cpu_projection.zig").project(a, &v2, component, verified.artifact.ood_point, &inputs, &late);
        defer a.free(packed_projection);
        for (projection, packed_projection) |want, actual| try std.testing.expect(want.eql(actual));
        const target = Legacy.expectedBoundary(&v2, component, verified.artifact.claims_to_verify_by_instance, &late);
        const z = verified.artifact.ood_point[verified.artifact.ood_point.len - v2.row_logs[ci] ..];
        var cols = try B.columns(a, z, projection, target);
        defer cols.deinit(a);
        try std.testing.expect(try valid(&cols, projection, z, target));
    }
    const cost = try CG.measure(a, &section, O.zero(), expected);
    try std.testing.expect(cost.valid);
    // A version-word edit cannot launder v1: even if structural decode now
    // succeeds, the identity mixed before its first challenge is different.
    var legacy = try S.proveCpu(a, &start, &P.TEST_SMALL, &inputs);
    defer legacy.deinit(a);
    const old_words = try S.encode(a, &legacy);
    defer a.free(old_words);
    try std.testing.expectError(error.MalformedOuterGkrSection, S.decode(a, &v2, old_words));
    old_words[1] = 2;
    var relabelled = try S.decode(a, &v2, old_words);
    defer relabelled.deinit(a);
    var channel = start;
    if (S.verify(a, &channel, &relabelled)) |accepted| {
        var owned = accepted;
        owned.deinit(a);
        return error.RelabelledLegacySectionAccepted;
    } else |_| {}
}

test "corpus OG05 outer GKR source mass covers classic consumers and refuses characteristic wrap" {
    const P = @import("profile.zig");
    const good = P.LEAF_CPU_24628607.withBindingV2();
    try P.requireSecurityWithSource(good, 40, 8);
    try std.testing.expectError(error.OuterGkrSourceMassRequired, P.requireSecurity(good, 40));
    const mass = try P.sourceUseMass(good, 8);
    try std.testing.expect(mass < core.fields.m31.Modulus);
    // Keep every GKR-instance log and hence the old GKR-only mass unchanged,
    // but enlarge a CLASSIC component sharing the Gate relation. Source mass
    // must catch what conservativeMass() omits.
    var bad = good;
    bad.row_logs[@intFromEnum(P.Component.qm31_ops)] = 30;
    try std.testing.expectEqual(good.conservativeMass(), bad.conservativeMass());
    try std.testing.expectError(error.Om31CandidateCharacteristicWrap, P.requireSecurityWithSource(bad, 40, 8));
}

const RowGuardCost = struct { qm31: u64, valid: bool };
fn rowGuardCost(class: *const @import("profile.zig").Class, legacy: bool, bad_index: ?usize, bad_one: bool) !RowGuardCost {
    const CG = @import("circuit.zig");
    var ctx = try Lane.Context.init(a, 0);
    defer ctx.deinit();
    Lane.begin(&ctx);
    var open = true;
    defer if (open) Lane.finish() catch {};
    var point: [MP.MAX_VARIABLES]Lane.Lane = undefined;
    for (point[0..class.layers()], 0..) |*wire, i| {
        const value = if (bad_index != null and bad_index.? == i) (if (bad_one) O.one() else O.zero()) else O.fromBase(M.fromCanonical(@intCast(i + 2)));
        wire.* = try Lane.Lane.guess(&ctx, value);
    }
    if (legacy) {
        for (class.instances) |instance| _ = try MP.MleEvalPointFor(Lane.Lane).init(point[class.layers() - instance.row_log .. class.layers()]);
    } else try CG.requireRowPoint(&ctx, class, point[0..class.layers()]);
    open = false;
    try Lane.finish();
    try ctx.finalize(false);
    return .{ .qm31 = ctx.gate_counts.qm31_ops, .valid = try ctx.isCircuitValid() };
}

test "outer GKR direct row guard excludes every nested suffix degeneracy and preserves lane-only coordinates" {
    const P = @import("profile.zig");
    const class = P.LEAF_CPU_24628607.withBindingV2();
    var longest: usize = 0;
    for (class.instances) |instance| longest = @max(longest, instance.row_log);
    const first = class.layers() - longest;
    // The smaller instance starts inside the longest suffix. Check its own
    // beginning as well as first/middle/last of the maximal row suffix.
    const smaller = class.layers() - class.instances[0].row_log;
    for ([_]usize{ first, first + longest / 2, class.layers() - 1, smaller }) |index| {
        for ([_]bool{ false, true }) |one| try std.testing.expect(!(try rowGuardCost(&class, false, index, one)).valid);
    }
    for ([_]bool{ false, true }) |one| try std.testing.expect((try rowGuardCost(&class, false, 0, one)).valid);
    const old = try rowGuardCost(&class, true, null, false);
    const direct = try rowGuardCost(&class, false, null, false);
    try std.testing.expect(old.valid and direct.valid);
    try std.testing.expect(direct.qm31 < old.qm31);
    std.debug.print("\nOUTER_ROW_GUARD_COST old_qm31={d} direct_qm31={d} saved_per_child={d} saved_four={d}\n", .{ old.qm31, direct.qm31, old.qm31 - direct.qm31, 4 * (old.qm31 - direct.qm31) });
    try std.testing.expectError(error.OuterGkrShapeMismatch, @import("circuit.zig").requireRowPoint(undefined, &class, &.{}));
}
