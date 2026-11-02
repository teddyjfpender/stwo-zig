//! Actual ALU MAIN + local13-fraction GKR binding through OM31 PCS/FRI. This
//! authenticates a local fragment; its nonzero FUNCTION/range debts are NOT a
//! complete execution closure. Production verifies the whole local roster.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Ch = core.channel.raw_mod_m31.Om31Channel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = struct {
    pub fn mixRoot(c: *Ch, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&c.inner, root);
    }
};
const Prover = engine.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Ch);
const GV = engine.lookups.gkr_verifier.ForField(O);
const GP = engine.lookups.gkr_prover.ForField(O);
const Role = @import("role.zig");
const Frame = @import("frame.zig");
const Inputs = @import("inputs.zig");
const a = std.testing.allocator;
const instance = Frame.Instance{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 13, .fixed_offset = 0, .main_offset = 0 };
const Provider = struct {
    source: *const A.word16_v1.alu_experiment.source.Source,
    pub fn emit(self: @This(), _: Frame.Instance, logical: usize, sink: *Inputs.RowSink) !void {
        const meta = self.source.metadata[logical];
        for (meta.range_indices) |value| sink.emitBase(.range16, [1]M{M.fromCanonical(value)}, M.one());
        var payload: [13]M = undefined;
        for (meta.payload, &payload) |v, *out| out.* = M.fromCanonical(v);
        sink.emitBase(.function, payload, M.fromCanonical(meta.multiplicity()).neg());
    }
};
fn config() !core.pcs.ForField(O).PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
}
const Bundle = struct { stark: Prover.ExtendedProof, gkr: GP.ProveBatchResult };
const Fault = enum { none, target, main, eq, prefix, projected_balanced };
fn produce(fault: Fault) !Bundle {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    try scheme.commit(a, &.{}, &ch);
    const Fact = A.word16_v1.alu_experiment.source.Fact;
    var facts: [17]Fact = undefined;
    for (&facts, 0..) |*f, i| f.* = .{ .op = .add, .a = if (i % 2 == 0) std.math.maxInt(u64) - i * 17 else i * 77731, .b = i * 9079 + 2671, .c = 0 };
    for (&facts) |*f| f.c = f.a +% f.b;
    var source = try A.word16_v1.alu_experiment.source.Source.init(a, &facts, 5);
    defer source.deinit();
    if (fault == .main) {
        const p = A.witness.physical(7, 5);
        source.main[46 * 32 + p] = source.main[46 * 32 + p].add(M.one());
        var row: [47]O = undefined;
        for (&row, 0..) |*v, c| v.* = O.fromBase(source.main[c * 32 + p]);
        var residuals: [64]O = undefined;
        var sink = A.evaluation.SinkFor(O){ .values = &residuals };
        try A.main_only.authority.emitFor(O, .{ .alu = {} }, &.{}, &row, &([_]O{O.zero()} ** 47), &sink);
        for (residuals[0..sink.count]) |r| try std.testing.expect(r.isZero());
    }
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commit(a, main, &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var inputs = try Inputs.Inputs.init(a, &.{instance}, &challenges, Provider{ .source = &source });
    defer inputs.deinit();
    var gkr = try GP.proveBatch(a, &ch, inputs.layers);
    errdefer gkr.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = gkr.artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var witness = try @import("witness.zig").Witness.init(a, &.{instance}, &inputs, &gkr.artifact, eta);
    defer witness.deinit();
    if (fault == .projected_balanced) {
        // Keep MAIN, child proof, eta and both terminal marginals unchanged.
        // Delta P0=Eq1 and delta P1=-Eq0 cancel in the final weighted sum,
        // so numerical prefix closure alone cannot authenticate this cache.
        var projected = try @import("witness.zig").Witness.initProjectionFromProvider(a, a, &.{instance}, &challenges, Provider{ .source = &source }, &gkr.artifact, eta);
        defer projected.deinit();
        const rows = 32;
        const p0 = A.witness.physical(3, 5);
        const p1 = A.witness.physical(9, 5);
        var eq0_words: [8]M = undefined;
        var eq1_words: [8]M = undefined;
        for (0..8) |c| {
            eq0_words[c] = witness.columns[0][c * rows + p0];
            eq1_words[c] = witness.columns[0][c * rows + p1];
        }
        const eq0 = O.fromM31Array(eq0_words);
        const eq1 = O.fromM31Array(eq1_words);
        try std.testing.expect(!eq0.isZero() and !eq1.isZero());
        try std.testing.expect(eq0.mul(eq1).add(eq1.mul(eq0.neg())).isZero());
        for (eq1.toM31Array(), eq0.neg().toM31Array(), 0..) |d0, d1, c| {
            projected.columns[0][c * rows + p0] = projected.columns[0][c * rows + p0].add(d0);
            projected.columns[0][c * rows + p1] = projected.columns[0][c * rows + p1].add(d1);
        }
        // This must succeed despite the corruption: the attack deliberately
        // preserves the terminal sum and all public numerical child claims.
        var corrupted = try projected.finalizeProjection(a, &.{instance}, &gkr.artifact, eta);
        var owns_corrupted = true;
        defer if (owns_corrupted) corrupted.deinit();
        try std.testing.expect(!std.mem.eql(M, witness.columns[0], corrupted.columns[0]));
        const last = A.witness.physical(rows - 1, 5);
        for (0..8) |c| try std.testing.expectEqual(witness.columns[0][(8 + c) * rows + last], corrupted.columns[0][(8 + c) * rows + last]);
        witness.deinit();
        witness = corrupted;
        owns_corrupted = false;
    }
    var data = try Role.Data.init(instance, &pending, 0);
    // Alter only the binding target; original ALU arithmetic stays valid.
    if (fault == .target) data.target_per_row = data.target_per_row.add(O.one());
    if (fault == .eq) witness.columns[0][7] = witness.columns[0][7].add(M.one());
    if (fault == .prefix) witness.columns[0][8 * 32 + 7] = witness.columns[0][8 * 32 + 7].add(M.one());
    var inter: [16]engine.pcs.ColumnEvaluation = undefined;
    for (&inter, 0..) |*c, i| c.* = .{ .log_size = 5, .values = witness.columns[0][i * 32 ..][0..32] };
    try scheme.commit(a, &inter, &ch);
    const component = Role.Component{ .main = .{ .log_size = 5, .public = .{ .alu = {} }, .offsets = .{ 0, 0 } }, .data = data, .inter_offset = 0, .epoch = 1 };
    owns = false;
    const proof = try Prover.prove(a, &.{component.asProverComponent()}, &ch, scheme, .{});
    return .{ .stark = proof, .gkr = gkr };
}
fn verify(bundle: *Bundle) !void {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    const commitments = bundle.stark.proof.commitment_scheme_proof.commitments.items;
    try receiver.commit(a, commitments[0], &.{}, &ch);
    try receiver.commit(a, commitments[1], &([_]u32{5} ** 47), &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var artifact = try GV.partiallyVerifyBatch(a, &.{.LogUp}, &bundle.gkr.proof, &ch);
    defer artifact.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    const data = try Role.Data.init(instance, &pending, 0);
    const component = Role.Component{ .main = .{ .log_size = 5, .public = .{ .alu = {} }, .offsets = .{ 0, 0 } }, .data = data, .inter_offset = 0, .epoch = 1 };
    try receiver.commit(a, commitments[2], &([_]u32{5} ** 16), &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    try core.verifier.ForField(O).verify(H, MC, a, &.{component.asVerifierComponent()}, &ch, &receiver, proof);
}
test "original ALU and actual13 local GKR fractions prove through single MAIN span and fresh wide receiver" {
    var bundle = try produce(.none);
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    try verify(&bundle);
}
test "physical GKR binding rejects changed arithmetic-valid MAIN target Eq prefix and balanced projected cache" {
    for ([_]Fault{ .target, .main, .eq, .prefix, .projected_balanced }) |fault| {
        var bundle = produce(fault) catch |err| switch (err) {
            error.ConstraintsNotSatisfied, error.InvalidLastLayerDegree => continue,
            else => return err,
        };
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        verify(&bundle) catch |err| switch (err) {
            error.OodsNotMatching, error.LastLayerDegreeInvalid => continue,
            else => return err,
        };
        return error.InvalidBindingAccepted;
    }
}
const mixed_instances = [_]Frame.Instance{
    .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 13, .fixed_offset = 0, .main_offset = 0 },
    .{ .origin = .{ .core = .alu_tail }, .row_log = 6, .terms = 13, .fixed_offset = 0, .main_offset = 47 },
};
const MixedProvider = struct {
    sources: [2]*const A.word16_v1.alu_experiment.source.Source,
    pub fn emit(self: @This(), instance_value: Frame.Instance, logical: usize, sink: *Inputs.RowSink) !void {
        const index: usize = if (instance_value.origin.core == .alu) 0 else 1;
        return (Provider{ .source = self.sources[index] }).emit(instance_value, logical, sink);
    }
};
fn proveMixed() !Bundle {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    try scheme.commit(a, &.{}, &ch);
    const Source = A.word16_v1.alu_experiment.source.Source;
    var sources: [2]Source = undefined;
    var done: usize = 0;
    defer for (sources[0..done]) |*s| s.deinit();
    var columns: [94]engine.pcs.ColumnEvaluation = undefined;
    for (&sources, 0..) |*source, index| {
        var facts: [17]A.word16_v1.alu_experiment.source.Fact = undefined;
        for (&facts, 0..) |*f, i| {
            const x = 1001 + i * 17 + index * 123;
            const y = 111 + i * 3;
            f.* = .{ .op = .add, .a = x, .b = y, .c = x + y };
        }
        source.* = try Source.init(a, &facts, @intCast(5 + index));
        done += 1;
        const main = try source.columns(a, 1);
        defer a.free(main);
        @memcpy(columns[index * 47 ..][0..47], main);
    }
    try scheme.commit(a, &columns, &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var inputs = try Inputs.Inputs.init(a, &mixed_instances, &challenges, MixedProvider{ .sources = .{ &sources[0], &sources[1] } });
    defer inputs.deinit();
    var gkr = try GP.proveBatch(a, &ch, inputs.layers);
    errdefer gkr.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = gkr.artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var witness = try @import("witness.zig").Witness.init(a, &mixed_instances, &inputs, &gkr.artifact, eta);
    defer witness.deinit();
    var components: [2]Role.Component = undefined;
    var handles: [2]engine.air.component_prover.ForField(O).ComponentProver = undefined;
    var inter: [32]engine.pcs.ColumnEvaluation = undefined;
    for (&components, &handles, mixed_instances, 0..) |*component, *handle, instance_value, index| {
        const rows = try instance_value.rows();
        component.* = .{ .main = .{ .log_size = instance_value.row_log, .public = .{ .alu = {} }, .offsets = .{ 0, index * 47 } }, .data = try Role.Data.init(instance_value, &pending, index), .inter_offset = index * 16, .epoch = 1 };
        handle.* = component.asProverComponent();
        for (inter[index * 16 ..][0..16], 0..) |*c, i| c.* = .{ .log_size = instance_value.row_log, .values = witness.columns[index][i * rows ..][0..rows] };
    }
    try scheme.commit(a, &inter, &ch);
    owns = false;
    return .{ .stark = try Prover.prove(a, &handles, &ch, scheme, .{}), .gkr = gkr };
}
fn verifyMixed(bundle: *Bundle) !void {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    const commitments = bundle.stark.proof.commitment_scheme_proof.commitments.items;
    try receiver.commit(a, commitments[0], &.{}, &ch);
    const main_logs = ([_]u32{5} ** 47) ++ ([_]u32{6} ** 47);
    try receiver.commit(a, commitments[1], &main_logs, &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp }, &bundle.gkr.proof, &ch);
    defer artifact.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var components: [2]Role.Component = undefined;
    var handles: [2]core.air.components.ForField(O).Component = undefined;
    for (&components, &handles, mixed_instances, 0..) |*component, *handle, instance_value, index| {
        component.* = .{ .main = .{ .log_size = instance_value.row_log, .public = .{ .alu = {} }, .offsets = .{ 0, index * 47 } }, .data = try Role.Data.init(instance_value, &pending, index), .inter_offset = index * 16, .epoch = 1 };
        handle.* = component.asVerifierComponent();
    }
    const inter_logs = ([_]u32{5} ** 16) ++ ([_]u32{6} ** 16);
    try receiver.commit(a, commitments[2], &inter_logs, &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    try core.verifier.ForField(O).verify(H, MC, a, &handles, &ch, &receiver, proof);
}
test "mixed-height physical role binding uses common GKR suffix and globally lifted PCS masks" {
    var bundle = try proveMixed();
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    try verifyMixed(&bundle);
}
