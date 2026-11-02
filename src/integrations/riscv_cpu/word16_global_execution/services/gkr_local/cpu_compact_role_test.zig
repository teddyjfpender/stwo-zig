//! Compact decode CPU MAIN (Geometry.cpu_compact_decode, 37 columns) and its
//! fourteen local GKR fractions through one OM31 PCS span. The ROM pc
//! coordinate is read from the previous MAIN row, so this is the only CPU
//! terminal binding with a cross-row projection. Like role_test.zig this is an
//! authenticated local fragment: its FUNCTION/ROM/range debts are closed only by
//! the complete roster (v3_execution_test.zig).
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
const Fixture = @import("../v3_fixture.zig");
const K = A.word16_execution.layout.compact;
const a = std.testing.allocator;
const LOG: u32 = Fixture.CPU_LOG;
const N: usize = 1 << LOG;
const instance = Frame.Instance{ .origin = .{ .core = .cpu }, .row_log = LOG, .terms = 14, .fixed_offset = 0, .main_offset = 0 };
const CpuSource = @import("../../../word16_execution/cpu_source.zig").Source;
const Provider = struct {
    cpu: *const CpuSource,
    pub fn emit(self: @This(), _: Frame.Instance, logical: usize, sink: *Inputs.RowSink) !void {
        try @import("pair_projection.zig").emitCpuMetadata(self.cpu, logical, true, sink);
    }
};
fn config() !core.pcs.ForField(O).PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
}
const Fault = enum { none, next, target, eq, prefix };
const Bundle = struct { stark: Prover.ExtendedProof, gkr: GP.ProveBatchResult, public: A.main_only.authority.PublicFor(O), epoch: u16 };
fn publicFor(cpu: *const CpuSource) !A.main_only.authority.PublicFor(O) {
    const old = try A.word16_execution.types.inputs(cpu.public, cpu.epoch, LOG);
    return .{ .cpu_compact = .{ .steps = old.steps, .initial_pc = old.initial_pc, .final_pc = old.final_pc, .epoch = old.epoch } };
}
fn mainRow(main: []const M, logical: usize) [K.COUNT]O {
    var out: [K.COUNT]O = undefined;
    const p = A.witness.physical(logical, LOG);
    for (&out, 0..) |*v, c| v.* = O.fromBase(main[c * N + p]);
    return out;
}
fn fixedRow(fixed: []const M, logical: usize) [3]O {
    var out: [3]O = undefined;
    const p = A.witness.physical(logical, LOG);
    for (&out, 0..) |*v, c| v.* = O.fromBase(fixed[c * N + p]);
    return out;
}
fn produce(fault: Fault) !Bundle {
    var captured = try Fixture.Captured.initWithLayout(a, true);
    defer captured.deinit();
    const native = &captured.native[0];
    try native.ensureCpuMain(captured.program, LOG);
    const cpu = &native.cpu.?;
    try std.testing.expect(cpu.compact and cpu.main.len == K.COUNT * N);
    // Compact decode is defined on the byte-pair layout (the pipeline sets
    // these from the receiver geometry; MAIN does not depend on them).
    cpu.fused_tail = true;
    cpu.u8_pairs = true;
    const fixed = try A.word16_cpu.fixed.cpu(a, LOG);
    defer a.free(fixed);
    const public = try publicFor(cpu);
    if (fault == .next) {
        // Arithmetic-valid forgery: an active row's static next PC. No MAIN-only
        // residual reads it on an active non-last row (or as the next row's
        // predecessor), so only the ROM fraction binding can reject it.
        const row = 2;
        try std.testing.expect(row + 1 < cpu.public.steps);
        cpu.main[(K.next) * N + A.witness.physical(row, LOG)] = cpu.main[(K.next) * N + A.witness.physical(row, LOG)].add(M.fromCanonical(4));
        for ([_]usize{ row, row + 1 }) |logical| {
            var residuals: [64]O = undefined;
            var sink = A.evaluation.SinkFor(O){ .values = &residuals };
            const current = mainRow(cpu.main, logical);
            const previous = mainRow(cpu.main, logical - 1);
            try A.main_only.authority.emitFor(O, public, &fixedRow(fixed, logical), &current, &previous, &sink);
            for (residuals[0..sink.count]) |r| try std.testing.expect(r.isZero());
        }
    }
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    var fixed_columns: [3]engine.pcs.ColumnEvaluation = undefined;
    for (&fixed_columns, 0..) |*c, i| c.* = .{ .log_size = LOG, .values = fixed[i * N ..][0..N] };
    try scheme.commit(a, &fixed_columns, &ch);
    var main_columns: [K.COUNT]engine.pcs.ColumnEvaluation = undefined;
    for (&main_columns, 0..) |*c, i| c.* = .{ .log_size = LOG, .values = cpu.main[i * N ..][0..N] };
    try scheme.commit(a, &main_columns, &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    // Native GKR inputs come from honest capture rows, never from MAIN.
    var inputs = try Inputs.Inputs.init(a, &.{instance}, &challenges, Provider{ .cpu = cpu });
    defer inputs.deinit();
    var gkr = try GP.proveBatch(a, &ch, inputs.layers);
    errdefer gkr.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = gkr.artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var witness = try @import("witness.zig").Witness.init(a, &.{instance}, &inputs, &gkr.artifact, eta);
    defer witness.deinit();
    var data = try Role.Data.init(instance, &pending, 0);
    data.cpu_u8_pairs = true;
    data.cpu_compact_decode = true;
    if (fault == .target) data.target_per_row = data.target_per_row.add(O.one());
    if (fault == .eq) witness.columns[0][7] = witness.columns[0][7].add(M.one());
    if (fault == .prefix) witness.columns[0][8 * N + 7] = witness.columns[0][8 * N + 7].add(M.one());
    var inter: [16]engine.pcs.ColumnEvaluation = undefined;
    for (&inter, 0..) |*c, i| c.* = .{ .log_size = LOG, .values = witness.columns[0][i * N ..][0..N] };
    try scheme.commit(a, &inter, &ch);
    const component = Role.Component{ .main = .{ .log_size = LOG, .public = public, .offsets = .{ 0, 0 } }, .data = data, .inter_offset = 0, .epoch = cpu.epoch };
    try component.validate();
    owns = false;
    const stark = if (fault == .none) try Prover.prove(a, &.{component.asProverComponent()}, &ch, scheme, .{}) else blk: {
        // Retain the fully encoded invalid proof so a separate fresh receiver
        // must demonstrate rejection, not only the producer's own guard.
        var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
        var failed: ?Prover.ExtendedProof = null;
        break :blk Prover.proveDiagnosedRetainingFailure(a, &.{component.asProverComponent()}, &ch, scheme, .{}, &diagnostic, &failed) catch |err| switch (err) {
            error.ConstraintsNotSatisfied => failed orelse return error.MissingInvalidCompactPhysicalProof,
            else => return err,
        };
    };
    return .{ .stark = stark, .gkr = gkr, .public = public, .epoch = cpu.epoch };
}
fn verify(bundle: *Bundle) !void {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    const commitments = bundle.stark.proof.commitment_scheme_proof.commitments.items;
    try receiver.commit(a, commitments[0], &([_]u32{LOG} ** 3), &ch);
    try receiver.commit(a, commitments[1], &([_]u32{LOG} ** K.COUNT), &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var artifact = try GV.partiallyVerifyBatch(a, &.{.LogUp}, &bundle.gkr.proof, &ch);
    defer artifact.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var data = try Role.Data.init(instance, &pending, 0);
    data.cpu_u8_pairs = true;
    data.cpu_compact_decode = true;
    const component = Role.Component{ .main = .{ .log_size = LOG, .public = bundle.public, .offsets = .{ 0, 0 } }, .data = data, .inter_offset = 0, .epoch = bundle.epoch };
    try receiver.commit(a, commitments[2], &([_]u32{LOG} ** 16), &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    try core.verifier.ForField(O).verify(H, MC, a, &.{component.asVerifierComponent()}, &ch, &receiver, proof);
}
test "compact decode CPU MAIN and fourteen local fractions prove through one span and a fresh receiver" {
    var bundle = try produce(.none);
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    try verify(&bundle);
}
test "compact CPU binding rejects forged static next PC target Eq and prefix" {
    for ([_]Fault{ .next, .target, .eq, .prefix }) |fault| {
        var bundle = try produce(fault);
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        if (verify(&bundle)) |_| return error.InvalidCompactBindingAccepted else |err| switch (err) {
            error.OodsNotMatching, error.LastLayerDegreeInvalid => std.debug.print("COMPACT_CPU_BINDING_TAMPER fault={s} fresh_receiver_rejected={s}\n", .{ @tagName(fault), @errorName(err) }),
            else => return err,
        }
    }
}
