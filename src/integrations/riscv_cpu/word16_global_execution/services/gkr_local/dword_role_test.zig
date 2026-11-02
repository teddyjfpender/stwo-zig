//! Physical bulk MAIN + local GKR binding + nonzero global RAM debt.
//! This fixture is a pending fragment, never a complete execution receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.memory.load_store_dword;
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
const Frame = @import("frame.zig");
const Role = @import("dword_role.zig");
const Global = @import("global_cpu.zig");
const Metadata = @import("global_metadata.zig");
const a = std.testing.allocator;
const kind: u1 = 0;
const mw = B.layout.MAIN;
const fw = B.layout.FIXED;
const instance = Frame.Instance{ .origin = .{ .dword = kind }, .row_log = 5, .terms = @import("dword_projection.zig").LOCAL_TERMS, .fixed_offset = 0, .main_offset = 0 };
fn config() !core.pcs.ForField(O).PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
}
fn shared(ch: *Ch) @import("manifest.zig").Shared {
    var out: @import("manifest.zig").Shared = undefined;
    out.ram.offset = ch.drawSecureFelt();
    for (&out.ram.coefficients) |*c| c.* = ch.drawSecureFelt();
    out.kio.offset = O.zero();
    out.kio.coefficients = @splat(O.zero());
    out.wire.offset = O.zero();
    out.wire.coefficients = @splat(O.zero());
    return out;
}
fn source() !B.source.Source {
    return B.source.Source.init(a, &.{.{ .opcode = .LD, .a = 0x1000, .immediate = 0, .c = 17, .epoch = 1, .tick = 4, .before = .{ .value = 17, .rights = 3, .epoch = 0, .tick = 0 }, .after = .{ .value = 17, .rights = 3, .epoch = 1, .tick = 4 } }}, 5);
}
const LocalProvider = struct {
    src: *const B.source.Source,
    pub fn emit(self: @This(), _: Frame.Instance, logical: usize, sink: anytype) !void {
        @import("dword_projection.zig").emitMetadata(self.src.metadata[logical], sink);
    }
};
const GlobalProvider = struct {
    src: *const B.source.Source,
    shared_ch: @import("manifest.zig").Shared,
    pub fn fill(self: @This(), logical: usize, d: []O, n: []@import("classic_witness.zig").Numerator) !void {
        const meta = self.src.metadata[logical];
        const before = meta.ramTuple(false);
        const after = meta.ramTuple(true);
        var d0 = self.shared_ch.ram.offset;
        var d1 = self.shared_ch.ram.offset;
        for (self.shared_ch.ram.coefficients, before, after) |c, x, y| {
            d0 = d0.sub(c.mulM31(x));
            d1 = d1.sub(c.mulM31(y));
        }
        d[0] = d0.mul(d1);
        n[0] = .{ .secure = d1.sub(d0).mulM31(meta.active()) };
    }
};
const Bundle = struct { stark: Prover.ExtendedProof, gkr: GP.ProveBatchResult, ram_claim: O };
const Fault = enum { none, target, eq, prefix, main };
fn produce(fault: Fault) !Bundle {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    var own_source = try source();
    const src = &own_source;
    defer src.deinit();
    var fixed: [fw]engine.pcs.ColumnEvaluation = undefined;
    for (&fixed, 0..) |*c, i| c.* = .{ .log_size = 5, .values = src.fixed[i * 32 ..][0..32] };
    try scheme.commit(a, &fixed, &ch);
    var main: [mw]engine.pcs.ColumnEvaluation = undefined;
    if (fault == .main) src.main[0] = M.fromCanonical(0x5b);
    for (&main, 0..) |*c, i| c.* = .{ .log_size = 5, .values = src.main[i * 32 ..][0..32] };
    try scheme.commit(a, &main, &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var inputs = try @import("inputs.zig").Inputs.init(a, &.{instance}, &challenges, LocalProvider{ .src = src });
    defer inputs.deinit();
    var gkr = try GP.proveBatch(a, &ch, inputs.layers);
    errdefer gkr.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = gkr.artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var binding = try @import("witness.zig").Witness.init(a, &.{instance}, &inputs, &gkr.artifact, eta);
    defer binding.deinit();
    var data = try Role.Data.init(instance, &pending, 0);
    if (fault == .target) data.target_per_row = data.target_per_row.add(O.one());
    if (fault == .eq) binding.columns[0][7] = binding.columns[0][7].add(M.one());
    if (fault == .prefix) binding.columns[0][8 * 32 + 7] = binding.columns[0][8 * 32 + 7].add(M.one());
    const global_ch = shared(&ch);
    src.releaseMain();
    var global = try @import("classic_witness.zig").Witness.init(a, 5, &.{.{ .inverses = 1 }}, GlobalProvider{ .src = src, .shared_ch = global_ch }, 1 << 20);
    defer global.deinit();
    const claims = Global.ClaimsFor(O){ .ram = global.claimSlice()[0], .kio = O.zero(), .wire = O.zero() };
    try std.testing.expect(!claims.ram.isZero());
    ch.mixFelts(&.{claims.ram});
    var inter: [32]engine.pcs.ColumnEvaluation = undefined;
    for (inter[0..16], 0..) |*c, i| c.* = .{ .log_size = 5, .values = binding.columns[0][i * 32 ..][0..32] };
    for (inter[16..], 0..) |*c, i| c.* = .{ .log_size = 5, .values = global.data[i * 32 ..][0..32] };
    try scheme.commit(a, &inter, &ch);
    const component = Role.Component{ .data = data, .rows = 1, .shared = global_ch, .claims = claims };
    try component.validate();
    owns = false;
    const stark = if (fault == .none) try Prover.prove(a, &.{component.asProverComponent()}, &ch, scheme, .{}) else blk: {
        // Retain a fully encoded invalid physical proof at the OODS guard,
        // then make a separate fresh verifier demonstrate rejection too.
        var diagnostic: ?@import("stwo_prover_api").ProveDiagnostic = null;
        var failed: ?Prover.ExtendedProof = null;
        break :blk Prover.proveDiagnosedRetainingFailure(a, &.{component.asProverComponent()}, &ch, scheme, .{}, &diagnostic, &failed) catch |err| switch (err) {
            error.ConstraintsNotSatisfied => failed orelse return error.MissingInvalidBulkPhysicalProof,
            else => return err,
        };
    };
    return .{ .stark = stark, .gkr = gkr, .ram_claim = claims.ram };
}
fn verify(bundle: *Bundle, changed_claim: bool) !void {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var receiver = try core.pcs.ForField(O).verifier.CommitmentSchemeVerifier(H, MC).init(a, cfg);
    defer receiver.deinit(a);
    const commitments = bundle.stark.proof.commitment_scheme_proof.commitments.items;
    try receiver.commit(a, commitments[0], &([_]u32{5} ** fw), &ch);
    try receiver.commit(a, commitments[1], &([_]u32{5} ** mw), &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var artifact = try GV.partiallyVerifyBatch(a, &.{.LogUp}, &bundle.gkr.proof, &ch);
    defer artifact.deinit(a);
    const pending = @import("child.zig").Pending{ .artifact = artifact, .challenges = challenges, .eta = ch.drawSecureFelt(), .digest = @splat(0) };
    const data = try Role.Data.init(instance, &pending, 0);
    const global_ch = shared(&ch);
    const claim = if (changed_claim) bundle.ram_claim.add(O.one()) else bundle.ram_claim;
    ch.mixFelts(&.{claim});
    const component = Role.Component{ .data = data, .rows = 1, .shared = global_ch, .claims = .{ .ram = claim, .kio = O.zero(), .wire = O.zero() } };
    try receiver.commit(a, commitments[2], &([_]u32{5} ** 32), &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    try core.verifier.ForField(O).verify(H, MC, a, &.{component.asVerifierComponent()}, &ch, &receiver, proof);
}
test "V3 dword physical OM proof freshly verifies authenticated local terminal and durable RAM debt" {
    var bundle = try produce(.none);
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    try verify(&bundle, false);
}
test "V3 dword physical binding rejects MAIN terminal Eq prefix and global claim changes" {
    for ([_]Fault{ .target, .eq, .prefix, .main }) |fault| {
        var bundle = try produce(fault);
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        if (verify(&bundle, false)) |_| return error.InvalidBulkBindingAccepted else |err| switch (err) {
            error.OodsNotMatching, error.LastLayerDegreeInvalid => std.debug.print("DWORD_BINDING_TAMPER fault={s} fresh_receiver_rejected={s}\n", .{ @tagName(fault), @errorName(err) }),
            else => return err,
        }
    }
    var bundle = try produce(.none);
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    if (verify(&bundle, true)) |_| return error.ChangedRamClaimAccepted else |_| {}
}
