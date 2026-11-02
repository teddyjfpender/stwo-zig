//! Physical bulk MAIN + local GKR binding + nonzero global RAM debt.
//! This fixture is a pending fragment, never a complete execution receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.crypto.bulk_memory;
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
const Role = @import("bulk_role.zig");
const Global = @import("global_cpu.zig");
const Metadata = @import("global_metadata.zig");
const a = std.testing.allocator;
const kind = B.layout.Kind.set;
const mw = B.layout.main(kind);
const fw = B.layout.fixedWidth(kind);
const instance = Frame.Instance{ .origin = .{ .bulk = kind }, .row_log = 5, .terms = @import("bulk_projection.zig").localTerms(kind), .fixed_offset = 0, .main_offset = 0 };
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
    const call = B.types.Call{ .op = .set, .pointer = 0x100, .epoch = 1, .tick = 4, .dst = 0x1000, .word1 = 0x5a, .len = 8, .packet = .{
        .{ .value = 0x1000, .rights = 3 }, .{ .value = 0x5a, .rights = 3 }, .{ .value = 8, .rights = 3 }, .{ .value = 0, .rights = 3 },
    } };
    return B.source.Source.init(a, kind, &.{call}, &.{.{ .dst = .{ .value = 17, .rights = 3 } }}, 5);
}
const Bundle = struct { stark: Prover.ExtendedProof, gkr: GP.ProveBatchResult, ram_claim: O };
const Fault = enum { none, target, eq, prefix, main };
fn produce(fault: Fault) !Bundle {
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    // Only the initialized bulk slot is ever read; the CPU source is absent.
    var sources: @import("../roster.zig").Sources = undefined;
    sources.bulk = @splat(null);
    sources.bulk[@intFromEnum(kind)] = try source();
    const src = &sources.bulk[@intFromEnum(kind)].?;
    defer src.deinit();
    var fixed: [fw]engine.pcs.ColumnEvaluation = undefined;
    for (&fixed, 0..) |*c, i| c.* = .{ .log_size = 5, .values = src.fixed[i * 32 ..][0..32] };
    try scheme.commit(a, &fixed, &ch);
    var main: [mw]engine.pcs.ColumnEvaluation = undefined;
    if (fault == .main) src.main[B.layout.set.fill * 32 + B.source.physical(0, 5)] = M.fromCanonical(0x5b);
    for (&main, 0..) |*c, i| c.* = .{ .log_size = 5, .values = src.main[i * 32 ..][0..32] };
    try scheme.commit(a, &main, &ch);
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    var inputs = try @import("inputs.zig").Inputs.init(a, &.{instance}, &challenges, @import("native_provider.zig").Provider{ .source = &sources });
    defer inputs.deinit();
    var gkr = try GP.proveBatch(a, &ch, inputs.layers);
    errdefer gkr.deinit(a);
    const eta = ch.drawSecureFelt();
    const pending = @import("child.zig").Pending{ .artifact = gkr.artifact, .challenges = challenges, .eta = eta, .digest = @splat(0) };
    var binding = try @import("witness.zig").Witness.init(a, &.{instance}, &inputs, &gkr.artifact, eta);
    defer binding.deinit();
    var data = try @import("role.zig").Data.init(instance, &pending, 0);
    if (fault == .target) data.target_per_row = data.target_per_row.add(O.one());
    if (fault == .eq) binding.columns[0][7] = binding.columns[0][7].add(M.one());
    if (fault == .prefix) binding.columns[0][8 * 32 + 7] = binding.columns[0][8 * 32 + 7].add(M.one());
    const global_ch = shared(&ch);
    // Retire wide MAIN and FIXED after committing and forming the local child.
    // The global provider must still use durable call/word metadata alone.
    const retained = try @import("bulk_metadata.zig").retainedBytes(src);
    @import("bulk_metadata.zig").retireLocal(src);
    @import("bulk_metadata.zig").retireLocal(src);
    try std.testing.expectEqual(retained, try @import("bulk_metadata.zig").retainedBytes(src));
    try std.testing.expectEqual(0, src.main.len + src.fixed.len + src.counts16.len + src.counts8.len);
    var retired_sink = @import("inputs.zig").RowSink{ .challenges = &challenges };
    try std.testing.expectError(error.LocalGkrMetadataRetired, (@import("native_provider.zig").Provider{ .source = &sources }).emit(instance, 0, &retired_sink));
    var global = try @import("classic_witness.zig").Witness.init(a, 5, try Metadata.groups(instance.origin), Metadata.Provider{ .source = &sources, .origin = instance.origin, .log_size = 5, .shared = global_ch }, 1 << 20);
    defer global.deinit();
    const claims = try Global.claimsFromVector(O, instance.origin, global.claimSlice());
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
    const data = try @import("role.zig").Data.init(instance, &pending, 0);
    const global_ch = shared(&ch);
    const claim = if (changed_claim) bundle.ram_claim.add(O.one()) else bundle.ram_claim;
    ch.mixFelts(&.{claim});
    const component = Role.Component{ .data = data, .rows = 1, .shared = global_ch, .claims = .{ .ram = claim, .kio = O.zero(), .wire = O.zero() } };
    try receiver.commit(a, commitments[2], &([_]u32{5} ** 32), &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    try core.verifier.ForField(O).verify(H, MC, a, &.{component.asVerifierComponent()}, &ch, &receiver, proof);
}
test "bulk set physical OM proof fresh verifies with authenticated local terminal and durable nonzero RAM debt" {
    var bundle = try produce(.none);
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    try verify(&bundle, false);
}
test "bulk physical binding rejects MAIN terminal Eq prefix and global claim changes" {
    for ([_]Fault{ .target, .eq, .prefix, .main }) |fault| {
        var bundle = try produce(fault);
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        if (verify(&bundle, false)) |_| return error.InvalidBulkBindingAccepted else |err| switch (err) {
            error.OodsNotMatching, error.LastLayerDegreeInvalid => std.debug.print("BULK_BINDING_TAMPER fault={s} fresh_receiver_rejected={s}\n", .{ @tagName(fault), @errorName(err) }),
            else => return err,
        }
    }
    var bundle = try produce(.none);
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    if (verify(&bundle, true)) |_| return error.ChangedRamClaimAccepted else |_| {}
}
