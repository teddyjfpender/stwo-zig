//! Physical sponge MAIN + local GKR binding + nonzero global RAM debt.
//! This fixture is a pending fragment, never a complete execution receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.crypto.keccak_sponge;
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
const Role = @import("sponge_role.zig");
const Global = @import("global_cpu.zig");
const Metadata = @import("global_metadata.zig");
const a = std.testing.allocator;
const fw = B.layout.FIXED;
fn instanceFor(comptime kind: B.layout.Kind) Frame.Instance {
    return .{ .origin = .{ .sponge = kind }, .row_log = 5, .terms = @import("sponge_projection.zig").localTerms(kind), .fixed_offset = 0, .main_offset = 0 };
}
fn config() !core.pcs.ForField(O).PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.ForField(O).FriConfig.init(0, 1, 12) };
}
fn shared(ch: *Ch) @import("manifest.zig").Shared {
    var out: @import("manifest.zig").Shared = undefined;
    out.ram.offset = ch.drawSecureFelt();
    for (&out.ram.coefficients) |*c| c.* = ch.drawSecureFelt();
    out.kio.offset = ch.drawSecureFelt();
    for (&out.kio.coefficients) |*c| c.* = ch.drawSecureFelt();
    out.wire.offset = O.zero();
    out.wire.coefficients = @splat(O.zero());
    return out;
}
fn plan() !B.source.Plan {
    const state = B.types.State{ .value = 0, .rights = 3 };
    const call = B.types.Call{ .pointer = 0x1000, .epoch = 1, .tick = 4, .state = @splat(state), .packet = .{
        .{ .value = 0x2000, .rights = 3 }, .{ .value = 0x3000, .rights = 3 }, .{ .value = 1, .rights = 3 }, .{ .value = 3, .rights = 3 },
    } };
    return B.source.Plan.init(a, &.{call}, &.{.{ .value = 0x61, .rights = 1 }});
}
const Bundle = struct { stark: Prover.ExtendedProof, gkr: GP.ProveBatchResult, claims: Global.ClaimsFor(O) };
const Fault = enum { none, target, eq, prefix, main };
fn produce(comptime kind: B.layout.Kind, fault: Fault) !Bundle {
    const instance = instanceFor(kind);
    const mw = comptime B.layout.main(kind);
    const cfg = try config();
    var ch = Ch.init();
    cfg.mixInto(&ch);
    var scheme = try Prover.init(a, cfg);
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    var own_plan = try plan();
    defer own_plan.deinit(a);
    var sources: @import("../roster.zig").Sources = undefined;
    sources.sponge = @splat(null);
    sources.sponge[@intFromEnum(kind)] = try B.source.Source.init(a, kind, &own_plan, 7, 5);
    const src = &sources.sponge[@intFromEnum(kind)].?;
    defer src.deinit();
    var fixed: [fw]engine.pcs.ColumnEvaluation = undefined;
    for (&fixed, 0..) |*c, i| c.* = .{ .log_size = 5, .values = src.fixed[i * 32 ..][0..32] };
    try scheme.commit(a, &fixed, &ch);
    var main: [mw]engine.pcs.ColumnEvaluation = undefined;
    if (fault == .main) src.main[0] = M.fromCanonical(0x5b);
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
    const retained = try @import("sponge_metadata.zig").retainedPlanBytes(&own_plan);
    try std.testing.expect(retained <= try @import("sponge_metadata.zig").requestUpperBound(.{ .calls = 1, .perms = 1, .first_id = 7 }));
    @import("sponge_metadata.zig").retireLocal(src);
    @import("sponge_metadata.zig").retireLocal(src);
    try std.testing.expectEqual(retained, try @import("sponge_metadata.zig").retainedPlanBytes(&own_plan));
    var global = try @import("classic_witness.zig").Witness.initTruth(a, 5, &.{.{ .inverses = @intCast(@import("sponge_projection.zig").ramTerms(kind) / 2) }, .{ .inverses = 25 }}, Metadata.Provider{ .source = &sources, .origin = instance.origin, .log_size = 5, .shared = global_ch }, 1 << 20);
    defer global.deinit();
    const claims = Global.ClaimsFor(O){ .ram = global.claimSlice()[0], .kio = global.claimSlice()[1], .wire = O.zero() };
    try std.testing.expect(!claims.ram.isZero());
    try std.testing.expect(!claims.kio.isZero());
    ch.mixFelts(&.{ claims.ram, claims.kio });
    var inter: [16 + @import("sponge_projection.zig").globalWidth(kind)]engine.pcs.ColumnEvaluation = undefined;
    for (inter[0..16], 0..) |*c, i| c.* = .{ .log_size = 5, .values = binding.columns[0][i * 32 ..][0..32] };
    for (inter[16..], 0..) |*c, i| c.* = .{ .log_size = 5, .values = global.data[i * 32 ..][0..32] };
    try scheme.commit(a, &inter, &ch);
    const component = Role.Component{ .data = data, .rows = 1, .first_id = 7, .shared = global_ch, .claims = claims };
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
    return .{ .stark = stark, .gkr = gkr, .claims = claims };
}
fn verify(comptime kind: B.layout.Kind, bundle: *Bundle, changed_claim: bool) !void {
    const instance = instanceFor(kind);
    const mw = comptime B.layout.main(kind);
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
    var claims = bundle.claims;
    if (changed_claim) claims.kio = claims.kio.add(O.one());
    ch.mixFelts(&.{ claims.ram, claims.kio });
    const component = Role.Component{ .data = data, .rows = 1, .first_id = 7, .shared = global_ch, .claims = claims };
    try receiver.commit(a, commitments[2], &([_]u32{5} ** (16 + @import("sponge_projection.zig").globalWidth(kind))), &ch);
    const proof = bundle.stark.proof;
    bundle.stark.proof = undefined;
    try core.verifier.ForField(O).verify(H, MC, a, &.{component.asVerifierComponent()}, &ch, &receiver, proof);
}
test "V3 SpongeGKR call and perm physical OM proof freshly verifies after metadata retirement" {
    inline for (.{ B.layout.Kind.call, B.layout.Kind.perm }) |kind| {
        var bundle = try produce(kind, .none);
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        try verify(kind, &bundle, false);
    }
}
test "V3 SpongeGKR physical binding rejects MAIN terminal Eq prefix and KIO claim changes" {
    for ([_]Fault{ .target, .eq, .prefix, .main }) |fault| {
        var bundle = try produce(.perm, fault);
        defer bundle.gkr.deinit(a);
        defer bundle.stark.aux.deinit(a);
        if (verify(.perm, &bundle, false)) |_| return error.InvalidSpongeBindingAccepted else |err| switch (err) {
            error.OodsNotMatching, error.LastLayerDegreeInvalid => std.debug.print("SPONGE_BINDING_TAMPER fault={s} fresh_receiver_rejected={s}\n", .{ @tagName(fault), @errorName(err) }),
            else => return err,
        }
    }
    var bundle = try produce(.call, .none);
    defer bundle.gkr.deinit(a);
    defer bundle.stark.aux.deinit(a);
    if (verify(.call, &bundle, true)) |_| return error.ChangedKioClaimAccepted else |_| {}
}

test "V3 SpongeGKR extended lanes are admitted only for the trusted sponge origin" {
    try std.testing.expectEqual(@as(u32, 8), try instanceFor(.perm).laneLog());
    try std.testing.expectEqual(@as(u32, 7), try instanceFor(.call).laneLog());
    var invalid = instanceFor(.perm);
    invalid.origin = .{ .core = .cpu };
    try std.testing.expectError(error.InvalidLocalGkrTerms, invalid.laneLog());
}
