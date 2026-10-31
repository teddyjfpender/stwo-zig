//! Standalone DIV/REM service artifact receiver. This is not CPU call ingress.
//! Expected typed requests and canonical claim limbs are supplied independently.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("stwo_cpu_backend").CpuBackend;
const rv = @import("stwo_riscv_frontend").rv64_air;
const D = rv.arithmetic.division;
const P = rv.protocol;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const Claim = [4]u32;
pub fn verifyOwned(a: std.mem.Allocator, requests: []const D.trace.Request, claim_limbs: Claim, proof: P.Proof) !void {
    var owned = proof;
    var owns_proof = true;
    defer if (owns_proof) owned.deinit(a);
    if (!std.meta.eql(proof.commitment_scheme_proof.config, P.config()) or proof.commitment_scheme_proof.revision_config != null) return error.InvalidRv64DivisionConfig;
    if (requests.len > 1 << 22) return error.InvalidRv64DivisionShape;
    var parts: [4]M = undefined;
    for (claim_limbs, &parts) |limb, *part| {
        if (limb >= core.fields.m31.Modulus) return error.InvalidRv64DivisionClaim;
        part.* = M.fromCanonical(limb);
    }
    const claimed = Q.fromM31Array(parts);
    const log = @max(5, std.math.log2_int_ceil(usize, @max(1, requests.len)));
    const fixed = try D.trace.fixedColumns(a, requests.len, log);
    defer a.free(fixed);
    const n = @as(usize, 1) << @intCast(log);
    var columns: [D.layout.FIXED]engine.pcs.ColumnEvaluation = undefined;
    for (&columns, 0..) |*column, c| column.* = .{ .log_size = log, .values = fixed[c * n ..][0..n] };
    var root_scheme = try Scheme.init(a, P.config());
    defer root_scheme.deinit(a);
    var root_channel = P.Channel{};
    try root_scheme.commit(a, &columns, &root_channel);
    var roots = try root_scheme.roots(a);
    defer roots.deinit(a);
    const commits = proof.commitment_scheme_proof.commitments.items;
    if (commits.len != 4 or !std.mem.eql(u8, &roots.items[0], &commits[0])) return error.Rv64DivisionFixedRootMismatch;
    var verifier = try Verifier.init(a, P.config());
    defer verifier.deinit(a);
    var channel = P.Channel{};
    P.config().mixInto(&channel);
    channel.mixU32s(&.{ 0x44565032, @intCast(requests.len), log });
    const fixed_logs: [D.layout.FIXED]u32 = @splat(log);
    const main_logs: [D.layout.MAIN]u32 = @splat(log);
    const interaction_logs: [D.layout.INTERACTION]u32 = @splat(log);
    try verifier.commit(a, commits[0], &fixed_logs, &channel);
    try verifier.commit(a, commits[1], &main_logs, &channel);
    const challenges = D.provider.Challenges.draw(&channel);
    var expected = Q.zero();
    for (requests) |request| {
        const tuple = try D.trace.requestTuple(request);
        expected = expected.sub(try challenges.denominator(&tuple).inv());
    }
    if (!expected.eql(claimed)) return error.Rv64DivisionRequestClosure;
    channel.mixFelts(&.{expected});
    try verifier.commit(a, commits[2], &interaction_logs, &channel);
    const component = D.component.Component{ .log_size = log, .count = requests.len, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .claim = expected };
    const components = [_]core.air.components.Component{component.asVerifierComponent()};
    owns_proof = false;
    try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &components, &channel, &verifier, proof);
}
