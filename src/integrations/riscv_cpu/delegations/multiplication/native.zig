//! Standalone typed-MUL/BYTE proof receiver. Expected requests are receiver
//! input; no producer root or unclosed operand/result claim is authoritative.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
pub const Mul = rv.arithmetic.multiplication;
const L = Mul.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = rv.protocol;
pub const B = @import("stwo_cpu_backend").CpuBackend;
pub const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const Claims = struct { multiplication: Q, bytes: Q };
pub const Public = struct { requests: []const Mul.trace.Request, log_size: u32 };
pub fn mixPublic(channel: *P.Channel, public: Public) !void {
    if (public.log_size < 5 or public.log_size > 22 or public.requests.len > (@as(usize, 1) << @intCast(public.log_size))) return error.InvalidRv64MultiplicationShape;
    if (96 * (@as(u64, 1) << @intCast(public.log_size)) >= core.fields.m31.Modulus) return error.InvalidRv64MultiplicationMass;
    P.config().mixInto(channel);
    channel.mixU32s(&.{ 0x4d554c50, 1, @intCast(public.requests.len), public.log_size });
    for (public.requests) |request| {
        _ = try Mul.layout.opcodeIndex(request.opcode);
        channel.mixU32s(&.{@intFromEnum(request.opcode)});
        channel.mixU64(request.a);
        channel.mixU64(request.b);
        channel.mixU64(request.result);
    }
}
pub fn drawAlpha(channel: *P.Channel) Q {
    channel.mixU32s(&.{ 0x52563634, 0x42595445, 1 });
    return channel.drawSecureFelt();
}
pub fn fill(out: []engine.pcs.ColumnEvaluation, values: []const M, log: u32) void {
    const n = @as(usize, 1) << @intCast(log);
    std.debug.assert(out.len * n == values.len);
    for (out, 0..) |*column, c| column.* = .{ .log_size = log, .values = values[c * n ..][0..n] };
}
pub fn verifyOwned(a: std.mem.Allocator, public: Public, claims: Claims, proof_value: P.Proof) !void {
    var proof = proof_value;
    var owns = true;
    defer if (owns) proof.deinit(a);
    var channel = P.Channel{};
    try mixPublic(&channel, public);
    for ([_]Q{ claims.multiplication, claims.bytes }) |claim| for (claim.toM31Array()) |part| if (part.v >= core.fields.m31.Modulus) return error.InvalidRv64MultiplicationClaim;
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4 or pcs.sampled_values.items.len != 4 or pcs.queried_values.items.len != 4 or pcs.decommitments.items.len != 4) return error.InvalidRv64MultiplicationProof;
    const fixed = try Mul.trace.fixedColumnsForLog(a, public.log_size);
    defer a.free(fixed);
    const zero: [256]u64 = @splat(0);
    var bytes = try rv.range.provider.Trace.init(a, &zero);
    defer bytes.deinit();
    var fixed_columns: [L.FIXED + 3]engine.pcs.ColumnEvaluation = undefined;
    fill(fixed_columns[0..L.FIXED], fixed, public.log_size);
    fill(fixed_columns[L.FIXED..], bytes.fixed, 8);
    var root_scheme = try Scheme.init(a, P.config());
    defer root_scheme.deinit(a);
    var root_channel = P.Channel{};
    try root_scheme.commitBorrowedStreaming(a, &fixed_columns, 8, &root_channel);
    var roots = try root_scheme.roots(a);
    defer roots.deinit(a);
    if (!std.mem.eql(u8, &roots.items[0], &pcs.commitments.items[0])) return error.Rv64MultiplicationFixedRootMismatch;
    const counts = [_]usize{ L.FIXED + 3, L.MAIN + 1, L.INTERACTION + 8, 16 };
    for (counts, 0..) |count, tree| {
        if (pcs.sampled_values.items[tree].len != count or pcs.queried_values.items[tree].len != count) return error.InvalidRv64MultiplicationProof;
        for (pcs.sampled_values.items[tree], 0..) |column, c| {
            const previous = if (tree == 1) c == L.COUNT else if (tree == 2) (c >= L.INTERACTION - 4 and c < L.INTERACTION) or c >= L.INTERACTION + 4 else false;
            if (column.len != @as(usize, if (previous) 2 else 1)) return error.InvalidRv64MultiplicationProof;
        }
    }
    var verifier = try Verifier.init(a, P.config());
    defer verifier.deinit(a);
    var fixed_logs: [L.FIXED + 3]u32 = undefined;
    @memset(fixed_logs[0..L.FIXED], public.log_size);
    @memset(fixed_logs[L.FIXED..], 8);
    var main_logs: [L.MAIN + 1]u32 = undefined;
    @memset(main_logs[0..L.MAIN], public.log_size);
    main_logs[L.MAIN] = 8;
    try verifier.commit(a, pcs.commitments.items[0], &fixed_logs, &channel);
    try verifier.commit(a, pcs.commitments.items[1], &main_logs, &channel);
    const challenges = Mul.provider.Challenges.draw(&channel);
    const alpha = drawAlpha(&channel);
    var expected = Q.zero();
    for (public.requests) |request| expected = expected.add(try challenges.denominator(&try Mul.trace.requestTuple(request)).inv());
    if (!claims.multiplication.add(claims.bytes).add(expected).isZero()) return error.Rv64MultiplicationClosure;
    channel.mixFelts(&.{ claims.multiplication, claims.bytes });
    var inter_logs: [L.INTERACTION + 8]u32 = undefined;
    @memset(inter_logs[0..L.INTERACTION], public.log_size);
    @memset(inter_logs[L.INTERACTION..], 8);
    try verifier.commit(a, pcs.commitments.items[2], &inter_logs, &channel);
    const mul = Mul.component.Component{ .log_size = public.log_size, .count = @intCast(public.requests.len), .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .byte_alpha = rv.range.cpu.PreparedAlpha.init(alpha), .claim = claims.multiplication };
    const byte = rv.providers.byte.Component{ .fixed_offset = L.FIXED, .main_offset = L.MAIN, .interaction_offset = L.INTERACTION, .alpha = alpha, .claim = claims.bytes };
    const components = [_]core.air.components.Component{ mul.asVerifierComponent(), byte.asVerifierComponent() };
    owns = false;
    try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &components, &channel, &verifier, proof);
}
pub const Bundle = struct {
    claims: Claims,
    proof: P.Proof,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};
/// Standalone diagnostic producer. The joint CPU caller reuses the exact same
/// concrete components; this API does not admit the reduced CPU plan by itself.
pub fn prove(a: std.mem.Allocator, public: Public, reference_domain: bool) !Bundle {
    var channel = P.Channel{};
    try mixPublic(&channel, public);
    var trace = try Mul.trace.Trace.initWithLog(a, public.requests, public.log_size);
    defer trace.deinit();
    var byte = try rv.range.provider.Trace.init(a, &trace.byte_counts);
    defer byte.deinit();
    var scheme = try Scheme.init(a, P.config());
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var fixed: [L.FIXED + 3]engine.pcs.ColumnEvaluation = undefined;
    fill(fixed[0..L.FIXED], trace.fixed, trace.log_size);
    fill(fixed[L.FIXED..], byte.fixed, 8);
    var main: [L.MAIN + 1]engine.pcs.ColumnEvaluation = undefined;
    fill(main[0..L.MAIN], trace.main, trace.log_size);
    fill(main[L.MAIN..], byte.main, 8);
    try scheme.commitBorrowedStreaming(a, &fixed, 8, &channel);
    try scheme.commitBorrowedStreaming(a, &main, 8, &channel);
    const challenges = Mul.provider.Challenges.draw(&channel);
    const alpha = drawAlpha(&channel);
    const claims = Claims{ .multiplication = try trace.generateInteraction(challenges, alpha), .bytes = try byte.generateInteraction(alpha) };
    channel.mixFelts(&.{ claims.multiplication, claims.bytes });
    var inter: [L.INTERACTION + 8]engine.pcs.ColumnEvaluation = undefined;
    fill(inter[0..L.INTERACTION], trace.interaction, trace.log_size);
    fill(inter[L.INTERACTION..], byte.interaction, 8);
    try scheme.commitBorrowedStreaming(a, &inter, 8, &channel);
    const component = Mul.component.Component{ .log_size = trace.log_size, .count = @intCast(public.requests.len), .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .byte_alpha = rv.range.cpu.PreparedAlpha.init(alpha), .claim = claims.multiplication, .reference_domain = reference_domain };
    const by = rv.providers.byte.Component{ .fixed_offset = L.FIXED, .main_offset = L.MAIN, .interaction_offset = L.INTERACTION, .alpha = alpha, .claim = claims.bytes };
    const provers = [_]engine.air.component_prover.ComponentProver{ component.asProverComponent(), by.asProverComponent() };
    owns = false;
    return .{ .claims = claims, .proof = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, &provers, &channel, scheme) };
}
