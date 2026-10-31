//! Separate strict-pair MUL2n/BYTE2n closed proof receiver. Expected requests are receiver
//! input; no producer root or unclosed operand/result claim is authoritative.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
pub const Mul = rv.arithmetic.multiplication;
const L = Mul.degree3_layout;
const Old = @import("native.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = rv.protocol;
pub const B = @import("stwo_cpu_backend").CpuBackend;
pub const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const Claims = Old.Claims;
pub const Public = Old.Public;
pub fn mixPublic(channel: *P.Channel, public: Public) !void {
    try Old.mixPublic(channel, public);
    channel.mixU32s(&.{ 0x4d554433, 1, L.MAIN, L.INTERACTION, L.CONSTRAINTS, 3, 1, L.BYTE_QUERIES });
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
    const counts = [_]usize{ L.FIXED + 3, L.MAIN + 1, L.INTERACTION + 8, 8 };
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
    const mul = Mul.degree3_component.Component{ .log_size = public.log_size, .count = @intCast(public.requests.len), .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .byte_alpha = alpha, .claim = claims.multiplication };
    const byte = rv.providers.byte_degree3.Component{ .base = .{ .fixed_offset = L.FIXED, .main_offset = L.MAIN, .interaction_offset = L.INTERACTION, .alpha = alpha, .claim = claims.bytes } };
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
pub fn prove(a: std.mem.Allocator, public: Public) !Bundle {
    return proveImpl(false, a, public);
}
fn proveImpl(comptime scalar_reference: bool, a: std.mem.Allocator, public: Public) !Bundle {
    var channel = P.Channel{};
    try mixPublic(&channel, public);
    var trace = try Mul.degree3_source.Source.initWithLog(a, public.requests, public.log_size);
    defer trace.deinit();
    var byte = try rv.range.provider.Trace.init(a, &trace.base.byte_counts);
    defer byte.deinit();
    var scheme = try Scheme.init(a, P.config());
    var owns = true;
    errdefer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var fixed: [L.FIXED + 3]engine.pcs.ColumnEvaluation = undefined;
    fill(fixed[0..L.FIXED], trace.base.fixed, trace.base.log_size);
    fill(fixed[L.FIXED..], byte.fixed, 8);
    var main: [L.MAIN + 1]engine.pcs.ColumnEvaluation = undefined;
    fill(main[0..L.MAIN], trace.base.main, trace.base.log_size);
    fill(main[L.MAIN..], byte.main, 8);
    try scheme.commitBorrowedStreaming(a, &fixed, 8, &channel);
    try scheme.commitBorrowedStreaming(a, &main, 8, &channel);
    try trace.releaseMain();
    const challenges = Mul.provider.Challenges.draw(&channel);
    const alpha = drawAlpha(&channel);
    const claims = Claims{ .multiplication = try trace.generate(challenges, alpha), .bytes = try byte.generateInteraction(alpha) };
    channel.mixFelts(&.{ claims.multiplication, claims.bytes });
    var inter: [L.INTERACTION + 8]engine.pcs.ColumnEvaluation = undefined;
    fill(inter[0..L.INTERACTION], trace.base.interaction, trace.base.log_size);
    fill(inter[L.INTERACTION..], byte.interaction, 8);
    try scheme.commitBorrowedStreaming(a, &inter, 8, &channel);
    const component = Mul.degree3_component.Component{ .log_size = trace.base.log_size, .count = @intCast(public.requests.len), .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .byte_alpha = alpha, .claim = claims.multiplication };
    const by = rv.providers.byte_degree3.Component{ .base = .{ .fixed_offset = L.FIXED, .main_offset = L.MAIN, .interaction_offset = L.INTERACTION, .alpha = alpha, .claim = claims.bytes } };
    var mul_handle = component.asProverComponent();
    var reference_vtable = mul_handle.vtable.*;
    if (comptime scalar_reference) {
        reference_vtable.evaluateConstraintQuotientsOnDomain = Mul.degree3_component.testing.scalarErased;
        mul_handle.vtable = &reference_vtable;
        mul_handle.domain_parallel_evaluator = null;
    }
    const provers = [_]engine.air.component_prover.ComponentProver{ mul_handle, by.asProverComponent() };
    owns = false;
    return .{ .claims = claims, .proof = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, &provers, &channel, scheme) };
}

pub const REQUESTS = [_]Mul.trace.Request{
    .{ .opcode = .MUL, .a = 0, .b = 0, .result = 0 },
    .{ .opcode = .MUL, .a = 0xffffffffffffffff, .b = 0xffffffffffffffff, .result = 1 },
    .{ .opcode = .MUL, .a = 0x8000000000000000, .b = 2, .result = 0 },
    .{ .opcode = .MULHU, .a = 0xffffffffffffffff, .b = 0xffffffffffffffff, .result = 0xfffffffffffffffe },
    .{ .opcode = .MULHU, .a = 0x8000000000000000, .b = 2, .result = 1 },
    .{ .opcode = .MULH, .a = 0xffffffffffffffff, .b = 0xffffffffffffffff, .result = 0 },
    .{ .opcode = .MULH, .a = 0x8000000000000000, .b = 0xffffffffffffffff, .result = 0 },
    .{ .opcode = .MULH, .a = 0x8000000000000000, .b = 2, .result = 0xffffffffffffffff },
    .{ .opcode = .MULH, .a = 0x8000000000000000, .b = 0x8000000000000000, .result = 0x4000000000000000 },
    .{ .opcode = .MULHSU, .a = 0xffffffffffffffff, .b = 0xffffffffffffffff, .result = 0xffffffffffffffff },
    .{ .opcode = .MULHSU, .a = 0x8000000000000000, .b = 0xffffffffffffffff, .result = 0x8000000000000000 },
    .{ .opcode = .MULHSU, .a = 0x7fffffffffffffff, .b = 0xffffffffffffffff, .result = 0x7ffffffffffffffe },
    .{ .opcode = .MULW, .a = 0xffffffff, .b = 2, .result = 0xfffffffffffffffe },
    .{ .opcode = .MULW, .a = 0x80000000, .b = 1, .result = 0xffffffff80000000 },
    .{ .opcode = .MULW, .a = 0xdeadbeef00000003, .b = 0xfedcba9800000004, .result = 12 },
};

pub const testing = if (@import("builtin").is_test) struct {
    pub fn proveScalarReference(a: std.mem.Allocator, public: Public) !Bundle {
        return proveImpl(true, a, public);
    }
} else struct {};
