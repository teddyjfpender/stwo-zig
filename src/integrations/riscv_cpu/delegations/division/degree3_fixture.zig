//! Closed standalone degree3 DIV/REM proof. Receiver supplies expected requests;
//! no CPU ingress, RAM, execution coverage or arbitrary open-claim acceptance.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const rv = @import("stwo_riscv_frontend").rv64_air;
const D = rv.arithmetic.division;
const P = rv.protocol;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Wire = @import("stwo_proof_wire");
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, P.Hasher, P.MerkleChannel);
pub const Encoded = struct {
    bytes: []u8,
    claim: [4]u32,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};
pub const REQUESTS = [_]D.trace.Request{
    .{ .opcode = .DIV, .a = 7, .b = 3, .result = 2 },
    .{ .opcode = .DIVU, .a = 0xffffffffffffffff, .b = 3, .result = 0x5555555555555555 },
    .{ .opcode = .REM, .a = 0xfffffffffffffff9, .b = 3, .result = 0xffffffffffffffff },
    .{ .opcode = .REMU, .a = 0xffffffffffffffff, .b = 3, .result = 0 },
    .{ .opcode = .DIVW, .a = 0x80000000, .b = 0xffffffff, .result = 0xffffffff80000000 },
    .{ .opcode = .DIVUW, .a = 0xffffffff, .b = 2, .result = 0x7fffffff },
    .{ .opcode = .REMW, .a = 0xfffffff9, .b = 3, .result = 0xffffffffffffffff },
    .{ .opcode = .REMUW, .a = 0xffffffff, .b = 2, .result = 1 },
    .{ .opcode = .DIV, .a = 0x8000000000000000, .b = 0xffffffffffffffff, .result = 0x8000000000000000 },
    .{ .opcode = .DIV, .a = 7, .b = 0, .result = 0xffffffffffffffff },
    .{ .opcode = .DIVU, .a = 7, .b = 0, .result = 0xffffffffffffffff },
    .{ .opcode = .REM, .a = 0xfffffffffffffff9, .b = 0, .result = 0xfffffffffffffff9 },
    .{ .opcode = .REMU, .a = 7, .b = 0, .result = 7 },
    .{ .opcode = .DIVW, .a = 7, .b = 0, .result = 0xffffffffffffffff },
    .{ .opcode = .DIVUW, .a = 7, .b = 0, .result = 0xffffffffffffffff },
    .{ .opcode = .REMW, .a = 0x80000000, .b = 0, .result = 0xffffffff80000000 },
    .{ .opcode = .REMUW, .a = 0x80000000, .b = 0, .result = 0xffffffff80000000 },
};
fn logFor(requests: []const D.trace.Request) !u32 {
    if (requests.len > 1 << 22) return error.InvalidRv64DivisionShape;
    for (requests) |request| _ = try D.layout.opcodeIndex(request.opcode);
    return @intCast(@max(5, std.math.log2_int_ceil(usize, @max(1, requests.len))));
}
fn mix(channel: *P.Channel, requests: []const D.trace.Request, log: u32) void {
    P.config().mixInto(channel);
    channel.mixU32s(&.{ 0x44445633, 1, @intCast(requests.len), log, D.layout.MAIN, D.layout.INTERACTION, D.layout.CONSTRAINTS, 3, 1 });
    for (requests) |r| {
        channel.mixU32s(&.{@intFromEnum(r.opcode)});
        channel.mixU64(r.a);
        channel.mixU64(r.b);
        channel.mixU64(r.result);
    }
}
fn columns(storage: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) void {
    const n = @as(usize, 1) << @intCast(log);
    for (out, 0..) |*v, c| v.* = .{ .log_size = log, .values = storage[c * n ..][0..n] };
}
fn component(log: u32, count: usize, ch: D.provider.Challenges, claim: Q) D.degree3_component.Component {
    return .{ .base = .{ .log_size = log, .count = count, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = ch, .claim = claim } };
}
pub fn produce(a: std.mem.Allocator, requests: []const D.trace.Request) !Encoded {
    return produceImpl(false, a, requests);
}
fn produceImpl(comptime scalar_reference: bool, a: std.mem.Allocator, requests: []const D.trace.Request) !Encoded {
    const log = try logFor(requests);
    var trace = try D.trace.Trace.initWithLog(a, requests, log);
    defer trace.deinit();
    var fixed: [D.layout.FIXED]engine.pcs.ColumnEvaluation = undefined;
    var main: [D.layout.MAIN]engine.pcs.ColumnEvaluation = undefined;
    var inter: [D.layout.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
    columns(trace.fixed, log, &fixed);
    columns(trace.main, log, &main);
    var scheme = try Scheme.init(a, P.config());
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    var ch = P.Channel{};
    mix(&ch, requests, log);
    try scheme.commit(a, &fixed, &ch);
    try scheme.commit(a, &main, &ch);
    try trace.releaseMain();
    const challenges = D.provider.Challenges.draw(&ch);
    const claim = try trace.generateInteraction(challenges);
    ch.mixFelts(&.{claim});
    columns(trace.interaction, log, &inter);
    try scheme.commit(a, &inter, &ch);
    const c = component(log, requests.len, challenges, claim);
    var handle = c.asProverComponent();
    var reference_vtable = handle.vtable.*;
    if (comptime scalar_reference) {
        reference_vtable.evaluateConstraintQuotientsOnDomain = D.degree3_component.testing.scalarErased;
        handle.vtable = &reference_vtable;
        handle.domain_parallel_evaluator = null;
    }
    const handles = [_]engine.air.component_prover.ComponentProver{handle};
    owns_scheme = false;
    var proof = try engine.prove.prove(Backend, P.Hasher, P.MerkleChannel, a, &handles, &ch, scheme);
    defer proof.deinit(a);
    const bytes = try Wire.encodeProofBytesBinary(a, proof);
    var limbs: [4]u32 = undefined;
    for (&limbs, claim.toM31Array()) |*v, m| v.* = m.v;
    return .{ .bytes = bytes, .claim = limbs };
}
pub fn verify(a: std.mem.Allocator, requests: []const D.trace.Request, encoded: Encoded) !void {
    const log = try logFor(requests);
    if (encoded.bytes.len > 64 << 20) return error.InvalidDivisionProofSize;
    var limbs: [4]M = undefined;
    for (&limbs, encoded.claim) |*v, raw| {
        if (raw >= core.fields.m31.Modulus) return error.InvalidDivisionClaim;
        v.* = M.fromCanonical(raw);
    }
    const claimed = Q.fromM31Array(limbs);
    var proof = try Wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    if (!std.meta.eql(proof.commitment_scheme_proof.config, P.config()) or proof.commitment_scheme_proof.revision_config != null) return error.InvalidDivisionConfig;
    const fixed = try D.trace.fixedColumns(a, requests.len, log);
    defer a.free(fixed);
    var fcols: [D.layout.FIXED]engine.pcs.ColumnEvaluation = undefined;
    columns(fixed, log, &fcols);
    var roots = try Scheme.init(a, P.config());
    defer roots.deinit(a);
    var root_channel = P.Channel{};
    try roots.commit(a, &fcols, &root_channel);
    var expected_roots = try roots.roots(a);
    defer expected_roots.deinit(a);
    const commits = proof.commitment_scheme_proof.commitments.items;
    if (commits.len != 4 or !std.mem.eql(u8, &expected_roots.items[0], &commits[0])) return error.InvalidDivisionFixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel).init(a, P.config());
    defer verifier.deinit(a);
    var ch = P.Channel{};
    mix(&ch, requests, log);
    try verifier.commit(a, commits[0], &@as([D.layout.FIXED]u32, @splat(log)), &ch);
    try verifier.commit(a, commits[1], &@as([D.layout.MAIN]u32, @splat(log)), &ch);
    const challenges = D.provider.Challenges.draw(&ch);
    var expected = Q.zero();
    for (requests) |r| expected = expected.sub(try challenges.denominator(&try D.trace.requestTuple(r)).inv());
    if (!expected.eql(claimed)) return error.InvalidDivisionClosure;
    ch.mixFelts(&.{claimed});
    try verifier.commit(a, commits[2], &@as([D.layout.INTERACTION]u32, @splat(log)), &ch);
    const c = component(log, requests.len, challenges, claimed);
    const handles = [_]core.air.components.Component{c.asVerifierComponent()};
    owns = false;
    try core.verifier.verify(P.Hasher, P.MerkleChannel, a, &handles, &ch, &verifier, proof);
}

pub const testing = if (@import("builtin").is_test) struct {
    pub fn produceScalarReference(a: std.mem.Allocator, requests: []const D.trace.Request) !Encoded {
        return produceImpl(true, a, requests);
    }
} else struct {};
