//! Public-IO ALU diagnostic, one PCS: ALU + known main consumer + U16.
//! No execution/register/RAM claim or production profile is selected.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const X = rv.word16_v1.alu_experiment;
const P = X.lookup;
const C = rv.word16_v1.binary_component;
const Trace = @import("alu_fixture_trace.zig");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
const Q = core.fields.qm31.QM31;
pub const CONFIG = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
pub const Encoded = struct { bytes: []u8, claims: [4]Q };
fn mix(channel: *Channel, roster: *const C.ExpectedRoster) !void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&.{ 0x57313641, 1, 5, 5, 16, 60, 52, 13, 10, 640, 3 });
    const digest = try C.expectedRosterDigest(roster);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}
fn draw(channel: *Channel) P.Challenges {
    channel.mixU32s(&.{ 0x55313652, 1 });
    const range16 = X.range_source.Challenges{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x414c5531, 13 });
    var function = rv.word16_v1.function_bus.Challenges{ .offset = channel.drawSecureFelt(), .coefficients = undefined };
    for (&function.coefficients) |*v| v.* = channel.drawSecureFelt();
    return .{ .range16 = range16, .function = function };
}
const Components = struct {
    alu: X.component.Component,
    known: C.Component,
    range: X.range_component.Component,
    fn init(ch: P.Challenges, claims: [4]Q, roster: *const C.ExpectedRoster) Components {
        return .{
            .alu = .{ .log_size = 5, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = .{ .range16 = claims[0], .function = claims[1] } },
            .known = .{ .kind = .expected_main, .log_size = 5, .offsets = .{ 2, P.MAIN, P.INTERACTION }, .challenges = .{ .and_ = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .function = ch.function }, .claims = .{ .and_ = Q.zero(), .function = claims[2] }, .expected_roster = roster },
            .range = .{ .offsets = .{ 36, P.MAIN + 14, P.INTERACTION + 8 }, .challenges = ch.range16, .claim = claims[3] },
        };
    }
};
pub fn produce(a: std.mem.Allocator, attack: Trace.Attack) !Encoded {
    var f = try Trace.Fixture.init(a, attack);
    defer f.deinit();
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    try mix(&channel, &f.roster);
    for ([_]u2{ 0, 1 }) |tree| {
        const columns = try f.columns(tree);
        defer a.free(columns);
        try scheme.commit(a, columns, &channel);
    }
    const ch = draw(&channel);
    const actual = try f.generate(ch);
    if (!actual[1].add(actual[2]).isZero()) return error.InvalidAluFunctionOracle;
    const claims = [_]Q{ actual[3].neg(), actual[1], actual[2], actual[3] };
    if (attack == .none and !actual[0].add(actual[3]).isZero()) return error.InvalidAluRangeOracle;
    channel.mixFelts(&claims);
    const columns = try f.columns(2);
    defer a.free(columns);
    try scheme.commit(a, columns, &channel);
    const c = Components.init(ch, claims, &f.roster);
    const handles = [_]engine.air.component_prover.ComponentProver{ c.alu.asProverComponent(), c.known.asProverComponent(), c.range.asProverComponent() };
    owns = false;
    var proof = try engine.prove.prove(Backend, H, MC, a, &handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof), .claims = claims };
}
pub fn verify(a: std.mem.Allocator, encoded: Encoded, tamper: bool) !void {
    for (encoded.claims) |claim| for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NonCanonicalAluClaim;
    if (!encoded.claims[0].add(encoded.claims[3]).isZero() or !encoded.claims[1].add(encoded.claims[2]).isZero()) return error.UnclosedAluClaims;
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var f = try Trace.Fixture.init(a, .none);
    defer f.deinit();
    var expected = try Scheme.init(a, CONFIG);
    defer expected.deinit(a);
    var scratch = Channel{};
    const fixed = try f.columns(0);
    defer a.free(fixed);
    try expected.commit(a, fixed, &scratch);
    var roots = try expected.roots(a);
    defer roots.deinit(a);
    if (!std.mem.eql(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0])) return error.InvalidAluFixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel{};
    try mix(&channel, &f.roster);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    for ([_]u2{ 0, 1 }) |tree| {
        const columns = try f.columns(tree);
        defer a.free(columns);
        const logs = try a.alloc(u32, columns.len);
        defer a.free(logs);
        for (columns, logs) |column, *log| log.* = column.log_size;
        try verifier.commit(a, commitments[tree], logs, &channel);
    }
    const ch = draw(&channel);
    channel.mixFelts(&encoded.claims);
    var logs: [P.INTERACTION + 8 + 8]u32 = undefined;
    @memset(logs[0 .. P.INTERACTION + 8], 5);
    @memset(logs[P.INTERACTION + 8 ..], 16);
    try verifier.commit(a, commitments[2], &logs, &channel);
    if (tamper) proof.commitment_scheme_proof.sampled_values.items[2][48][1] = proof.commitment_scheme_proof.sampled_values.items[2][48][1].add(Q.one());
    const c = Components.init(ch, encoded.claims, &f.roster);
    const handles = [_]core.air.components.Component{ c.alu.asVerifierComponent(), c.known.asVerifierComponent(), c.range.asVerifierComponent() };
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &channel, &verifier, proof);
}
