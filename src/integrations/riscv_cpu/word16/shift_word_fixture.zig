//! Public-IO SHIFT diagnostic, one PCS: SHIFT + known main consumer + U16.
//! No execution/register/RAM claim or production profile is selected.
const std = @import("std");
const Profile = @import("fixture_profile.zig");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const X = rv.word16_v1.shift_word_experiment;
const P = X.lookup;
const C = rv.word16_v1.binary_component;
const RangeSource = rv.word16_v1.alu_experiment.range_source;
const RangeComponent = rv.word16_v1.alu_experiment.range_component;
const Trace = @import("shift_word_fixture_trace.zig");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
const Q = core.fields.qm31.QM31;
pub const CONFIG = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
pub const Encoded = struct { bytes: []u8, claims: [6]Q };
fn mix(channel: *Channel, roster: *const C.ExpectedRoster) !void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&.{ X.table.DOMAIN_TAG, 1, 5, 5, 20, 16, 53, 48, 13, 7, 160, 288, 3 });
    const digest = try C.expectedRosterDigest(roster);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}
fn draw(channel: *Channel) P.Challenges {
    channel.mixU32s(&.{ 0x55313652, 1 });
    const range16 = RangeSource.Challenges{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x414c5531, 13 });
    var function = rv.word16_v1.function_bus.Challenges{ .offset = channel.drawSecureFelt(), .coefficients = undefined };
    for (&function.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ X.table.DOMAIN_TAG, 6 });
    return .{ .shift = rv.providers.tables.Challenges.draw(channel), .range16 = range16, .function = function };
}
const Components = struct {
    shift: X.component.Component,
    known: C.Component,
    table: X.table_component.Component,
    range: RangeComponent.Component,
    fn init(ch: P.Challenges, claims: [6]Q, roster: *const C.ExpectedRoster) Components {
        return .{
            .shift = .{ .log_size = 5, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = .{ .shift = claims[0], .range16 = claims[1], .function = claims[2] } },
            .known = .{ .kind = .expected_main, .log_size = 5, .offsets = .{ 2, P.MAIN, P.INTERACTION }, .challenges = .{ .and_ = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .function = ch.function }, .claims = .{ .and_ = Q.zero(), .function = claims[3] }, .expected_roster = roster },
            .table = .{ .offsets = .{ 36, P.MAIN + 14, P.INTERACTION + 8 }, .challenges = ch.shift, .claim = claims[4] },
            .range = .{ .offsets = .{ 44, P.MAIN + 15, P.INTERACTION + 16 }, .challenges = ch.range16, .claim = claims[5] },
        };
    }
};
pub fn produce(a: std.mem.Allocator, attack: Trace.Attack) !Encoded {
    return produceWithRecorder(a, attack, null);
}
pub fn produceWithRecorder(a: std.mem.Allocator, attack: Trace.Attack, recorder: ?*Profile.Recorder) !Encoded {
    var f = blk: {
        var scope = try Profile.Scope.begin(recorder, "witness.prepare", "Prepare complete diagnostic witnesses");
        defer scope.end();
        break :blk try Trace.Fixture.initWithRecorder(a, attack, recorder);
    };
    defer f.deinit();
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    try mix(&channel, &f.roster);
    for ([_]u2{ 0, 1 }) |tree| {
        const columns = try f.columns(tree);
        defer a.free(columns);
        var scope = try Profile.Scope.begin(recorder, if (tree == 0) "commit.fixed" else "commit.main", if (tree == 0) "Commit immutable material" else "Commit all main advice");
        defer scope.end();
        try scheme.commit(a, columns, &channel);
    }
    const ch = draw(&channel);
    const actual = blk: {
        var scope = try Profile.Scope.begin(recorder, "interaction.prepare", "Generate all interaction witnesses");
        defer scope.end();
        break :blk try f.generateWithRecorder(ch, recorder);
    };
    if (!actual[2].add(actual[3]).isZero()) return error.InvalidShiftFunctionOracle;
    const claims = [_]Q{ actual[4].neg(), actual[5].neg(), actual[2], actual[3], actual[4], actual[5] };
    if (attack == .none and (!actual[0].add(actual[4]).isZero() or !actual[1].add(actual[5]).isZero())) return error.InvalidShiftRangeOracle;
    channel.mixFelts(&claims);
    const columns = try f.columns(2);
    defer a.free(columns);
    {
        var scope = try Profile.Scope.begin(recorder, "commit.interaction", "Commit all interaction advice");
        defer scope.end();
        try scheme.commit(a, columns, &channel);
    }
    const c = Components.init(ch, claims, &f.roster);
    const handles = [_]engine.air.component_prover.ComponentProver{ c.shift.asProverComponent(), c.known.asProverComponent(), c.table.asProverComponent(), c.range.asProverComponent() };
    owns = false;
    var proof = try Profile.prove(a, &handles, &channel, scheme, recorder);
    defer proof.deinit(a);
    var encode_scope = try Profile.Scope.begin(recorder, "wire.encode", "Encode native proof");
    defer encode_scope.end();
    return .{ .bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof), .claims = claims };
}
pub fn verify(a: std.mem.Allocator, encoded: Encoded, tamper: bool) !void {
    for (encoded.claims) |claim| for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NonCanonicalShiftClaim;
    if (!encoded.claims[0].add(encoded.claims[4]).isZero() or !encoded.claims[1].add(encoded.claims[5]).isZero() or !encoded.claims[2].add(encoded.claims[3]).isZero()) return error.UnclosedShiftClaims;
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
    if (!std.mem.eql(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0])) return error.InvalidShiftFixedRoot;
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
    var logs: [P.INTERACTION + 8 + 8 + 8]u32 = undefined;
    @memset(logs[0 .. P.INTERACTION + 8], 5);
    @memset(logs[P.INTERACTION + 8 .. P.INTERACTION + 16], 20);
    @memset(logs[P.INTERACTION + 16 ..], 16);
    try verifier.commit(a, commitments[2], &logs, &channel);
    if (tamper) proof.commitment_scheme_proof.sampled_values.items[2][44][1] = proof.commitment_scheme_proof.sampled_values.items[2][44][1].add(Q.one());
    const c = Components.init(ch, encoded.claims, &f.roster);
    const handles = [_]core.air.components.Component{ c.shift.asVerifierComponent(), c.known.asVerifierComponent(), c.table.asVerifierComponent(), c.range.asVerifierComponent() };
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &channel, &verifier, proof);
}
