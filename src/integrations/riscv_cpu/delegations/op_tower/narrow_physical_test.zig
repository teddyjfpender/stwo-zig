//! Closed-admission composite narrow Miller-line correctness fixture. The input
//! frontier and32-step arithmetic DAG share one PCS/proof and one SSA closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const T = front.rv64_air.crypto.bn254_tower;
const N = T.narrow;
const S = N.source;
const Eq = N.equations;
const LF = Eq.Layout(.frontier);
const LA = Eq.Layout(.arithmetic);
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;
const FL = 8;
const AL = 15;
const FIRST_ID = 7;
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
const CF = N.Component(.frontier);
const CA = N.Component(.arithmetic);
fn mix(channel: *Channel) void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&.{ 0x4f50544e, 1, @intCast(T.execution.TAG), FL, AL, FIRST_ID, 1, LF.MAIN, LA.MAIN, LF.INTERACTION, LA.INTERACTION, LF.CONSTRAINTS, LA.CONSTRAINTS, N.micro.G.carry_bits, @intCast(N.micro.G.carry_offset) });
}
fn draw(channel: *Channel) Eq.Challenges {
    return .{ .bytes = channel.drawSecureFelt(), .carries = channel.drawSecureFelt(), .ssa = front.rv64_air.crypto.curves.equations.Wire.draw(channel), .wire = front.rv64_air.crypto.curves.equations.Wire.draw(channel) };
}
fn columns(storage: []const M, log: u32, out: []engine.pcs.ColumnEvaluation) void {
    const n = @as(usize, 1) << @intCast(log);
    for (out, 0..) |*column, index| column.* = .{ .log_size = log, .values = storage[index * n ..][0..n] };
}
fn logs(comptime left: usize, comptime right: usize) [left + right]u32 {
    return ([_]u32{FL} ** left) ++ ([_]u32{AL} ** right);
}
fn input() N.trace.Input {
    var out: N.trace.Input = @splat(0);
    for (0..12) |index| out[index] = (@as(u256, 1) << 240) + @as(u256, 0x102030405060708) * (index + 1);
    out[12] = 1;
    out[18] = 1;
    out[19] = 1;
    return out;
}
fn expected(ch: Eq.Challenges, packet: *const N.trace.Input, id: u32, corrupt: bool) !Q {
    const trace = front.rv64_air.crypto.curves.trace;
    var total = Q.zero();
    for (0..20) |coord| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, packet[coord], .little);
        total = total.sub(try ch.wire.denominator(&trace.externalTuple(12, id, coord, bytes)).inv());
    }
    // A*1=A, independent of the narrow/wide arithmetic implementations.
    for (0..12) |coord| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, packet[coord], .little);
        if (corrupt and coord == 0) bytes[0] ^= 1;
        total = total.add(try ch.wire.denominator(&trace.externalTuple(12, id, 20 + coord, bytes)).inv());
    }
    return total;
}
fn componentF(ch: Eq.Challenges, claim: Eq.Claims) CF {
    return .{ .log_size = FL, .public = .{ .calls = 1, .first_id = FIRST_ID }, .claims = claim, .challenges = ch };
}
fn componentA(ch: Eq.Challenges, claim: Eq.Claims) CA {
    return .{ .log_size = AL, .public = .{ .calls = 1, .first_id = FIRST_ID }, .claims = claim, .challenges = ch, .offsets = .{ S.FIXED, LF.MAIN, LF.INTERACTION } };
}
fn encodeClaim(destination: []u8, q: Q) void {
    for (q.toM31Array(), 0..) |value, index| std.mem.writeInt(u32, destination[4 * index ..][0..4], value.v, .little);
}
fn decodeClaim(source: []const u8) !Q {
    var values: [4]M = undefined;
    for (&values, 0..) |*value, index| {
        const integer = std.mem.readInt(u32, source[4 * index ..][0..4], .little);
        if (integer >= core.fields.m31.Modulus) return error.NoncanonicalTowerClaim;
        value.* = M.fromCanonical(integer);
    }
    return Q.fromM31Array(values);
}
fn receive(encoded: []const u8, packet: *const N.trace.Input, mutation: u8) !void {
    if (encoded.len < 64) return error.InvalidTowerFrame;
    const claims = [_]Q{ try decodeClaim(encoded[0..16]), try decodeClaim(encoded[16..32]), try decodeClaim(encoded[32..48]), try decodeClaim(encoded[48..64]) };
    if (!claims[0].add(claims[2]).isZero()) return error.TowerSsaNotClosed;
    var proof = try wire.decodeProofBytesBinary(a, encoded[64..]);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidTowerProofShape;
    const ff = try N.trace.fixed(a, .frontier, FL);
    defer a.free(ff);
    const af = try N.trace.fixed(a, .arithmetic, AL);
    defer a.free(af);
    var fixed_columns: [2 * S.FIXED]engine.pcs.ColumnEvaluation = undefined;
    columns(ff, FL, fixed_columns[0..S.FIXED]);
    columns(af, AL, fixed_columns[S.FIXED..]);
    var setup = try Scheme.init(a, CONFIG);
    defer setup.deinit(a);
    var scratch = Channel{};
    try setup.commit(a, &fixed_columns, &scratch);
    var fresh = try setup.roots(a);
    defer fresh.deinit(a);
    if (!std.mem.eql(u8, &roots[0], &fresh.items[0])) return error.InvalidTowerFixedRoot;
    var verifier = try Verifier.init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel{};
    mix(&channel);
    try verifier.commit(a, roots[0], &logs(S.FIXED, S.FIXED), &channel);
    try verifier.commit(a, roots[1], &logs(LF.MAIN, LA.MAIN), &channel);
    const ch = draw(&channel);
    if (!claims[1].add(claims[3]).eql(try expected(ch, packet, if (mutation == 1) FIRST_ID + 1 else FIRST_ID, mutation == 2))) return error.TowerWireNotClosed;
    channel.mixFelts(&claims);
    try verifier.commit(a, roots[2], &logs(LF.INTERACTION, LA.INTERACTION), &channel);
    if (mutation == 3) proof.commitment_scheme_proof.sampled_values.items[1][LF.MAIN + N.micro.RESULT][0] = proof.commitment_scheme_proof.sampled_values.items[1][LF.MAIN + N.micro.RESULT][0].add(Q.one());
    const f = componentF(ch, .{ .ssa = claims[0], .wire = claims[1] });
    const ar = componentA(ch, .{ .ssa = claims[2], .wire = claims[3] });
    const components = [_]core.air.components.Component{ f.asVerifierComponent(), ar.asVerifierComponent() };
    owns = false;
    try core.verifier.verify(H, MC, a, &components, &channel, &verifier, proof);
}
test "narrow OP Miller-line composite proof closes SSA and fresh Wire authority" {
    const packet = input();
    var fs = try N.trace.Source(.frontier).init(a, &.{packet}, FIRST_ID, FL);
    defer fs.deinit();
    var ars = try N.trace.Source(.arithmetic).init(a, &.{packet}, FIRST_ID, AL);
    defer ars.deinit();
    var fixed_columns: [2 * S.FIXED]engine.pcs.ColumnEvaluation = undefined;
    var main_columns: [LF.MAIN + LA.MAIN]engine.pcs.ColumnEvaluation = undefined;
    var inter_columns: [LF.INTERACTION + LA.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
    columns(fs.fixed, FL, fixed_columns[0..S.FIXED]);
    columns(ars.fixed, AL, fixed_columns[S.FIXED..]);
    columns(fs.main, FL, main_columns[0..LF.MAIN]);
    columns(ars.main, AL, main_columns[LF.MAIN..]);
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    mix(&channel);
    try scheme.commit(a, &fixed_columns, &channel);
    try scheme.commit(a, &main_columns, &channel);
    const ch = draw(&channel);
    const fc = try fs.generateInteraction(ch);
    const ac = try ars.generateInteraction(ch);
    try std.testing.expect(fc.ssa.add(ac.ssa).isZero());
    try std.testing.expect(fc.wire.add(ac.wire).eql(try expected(ch, &packet, FIRST_ID, false)));
    const claims = [_]Q{ fc.ssa, fc.wire, ac.ssa, ac.wire };
    channel.mixFelts(&claims);
    columns(fs.interaction, FL, inter_columns[0..LF.INTERACTION]);
    columns(ars.interaction, AL, inter_columns[LF.INTERACTION..]);
    try scheme.commit(a, &inter_columns, &channel);
    const f = componentF(ch, fc);
    const ar = componentA(ch, ac);
    const components = [_]engine.air.component_prover.ComponentProver{ f.asProverComponent(), ar.asProverComponent() };
    owns = false;
    var proof = try engine.prove.prove(Backend, H, MC, a, &components, &channel, scheme);
    defer proof.deinit(a);
    const bytes = try wire.encodeProofBytesBinary(a, proof);
    defer a.free(bytes);
    const framed = try a.alloc(u8, 64 + bytes.len);
    defer a.free(framed);
    for (claims, 0..) |claim, index| encodeClaim(framed[16 * index ..][0..16], claim);
    @memcpy(framed[64..], bytes);
    try receive(framed, &packet, 0);
    for (1..4) |mutation| try std.testing.expect(std.meta.isError(receive(framed, &packet, @intCast(mutation))));
    framed[0] ^= 1;
    try std.testing.expectError(error.TowerSsaNotClosed, receive(framed, &packet, 0));
    std.debug.print("OP_TOWER_NARROW_PHYSICAL toy_profile=true proof_bytes={} arithmetic={}/{} frontier={}/{} degree=3\n", .{ framed.len, LA.MAIN, LA.INTERACTION, LF.MAIN, LF.INTERACTION });
}
