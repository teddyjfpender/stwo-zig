//! Standalone physical truth qualification, not OP execution admission. The
//! expected Wire35 claim comes from independently supplied output coordinates.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const B = @import("stwo_cpu_backend").CpuBackend;
const T = front.rv64_air.crypto.bn254_tower;
const L = T.Layout;
const N = T.Native;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const wire = @import("stwo_proof_wire");
const a = std.testing.allocator;
const LOG = 8;
const FIRST_ID = 7;
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
fn mix(channel: *Channel) void {
    CONFIG.mixInto(channel);
    // Every receiver recreates the carried definition from its own source.
    channel.mixU32s(&.{ 0x4f505430, 1, @intCast(T.execution.TAG), LOG, FIRST_ID, 1, L.MAIN, L.INTERACTION, L.CONSTRAINTS });
    inline for (L.GEOMETRY) |g| channel.mixU32s(&.{ @intCast(g.group), g.carry_bits, @intCast(g.carry_offset), @intCast(g.q_bytes) });
}
fn columns(storage: []const M, output: []engine.pcs.ColumnEvaluation) void {
    const n = @as(usize, 1) << LOG;
    for (output, 0..) |*column, i| column.* = .{ .log_size = LOG, .values = storage[i * n ..][0..n] };
}
fn packet() N.Packet {
    var out: N.Packet = @splat(0);
    // A dense accumulator times the multiplicative identity. The receiver's
    // expected output is known without executing either witness implementation.
    for (0..12) |i| {
        const value: u256 = (@as(u256, 1) << 240) + 0x102030405060708 * (i + 1);
        std.mem.writeInt(u256, out[32 * i ..][0..32], value, .little);
    }
    out[12 * 32] = 1;
    out[18 * 32] = 1;
    out[19 * 32] = 1;
    return out;
}
fn expected(ch: T.Challenges, input: *const N.Packet, id: u32, corrupt_output: bool) !Q {
    const trace = front.rv64_air.crypto.curves.trace;
    var total = Q.zero();
    for (0..20) |coord| {
        const bytes = input[32 * coord ..][0..32].*;
        total = total.sub(try ch.wire.denominator(&trace.externalTuple(12, id, coord, bytes)).inv());
    }
    for (0..12) |coord| {
        var bytes = input[32 * coord ..][0..32].*;
        if (corrupt_output and coord == 0) bytes[0] ^= 1;
        total = total.add(try ch.wire.denominator(&trace.externalTuple(12, id, 20 + coord, bytes)).inv());
    }
    return total;
}
fn receive(encoded: []const u8, input: *const N.Packet, tamper: u8) !void {
    var proof = try wire.decodeProofBytesBinary(a, encoded);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidTowerProofShape;
    const fresh_fixed = try front.rv64_air.crypto.curves.trace.fixed(a, LOG);
    defer a.free(fresh_fixed);
    var fixed_columns: [4]engine.pcs.ColumnEvaluation = undefined;
    columns(fresh_fixed, &fixed_columns);
    var scheme = try Scheme.init(a, CONFIG);
    defer scheme.deinit(a);
    var scratch = Channel{};
    try scheme.commit(a, &fixed_columns, &scratch);
    var fresh_roots = try scheme.roots(a);
    defer fresh_roots.deinit(a);
    if (!std.mem.eql(u8, &roots[0], &fresh_roots.items[0])) return error.InvalidTowerFixedRoot;
    var verifier = try Verifier.init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel{};
    mix(&channel);
    try verifier.commit(a, roots[0], &([_]u32{LOG} ** 4), &channel);
    try verifier.commit(a, roots[1], &([_]u32{LOG} ** L.MAIN), &channel);
    const challenges = T.Challenges{ .bytes = channel.drawSecureFelt(), .wire = front.rv64_air.crypto.curves.equations.Wire.draw(&channel) };
    const claim = try expected(challenges, input, if (tamper == 1) FIRST_ID + 1 else FIRST_ID, tamper == 2);
    channel.mixFelts(&.{claim});
    try verifier.commit(a, roots[2], &([_]u32{LOG} ** L.INTERACTION), &channel);
    if (tamper == 3) proof.commitment_scheme_proof.sampled_values.items[1][L.OUT][0] = proof.commitment_scheme_proof.sampled_values.items[1][L.OUT][0].add(Q.one());
    const component = T.Component{ .log_size = LOG, .public = .{ .calls = 1, .first_id = FIRST_ID }, .claim = claim, .challenges = challenges };
    const components = [_]core.air.components.Component{component.asVerifierComponent()};
    owns = false;
    try core.verifier.verify(H, MC, a, &components, &channel, &verifier, proof);
}
test "OP sparse034 physical carried truth and fresh source-owned receiver reject Wire and proof mutations" {
    const input = packet();
    var source = try T.Trace.Source.init(a, &.{input}, FIRST_ID, LOG);
    defer source.deinit();
    var fixed_columns: [4]engine.pcs.ColumnEvaluation = undefined;
    var main_columns: [L.MAIN]engine.pcs.ColumnEvaluation = undefined;
    var inter_columns: [L.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
    columns(source.fixed, &fixed_columns);
    columns(source.main, &main_columns);
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    mix(&channel);
    try scheme.commit(a, &fixed_columns, &channel);
    try scheme.commit(a, &main_columns, &channel);
    const challenges = T.Challenges{ .bytes = channel.drawSecureFelt(), .wire = front.rv64_air.crypto.curves.equations.Wire.draw(&channel) };
    const claim = try source.generateInteraction(challenges);
    try std.testing.expect(claim.eql(try expected(challenges, &input, FIRST_ID, false)));
    channel.mixFelts(&.{claim});
    columns(source.interaction, &inter_columns);
    try scheme.commit(a, &inter_columns, &channel);
    const component = T.Component{ .log_size = LOG, .public = .{ .calls = 1, .first_id = FIRST_ID }, .claim = claim, .challenges = challenges };
    const components = [_]engine.air.component_prover.ComponentProver{component.asProverComponent()};
    owns = false;
    var proof = try engine.prove.prove(B, H, MC, a, &components, &channel, scheme);
    defer proof.deinit(a);
    const encoded = try wire.encodeProofBytesBinary(a, proof);
    defer a.free(encoded);
    try receive(encoded, &input, 0);
    for (1..4) |mutation| try std.testing.expect(std.meta.isError(receive(encoded, &input, @intCast(mutation))));
    std.debug.print("OP_TOWER_PHYSICAL toy_profile=true proof_bytes={} main={} inter={} degree={}\n", .{ encoded.len, L.MAIN, L.INTERACTION, L.DEGREE });
}
