//! Closed indexed-address diagnostic. No RAM, JALR or Ethereum acceptance.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const front = @import("stwo_riscv_frontend");
const air = front.rv64_air;
const T = @import("../rv64_distributed_v1/manifest.zig").T;
const Backend = @import("stwo_cpu_backend").CpuBackend;
pub const Materials = @import("materials.zig").Materials;
pub const Geometry = @import("materials.zig").Geometry;
pub const Pair = @import("materials.zig").Pair;
pub const Sources = @import("sources.zig");
pub const Protocol = @import("protocol.zig");
pub const Components = @import("components.zig").Components;
pub const Encoded = struct {
    bytes: []u8,
    claims: Sources.Claims,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};
pub fn produce(a: std.mem.Allocator, materials: *const Materials, state: air.word16_cpu.public.Public, records: []const front.rv64.machine.Retirement, pairs: []const Pair) !Encoded {
    return produceInternal(a, materials, state, records, pairs, false);
}
/// Diagnostic scalar oracle; backend choice never enters the transcript.
pub fn produceReference(a: std.mem.Allocator, materials: *const Materials, state: air.word16_cpu.public.Public, records: []const front.rv64.machine.Retirement, pairs: []const Pair) !Encoded {
    return produceInternal(a, materials, state, records, pairs, true);
}
fn produceInternal(a: std.mem.Allocator, materials: *const Materials, state: air.word16_cpu.public.Public, records: []const front.rv64.machine.Retirement, pairs: []const Pair, scalar_reference: bool) !Encoded {
    _ = try materials.validatePublic(state, pairs);
    var source = try Sources.Source.init(a, materials, state, records, pairs);
    defer source.deinit();
    var scheme = try T.Scheme.init(a, T.P.config());
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = T.P.Channel{};
    try Protocol.mix(&channel, materials, state, pairs);
    try materials.appendFixed(a, &scheme, &channel);
    const main = try source.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    source.releaseMain();
    const ch = Protocol.draw(&channel);
    const claims = try source.generate(ch);
    Protocol.mixClaims(&channel, claims);
    const inter = try source.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    source.releaseCommittedInteraction();
    var components = try Components.init(materials, source.cpu.public, ch, claims, &source.map_roster);
    for (&components.index) |*component| component.scalar_reference = scalar_reference;
    const handles = try components.provers(a);
    defer a.free(handles);
    owns = false;
    var proof = try engine.prove.prove(Backend, T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try wire.encodeProofBytesBinary(a, proof), .claims = claims };
}
pub fn verify(a: std.mem.Allocator, materials: *const Materials, state: air.word16_cpu.public.Public, pairs: []const Pair, encoded: Encoded) !void {
    const public = try materials.validatePublic(state, pairs);
    try encoded.claims.validate();
    if (encoded.bytes.len > 64 * 1024 * 1024) return error.IndexProofResourceLimit;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, T.P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4 or !std.meta.eql(pcs.commitments.items[0], materials.fixed_root.value)) return error.InvalidIndexProof;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(T.P.Hasher, T.P.MerkleChannel).init(a, T.P.config());
    defer verifier.deinit(a);
    var channel = T.P.Channel{};
    try Protocol.mix(&channel, materials, state, pairs);
    for ([_]usize{ 0, 1 }) |tree| {
        const logs = try materials.logs(a, tree);
        defer a.free(logs);
        try verifier.commit(a, pcs.commitments.items[tree], logs, &channel);
    }
    const ch = Protocol.draw(&channel);
    Protocol.mixClaims(&channel, encoded.claims);
    const logs = try materials.logs(a, 2);
    defer a.free(logs);
    try verifier.commit(a, pcs.commitments.items[2], logs, &channel);
    const roster = try Sources.rosterFor(materials, pairs);
    var components = try Components.init(materials, public, ch, encoded.claims, &roster);
    const handles = try components.verifiers(a);
    defer a.free(handles);
    owns = false;
    try core.verifier.verify(T.P.Hasher, T.P.MerkleChannel, a, handles, &channel, &verifier, proof);
}
