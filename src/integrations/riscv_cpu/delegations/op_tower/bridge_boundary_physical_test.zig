//! Physical malicious-trace fixture. The producer deliberately bypasses native
//! pointer validation; the fresh STARK receiver must enforce the packet AIR.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = A.crypto.secp256k1.word16_bridge;
const L = S.layout;
const Boundary = @import("bridge_boundary_test.zig");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const a = std.testing.allocator;
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 12 } };
const MaliciousSource = struct {
    allocator: std.mem.Allocator,
    kind: S.types.Kind = .bn254_sparse034,
    log_size: u32 = 5,
    first_id: u32 = 1,
    calls: []u8,
    rows: [32][L.MAIN]M,
    fixed: []M,
    counts16: []u64,
    counts8: []u64,
    interaction: []M = &.{},
    // Intentionally untrusted producer: no native packet guard participates.
    pub fn validateCall(_: *const @This(), _: u8) !void {}
    pub fn rowForCall(self: *const @This(), present: ?u8, coord: usize, _: u32) [L.MAIN]M {
        return if (present != null) self.rows[coord] else [_]M{M.zero()} ** L.MAIN;
    }
    fn init(poison: bool) !@This() {
        const calls = try a.alloc(u8, 1);
        errdefer a.free(calls);
        calls[0] = 1;
        const fixed = try S.source.fixed(a, .bn254_sparse034, 5);
        errdefer a.free(fixed);
        const c16 = try a.alloc(u64, 65536);
        errdefer a.free(c16);
        @memset(c16, 0);
        const c8 = try a.alloc(u64, 256);
        errdefer a.free(c8);
        @memset(c8, 0);
        var out = @This(){ .allocator = a, .calls = calls, .fixed = fixed, .counts16 = c16, .counts8 = c8, .rows = undefined };
        const packet = Boundary.call();
        for (&out.rows, 0..) |*row, index| {
            row.* = if (index < 20) S.source.nativeTowerRow(packet, index, 1) else [_]M{M.zero()} ** L.MAIN;
            if (poison and index < 20) Boundary.poisonPointer(row, index, false);
            for (L.U16) |column| c16[row[column].v] += 1;
            for (L.U8) |column| c8[row[column].v] += 1;
        }
        return out;
    }
    fn deinit(self: *@This()) void {
        a.free(self.calls);
        a.free(self.fixed);
        a.free(self.counts16);
        a.free(self.counts8);
        a.free(self.interaction);
    }
};
fn mix(channel: *Channel) void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&.{ 0x4f504250, 1, 0x40001, 5, 1, 1 });
}
fn draw(channel: *Channel) S.types.Challenges {
    var out: S.types.Challenges = undefined;
    out.ram.offset = channel.drawSecureFelt();
    for (&out.ram.coefficients) |*c| c.* = channel.drawSecureFelt();
    out.owner.offset = channel.drawSecureFelt();
    for (&out.owner.coefficients) |*c| c.* = channel.drawSecureFelt();
    out.wire = A.crypto.secp256k1.equations.Wire.draw(channel);
    out.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    out.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    return out;
}
fn columns(data: []const M, out: []engine.pcs.ColumnEvaluation) void {
    for (out, 0..) |*column, c| column.* = .{ .log_size = 5, .values = data[32 * c ..][0..32] };
}
fn component(claims: S.types.Claims, ch: S.types.Challenges) S.component.Component {
    return .{ .kind = .bn254_sparse034, .log_size = 5, .rows = 1, .first_id = 1, .offsets = .{ 0, 0, 0 }, .claims = claims, .challenges = ch };
}
fn receive(bytes: []const u8, claims: S.types.Claims) !void {
    const Wire = @import("stwo_proof_wire");
    var proof = try Wire.decodeProofBytesBinary(a, bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidBoundaryProof;
    const fixed = try S.source.fixed(a, .bn254_sparse034, 5);
    defer a.free(fixed);
    var fixed_columns: [L.FIXED]engine.pcs.ColumnEvaluation = undefined;
    columns(fixed, &fixed_columns);
    var setup = try Scheme.init(a, CONFIG);
    defer setup.deinit(a);
    var scratch = Channel{};
    try setup.commit(a, &fixed_columns, &scratch);
    var expected_roots = try setup.roots(a);
    defer expected_roots.deinit(a);
    if (!std.mem.eql(u8, &roots[0], &expected_roots.items[0])) return error.InvalidBoundaryFixedRoot;
    var receiver = try Verifier.init(a, CONFIG);
    defer receiver.deinit(a);
    var channel = Channel{};
    mix(&channel);
    try receiver.commit(a, roots[0], &([_]u32{5} ** L.FIXED), &channel);
    try receiver.commit(a, roots[1], &([_]u32{5} ** L.MAIN), &channel);
    const ch = draw(&channel);
    channel.mixFelts(&claims.values());
    try receiver.commit(a, roots[2], &([_]u32{5} ** L.INTERACTION), &channel);
    const c = component(claims, ch);
    const handles = [_]core.air.components.Component{c.asVerifierComponent()};
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &channel, &receiver, proof);
}
fn qualify(poison: bool) !void {
    var source = try MaliciousSource.init(poison);
    defer source.deinit();
    const main = try a.alloc(M, L.MAIN * 32);
    defer a.free(main);
    for (source.rows, 0..) |row, index| for (row, 0..) |value, column| {
        main[column * 32 + A.memory.closed_ram.trace.physical(index, 5)] = value;
    };
    var fixed_columns: [L.FIXED]engine.pcs.ColumnEvaluation = undefined;
    var main_columns: [L.MAIN]engine.pcs.ColumnEvaluation = undefined;
    var inter_columns: [L.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
    columns(source.fixed, &fixed_columns);
    columns(main, &main_columns);
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    mix(&channel);
    try scheme.commit(a, &fixed_columns, &channel);
    try scheme.commit(a, &main_columns, &channel);
    const ch = draw(&channel);
    const d16 = try a.alloc(Q, 65536);
    defer a.free(d16);
    const d8 = try a.alloc(Q, 256);
    defer a.free(d8);
    for (d16, 0..) |*d, value| d.* = try ch.range16.denominatorFor(Q, Q.fromBase(M.fromCanonical(@intCast(value)))).inv();
    for (d8, 0..) |*d, value| d.* = try ch.range8.denominatorFor(Q, Q.fromBase(M.fromCanonical(@intCast(value)))).inv();
    const claims = try S.source.generateRowsForTest(&source, ch, d16, d8);
    channel.mixFelts(&claims.values());
    columns(source.interaction, &inter_columns);
    try scheme.commit(a, &inter_columns, &channel);
    const c = component(claims, ch);
    const handles = [_]engine.air.component_prover.ComponentProver{c.asProverComponent()};
    owns = false;
    var proof = engine.prove.prove(Backend, H, MC, a, &handles, &channel, scheme) catch |err| {
        if (poison and err == error.ConstraintsNotSatisfied) {
            std.debug.print("OP_PACKET_OVERFLOW_PHYSICAL rejected=ConstraintsNotSatisfied native_guards_bypassed=true toy_profile=true\n", .{});
            return;
        }
        return err;
    };
    defer proof.deinit(a);
    const bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof);
    defer a.free(bytes);
    if (!poison) return receive(bytes, claims);
    // This failure must come from physical verification, not native validation.
    if (receive(bytes, claims)) |_| return error.WrappedPointerProofAccepted else |err| {
        if (err == error.OutOfMemory) return err;
        std.debug.print("OP_PACKET_OVERFLOW_PHYSICAL rejected={s} proof_bytes={} toy_profile=true\n", .{ @errorName(err), bytes.len });
    }
}
test "OP640 physical packet proof rejects coherent wrapped-pointer trace beyond native guard" {
    try qualify(false);
    try qualify(true);
}
