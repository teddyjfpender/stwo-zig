//! Explicit standalone public-IO fixture. No CPU/service coordinator activation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const B = @import("stwo_cpu_backend").CpuBackend;
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const D = K.pair2n;
const L = D.layout;
const Q = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
pub const Claims = [3]Q;
pub const Encoded = struct {
    bytes: []u8,
    claims: Claims,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
    }
};
pub fn config(production: bool) !core.pcs.PcsConfig {
    return .{ .pow_bits = if (production) 26 else 0, .fri_config = try core.fri.FriConfig.init(0, 1, if (production) 70 else 12) };
}
pub fn input(seed: u64) K.trace.State {
    var state: K.trace.State = undefined;
    for (&state, 0..) |*v, i| v.* = ((seed +% i +% 1) *% 0x9e3779b97f4a7c15) ^ @as(u64, @intCast(i));
    return state;
}
pub fn reference(before: K.trace.State) K.trace.State {
    var state = std.crypto.core.keccak.KeccakF(1600){ .st = before };
    state.permute();
    return state.st;
}
fn start(channel: anytype, inputs: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig) !void {
    if (log > 18) return error.Pair2nFixtureGeometryLimit;
    try K.layout.validateGeometry(inputs.len, first, log);
    cfg.mixInto(channel);
    L.mix(channel);
    channel.mixU32s(&.{ @intCast(inputs.len), first, log });
    // Complete externally expected inputs AND independently computed outputs bind
    // the local transcript before MAIN/challenges, rather than native trace claims.
    for (inputs) |before| {
        for (before) |v| channel.mixU64(v);
        for (reference(before)) |v| channel.mixU64(v);
    }
}
fn expectedIo(inputs: []const K.trace.State, first: u32, ch: K.equations.Challenges) !Q {
    var sum = Q.zero();
    for (inputs, 0..) |before, index| {
        for ([_]K.trace.State{ before, reference(before) }, 0..) |state, direction| for (0..25) |lane| {
            var tuple: [11]Q = undefined;
            tuple[0] = Q.fromBase(core.fields.m31.M31.fromCanonical(first + @as(u32, @intCast(index))));
            tuple[1] = Q.fromBase(core.fields.m31.M31.fromCanonical(@intCast(direction)));
            tuple[2] = Q.fromBase(core.fields.m31.M31.fromCanonical(@intCast(lane)));
            for (0..8) |byte| tuple[3 + byte] = Q.fromBase(core.fields.m31.M31.fromCanonical(@intCast((state[lane] >> @as(u6, @intCast(8 * byte))) & 255)));
            sum = sum.add(try ch.io.denominator(&tuple).inv());
        };
    }
    return sum;
}
fn append(out: []engine.pcs.ColumnEvaluation, data: []const core.fields.m31.M31, log: u32) void {
    const n = @as(usize, 1) << @intCast(log);
    for (out, 0..) |*c, i| c.* = .{ .log_size = log, .values = data[i * n ..][0..n] };
}
const Fixture = struct {
    trace: D.trace.Trace,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    fn init(a: std.mem.Allocator, inputs: []const K.trace.State, first: u32, log: u32) !Fixture {
        var trace = try D.trace.Trace.init(a, inputs, first, log);
        errdefer trace.deinit();
        const counts = try K.interaction.Counts.fromTrace(&trace.base);
        var chi = try K.tables.Trace.init(a, .chi, &counts.chi);
        errdefer chi.deinit();
        return .{ .trace = trace, .chi = chi, .xor5 = try K.tables.Trace.init(a, .xor5, &counts.xor5) };
    }
    fn deinit(self: *Fixture) void {
        self.trace.deinit();
        self.chi.deinit();
        self.xor5.deinit();
    }
    fn columns(self: *const Fixture, a: std.mem.Allocator, tree: usize) ![]engine.pcs.ColumnEvaluation {
        const widths = [_]usize{ L.FIXED, L.MAIN, L.INTERACTION };
        const table = [_]usize{ 7, 1, 4 };
        const out = try a.alloc(engine.pcs.ColumnEvaluation, widths[tree] + 2 * table[tree]);
        append(out[0..widths[tree]], switch (tree) {
            0 => self.trace.base.fixed,
            1 => self.trace.main,
            2 => self.trace.interaction,
            else => unreachable,
        }, self.trace.base.log_size);
        append(out[widths[tree]..][0..table[tree]], switch (tree) {
            0 => self.chi.fixed,
            1 => self.chi.main,
            2 => self.chi.interaction,
            else => unreachable,
        }, 13);
        append(out[widths[tree] + table[tree] ..], switch (tree) {
            0 => self.xor5.fixed,
            1 => self.xor5.main,
            2 => self.xor5.interaction,
            else => unreachable,
        }, 10);
        return out;
    }
};
fn components(log: u32, count: u32, first: u32, ch: K.equations.Challenges, claims: Claims) [3]D.component.Component {
    return .{
        .{ .kind = .permutation, .log_size = log, .calls = count, .first_call_id = first, .challenges = ch, .claim = claims[0] },
        .{ .kind = .chi, .log_size = 13, .challenges = ch, .claim = claims[1], .offsets = .{ .fixed = L.FIXED, .main = L.MAIN, .interaction = L.INTERACTION } },
        .{ .kind = .xor5, .log_size = 10, .challenges = ch, .claim = claims[2], .offsets = .{ .fixed = L.FIXED + 7, .main = L.MAIN + 1, .interaction = L.INTERACTION + 4 } },
    };
}
pub fn produce(a: std.mem.Allocator, inputs: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig) !Encoded {
    return produceInternal(a, inputs, inputs, first, log, cfg, false, false);
}
fn produceInternal(a: std.mem.Allocator, inputs: []const K.trace.State, witness_inputs: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig, suppress: bool, allow_unclosed: bool) !Encoded {
    if (inputs.len != witness_inputs.len) return error.InvalidPair2nFixture;
    var fixture = try Fixture.init(a, witness_inputs, first, log);
    defer fixture.deinit();
    var scheme = try Scheme.init(a, cfg);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(5);
    var channel = core.channel.blake2s.Blake2sChannel{};
    try start(&channel, inputs, first, log, cfg);
    const fixed = try fixture.columns(a, 0);
    defer a.free(fixed);
    try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
    if (suppress) fixture.trace.main[L.ROUND_ENABLE * fixture.trace.base.size() + @import("stwo_riscv_frontend").rv64_air.witness.physical(2, log)] = core.fields.m31.M31.zero();
    const main = try fixture.columns(a, 1);
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    fixture.trace.releaseMain();
    try fixture.chi.releaseMain();
    try fixture.xor5.releaseMain();
    const ch = K.equations.Challenges.draw(&channel);
    const claims = Claims{ try D.interaction.generate(&fixture.trace, ch), try fixture.chi.generateInteraction(ch), try fixture.xor5.generateInteraction(ch) };
    if (!allow_unclosed and !claims[0].add(claims[1]).add(claims[2]).eql(try expectedIo(inputs, first, ch))) return error.UnclosedPair2nPublicIo;
    channel.mixFelts(&claims);
    const inter = try fixture.columns(a, 2);
    defer a.free(inter);
    try scheme.commitBorrowedStreaming(a, inter, 8, &channel);
    var cc = components(log, @intCast(inputs.len), first, ch, claims);
    const handles = [_]engine.air.component_prover.ComponentProver{ cc[0].asProverComponent(), cc[1].asProverComponent(), cc[2].asProverComponent() };
    owns = false;
    var proof = try engine.prove.prove(B, H, MC, a, &handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try wire.encodeProofBytesBinary(a, proof), .claims = claims };
}
fn fillLogs(out: []u32, first_count: usize, log: u32, table_width: usize) void {
    @memset(out[0..first_count], log);
    @memset(out[first_count..][0..table_width], 13);
    @memset(out[first_count + table_width ..], 10);
}
pub fn verify(a: std.mem.Allocator, inputs: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig, encoded: Encoded) !void {
    return verifyInternal(a, inputs, first, log, cfg, encoded, true);
}
fn verifyInternal(a: std.mem.Allocator, inputs: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig, encoded: Encoded, enforce_io: bool) !void {
    if (log > 18) return error.Pair2nFixtureGeometryLimit;
    try K.layout.validateGeometry(inputs.len, first, log);
    for (encoded.claims) |q| for (q.toM31Array()) |m| {
        if (m.v >= core.fields.m31.Modulus) return error.NoncanonicalPair2nClaim;
    };
    if (encoded.bytes.len > 64 << 20) return error.Pair2nProofLimit;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const pcs = &proof.commitment_scheme_proof;
    if (!std.meta.eql(pcs.config, cfg) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.InvalidPair2nSuite;
    const fixed = try K.trace.fixedColumnsForLog(a, log);
    defer a.free(fixed);
    const zeros_chi: [8192]u64 = @splat(0);
    const zeros_xor: [1024]u64 = @splat(0);
    var chi = try K.tables.Trace.init(a, .chi, &zeros_chi);
    defer chi.deinit();
    var xor5 = try K.tables.Trace.init(a, .xor5, &zeros_xor);
    defer xor5.deinit();
    var fixed_columns: [L.FIXED + 14]engine.pcs.ColumnEvaluation = undefined;
    append(fixed_columns[0..L.FIXED], fixed, log);
    append(fixed_columns[L.FIXED..][0..7], chi.fixed, 13);
    append(fixed_columns[L.FIXED + 7 ..], xor5.fixed, 10);
    var fixed_scheme = try Scheme.init(a, cfg);
    defer fixed_scheme.deinit(a);
    fixed_scheme.setCompactPolynomialStorage(5);
    var scratch_channel = core.channel.blake2s.Blake2sChannel{};
    try fixed_scheme.commitBorrowedStreaming(a, &fixed_columns, 8, &scratch_channel);
    if (!std.mem.eql(u8, &fixed_scheme.trees.items[0].root(), &pcs.commitments.items[0])) return error.InvalidPair2nFixedRoot;
    var verifier = try Verifier.init(a, cfg);
    defer verifier.deinit(a);
    var replay = core.channel.blake2s.Blake2sChannel{};
    try start(&replay, inputs, first, log, cfg);
    const logs = try a.alloc(u32, L.INTERACTION + 8);
    defer a.free(logs);
    fillLogs(logs[0 .. L.FIXED + 14], L.FIXED, log, 7);
    try verifier.commit(a, pcs.commitments.items[0], logs[0 .. L.FIXED + 14], &replay);
    fillLogs(logs[0 .. L.MAIN + 2], L.MAIN, log, 1);
    try verifier.commit(a, pcs.commitments.items[1], logs[0 .. L.MAIN + 2], &replay);
    const ch = K.equations.Challenges.draw(&replay);
    if (enforce_io and !encoded.claims[0].add(encoded.claims[1]).add(encoded.claims[2]).eql(try expectedIo(inputs, first, ch))) return error.UnclosedPair2nPublicIo;
    replay.mixFelts(&encoded.claims);
    fillLogs(logs[0 .. L.INTERACTION + 8], L.INTERACTION, log, 4);
    try verifier.commit(a, pcs.commitments.items[2], logs[0 .. L.INTERACTION + 8], &replay);
    var cc = components(log, @intCast(inputs.len), first, ch, encoded.claims);
    const handles = [_]core.air.components.Component{ cc[0].asVerifierComponent(), cc[1].asVerifierComponent(), cc[2].asVerifierComponent() };
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &replay, &verifier, proof);
}

pub const testing = if (@import("builtin").is_test) struct {
    pub fn wrongWitness(a: std.mem.Allocator, expected: []const K.trace.State, witness: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig) !Encoded {
        return produceInternal(a, expected, witness, first, log, cfg, false, true);
    }
    pub fn suppressEnable(a: std.mem.Allocator, inputs: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig) !Encoded {
        return produceInternal(a, inputs, inputs, first, log, cfg, true, false);
    }
    pub fn verifyPhysical(a: std.mem.Allocator, inputs: []const K.trace.State, first: u32, log: u32, cfg: core.pcs.PcsConfig, encoded: Encoded) !void {
        return verifyInternal(a, inputs, first, log, cfg, encoded, false);
    }
} else void;
