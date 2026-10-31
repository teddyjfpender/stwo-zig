//! Experimental CLOSED seven-component proof of independently expected RAM
//! operations, complete finite image/policy and terminal values. Not a CPU proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const R = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram;
const T = R.types;
const L = R.layout;
const F = @import("rv64_closed_ram_fixture.zig");
pub const public = @import("rv64_closed_ram_public.zig");
pub const Attack = enum { none, future_before, duplicate_init, orphan_write, readonly_write, bad_image, noncanonical, padding, owner_weight, owner_origin, fork, range_count };
const Q = T.Q;
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
pub const CONFIG = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
pub const Encoded = struct {
    bytes: []u8,
    claims: [7]T.Claims,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};
fn mix(channel: *Channel, expected: public.Expected) !void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&.{ 0x52414d43, 1, 7, 5, 6, 5, 5, 5, 16, 8 });
    for ([_][32]u8{ T.identity(), try expected.digest() }) |digest| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
        channel.mixU32s(&words);
    }
}
pub fn draw(channel: *Channel) T.Challenges {
    channel.mixU32s(&.{ 0x52414d52, 1, 14 });
    var ch: T.Challenges = undefined;
    ch.ram.offset = channel.drawSecureFelt();
    for (&ch.ram.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x4f574e52, 1, 13 });
    ch.owner.offset = channel.drawSecureFelt();
    for (&ch.owner.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x55313652, 1 });
    ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x55303852, 1 });
    ch.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    return ch;
}
fn mixClaims(channel: *Channel, claims: [7]T.Claims) void {
    for (claims) |claim| channel.mixFelts(&claim.values());
}
fn components(f: *const F.Fixture, ch: T.Challenges, claims: [7]T.Claims) [7]R.component.Component {
    var result: [7]R.component.Component = undefined;
    var offsets: [3]usize = @splat(0);
    for (&f.traces, claims, &result) |*trace, claim, *c| {
        c.* = .{ .kind = trace.kind, .log_size = trace.log_size, .rows = trace.rows, .offsets = offsets, .claims = claim, .challenges = ch, .public_rows = if (trace.public_rows) |*p| p else null };
        for (&offsets, L.widths(trace.kind)) |*offset, width| offset.* += width;
    }
    return result;
}
fn validateClaims(claims: [7]T.Claims) !void {
    var sums: [4]Q = @splat(Q.zero());
    for (claims, 0..) |claim, index| {
        for (claim.values(), &sums, 0..) |value, *sum, relation| {
            for (value.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalClosedRamClaim;
            const used = switch (index) {
                0, 1 => true,
                2, 3 => relation != 1,
                4 => relation == 1,
                5 => relation == 2,
                6 => relation == 3,
                else => unreachable,
            };
            if (!used and !value.isZero()) return error.UnusedClosedRamClaim;
            sum.* = sum.add(value);
        }
    }
    for (sums) |sum| if (!sum.isZero()) return error.UnclosedRamClaims;
}
pub fn mutate(f: *F.Fixture, attack: Attack) !void {
    switch (attack) {
        .none => {},
        .future_before => set(&f.traces[0], 0, 8, 2),
        .duplicate_init => {
            for (0..4) |i| set(&f.traces[2], 1, 1 + i, f.traces[2].main[(1 + i) * 32 + R.trace.physical(0, 5)].v);
        },
        .orphan_write => set(&f.traces[1], 5, 0, 1),
        .readonly_write => set(&f.traces[0], 2, 1, 1),
        .bad_image => set(&f.traces[2], 0, 5, 6),
        .noncanonical => set(&f.traces[0], 0, 11, 256),
        .padding => set(&f.traces[0], 4, 14, 1),
        .owner_weight => set(&f.traces[4], 0, 13, 2),
        .owner_origin => set(&f.traces[0], 0, 3, 0),
        .fork => {
            // Locally valid second consumer of A's INIT: skip the first read's
            // timestamp. Only the joint physical RAM ledger rules this out.
            set(&f.traces[0], 1, 10, 0);
            set(&f.traces[0], 1, 25, 7);
        },
        .range_count => {},
    }
    try f.recount();
    if (attack == .range_count) f.traces[5].main[0] = f.traces[5].main[0].add(M.one());
}
fn set(trace: *R.trace.Trace, row: usize, c: usize, value: u32) void {
    trace.main[c * trace.size() + R.trace.physical(row, trace.log_size)] = M.fromCanonical(value);
}
pub fn produce(a: std.mem.Allocator, expected: public.Expected, attack: Attack) !Encoded {
    var f = try F.Fixture.init(a, expected);
    defer f.deinit();
    try mutate(&f, attack);
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    try mix(&channel, expected);
    for ([_]u2{ 0, 1 }) |tree| {
        const columns = try f.columns(tree);
        defer a.free(columns);
        try scheme.commit(a, columns, &channel);
    }
    const ch = draw(&channel);
    var claims = try f.generate(ch);
    // Adversarial prover attempts still present a formally closed ledger. Any
    // changed claim must fail its physical prefix constraint in the actual proof.
    var sums: [4]Q = @splat(Q.zero());
    for (claims) |claim| for (claim.values(), &sums) |v, *sum| {
        sum.* = sum.add(v);
    };
    if (attack == .none) try validateClaims(claims) else {
        claims[3].ram = claims[3].ram.sub(sums[0]);
        claims[4].owner = claims[4].owner.sub(sums[1]);
        claims[5].range16 = claims[5].range16.sub(sums[2]);
        claims[6].range8 = claims[6].range8.sub(sums[3]);
    }
    try validateClaims(claims);
    mixClaims(&channel, claims);
    const inter = try f.columns(2);
    defer a.free(inter);
    try scheme.commit(a, inter, &channel);
    const c = components(&f, ch, claims);
    var handles: [7]engine.air.component_prover.ComponentProver = undefined;
    for (&c, &handles) |*component, *handle| handle.* = component.asProverComponent();
    owns = false;
    var proof = try engine.prove.prove(Backend, H, MC, a, &handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof), .claims = claims };
}
pub fn verify(a: std.mem.Allocator, expected: public.Expected, encoded: Encoded) !void {
    try expected.validate();
    try validateClaims(encoded.claims);
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    if (proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidClosedRamCommitments;
    var f = try F.Fixture.init(a, expected);
    defer f.deinit();
    var fixed_scheme = try Scheme.init(a, CONFIG);
    defer fixed_scheme.deinit(a);
    var scratch = Channel{};
    const fixed = try f.columns(0);
    defer a.free(fixed);
    try fixed_scheme.commit(a, fixed, &scratch);
    var roots = try fixed_scheme.roots(a);
    defer roots.deinit(a);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (!std.mem.eql(u8, &roots.items[0], &commitments[0])) return error.InvalidClosedRamFixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel{};
    try mix(&channel, expected);
    var all_logs: [3][]u32 = undefined;
    var logs_built: usize = 0;
    defer for (all_logs[0..logs_built]) |logs| a.free(logs);
    for (0..3) |tree| {
        var count: usize = 0;
        for (f.traces) |trace| count += L.widths(trace.kind)[tree];
        const logs = try a.alloc(u32, count);
        all_logs[tree] = logs;
        logs_built += 1;
        var cursor: usize = 0;
        for (f.traces) |trace| {
            const width = L.widths(trace.kind)[tree];
            @memset(logs[cursor..][0..width], trace.log_size);
            cursor += width;
        }
    }
    for (0..2) |tree| try verifier.commit(a, commitments[tree], all_logs[tree], &channel);
    const ch = draw(&channel);
    mixClaims(&channel, encoded.claims);
    try verifier.commit(a, commitments[2], all_logs[2], &channel);
    const c = components(&f, ch, encoded.claims);
    var handles: [7]core.air.components.Component = undefined;
    for (&c, &handles) |*component, *handle| handle.* = component.asVerifierComponent();
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &channel, &verifier, proof);
}
