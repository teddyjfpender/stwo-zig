//! Experimental CLOSED finite-image LS operation proof, not a CPU verifier.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const R = rv.memory.closed_ram;
const X = rv.memory.load_store_v1;
const T = X.types;
const F = @import("rv64_load_store_fixture.zig");
pub const public = @import("rv64_load_store_public.zig");
pub const Data = @import("rv64_load_store_data.zig");
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
const Q = T.Q;
const M = T.M;
pub const CONFIG = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
pub const Encoded = struct {
    bytes: []u8,
    claims: [8]T.Claims,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};
pub const Attack = enum { none, wrong_store_b, wrong_store_b_high, preserved_byte, wrong_signed_load, misaligned, bad_add_carry, effective_alias, quotient_alias, wrong_selection, wrong_parity, readonly_write, orphan_write, future_before, fork, inactive, owner_weight, range_count, selection_count, selection_weight_cancel };
fn mix(channel: *Channel, expected: public.Expected) !void {
    CONFIG.mixInto(channel);
    channel.mixU32s(&.{ 0x4c53434c, 1, 8, 6, 7, 5, 5, 6, 16, 8, 16 });
    for ([_][32]u8{ T.identity(), try expected.digest() }) |digest| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
        channel.mixU32s(&words);
    }
}
pub fn draw(channel: *Channel) T.Challenges {
    channel.mixU32s(&.{ 0x4c535241, 1, 14 });
    var ch: T.Challenges = undefined;
    ch.ram.offset = channel.drawSecureFelt();
    for (&ch.ram.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x4c534f57, 1, 21 });
    ch.owner.offset = channel.drawSecureFelt();
    for (&ch.owner.coefficients) |*v| v.* = channel.drawSecureFelt();
    channel.mixU32s(&.{ 0x55313652, 1 });
    ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x55303852, 1 });
    ch.range8 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    channel.mixU32s(&.{ 0x4c53534c, 1, 5, 16 });
    ch.selection.offset = channel.drawSecureFelt();
    for (&ch.selection.coefficients) |*v| v.* = channel.drawSecureFelt();
    return ch;
}
fn mixClaims(channel: *Channel, claims: [8]T.Claims) void {
    for (claims) |claim| channel.mixFelts(&claim.values());
}
fn baseChallenges(ch: T.Challenges) R.types.Challenges {
    return .{ .ram = ch.ram, .owner = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) }, .range16 = ch.range16, .range8 = ch.range8 };
}
fn baseClaims(c: T.Claims) R.types.Claims {
    return .{ .ram = c.ram, .owner = c.owner, .range16 = c.range16, .range8 = c.range8 };
}
pub const LOGS = [_]u32{ 6, 7, 5, 5, 6, 16, 8, 16 };
fn rosterWidths() [8][3]usize {
    return .{ X.layout.widths(.ls), X.layout.widths(.ls), R.layout.widths(.initial), R.layout.widths(.terminal), X.layout.widths(.owner), R.layout.widths(.range16), R.layout.widths(.range8), X.layout.widths(.selection) };
}
const Components = struct {
    ls: [2]X.component.Component,
    boundary: [2]R.component.Component,
    owner: X.component.Component,
    range: [2]R.component.Component,
    selection: X.component.Component,
    fn init(f: *const F.Fixture, ch: T.Challenges, claims: [8]T.Claims) Components {
        var offsets: [8][3]usize = undefined;
        var at: [3]usize = @splat(0);
        const widths = rosterWidths();
        for (&offsets, widths) |*offset, width| {
            offset.* = at;
            for (&at, width) |*v, amount| v.* += amount;
        }
        var result: Components = undefined;
        for (&result.ls, &f.ls, 0..) |*component, *trace, n| component.* = .{ .kind = .ls, .log_size = trace.log_size, .rows = trace.rows, .offsets = offsets[n], .claims = claims[n], .challenges = ch };
        for (&result.boundary, &f.boundary, 0..) |*component, *trace, n| component.* = .{ .kind = trace.kind, .log_size = trace.log_size, .rows = trace.rows, .offsets = offsets[2 + n], .public_rows = if (trace.public_rows) |*p| p else null, .claims = baseClaims(claims[2 + n]), .challenges = baseChallenges(ch) };
        result.owner = .{ .kind = .owner, .log_size = 6, .rows = f.owner.rows, .offsets = offsets[4], .public_rows = if (f.owner.public_rows) |*p| p else null, .claims = claims[4], .challenges = ch };
        for (&result.range, &f.range, 0..) |*component, *trace, n| component.* = .{ .kind = trace.kind, .log_size = trace.log_size, .rows = 0, .offsets = offsets[5 + n], .claims = baseClaims(claims[5 + n]), .challenges = baseChallenges(ch) };
        result.selection = .{ .kind = .selection, .log_size = 16, .rows = 0, .offsets = offsets[7], .claims = claims[7], .challenges = ch };
        return result;
    }
    fn provers(self: *const Components) [8]engine.air.component_prover.ComponentProver {
        return .{ self.ls[0].asProverComponent(), self.ls[1].asProverComponent(), self.boundary[0].asProverComponent(), self.boundary[1].asProverComponent(), self.owner.asProverComponent(), self.range[0].asProverComponent(), self.range[1].asProverComponent(), self.selection.asProverComponent() };
    }
    fn verifiers(self: *const Components) [8]core.air.components.Component {
        return .{ self.ls[0].asVerifierComponent(), self.ls[1].asVerifierComponent(), self.boundary[0].asVerifierComponent(), self.boundary[1].asVerifierComponent(), self.owner.asVerifierComponent(), self.range[0].asVerifierComponent(), self.range[1].asVerifierComponent(), self.selection.asVerifierComponent() };
    }
};
fn validateClaims(claims: [8]T.Claims) !void {
    var sums: [5]Q = @splat(Q.zero());
    for (claims, 0..) |claim, role| for (claim.values(), &sums, 0..) |value, *sum, relation| {
        for (value.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalLoadStoreClaim;
        const used = switch (role) {
            0, 1 => true,
            2, 3 => relation == 0 or relation == 2 or relation == 3,
            4 => relation == 1,
            5 => relation == 2,
            6 => relation == 3,
            7 => relation == 4,
            else => unreachable,
        };
        if (!used and !value.isZero()) return error.UnusedLoadStoreClaim;
        sum.* = sum.add(value);
    };
    for (sums) |sum| if (!sum.isZero()) return error.UnclosedLoadStoreClaims;
}
pub fn mutate(f: *F.Fixture, attack: Attack) !void {
    const L = X.layout;
    switch (attack) {
        .none => {},
        .wrong_store_b_high => add(&f.ls[1], 5, L.b + 3, M.one()),
        .wrong_store_b => set(&f.ls[1], 5, L.b, 0xabcd),
        .preserved_byte => add(&f.ls[1], 5, 21, M.one()),
        .wrong_signed_load => set(&f.ls[0], 0, L.c + 3, 0),
        .misaligned => {
            set(&f.ls[0], 16, L.offsets, 0);
            set(&f.ls[0], 16, L.offsets + 1, 1);
        },
        .bad_add_carry => set(&f.ls[1], 20, L.address_carries + 3, 0),
        .effective_alias => add(&f.ls[0], 0, L.effective + 3, M.one()),
        .quotient_alias => set(&f.ls[0], 0, L.quotient, (try M.fromCanonical(8).inv()).v),
        .wrong_selection => add(&f.ls[0], 0, L.selected_byte, M.one()),
        .wrong_parity => {
            set(&f.ls[0], 1, L.offsets + 1, 0);
            set(&f.ls[0], 1, L.offsets, 1);
        },
        .readonly_write => set(&f.ls[0], 0, 1, 1),
        .orphan_write => set(&f.ls[1], 25, 0, 1),
        .future_before => set(&f.ls[0], 0, 8, 1),
        .fork => {
            set(&f.ls[0], 1, 10, 0);
            set(&f.ls[0], 1, 25, 7);
        },
        .inactive => set(&f.ls[0], 24, L.b, 1),
        .owner_weight => {
            const n = f.owner.size();
            f.owner.main[21 * n + R.trace.physical(0, 6)] = M.fromCanonical(2);
        },
        .range_count, .selection_count, .selection_weight_cancel => {},
    }
    try f.recount();
    if (attack == .range_count) f.range[0].main[0] = f.range[0].main[0].add(M.one());
    if (attack == .selection_count) f.selection.main[0] = f.selection.main[0].add(M.one());
    if (attack == .selection_weight_cancel) {
        f.selection.main[0] = f.selection.main[0].add(M.one());
        const n = f.selection.size();
        f.selection.main[n] = f.selection.main[n].sub(M.one());
    }
}
fn set(trace: *X.trace.Trace, row: usize, c: usize, value: u32) void {
    trace.main[c * trace.size() + R.trace.physical(row, trace.log_size)] = M.fromCanonical(value);
}
fn add(trace: *X.trace.Trace, row: usize, c: usize, value: M) void {
    const at = c * trace.size() + R.trace.physical(row, trace.log_size);
    trace.main[at] = trace.main[at].add(value);
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
    if (attack == .none) try validateClaims(claims) else {
        var sums: [5]Q = @splat(Q.zero());
        for (claims) |claim| for (claim.values(), &sums) |v, *sum| {
            sum.* = sum.add(v);
        };
        claims[3].ram = claims[3].ram.sub(sums[0]);
        claims[4].owner = claims[4].owner.sub(sums[1]);
        claims[5].range16 = claims[5].range16.sub(sums[2]);
        claims[6].range8 = claims[6].range8.sub(sums[3]);
        claims[7].selection = claims[7].selection.sub(sums[4]);
    }
    try validateClaims(claims);
    mixClaims(&channel, claims);
    const columns = try f.columns(2);
    defer a.free(columns);
    try scheme.commit(a, columns, &channel);
    const components = Components.init(&f, ch, claims);
    const handles = components.provers();
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
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != 4) return error.InvalidLoadStoreCommitments;
    var f = try F.Fixture.initGeometry(a, expected);
    defer f.deinit();
    var scheme = try Scheme.init(a, CONFIG);
    defer scheme.deinit(a);
    var scratch = Channel{};
    const fixed = try f.columns(0);
    defer a.free(fixed);
    try scheme.commit(a, fixed, &scratch);
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (!std.mem.eql(u8, &roots.items[0], &commitments[0])) return error.InvalidLoadStoreFixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel{};
    try mix(&channel, expected);
    var logs: [3][]u32 = undefined;
    var built: usize = 0;
    defer for (logs[0..built]) |owned| a.free(owned);
    for (0..3) |tree| {
        var count: usize = 0;
        for (rosterWidths()) |widths| count += widths[tree];
        logs[tree] = try a.alloc(u32, count);
        built += 1;
        var cursor: usize = 0;
        for (rosterWidths(), LOGS) |widths, log| {
            @memset(logs[tree][cursor..][0..widths[tree]], log);
            cursor += widths[tree];
        }
    }
    for (0..2) |tree| try verifier.commit(a, commitments[tree], logs[tree], &channel);
    const ch = draw(&channel);
    mixClaims(&channel, encoded.claims);
    try verifier.commit(a, commitments[2], logs[2], &channel);
    const components = Components.init(&f, ch, encoded.claims);
    const handles = components.verifiers();
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &channel, &verifier, proof);
}
