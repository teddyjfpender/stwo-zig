//! Known-public FUNCTION31 -> weighted BINARY3 -> canonical AND, one PCS.
//! Diagnostic only: no CPU/register/RAM or distributed acceptance claim.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = rv.word16_v1.binary_source;
const P = rv.word16_v1.binary_lookup;
const C = rv.word16_v1.binary_component;
const T = rv.providers.tables;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Channel = core.channel.blake2s.Blake2sChannel;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Backend = @import("stwo_cpu_backend").CpuBackend;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
pub const CONFIG = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
const N = 32;
pub const WEIGHTS = [3]u32{ 7, 11, 13 };
pub const FACTS = [3]S.Fact{
    .{ .op = .and_, .a = 0x0123456789abcdef, .b = 0xfedcba9876543210, .c = 0x0123456789abcdef & 0xfedcba9876543210 },
    .{ .op = .or_, .a = 0x7fff8000ffff1234, .b = 0xfedcba9876543210, .c = 0x7fff8000ffff1234 | 0xfedcba9876543210 },
    .{ .op = .xor, .a = 0x8000000000000000, .b = 0xffff, .c = 0x800000000000ffff },
};
pub fn expectedRoster() C.ExpectedRoster {
    var roster: C.ExpectedRoster = @splat(@splat(M.zero()));
    var cursor: usize = 0;
    for (FACTS, WEIGHTS) |f, weight| for (0..weight) |_| {
        roster[cursor][0] = M.fromCanonical(rv.word16_v1.operations.busIdFor(.binary, @intFromEnum(f.op)));
        for ([_]u64{ f.a, f.b, f.c }, 0..) |word, group| for (0..4) |i| {
            roster[cursor][1 + 4 * group + i] = M.fromCanonical(@as(u16, @truncate(word >> @as(u6, @intCast(16 * i)))));
        };
        roster[cursor][13] = M.one();
        cursor += 1;
    };
    std.debug.assert(cursor == 31);
    return roster;
}
fn store(data: []M, row: usize, col: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, i| data[(col + i) * N + row] = v;
}
const Fixture = struct {
    allocator: std.mem.Allocator,
    source: S.Source,
    borrowed: []M,
    roster: C.ExpectedRoster,
    known_fixed: []M,
    known_main: []M,
    known_inter: []M = &.{},
    table: T.Setup,
    request: T.Request,
    fn init(a: std.mem.Allocator, borrowed_mode: bool) !Fixture {
        _ = try rv.word16_v1.function_bus.admitPositiveMass(&.{31});
        _ = try rv.word16_v1.function_bus.admitPositiveMass(&.{8 * N});
        const borrowed = try a.alloc(M, if (borrowed_mode) S.MAIN * N else 0);
        errdefer a.free(borrowed);
        var source = if (borrowed_mode) try S.Source.initWeightedWithMainBuffers(a, &FACTS, &WEIGHTS, 5, .{ .main = borrowed }) else try S.Source.initWeighted(a, &FACTS, &WEIGHTS, 5);
        errdefer source.deinit();
        const roster = expectedRoster();
        const known_fixed = try C.expectedMainFixed(a);
        errdefer a.free(known_fixed);
        const known_main = try C.expectedMainValues(a, &roster);
        errdefer a.free(known_main);
        var table = try T.Setup.init(a, .byte_and);
        errdefer table.deinit();
        return .{ .allocator = a, .source = source, .borrowed = borrowed, .roster = roster, .known_fixed = known_fixed, .known_main = known_main, .table = table, .request = try T.Request.init(a, &table, source.and_counts) };
    }
    fn deinit(self: *Fixture) void {
        self.source.deinit();
        self.allocator.free(self.borrowed);
        self.allocator.free(self.known_fixed);
        self.allocator.free(self.known_main);
        self.allocator.free(self.known_inter);
        self.request.deinit();
        self.table.deinit();
    }
    fn columns(self: *const Fixture, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const small = switch (tree) {
            0 => [_][]const M{ self.source.fixed, self.known_fixed },
            1 => [_][]const M{ self.source.main, self.known_main },
            2 => [_][]const M{ self.source.interaction, self.known_inter },
            else => return error.InvalidWeightedBinaryTree,
        };
        const large = switch (tree) {
            0 => self.table.fixed,
            1 => self.request.main,
            2 => self.request.interaction,
            else => unreachable,
        };
        const columns_ = try self.allocator.alloc(engine.pcs.ColumnEvaluation, small[0].len / N + small[1].len / N + large.len / 65536);
        var at: usize = 0;
        for (small) |values| for (0..values.len / N) |i| {
            columns_[at] = .{ .log_size = 5, .values = values[i * N ..][0..N] };
            at += 1;
        };
        for (0..large.len / 65536) |i| {
            columns_[at] = .{ .log_size = 16, .values = large[i * 65536 ..][0..65536] };
            at += 1;
        }
        return columns_;
    }
    fn generate(self: *Fixture, ch: P.Challenges) ![4]Q {
        const source = try self.source.generate(ch);
        const table = try self.request.generateInteraction(ch.and_);
        const output = try self.allocator.alloc(M, 8 * N);
        errdefer self.allocator.free(output);
        var sum = Q.zero();
        for (self.roster, 0..) |row, logical| {
            var tuple: [13]Q = undefined;
            for (&tuple, 0..) |*v, c| v.* = Q.fromBase(row[c]);
            const inverse = try ch.function.denominatorFor(Q, tuple).inv();
            const position = rv.witness.physical(logical, 5);
            store(output, position, 0, inverse);
            sum = sum.add(inverse.mulM31(row[13]));
            store(output, position, 4, sum);
        }
        for (sum.toM31Array(), 0..) |v, c| for (0..N) |position| {
            output[(4 + c) * N + position] = output[(4 + c) * N + position].sub(v);
        };
        self.known_inter = output;
        if (!source.function.add(sum).isZero() or !source.and_.add(table).isZero()) return error.UnclosedWeightedBinaryClaims;
        return .{ source.and_, source.function, sum, table };
    }
};
fn mix(channel: *Channel, roster: *const C.ExpectedRoster) !void {
    CONFIG.mixInto(channel);
    // Version, ordered role IDs/logs/widths and all positive relation masses.
    channel.mixU32s(&.{ 0x57424d55, 1, 1, 5, 2, S.MAIN, S.INTERACTION, 2, 5, 34, 14, 8, 3, 16, 5, 1, 8, 13, 31, 256 });
    const digest = try C.expectedRosterDigest(roster);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
fn draw(channel: *Channel) P.Challenges {
    channel.mixU32s(&.{ 0x414e4438, 3 });
    const and_ = T.Challenges.draw(channel);
    channel.mixU32s(&.{ 0x46554e31, 13 });
    var function = P.FunctionChallenges{ .offset = channel.drawSecureFelt(), .coefficients = undefined };
    for (&function.coefficients) |*v| v.* = channel.drawSecureFelt();
    return .{ .and_ = and_, .function = function };
}
fn components(ch: P.Challenges, claims: [4]Q, roster: *const C.ExpectedRoster) [3]C.Component {
    return .{
        .{ .kind = .binary, .log_size = 5, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = .{ .and_ = claims[0], .function = claims[1] } },
        .{ .kind = .expected_main, .log_size = 5, .offsets = .{ 2, S.MAIN, S.INTERACTION }, .challenges = ch, .claims = .{ .and_ = Q.zero(), .function = claims[2] }, .expected_roster = roster },
        .{ .kind = .and_table, .log_size = 16, .offsets = .{ 36, S.MAIN + 14, S.INTERACTION + 8 }, .challenges = ch, .claims = .{ .and_ = claims[3], .function = Q.zero() } },
    };
}
pub const Encoded = struct {
    bytes: []u8,
    claims: [4]Q,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        self.* = undefined;
    }
};
pub const Attack = enum { none, weight, missing_fact, balanced_and_debt };
pub fn produce(a: std.mem.Allocator, borrowed: bool, attack: Attack) !Encoded {
    var f = try Fixture.init(a, borrowed);
    defer f.deinit();
    const position = rv.witness.physical(0, 5);
    if (attack == .weight) f.source.main[(S.MAIN - 1) * N + position] = M.fromCanonical(6);
    if (attack == .missing_fact) {
        const padding = rv.witness.physical(3, 5);
        for (0..S.MAIN) |c| f.source.main[c * N + position] = f.source.main[c * N + padding];
    }
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    try mix(&channel, &f.roster);
    for ([_]u2{ 0, 1 }) |tree| {
        const columns_ = try f.columns(tree);
        defer a.free(columns_);
        try scheme.commitBorrowedStreaming(a, columns_, 8, &channel);
    }
    f.source.releaseMain();
    @memset(f.borrowed, M.fromCanonical(23));
    const ch = draw(&channel);
    var claims = try f.generate(ch);
    if (attack == .balanced_and_debt) {
        claims[0] = claims[0].add(Q.one());
        claims[3] = claims[3].sub(Q.one());
    }
    channel.mixFelts(&claims);
    const columns_ = try f.columns(2);
    defer a.free(columns_);
    try scheme.commitBorrowedStreaming(a, columns_, 8, &channel);
    const c = components(ch, claims, &f.roster);
    const handles = [_]engine.air.component_prover.ComponentProver{ c[0].asProverComponent(), c[1].asProverComponent(), c[2].asProverComponent() };
    owns = false;
    var proof = try engine.prove.prove(Backend, H, MC, a, &handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof), .claims = claims };
}
pub fn verify(a: std.mem.Allocator, encoded: Encoded) !void {
    for (encoded.claims) |claim| for (claim.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NonCanonicalWord16Claim;
    if (!encoded.claims[0].add(encoded.claims[3]).isZero() or !encoded.claims[1].add(encoded.claims[2]).isZero()) return error.UnclosedWeightedBinaryClaims;
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    if (proof.commitment_scheme_proof.commitments.items.len != 4) return error.InvalidWeightedBinaryProofShape;
    var f = try Fixture.init(a, false);
    defer f.deinit();
    var expected = try Scheme.init(a, CONFIG);
    defer expected.deinit(a);
    var scratch = Channel{};
    const fixed = try f.columns(0);
    defer a.free(fixed);
    try expected.commitBorrowedStreaming(a, fixed, 8, &scratch);
    var roots = try expected.roots(a);
    defer roots.deinit(a);
    if (!std.mem.eql(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0])) return error.UnexpectedWord16FixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel{};
    try mix(&channel, &f.roster);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    var ch: P.Challenges = undefined;
    for ([_]u2{ 0, 1, 2 }) |tree| {
        if (tree == 2) {
            ch = draw(&channel);
            channel.mixFelts(&encoded.claims);
        }
        var logs: []u32 = undefined;
        if (tree != 2) {
            const columns_ = try f.columns(tree);
            defer a.free(columns_);
            logs = try a.alloc(u32, columns_.len);
            for (columns_, logs) |column, *log| log.* = column.log_size;
        } else {
            logs = try a.alloc(u32, S.INTERACTION + 16);
            @memset(logs[0 .. S.INTERACTION + 8], 5);
            @memset(logs[S.INTERACTION + 8 ..], 16);
        }
        defer a.free(logs);
        try verifier.commit(a, commitments[tree], logs, &channel);
    }
    const c = components(ch, encoded.claims, &f.roster);
    const handles = [_]core.air.components.Component{ c[0].asVerifierComponent(), c[1].asVerifierComponent(), c[2].asVerifierComponent() };
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &channel, &verifier, proof);
}
