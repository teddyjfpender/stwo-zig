//! Diagnostic expected IO -> Word16 BINARY -> canonical AND, one PCS/FRI.
//! This fixture proves no RV64 control flow, register or RAM transitions.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const B = rv.word16_v1.binary;
const P = rv.word16_v1.binary_lookup;
const C = rv.word16_v1.binary_component;
const T = rv.providers.tables;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const N = 32;
fn phys(i: usize) usize {
    return rv.witness.physical(i, 5);
}
fn store(data: []M, row: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, i| data[(start + i) * N + row] = v;
}
fn fact(i: usize) B.RowFor(Q) {
    const ops = [_]rv.word16_v1.operations.Binary{ .and_, .or_, .xor };
    return B.witness(ops[i % 3], 0x7fff8000ffff1234 ^ @as(u64, @intCast(i)), 0xfedcba9876543210 + @as(u64, @intCast(i)));
}
pub const Fixture = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    expected: []M,
    main: []M,
    inter: []M = &.{},
    expected_inter: []M = &.{},
    table: T.Setup,
    request: T.Request,
    pub fn init(allocator: std.mem.Allocator, bad: bool) !Fixture {
        _ = try rv.word16_v1.function_bus.admitPositiveMass(&.{3});
        _ = try rv.word16_v1.function_bus.admitPositiveMass(&.{8 * N});
        const fixed = try allocator.alloc(M, 2 * N);
        errdefer allocator.free(fixed);
        const expected = try allocator.alloc(M, 16 * N);
        errdefer allocator.free(expected);
        const main = try allocator.alloc(M, P.MAIN * N);
        errdefer allocator.free(main);
        @memset(fixed, M.zero());
        @memset(expected, M.zero());
        @memset(main, M.zero());
        fixed[phys(0)] = M.one();
        fixed[N + phys(N - 1)] = M.one();
        expected[14 * N + phys(0)] = M.one();
        expected[15 * N + phys(N - 1)] = M.one();
        const counts = try allocator.alloc(u64, 65536);
        defer allocator.free(counts);
        @memset(counts, 0);
        for (0..N) |i| {
            var row = if (i < 3) fact(i) else B.witness(.and_, 0, 0);
            if (i >= 3) {
                row.active = Q.zero();
                row.selectors[0] = Q.zero();
                row.payload[0] = Q.zero();
            }
            const physical = phys(i);
            if (i < 3) {
                for (row.payload, 0..) |v, j| expected[j * N + physical] = try v.tryIntoM31();
                expected[13 * N + physical] = M.one();
                main[B.LOCAL_MAIN * N + physical] = M.one();
            }
            if (bad and i == 1) row.payload[9] = row.payload[9].add(Q.one());
            const values = P.rowToColumnsFor(Q, row);
            for (values, 0..) |v, j| main[j * N + physical] = try v.tryIntoM31();
            for (0..8) |j| {
                const tuple = B.andTupleFor(Q, &row, j);
                const x = (try tuple[0].tryIntoM31()).v;
                const y = (try tuple[1].tryIntoM31()).v;
                counts[x * 256 + y] += 1;
            }
        }
        var table = try T.Setup.init(allocator, .byte_and);
        errdefer table.deinit();
        return .{ .allocator = allocator, .fixed = fixed, .expected = expected, .main = main, .table = table, .request = try T.Request.init(allocator, &table, counts) };
    }
    pub fn deinit(self: *Fixture) void {
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.expected);
        a.free(self.main);
        a.free(self.inter);
        a.free(self.expected_inter);
        self.request.deinit();
        self.table.deinit();
    }
    fn columns(self: *const Fixture, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const a = self.allocator;
        const small = switch (tree) {
            0 => [_][]const M{ self.fixed, self.expected },
            1 => [_][]const M{ self.main, &.{} },
            2 => [_][]const M{ self.inter, self.expected_inter },
            else => unreachable,
        };
        const large = switch (tree) {
            0 => self.table.fixed,
            1 => self.request.main,
            2 => self.request.interaction,
            else => unreachable,
        };
        const result = try a.alloc(engine.pcs.ColumnEvaluation, small[0].len / N + small[1].len / N + large.len / 65536);
        var index: usize = 0;
        for (small) |storage| for (0..storage.len / N) |i| {
            result[index] = .{ .log_size = 5, .values = storage[i * N ..][0..N] };
            index += 1;
        };
        for (0..large.len / 65536) |i| {
            result[index] = .{ .log_size = 16, .values = large[i * 65536 ..][0..65536] };
            index += 1;
        }
        return result;
    }
    pub fn generate(self: *Fixture, ch: P.Challenges) ![4]Q {
        const a = self.allocator;
        if (self.inter.len != 0 or self.expected_inter.len != 0 or self.request.interaction.len != 0) return error.InvalidBinaryFixturePhase;
        const data = try a.alloc(M, P.INTERACTION * N);
        errdefer a.free(data);
        const expected_data = try a.alloc(M, 8 * N);
        errdefer a.free(expected_data);
        @memset(data, M.zero());
        @memset(expected_data, M.zero());
        var and_sum = Q.zero();
        var function_sum = Q.zero();
        var expected_sum = Q.zero();
        for (0..N) |i| {
            const r = phys(i);
            var source: [P.MAIN]Q = undefined;
            for (&source, 0..) |*v, j| v.* = Q.fromBase(self.main[j * N + r]);
            const row = P.rowFromColumnsFor(Q, &source);
            for (0..4) |batch| {
                const x = B.andTupleFor(Q, &row, 2 * batch);
                const y = B.andTupleFor(Q, &row, 2 * batch + 1);
                const dx = ch.and_.denominator(&x);
                const dy = ch.and_.denominator(&y);
                const inverse = try dx.mul(dy).inv();
                store(data, r, 4 * batch, inverse);
                and_sum = and_sum.add(dx.add(dy).mul(inverse));
            }
            store(data, r, 16, and_sum);
            const inverse = try ch.function.denominatorFor(Q, row.payload).inv();
            store(data, r, 20, inverse);
            function_sum = function_sum.sub(inverse.mul(source[B.LOCAL_MAIN]));
            store(data, r, 24, function_sum);
            var expected_tuple: [13]Q = undefined;
            for (&expected_tuple, 0..) |*v, j| v.* = Q.fromBase(self.expected[j * N + r]);
            const expected_inverse = try ch.function.denominatorFor(Q, expected_tuple).inv();
            store(expected_data, r, 0, expected_inverse);
            expected_sum = expected_sum.add(expected_inverse.mulM31(self.expected[13 * N + r]));
            store(expected_data, r, 4, expected_sum);
        }
        for (0..N) |r| {
            for (and_sum.toM31Array(), 0..) |_, j| data[(16 + j) * N + r] = data[(16 + j) * N + r].sub(and_sum.toM31Array()[j]);
            for (function_sum.toM31Array(), 0..) |_, j| data[(24 + j) * N + r] = data[(24 + j) * N + r].sub(function_sum.toM31Array()[j]);
            for (expected_sum.toM31Array(), 0..) |_, j| expected_data[(4 + j) * N + r] = expected_data[(4 + j) * N + r].sub(expected_sum.toM31Array()[j]);
        }
        const table_claim = try self.request.generateInteraction(ch.and_);
        self.inter = data;
        self.expected_inter = expected_data;
        return .{ and_sum, function_sum, expected_sum, table_claim };
    }
};
const Backend = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(Backend, H, MC);
pub const CONFIG = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
fn mix(channel: *Channel) void {
    CONFIG.mixInto(channel);
    // Version, ordered roles, native logs, payload arity, exact positive masses.
    channel.mixU32s(&.{ 0x57313642, 1, 1, 5, 2, 5, 3, 16, 13, 3, 8 * N, 2 });
}
fn draw(channel: *Channel) P.Challenges {
    channel.mixU32s(&.{ 0x414e4438, 3 });
    const and_ = T.Challenges.draw(channel);
    channel.mixU32s(&.{ 0x42494e31, 13 });
    var function: P.FunctionChallenges = undefined;
    function.offset = channel.drawSecureFelt();
    for (&function.coefficients) |*v| v.* = channel.drawSecureFelt();
    return .{ .and_ = and_, .function = function };
}
fn components(ch: P.Challenges, claims: [4]Q) [3]C.Component {
    return .{
        .{ .kind = .binary, .log_size = 5, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = .{ .and_ = claims[0], .function = claims[1] } },
        .{ .kind = .expected, .log_size = 5, .offsets = .{ 2, P.MAIN, P.INTERACTION }, .challenges = ch, .claims = .{ .and_ = Q.zero(), .function = claims[2] } },
        .{ .kind = .and_table, .log_size = 16, .offsets = .{ 18, P.MAIN, P.INTERACTION + 8 }, .challenges = ch, .claims = .{ .and_ = claims[3], .function = Q.zero() } },
    };
}
pub const Encoded = struct { bytes: []u8, claims: [4]Q };
pub fn produce(a: std.mem.Allocator, bad: bool) !Encoded {
    return produceWithAttack(a, if (bad) .output else .none);
}
pub const Attack = enum { none, output, and_fact, cross_family, packed_alias };
pub fn produceWithAttack(a: std.mem.Allocator, attack: Attack) !Encoded {
    var f = try Fixture.init(a, attack == .output);
    defer f.deinit();
    if (attack == .and_fact or attack == .packed_alias) {
        // Keep ALL local arithmetic and the claimed public output consistent.
        // Only fixed AND membership can reject this false truth-table fact.
        const r = phys(0);
        if (attack == .and_fact) {
            f.main[33 * N + r] = f.main[33 * N + r].add(M.one());
            f.main[9 * N + r] = f.main[9 * N + r].add(M.one());
            f.expected[9 * N + r] = f.expected[9 * N + r].add(M.one());
        } else {
            // Preserve the reconstructed U16 operand modulo M31 while making
            // byte0 negative and byte1 larger. Only separate tuple-coordinate
            // membership proves byte canonicality; a packed sum would alias.
            f.main[17 * N + r] = f.main[17 * N + r].sub(M.fromCanonical(256));
            f.main[18 * N + r] = f.main[18 * N + r].add(M.one());
        }
        var values: [P.MAIN]Q = undefined;
        for (&values, 0..) |*v, c| v.* = Q.fromBase(f.main[c * N + r]);
        const row = P.rowFromColumnsFor(Q, &values);
        var residuals: [B.CONSTRAINTS]Q = undefined;
        var sink = rv.evaluation.Sink{ .values = &residuals };
        B.emitFor(Q, &row, &sink);
        for (residuals) |value| if (!value.isZero()) return error.InvalidForgeryOracle;
    } else if (attack == .cross_family) {
        // Same private inputs/results, but claim an ALU ADD identity (0) for
        // this AND fact (16). Manifest roles alone would not separate them.
        f.main[phys(0)] = M.zero();
        f.expected[phys(0)] = M.zero();
    }
    var scheme = try Scheme.init(a, CONFIG);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    var channel = Channel{};
    mix(&channel);
    for ([_]u2{ 0, 1 }) |tree| {
        const columns = try f.columns(tree);
        defer a.free(columns);
        try scheme.commit(a, columns, &channel);
    }
    const ch = draw(&channel);
    const actual = try f.generate(ch);
    if (attack != .output and !actual[1].add(actual[2]).isZero()) return error.InvalidFunctionClosureOracle;
    const claims = [_]Q{ actual[3].neg(), actual[2].neg(), actual[2], actual[3] };
    channel.mixFelts(&claims);
    const columns = try f.columns(2);
    defer a.free(columns);
    try scheme.commit(a, columns, &channel);
    const c = components(ch, claims);
    const handles = [_]engine.air.component_prover.ComponentProver{ c[0].asProverComponent(), c[1].asProverComponent(), c[2].asProverComponent() };
    owns = false;
    var proof = try engine.prove.prove(Backend, H, MC, a, &handles, &channel, scheme);
    defer proof.deinit(a);
    return .{ .bytes = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof), .claims = claims };
}
pub fn verify(a: std.mem.Allocator, encoded: Encoded, tamper: bool) !void {
    for (encoded.claims) |claim| for (claim.toM31Array()) |coordinate| {
        if (coordinate.v >= core.fields.m31.Modulus) return error.NonCanonicalWord16Claim;
    };
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded.bytes);
    var owns = true;
    defer if (owns) proof.deinit(a);
    var f = try Fixture.init(a, false);
    defer f.deinit();
    var expected = try Scheme.init(a, CONFIG);
    defer expected.deinit(a);
    var scratch = Channel{};
    const fixed = try f.columns(0);
    defer a.free(fixed);
    try expected.commit(a, fixed, &scratch);
    var roots = try expected.roots(a);
    defer roots.deinit(a);
    if (!std.mem.eql(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0])) return error.UnexpectedWord16FixedRoot;
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(a, CONFIG);
    defer verifier.deinit(a);
    var channel = Channel{};
    mix(&channel);
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
    if (!encoded.claims[0].add(encoded.claims[3]).isZero() or !encoded.claims[1].add(encoded.claims[2]).isZero()) return error.UnclosedWord16Claims;
    channel.mixFelts(&encoded.claims);
    var logs: [P.INTERACTION + 8 + 8]u32 = undefined;
    @memset(logs[0 .. P.INTERACTION + 8], 5);
    @memset(logs[P.INTERACTION + 8 ..], 16);
    try verifier.commit(a, commitments[2], &logs, &channel);
    if (tamper) proof.commitment_scheme_proof.sampled_values.items[2][24][1] = proof.commitment_scheme_proof.sampled_values.items[2][24][1].add(Q.one());
    const c = components(ch, encoded.claims);
    const handles = [_]core.air.components.Component{ c[0].asVerifierComponent(), c[1].asVerifierComponent(), c[2].asVerifierComponent() };
    owns = false;
    try core.verifier.verify(H, MC, a, &handles, &channel, &verifier, proof);
}
