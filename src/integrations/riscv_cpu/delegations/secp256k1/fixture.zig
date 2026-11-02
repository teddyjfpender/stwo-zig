//! Public-input/output diagnostic fixture; CPU and RAM authentication are separate.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = rv.crypto.secp256k1;
const L = S.layout;
const P = S.program;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const physical = rv.witness.physical;
const B = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
pub const Claims = struct { product: Q, linear: Q, bytes: Q };
pub const Fixture = struct {
    product: S.trace.Trace,
    linear: S.trace.Trace,
    bytes: rv.range.provider.Trace,
    pub fn init(a: std.mem.Allocator, program: *const P.Program, in: []const S.trace.Input) !Fixture {
        var batch = try S.batch.Batch.init(a, program, in, 1);
        errdefer batch.deinit();
        const product = batch.product;
        const linear = batch.linear;
        var counts: [256]u64 = undefined;
        for (&counts, product.byte_counts, linear.byte_counts) |*v, x, y| v.* = x + y;
        return .{ .product = product, .linear = linear, .bytes = try rv.range.provider.Trace.init(a, &counts) };
    }
    pub fn deinit(self: *Fixture) void {
        self.bytes.deinit();
        self.linear.deinit();
        self.product.deinit();
    }
    pub fn columns(self: *const Fixture, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const x = switch (tree) {
            0 => self.product.fixed,
            1 => self.product.main,
            2 => self.product.interaction,
            else => unreachable,
        };
        const y = switch (tree) {
            0 => self.linear.fixed,
            1 => self.linear.main,
            2 => self.linear.interaction,
            else => unreachable,
        };
        const z = switch (tree) {
            0 => self.bytes.fixed,
            1 => self.bytes.main,
            2 => self.bytes.interaction,
            else => unreachable,
        };
        const nx = x.len / self.product.size();
        const ny = y.len / self.linear.size();
        const nz = z.len / 256;
        const out = try a.alloc(engine.pcs.ColumnEvaluation, nx + ny + nz);
        columnsFrom(out[0..nx], x, self.product.log_size);
        columnsFrom(out[nx..][0..ny], y, self.linear.log_size);
        columnsFrom(out[nx + ny ..], z, 8);
        return out;
    }
};
pub fn columnsFrom(out: []engine.pcs.ColumnEvaluation, data: []const M, log: u32) void {
    const n = @as(usize, 1) << @intCast(log);
    for (out, 0..) |*v, i| v.* = .{ .log_size = log, .values = data[i * n ..][0..n] };
}
pub fn mixPublic(channel: *Channel, program: *const P.Program, in: []const S.trace.Input) !void {
    channel.mixU32s(&.{ 0x53525636, 1, @intFromEnum(program.kind), @intCast(in.len), 1, try L.logSize(.product, program, in.len), try L.logSize(.linear, program, in.len) });
    for (in) |input| {
        const values = try P.execute(program, input.coordinates[0..program.inputs]);
        for (input.coordinates[0..program.inputs]) |coordinate| {
            const bytes = P.bytes(coordinate);
            var words: [8]u32 = undefined;
            for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
            channel.mixU32s(&words);
        }
        for (program.outputs) |w| {
            const bytes = P.bytes(values[w]);
            var words: [8]u32 = undefined;
            for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
            channel.mixU32s(&words);
        }
    }
}
pub fn components(program: *const P.Program, count: usize, plog: u32, llog: u32, ch: S.equations.Challenges, claims: Claims) [2]S.component.Component {
    return .{
        .{ .kind = .product, .program = program, .log_size = plog, .public = .{ .calls = @intCast(count) }, .challenges = ch, .claim = claims.product },
        .{ .kind = .linear, .program = program, .log_size = llog, .public = .{ .calls = @intCast(count) }, .offsets = .{ .fixed = L.FIXED, .main = L.main(.product), .interaction = L.interaction(.product) }, .challenges = ch, .claim = claims.linear },
    };
}
fn bytesComponent(ch: S.equations.Challenges, claim: Q) rv.providers.byte.Component {
    return .{ .fixed_offset = 2 * L.FIXED, .main_offset = L.main(.product) + L.main(.linear), .interaction_offset = L.interaction(.product) + L.interaction(.linear), .alpha = ch.bytes, .claim = claim };
}
pub fn proveAndVerify(a: std.mem.Allocator, program: *const P.Program, in: []const S.trace.Input, tamper: bool) !void {
    try produce(a, program, in, tamper, null);
}
pub fn produceArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize) !void {
    const in = try fixtureInputs(a, count);
    defer a.free(in);
    try produce(a, P.get(kind), in, false, directory);
}
pub fn fixtureInputs(a: std.mem.Allocator, count: usize) ![]S.trace.Input {
    const in = try a.alloc(S.trace.Input, count);
    const modulus = P.field.base_modulus.integer();
    for (in, 0..) |*input, i| {
        for (&input.coordinates, 0..) |*coordinate, j| coordinate.* = if ((i + j) % 7 == 0) @as(u256, std.math.maxInt(u256)) - i - j else if ((i + j) % 5 == 0) modulus - i - j else @as(u256, i + 1) * 0x9e3779b97f4a7c15 + j * 37;
    }
    return in;
}
fn configFor(production: bool) !core.pcs.PcsConfig {
    return .{ .pow_bits = if (production) 26 else 0, .fri_config = try core.fri.FriConfig.init(0, 1, if (production) 70 else 12) };
}
fn produce(a: std.mem.Allocator, program: *const P.Program, in: []const S.trace.Input, tamper: bool, artifact: ?[]const u8) !void {
    return produceWithStorage(a, program, in, tamper, artifact, false);
}
pub fn produceReleasedArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize) !void {
    const in = try fixtureInputs(a, count);
    defer a.free(in);
    try produceWithStorage(a, P.get(kind), in, false, directory, true);
}
fn produceWithStorage(a: std.mem.Allocator, program: *const P.Program, in: []const S.trace.Input, tamper: bool, artifact: ?[]const u8, release_main: bool) !void {
    var timer = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var recorder = engine.stage_profile.Recorder.init(a, "cpu", "rv64-projective-secp256k1");
    defer recorder.deinit();
    var fixture = try Fixture.init(a, program, in);
    var owns = true;
    defer if (owns) fixture.deinit();
    const plog = fixture.product.log_size;
    const llog = fixture.linear.log_size;
    const witness_ns = phase.lap();
    const config = try configFor(artifact != null);
    var channel = Channel{};
    config.mixInto(&channel);
    try mixPublic(&channel, program, in);
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    const fixed = try fixture.columns(a, 0);
    defer a.free(fixed);
    const main = try fixture.columns(a, 1);
    defer a.free(main);
    try scheme.commit(a, fixed, &channel);
    const fixed_ns = phase.lap();
    try scheme.commit(a, main, &channel);
    const main_ns = phase.lap();
    const metadata_bytes = fixture.product.lookup_bytes.len + fixture.linear.lookup_bytes.len;
    if (release_main) {
        try fixture.product.releaseMain();
        try fixture.linear.releaseMain();
    }
    const ch = S.equations.Challenges.draw(&channel);
    const claims = Claims{ .product = try fixture.product.generateInteraction(ch), .linear = try fixture.linear.generateInteraction(ch), .bytes = try fixture.bytes.generateInteraction(ch.bytes) };
    try std.testing.expect(claims.product.add(claims.linear).add(claims.bytes).eql(try expectedWireClaim(program, in, 1, ch.wire)));
    const interactions_ns = phase.lap();
    channel.mixFelts(&.{ claims.product, claims.linear, claims.bytes });
    const inter = try fixture.columns(a, 2);
    defer a.free(inter);
    try scheme.commit(a, inter, &channel);
    const commit_interaction_ns = phase.lap();
    var c = components(program, in.len, plog, llog, ch, claims);
    for (&c) |*component| component.stage_recorder = if (artifact != null) &recorder else null;
    const byte = bytesComponent(ch, claims.bytes);
    const provers = [_]engine.air.component_prover.ComponentProver{ c[0].asProverComponent(), c[1].asProverComponent(), byte.asProverComponent() };
    owns_scheme = false;
    var proof = try engine.prove.prove(B, H, MC, a, &provers, &channel, scheme);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    const prove_ns = phase.lap();
    const encoded = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof);
    defer a.free(encoded);
    proof.deinit(a);
    owns_proof = false;
    fixture.deinit();
    owns = false;
    const release_ns = phase.lap();
    if (artifact) |directory| {
        try std.fs.cwd().makePath(directory);
        var dir = try std.fs.cwd().openDir(directory, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
        const json = try std.json.Stringify.valueAlloc(a, claims, .{ .whitespace = .indent_2 });
        defer a.free(json);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = json });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        var stages = try recorder.snapshot(a);
        defer stages.deinit(a);
        const report = try std.json.Stringify.valueAlloc(a, .{
            .schema = "rv64-projective-secp256k1-fixture-v1",
            .main_released_before_challenges = release_main,
            .witness_metadata_bytes = metadata_bytes,
            .kind = program.kind,
            .calls = in.len,
            .cpu_ram_bridge = false,
            .pow_bits = config.pow_bits,
            .queries = config.fri_config.n_queries,
            .proof_bytes = encoded.len,
            .proof_sha256 = hex[0..],
            .pipeline_ns = timer.read(),
            .phase_ns = .{ .witness = witness_ns, .fixed_commit = fixed_ns, .main_commit = main_ns, .interactions = interactions_ns, .interaction_commit = commit_interaction_ns, .prove = prove_ns, .serialize_release = release_ns },
            .stages = stages,
            .product = .{ .rows_per_call = program.rows(true), .log = plog, .fixed = L.FIXED, .main = L.main(.product), .interaction = L.interaction(.product), .constraints = L.constraints(.product) },
            .linear = .{ .rows_per_call = program.rows(false), .log = llog, .fixed = L.FIXED, .main = L.main(.linear), .interaction = L.interaction(.linear), .constraints = L.constraints(.linear) },
            .maximum_degree = 4,
            .source_bytes = 4 * ((L.FIXED + L.main(.product) + L.interaction(.product)) * (@as(usize, 1) << @intCast(plog)) + (L.FIXED + L.main(.linear) + L.interaction(.linear)) * (@as(usize, 1) << @intCast(llog)) + 12 * 256),
            .mask_values = L.FIXED + L.main(.product) + L.interaction(.product) + 6 + L.FIXED + L.main(.linear) + L.interaction(.linear) + 6 + 16,
            .process_usage = try @import("stwo_riscv_frontend").process_usage.sample(),
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = report });
    }
    try verifyEncoded(a, encoded, program, in, claims, config, tamper);
}
fn verifyEncoded(a: std.mem.Allocator, encoded: []const u8, program: *const P.Program, in: []const S.trace.Input, claims: Claims, config: core.pcs.PcsConfig, tamper: bool) !void {
    const plog = try L.logSize(.product, program, in.len);
    const llog = try L.logSize(.linear, program, in.len);
    for ([_]Q{ claims.product, claims.linear, claims.bytes }) |value| for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalSecpClaim;
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const pfixed = try S.trace.fixedColumns(a, .product, program, plog);
    defer a.free(pfixed);
    const lfixed = try S.trace.fixedColumns(a, .linear, program, llog);
    defer a.free(lfixed);
    const zeros: [256]u64 = @splat(0);
    var bytes = try rv.range.provider.Trace.init(a, &zeros);
    defer bytes.deinit();
    var fixed: [2 * L.FIXED + 3]engine.pcs.ColumnEvaluation = undefined;
    columnsFrom(fixed[0..L.FIXED], pfixed, plog);
    columnsFrom(fixed[L.FIXED..][0..L.FIXED], lfixed, llog);
    columnsFrom(fixed[2 * L.FIXED ..], bytes.fixed, 8);
    var setup = try Scheme.init(a, config);
    defer setup.deinit(a);
    var scratch = Channel{};
    try setup.commit(a, &fixed, &scratch);
    try std.testing.expectEqualSlices(u8, &setup.trees.items[0].commitment.root(), &proof.commitment_scheme_proof.commitments.items[0]);
    var replay = Channel{};
    config.mixInto(&replay);
    try mixPublic(&replay, program, in);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    var fixed_logs: [2 * L.FIXED + 3]u32 = undefined;
    @memset(fixed_logs[0..L.FIXED], plog);
    @memset(fixed_logs[L.FIXED..][0..L.FIXED], llog);
    @memset(fixed_logs[2 * L.FIXED ..], 8);
    var main_logs: [L.main(.product) + L.main(.linear) + 1]u32 = undefined;
    @memset(main_logs[0..L.main(.product)], plog);
    @memset(main_logs[L.main(.product)..][0..L.main(.linear)], llog);
    main_logs[main_logs.len - 1] = 8;
    var inter_logs: [L.interaction(.product) + L.interaction(.linear) + 8]u32 = undefined;
    @memset(inter_logs[0..L.interaction(.product)], plog);
    @memset(inter_logs[L.interaction(.product)..][0..L.interaction(.linear)], llog);
    @memset(inter_logs[inter_logs.len - 8 ..], 8);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[0], &fixed_logs, &replay);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[1], &main_logs, &replay);
    const ch = S.equations.Challenges.draw(&replay);
    try std.testing.expect(claims.product.add(claims.linear).add(claims.bytes).eql(try expectedWireClaim(program, in, 1, ch.wire)));
    replay.mixFelts(&.{ claims.product, claims.linear, claims.bytes });
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], &inter_logs, &replay);
    if (tamper) {
        const column = L.interaction(.product) - 1;
        proof.commitment_scheme_proof.sampled_values.items[2][column][1] = proof.commitment_scheme_proof.sampled_values.items[2][column][1].add(Q.one());
    }
    const c = components(program, in.len, plog, llog, ch, claims);
    const byte = bytesComponent(ch, claims.bytes);
    const verifiers = [_]core.air.components.Component{ c[0].asVerifierComponent(), c[1].asVerifierComponent(), byte.asVerifierComponent() };
    owns = false;
    if (tamper) try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof)) else try core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof);
}
pub fn expectedWireClaim(program: *const P.Program, inputs: []const S.trace.Input, first_id: u32, ch: S.equations.Wire) !Q {
    var out = Q.zero();
    for (inputs, 0..) |input, call| {
        const id = std.math.cast(u32, @as(u64, first_id) + call) orelse return error.InvalidSecpCallSpan;
        const values = try P.execute(program, input.coordinates[0..program.inputs]);
        for (input.coordinates[0..program.inputs], 0..) |v, w| out = out.sub((try ch.denominator(&S.equations.externalTuple(program, id, @intCast(w), v)).inv()).mulM31(M.fromCanonical(program.uses[w])));
        for (program.outputs) |w| out = out.add(try ch.denominator(&S.equations.externalTuple(program, id, w, values[w])).inv());
    }
    return out;
}

pub fn verifyArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize) !void {
    const in = try fixtureInputs(a, count);
    defer a.free(in);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const encoded = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(encoded);
    const json = try dir.readFileAlloc(a, "claims.json", 1024 * 1024);
    defer a.free(json);
    const claims = try std.json.parseFromSlice(Claims, a, json, .{});
    defer claims.deinit();
    try verifyEncoded(a, encoded, P.get(kind), in, claims.value, try configFor(true), false);
}
