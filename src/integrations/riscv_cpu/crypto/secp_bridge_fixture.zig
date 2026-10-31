//! Known-public RAM/call control. CPU and authenticated hash boundaries are absent.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const S = rv.crypto.secp256k1;
const P = S.program;
const SL = S.layout;
const Bridge = S.bridge;
const L = Bridge.layout;
const Format = Bridge.equations.PacketFormat;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const F = @import("secp_fixture.zig");
const B = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
pub fn makeCalls(a: std.mem.Allocator, program: *const P.Program, count: usize) ![]Bridge.trace.Call {
    return makeCallsWithFormat(a, program, count, .big_endian_bytes_v1);
}
pub fn makeCallsWithFormat(a: std.mem.Allocator, program: *const P.Program, count: usize, format: Format) ![]Bridge.trace.Call {
    const calls = try a.alloc(Bridge.trace.Call, count);
    errdefer a.free(calls);
    const input = try F.fixtureInputs(a, 1);
    defer a.free(input);
    var before: [24]u64 = @splat(0);
    for (input[0].coordinates[0..program.inputs], 0..) |coordinate, i| {
        var bytes: [32]u8 = undefined;
        if (format == .big_endian_bytes_v1) std.mem.writeInt(u256, &bytes, coordinate, .big) else std.mem.writeInt(u256, &bytes, coordinate, .little);
        for (0..4) |lane| before[4 * i + lane] = std.mem.readInt(u64, bytes[8 * lane ..][0..8], .little);
    }
    for (calls, 0..) |*call, i| {
        var coordinates: [6]u256 = undefined;
        for (coordinates[0..program.inputs], 0..) |*coordinate, c| {
            var bytes: [32]u8 = undefined;
            for (0..4) |lane| std.mem.writeInt(u64, bytes[8 * lane ..][0..8], before[4 * c + lane], .little);
            coordinate.* = if (format == .big_endian_bytes_v1) std.mem.readInt(u256, &bytes, .big) else std.mem.readInt(u256, &bytes, .little);
        }
        const values = try P.execute(program, coordinates[0..program.inputs]);
        var after = before;
        for (program.outputs, 0..) |wire, c| {
            var bytes: [32]u8 = undefined;
            if (format == .big_endian_bytes_v1) std.mem.writeInt(u256, &bytes, values[wire], .big) else std.mem.writeInt(u256, &bytes, values[wire], .little);
            for (0..4) |lane| after[4 * c + lane] = std.mem.readInt(u64, bytes[8 * lane ..][0..8], .little);
        }
        call.* = .{ .call_id = i + 1, .clock = 3 + 8 * i, .pointer = 0x1fe0, .before = before, .after = after, .previous_clocks = @splat(if (i == 0) 0 else @intCast(4 * (3 + 8 * (i - 1)))) };
        if (program.kind == .add) for (call.writable[12..]) |*writable| {
            writable.* = false;
        };
        before = after;
    }
    return calls;
}
const Claims = struct { product: Q, linear: Q, bridge: Q, bytes: Q };
const Fixture = struct {
    modular: F.Fixture,
    bridge: Bridge.trace.Trace,
    fn init(a: std.mem.Allocator, program: *const P.Program, calls: []const Bridge.trace.Call, format: Format) !Fixture {
        const blog = try Bridge.trace.logSize(program, calls.len);
        _ = try SL.admitRoster(&.{ .{ .kind = .product, .program = program, .calls = calls.len, .first_id = 1, .log = try SL.logSize(.product, program, calls.len) }, .{ .kind = .linear, .program = program, .calls = calls.len, .first_id = 1, .log = try SL.logSize(.linear, program, calls.len) } }, &.{L.RANGE_COUNT * (@as(u64, 1) << @intCast(blog))});
        var bridge = try Bridge.trace.Trace.initWithFormat(a, program, calls, 1, format);
        errdefer bridge.deinit();
        const in = try a.alloc(S.trace.Input, calls.len);
        defer a.free(in);
        for (calls, in) |call, *input| {
            input.coordinates = @splat(0);
            for (input.coordinates[0..program.inputs], 0..) |*coordinate, c| {
                var bytes: [32]u8 = undefined;
                for (0..4) |lane| std.mem.writeInt(u64, bytes[8 * lane ..][0..8], call.before[4 * c + lane], .little);
                coordinate.* = if (format == .big_endian_bytes_v1) std.mem.readInt(u256, &bytes, .big) else std.mem.readInt(u256, &bytes, .little);
            }
        }
        var batch = try S.batch.Batch.init(a, program, in, 1);
        errdefer batch.deinit();
        var counts: [256]u64 = undefined;
        for (&counts, batch.product.byte_counts, batch.linear.byte_counts, bridge.byte_counts) |*v, p, l, b| v.* = p + l + b;
        return .{ .modular = .{ .product = batch.product, .linear = batch.linear, .bytes = try rv.range.provider.Trace.init(a, &counts) }, .bridge = bridge };
    }
    fn deinit(self: *Fixture) void {
        self.bridge.deinit();
        self.modular.deinit();
    }
    fn columns(self: *const Fixture, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const base = try self.modular.columns(a, tree);
        defer a.free(base);
        const sizes = [_]usize{ L.FIXED, L.MAIN, L.INTERACTION };
        const byte_sizes = [_]usize{ 3, 1, 8 };
        const prefix = base.len - byte_sizes[tree];
        const count = sizes[tree];
        const out = try a.alloc(engine.pcs.ColumnEvaluation, base.len + count);
        @memcpy(out[0..prefix], base[0..prefix]);
        F.columnsFrom(out[prefix..][0..count], switch (tree) {
            0 => self.bridge.fixed,
            1 => self.bridge.main,
            2 => self.bridge.interaction,
            else => unreachable,
        }, self.bridge.log_size);
        @memcpy(out[prefix + count ..], base[prefix..]);
        return out;
    }
};
fn mixPublic(channel: *Channel, program: *const P.Program, calls: []const Bridge.trace.Call, format: Format) !void {
    channel.mixU32s(&.{ 0x53425231, if (format == .big_endian_bytes_v1) @as(u32, 1) else 2, @intFromEnum(program.kind), @intCast(calls.len), 1, try SL.logSize(.product, program, calls.len), try SL.logSize(.linear, program, calls.len), try Bridge.trace.logSize(program, calls.len) });
    for (calls) |call| channel.mixU32s(&.{ @truncate(call.call_id), @truncate(call.call_id >> 32), @truncate(call.clock), @truncate(call.clock >> 32), @truncate(call.pointer), @truncate(call.pointer >> 32) });
    if (calls.len != 0) {
        const first = calls[0];
        const last = calls[calls.len - 1];
        for (0..@as(usize, program.inputs) * 4) |lane| channel.mixU32s(&.{ @truncate(first.before[lane]), @truncate(first.before[lane] >> 32), @truncate(last.after[lane]), @truncate(last.after[lane] >> 32), @intFromBool(first.writable[lane]) });
    }
}
fn expected(program: *const P.Program, calls: []const Bridge.trace.Call, ch: Bridge.equations.Challenges) !Q {
    var out = Q.zero();
    if (calls.len == 0) return out;
    const first = calls[0];
    const last = calls[calls.len - 1];
    for (0..@as(usize, program.inputs) * 4) |lane| {
        out = out.add(try ch.ram.denominator(rv.relations.boundaryTuple(1, first.pointer + 8 * lane, 0, first.before[lane], true, first.writable[lane])).inv());
        out = out.sub(try ch.ram.denominator(rv.relations.boundaryTuple(1, last.pointer + 8 * lane, @intCast(4 * last.clock), last.after[lane], true, last.writable[lane])).inv());
    }
    for (calls) |call| {
        var tuple: [11]Q = undefined;
        tuple[0] = Q.fromBase(M.fromCanonical(@intFromEnum(program.kind)));
        tuple[1] = Q.fromBase(M.fromCanonical(@intCast(call.call_id)));
        tuple[2] = Q.fromBase(M.fromCanonical(@intCast(4 * call.clock)));
        for (0..8) |byte| tuple[3 + byte] = Q.fromBase(M.fromCanonical(@intCast((call.pointer >> @as(u6, @intCast(8 * byte))) & 255)));
        out = out.sub(try ch.call.denominator(&tuple).inv());
    }
    return out;
}
fn byteComponent(ch: S.equations.Challenges, claim: Q) rv.providers.byte.Component {
    return .{ .fixed_offset = 2 * SL.FIXED + L.FIXED, .main_offset = SL.main(.product) + SL.main(.linear) + L.MAIN, .interaction_offset = SL.interaction(.product) + SL.interaction(.linear) + L.INTERACTION, .alpha = ch.bytes, .claim = claim };
}
fn bridgeComponent(program: *const P.Program, count: usize, log: u32, format: Format, ch: Bridge.equations.Challenges, claim: Q) Bridge.component.Component {
    return .{ .program = program, .calls = @intCast(count), .log_size = log, .packet_format = format, .offsets = .{ .fixed = 2 * SL.FIXED, .main = SL.main(.product) + SL.main(.linear), .interaction = SL.interaction(.product) + SL.interaction(.linear) }, .challenges = ch, .claim = claim };
}
pub fn run(a: std.mem.Allocator, kind: P.Kind, count: usize, tamper: bool) !void {
    try produce(a, kind, count, tamper, null, .big_endian_bytes_v1);
}
pub fn produceArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize) !void {
    try produce(a, kind, count, false, directory, .big_endian_bytes_v1);
}
fn configFor(production: bool) !core.pcs.PcsConfig {
    return .{ .pow_bits = if (production) 26 else 0, .fri_config = try core.fri.FriConfig.init(0, 1, if (production) 70 else 12) };
}
fn produce(a: std.mem.Allocator, kind: P.Kind, count: usize, tamper: bool, artifact: ?[]const u8, format: Format) !void {
    return produceWithStorage(a, kind, count, tamper, artifact, format, false);
}
pub fn produceReleasedArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize, format: Format) !void {
    try produceWithStorage(a, kind, count, false, directory, format, true);
}
fn produceWithStorage(a: std.mem.Allocator, kind: P.Kind, count: usize, tamper: bool, artifact: ?[]const u8, format: Format, release_main: bool) !void {
    var timer = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var recorder = engine.stage_profile.Recorder.init(a, "cpu", "rv64-projective-secp256k1-bridge");
    defer recorder.deinit();
    const program = P.get(kind);
    const calls = try makeCallsWithFormat(a, program, count, format);
    defer a.free(calls);
    var fixture = try Fixture.init(a, program, calls, format);
    var owns_fixture = true;
    defer if (owns_fixture) fixture.deinit();
    const witness_ns = phase.lap();
    const config = try configFor(artifact != null);
    var channel = Channel{};
    config.mixInto(&channel);
    try mixPublic(&channel, program, calls, format);
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
    const metadata_bytes = fixture.modular.product.lookup_bytes.len + fixture.modular.linear.lookup_bytes.len + fixture.bridge.metadata.len * @sizeOf(Bridge.trace.Call);
    if (release_main) {
        try fixture.modular.product.releaseMain();
        try fixture.modular.linear.releaseMain();
        try fixture.bridge.releaseMain();
    }
    const ch = S.equations.Challenges.draw(&channel);
    const bch = Bridge.equations.Challenges{ .wire = ch.wire, .bytes = ch.bytes, .call = Bridge.equations.CallChallenges.draw(&channel), .ram = rv.relations.Challenges.draw(&channel) };
    const claims = Claims{ .product = try fixture.modular.product.generateInteraction(ch), .linear = try fixture.modular.linear.generateInteraction(ch), .bridge = try fixture.bridge.generateInteraction(bch), .bytes = try fixture.modular.bytes.generateInteraction(ch.bytes) };
    try std.testing.expect(claims.product.add(claims.linear).add(claims.bridge).add(claims.bytes).eql(try expected(program, calls, bch)));
    const interactions_ns = phase.lap();
    channel.mixFelts(&.{ claims.product, claims.linear, claims.bridge, claims.bytes });
    const inter = try fixture.columns(a, 2);
    defer a.free(inter);
    try scheme.commit(a, inter, &channel);
    const interaction_commit_ns = phase.lap();
    var cs = F.components(program, count, fixture.modular.product.log_size, fixture.modular.linear.log_size, ch, .{ .product = claims.product, .linear = claims.linear, .bytes = claims.bytes });
    for (&cs) |*component| component.stage_recorder = if (artifact != null) &recorder else null;
    var bc = bridgeComponent(program, count, fixture.bridge.log_size, format, bch, claims.bridge);
    bc.stage_recorder = if (artifact != null) &recorder else null;
    const byte = byteComponent(ch, claims.bytes);
    const provers = [_]engine.air.component_prover.ComponentProver{ cs[0].asProverComponent(), cs[1].asProverComponent(), bc.asProverComponent(), byte.asProverComponent() };
    owns_scheme = false;
    var proof = try engine.prove.prove(B, H, MC, a, &provers, &channel, scheme);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    const proving_ns = phase.lap();
    const encoded = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof);
    defer a.free(encoded);
    proof.deinit(a);
    owns_proof = false;
    const plog = fixture.modular.product.log_size;
    const llog = fixture.modular.linear.log_size;
    const blog = fixture.bridge.log_size;
    fixture.deinit();
    owns_fixture = false;
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
            .schema = if (format == .big_endian_bytes_v1) "rv64-projective-secp256k1-bridge-fixture-v1" else "rv64-projective-secp256k1-bridge-fixture-v2",
            .packet_format = format,
            .main_released_before_challenges = release_main,
            .witness_metadata_bytes = metadata_bytes,
            .kind = kind,
            .calls = count,
            .cpu_present = false,
            .authenticated_ram_hash_boundary = false,
            .known_public_ram_and_call_control = true,
            .pow_bits = config.pow_bits,
            .queries = config.fri_config.n_queries,
            .proof_bytes = encoded.len,
            .proof_sha256 = hex[0..],
            .pipeline_ns = timer.read(),
            .phase_ns = .{ .witness = witness_ns, .fixed_commit = fixed_ns, .main_commit = main_ns, .interactions = interactions_ns, .interaction_commit = interaction_commit_ns, .prove = proving_ns, .serialize_release = release_ns },
            .stages = stages,
            .product_log = plog,
            .linear_log = llog,
            .bridge_log = blog,
            .bridge_columns = L.FIXED + L.MAIN + L.INTERACTION,
            .bridge_constraints = L.CONSTRAINTS,
            .bridge_metadata_byte_queries_per_row = L.RANGE_COUNT,
            .bridge_coordinate_byte_queries_per_row = 0,
            .maximum_degree = 4,
            .source_bytes = 4 * ((SL.FIXED + SL.main(.product) + SL.interaction(.product)) * (@as(usize, 1) << @intCast(plog)) + (SL.FIXED + SL.main(.linear) + SL.interaction(.linear)) * (@as(usize, 1) << @intCast(llog)) + (L.FIXED + L.MAIN + L.INTERACTION) * (@as(usize, 1) << @intCast(blog)) + 12 * 256),
            .mask_values = SL.FIXED + SL.main(.product) + SL.interaction(.product) + 6 + SL.FIXED + SL.main(.linear) + SL.interaction(.linear) + 6 + L.FIXED + L.MAIN + L.INTERACTION + 15 + 16,
            .process_usage = try @import("stwo_riscv_frontend").process_usage.sample(),
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = report });
    }
    try verify(a, encoded, program, calls, claims, config, tamper, format);
}
fn verify(a: std.mem.Allocator, encoded: []const u8, program: *const P.Program, calls: []const Bridge.trace.Call, claims: Claims, config: core.pcs.PcsConfig, tamper: bool, format: Format) !void {
    for ([_]Q{ claims.product, claims.linear, claims.bridge, claims.bytes }) |value| for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalSecpClaim;
    const plog = try SL.logSize(.product, program, calls.len);
    const llog = try SL.logSize(.linear, program, calls.len);
    const blog = try Bridge.trace.logSize(program, calls.len);
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded);
    var owns = true;
    defer if (owns) proof.deinit(a);
    const p = try S.trace.fixedColumns(a, .product, program, plog);
    defer a.free(p);
    const l = try S.trace.fixedColumns(a, .linear, program, llog);
    defer a.free(l);
    const b = try Bridge.trace.fixedColumnsForLog(a, program, blog);
    defer a.free(b);
    const zeros: [256]u64 = @splat(0);
    var bytes = try rv.range.provider.Trace.init(a, &zeros);
    defer bytes.deinit();
    var fixed: [2 * SL.FIXED + L.FIXED + 3]engine.pcs.ColumnEvaluation = undefined;
    F.columnsFrom(fixed[0..SL.FIXED], p, plog);
    F.columnsFrom(fixed[SL.FIXED..][0..SL.FIXED], l, llog);
    F.columnsFrom(fixed[2 * SL.FIXED ..][0..L.FIXED], b, blog);
    F.columnsFrom(fixed[2 * SL.FIXED + L.FIXED ..], bytes.fixed, 8);
    var setup = try Scheme.init(a, config);
    defer setup.deinit(a);
    var scratch = Channel{};
    try setup.commit(a, &fixed, &scratch);
    var roots = try setup.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    var replay = Channel{};
    config.mixInto(&replay);
    try mixPublic(&replay, program, calls, format);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    const f_logs = try a.alloc(u32, 2 * SL.FIXED + L.FIXED + 3);
    defer a.free(f_logs);
    fillLogs(f_logs, SL.FIXED, SL.FIXED, L.FIXED, plog, llog, blog);
    const m_logs = try a.alloc(u32, SL.main(.product) + SL.main(.linear) + L.MAIN + 1);
    defer a.free(m_logs);
    fillLogs(m_logs, SL.main(.product), SL.main(.linear), L.MAIN, plog, llog, blog);
    const i_logs = try a.alloc(u32, SL.interaction(.product) + SL.interaction(.linear) + L.INTERACTION + 8);
    defer a.free(i_logs);
    fillLogs(i_logs, SL.interaction(.product), SL.interaction(.linear), L.INTERACTION, plog, llog, blog);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[0], f_logs, &replay);
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[1], m_logs, &replay);
    const ch = S.equations.Challenges.draw(&replay);
    const bch = Bridge.equations.Challenges{ .wire = ch.wire, .bytes = ch.bytes, .call = Bridge.equations.CallChallenges.draw(&replay), .ram = rv.relations.Challenges.draw(&replay) };
    try std.testing.expect(claims.product.add(claims.linear).add(claims.bridge).add(claims.bytes).eql(try expected(program, calls, bch)));
    replay.mixFelts(&.{ claims.product, claims.linear, claims.bridge, claims.bytes });
    try verifier.commit(a, proof.commitment_scheme_proof.commitments.items[2], i_logs, &replay);
    if (tamper) {
        const offset = SL.interaction(.product) + SL.interaction(.linear) + L.INTERACTION - 4;
        proof.commitment_scheme_proof.sampled_values.items[2][offset][1] = proof.commitment_scheme_proof.sampled_values.items[2][offset][1].add(Q.one());
    }
    const cs = F.components(program, calls.len, plog, llog, ch, .{ .product = claims.product, .linear = claims.linear, .bytes = claims.bytes });
    const bc = bridgeComponent(program, calls.len, blog, format, bch, claims.bridge);
    const byte = byteComponent(ch, claims.bytes);
    const verifiers = [_]core.air.components.Component{ cs[0].asVerifierComponent(), cs[1].asVerifierComponent(), bc.asVerifierComponent(), byte.asVerifierComponent() };
    owns = false;
    if (tamper) try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof)) else try core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof);
}
fn fillLogs(out: []u32, np: usize, nl: usize, nb: usize, plog: u32, llog: u32, blog: u32) void {
    @memset(out[0..np], plog);
    @memset(out[np..][0..nl], llog);
    @memset(out[np + nl ..][0..nb], blog);
    @memset(out[np + nl + nb ..], 8);
}

pub fn verifyArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize) !void {
    const calls = try makeCalls(a, P.get(kind), count);
    defer a.free(calls);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const encoded = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(encoded);
    const json = try dir.readFileAlloc(a, "claims.json", 1024 * 1024);
    defer a.free(json);
    const claims = try std.json.parseFromSlice(Claims, a, json, .{});
    defer claims.deinit();
    try verify(a, encoded, P.get(kind), calls, claims.value, try configFor(true), false, .big_endian_bytes_v1);
}

pub fn runWords(a: std.mem.Allocator, kind: P.Kind, count: usize, tamper: bool) !void {
    try produce(a, kind, count, tamper, null, .little_endian_words_v2);
}
pub fn produceWordsArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize) !void {
    try produce(a, kind, count, false, directory, .little_endian_words_v2);
}
pub fn verifyWordsArtifact(a: std.mem.Allocator, directory: []const u8, kind: P.Kind, count: usize) !void {
    const calls = try makeCallsWithFormat(a, P.get(kind), count, .little_endian_words_v2);
    defer a.free(calls);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const encoded = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(encoded);
    const json = try dir.readFileAlloc(a, "claims.json", 1024 * 1024);
    defer a.free(json);
    const claims = try std.json.parseFromSlice(Claims, a, json, .{});
    defer claims.deinit();
    try verify(a, encoded, P.get(kind), calls, claims.value, try configFor(true), false, .little_endian_words_v2);
}
