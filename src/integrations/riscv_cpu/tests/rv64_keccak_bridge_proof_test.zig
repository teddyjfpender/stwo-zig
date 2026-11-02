//! Complete crypto/lane/RAM boundary proof; CPU call emitter remains external.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const bridge = K.bridge;
const L = bridge.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const B = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const fixture = @import("rv64_keccak_proof_test.zig");
const physical = rv.witness.physical;
fn callsFixture() [2]bridge.trace.Call {
    const before = fixture.inputState(17);
    const mid = fixture.reference(before);
    return .{
        .{ .call_id = 1, .clock = 3, .pointer = 0x1ff8, .before = before, .after = mid, .previous_clocks = @splat(0) },
        .{ .call_id = 2, .clock = 11, .pointer = 0x1ff8, .before = mid, .after = fixture.reference(mid), .previous_clocks = @splat(12) },
    };
}
fn draw(channel: *Channel, ch: K.equations.Challenges) bridge.equations.Challenges {
    const call = bridge.equations.CallChallenges.draw(channel);
    const ram = rv.relations.Challenges.draw(channel);
    channel.mixU32s(&.{ 0x4b425954, 1 });
    return .{ .io = ch.io, .call = call, .ram = ram, .bytes = channel.drawSecureFelt() };
}
fn expected(calls: []const bridge.trace.Call, ch: bridge.equations.Challenges) !Q {
    var ram = Q.zero();
    if (calls.len == 0) return ram;
    for (0..25) |lane| {
        const before = rv.relations.boundaryTuple(1, calls[0].pointer + 8 * lane, 0, calls[0].before[lane], true, true);
        const after = rv.relations.boundaryTuple(1, calls[0].pointer + 8 * lane, @intCast(4 * calls[calls.len - 1].clock), calls[calls.len - 1].after[lane], true, true);
        ram = ram.add(try ch.ram.denominator(before).inv()).sub(try ch.ram.denominator(after).inv());
    }
    for (calls) |call| {
        var tuple: [10]Q = undefined;
        tuple[0] = Q.fromBase(M.fromCanonical(@intCast(call.call_id)));
        tuple[1] = Q.fromBase(M.fromCanonical(@intCast(4 * call.clock)));
        for (0..8) |byte| tuple[2 + byte] = Q.fromBase(M.fromCanonical(@intCast((call.pointer >> @as(u6, @intCast(8 * byte))) & 255)));
        ram = ram.sub(try ch.call.denominator(&tuple).inv());
    }
    return ram;
}
fn fill(out: []engine.pcs.ColumnEvaluation, k: []const engine.pcs.ColumnEvaluation, b: []const M, by: []const M, log: u32, tree: u2) void {
    @memcpy(out[0..k.len], k);
    const counts = [_]usize{ L.FIXED, L.MAIN, L.INTERACTION };
    fixture.appendColumns(out[k.len..][0..counts[tree]], b, log);
    fixture.appendColumns(out[k.len + counts[tree] ..], by, 8);
}
fn run(tamper: bool) !void {
    _ = try runImpl(std.testing.allocator, tamper, 2, null);
}
const Claims = struct { permutation: Q, chi: Q, xor5: Q, bridge: Q, bytes: Q };
fn makeCalls(a: std.mem.Allocator, count: usize) ![]bridge.trace.Call {
    _ = try K.layout.logSize(count);
    _ = try bridge.trace.logSize(count);
    const calls = try a.alloc(bridge.trace.Call, count);
    var before = fixture.inputState(17);
    for (calls, 0..) |*call, i| {
        const after = fixture.reference(before);
        call.* = .{ .call_id = i + 1, .clock = 3 + 8 * i, .pointer = 0x1ff8, .before = before, .after = after, .previous_clocks = @splat(if (i == 0) 0 else @intCast(4 * (3 + 8 * (i - 1)))) };
        before = after;
    }
    return calls;
}
fn configFor(production: bool) !core.pcs.PcsConfig {
    return .{ .pow_bits = if (production) 26 else 0, .fri_config = try core.fri.FriConfig.init(0, 1, if (production) 70 else 12) };
}
pub fn produceArtifact(a: std.mem.Allocator, dir: []const u8, count: usize) !void {
    _ = try runImpl(a, false, count, dir);
}
fn runImpl(a: std.mem.Allocator, tamper: bool, count: usize, artifact: ?[]const u8) ![32]u8 {
    return runImplWithStorage(a, tamper, count, artifact, false);
}
pub fn produceReleasedArtifact(a: std.mem.Allocator, directory: []const u8, count: usize) !void {
    _ = try runImplWithStorage(a, false, count, directory, true);
}
fn runImplWithStorage(a: std.mem.Allocator, tamper: bool, count: usize, artifact: ?[]const u8, release_main: bool) ![32]u8 {
    var timer = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var recorder = engine.stage_profile.Recorder.init(a, "cpu", "rv64-keccak-lane-bridge");
    defer recorder.deinit();
    var component_recorders = [_]engine.stage_profile.Recorder{
        engine.stage_profile.Recorder.initWithOptions(a, "cpu", "keccak-permutation", .{ .capture_tasks = false, .capture_work = false }),
        engine.stage_profile.Recorder.initWithOptions(a, "cpu", "keccak-chi", .{ .capture_tasks = false, .capture_work = false }),
        engine.stage_profile.Recorder.initWithOptions(a, "cpu", "keccak-xor5", .{ .capture_tasks = false, .capture_work = false }),
        engine.stage_profile.Recorder.initWithOptions(a, "cpu", "keccak-lane-bridge", .{ .capture_tasks = false, .capture_work = false }),
    };
    defer for (&component_recorders) |*child| child.deinit();
    const calls = try makeCalls(a, count);
    defer a.free(calls);
    const inputs = try a.alloc(K.trace.State, count);
    defer a.free(inputs);
    for (inputs, calls) |*input, call| input.* = call.before;
    _ = try K.layout.admitRoster(&.{count}, &.{40 * (@as(u64, 1) << @intCast(try bridge.trace.logSize(count)))});
    var k = try fixture.Fixture.init(a, inputs);
    var owns_k = true;
    defer if (owns_k) k.deinit();
    var b = try bridge.trace.Trace.init(a, calls, 1);
    var owns_b = true;
    defer if (owns_b) b.deinit();
    var byte = try rv.range.provider.Trace.init(a, &b.byte_counts);
    var owns_byte = true;
    defer if (owns_byte) byte.deinit();
    const witness_ns = phase.lap();
    const config = try configFor(artifact != null);
    var channel = Channel{};
    config.mixInto(&channel);
    channel.mixU32s(&.{ 0x4b425247, 2, @intCast(count), 1, 4, 25 });
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    const kfixed = try k.columns(a, 0);
    defer a.free(kfixed);
    const kmain = try k.columns(a, 1);
    defer a.free(kmain);
    const fixed = try a.alloc(engine.pcs.ColumnEvaluation, kfixed.len + L.FIXED + 3);
    defer a.free(fixed);
    const main = try a.alloc(engine.pcs.ColumnEvaluation, kmain.len + L.MAIN + 1);
    defer a.free(main);
    fill(fixed, kfixed, b.fixed, byte.fixed, b.log_size, 0);
    fill(main, kmain, b.main, byte.main, b.log_size, 1);
    try scheme.commit(a, fixed, &channel);
    const fixed_commit_ns = phase.lap();
    try scheme.commit(a, main, &channel);
    const main_commit_ns = phase.lap();
    const metadata_bytes = k.trace.metadata.len * @sizeOf(K.trace.PackedRow) + k.chi.multiplicities.len * 4 + k.xor5.multiplicities.len * 4 + b.metadata.len * @sizeOf(bridge.trace.Call);
    if (release_main) {
        try k.trace.releaseMain();
        try k.chi.releaseMain();
        try k.xor5.releaseMain();
        try b.releaseMain();
    }
    const ch = K.equations.Challenges.draw(&channel);
    const bc = draw(&channel, ch);
    const kclaim = try K.interaction.generate(&k.trace, ch);
    const chiclaim = try k.chi.generateInteraction(ch);
    const xorclaim = try k.xor5.generateInteraction(ch);
    const bclaim = try b.generateInteraction(bc);
    const byteclaim = try byte.generateInteraction(bc.bytes);
    try std.testing.expect(kclaim.add(chiclaim).add(xorclaim).add(bclaim).add(byteclaim).eql(try expected(calls, bc)));
    const interaction_generation_ns = phase.lap();
    channel.mixFelts(&.{ kclaim, chiclaim, xorclaim, bclaim, byteclaim });
    const ki = try k.columns(a, 2);
    defer a.free(ki);
    const inter = try a.alloc(engine.pcs.ColumnEvaluation, ki.len + L.INTERACTION + 8);
    defer a.free(inter);
    fill(inter, ki, b.interaction, byte.interaction, b.log_size, 2);
    try scheme.commit(a, inter, &channel);
    const interaction_commit_ns = phase.lap();
    const kc = [_]K.component.Component{
        .{ .kind = .permutation, .calls = @intCast(calls.len), .log_size = k.trace.log_size, .challenges = ch, .claim = kclaim, .stage_recorder = if (artifact != null) &component_recorders[0] else null },
        .{ .kind = .chi, .log_size = 13, .challenges = ch, .claim = chiclaim, .stage_recorder = if (artifact != null) &component_recorders[1] else null, .offsets = .{ .fixed = K.layout.FIXED, .main = K.layout.MAIN, .interaction = K.layout.INTERACTION } },
        .{ .kind = .xor5, .log_size = 10, .challenges = ch, .claim = xorclaim, .stage_recorder = if (artifact != null) &component_recorders[2] else null, .offsets = .{ .fixed = K.layout.FIXED + 7, .main = K.layout.MAIN + 1, .interaction = K.layout.INTERACTION + 4 } },
    };
    const cb = bridge.component.Component{ .calls = @intCast(calls.len), .log_size = b.log_size, .challenges = bc, .claim = bclaim, .stage_recorder = if (artifact != null) &component_recorders[3] else null, .offsets = .{ .fixed = kfixed.len, .main = kmain.len, .interaction = ki.len } };
    const by = rv.providers.byte.Component{ .fixed_offset = kfixed.len + L.FIXED, .main_offset = kmain.len + L.MAIN, .interaction_offset = ki.len + L.INTERACTION, .alpha = bc.bytes, .claim = byteclaim };
    const provers = [_]engine.air.component_prover.ComponentProver{ kc[0].asProverComponent(), kc[1].asProverComponent(), kc[2].asProverComponent(), cb.asProverComponent(), by.asProverComponent() };
    owns_scheme = false;
    var proof = try engine.prove.prove(B, H, MC, a, &provers, &channel, scheme);
    const proving_ns = phase.lap();
    const fixed_root = proof.commitment_scheme_proof.commitments.items[0];
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    if (artifact != null) for (&component_recorders) |*child| try recorder.adoptJoinedStages(child);
    const encoded = try @import("stwo_proof_wire").encodeProofBytesBinary(a, proof);
    defer a.free(encoded);
    proof.deinit(a);
    owns_proof = false;
    const claims = Claims{ .permutation = kclaim, .chi = chiclaim, .xor5 = xorclaim, .bridge = bclaim, .bytes = byteclaim };
    const source_bytes: usize = 4 * ((K.layout.FIXED + K.layout.MAIN + K.layout.INTERACTION) * k.trace.size() + (L.FIXED + L.MAIN + L.INTERACTION) * b.size() + 12 * (8192 + 1024 + 256));
    byte.deinit();
    owns_byte = false;
    b.deinit();
    owns_b = false;
    k.deinit();
    owns_k = false;
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
            .schema = "rv64-keccak-lane-ram-fixture-v2",
            .main_released_before_challenges = release_main,
            .witness_metadata_bytes = metadata_bytes,
            .cpu_component = false,
            .ram_hash_boundary = false,
            .lane_ram_bridge = true,
            .calls = count,
            .pow_bits = config.pow_bits,
            .queries = config.fri_config.n_queries,
            .proof_bytes = encoded.len,
            .proof_sha256 = hex[0..],
            .source_bytes = source_bytes,
            .permutation_log = try K.layout.logSize(count),
            .bridge_log = try bridge.trace.logSize(count),
            .table_logs = [_]u32{ 13, 10, 8 },
            .maximum_trace_log = @max(13, try bridge.trace.logSize(count)),
            .maximum_constraint_log_degree_bound = @max(15, try bridge.trace.logSize(count) + 2),
            .prove_pipeline_ns = timer.read(),
            .phase_ns = .{ .witness = witness_ns, .fixed_commit = fixed_commit_ns, .main_commit = main_commit_ns, .interactions = interaction_generation_ns, .interaction_commit = interaction_commit_ns, .prove = proving_ns },
            .stages = stages,
            .process_usage = try @import("stwo_riscv_frontend").process_usage.sample(),
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = report });
    }
    try verifyEncoded(a, encoded, calls, claims, config, tamper);
    return fixed_root;
}
fn fillLogs(logs: []u32, tree: u2, count: usize) void {
    const kp = [_]usize{ K.layout.FIXED, K.layout.MAIN, K.layout.INTERACTION };
    const tp = [_]usize{ 7, 1, 4 };
    const bp = [_]usize{ L.FIXED, L.MAIN, L.INTERACTION };
    @memset(logs[0..kp[tree]], K.layout.logSize(count) catch unreachable);
    @memset(logs[kp[tree]..][0..tp[tree]], 13);
    @memset(logs[kp[tree] + tp[tree] ..][0..tp[tree]], 10);
    const at = kp[tree] + 2 * tp[tree];
    @memset(logs[at..][0..bp[tree]], bridge.trace.logSize(count) catch unreachable);
    @memset(logs[at + bp[tree] ..], 8);
}
fn verifyEncoded(a: std.mem.Allocator, encoded: []const u8, calls: []const bridge.trace.Call, claims: Claims, config: core.pcs.PcsConfig, tamper: bool) !void {
    const count = calls.len;
    _ = try K.layout.admitRoster(&.{count}, &.{40 * (@as(u64, 1) << @intCast(try bridge.trace.logSize(count)))});
    const kclaim = claims.permutation;
    const chiclaim = claims.chi;
    const xorclaim = claims.xor5;
    const bclaim = claims.bridge;
    const byteclaim = claims.bytes;
    for ([_]Q{ kclaim, chiclaim, xorclaim, bclaim, byteclaim }) |value| for (value.toM31Array()) |limb| {
        if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalClaim;
    };
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    // Fresh verifier geometry contains no input-dependent setup. Public RAM
    // endpoints/call requests alone determine the expected combined claim.
    const bf = try bridge.trace.fixedColumns(a, calls.len, 1);
    defer a.free(bf);
    const zero: [256]u64 = @splat(0);
    var freshbyte = try rv.range.provider.Trace.init(a, &zero);
    defer freshbyte.deinit();
    const fresh_geometry = try K.trace.fixedColumns(a, @intCast(calls.len), 1);
    defer a.free(fresh_geometry);
    const chi_zero: [8192]u64 = @splat(0);
    const xor_zero: [1024]u64 = @splat(0);
    var fresh_chi = try K.tables.Trace.init(a, .chi, &chi_zero);
    defer fresh_chi.deinit();
    var fresh_xor = try K.tables.Trace.init(a, .xor5, &xor_zero);
    defer fresh_xor.deinit();
    var fresh_kfixed: [K.layout.FIXED + 14]engine.pcs.ColumnEvaluation = undefined;
    fixture.appendColumns(fresh_kfixed[0..K.layout.FIXED], fresh_geometry, try K.layout.logSize(calls.len));
    fixture.appendColumns(fresh_kfixed[K.layout.FIXED..][0..7], fresh_chi.fixed, 13);
    fixture.appendColumns(fresh_kfixed[K.layout.FIXED + 7 ..], fresh_xor.fixed, 10);
    const trusted = try a.alloc(engine.pcs.ColumnEvaluation, K.layout.FIXED + 14 + L.FIXED + 3);
    defer a.free(trusted);
    fill(trusted, &fresh_kfixed, bf, freshbyte.fixed, try bridge.trace.logSize(count), 0);
    var trusted_scheme = try Scheme.init(a, config);
    defer trusted_scheme.deinit(a);
    var scratch_channel = Channel{};
    try trusted_scheme.commit(a, trusted, &scratch_channel);
    var roots = try trusted_scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    var replay = Channel{};
    config.mixInto(&replay);
    replay.mixU32s(&.{ 0x4b425247, 2, @intCast(count), 1, 4, 25 });
    const commitments = proof.commitment_scheme_proof.commitments.items;
    const logs = try a.alloc(u32, K.layout.INTERACTION + 8 + L.INTERACTION + 8);
    defer a.free(logs);
    fillLogs(logs[0 .. K.layout.FIXED + 14 + L.FIXED + 3], 0, count);
    try verifier.commit(a, commitments[0], logs[0 .. K.layout.FIXED + 14 + L.FIXED + 3], &replay);
    fillLogs(logs[0 .. K.layout.MAIN + 2 + L.MAIN + 1], 1, count);
    try verifier.commit(a, commitments[1], logs[0 .. K.layout.MAIN + 2 + L.MAIN + 1], &replay);
    const freshch = K.equations.Challenges.draw(&replay);
    const freshbc = draw(&replay, freshch);
    const kc = [_]K.component.Component{
        .{ .kind = .permutation, .calls = @intCast(count), .log_size = try K.layout.logSize(count), .challenges = freshch, .claim = kclaim },
        .{ .kind = .chi, .log_size = 13, .challenges = freshch, .claim = chiclaim, .offsets = .{ .fixed = K.layout.FIXED, .main = K.layout.MAIN, .interaction = K.layout.INTERACTION } },
        .{ .kind = .xor5, .log_size = 10, .challenges = freshch, .claim = xorclaim, .offsets = .{ .fixed = K.layout.FIXED + 7, .main = K.layout.MAIN + 1, .interaction = K.layout.INTERACTION + 4 } },
    };
    const cb = bridge.component.Component{ .calls = @intCast(count), .log_size = try bridge.trace.logSize(count), .challenges = freshbc, .claim = bclaim, .offsets = .{ .fixed = K.layout.FIXED + 14, .main = K.layout.MAIN + 2, .interaction = K.layout.INTERACTION + 8 } };
    const by = rv.providers.byte.Component{ .fixed_offset = K.layout.FIXED + 14 + L.FIXED, .main_offset = K.layout.MAIN + 2 + L.MAIN, .interaction_offset = K.layout.INTERACTION + 8 + L.INTERACTION, .alpha = freshbc.bytes, .claim = byteclaim };
    try std.testing.expect(kclaim.add(chiclaim).add(xorclaim).add(bclaim).add(byteclaim).eql(try expected(calls, freshbc)));
    replay.mixFelts(&.{ kclaim, chiclaim, xorclaim, bclaim, byteclaim });
    fillLogs(logs[0 .. K.layout.INTERACTION + 8 + L.INTERACTION + 8], 2, count);
    try verifier.commit(a, commitments[2], logs[0 .. K.layout.INTERACTION + 8 + L.INTERACTION + 8], &replay);
    if (tamper) proof.commitment_scheme_proof.sampled_values.items[1][K.layout.MAIN + 2][1] = proof.commitment_scheme_proof.sampled_values.items[1][K.layout.MAIN + 2][1].add(Q.one());
    const verifiers = [_]core.air.components.Component{ kc[0].asVerifierComponent(), kc[1].asVerifierComponent(), kc[2].asVerifierComponent(), cb.asVerifierComponent(), by.asVerifierComponent() };
    owns_proof = false;
    if (tamper) try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof)) else try core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof);
}
pub fn verifyArtifact(a: std.mem.Allocator, directory: []const u8, count: usize) !void {
    const calls = try makeCalls(a, count);
    defer a.free(calls);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const bytes = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(bytes);
    const json = try dir.readFileAlloc(a, "claims.json", 1024 * 1024);
    defer a.free(json);
    const claims = try std.json.parseFromSlice(Claims, a, json, .{});
    defer claims.deinit();
    try verifyEncoded(a, bytes, calls, claims.value, try configFor(true), false);
}

test "Keccak narrow lane bridge closes crypto, RAM and call claims in one native proof" {
    try run(false);
}
test "Keccak lane bridge rejects previous pointer sample mutation" {
    try run(true);
}
test "Keccak bridge constructors reject clock truncation, overflow and forged call IDs" {
    const a = std.testing.allocator;
    var calls = callsFixture();
    calls[0].clock = 1 << 22;
    try std.testing.expectError(error.InvalidKeccakBridgeCall, bridge.trace.Trace.init(a, &calls, 1));
    calls = callsFixture();
    calls[0].pointer = std.math.maxInt(u64) - 7;
    try std.testing.expectError(error.InvalidKeccakBridgeCall, bridge.trace.Trace.init(a, &calls, 1));
    calls = callsFixture();
    calls[0].call_id = 1 << 40;
    try std.testing.expectError(error.InvalidKeccakBridgeCall, bridge.trace.Trace.init(a, &calls, 1));
    calls = callsFixture();
    calls[0].previous_clocks[3] = 12;
    try std.testing.expectError(error.InvalidKeccakBridgeClock, bridge.trace.Trace.init(a, &calls, 1));
}

test "Keccak bridge rows enforce address carries, alignment, clock gaps and repeated arguments" {
    const a = std.testing.allocator;
    const calls = callsFixture();
    var trace = try bridge.trace.Trace.init(a, &calls, 1);
    defer trace.deinit();
    var channel = Channel{};
    channel.mixU32s(&.{ 0x4b424554, 43 });
    const kch = K.equations.Challenges.draw(&channel);
    const ch = draw(&channel, kch);
    const claim = try trace.generateInteraction(ch);
    var fixed: [L.FIXED]Q = undefined;
    var main: [L.MAIN]Q = undefined;
    var previous: [L.PREVIOUS_MAIN]Q = undefined;
    var previous_header: [2]Q = undefined;
    var inter: [L.BATCHES]Q = undefined;
    var values: [L.CONSTRAINTS]Q = undefined;
    const n = trace.size();
    for (0..n) |logical| {
        const r = physical(logical, trace.log_size);
        const p = physical((logical + n - 1) % n, trace.log_size);
        for (&fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
        for (&main, 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + r]);
        for (&previous, 0..) |*v, c| v.* = Q.fromBase(trace.main[c * n + p]);
        for (&previous_header, 0..) |*v, c| v.* = Q.fromBase(trace.main[(L.ACTIVE + c) * n + p]);
        for (&inter, 0..) |*v, b| v.* = secure(trace.interaction, n, r, b);
        const row = bridge.equations.Row{ .fixed = &fixed, .main = &main, .previous_main = &previous, .previous_header = &previous_header };
        const prev = secure(trace.interaction, n, p, L.BATCHES - 1);
        var sink = rv.evaluation.Sink{ .values = &values };
        bridge.equations.emit(row, &inter, prev, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_id }, &sink);
        try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), sink.count);
        for (values) |v| try std.testing.expect(v.isZero());
        if (logical == 50) {
            sink.count = 0;
            bridge.equations.emit(row, &inter, prev, claim, ch, .{ .calls = trace.calls - 1, .first_id = trace.first_id }, &sink);
            try std.testing.expect(!values[6].isZero());
        }
        if (logical == n - 1) {
            main[L.ACTIVE] = Q.one();
            sink.count = 0;
            bridge.equations.emit(row, &inter, prev, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_id }, &sink);
            try std.testing.expect(!values[1].isZero());
        }
        if (logical == 1) {
            for ([_]usize{ L.ADDRESS, L.CARRY, L.ALIGNED, L.TICK, L.PREVIOUS, L.GAP }) |column| {
                main[column] = main[column].add(Q.one());
                sink.count = 0;
                bridge.equations.emit(row, &inter, prev, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_id }, &sink);
                var nonzero = false;
                for (values[0..L.DIRECT]) |v| nonzero = nonzero or !v.isZero();
                try std.testing.expect(nonzero);
                main[column] = main[column].sub(Q.one());
            }
            previous[L.POINTER] = previous[L.POINTER].add(Q.one());
            sink.count = 0;
            bridge.equations.emit(row, &inter, prev, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_id }, &sink);
            var nonzero = false;
            for (values[0..L.DIRECT]) |v| nonzero = nonzero or !v.isZero();
            try std.testing.expect(nonzero);
        }
    }
    var total: u64 = 0;
    for (trace.byte_counts) |count| total += count;
    try std.testing.expectEqual(@as(u64, @intCast(n * L.RANGE_COUNT)), total);
}
fn secure(data: []const M, n: usize, row: usize, batch: usize) Q {
    return Q.fromM31(data[(4 * batch) * n + row], data[(4 * batch + 1) * n + row], data[(4 * batch + 2) * n + row], data[(4 * batch + 3) * n + row]);
}

test "Keccak bridge v2 key depends only on domain across counts and near-modulus IDs" {
    const a = std.testing.allocator;
    const expected_fixed = try bridge.trace.fixedColumnsForLog(a, 7);
    defer a.free(expected_fixed);
    const calls = try makeCalls(a, 4);
    defer a.free(calls);
    for (0..5) |count| {
        for ([_]u32{ 1, 31, core.fields.m31.Modulus - @as(u32, @intCast(@max(1, count))) }) |first| {
            for (calls, 0..) |*call, i| call.call_id = @as(u64, first) + i;
            var trace = try bridge.trace.Trace.initWithLog(a, calls[0..count], first, 7);
            defer trace.deinit();
            try std.testing.expectEqualSlices(M, expected_fixed, trace.fixed);
        }
    }
    try std.testing.expectError(error.InvalidKeccakCallId, bridge.trace.Trace.initWithLog(std.testing.failing_allocator, calls[0..3], core.fields.m31.Modulus - 2, 7));
    try std.testing.expectError(error.ByteLookupMassExceeded, bridge.trace.fixedColumnsForLog(std.testing.failing_allocator, 26));
}

test "Keccak v2 mixed crypto and bridge proofs retain one fixed root across request counts" {
    const first = try runImpl(std.testing.allocator, false, 3, null);
    const second = try runImpl(std.testing.allocator, false, 4, null);
    try std.testing.expectEqualSlices(u8, &first, &second);
}

test "Keccak v2 empty service batch closes crypto, RAM, call and BYTE obligations" {
    _ = try runImpl(std.testing.allocator, false, 0, null);
}

/// Test-only proof-wire oracle; production fixture entry points are unchanged.
pub const lane_testing = if (@import("builtin").is_test) struct {
    pub fn digest(a: std.mem.Allocator, count: usize) ![32]u8 {
        return runImpl(a, false, count, null);
    }
} else struct {};
