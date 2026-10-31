const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const K = @import("stwo_riscv_frontend").rv64_air.crypto.keccak;
const L = K.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const B = @import("stwo_cpu_backend").CpuBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const Component = K.component.Component;
const physical = @import("stwo_riscv_frontend").rv64_air.witness.physical;
pub fn appendColumns(out: []engine.pcs.ColumnEvaluation, storage: []const M, log: u32) void {
    const n = @as(usize, 1) << @intCast(log);
    for (out, 0..) |*column, i| column.* = .{ .log_size = log, .values = storage[i * n ..][0..n] };
}
pub fn inputState(i: usize) K.trace.State {
    var state: K.trace.State = undefined;
    for (&state, 0..) |*lane, j| lane.* = (@as(u64, @intCast(i + j + 1)) *% 0x9e3779b97f4a7c15) ^ @as(u64, @intCast(j));
    return state;
}
pub fn reference(input: K.trace.State) K.trace.State {
    var bytes: [200]u8 = undefined;
    for (input, 0..) |lane, i| std.mem.writeInt(u64, bytes[8 * i ..][0..8], lane, .little);
    var state = std.crypto.core.keccak.KeccakF(1600).init(bytes);
    state.permute();
    var output: K.trace.State = undefined;
    for (&output, 0..) |*lane, i| lane.* = std.mem.readInt(u64, state.asBytes()[8 * i ..][0..8], .little);
    return output;
}
fn tupleFor(id: u32, direction: u32, lane: usize, state: K.trace.State) [L.IO_ARITY]Q {
    var tuple: [L.IO_ARITY]Q = undefined;
    tuple[0] = Q.fromBase(M.fromCanonical(id));
    tuple[1] = Q.fromBase(M.fromCanonical(direction));
    tuple[2] = Q.fromBase(M.fromCanonical(@intCast(lane)));
    for (0..8) |byte| tuple[3 + byte] = Q.fromBase(M.fromCanonical(@intCast((state[lane] >> @as(u6, @intCast(8 * byte))) & 255)));
    return tuple;
}
fn expectedIo(inputs: []const K.trace.State, first: u32, ch: K.equations.Challenges) !Q {
    var sum = Q.zero();
    for (inputs, 0..) |input, i| {
        for (0..L.IO_LANES) |lane| {
            sum = sum.add(try ch.io.denominator(&tupleFor(first + @as(u32, @intCast(i)), 0, lane, input)).inv());
            sum = sum.add(try ch.io.denominator(&tupleFor(first + @as(u32, @intCast(i)), 1, lane, reference(input))).inv());
        }
    }
    return sum;
}
pub const Fixture = struct {
    batch_policy: K.equations.BatchPolicy = .triple_v2,
    trace: K.trace.Trace,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    pub fn init(a: std.mem.Allocator, inputs: []const K.trace.State) !Fixture {
        return initWithLog(a, inputs, 1, try L.logSize(inputs.len));
    }
    pub fn initWithLog(a: std.mem.Allocator, inputs: []const K.trace.State, first_id: u32, log: u32) !Fixture {
        return initWithPolicy(a, inputs, first_id, log, .triple_v2);
    }
    pub fn initWithPolicy(a: std.mem.Allocator, inputs: []const K.trace.State, first_id: u32, log: u32, policy: K.equations.BatchPolicy) !Fixture {
        var trace = try K.trace.Trace.initWithLog(a, inputs, first_id, log);
        errdefer trace.deinit();
        const counts = try K.interaction.Counts.fromTrace(&trace);
        var chi = try K.tables.Trace.init(a, .chi, &counts.chi);
        errdefer chi.deinit();
        return .{ .batch_policy = policy, .trace = trace, .chi = chi, .xor5 = try K.tables.Trace.init(a, .xor5, &counts.xor5) };
    }
    pub fn deinit(self: *Fixture) void {
        self.xor5.deinit();
        self.chi.deinit();
        self.trace.deinit();
    }
    pub fn columns(self: *const Fixture, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const pf = [_]usize{ L.FIXED, L.MAIN, self.batch_policy.interactionCount() };
        const tf = [_]usize{ 7, 1, 4 };
        const result = try a.alloc(engine.pcs.ColumnEvaluation, pf[tree] + 2 * tf[tree]);
        appendColumns(result[0..pf[tree]], switch (tree) {
            0 => self.trace.fixed,
            1 => self.trace.main,
            2 => self.trace.interaction,
            else => unreachable,
        }, self.trace.log_size);
        appendColumns(result[pf[tree]..][0..tf[tree]], switch (tree) {
            0 => self.chi.fixed,
            1 => self.chi.main,
            2 => self.chi.interaction,
            else => unreachable,
        }, 13);
        appendColumns(result[pf[tree] + tf[tree] ..], switch (tree) {
            0 => self.xor5.fixed,
            1 => self.xor5.main,
            2 => self.xor5.interaction,
            else => unreachable,
        }, 10);
        return result;
    }
};
test "RV64 compact triple Keccak witness agrees with independent standard permutation" {
    const a = std.testing.allocator;
    const inputs = [_]K.trace.State{ @splat(0), inputState(0), inputState(7) };
    var trace = try K.trace.Trace.init(a, &inputs, 11);
    defer trace.deinit();
    for (inputs, 0..) |input, i| {
        const output = reference(input);
        const row = trace.mainRow(i / 2 * 29 + 27 + i % 2);
        for (output, 0..) |lane, j| for (0..64) |b| try std.testing.expectEqual(@as(u32, @intCast((lane >> @as(u6, @intCast(b))) & 1)), row[j * 64 + b].toU32());
    }
    _ = try K.interaction.Counts.fromTrace(&trace);
    try std.testing.expectEqual(@as(usize, 4551), L.FIXED + L.MAIN + L.INTERACTION);
}
test "RV64 triple Keccak native proof closes all calls in one PCS and fresh verifier" {
    try nativeProof(false, 1);
}
test "RV64 triple Keccak rejects final predecessor sampled value corruption" {
    try nativeProof(true, 1);
}
test "RV64 triple Keccak proves three calls including an incomplete pair" {
    try nativeProof(false, 3);
}
fn nativeProof(tamper: bool, count: usize) !void {
    return produceAndVerify(std.testing.allocator, tamper, count, null);
}
pub fn produceArtifact(a: std.mem.Allocator, directory: []const u8, count: usize) !void {
    try produceAndVerify(a, false, count, directory);
}
pub fn produceArtifactWithLog(a: std.mem.Allocator, directory: []const u8, count: usize, log: u32) !void {
    _ = try produceAndVerifyPublic(a, false, count, directory, 1, log);
}
const Claims = struct { permutation: Q, chi: Q, xor5: Q };
fn fixtureConfig(production: bool) !core.pcs.PcsConfig {
    return .{ .pow_bits = if (production) 26 else 0, .fri_config = try core.fri.FriConfig.init(0, 1, if (production) 70 else 12) };
}
fn produceAndVerify(a: std.mem.Allocator, tamper: bool, count: usize, artifact: ?[]const u8) !void {
    _ = try produceAndVerifyPublic(a, tamper, count, artifact, 1, try L.logSize(count));
}
fn produceAndVerifyPublic(a: std.mem.Allocator, tamper: bool, count: usize, artifact: ?[]const u8, first_id: u32, selected_log: u32) ![32]u8 {
    return produceAndVerifyPublicWithStorage(a, tamper, count, artifact, first_id, selected_log, false);
}
pub fn produceReleasedArtifact(a: std.mem.Allocator, directory: []const u8, count: usize) !void {
    _ = try produceAndVerifyPublicWithStorage(a, false, count, directory, 1, try L.logSize(count), true);
}
fn produceAndVerifyPublicWithStorage(a: std.mem.Allocator, tamper: bool, count: usize, artifact: ?[]const u8, first_id: u32, selected_log: u32, release_main: bool) ![32]u8 {
    return produceAndVerifyPolicy(a, tamper, count, artifact, first_id, selected_log, release_main, .triple_v2);
}
fn produceAndVerifyPolicy(a: std.mem.Allocator, tamper: bool, count: usize, artifact: ?[]const u8, first_id: u32, selected_log: u32, release_main: bool, policy: K.equations.BatchPolicy) ![32]u8 {
    const interaction_count = policy.interactionCount();
    try L.validateGeometry(count, first_id, selected_log);
    var timer = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var recorder = engine.stage_profile.Recorder.init(a, "cpu", "rv64-keccak-primitive");
    defer recorder.deinit();
    // Component domain callbacks may overlap. Each recorder has one serial
    // owner; completed trees move into the report only after prove has joined.
    var component_recorders = [_]engine.stage_profile.Recorder{
        engine.stage_profile.Recorder.initWithOptions(a, "cpu", "keccak-permutation", .{ .capture_tasks = false, .capture_work = false }),
        engine.stage_profile.Recorder.initWithOptions(a, "cpu", "keccak-chi", .{ .capture_tasks = false, .capture_work = false }),
        engine.stage_profile.Recorder.initWithOptions(a, "cpu", "keccak-xor5", .{ .capture_tasks = false, .capture_work = false }),
    };
    defer for (&component_recorders) |*child| child.deinit();
    const inputs = try a.alloc(K.trace.State, count);
    defer a.free(inputs);
    for (inputs, 0..) |*input, i| input.* = inputState(i + 2);
    var fixture = try Fixture.initWithPolicy(a, inputs, first_id, selected_log, policy);
    var owns_fixture = true;
    defer if (owns_fixture) fixture.deinit();
    const witness_ns = phase.lap();
    const config = try fixtureConfig(artifact != null);
    var channel = Channel{};
    config.mixInto(&channel);
    channel.mixU32s(&.{ 0x4b363456, 2, @intCast(count), first_id, selected_log, 4, 3 });
    if (policy == .quartet_v3) policy.mix(&channel);
    var scheme = try Scheme.init(a, config);
    var owns = true;
    defer if (owns) scheme.deinit(a);
    const fixed = try fixture.columns(a, 0);
    defer a.free(fixed);
    const main = try fixture.columns(a, 1);
    defer a.free(main);
    try scheme.commit(a, fixed, &channel);
    const fixed_commit_ns = phase.lap();
    try scheme.commit(a, main, &channel);
    const main_commit_ns = phase.lap();
    const metadata_bytes = fixture.trace.metadata.len * @sizeOf(K.trace.PackedRow) + fixture.chi.multiplicities.len * 4 + fixture.xor5.multiplicities.len * 4;
    if (release_main) {
        try fixture.trace.releaseMain();
        try fixture.chi.releaseMain();
        try fixture.xor5.releaseMain();
    }
    const ch = K.equations.Challenges.draw(&channel);
    const claim = try K.interaction.generateForPolicy(&fixture.trace, ch, policy, .{ .pool = engine.work_pool.currentScopedPool() });
    const chi_claim = try fixture.chi.generateInteraction(ch);
    const xor_claim = try fixture.xor5.generateInteraction(ch);
    try std.testing.expect(claim.add(chi_claim).add(xor_claim).eql(try expectedIo(inputs, first_id, ch)));
    const interaction_generation_ns = phase.lap();
    channel.mixFelts(&.{ claim, chi_claim, xor_claim });
    const inter = try fixture.columns(a, 2);
    defer a.free(inter);
    try scheme.commit(a, inter, &channel);
    const interaction_commit_ns = phase.lap();
    const components = [_]Component{
        .{ .kind = .permutation, .calls = @intCast(count), .first_call_id = first_id, .log_size = fixture.trace.log_size, .challenges = ch, .claim = claim, .stage_recorder = if (artifact != null) &component_recorders[0] else null },
        .{ .kind = .chi, .log_size = 13, .challenges = ch, .claim = chi_claim, .stage_recorder = if (artifact != null) &component_recorders[1] else null, .offsets = .{ .fixed = L.FIXED, .main = L.MAIN, .interaction = interaction_count } },
        .{ .kind = .xor5, .log_size = 10, .challenges = ch, .claim = xor_claim, .stage_recorder = if (artifact != null) &component_recorders[2] else null, .offsets = .{ .fixed = L.FIXED + 7, .main = L.MAIN + 1, .interaction = interaction_count + 4 } },
    };
    const quartet = K.quartet_component.Component{ .base = components[0] };
    const permutation = if (policy == .quartet_v3) quartet.asProverComponent() else components[0].asProverComponent();
    const provers = [_]engine.air.component_prover.ComponentProver{ permutation, components[1].asProverComponent(), components[2].asProverComponent() };
    owns = false;
    var proof = try engine.prove.prove(B, H, MC, a, &provers, &channel, scheme);
    const proving_ns = phase.lap();
    const fixed_root = proof.commitment_scheme_proof.commitments.items[0];
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    if (artifact != null) for (&component_recorders) |*child| try recorder.adoptJoinedStages(child);
    const wire = @import("stwo_proof_wire");
    const encoded = try wire.encodeProofBytesBinary(a, proof);
    defer a.free(encoded);
    proof.deinit(a);
    owns_proof = false;
    fixture.deinit();
    owns_fixture = false;
    const claims = Claims{ .permutation = claim, .chi = chi_claim, .xor5 = xor_claim };
    const prove_ns = timer.read();
    const serialization_and_release_ns = phase.lap();
    if (artifact) |directory| {
        try std.fs.cwd().makePath(directory);
        var dir = try std.fs.cwd().openDir(directory, .{});
        defer dir.close();
        try dir.writeFile(.{ .sub_path = "proof.bin", .data = encoded });
        const json = try std.json.Stringify.valueAlloc(a, claims, .{ .whitespace = .indent_2 });
        defer a.free(json);
        try dir.writeFile(.{ .sub_path = "claims.json", .data = json });
        const hash = std.crypto.hash.sha2.Sha256.hash;
        var digest: [32]u8 = undefined;
        hash(encoded, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        const usage = try @import("stwo_riscv_frontend").process_usage.sample();
        var stages = try recorder.snapshot(a);
        defer stages.deinit(a);
        const report = try std.json.Stringify.valueAlloc(a, .{
            .schema = if (policy == .triple_v2) "rv64-keccak-primitive-fixture-v2" else "rv64-keccak-primitive-fixture-v3-quartet",
            .cpu_ram_bridge = false,
            .main_released_before_challenges = release_main,
            .witness_metadata_bytes = metadata_bytes,
            .calls = count,
            .first_call_id = first_id,
            .pow_bits = config.pow_bits,
            .queries = config.fri_config.n_queries,
            .proof_bytes = encoded.len,
            .proof_sha256 = hex[0..],
            .prove_pipeline_ns = prove_ns,
            .phase_ns = .{ .witness = witness_ns, .fixed_commit = fixed_commit_ns, .main_commit = main_commit_ns, .interactions = interaction_generation_ns, .interaction_commit = interaction_commit_ns, .prove = proving_ns, .serialize_release = serialization_and_release_ns },
            .stages = stages,
            .permutation_log = selected_log,
            .permutation_columns = L.FIXED + L.MAIN + interaction_count,
            .permutation_mask_values = L.FIXED + 5 * L.STATE + L.PARITY + 2 * (L.MAIN - L.ACTIVE_A) + interaction_count + 4,
            .permutation_constraints = policy.constraints(),
            .maximum_degree = policy.degree(),
            .source_bytes = 4 * ((L.FIXED + L.MAIN + interaction_count) * (@as(usize, 1) << @intCast(selected_log)) + 12 * (8192 + 1024)),
            .process_usage = usage,
        }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try dir.writeFile(.{ .sub_path = "producer.json", .data = report });
    }
    if (comptime @import("builtin").is_test) std.crypto.hash.sha2.Sha256.hash(encoded, &gather_testing.last_digest, .{});
    try verifyEncodedPolicy(a, encoded, inputs, claims, config, tamper, first_id, selected_log, policy);
    if (comptime @import("builtin").is_test) if (policy == .quartet_v3 and !tamper) {
        if (verifyEncodedPolicy(a, encoded, inputs, claims, config, false, first_id, selected_log, .triple_v2)) |_| return error.ExpectedLookupPolicyRejection else |_| {}
    };
    return fixed_root;
}
fn fillLogs(logs: []u32, permutation: usize, log: u32, table: usize) void {
    @memset(logs[0..permutation], log);
    @memset(logs[permutation..][0..table], 13);
    @memset(logs[permutation + table ..], 10);
}
fn verifyEncoded(a: std.mem.Allocator, encoded: []const u8, inputs: []const K.trace.State, claims: Claims, config: core.pcs.PcsConfig, tamper: bool, first_id: u32, selected_log: u32) !void {
    return verifyEncodedPolicy(a, encoded, inputs, claims, config, tamper, first_id, selected_log, .triple_v2);
}
fn verifyEncodedPolicy(a: std.mem.Allocator, encoded: []const u8, inputs: []const K.trace.State, claims: Claims, config: core.pcs.PcsConfig, tamper: bool, first_id: u32, selected_log: u32, policy: K.equations.BatchPolicy) !void {
    const interaction_count = policy.interactionCount();
    const count = inputs.len;
    try L.validateGeometry(count, first_id, selected_log);
    const claim = claims.permutation;
    const chi_claim = claims.chi;
    const xor_claim = claims.xor5;
    for ([_]Q{ claim, chi_claim, xor_claim }) |value| for (value.toM31Array()) |limb| {
        if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalClaim;
    };
    var proof = try @import("stwo_proof_wire").decodeProofBytesBinary(a, encoded);
    var owns_proof = true;
    defer if (owns_proof) proof.deinit(a);
    // Only public geometry and canonical fixed table semantics survive. No
    // producer trace, counts, interaction or permutation witness is reused.
    const geometry = try K.trace.fixedColumnsForLog(a, selected_log);
    defer a.free(geometry);
    const zero_chi: [8192]u64 = @splat(0);
    const zero_xor: [1024]u64 = @splat(0);
    var receiver_chi = try K.tables.Trace.init(a, .chi, &zero_chi);
    defer receiver_chi.deinit();
    var receiver_xor = try K.tables.Trace.init(a, .xor5, &zero_xor);
    defer receiver_xor.deinit();
    var receiver_fixed: [L.FIXED + 14]engine.pcs.ColumnEvaluation = undefined;
    appendColumns(receiver_fixed[0..L.FIXED], geometry, selected_log);
    appendColumns(receiver_fixed[L.FIXED..][0..7], receiver_chi.fixed, 13);
    appendColumns(receiver_fixed[L.FIXED + 7 ..], receiver_xor.fixed, 10);
    var fixed_scheme = try Scheme.init(a, config);
    defer fixed_scheme.deinit(a);
    var scratch_channel = Channel{};
    try fixed_scheme.commit(a, &receiver_fixed, &scratch_channel);
    var roots = try fixed_scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    var replay = Channel{};
    config.mixInto(&replay);
    replay.mixU32s(&.{ 0x4b363456, 2, @intCast(count), first_id, selected_log, 4, 3 });
    if (policy == .quartet_v3) policy.mix(&replay);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    const logs = try a.alloc(u32, interaction_count + 8);
    defer a.free(logs);
    fillLogs(logs[0 .. L.FIXED + 14], L.FIXED, selected_log, 7);
    try verifier.commit(a, commitments[0], logs[0 .. L.FIXED + 14], &replay);
    fillLogs(logs[0 .. L.MAIN + 2], L.MAIN, selected_log, 1);
    try verifier.commit(a, commitments[1], logs[0 .. L.MAIN + 2], &replay);
    const fresh_ch = K.equations.Challenges.draw(&replay);
    const components = [_]Component{
        .{ .kind = .permutation, .calls = @intCast(count), .first_call_id = first_id, .log_size = selected_log, .challenges = fresh_ch, .claim = claim },
        .{ .kind = .chi, .log_size = 13, .challenges = fresh_ch, .claim = chi_claim, .offsets = .{ .fixed = L.FIXED, .main = L.MAIN, .interaction = interaction_count } },
        .{ .kind = .xor5, .log_size = 10, .challenges = fresh_ch, .claim = xor_claim, .offsets = .{ .fixed = L.FIXED + 7, .main = L.MAIN + 1, .interaction = interaction_count + 4 } },
    };
    try std.testing.expect(claim.add(chi_claim).add(xor_claim).eql(try expectedIo(inputs, first_id, fresh_ch)));
    replay.mixFelts(&.{ claim, chi_claim, xor_claim });
    fillLogs(logs[0 .. interaction_count + 8], interaction_count, selected_log, 4);
    try verifier.commit(a, commitments[2], logs[0 .. interaction_count + 8], &replay);
    if (tamper) proof.commitment_scheme_proof.sampled_values.items[2][interaction_count - 4][1] = proof.commitment_scheme_proof.sampled_values.items[2][interaction_count - 4][1].add(Q.one());
    const quartet = K.quartet_component.Component{ .base = components[0] };
    const permutation = if (policy == .quartet_v3) quartet.asVerifierComponent() else components[0].asVerifierComponent();
    const verifiers = [_]core.air.components.Component{ permutation, components[1].asVerifierComponent(), components[2].asVerifierComponent() };
    owns_proof = false;
    if (tamper) try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof)) else try core.verifier.verify(H, MC, a, &verifiers, &replay, &verifier, proof);
}
pub fn verifyArtifact(a: std.mem.Allocator, directory: []const u8, count: usize) !void {
    return verifyArtifactWithLog(a, directory, count, try L.logSize(count));
}
pub fn verifyArtifactWithLog(a: std.mem.Allocator, directory: []const u8, count: usize, log: u32) !void {
    return verifyArtifactWithPolicy(a, directory, count, log, .triple_v2);
}
fn verifyArtifactWithPolicy(a: std.mem.Allocator, directory: []const u8, count: usize, log: u32, policy: K.equations.BatchPolicy) !void {
    try L.validateGeometry(count, 1, log);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    const bytes = try dir.readFileAlloc(a, "proof.bin", 64 * 1024 * 1024);
    defer a.free(bytes);
    const json = try dir.readFileAlloc(a, "claims.json", 1024 * 1024);
    defer a.free(json);
    const claims = try std.json.parseFromSlice(Claims, a, json, .{});
    defer claims.deinit();
    const inputs = try a.alloc(K.trace.State, count);
    defer a.free(inputs);
    for (inputs, 0..) |*input, i| input.* = inputState(i + 2);
    try verifyEncodedPolicy(a, bytes, inputs, claims.value, try fixtureConfig(true), false, 1, log, policy);
}

fn drawFixtureChallenges() K.equations.Challenges {
    var channel = Channel{};
    channel.mixU32s(&.{ 0x514b5445, 37 });
    return K.equations.Challenges.draw(&channel);
}
fn secure(data: []const M, n: usize, row: usize, batch: usize) Q {
    return Q.fromM31(data[(4 * batch) * n + row], data[(4 * batch + 1) * n + row], data[(4 * batch + 2) * n + row], data[(4 * batch + 3) * n + row]);
}
fn rowView(trace: *const K.trace.Trace, logical: usize, fixed: *[L.FIXED]Q, main: *[L.MAIN]Q, shifted: *[4][L.STATE]Q, previous_header: *[3]Q) K.equations.Row {
    const n = trace.size();
    const r = physical(logical, trace.log_size);
    for (fixed, 0..) |*v, c| v.* = Q.fromBase(trace.fixed[c * n + r]);
    const base = trace.mainRow(logical);
    for (main, base) |*v, b| v.* = Q.fromBase(b);
    for (L.MASK_OFFSETS[1..], 0..) |offset, j| {
        const other: usize = @intCast(@mod(@as(isize, @intCast(logical)) + offset, @as(isize, @intCast(n))));
        const b = trace.mainRow(other);
        for (&shifted[j], b[0..L.STATE]) |*v, x| v.* = Q.fromBase(x);
    }
    const previous = trace.mainRow((logical + n - 1) % n);
    for (previous_header, previous[L.ACTIVE_A..]) |*v, b| v.* = Q.fromBase(b);
    return .{ .fixed = fixed, .main = main, .previous_header = previous_header, .state_minus_two = &shifted[0], .state_minus_one = &shifted[1], .state_plus_one = &shifted[2], .state_plus_two = &shifted[3] };
}
test "RV64 Keccak stitched prefix closes odd calls and rejects forged loops and transitions" {
    const a = std.testing.allocator;
    const inputs = [_]K.trace.State{ inputState(0), inputState(1), inputState(2) };
    var trace = try K.trace.Trace.init(a, &inputs, 9);
    defer trace.deinit();
    const ch = drawFixtureChallenges();
    const claim = try K.interaction.generate(&trace, ch);
    const values = try a.alloc(Q, L.CONSTRAINTS);
    defer a.free(values);
    const Sink = @import("stwo_riscv_frontend").rv64_air.evaluation.Sink;
    var fixed: [L.FIXED]Q = undefined;
    var main: [L.MAIN]Q = undefined;
    var shifted: [4][L.STATE]Q = undefined;
    var previous_header: [3]Q = @splat(Q.zero());
    var interaction: [L.BATCHES]Q = undefined;
    for (0..trace.size()) |i| {
        const view = rowView(&trace, i, &fixed, &main, &shifted, &previous_header);
        const r = physical(i, trace.log_size);
        const prev = physical((i + trace.size() - 1) % trace.size(), trace.log_size);
        for (&interaction, 0..) |*v, b| v.* = secure(trace.interaction, trace.size(), r, b);
        var sink = Sink{ .values = values };
        const previous = secure(trace.interaction, trace.size(), prev, L.BATCHES - 1);
        K.equations.emit(view, &interaction, previous, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
        try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), sink.count);
        for (values) |value| try std.testing.expect(value.isZero());
        if (i == 58) {
            sink.count = 0;
            K.equations.emit(view, &interaction, previous, claim, ch, .{ .calls = trace.calls - 1, .first_id = trace.first_call_id }, &sink);
            try std.testing.expect(!values[10].isZero());
            previous_header[1] = Q.one(); // Forged fourth call in odd pair.
            sink.count = 0;
            K.equations.emit(view, &interaction, previous, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
            try std.testing.expect(!values[10].isZero());
        }
        if (i == trace.size() - 1) {
            main[L.ACTIVE_A] = Q.one();
            sink.count = 0;
            K.equations.emit(view, &interaction, previous, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
            try std.testing.expect(!values[3].isZero());
        }
        if (i == 0) {
            sink.count = 0;
            K.equations.emit(view, &interaction, previous, claim.add(Q.one()), ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
            try std.testing.expect(!values[L.DIRECT].isZero());
        }
        if (i == 2) {
            interaction[13] = interaction[13].add(Q.one());
            sink.count = 0;
            K.equations.emit(view, &interaction, previous, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
            try std.testing.expect(!values[L.DIRECT + 13].isZero());
            interaction[13] = interaction[13].sub(Q.one());
            shifted[2][37] = shifted[2][37].add(Q.one());
            sink.count = 0;
            K.equations.emit(view, &interaction, previous, claim, ch, .{ .calls = trace.calls, .first_id = trace.first_call_id }, &sink);
            var nonzero = false;
            for (values[L.DIRECT..]) |value| nonzero = nonzero or !value.isZero();
            try std.testing.expect(nonzero);
        }
    }
}
test "RV64 Keccak rejects invalid counts and does not publish failed interactions" {
    const a = std.testing.allocator;
    var empty = try K.trace.Trace.init(a, &.{}, 1);
    defer empty.deinit();
    try std.testing.expectEqual(@as(u32, 5), empty.log_size);
    const inputs = [_]K.trace.State{inputState(1)};
    try std.testing.expectError(error.InvalidKeccakCallId, K.trace.Trace.init(a, &inputs, 0));
    var trace = try K.trace.Trace.init(a, &inputs, 1);
    defer trace.deinit();
    var ch = drawFixtureChallenges();
    ch.chi = .{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    try std.testing.expectError(error.DivisionByZero, K.interaction.generate(&trace, ch));
    try std.testing.expectEqual(@as(usize, 0), trace.interaction.len);
    var counts: [8192]u64 = @splat(0);
    counts[7] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidKeccakTableCounts, K.tables.Trace.init(a, .chi, &counts));
}

test "legacy Keccak tuple extraction retains arbitrary-QM31 pair values" {
    try @import("stwo_riscv_frontend").testing.keccak_tuple_regression.run();
}

test "RV64 Keccak arbitrary-QM31 row polynomials have degree at most four" {
    const a = std.testing.allocator;
    const ch = drawFixtureChallenges();
    const values = try a.alloc(Q, 6 * L.CONSTRAINTS);
    defer a.free(values);
    var fixed: [L.FIXED]Q = undefined;
    var main: [L.MAIN]Q = undefined;
    var shifted: [4][L.STATE]Q = undefined;
    var previous_header: [3]Q = @splat(Q.zero());
    var interaction: [L.BATCHES]Q = undefined;
    const Sink = @import("stwo_riscv_frontend").rv64_air.evaluation.Sink;
    const delta = Q.fromU32Unchecked(7, 9, 11, 13);
    const previous = Q.fromU32Unchecked(19, 23, 29, 31);
    for (0..6) |t| {
        const x = delta.mulM31(M.fromCanonical(@intCast(t)));
        for (&fixed, 0..) |*v, i| v.* = x.add(Q.fromU32Unchecked(@intCast(17 * i + 1), 1, 3, 5));
        for (&main, 0..) |*v, i| v.* = x.add(Q.fromU32Unchecked(@intCast(13 * i + 1), 7, 11, 17));
        for (&shifted, 0..) |*state, j| for (state, 0..) |*v, i| {
            v.* = x.add(Q.fromU32Unchecked(@intCast(11 * i + j + 1), 19, 23, 29));
        };
        for (&interaction, 0..) |*v, i| v.* = x.add(Q.fromU32Unchecked(@intCast(7 * i + 1), 31, 37, 41));
        for (&previous_header, 0..) |*v, i| v.* = x.add(Q.fromU32Unchecked(@intCast(5 * i + 1), 43, 47, 53));
        const row = K.equations.Row{ .fixed = &fixed, .main = &main, .previous_header = &previous_header, .state_minus_two = &shifted[0], .state_minus_one = &shifted[1], .state_plus_one = &shifted[2], .state_plus_two = &shifted[3] };
        var sink = Sink{ .values = values[t * L.CONSTRAINTS ..][0..L.CONSTRAINTS] };
        K.equations.emit(row, &interaction, previous.add(x), Q.one(), ch, .{ .calls = 3, .first_id = 1 }, &sink);
        try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), sink.count);
    }
    for (0..5) |order| for (0..5 - order) |t| for (0..L.CONSTRAINTS) |c| {
        values[t * L.CONSTRAINTS + c] = values[(t + 1) * L.CONSTRAINTS + c].sub(values[t * L.CONSTRAINTS + c]);
    };
    for (values[0..L.CONSTRAINTS]) |value| try std.testing.expect(value.isZero());
}

test "RV64 Keccak n128 row waves use a bounded three-worker existing pool" {
    var pool: engine.work_pool.WorkPool = undefined;
    const stack: usize = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = stack });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try nativeProof(false, 5);
}

test "Keccak characteristic admission rejects unsafe geometry and shared-family rosters before allocation" {
    const max_calls = 111848;
    const safe = try L.admitRoster(&.{max_calls}, &.{});
    try std.testing.expect(safe.chi < core.fields.m31.Modulus);
    try std.testing.expectEqual(@as(u64, 55924 * 38400), safe.chi);
    try std.testing.expectError(error.KeccakLookupMassExceeded, L.logSize(max_calls + 1));
    try std.testing.expectError(error.KeccakLookupMassExceeded, K.trace.fixedColumns(std.testing.failing_allocator, max_calls + 1, 1));
    try std.testing.expectError(error.KeccakLookupMassExceeded, L.admitRoster(&.{ 60000, 60000 }, &.{}));
    try std.testing.expectError(error.KeccakLookupMassExceeded, L.admitRoster(&.{std.math.maxInt(usize)}, &.{}));
    _ = try L.admitRoster(&.{ 100, 200 }, &.{core.fields.m31.Modulus - 1});
    try std.testing.expectError(error.ByteLookupMassExceeded, L.admitRoster(&.{100}, &.{ core.fields.m31.Modulus - 1, 1 }));
    var component = Component{ .kind = .permutation, .calls = max_calls + 1, .log_size = 21, .challenges = drawFixtureChallenges(), .claim = Q.zero() };
    try std.testing.expectError(error.KeccakLookupMassExceeded, component.validate());
    component.calls = 3;
    component.log_size = 5;
    try std.testing.expectError(error.InvalidKeccakComponentGeometry, component.validate());
}

test "Keccak v2 preprocessing is domain-only across counts and canonical call-ID spans" {
    const a = std.testing.allocator;
    const inputs = [_]K.trace.State{ inputState(0), inputState(1), inputState(2), inputState(3) };
    const expected_fixed = try K.trace.fixedColumnsForLog(a, 6);
    defer a.free(expected_fixed);
    for (0..5) |count| {
        for ([_]u32{ 1, 31, core.fields.m31.Modulus - @as(u32, @intCast(@max(1, count))) }) |first| {
            var trace = try K.trace.Trace.initWithLog(a, inputs[0..count], first, 6);
            defer trace.deinit();
            try std.testing.expectEqualSlices(M, expected_fixed, trace.fixed);
            if (count == 3 and first == core.fields.m31.Modulus - 3) {
                // This evaluates the dummy fourth call's wrapped field ID with
                // zero I/O weight; no canonical-integer constructor sees p.
                _ = try K.interaction.generate(&trace, drawFixtureChallenges());
            }
        }
    }
    try std.testing.expectError(error.InvalidKeccakCallId, K.trace.Trace.initWithLog(std.testing.failing_allocator, inputs[0..3], core.fields.m31.Modulus - 2, 6));
    try std.testing.expectError(error.InvalidKeccakCallId, K.trace.fixedColumns(std.testing.failing_allocator, 3, core.fields.m31.Modulus - 2));
}
test "Keccak v2 fresh proofs reuse one geometry for short and near-modulus call-ID instances" {
    const empty_root = try produceAndVerifyPublic(std.testing.allocator, false, 0, null, 1, 6);
    const short_root = try produceAndVerifyPublic(std.testing.allocator, false, 1, null, 31, 6);
    const odd_root = try produceAndVerifyPublic(std.testing.allocator, false, 3, null, core.fields.m31.Modulus - 3, 6);
    try std.testing.expectEqualSlices(u8, &empty_root, &short_root);
    try std.testing.expectEqualSlices(u8, &short_root, &odd_root);
}

pub const gather_testing = if (@import("builtin").is_test) struct {
    threadlocal var last_digest: [32]u8 = undefined;
    pub fn digest(a: std.mem.Allocator, log: u32) ![32]u8 {
        _ = try produceAndVerifyPublic(a, false, 1, null, 1, log);
        return last_digest;
    }
} else struct {};

/// Explicit experimental quartet profile; the production CPU coordinator has
/// no admission path for it and all legacy fixture APIs above remain triple.
pub fn produceQuartetArtifact(a: std.mem.Allocator, directory: []const u8, count: usize) !void {
    _ = try produceAndVerifyPolicy(a, false, count, directory, 1, try L.logSize(count), true, .quartet_v3);
}
pub fn verifyQuartetArtifact(a: std.mem.Allocator, directory: []const u8, count: usize) !void {
    return verifyArtifactWithPolicy(a, directory, count, try L.logSize(count), .quartet_v3);
}
pub const quartet_testing = if (@import("builtin").is_test) struct {
    pub fn digest(a: std.mem.Allocator, count: usize, first_id: u32, log: u32) ![32]u8 {
        _ = try prove(a, count, first_id, log, false);
        return gather_testing.last_digest;
    }
    pub fn prove(a: std.mem.Allocator, count: usize, first_id: u32, log: u32, tamper: bool) ![32]u8 {
        return produceAndVerifyPolicy(a, tamper, count, null, first_id, log, true, .quartet_v3);
    }
} else struct {};
