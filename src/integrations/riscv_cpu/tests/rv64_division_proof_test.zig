const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const B = @import("stwo_cpu_backend").CpuBackend;
const rv = @import("stwo_riscv_frontend").rv64_air;
const D = rv.arithmetic.division;
const tests = @import("rv64_division_test.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Scheme = engine.pcs.CommitmentSchemeProver(B, H, MC);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
const a = std.testing.allocator;
fn columns(storage: []const M, log: u32, output: []engine.pcs.ColumnEvaluation) void {
    const n = @as(usize, 1) << @intCast(log);
    for (output, 0..) |*column, i| column.* = .{ .log_size = log, .values = storage[i * n ..][0..n] };
}
test "division native artifact proves all eight operations and receiver rejects changed prefix" {
    const artifact_dir = std.process.getEnvVarOwned(a, "STWO_RV64_DIVISION_ARTIFACT_DIR") catch null;
    defer if (artifact_dir) |path| a.free(path);
    const config = if (artifact_dir != null) rv.protocol.config() else core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 12) };
    const work = engine.work_pool;
    const workers_env = std.process.getEnvVarOwned(a, "STWO_RV64_DIVISION_WORKERS") catch null;
    defer if (workers_env) |value| a.free(value);
    var pool: work.WorkPool = .{};
    var owns_pool = false;
    defer if (owns_pool) pool.deinit();
    var binding: ?work.ScopedPoolBinding = null;
    defer if (binding) |*value| value.deinit();
    if (workers_env) |value| {
        const workers = try std.fmt.parseInt(usize, value, 10);
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024, .backing_allocator = a });
        owns_pool = true;
        binding = try work.ScopedPoolBinding.init(&pool);
    }
    const reference = std.process.hasEnvVarConstant("STWO_RV64_DIVISION_REFERENCE");
    const requests = tests.fixtures();
    var trace = try D.trace.Trace.init(a, &requests);
    defer trace.deinit();
    var fixed: [D.layout.FIXED]engine.pcs.ColumnEvaluation = undefined;
    var main: [D.layout.MAIN]engine.pcs.ColumnEvaluation = undefined;
    var interaction: [D.layout.INTERACTION]engine.pcs.ColumnEvaluation = undefined;
    columns(trace.fixed, trace.log_size, &fixed);
    columns(trace.main, trace.log_size, &main);
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    var channel = Channel{};
    config.mixInto(&channel);
    channel.mixU32s(&.{ 0x44565032, @intCast(requests.len), trace.log_size });
    try scheme.commit(a, &fixed, &channel);
    try scheme.commit(a, &main, &channel);
    const challenges = D.provider.Challenges.draw(&channel);
    const claim = try trace.generateInteraction(challenges);
    channel.mixFelts(&.{claim});
    columns(trace.interaction, trace.log_size, &interaction);
    try scheme.commit(a, &interaction, &channel);
    const component = D.component.Component{ .log_size = trace.log_size, .count = requests.len, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = challenges, .claim = claim, .reference_domain = reference };
    const components = [_]engine.air.component_prover.ComponentProver{component.asProverComponent()};
    owns_scheme = false;
    var proof = try engine.prove.prove(B, H, MC, a, &components, &channel, scheme);
    defer proof.deinit(a);
    const wire = @import("stwo_proof_wire");
    const bytes = try wire.encodeProofBytesBinary(a, proof);
    defer a.free(bytes);
    if (artifact_dir) |path| {
        try std.fs.cwd().makePath(path);
        var directory = try std.fs.cwd().openDir(path, .{});
        defer directory.close();
        var limbs: [4]u32 = undefined;
        for (claim.toM31Array(), &limbs) |part, *limb| limb.* = part.toU32();
        const request_bytes = try std.json.Stringify.valueAlloc(a, requests, .{});
        defer a.free(request_bytes);
        const claim_bytes = try std.json.Stringify.valueAlloc(a, limbs, .{});
        defer a.free(claim_bytes);
        try directory.writeFile(.{ .sub_path = "requests.json", .data = request_bytes });
        try directory.writeFile(.{ .sub_path = "claim.json", .data = claim_bytes });
        try directory.writeFile(.{ .sub_path = "proof.bin", .data = bytes });
    }
    // Receiver derives geometry and its preprocessing root, and derives the
    // expected typed bus claim from its own requested operands/results.
    const receiver_fixed = try D.trace.fixedColumns(a, requests.len, trace.log_size);
    defer a.free(receiver_fixed);
    var receiver_columns: [D.layout.FIXED]engine.pcs.ColumnEvaluation = undefined;
    columns(receiver_fixed, trace.log_size, &receiver_columns);
    var root_scheme = try Scheme.init(a, config);
    defer root_scheme.deinit(a);
    var root_channel = Channel{};
    try root_scheme.commit(a, &receiver_columns, &root_channel);
    var roots = try root_scheme.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqualSlices(u8, &roots.items[0], &proof.commitment_scheme_proof.commitments.items[0]);
    for (0..3) |tamper| {
        var candidate = try wire.decodeProofBytesBinary(a, bytes);
        var owns_candidate = true;
        defer if (owns_candidate) candidate.deinit(a);
        var verifier = try Verifier.init(a, config);
        defer verifier.deinit(a);
        var replay = Channel{};
        config.mixInto(&replay);
        replay.mixU32s(&.{ 0x44565032, @intCast(requests.len), trace.log_size });
        const commits = candidate.commitment_scheme_proof.commitments.items;
        const fixed_logs: [D.layout.FIXED]u32 = @splat(trace.log_size);
        const main_logs: [D.layout.MAIN]u32 = @splat(trace.log_size);
        const interaction_logs: [D.layout.INTERACTION]u32 = @splat(trace.log_size);
        try verifier.commit(a, commits[0], &fixed_logs, &replay);
        try verifier.commit(a, commits[1], &main_logs, &replay);
        const fresh = D.provider.Challenges.draw(&replay);
        var expected = Q.zero();
        for (requests) |request| {
            const tuple = try D.trace.requestTuple(request);
            expected = expected.sub(try fresh.denominator(&tuple).inv());
        }
        try std.testing.expect(expected.eql(claim));
        replay.mixFelts(&.{expected});
        try verifier.commit(a, commits[2], &interaction_logs, &replay);
        if (tamper == 1) candidate.commitment_scheme_proof.sampled_values.items[2][4][1] = candidate.commitment_scheme_proof.sampled_values.items[2][4][1].add(Q.one());
        if (tamper == 2) candidate.commitment_scheme_proof.sampled_values.items[1][D.layout.COUNT][1] = candidate.commitment_scheme_proof.sampled_values.items[1][D.layout.COUNT][1].add(Q.one());
        if (artifact_dir != null and tamper == 2) {
            var directory = try std.fs.cwd().openDir(artifact_dir.?, .{});
            defer directory.close();
            const changed = try wire.encodeProofBytesBinary(a, candidate);
            defer a.free(changed);
            try directory.writeFile(.{ .sub_path = "bad-count-prefix.bin", .data = changed });
        }
        const receiver = D.component.Component{ .log_size = trace.log_size, .count = requests.len, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = fresh, .claim = expected };
        const receiver_components = [_]core.air.components.Component{receiver.asVerifierComponent()};
        owns_candidate = false;
        if (tamper != 0) try std.testing.expectError(error.OodsNotMatching, core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, candidate)) else try core.verifier.verify(H, MC, a, &receiver_components, &replay, &verifier, candidate);
    }
}
