const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const V = frontend.rv64_air.evaluation;
const Air = frontend.testing.component_proof.universal_air;
const Legacy = frontend.testing.component_proof.poseidon_air;
const C = frontend.testing.component_proof.universal_component.Component;
const Relations = frontend.testing.component_proof.relations.Relations;
const Support = frontend.testing.component_proof.support;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn randomRelations(rng: std.Random) Relations {
    var result: Relations = undefined;
    inline for (std.meta.fields(Relations)) |field| @field(result, field.name) = @TypeOf(@field(result, field.name)).init(randomQ(rng), randomQ(rng));
    return result;
}
fn component(log: u32, relations: *const Relations, claims: [Air.N_SUMS]Q, simd: bool) C {
    return .{ .log_size = log, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = 0, .main_col_offset = 0, .interaction_col_offset = 0, .relations = relations, .claims = claims, .enable_simd_domain = simd };
}
fn compare(comptime F: type) !void {
    var prng = std.Random.DefaultPrng.init(0x504f534549444f4e);
    const rng = prng.random();
    const scalar = try a.alloc([Air.N_MAIN_COLUMNS]Q, V.LANES);
    defer a.free(scalar);
    const main = try a.create([Air.N_MAIN_COLUMNS]F);
    defer a.destroy(main);
    for (main, 0..) |*value, column| {
        var secure: [V.LANES]Q = undefined;
        var base: [V.LANES]M = undefined;
        for (0..V.LANES) |lane| {
            secure[lane] = if (F == V.PackedBase) Q.fromBase(M.fromU64(rng.int(u32))) else randomQ(rng);
            base[lane] = secure[lane].c0.a;
            scalar[lane][column] = secure[lane];
        }
        value.* = if (F == V.PackedBase) V.PackedBase.fromLanes(base) else V.PackedSecure.fromLanes(secure);
    }
    const relations = randomRelations(rng);
    const first = M.fromU64(rng.int(u32));
    const claims = [_]Q{ randomQ(rng), randomQ(rng) };
    var sums: [Air.N_SUMS]V.PackedSecure = undefined;
    var prior: [Air.N_SUMS]V.PackedSecure = undefined;
    var scalar_sums: [V.LANES][Air.N_SUMS]Q = undefined;
    var scalar_prior: [V.LANES][Air.N_SUMS]Q = undefined;
    for (&sums, &prior, 0..) |*sum, *prev, index| {
        var current_lanes: [V.LANES]Q = undefined;
        var previous_lanes: [V.LANES]Q = undefined;
        for (0..V.LANES) |lane| {
            current_lanes[lane] = randomQ(rng);
            previous_lanes[lane] = randomQ(rng);
            scalar_sums[lane][index] = current_lanes[lane];
            scalar_prior[lane][index] = previous_lanes[lane];
        }
        sum.* = V.PackedSecure.fromLanes(current_lanes);
        prev.* = V.PackedSecure.fromLanes(previous_lanes);
    }
    const direct = try a.create([Air.N_CONSTRAINTS]F);
    defer a.destroy(direct);
    direct.* = Air.evaluateGeneric(F, main.*);
    const mixed = Air.interactionConstraintsMixed(F, main.*, if (F == V.PackedBase) V.PackedBase.splat(first) else V.PackedSecure.fromBaseScalar(first), sums, prior, .{ V.PackedSecure.splat(claims[0]), V.PackedSecure.splat(claims[1]) }, &relations);
    var powers: [Air.N_CONSTRAINTS + Air.N_SUMS]Q = undefined;
    for (&powers) |*value| value.* = randomQ(rng);
    const instance = component(5, &relations, claims, true);
    const weighted = if (F == V.PackedBase) C.testing.evaluatePacket(&instance, main.*, V.PackedBase.zero(), V.PackedBase.splat(first), sums, prior, &powers) else V.PackedSecure.zero();
    for (scalar, 0..) |row, lane| {
        const expected = Air.evaluateGeneric(Q, row);
        const expected_mixed = Air.interactionConstraintsGeneric(Q, row, Q.fromBase(first), scalar_sums[lane], scalar_prior[lane], claims, &relations);
        for (expected, direct) |value, actual| {
            const secure = V.liftFor(F, actual);
            try std.testing.expect(value.eql(secure.lane(lane)));
        }
        for (expected_mixed, mixed) |value, actual| try std.testing.expect(value.eql(actual.lane(lane)));
        if (F == V.PackedBase) {
            var base_main: [Air.N_MAIN_COLUMNS]M = undefined;
            for (&base_main, row) |*value, source| value.* = source.c0.a;
            const reference = C.testing.evaluateScalar(&instance, base_main, M.zero(), first, scalar_sums[lane], scalar_prior[lane], &powers);
            try std.testing.expect(reference.eql(weighted.lane(lane)));
        }
    }
    // All twelve existing relation arities retain the same challenge polynomial.
    inline for (std.meta.fields(Relations)) |field| {
        const relation = @field(relations, field.name);
        const arity = relation.alpha_powers.len;
        var tuple: [arity]F = undefined;
        for (&tuple, 0..) |*value, i| value.* = main[i];
        const actual = relation.combineFor(F, tuple);
        for (scalar, 0..) |row, lane| try std.testing.expect(relation.combine(row[0..arity].*).eql(actual.lane(lane)));
    }
}
test "universal Poseidon SIMD local and mixed equations match every arbitrary base scalar lane" {
    try compare(V.PackedBase);
}
test "universal Poseidon SIMD retains arbitrary secure OODS equations and all relation arities" {
    try compare(V.PackedSecure);
}
const Column = engine.air.accumulation.ColumnAccumulator;
const Job = struct {
    instance: *const C,
    values: [][]const M,
    inverse: [2]M,
    output: Column,
    start: usize,
    end: usize,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        C.testing.evaluateRows(self.instance, a, self.values, self.inverse, &self.output, self.start, self.end) catch |failure| {
            self.failure = failure;
        };
    }
};
test "universal Poseidon SIMD domain masks additive tails and1/3/8/16joined workers equal scalar" {
    const log = 7;
    const size = 2 << log;
    const source_count = 1 + Air.N_MAIN_COLUMNS + Air.N_INTERACTION_COLUMNS;
    var prng = std.Random.DefaultPrng.init(0x504f53444f4d4149);
    const rng = prng.random();
    const storage = try a.alloc(M, source_count * size);
    defer a.free(storage);
    for (storage) |*value| value.* = M.fromU64(rng.int(u32));
    const values = try a.alloc([]const M, source_count);
    defer a.free(values);
    for (values, 0..) |*value, column| value.* = storage[column * size ..][0..size];
    const relations = randomRelations(rng);
    const claims = [_]Q{ randomQ(rng), randomQ(rng) };
    const scalar = component(log, &relations, claims, false);
    const simd = component(log, &relations, claims, true);
    const inverse = [_]M{ M.fromCanonical(17), M.fromCanonical(23) };
    const alpha = randomQ(rng);
    const constraints = Air.N_CONSTRAINTS + Air.N_SUMS;
    var old = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 1, constraints);
    defer old.deinit();
    var candidate = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, log + 1, constraints);
    defer candidate.deinit();
    const oracle = try old.columns(a, &.{.{ .log_size = log + 1, .n_cols = constraints }});
    defer a.free(oracle);
    const output = try candidate.columns(a, &.{.{ .log_size = log + 1, .n_cols = constraints }});
    defer a.free(output);
    for ([_]usize{ 1, 3, 8, 16 }) |workers| {
        try C.testing.evaluateRows(&scalar, a, values, inverse, &oracle[0], 0, size);
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var jobs: [engine.work_pool.MAX_WORKERS]Job = undefined;
        for (jobs[0..workers], 0..) |*job, i| job.* = .{ .instance = &simd, .values = values, .inverse = inverse, .output = output[0], .start = size * i / workers, .end = size * (i + 1) / workers };
        var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(workers));
        defer lease.deinit();
        var group = std.Thread.WaitGroup{};
        var joined = false;
        defer if (!joined) {
            group.wait();
            lease.completeWave();
        };
        for (jobs[1..workers]) |*job| try lease.spawnWg(&group, Job.run, .{job});
        jobs[0].run();
        group.wait();
        lease.completeWave();
        joined = true;
        for (jobs[0..workers]) |job| if (job.failure) |failure| return failure;
        for (0..size) |row| try std.testing.expect(oracle[0].col.at(row).eql(output[0].col.at(row)));
    }
}
const wire = @import("stwo_proof_wire");
const Engine = engine.engine.ProverEngine(@import("stwo_cpu_backend").CpuBackend, wire.Hasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel, core.channel.blake2s.Blake2sChannel);
const CONFIG = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };
const CALLS = [_]Legacy.Call{
    Legacy.Call.narrow(123, 456),
    .{ .input = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, .wide = true },
    .{ .input = .{ 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 }, .io = true },
};
const Encoded = struct { bytes: []u8, claims: [2]Q };
fn prove(simd: bool) !Encoded {
    const log = 5;
    var scheme = try Engine.init(a, CONFIG);
    var moved = false;
    defer if (!moved) Engine.deinit(&scheme, a);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    CONFIG.mixInto(&channel);
    try Engine.commit(&scheme, a, try Support.generateSelectors(a, log, CALLS.len), null, &channel);
    var main = try Air.generateMain(a, &CALLS, log);
    var main_moved = false;
    defer if (!main_moved) main.deinit(a);
    const main_columns = try Support.takeColumns(Air.N_MAIN_COLUMNS, a, &main.values, log);
    main_moved = true;
    try Engine.commit(&scheme, a, main_columns, null, &channel);
    const relations = try Relations.draw(a, &channel);
    var interaction = try Legacy.generateInteraction(a, &CALLS, log, &relations);
    var interaction_moved = false;
    defer if (!interaction_moved) interaction.deinit(a);
    channel.mixFelts(&interaction.claims.sums);
    const columns = try Support.takeColumns(Air.N_INTERACTION_COLUMNS, a, &interaction.columns, log);
    interaction_moved = true;
    try Engine.commit(&scheme, a, columns, null, &channel);
    const instance = component(log, &relations, interaction.claims.sums, simd);
    moved = true;
    var handle = instance.asProverComponent();
    // Exercise this native prepared evaluator rather than an optional backend program.
    handle.backend_composition_capability = null;
    var extended = try Engine.prove(a, &.{handle}, &channel, scheme, .{});
    defer extended.aux.deinit(a);
    defer extended.proof.deinit(a);
    return .{ .bytes = try wire.encodeProofBytesBinary(a, extended.proof), .claims = interaction.claims.sums };
}
fn verify(encoded: Encoded) !void {
    const log = 5;
    var proof = try wire.decodeProofBytesBinary(a, encoded.bytes);
    var moved = false;
    defer if (!moved) proof.deinit(a);
    const roots = proof.commitment_scheme_proof.commitments.items;
    if (roots.len != 4) return error.InvalidProofShape;
    var fixed = try Engine.init(a, CONFIG);
    defer Engine.deinit(&fixed, a);
    var scratch = Engine.Channel{};
    try Engine.commit(&fixed, a, try Support.generateSelectors(a, log, CALLS.len), null, &scratch);
    var expected = try fixed.roots(a);
    defer expected.deinit(a);
    try std.testing.expectEqualDeep(expected.items[0], roots[0]);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(Engine.Hasher, Engine.MerkleChannel).init(a, CONFIG);
    defer scheme.deinit(a);
    var channel = Engine.Channel{};
    CONFIG.mixInto(&channel);
    try scheme.commit(a, roots[0], &.{ log, log }, &channel);
    try scheme.commit(a, roots[1], &([_]u32{log} ** Air.N_MAIN_COLUMNS), &channel);
    const relations = try Relations.draw(a, &channel);
    channel.mixFelts(&encoded.claims);
    try scheme.commit(a, roots[2], &([_]u32{log} ** Air.N_INTERACTION_COLUMNS), &channel);
    const instance = component(log, &relations, encoded.claims, false);
    moved = true;
    try core.verifier.verify(Engine.Hasher, Engine.MerkleChannel, a, &.{instance.asVerifierComponent()}, &channel, &scheme, proof);
}
test "universal Poseidon native SIMD proof bytes match default scalar and fresh scalar receiver" {
    const scalar = try prove(false);
    defer a.free(scalar.bytes);
    const simd = try prove(true);
    defer a.free(simd.bytes);
    try std.testing.expectEqualSlices(u8, scalar.bytes, simd.bytes);
    try verify(simd);
    var changed = simd;
    changed.claims[1] = changed.claims[1].add(Q.one());
    if (verify(changed)) |_| return error.ExpectedClaimRejection else |_| {}
    // The shared provider's default remains explicitly disabled.
    const relations = Relations.dummy();
    const default = C{ .log_size = 5, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = 0, .main_col_offset = 0, .interaction_col_offset = 0, .relations = &relations, .claims = .{ Q.zero(), Q.zero() } };
    try std.testing.expect(!default.enable_simd_domain);
    const Narrow = frontend.testing.component_proof.narrow_component.Component;
    const unsupported = Narrow{ .log_size = 5, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = 1, .main_col_offset = 0, .interaction_col_offset = 0, .relations = &relations, .claims = .{ Q.zero(), Q.zero() }, .enable_simd_domain = true };
    try std.testing.expectError(error.UnsupportedPoseidonSimdDomain, unsupported.validate());
}
