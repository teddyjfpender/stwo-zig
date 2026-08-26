const std = @import("std");
const stwo_core = @import("stwo_core");
const m31 = stwo_core.fields.m31;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const pcs = stwo_core.pcs;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const provider = @import("universal_shared_provider.zig");
const universal = @import("universal_challenges.zig");
const manifest_mod = @import("universal_adapter_manifest.zig");
const range_bridge = @import("range_check_8_8_bridge.zig");
const relation = @import("../../air/lang/relation.zig");
const poseidon_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const hash_component = @import("../../air/memory_commitment/hash_component.zig");

test "R-012 shared providers occupy exact roster slots without duplicate AIR" {
    try provider.PoseidonSourceAuthority.pinned().validate();
    try std.testing.expectEqualSlices(
        u8,
        &provider.POSEIDON_SOURCE_AUTHORITY_DIGEST,
        &provider.PoseidonSourceAuthority.pinned().identityDigest(),
    );
    const relations = universal.UniversalRelations.dummy();
    var provider_relations = try provider.SharedProviderRelations.init(&relations);
    try provider_relations.validateAgainst(&relations);

    var builder = manifest_mod.Builder{};
    _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(4));
    _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());
    const manifest = try builder.seal();

    const poseidon_claims = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    };
    var poseidon = try provider.Poseidon2Adapter.init(
        &manifest,
        4,
        3,
        &provider_relations,
        &relations,
        poseidon_claims,
    );

    var definition = try range_bridge.build(std.testing.allocator);
    defer definition.deinit();
    const range_binding = try range_bridge.Binding.canonical(&definition);
    const range_executor = try range_bridge.Executor.init(
        &definition,
        &range_binding,
    );
    const range_claim = QM31.fromU32Unchecked(9, 10, 11, 12);
    var range = try provider.RangeCheck8x8Adapter.init(
        &definition,
        &range_executor,
        &manifest,
        &provider_relations,
        &relations,
        range_claim,
    );

    var gate = try manifest_mod.ProofGate.init(&manifest);
    try gate.append(&manifest, try poseidon.binding(&manifest));
    try gate.append(&manifest, try range.binding(&manifest));
    try gate.sealGate(&manifest);
    try gate.validate(&manifest);

    const verifier = try gate.verifierSlice();
    const prover = try gate.proverSlice();
    try std.testing.expectEqual(@as(usize, 2), verifier.len);
    try std.testing.expectEqual(@as(usize, 432), verifier[0].nConstraints());
    try std.testing.expectEqual(@as(usize, 1), verifier[1].nConstraints());
    try std.testing.expectEqual(verifier[0].nConstraints(), prover[0].nConstraints());
    try std.testing.expectEqual(verifier[1].nConstraints(), prover[1].nConstraints());
}

test "R-012 shared provider admission rejects challenge geometry and authority drift" {
    const relations = universal.UniversalRelations.dummy();
    var provider_relations = try provider.SharedProviderRelations.init(&relations);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(4));
    _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());
    const manifest = try builder.seal();

    provider_relations.native.poseidon2.z =
        provider_relations.native.poseidon2.z.add(QM31.fromBase(M31.one()));
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        provider.Poseidon2Adapter.init(
            &manifest,
            4,
            1,
            &provider_relations,
            &relations,
            .{ QM31.zero(), QM31.zero() },
        ),
    );
    provider_relations = try provider.SharedProviderRelations.init(&relations);

    var bad_builder = manifest_mod.Builder{};
    var bad_geometry = provider.Poseidon2Adapter.manifestGeometry(4);
    bad_geometry.main_columns -= 1;
    _ = try bad_builder.append(bad_geometry);
    const bad_manifest = try bad_builder.seal();
    try std.testing.expectError(
        error.ProviderGeometryMismatch,
        provider.Poseidon2Adapter.init(
            &bad_manifest,
            4,
            1,
            &provider_relations,
            &relations,
            .{ QM31.zero(), QM31.zero() },
        ),
    );

    var definition = try range_bridge.build(std.testing.allocator);
    defer definition.deinit();
    const range_binding = try range_bridge.Binding.canonical(&definition);
    var range_executor = try range_bridge.Executor.init(
        &definition,
        &range_binding,
    );
    range_executor.binding_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        provider.RangeCheck8x8Adapter.init(
            &definition,
            &range_executor,
            &manifest,
            &provider_relations,
            &relations,
            QM31.zero(),
        ),
    );

    try std.testing.expectError(
        error.ProviderTraceShapeMismatch,
        provider.Poseidon2Adapter.init(
            &manifest,
            provider.POSEIDON_LOG_SIZE_EXCLUSIVE_LIMIT,
            1,
            &provider_relations,
            &relations,
            .{ QM31.zero(), QM31.zero() },
        ),
    );

    var noncanonical_claim = QM31.zero();
    noncanonical_claim.c0.a.v = m31.Modulus;
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        provider.Poseidon2Adapter.init(
            &manifest,
            4,
            1,
            &provider_relations,
            &relations,
            .{ noncanonical_claim, QM31.zero() },
        ),
    );
}

test "R-012 shared provider binding revalidates borrowed authority and component shape" {
    const relations = universal.UniversalRelations.dummy();
    var provider_relations = try provider.SharedProviderRelations.init(&relations);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(4));
    _ = try builder.append(provider.RangeCheck8x8Adapter.manifestGeometry());
    const manifest = try builder.seal();

    var poseidon = try provider.Poseidon2Adapter.init(
        &manifest,
        4,
        1,
        &provider_relations,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );
    provider_relations.native.poseidon2.alpha_powers[1] = QM31.zero();
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        poseidon.binding(&manifest),
    );
    provider_relations = try provider.SharedProviderRelations.init(&relations);
    poseidon = try provider.Poseidon2Adapter.init(
        &manifest,
        4,
        1,
        &provider_relations,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );
    poseidon.component.main_col_offset += 1;
    try std.testing.expectError(
        error.ProviderAuthorityMismatch,
        poseidon.binding(&manifest),
    );
    poseidon = try provider.Poseidon2Adapter.init(
        &manifest,
        4,
        1,
        &provider_relations,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );
    poseidon.component.log_size = std.math.maxInt(u32);
    try std.testing.expectError(
        error.ProviderAuthorityMismatch,
        poseidon.binding(&manifest),
    );
    poseidon = try provider.Poseidon2Adapter.init(
        &manifest,
        4,
        1,
        &provider_relations,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );
    poseidon.component.poseidon_claims[0] = QM31.one();
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        poseidon.binding(&manifest),
    );

    var definition = try range_bridge.build(std.testing.allocator);
    defer definition.deinit();
    const range_binding = try range_bridge.Binding.canonical(&definition);
    const range_executor = try range_bridge.Executor.init(
        &definition,
        &range_binding,
    );
    var range = try provider.RangeCheck8x8Adapter.init(
        &definition,
        &range_executor,
        &manifest,
        &provider_relations,
        &relations,
        QM31.zero(),
    );
    range.component.tuple_col_indices[0] += 1;
    try std.testing.expectError(
        error.ProviderAuthorityMismatch,
        range.binding(&manifest),
    );

    range = try provider.RangeCheck8x8Adapter.init(
        &definition,
        &range_executor,
        &manifest,
        &provider_relations,
        &relations,
        QM31.zero(),
    );
    provider_relations.native.range_check_8_8.z =
        provider_relations.native.range_check_8_8.z.add(QM31.fromBase(M31.one()));
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        range.binding(&manifest),
    );
    provider_relations = try provider.SharedProviderRelations.init(&relations);
    range = try provider.RangeCheck8x8Adapter.init(
        &definition,
        &range_executor,
        &manifest,
        &provider_relations,
        &relations,
        QM31.zero(),
    );
    range.component.claim = QM31.one();
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        range.binding(&manifest),
    );
}

test "R-012 shared provider rejects malformed cached powers and field limbs" {
    var relations = universal.UniversalRelations.dummy();
    relations.elements[@intFromEnum(relation.Domain.poseidon2)]
        .alpha_powers[3] = QM31.zero();
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        provider.SharedProviderRelations.init(&relations),
    );

    relations = universal.UniversalRelations.dummy();
    relations.elements[@intFromEnum(relation.Domain.poseidon2_io)]
        .z.c0.a.v = m31.Modulus;
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        provider.SharedProviderRelations.init(&relations),
    );

    relations = universal.UniversalRelations.dummy();
    var provider_relations = try provider.SharedProviderRelations.init(&relations);
    provider_relations.native.range_check_8_8.alpha.c1.b.v = m31.Modulus;
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        provider_relations.validate(),
    );
}

test "R-012 shared provider receipt preserves high canonical challenge limbs" {
    var draws: [universal.DRAW_COUNT]QM31 = undefined;
    for (&draws, 0..) |*draw, index| {
        const delta: u32 = @intCast(8 * index + 8);
        draw.* = QM31.fromU32Unchecked(
            m31.Modulus - delta,
            m31.Modulus - delta + 1,
            m31.Modulus - delta + 2,
            m31.Modulus - delta + 3,
        );
    }
    const relations = universal.UniversalRelations.fromDraws(&draws);
    const first = try provider.SharedProviderRelations.init(&relations);
    var second = try provider.SharedProviderRelations.init(&relations);
    try std.testing.expectEqualSlices(
        u8,
        &try first.identityDigest(),
        &try second.identityDigest(),
    );
    try second.validateAgainst(&relations);

    second.native.poseidon2.z.c1.b.v -= 1;
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        second.validateAgainst(&relations),
    );
}

test "R-012 universal Poseidon metadata drops only the memory activity shell" {
    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try provider.SharedProviderRelations.init(&relations);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(4));
    const manifest = try builder.seal();
    var poseidon = try provider.Poseidon2Adapter.init(
        &manifest,
        4,
        1,
        &provider_relations,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );

    try std.testing.expectEqual(@as(usize, 1), poseidon.component.nPreprocessedColumns());
    try std.testing.expectEqual(@as(usize, 432), poseidon.component.nConstraints());
    const indices = try poseidon.component.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(
        usize,
        &.{poseidon.placement.preprocessed_offset},
        indices,
    );
    var bounds = try poseidon.component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 445), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 8), bounds.items[2].len);

    var narrow = poseidon.component;
    narrow.poseidon_shell = .narrow_memory;
    try std.testing.expectEqual(@as(usize, 2), narrow.nPreprocessedColumns());
    try std.testing.expectEqual(@as(usize, 435), narrow.nConstraints());
}

test "R-012 universal Poseidon prepared domain removes exactly one source view" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const eval_log_size = log_size + 1;
    const eval_size = @as(usize, 1) << @intCast(eval_log_size);
    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try provider.SharedProviderRelations.init(&relations);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(provider.Poseidon2Adapter.manifestGeometry(log_size));
    const manifest = try builder.seal();
    var adapter = try provider.Poseidon2Adapter.init(
        &manifest,
        log_size,
        1,
        &provider_relations,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );

    const values = try allocator.alloc(M31, eval_size);
    defer allocator.free(values);
    for (values, 0..) |*value, index|
        value.* = M31.fromU64((17 * index + 5) % 97);
    const poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = values,
        .coefficients = null,
    };
    var preprocessed = [_]prover_component.Poly{ poly, poly };
    const main = try allocator.alloc(prover_component.Poly, poseidon_air.N_MAIN_COLUMNS);
    defer allocator.free(main);
    @memset(main, poly);
    const interaction = try allocator.alloc(
        prover_component.Poly,
        poseidon_air.N_INTERACTION_COLUMNS,
    );
    defer allocator.free(interaction);
    @memset(interaction, poly);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        main,
        interaction,
    };
    var trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var general_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(5, 2, 1, 0),
        eval_log_size,
        adapter.component.nConstraints(),
    );
    defer general_accumulator.deinit();
    var general = (try adapter.component.asProverComponent()
        .prepareConstraintQuotientsOnDomain(
        allocator,
        &trace,
        &general_accumulator,
    )).?;
    defer general.deinit();

    var narrow_component = adapter.component;
    narrow_component.poseidon_shell = .narrow_memory;
    narrow_component.is_active_col_idx = 1;
    var narrow_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(5, 2, 1, 0),
        eval_log_size,
        narrow_component.nConstraints(),
    );
    defer narrow_accumulator.deinit();
    var narrow = (try narrow_component.asProverComponent()
        .prepareConstraintQuotientsOnDomain(
        allocator,
        &trace,
        &narrow_accumulator,
    )).?;
    defer narrow.deinit();

    try std.testing.expectEqual(
        general.resources.final_output_bytes,
        narrow.resources.final_output_bytes,
    );
    try std.testing.expectEqual(
        general.resources.shared_resident_bytes + @sizeOf([]const M31),
        narrow.resources.shared_resident_bytes,
    );

    var cancellation = prover_task_graph.CancellationToken{};
    var task_context = prover_task_graph.TaskContext{
        .user_context = general.context,
        .cancellation = &cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = prover_work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
    try general.run(&task_context);
}

test "R-012 universal Poseidon provider admits atomic IO without the memory-only shell" {
    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try provider.SharedProviderRelations.init(&relations);
    var input: [poseidon_air.WIDTH]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = @intCast(100 + index);
    var calls = [_]poseidon_air.Call{
        .{ .input = input },
        .{ .input = input, .wide = true },
        .{ .input = input, .io = true },
    };
    const expected_numerators = [_][4]QM31{
        .{ QM31.one().neg(), QM31.one(), QM31.zero(), QM31.zero() },
        .{ QM31.one().neg(), QM31.zero(), QM31.one(), QM31.zero() },
        .{ QM31.zero(), QM31.zero(), QM31.zero(), QM31.one() },
    };
    for (&calls, expected_numerators) |*call, expected| {
        const row = poseidon_air.fill(call.*);
        var main: [poseidon_air.N_MAIN_COLUMNS]QM31 = undefined;
        for (&main, row) |*destination, value|
            destination.* = QM31.fromBase(value);
        const pairs = poseidon_air.rowPairs(main, &provider_relations.native);
        const actual = [_]QM31{
            pairs[0].n1,
            pairs[0].n2,
            pairs[1].n1,
            pairs[1].n2,
        };
        for (actual, expected) |numerator, wanted|
            try std.testing.expect(numerator.eql(wanted));
        var claims: [poseidon_air.N_SUMS]QM31 = undefined;
        for (&claims, pairs) |*claim, pair| {
            claim.* = pair.n1.mul(try pair.d1.inv())
                .add(pair.n2.mul(try pair.d2.inv()));
        }
        const constraints = hash_component.poseidonGeneralConstraints(
            main,
            QM31.one(),
            .{ QM31.zero(), QM31.zero() },
            .{ QM31.zero(), QM31.zero() },
            claims,
            &provider_relations.native,
        );
        for (constraints) |constraint|
            try std.testing.expect(constraint.isZero());
    }

    const io_row = poseidon_air.fill(calls[2]);
    var io_main: [poseidon_air.N_MAIN_COLUMNS]QM31 = undefined;
    for (&io_main, io_row) |*destination, value|
        destination.* = QM31.fromBase(value);
    const memory_only = poseidon_air.narrowModeConstraints(io_main);
    try std.testing.expect(memory_only[0].isZero());
    try std.testing.expect(!memory_only[1].isZero());

    var conflicting = calls[2];
    conflicting.wide = true;
    const conflicting_row = poseidon_air.fill(conflicting);
    for (&io_main, conflicting_row) |*destination, value|
        destination.* = QM31.fromBase(value);
    const direct = poseidon_air.evaluate(io_main);
    try std.testing.expect(!direct[poseidon_air.N_CONSTRAINTS - 1].isZero());
}
