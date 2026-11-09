//! Retained typed-component contract checks; fixtures are test-owned.
const support = @import("universal_typed_component_test_support.zig");
const std = support.std;
const stwo_core = support.stwo_core;
const core_components = support.core_components;
const pcs = support.pcs;
const M31 = support.M31;
const QM31 = support.QM31;
const prover_accumulation = support.prover_accumulation;
const prover_component = support.prover_component;
const prepared_domain = support.prepared_domain;
const prover_task_graph = support.prover_task_graph;
const manifest_mod = support.manifest_mod;
const adapter = support.adapter;
const universal_binding = support.universal_binding;
const universal = support.universal;
const framework = support.framework;
const catalog = support.catalog;
const roster = support.roster;
const fri_input = support.fri_input;
const fri_relation = support.fri_relation;
const merkle = support.merkle;
const merkle_relation = support.merkle_relation;
const merkle_witness = support.merkle_witness;
const qm31_mul_relation = support.qm31_mul_relation;
const relation_challenges = support.relation_challenges;
const qm31_mul = support.qm31_mul;
const FriAdapter = support.FriAdapter;
const MerkleAdapter = support.MerkleAdapter;
const MerkleFramework = support.MerkleFramework;
const friGeometry = support.friGeometry;
const merkleGeometry = support.merkleGeometry;
const admitTypedRow = support.admitTypedRow;
const expectPairArraysEqual = support.expectPairArraysEqual;
const fixtureInvocation = support.fixtureInvocation;
const committedSecure = support.committedSecure;
const testTaskContext = support.testTaskContext;
const prepareFailureCase = support.prepareFailureCase;
const verifierPointCase = support.verifierPointCase;

test "R-012 universal manifest pins roster order offsets claims and transcript" {
    var builder = manifest_mod.Builder{};
    const fri_placement = try builder.append(friGeometry(4));
    const merkle_placement = try builder.append(merkleGeometry(4));
    const manifest = try builder.seal();
    try manifest.validate();

    try std.testing.expectEqual(@as(u32, 0), fri_placement.preprocessed_offset);
    try std.testing.expectEqual(@as(u32, 0), fri_placement.main_offset);
    try std.testing.expectEqual(@as(u32, 0), fri_placement.interaction_offset);
    try std.testing.expectEqual(@as(u32, 0), fri_placement.constraint_offset);
    try std.testing.expectEqual(@as(u32, 20), merkle_placement.preprocessed_offset);
    try std.testing.expectEqual(@as(u32, 2), merkle_placement.main_offset);
    try std.testing.expectEqual(@as(u32, 20), merkle_placement.interaction_offset);
    try std.testing.expectEqual(@as(u32, 8), merkle_placement.constraint_offset);
    try std.testing.expectEqual(@as(u32, 20), manifest.total_preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 48), manifest.total_main_columns);
    try std.testing.expectEqual(@as(u32, 28), manifest.total_interaction_columns);
    try std.testing.expectEqual(@as(u32, 21), manifest.total_constraints);

    var reverse = manifest_mod.Builder{};
    _ = try reverse.append(merkleGeometry(4));
    try std.testing.expectError(
        error.RosterOrderMismatch,
        reverse.append(friGeometry(4)),
    );
    var invalid = manifest_mod.Builder{};
    try std.testing.expectError(
        error.InvalidRosterRow,
        invalid.append(.{
            .roster_row = roster.COMPONENT_COUNT,
            .log_size = 4,
            .preprocessed_columns = 1,
            .main_columns = 1,
            .interaction_columns = 4,
            .direct_constraints = 1,
            .interaction_batches = 1,
            .protocol_constraint_degree = 3,
            .profiled_constraint_degree = 3,
            .semantic_digest = [_]u8{0} ** 32,
        }),
    );

    var claims = try manifest_mod.ClaimVector.init(&manifest);
    try claims.bind(.fri_verifier_input, QM31.fromU32Unchecked(1, 2, 3, 4));
    try std.testing.expectError(
        error.ClaimAlreadyBound,
        claims.bind(.fri_verifier_input, QM31.zero()),
    );
    try std.testing.expectError(error.ClaimMissing, claims.sealClaims(&manifest));
    try claims.bind(.merkle_path, QM31.fromU32Unchecked(5, 6, 7, 8));
    try claims.sealClaims(&manifest);
    try claims.validate(&manifest);

    const Blake2sChannel = stwo_core.channel.blake2s.Blake2sChannel;
    var prover_channel = Blake2sChannel{};
    var verifier_channel = Blake2sChannel{};
    try manifest.mixStatementPrefix(&prover_channel);
    try claims.mixInteractionClaims(&manifest, &prover_channel);
    try manifest.mixStatementPrefix(&verifier_channel);
    try claims.mixInteractionClaims(&manifest, &verifier_channel);
    try std.testing.expect(
        prover_channel.drawSecureFelt().eql(verifier_channel.drawSecureFelt()),
    );

    var mutated = manifest;
    mutated.total_main_columns += 1;
    try std.testing.expectError(error.ManifestSealMismatch, mutated.validate());
    var mutated_claims = claims;
    mutated_claims.values[@intFromEnum(roster.Component.merkle_path)] = QM31.zero();
    try std.testing.expectError(
        error.ClaimSealMismatch,
        mutated_claims.validate(&manifest),
    );
}

test "R-012 generic adapter closes row 33 on every domain row" {
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    const invocation = fixtureInvocation(1);
    const row = try merkle_witness.logicalRow(invocation);
    const rows = [_]merkle_relation.Row{row};
    var interaction = try MerkleFramework.generatePrepared(
        std.testing.allocator,
        &relation_plan,
        &rows,
        log_size,
        &relations,
    );
    defer interaction.deinit(std.testing.allocator);

    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const component = try MerkleAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .merkle_path,
        log_size,
        .{},
        &relations,
        interaction.claimed_sum,
    );
    try std.testing.expectEqual(@as(usize, 13), component.nConstraints());
    try std.testing.expectEqual(@as(u32, log_size + 1), component.maxConstraintLogDegreeBound());

    const size: usize = 1 << log_size;
    for (0..size) |logical_row| {
        const committed = framework.committedRow(logical_row, log_size);
        const previous = framework.committedRow((logical_row + size - 1) % size, log_size);
        const logical = if (logical_row == 0)
            row
        else
            [_]M31{M31.zero()} ** merkle.LOGICAL_INPUT_COUNT;
        var current: [merkle.INTERACTION_BATCH_COUNT]QM31 = undefined;
        for (&current, 0..) |*value, batch|
            value.* = committedSecure(
                merkle.INTERACTION_BATCH_COUNT,
                &interaction.columns,
                batch,
                committed,
            );
        var roots: [MerkleAdapter.CONSTRAINT_COUNT_TOTAL]QM31 = undefined;
        try component.evaluateBaseRowInto(
            logical,
            current,
            committedSecure(
                merkle.INTERACTION_BATCH_COUNT,
                &interaction.columns,
                merkle.INTERACTION_BATCH_COUNT - 1,
                previous,
            ),
            &roots,
        );
        for (roots) |root| try std.testing.expect(root.isZero());
    }
}

test "R-012 generic adapter exposes a sealed outer proof gate" {
    var fri_definition = try fri_input.build(std.testing.allocator);
    defer fri_definition.deinit();
    const fri_plan = try fri_relation.authenticate(&fri_definition);
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    const row = try merkle_witness.logicalRow(fixtureInvocation(0));
    var interaction = try MerkleFramework.generatePrepared(
        std.testing.allocator,
        &relation_plan,
        &.{row},
        log_size,
        &relations,
    );
    defer interaction.deinit(std.testing.allocator);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(friGeometry(log_size));
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const fri_component = try FriAdapter.init(
        &fri_definition,
        fri_plan,
        &manifest,
        .fri_verifier_input,
        log_size,
        [_]M31{M31.zero()} ** FriAdapter.PARAMETER_COLUMN_COUNT,
        &relations,
        QM31.zero(),
    );
    const component = try MerkleAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .merkle_path,
        log_size,
        .{},
        &relations,
        interaction.claimed_sum,
    );

    var gate = try manifest_mod.ProofGate.init(&manifest);
    try std.testing.expectError(
        error.AdapterOrderMismatch,
        gate.append(&manifest, try component.binding(&manifest)),
    );
    try gate.append(&manifest, try fri_component.binding(&manifest));
    try gate.append(&manifest, try component.binding(&manifest));
    try gate.sealGate(&manifest);
    try gate.validate(&manifest);
    const verifier = try gate.verifierSlice();
    const prover = try gate.proverSlice();
    try std.testing.expectEqual(@as(usize, 2), verifier.len);
    try std.testing.expectEqual(@as(usize, 2), prover.len);
    for (verifier, prover) |verifier_component, prover_component_value| {
        try std.testing.expectEqual(
            verifier_component.nConstraints(),
            prover_component_value.nConstraints(),
        );
    }

    const components = core_components.Components{
        .components = verifier,
        .n_preprocessed_columns = manifest.total_preprocessed_columns,
    };
    var bounds = try components.columnLogSizes(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, manifest_mod.TREE_COUNT), bounds.items.len);
    try std.testing.expectEqual(@as(usize, manifest.total_preprocessed_columns), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, manifest.total_main_columns), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, manifest.total_interaction_columns), bounds.items[2].len);
}

test "R-012 generic adapter prepared domain loop is allocation-free" {
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const component = try MerkleAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .merkle_path,
        log_size,
        .{},
        &relations,
        QM31.zero(),
    );

    const eval_log_size = component.maxConstraintLogDegreeBound();
    const eval_size: usize = @as(usize, 1) << @intCast(eval_log_size);
    const zero_values = try std.testing.allocator.alloc(M31, eval_size);
    defer std.testing.allocator.free(zero_values);
    @memset(zero_values, M31.zero());
    const zero_poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = zero_values,
    };
    var preprocessed = [_]prover_component.Poly{};
    var main = [_]prover_component.Poly{zero_poly} **
        merkle.PHYSICAL_MAIN_COLUMN_COUNT;
    var interaction = [_]prover_component.Poly{zero_poly} **
        merkle.INTERACTION_COLUMN_COUNT;
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = measured.allocator();
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        allocator,
        &trace,
        &accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(
        eval_size * @sizeOf(QM31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources.worker_stack_bytes,
    );
    const allocation_count = measured.alloc_index;
    measured.fail_index = allocation_count;
    measured.resize_fail_index = measured.resize_index;
    var cancellation = prover_task_graph.CancellationToken{};
    var task_context = testTaskContext(prepared.context, &cancellation);
    try prepared.run(&task_context);
    try std.testing.expectEqual(allocation_count, measured.alloc_index);
    try std.testing.expect(!measured.has_induced_failure);
    measured.fail_index = std.math.maxInt(usize);
    measured.resize_fail_index = std.math.maxInt(usize);
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    for (0..result.len()) |row| try std.testing.expect(result.at(row).isZero());

    var cancelled_accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        std.testing.allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer cancelled_accumulator.deinit();
    var cancelled = (try prover.prepareConstraintQuotientsOnDomain(
        std.testing.allocator,
        &trace,
        &cancelled_accumulator,
    )).?;
    defer cancelled.deinit();
    var cancelled_token = prover_task_graph.CancellationToken{};
    _ = cancelled_token.request();
    var cancelled_context = testTaskContext(cancelled.context, &cancelled_token);
    try cancelled.run(&cancelled_context);
    var cancelled_result = try cancelled_accumulator.finalize();
    defer cancelled_result.deinit(std.testing.allocator);
    for (0..cancelled_result.len()) |row|
        try std.testing.expect(cancelled_result.at(row).isZero());

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareFailureCase,
        .{ &component, &trace, eval_log_size },
    );
}

test "R-012 row 29 keeps the pinned cubic quotient budget despite conservative profiling" {
    var definition = try fri_input.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try fri_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(friGeometry(log_size));
    const manifest = try builder.seal();
    const parameters = [_]M31{M31.zero()} ** fri_input.PARAMETER_COUNT;
    const component = try FriAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .fri_verifier_input,
        log_size,
        parameters,
        &relations,
        QM31.zero(),
    );
    try std.testing.expectEqual(@as(u32, log_size + 1), component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(
        @as(usize, fri_input.DIRECT_CONSTRAINT_COUNT + fri_input.INTERACTION_BATCH_COUNT),
        component.nConstraints(),
    );
}

test "R-012 one compiler-owned adapter factory admits all 34 typed logical rows" {
    const relations = universal.UniversalRelations.dummy();
    inline for (catalog.LOGICAL_ROWS) |entry|
        try admitTypedRow(entry.Air, entry.row, entry.requires_location, &relations);
}

test "R-012 universal wire lowering is identical to the dedicated row 30 plan" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const UniversalRelation = universal_binding.Binding(qm31_mul);
    const universal_plan = try UniversalRelation.authenticate(&definition);
    const dedicated_plan = try qm31_mul_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();

    var row: UniversalRelation.Row = undefined;
    for (&row, 0..) |*value, index|
        value.* = M31.fromU64(@as(u64, @intCast(index)) + 1);
    const actual = try universal_plan.preparedRowPairs(row, &relations);
    const wire_elements = relations.get(.recursion_wire);
    const wire_challenge = relation_challenges.RelationElements(6).init(
        wire_elements.z,
        wire_elements.alpha,
    );
    const expected = try dedicated_plan.rowPairs(
        &definition,
        row[0..qm31_mul.PHYSICAL_MAIN_COLUMN_COUNT].*,
        wire_challenge,
    );
    try expectPairArraysEqual(expected, actual);

    var secure_row: UniversalRelation.Runtime.SecureRow = undefined;
    for (&secure_row, row) |*secure, base| secure.* = QM31.fromBase(base);
    const secure = try universal_plan.preparedSecureRowPairs(
        secure_row,
        &relations,
    );
    try expectPairArraysEqual(expected, secure);
}

test "R-012 generic adapter verifier point path consumes manifest offsets" {
    try verifierPointCase(MerkleAdapter);
    const Verifier = @import("stwo_riscv_air_lang").modules.framework_universal_typed_verifier_component.ComponentForManifest(
        merkle,
        merkle_relation,
        @import("stwo_riscv_air_lang").modules.framework_universal_manifest_contract,
    );
    try verifierPointCase(Verifier);
}
