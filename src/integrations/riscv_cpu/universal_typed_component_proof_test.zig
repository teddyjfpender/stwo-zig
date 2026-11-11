//! Real native PCS/FRI gate for the manifest-driven universal adapter.
//!
//! Rows 29 and 33 deliberately exercise disjoint geometry: the FRI input row
//! owns verifier preprocessing and proof-kind parameters, while the Merkle
//! path row owns a wide main trace and no preprocessing.  Proving them in one
//! ordered manifest checks global tree offsets, claim order, OODS masks, and
//! the allocation-free prepared evaluator through the actual outer engine.

const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const core_verifier = stwo_core.verifier;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const pcs_core = stwo_core.pcs;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_air = @import("stwo_prover_engine").air.component_prover;
const prover_circle = @import("stwo_prover_engine").poly.circle;
const recursion = frontend.recursion;
const recursion_air = recursion.air;
const recursion_engine = recursion.engine;
const manifest_mod = recursion_air.universal_adapter_manifest;
const adapter = recursion_air.universal_typed_component;
const universal = recursion_air.universal_challenges;
const framework = recursion_air.framework_interaction;
const fri_input = recursion_air.fri_verifier_input;
const fri_relation = recursion_air.fri_verifier_input_relation;
const merkle = recursion_air.merkle_path;
const merkle_relation = recursion_air.merkle_path_relation;
const merkle_witness = recursion_air.merkle_path_witness;
const fri_leaf = recursion_air.fri_merkle_leaf;
const fri_leaf_relation = recursion_air.fri_merkle_leaf_relation;
const fri_leaf_witness = recursion_air.fri_merkle_leaf_witness;
const fri_node = recursion_air.fri_merkle_node;
const fri_node_relation = recursion_air.fri_merkle_node_relation;
const fri_node_witness = recursion_air.fri_merkle_node_witness;
const test_support = @import("universal_typed_component_proof_test_support.zig");

const Engine = recursion_engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion_engine.Hasher,
    recursion_engine.MerkleChannel,
);
const FriAdapter = adapter.Component(fri_input, fri_relation);
const MerkleAdapter = adapter.Component(merkle, merkle_relation);
const MerkleFramework = framework.Runtime(merkle_relation.Runtime);
const FriLeafAdapter = adapter.Component(fri_leaf, fri_leaf_relation);
const FriLeafFramework = framework.Runtime(fri_leaf_relation.Runtime);
const FriNodeAdapter = adapter.Component(fri_node, fri_node_relation);
const FriNodeFramework = framework.Runtime(fri_node_relation.Runtime);
const LOG_SIZE: u32 = 4;
const PP_COUNT = fri_input.PREPROCESSED_COLUMN_COUNT +
    merkle.PREPROCESSED_COLUMN_COUNT;
const MAIN_COUNT = fri_input.PHYSICAL_MAIN_COLUMN_COUNT +
    merkle.PHYSICAL_MAIN_COLUMN_COUNT;
const INTERACTION_COUNT = fri_input.INTERACTION_COLUMN_COUNT +
    merkle.INTERACTION_COLUMN_COUNT;

const LEAF_LAYERS = [_]fri_leaf_witness.LayerProfile{
    .{ .width = 16, .tree_height = 7 },
    .{ .width = 4, .tree_height = 3 },
    .{ .width = 2, .tree_height = 3 },
};
const LEAF_PROFILE = fri_leaf_witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 9,
    .layers = &LEAF_LAYERS,
};
const claimsFor = test_support.claimsFor;
const leafClaims = test_support.leafClaims;
const nodeClaims = test_support.nodeClaims;
const friLeafParameters = test_support.friLeafParameters;
const LeafOpeningFixture = test_support.LeafOpeningFixture;
const splitFlatColumns = test_support.splitFlatColumns;
const commitOrderStorage = test_support.commitOrderStorage;
const validateLeafRows = test_support.validateLeafRows;
const validateNodeRows = test_support.validateNodeRows;
const diagnoseComposition = test_support.diagnoseComposition;
const diagnoseCompositionAtLog = test_support.diagnoseCompositionAtLog;
const evaluateMasks = test_support.evaluateMasks;
const commitZeroTree = test_support.commitZeroTree;
const commitTree = test_support.commitTree;
const fixtureInvocation = test_support.fixtureInvocation;
const fixtureDigest = test_support.fixtureDigest;
const assertRelationChallengesEqual = test_support.assertRelationChallengesEqual;

test "R-012 active FRI Merkle leaf adapter proves and independently verifies" {
    const allocator = std.testing.allocator;
    const reference = try fri_leaf_witness.Reference.seal(
        LEAF_PROFILE,
        LEAF_PROFILE,
    );
    var preprocessing = try fri_leaf_witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
    const log_size = preprocessing.log_size;
    const row_count = @as(usize, 1) << @intCast(log_size);
    var openings = try LeafOpeningFixture.init(allocator);
    defer openings.deinit();
    const opening = fri_leaf_witness.OpeningWitness{
        .segment_leaf = openings.opening(0),
    };

    var definition = try fri_leaf.build(allocator);
    defer definition.deinit();
    const relation_plan = try fri_leaf_relation.authenticate(&definition);
    const binding_value = try fri_leaf_witness.Binding.canonical(&definition);
    const executor = try fri_leaf_witness.Executor.init(&definition, &binding_value);
    var manifest_builder = manifest_mod.Builder{};
    _ = try manifest_builder.append(FriLeafAdapter.manifestGeometry(
        .fri_merkle_leaf,
        log_size,
    ));
    const manifest = try manifest_builder.seal();

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var scheme = try Engine.init(allocator, config);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};

    const pp_storage = try allocator.alloc(
        M31,
        fri_leaf.PREPROCESSED_COLUMN_COUNT * row_count,
    );
    var pp_columns: [fri_leaf.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitFlatColumns(row_count, pp_storage, &pp_columns);
    try executor.generatePreprocessedInto(&preprocessing, reference, &pp_columns);
    const pp_committed = try commitOrderStorage(
        fri_leaf.PREPROCESSED_COLUMN_COUNT,
        allocator,
        pp_storage,
        log_size,
    );
    allocator.free(pp_storage);
    try commitTree(
        fri_leaf.PREPROCESSED_COLUMN_COUNT,
        &scheme,
        allocator,
        pp_committed,
        log_size,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const main_storage = try allocator.alloc(
        M31,
        fri_leaf.PHYSICAL_MAIN_COLUMN_COUNT * row_count,
    );
    var main_columns: [fri_leaf.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitFlatColumns(row_count, main_storage, &main_columns);
    try executor.generateMainInto(
        &preprocessing,
        reference,
        &main_columns,
        opening,
    );
    const main_committed = try commitOrderStorage(
        fri_leaf.PHYSICAL_MAIN_COLUMN_COUNT,
        allocator,
        main_storage,
        log_size,
    );
    allocator.free(main_storage);
    try commitTree(
        fri_leaf.PHYSICAL_MAIN_COLUMN_COUNT,
        &scheme,
        allocator,
        main_committed,
        log_size,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    try manifest.mixStatementPrefix(&channel);
    const proving_relations = try universal.UniversalRelations.draw(allocator, &channel);
    const rows = try allocator.alloc(fri_leaf_relation.Row, preprocessing.rows.len);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| row.* = try fri_leaf_witness.logicalRow(
        reference,
        &preprocessing,
        index,
        opening,
    );
    var generated = try FriLeafFramework.generatePrepared(
        allocator,
        &relation_plan,
        rows,
        log_size,
        &proving_relations,
    );
    defer generated.deinit(allocator);
    const interaction_storage = try allocator.alloc(
        M31,
        fri_leaf.INTERACTION_COLUMN_COUNT * row_count,
    );
    for (generated.columns, 0..) |column, index|
        @memcpy(interaction_storage[index * row_count ..][0..row_count], column);
    var claims = try leafClaims(&manifest, generated.claimed_sum);
    try claims.mixInteractionClaims(&manifest, &channel);
    try commitTree(
        fri_leaf.INTERACTION_COLUMN_COUNT,
        &scheme,
        allocator,
        interaction_storage,
        log_size,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const parameters = friLeafParameters(.segment_leaf);
    var component = try FriLeafAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .fri_merkle_leaf,
        log_size,
        parameters,
        &proving_relations,
        generated.claimed_sum,
    );
    try validateLeafRows(&component, rows, &generated.columns, log_size);
    try diagnoseComposition(allocator, &scheme, &component, &manifest);
    // A component-only proof does not exercise the accumulator's heterogeneous
    // degree lifting.  Force the same four-bit gap seen in the universal outer
    // assembly so an under-declared quotient degree fails here in seconds.
    try diagnoseCompositionAtLog(
        allocator,
        &scheme,
        &component,
        &manifest,
        component.maxConstraintLogDegreeBound() + 4,
    );
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try gate.append(&manifest, try component.binding(&manifest));
    try gate.sealGate(&manifest);
    scheme_moved = true;
    var extended = Engine.prove(
        allocator,
        try gate.proverSlice(),
        &channel,
        scheme,
        .{},
    ) catch |err| {
        std.debug.print("  active row-25 proof failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer extended.aux.deinit(allocator);
    var proof_moved = false;
    defer if (!proof_moved) extended.proof.deinit(allocator);

    const commitments = extended.proof.commitment_scheme_proof.commitments.items;
    var verifier_scheme = try VerifierScheme.init(allocator, config);
    defer verifier_scheme.deinit(allocator);
    var verifier_channel = Engine.Channel{};
    const pp_logs = [_]u32{log_size} ** fri_leaf.PREPROCESSED_COLUMN_COUNT;
    try verifier_scheme.commit(allocator, commitments[0], &pp_logs, &verifier_channel);
    const main_logs = [_]u32{log_size} ** fri_leaf.PHYSICAL_MAIN_COLUMN_COUNT;
    try verifier_scheme.commit(allocator, commitments[1], &main_logs, &verifier_channel);
    try manifest.mixStatementPrefix(&verifier_channel);
    const verifier_relations = try universal.UniversalRelations.draw(
        allocator,
        &verifier_channel,
    );
    var verifier_claims = try leafClaims(&manifest, generated.claimed_sum);
    try verifier_claims.mixInteractionClaims(&manifest, &verifier_channel);
    const interaction_logs = [_]u32{log_size} ** fri_leaf.INTERACTION_COLUMN_COUNT;
    try verifier_scheme.commit(
        allocator,
        commitments[2],
        &interaction_logs,
        &verifier_channel,
    );
    var verifier_definition = try fri_leaf.build(allocator);
    defer verifier_definition.deinit();
    const verifier_plan = try fri_leaf_relation.authenticate(&verifier_definition);
    var verifier_component = try FriLeafAdapter.init(
        &verifier_definition,
        verifier_plan,
        &manifest,
        .fri_merkle_leaf,
        log_size,
        parameters,
        &verifier_relations,
        generated.claimed_sum,
    );
    var verifier_gate = try manifest_mod.ProofGate.init(&manifest);
    try verifier_gate.append(
        &manifest,
        try verifier_component.binding(&manifest),
    );
    try verifier_gate.sealGate(&manifest);
    proof_moved = true;
    try core_verifier.verify(
        recursion_engine.Hasher,
        recursion_engine.MerkleChannel,
        allocator,
        try verifier_gate.verifierSlice(),
        &verifier_channel,
        &verifier_scheme,
        extended.proof,
    );
}

test "R-012 active FRI Merkle node adapter proves and independently verifies" {
    const allocator = std.testing.allocator;
    const reference = try fri_node_witness.Reference.seal(
        LEAF_PROFILE,
        LEAF_PROFILE,
    );
    var preprocessing = try fri_node_witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
    const log_size = preprocessing.log_size;
    const row_count = @as(usize, 1) << @intCast(log_size);
    var openings = try LeafOpeningFixture.init(allocator);
    defer openings.deinit();
    const opening = fri_node_witness.OpeningWitness{
        .segment_leaf = openings.opening(0),
    };

    var definition = try fri_node.build(allocator);
    defer definition.deinit();
    const relation_plan = try fri_node_relation.authenticate(&definition);
    const binding_value = try fri_node_witness.Binding.canonical(&definition);
    const executor = try fri_node_witness.Executor.init(&definition, &binding_value);
    var manifest_builder = manifest_mod.Builder{};
    _ = try manifest_builder.append(FriNodeAdapter.manifestGeometry(
        .fri_merkle_node,
        log_size,
    ));
    const manifest = try manifest_builder.seal();

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var scheme = try Engine.init(allocator, config);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};

    const pp_storage = try allocator.alloc(
        M31,
        fri_node.PREPROCESSED_COLUMN_COUNT * row_count,
    );
    var pp_columns: [fri_node.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitFlatColumns(row_count, pp_storage, &pp_columns);
    try executor.generatePreprocessedInto(&preprocessing, reference, &pp_columns);
    const pp_committed = try commitOrderStorage(
        fri_node.PREPROCESSED_COLUMN_COUNT,
        allocator,
        pp_storage,
        log_size,
    );
    allocator.free(pp_storage);
    try commitTree(
        fri_node.PREPROCESSED_COLUMN_COUNT,
        &scheme,
        allocator,
        pp_committed,
        log_size,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const main_storage = try allocator.alloc(
        M31,
        fri_node.PHYSICAL_MAIN_COLUMN_COUNT * row_count,
    );
    var main_columns: [fri_node.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitFlatColumns(row_count, main_storage, &main_columns);
    try executor.generateMainInto(
        &preprocessing,
        reference,
        &main_columns,
        opening,
    );
    const main_committed = try commitOrderStorage(
        fri_node.PHYSICAL_MAIN_COLUMN_COUNT,
        allocator,
        main_storage,
        log_size,
    );
    allocator.free(main_storage);
    try commitTree(
        fri_node.PHYSICAL_MAIN_COLUMN_COUNT,
        &scheme,
        allocator,
        main_committed,
        log_size,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    try manifest.mixStatementPrefix(&channel);
    const proving_relations = try universal.UniversalRelations.draw(allocator, &channel);
    const rows = try allocator.alloc(fri_node_relation.Row, preprocessing.rows.len);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| row.* = try fri_node_witness.logicalRow(
        reference,
        &preprocessing,
        index,
        opening,
    );
    var generated = try FriNodeFramework.generatePrepared(
        allocator,
        &relation_plan,
        rows,
        log_size,
        &proving_relations,
    );
    defer generated.deinit(allocator);
    const interaction_storage = try allocator.alloc(
        M31,
        fri_node.INTERACTION_COLUMN_COUNT * row_count,
    );
    for (generated.columns, 0..) |column, index|
        @memcpy(interaction_storage[index * row_count ..][0..row_count], column);
    var claims = try nodeClaims(&manifest, generated.claimed_sum);
    try claims.mixInteractionClaims(&manifest, &channel);
    try commitTree(
        fri_node.INTERACTION_COLUMN_COUNT,
        &scheme,
        allocator,
        interaction_storage,
        log_size,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    const selectors = fri_node_witness.ProofKind.segment_leaf.selectors();
    const parameters = selectors[0..2].*;
    var component = try FriNodeAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .fri_merkle_node,
        log_size,
        parameters,
        &proving_relations,
        generated.claimed_sum,
    );
    try validateNodeRows(&component, rows, &generated.columns, log_size);
    try diagnoseComposition(allocator, &scheme, &component, &manifest);
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try gate.append(&manifest, try component.binding(&manifest));
    try gate.sealGate(&manifest);
    scheme_moved = true;
    var extended = Engine.prove(
        allocator,
        try gate.proverSlice(),
        &channel,
        scheme,
        .{},
    ) catch |err| {
        std.debug.print("  active row-26 proof failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer extended.aux.deinit(allocator);
    var proof_moved = false;
    defer if (!proof_moved) extended.proof.deinit(allocator);

    const commitments = extended.proof.commitment_scheme_proof.commitments.items;
    var verifier_scheme = try VerifierScheme.init(allocator, config);
    defer verifier_scheme.deinit(allocator);
    var verifier_channel = Engine.Channel{};
    const pp_logs = [_]u32{log_size} ** fri_node.PREPROCESSED_COLUMN_COUNT;
    try verifier_scheme.commit(allocator, commitments[0], &pp_logs, &verifier_channel);
    const main_logs = [_]u32{log_size} ** fri_node.PHYSICAL_MAIN_COLUMN_COUNT;
    try verifier_scheme.commit(allocator, commitments[1], &main_logs, &verifier_channel);
    try manifest.mixStatementPrefix(&verifier_channel);
    const verifier_relations = try universal.UniversalRelations.draw(
        allocator,
        &verifier_channel,
    );
    var verifier_claims = try nodeClaims(&manifest, generated.claimed_sum);
    try verifier_claims.mixInteractionClaims(&manifest, &verifier_channel);
    const interaction_logs = [_]u32{log_size} ** fri_node.INTERACTION_COLUMN_COUNT;
    try verifier_scheme.commit(
        allocator,
        commitments[2],
        &interaction_logs,
        &verifier_channel,
    );
    var verifier_definition = try fri_node.build(allocator);
    defer verifier_definition.deinit();
    const verifier_plan = try fri_node_relation.authenticate(&verifier_definition);
    var verifier_component = try FriNodeAdapter.init(
        &verifier_definition,
        verifier_plan,
        &manifest,
        .fri_merkle_node,
        log_size,
        parameters,
        &verifier_relations,
        generated.claimed_sum,
    );
    var verifier_gate = try manifest_mod.ProofGate.init(&manifest);
    try verifier_gate.append(
        &manifest,
        try verifier_component.binding(&manifest),
    );
    try verifier_gate.sealGate(&manifest);
    proof_moved = true;
    try core_verifier.verify(
        recursion_engine.Hasher,
        recursion_engine.MerkleChannel,
        allocator,
        try verifier_gate.verifierSlice(),
        &verifier_channel,
        &verifier_scheme,
        extended.proof,
    );
}

test "R-012 manifest-driven rows 29 and 33 prove and independently verify" {
    const allocator = std.testing.allocator;
    comptime @import("stwo_prover_api").assertProverEngine(Engine);

    var manifest_builder = manifest_mod.Builder{};
    _ = try manifest_builder.append(FriAdapter.manifestGeometry(
        .fri_verifier_input,
        LOG_SIZE,
    ));
    _ = try manifest_builder.append(MerkleAdapter.manifestGeometry(
        .merkle_path,
        LOG_SIZE,
    ));
    const manifest = try manifest_builder.seal();
    try std.testing.expectEqual(@as(u32, PP_COUNT), manifest.total_preprocessed_columns);
    try std.testing.expectEqual(@as(u32, MAIN_COUNT), manifest.total_main_columns);
    try std.testing.expectEqual(
        @as(u32, INTERACTION_COUNT),
        manifest.total_interaction_columns,
    );

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var scheme = try Engine.init(allocator, config);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var proving_channel = Engine.Channel{};

    try commitZeroTree(PP_COUNT, &scheme, allocator, LOG_SIZE, &proving_channel);
    try Engine.flushPendingCommit(&scheme, allocator, &proving_channel);
    const merkle_row = try merkle_witness.logicalRow(fixtureInvocation(1));
    const row_count = @as(usize, 1) << @intCast(LOG_SIZE);
    const main_storage = try allocator.alloc(M31, MAIN_COUNT * row_count);
    @memset(main_storage, M31.zero());
    const main_row = framework.committedRow(0, LOG_SIZE);
    for (merkle_row, 0..) |value, column| {
        main_storage[
            (fri_input.PHYSICAL_MAIN_COLUMN_COUNT + column) *
                row_count + main_row
        ] = value;
    }
    try commitTree(
        MAIN_COUNT,
        &scheme,
        allocator,
        main_storage,
        LOG_SIZE,
        &proving_channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &proving_channel);
    try manifest.mixStatementPrefix(&proving_channel);
    const proving_relations = try universal.UniversalRelations.draw(
        allocator,
        &proving_channel,
    );
    var proving_merkle_definition = try merkle.build(allocator);
    defer proving_merkle_definition.deinit();
    const proving_merkle_plan = try merkle_relation.authenticate(
        &proving_merkle_definition,
    );
    var merkle_interaction = try MerkleFramework.generatePrepared(
        allocator,
        &proving_merkle_plan,
        &.{merkle_row},
        LOG_SIZE,
        &proving_relations,
    );
    defer merkle_interaction.deinit(allocator);
    try std.testing.expect(!merkle_interaction.claimed_sum.isZero());
    var proving_claims = try claimsFor(
        &manifest,
        merkle_interaction.claimed_sum,
    );
    try proving_claims.mixInteractionClaims(&manifest, &proving_channel);
    const interaction_storage = try allocator.alloc(
        M31,
        INTERACTION_COUNT * row_count,
    );
    @memset(interaction_storage, M31.zero());
    for (merkle_interaction.columns, 0..) |column, local_column| {
        @memcpy(
            interaction_storage[(fri_input.INTERACTION_COLUMN_COUNT + local_column) *
                row_count ..][0..row_count],
            column,
        );
    }
    try commitTree(
        INTERACTION_COUNT,
        &scheme,
        allocator,
        interaction_storage,
        LOG_SIZE,
        &proving_channel,
    );

    var fri_definition = try fri_input.build(allocator);
    defer fri_definition.deinit();
    const fri_plan = try fri_relation.authenticate(&fri_definition);
    const fri_component = try FriAdapter.init(
        &fri_definition,
        fri_plan,
        &manifest,
        .fri_verifier_input,
        LOG_SIZE,
        [_]M31{M31.zero()} ** FriAdapter.PARAMETER_COLUMN_COUNT,
        &proving_relations,
        QM31.zero(),
    );
    const merkle_component = try MerkleAdapter.init(
        &proving_merkle_definition,
        proving_merkle_plan,
        &manifest,
        .merkle_path,
        LOG_SIZE,
        .{},
        &proving_relations,
        merkle_interaction.claimed_sum,
    );
    var proving_gate = try manifest_mod.ProofGate.init(&manifest);
    try proving_gate.append(&manifest, try fri_component.binding(&manifest));
    try proving_gate.append(&manifest, try merkle_component.binding(&manifest));
    try proving_gate.sealGate(&manifest);
    const proving_components = try proving_gate.proverSlice();

    scheme_moved = true;
    var extended = try Engine.prove(
        allocator,
        proving_components,
        &proving_channel,
        scheme,
        .{},
    );
    defer extended.aux.deinit(allocator);
    var proof_moved = false;
    defer if (!proof_moved) extended.proof.deinit(allocator);
    const proof_size = extended.proof.sizeEstimate();
    const commitments = extended.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(@as(usize, manifest_mod.TREE_COUNT + 1), commitments.len);

    // Independent replay constructs fresh compiler programs and relation plans;
    // only the fixed manifest, claims, roots, and protocol configuration cross
    // the boundary from the prover.
    var verifier_scheme = try VerifierScheme.init(allocator, config);
    defer verifier_scheme.deinit(allocator);
    var verifier_channel = Engine.Channel{};
    const pp_logs = [_]u32{LOG_SIZE} ** PP_COUNT;
    try verifier_scheme.commit(
        allocator,
        commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
        &pp_logs,
        &verifier_channel,
    );
    const main_logs = [_]u32{LOG_SIZE} ** MAIN_COUNT;
    try verifier_scheme.commit(
        allocator,
        commitments[manifest_mod.MAIN_TREE_INDEX],
        &main_logs,
        &verifier_channel,
    );
    try manifest.mixStatementPrefix(&verifier_channel);
    const verifier_relations = try universal.UniversalRelations.draw(
        allocator,
        &verifier_channel,
    );
    assertRelationChallengesEqual(&proving_relations, &verifier_relations);
    var verifier_claims = try claimsFor(
        &manifest,
        merkle_interaction.claimed_sum,
    );
    try verifier_claims.mixInteractionClaims(&manifest, &verifier_channel);
    const interaction_logs = [_]u32{LOG_SIZE} ** INTERACTION_COUNT;
    try verifier_scheme.commit(
        allocator,
        commitments[manifest_mod.INTERACTION_TREE_INDEX],
        &interaction_logs,
        &verifier_channel,
    );

    var verifier_fri_definition = try fri_input.build(allocator);
    defer verifier_fri_definition.deinit();
    const verifier_fri_plan = try fri_relation.authenticate(
        &verifier_fri_definition,
    );
    var verifier_merkle_definition = try merkle.build(allocator);
    defer verifier_merkle_definition.deinit();
    const verifier_merkle_plan = try merkle_relation.authenticate(
        &verifier_merkle_definition,
    );
    const verifier_fri_component = try FriAdapter.init(
        &verifier_fri_definition,
        verifier_fri_plan,
        &manifest,
        .fri_verifier_input,
        LOG_SIZE,
        [_]M31{M31.zero()} ** FriAdapter.PARAMETER_COLUMN_COUNT,
        &verifier_relations,
        QM31.zero(),
    );
    const verifier_merkle_component = try MerkleAdapter.init(
        &verifier_merkle_definition,
        verifier_merkle_plan,
        &manifest,
        .merkle_path,
        LOG_SIZE,
        .{},
        &verifier_relations,
        merkle_interaction.claimed_sum,
    );
    var verifier_gate = try manifest_mod.ProofGate.init(&manifest);
    try verifier_gate.append(
        &manifest,
        try verifier_fri_component.binding(&manifest),
    );
    try verifier_gate.append(
        &manifest,
        try verifier_merkle_component.binding(&manifest),
    );
    try verifier_gate.sealGate(&manifest);
    const verifier_components = try verifier_gate.verifierSlice();

    proof_moved = true;
    try core_verifier.verify(
        recursion_engine.Hasher,
        recursion_engine.MerkleChannel,
        allocator,
        verifier_components,
        &verifier_channel,
        &verifier_scheme,
        extended.proof,
    );
    try std.testing.expect(proof_size != 0);
    try std.testing.expectEqual(proving_channel.n_draws, verifier_channel.n_draws);
    try std.testing.expect(std.meta.eql(
        proving_channel.digestWords(),
        verifier_channel.digestWords(),
    ));
    std.debug.print(
        "\n  R-012 universal adapter proof: rows=16 adapters=2 " ++
            "columns={d}+{d}+{d} constraints={d} proof_estimate={d} " ++
            "draws={d} transcript={any}\n",
        .{
            PP_COUNT,
            MAIN_COUNT,
            INTERACTION_COUNT,
            manifest.total_constraints,
            proof_size,
            proving_channel.n_draws,
            proving_channel.digestWords(),
        },
    );
}
