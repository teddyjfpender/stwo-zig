//! Real native PCS/FRI gate for typed universal-control row 0.
//!
//! This proves the standalone row component, including its authenticated
//! direct program and both source-exact framework LogUp transitions. It does
//! not claim universal relation closure or a recursively verified child proof;
//! those require the remaining 35 row adapters and the composition circuit.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const core_air_components = stwo_core.air.components;
const core_verifier = stwo_core.verifier;
const M31 = stwo_core.fields.m31.M31;
const pcs_core = stwo_core.pcs;
const prover_pcs = @import("stwo_prover_engine").pcs;

const recursion = frontend.recursion;
const air = recursion.air;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion.engine.Hasher,
    recursion.engine.MerkleChannel,
);
const ProofKind = air.control_witness.ProofKind;

test "typed recursion control native PCS FRI adapter independently verifies" {
    comptime @import("stwo_prover_api").assertProverEngine(Engine);
    const allocator = std.testing.allocator;
    const proof_kind: ProofKind = .segment_leaf;

    var schedules = try Schedules.init(allocator);
    defer schedules.deinit();
    var preprocessing = try air.control_witness.Preprocessed.init(
        allocator,
        &schedules.vm,
        &schedules.recursion,
    );
    defer preprocessing.deinit();
    var committed_preprocessed = try CommittedPreprocessed.init(
        allocator,
        &preprocessing,
        &schedules.vm,
        &schedules.recursion,
    );
    var committed_preprocessed_moved = false;
    defer if (!committed_preprocessed_moved)
        committed_preprocessed.deinit(allocator);

    var proving_definition = try air.control.build(allocator);
    defer proving_definition.deinit();
    const relation_plan = try air.control_relation.authenticate(
        &proving_definition,
    );
    const logical_rows = try allocator.alloc(
        air.control_relation.Row,
        preprocessing.rows.len,
    );
    defer allocator.free(logical_rows);
    for (logical_rows, preprocessing.rows) |*target, row| {
        target.* = air.control_witness.logicalRow(row, proof_kind);
    }

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = try stwo_core.fri.FriConfig.init(0, 1, 3),
    };
    var scheme = try Engine.init(allocator, config);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var proving_channel = Engine.Channel{};

    committed_preprocessed_moved = true;
    try commitBacked(
        air.control.PREPROCESSED_COLUMN_COUNT,
        &scheme,
        allocator,
        &committed_preprocessed.columns,
        committed_preprocessed.storage,
        preprocessing.log_size,
        &proving_channel,
    );
    // The first-tree optimization may be outstanding on a worker. Flush here
    // because relation challenges must be drawn after the root is absorbed,
    // exactly as the independent verifier's synchronous `commit` does.
    try Engine.flushPendingCommit(&scheme, allocator, &proving_channel);
    try std.testing.expectEqual(@as(usize, 1), scheme.trees.items.len);
    const expected_preprocessed_root = scheme.trees.items[0].root();

    air.control_component.mixStatementPrefix(
        &proving_channel,
        preprocessing.log_size,
        proof_kind,
    );
    const proving_relations = try air.universal_challenges.UniversalRelations.draw(
        allocator,
        &proving_channel,
    );
    const Framework = air.framework_interaction.Runtime(
        air.control_relation.Runtime,
    );
    var interaction = try Framework.generatePrepared(
        allocator,
        &relation_plan,
        logical_rows,
        preprocessing.log_size,
        &proving_relations,
    );
    var interaction_moved = false;
    defer if (!interaction_moved) interaction.deinit(allocator);
    const claimed_sum = interaction.claimed_sum;
    air.control_component.mixInteractionClaim(
        &proving_channel,
        preprocessing.log_size,
        claimed_sum,
    );

    interaction_moved = true;
    try commitBacked(
        air.control.INTERACTION_COLUMN_COUNT,
        &scheme,
        allocator,
        &interaction.columns,
        interaction.storage,
        preprocessing.log_size,
        &proving_channel,
    );

    const proving_component = try air.control_component.Component.init(
        &proving_definition,
        preprocessing.log_size,
        proof_kind,
        &proving_relations,
        claimed_sum,
    );
    const proving_components = [_]Engine.Component{
        proving_component.asProverComponent(),
    };
    scheme_moved = true;
    var extended = try Engine.prove(
        allocator,
        &proving_components,
        &proving_channel,
        scheme,
        .{},
    );
    defer extended.aux.deinit(allocator);
    var proof_moved = false;
    defer if (!proof_moved) extended.proof.deinit(allocator);

    const proof_size = extended.proof.sizeEstimate();
    const breakdown = extended.proof.sizeBreakdownEstimate();
    const proving_digest = proving_channel.digestWords();
    const proving_draws = proving_channel.n_draws;
    const commitments = extended.proof.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqual(@as(usize, 3), commitments.len);
    try std.testing.expect(std.meta.eql(
        expected_preprocessed_root,
        commitments[0],
    ));

    // Independent replay: rebuild the typed programs, draw a fresh relation
    // bundle from the verifier transcript, and use only verifier-owned public
    // inputs (mode, geometry, claimed sum, and preprocessing root).
    var verifier = try VerifierScheme.init(allocator, config);
    defer verifier.deinit(allocator);
    var verifier_channel = Engine.Channel{};
    const preprocessed_logs = [_]u32{preprocessing.log_size} **
        air.control.PREPROCESSED_COLUMN_COUNT;
    try verifier.commit(
        allocator,
        expected_preprocessed_root,
        &preprocessed_logs,
        &verifier_channel,
    );
    air.control_component.mixStatementPrefix(
        &verifier_channel,
        preprocessing.log_size,
        proof_kind,
    );
    const verifier_relations = try air.universal_challenges.UniversalRelations.draw(
        allocator,
        &verifier_channel,
    );
    assertRelationChallengesEqual(&proving_relations, &verifier_relations);
    air.control_component.mixInteractionClaim(
        &verifier_channel,
        preprocessing.log_size,
        claimed_sum,
    );
    const interaction_logs = [_]u32{preprocessing.log_size} **
        air.control.INTERACTION_COLUMN_COUNT;
    try verifier.commit(
        allocator,
        commitments[1],
        &interaction_logs,
        &verifier_channel,
    );

    var verifier_definition = try air.control.build(allocator);
    defer verifier_definition.deinit();
    const verifier_component = try air.control_component.Component.init(
        &verifier_definition,
        preprocessing.log_size,
        proof_kind,
        &verifier_relations,
        claimed_sum,
    );
    const verifier_components = [_]core_air_components.Component{
        verifier_component.asVerifierComponent(),
    };
    proof_moved = true;
    try core_verifier.verify(
        recursion.engine.Hasher,
        recursion.engine.MerkleChannel,
        allocator,
        &verifier_components,
        &verifier_channel,
        &verifier,
        extended.proof,
    );

    try std.testing.expectEqual(proving_draws, verifier_channel.n_draws);
    try std.testing.expect(std.meta.eql(
        proving_digest,
        verifier_channel.digestWords(),
    ));
    try std.testing.expect(proof_size != 0);
    std.debug.print(
        "\n  R-012 typed control proof: rows={d} log={d} proof_estimate={d} " ++
            "oods={d} queries={d} fri={d}+{d} trace={d} draws={d} transcript={any}\n",
        .{
            preprocessing.rows.len,
            preprocessing.log_size,
            proof_size,
            breakdown.oods_samples,
            breakdown.queries_values,
            breakdown.fri_samples,
            breakdown.fri_decommitments,
            breakdown.trace_decommitments,
            proving_draws,
            proving_digest,
        },
    );
}

const Schedules = struct {
    vm: air.verifier_schedule.Plan,
    recursion: air.verifier_schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Schedules {
        const shape = try controlShape();
        var vm = try air.verifier_schedule.Plan.init(
            allocator,
            try air.verifier_schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try air.verifier_schedule.Plan.init(
                allocator,
                try air.verifier_schedule.ProgramSpec.init(
                    .recursion,
                    3,
                    0,
                    3,
                    2,
                ),
                shape,
            ),
        };
    }

    fn deinit(self: *Schedules) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

const CommittedPreprocessed = struct {
    storage: []M31,
    columns: [air.control.PREPROCESSED_COLUMN_COUNT][]M31,

    fn init(
        allocator: std.mem.Allocator,
        preprocessing: *const air.control_witness.Preprocessed,
        vm: *const air.verifier_schedule.Plan,
        recursion_plan: *const air.verifier_schedule.Plan,
    ) !CommittedPreprocessed {
        const size = @as(usize, 1) << @intCast(preprocessing.log_size);
        const value_count = air.control.PREPROCESSED_COLUMN_COUNT * size;
        const logical_storage = try allocator.alloc(M31, value_count);
        defer allocator.free(logical_storage);
        var logical_columns: [air.control.PREPROCESSED_COLUMN_COUNT][]M31 =
            undefined;
        for (&logical_columns, 0..) |*column, index| {
            column.* = logical_storage[index * size ..][0..size];
        }
        try preprocessing.generateInto(
            &logical_columns,
            vm,
            recursion_plan,
        );

        const storage = try allocator.alloc(M31, value_count);
        errdefer allocator.free(storage);
        var columns: [air.control.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&columns, 0..) |*column, index| {
            column.* = storage[index * size ..][0..size];
        }
        for (0..size) |logical_row| {
            const committed_row = air.framework_interaction.committedRow(
                logical_row,
                preprocessing.log_size,
            );
            for (columns, logical_columns) |column, logical_column| {
                column[committed_row] = logical_column[logical_row];
            }
        }
        return .{ .storage = storage, .columns = columns };
    }

    fn deinit(self: *CommittedPreprocessed, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }
};

/// Transfers one contiguous column arena into the proof transaction. This
/// exercises the no-copy backing-buffer seam used by high-throughput provers;
/// the scheme consumes descriptors and storage on both success and failure.
fn commitBacked(
    comptime column_count: usize,
    scheme: *Engine.Scheme,
    allocator: std.mem.Allocator,
    columns: *const [column_count][]M31,
    storage: []M31,
    log_size: u32,
    channel: *Engine.Channel,
) !void {
    const evaluations = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        column_count,
    );
    var submitted = false;
    errdefer if (!submitted) {
        allocator.free(evaluations);
        allocator.free(storage);
    };
    for (evaluations, columns) |*evaluation, column| {
        evaluation.* = .{ .log_size = log_size, .values = column };
    }
    const backing_buffers = try allocator.alloc([]M31, 1);
    errdefer if (!submitted) allocator.free(backing_buffers);
    backing_buffers[0] = storage;
    submitted = true;
    try Engine.commitWithBacking(
        scheme,
        allocator,
        evaluations,
        backing_buffers,
        null,
        channel,
    );
}

fn controlShape() !recursion.fixed_profile.ProofShapeV1 {
    const fri = try recursion.fixed_profile.FriSchedule.init(
        8,
        recursion.protocol.PCS_CONFIG.fri_config,
    );
    return .{
        .air_program_id = recursion.poseidon2_channel.hashBytes(
            "control-air",
            0x5450,
        ),
        .preprocessing_id = recursion.poseidon2_channel.hashBytes(
            "control-preprocessing",
            0x5450,
        ),
        .table_layout_id = recursion.poseidon2_channel.hashBytes(
            "control-layout",
            0x5450,
        ),
        .table_count = 16,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .preprocessed_column_count = 4,
        .tree_column_counts = .{ 4, 4, 4, 4 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1024,
        .fri = fri,
    };
}

fn assertRelationChallengesEqual(
    proving: *const air.universal_challenges.UniversalRelations,
    verifying: *const air.universal_challenges.UniversalRelations,
) void {
    for (proving.elements, verifying.elements) |left, right| {
        std.debug.assert(left.z.eql(right.z));
        std.debug.assert(left.alpha.eql(right.alpha));
        std.debug.assert(left.arity == right.arity);
    }
}
