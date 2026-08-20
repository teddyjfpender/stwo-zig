const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const bundle = @import("segment_leaf_outer_bundle.zig");
const fixed_wire = @import("fixed_wire.zig");
const fixed_profile = @import("fixed_profile.zig");
const leaf_authority = @import("segment_leaf_authority.zig");
const public_source_mod = @import("segment_public_outer_source.zig");
const statement_source = @import("segment_statement_outer_source.zig");
const transcript_source_mod = @import("segment_transcript_outer_source.zig");
const transcript_witness = @import("segment_transcript_witness.zig");
const transcript_program = @import("transcript_program.zig");
const vm_claim = @import("vm_public_claim.zig");
const vm_semantics = @import("vm_public_semantics_circuit.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const public_data_mod = @import("../air/public_data.zig");
const native_relations_mod = @import("../air/relation_challenges.zig");
const air = @import("air/mod.zig");
const manifest_mod = air.universal_adapter_manifest;
const lowering = air.verifier_arithmetic_lowering;
const framework = air.framework_interaction;
const statement_relation = air.statement_semantics_input_relation;
const statement_witness = air.statement_semantics_input_witness;
const claim_semantics_relation = air.vm_public_claim_semantics_input_relation;
const public_logup_relation = air.vm_public_logup_input_relation;
const roster = air.universal_roster;
const schedule = air.verifier_schedule;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;

const dimensions = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 1,
    .sampled_value_count = 4,
    .queried_value_count = 12,
    .trace_path_count = 12,
    .fri_layer_count = 1,
    .query_count = 2,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 5,
};

test "R-012 segment-leaf bundle pins ownership and hot-path cost" {
    try std.testing.expectEqual(@as(usize, 18), bundle.PREFIX_ROW_COUNT);
    try std.testing.expectEqual(@as(usize, 35), bundle.SHARED_PROVIDER_ROW);
    try std.testing.expectEqual(@as(usize, 19), bundle.OWNED_ROW_COUNT);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 1, 1, 43 },
        &bundle.HOT_TREE_HEAP_ALLOCATIONS,
    );
    try std.testing.expectEqual(
        @as(usize, 45),
        bundle.HOT_ALL_TREES_HEAP_ALLOCATIONS,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        bundle.HOT_ALL_TREES_PAIR_AUTHENTICATIONS,
    );
}

test "R-012 segment-leaf bundle lowering lanes match their source wire claims" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const outer = try fixture.outerBundle();
    const lanes = outer.loweringLanes();
    const relations = universal.UniversalRelations.dummy();

    const statement_rows = try allocator.alloc(
        statement_relation.Row,
        fixture.statement_authority.statement_semantics_preprocessing.rows.len,
    );
    defer allocator.free(statement_rows);
    for (
        statement_rows,
        fixture.statement_authority.statement_semantics_preprocessing.rows,
        fixture.statement_prepared.statement_values,
    ) |*row, preprocessing, value| row.* = try statement_witness.logicalRow(
        preprocessing,
        value,
        .segment_leaf,
    );
    const statement_claim = try sourceWireClaim(
        statement_relation.Runtime,
        allocator,
        &fixture.statement_authority.statement_semantics_relation,
        statement_rows,
        statement_source.STATEMENT_SEMANTICS_LOG_SIZE,
        &relations,
    );
    const claim_semantics_claim = try sourceWireClaim(
        claim_semantics_relation.Runtime,
        allocator,
        &fixture.public_source.owners.claim_semantics.relation,
        fixture.public_prepared.claim_semantics_rows,
        fixture.public_source.log_sizes[3],
        &relations,
    );
    const public_logup_claim = try sourceWireClaim(
        public_logup_relation.Runtime,
        allocator,
        &fixture.public_source.owners.public_logup.relation,
        fixture.public_prepared.public_logup_rows,
        fixture.public_source.log_sizes[4],
        &relations,
    );

    const public_evaluations = fixture.public_prepared.loweringEvaluations(
        &fixture.public_source,
    );
    try expectLaneInputParity(
        allocator,
        lanes[0],
        fixture.statement_prepared.loweringEvaluation(),
        statement_claim,
        &relations,
    );
    try expectLaneInputParity(
        allocator,
        lanes[1],
        public_evaluations[0],
        claim_semantics_claim,
        &relations,
    );
    try expectLaneInputParity(
        allocator,
        lanes[2],
        public_evaluations[1],
        public_logup_claim,
        &relations,
    );
}

const SHAPE = vm_claim.Shape{ .max_input_words = 3, .max_output_words = 3 };
const Wire = fixed_wire.FixedStarkProofWire(dimensions);
const TranscriptPrepared = transcript_witness.Prepared(dimensions);
const TranscriptSource = transcript_source_mod.Source(dimensions);
const SegmentBundle = bundle.Bundle(dimensions);

test "R-012 segment-leaf bundle fills and audits its complete source cohort" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const outer = try fixture.outerBundle();
    const manifest = try fixture.manifest(&outer);
    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
    );

    const lanes = outer.loweringLanes();
    try std.testing.expectEqual(@as(usize, 3), lanes.len);
    try std.testing.expectEqual(
        statement_source.STATEMENT_CIRCUIT_ID,
        lanes[0].circuit_id,
    );
    try std.testing.expectEqual(
        public_source_mod.CLAIM_CIRCUIT_ID,
        lanes[1].circuit_id,
    );
    try std.testing.expectEqual(
        public_source_mod.PUBLIC_LOGUP_CIRCUIT_ID,
        lanes[2].circuit_id,
    );
    for (lanes) |lane| try lane.graph.validate();

    var preprocessed = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    var main = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    var interaction = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();

    // Measure only the retained hot writers.  All cold authorities, prepared
    // witnesses, manifest storage, and caller-owned tree storage already
    // exist before the counter begins.
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    const measured_allocator = measured.allocator();
    const saved_transcript_allocator = fixture.transcript_source.allocator;
    const saved_statement_workspace_allocator = fixture.statement_workspace.allocator;
    const saved_public_allocator = fixture.public_source.allocator;
    fixture.transcript_source.allocator = measured_allocator;
    fixture.statement_workspace.allocator = measured_allocator;
    fixture.public_source.allocator = measured_allocator;
    defer {
        fixture.public_source.allocator = saved_public_allocator;
        fixture.statement_workspace.allocator = saved_statement_workspace_allocator;
        fixture.transcript_source.allocator = saved_transcript_allocator;
    }

    try outer.fillPreprocessedInto(&manifest, preprocessed.columns);
    try std.testing.expectEqual(
        bundle.HOT_TREE_HEAP_ALLOCATIONS[0],
        measured.alloc_index,
    );
    try outer.fillMainInto(&manifest, main.columns);
    try std.testing.expectEqual(
        bundle.HOT_TREE_HEAP_ALLOCATIONS[0] +
            bundle.HOT_TREE_HEAP_ALLOCATIONS[1],
        measured.alloc_index,
    );
    const claims = try outer.fillInteractionInto(
        &manifest,
        &relations,
        &provider_relations,
        interaction.columns,
    );
    try std.testing.expectEqual(
        bundle.HOT_ALL_TREES_HEAP_ALLOCATIONS,
        measured.alloc_index,
    );
    try expectOwnedTreeHasData(
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        preprocessed.columns,
    );
    try expectOwnedTreeHasData(
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
        main.columns,
    );
    try expectOwnedTreeHasData(
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        interaction.columns,
    );
    try expectUnownedTreeZero(
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        preprocessed.columns,
    );
    try expectUnownedTreeZero(
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
        main.columns,
    );
    try expectUnownedTreeZero(
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        interaction.columns,
    );

    // Diagnostics are cold by contract and therefore intentionally run after
    // restoring the production allocators.
    fixture.public_source.allocator = saved_public_allocator;
    fixture.statement_workspace.allocator = saved_statement_workspace_allocator;
    fixture.transcript_source.allocator = saved_transcript_allocator;
    const audits = try outer.auditInteractionDomains(
        &relations,
        &provider_relations,
        claims,
        null,
    );
    const contribution = audits.closureContribution();
    var expected_total = QM31.zero();
    for (claims.prefixValues()) |value| expected_total = expected_total.add(value);
    expected_total = expected_total.add(claims.sharedProviderValue());
    try std.testing.expect(contribution.total().eql(expected_total));
    var accumulated = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
    contribution.addInto(&accumulated);
    for (accumulated, contribution.values) |actual, expected|
        try std.testing.expect(actual.eql(expected));

    var claim_vector = try manifest_mod.ClaimVector.init(&manifest);
    try claims.bindPrefixInto(&claim_vector);
    const prefix_mask = (@as(u64, 1) << bundle.PREFIX_ROW_COUNT) - 1;
    try std.testing.expectEqual(prefix_mask, claim_vector.bound_mask);
    try claims.bindSharedProviderInto(&claim_vector);
    try std.testing.expectEqual(
        prefix_mask | (@as(u64, 1) << bundle.SHARED_PROVIDER_ROW),
        claim_vector.bound_mask,
    );

    const components = try outer.initComponents(
        &manifest,
        &relations,
        &provider_relations,
        claims,
    );
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try components.appendPrefixToGate(&manifest, &gate);
    try std.testing.expectEqual(@as(u8, bundle.PREFIX_ROW_COUNT), gate.count);
    try std.testing.expectError(
        error.AdapterOrderMismatch,
        components.appendSharedProviderToGate(&manifest, &gate),
    );
    try std.testing.expectEqual(@as(u8, bundle.PREFIX_ROW_COUNT), gate.count);
}

fn sourceWireClaim(
    comptime Runtime: type,
    allocator: std.mem.Allocator,
    plan: *const Runtime.Plan,
    rows: []const Runtime.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
) !QM31 {
    const Framework = framework.Runtime(Runtime);
    var generated = try Framework.generatePrepared(
        allocator,
        plan,
        rows,
        log_size,
        relations,
    );
    defer generated.deinit(allocator);
    const audit = try plan.auditPreparedDomainSums(
        allocator,
        rows,
        relations,
        generated.claimed_sum,
    );
    return audit.values[
        @intFromEnum(
            @import("../air/lang/relation.zig").Domain.recursion_wire,
        )
    ];
}

fn expectLaneInputParity(
    allocator: std.mem.Allocator,
    lane: lowering.Lane,
    evaluation: lowering.Evaluation,
    source_claim: QM31,
    relations: *const universal.UniversalRelations,
) !void {
    var inactive_lane = lane;
    inactive_lane.circuit_id += 1_000;
    inactive_lane.active_in = .binary;
    const lane_storage = [_]lowering.Lane{ lane, inactive_lane };
    const reference = try lowering.Reference.seal(&lane_storage);
    var plan = try lowering.Plan.init(allocator, reference);
    defer plan.deinit();
    const evaluation_storage = [_]lowering.Evaluation{ evaluation, evaluation };
    const derived = try plan.inputBoundaryClaim(
        allocator,
        reference,
        .{ .lanes = &evaluation_storage },
        .segment_leaf,
        relations,
    );
    if (!derived.eql(source_claim)) {
        std.debug.print(
            "\n  SEGMENT_LANE_PARITY circuit={d} source={any} derived={any}\n",
            .{ lane.circuit_id, source_claim.toM31Array(), derived.toM31Array() },
        );
        return switch (lane.circuit_id) {
            statement_source.STATEMENT_CIRCUIT_ID => error.StatementLaneInputBoundaryMismatch,
            public_source_mod.CLAIM_CIRCUIT_ID => error.PublicClaimLaneInputBoundaryMismatch,
            public_source_mod.PUBLIC_LOGUP_CIRCUIT_ID => error.PublicLogupLaneInputBoundaryMismatch,
            else => error.LaneInputBoundaryMismatch,
        };
    }
    for (lane.graph.outputs) |node_id| {
        if (!evaluation.values[node_id].isZero()) {
            std.debug.print(
                "\n  SEGMENT_LANE_OUTPUT circuit={d} node={d} value={any}\n",
                .{
                    lane.circuit_id,
                    node_id,
                    evaluation.values[node_id].toM31Array(),
                },
            );
            return error.LaneOutputNonZero;
        }
    }
}

test "R-012 segment-leaf bundle rejects aliases and rolls back across sources" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const outer = try fixture.outerBundle();
    const manifest = try fixture.manifest(&outer);

    var preprocessed = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    const owned_placement = try manifest.placement(.control);
    const recursive_placement = try manifest.placement(.vm_air_composition_input);
    const owned_index: usize = owned_placement.preprocessed_offset;
    const recursive_index: usize = recursive_placement.preprocessed_offset;
    const saved_recursive = preprocessed.columns[recursive_index];
    preprocessed.columns[recursive_index] = preprocessed.columns[owned_index];
    try std.testing.expectError(
        error.DestinationAlias,
        outer.fillPreprocessedInto(&manifest, preprocessed.columns),
    );
    preprocessed.columns[recursive_index] = saved_recursive;
    try expectOwnedTreeZero(
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        preprocessed.columns,
    );

    preprocessed.columns[owned_index][0] = M31.one();
    try std.testing.expectError(
        error.DestinationNotZero,
        outer.fillPreprocessedInto(&manifest, preprocessed.columns),
    );
    preprocessed.columns[owned_index][0] = M31.zero();

    // The public source runs last.  Corrupt it so transcript and statement
    // have already committed when admission fails, then prove the bundle-wide
    // rollback clears only its nineteen rows.
    var main = try Tree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    const recursive_main: usize = recursive_placement.main_offset;
    const sentinel = M31.fromCanonical(0x5151);
    main.columns[recursive_main][0] = sentinel;
    const saved = fixture.public_prepared.claim_input_rows[0][0];
    fixture.public_prepared.claim_input_rows[0][0] = saved.add(M31.one());
    try std.testing.expectError(
        error.PreparedAuthorityMismatch,
        outer.fillMainInto(&manifest, main.columns),
    );
    fixture.public_prepared.claim_input_rows[0][0] = saved;
    try expectOwnedTreeZero(
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
        main.columns,
    );
    try std.testing.expect(main.columns[recursive_main][0].eql(sentinel));
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    data: public_data_mod.PublicData,
    leaf_preprocessing: leaf_authority.Preprocessing,
    leaf: leaf_authority.Prepared,
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    transcript_preprocessing: transcript_witness.Preprocessing,
    transcript_prepared: TranscriptPrepared,
    transcript_source: TranscriptSource,
    statement_authority: statement_source.Authority,
    statement_workspace: statement_source.Workspace,
    statement_prepared: statement_source.Prepared,
    public_source: public_source_mod.Source,
    public_prepared: public_source_mod.Prepared,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const data = testPublicData();
        var leaf_preprocessing = try leaf_authority.Preprocessing.init(
            allocator,
            SHAPE,
        );
        errdefer leaf_preprocessing.deinit();
        var leaf = try leaf_authority.Prepared.init(
            allocator,
            &leaf_preprocessing,
            &data,
        );
        errdefer leaf.deinit();

        var vm_plan = try testPlan(allocator, .vm);
        errdefer vm_plan.deinit();
        var recursion_plan = try testPlan(allocator, .recursion);
        errdefer recursion_plan.deinit();
        var transcript_preprocessing = try transcript_witness.Preprocessing.init(
            allocator,
            &vm_plan,
            &recursion_plan,
        );
        errdefer transcript_preprocessing.deinit();

        const native_relations = native_relations_mod.Relations.dummy();
        const claimed_sums = [_]QM31{
            try vm_semantics.expectedClaimedSum(&data, &native_relations),
        };
        const wire = testWire(claimed_sums[0]);
        var public_claim_words: [channel.RATE]M31 = undefined;
        for (&public_claim_words, leaf.claim.digest) |*destination, raw|
            destination.* = M31.fromCanonical(raw);
        var transcript_prepared = try TranscriptPrepared.init(
            allocator,
            &transcript_preprocessing,
            &vm_plan,
            &recursion_plan,
            &leaf.statement.words,
            .{ .vm = public_claim_words },
            &wire,
        );
        errdefer transcript_prepared.deinit();
        var transcript_source = try TranscriptSource.init(
            allocator,
            &vm_plan,
            &recursion_plan,
            &transcript_preprocessing,
            &transcript_prepared,
            try transcript_source_mod.PowLogSizes.init(4, 4),
        );
        errdefer transcript_source.deinit();

        var statement_authority = try statement_source.Authority.init(
            allocator,
            &leaf_preprocessing,
        );
        errdefer statement_authority.deinit();
        var statement_workspace = try statement_source.Workspace.init(allocator);
        errdefer statement_workspace.deinit();
        var statement_prepared = try statement_source.Prepared.init(
            allocator,
            &statement_authority,
            &statement_workspace,
            &leaf_preprocessing,
            &data,
            &leaf,
        );
        errdefer statement_prepared.deinit();

        var source_public = try public_source_mod.Source.init(
            allocator,
            &vm_plan,
            &recursion_plan,
            &leaf_preprocessing,
            dimensions.claimed_sum_count,
        );
        errdefer source_public.deinit();
        var public_prepared = try public_source_mod.Prepared.init(
            allocator,
            &source_public,
            &leaf_preprocessing,
            &leaf,
            &data,
            &native_relations,
            &claimed_sums,
        );
        errdefer public_prepared.deinit();

        return .{
            .allocator = allocator,
            .data = data,
            .leaf_preprocessing = leaf_preprocessing,
            .leaf = leaf,
            .vm_plan = vm_plan,
            .recursion_plan = recursion_plan,
            .transcript_preprocessing = transcript_preprocessing,
            .transcript_prepared = transcript_prepared,
            .transcript_source = transcript_source,
            .statement_authority = statement_authority,
            .statement_workspace = statement_workspace,
            .statement_prepared = statement_prepared,
            .public_source = source_public,
            .public_prepared = public_prepared,
        };
    }

    fn deinit(self: *Fixture) void {
        self.public_prepared.deinit();
        self.public_source.deinit();
        self.statement_prepared.deinit();
        self.statement_workspace.deinit();
        self.statement_authority.deinit();
        self.transcript_source.deinit();
        self.transcript_prepared.deinit();
        self.transcript_preprocessing.deinit();
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.leaf.deinit();
        self.leaf_preprocessing.deinit();
        self.* = undefined;
    }

    fn outerBundle(self: *Fixture) !SegmentBundle {
        return SegmentBundle.init(.{
            .vm_plan = &self.vm_plan,
            .recursion_plan = &self.recursion_plan,
            .transcript_preprocessing = &self.transcript_preprocessing,
            .transcript_prepared = &self.transcript_prepared,
            .transcript_source = &self.transcript_source,
            .leaf_preprocessing = &self.leaf_preprocessing,
            .leaf = &self.leaf,
            .public_data = &self.data,
            .statement_authority = &self.statement_authority,
            .statement_workspace = &self.statement_workspace,
            .statement_prepared = &self.statement_prepared,
            .public_source = &self.public_source,
            .public_prepared = &self.public_prepared,
        });
    }

    fn manifest(
        self: *Fixture,
        outer: *const SegmentBundle,
    ) !manifest_mod.Manifest {
        _ = self;
        var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
        outer.installLogSizes(&logs);
        return universal_manifest.build(logs);
    }
};

const Tree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !Tree {
        const columns = try allocator.alloc([]M31, treeColumnCount(manifest, tree));
        errdefer allocator.free(columns);
        var total: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            total += geometryColumnCount(placement.geometry, tree) *
                (@as(usize, 1) << @intCast(placement.geometry.log_size));
        }
        const storage = try allocator.alloc(M31, total);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset = treeOffset(placement, tree);
            const column_count = geometryColumnCount(placement.geometry, tree);
            const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..column_count]) |*column| {
                column.* = storage[cursor..][0..row_count];
                cursor += row_count;
            }
        }
        std.debug.assert(cursor == storage.len);
        return .{ .allocator = allocator, .columns = columns, .storage = storage };
    }

    fn deinit(self: *Tree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

fn testPlan(allocator: std.mem.Allocator, schema: schedule.Schema) !schedule.Plan {
    const shape = schedule.ScheduleShape{
        .protocol_id = protocol.protocolId(),
        .shape_id = channel.hashBytes("segment-leaf-bundle-test-shape", 0x5342),
        .interaction_pow_bits = 0,
        .pcs_pow_bits = 0,
        .query_count = dimensions.query_count,
        .table_count = dimensions.commitment_count,
        .claimed_sum_count = dimensions.claimed_sum_count,
        .sampled_value_count = dimensions.sampled_value_count,
        .tree_heights = .{ 5, 5, 5, 5 },
        .fri = try fixed_profile.FriSchedule.init(4, protocol.PCS_CONFIG.fri_config),
    };
    return schedule.Plan.initShape(
        allocator,
        if (schema == .vm)
            try schedule.vmProgramSpec(SHAPE.max_input_words, SHAPE.max_output_words)
        else
            schedule.RECURSION_PROGRAM_SPEC_V1,
        shape,
    );
}

fn testWire(claimed_sum: QM31) Wire {
    var wire = std.mem.zeroes(Wire);
    for (&wire.commitments, 0..) |*digest, digest_index| {
        for (digest, 0..) |*value, index|
            value.* = @intCast(1 + 17 * digest_index + index);
    }
    for (claimed_sum.toM31Array(), 0..) |limb, index|
        wire.claimed_sums[0][index] = limb.toU32();
    for (&wire.sampled_values, 0..) |*value, index| {
        for (value, 0..) |*limb, limb_index|
            limb.* = @intCast(300 + 4 * index + limb_index);
    }
    for (&wire.fri_layers[0].commitment, 0..) |*value, index|
        value.* = @intCast(400 + index);
    for (&wire.last_layer_coefficients[0], 0..) |*value, index|
        value.* = @intCast(500 + index);
    return wire;
}

const test_input_words = [_]u32{ 0x4433_2211, 0x55 };
const test_output_words = [_]public_data_mod.OutputWord{
    .{ .addr = 0x10_0004, .value = 4, .clock = 5 },
    .{ .addr = 0x10_0008, .value = 0x8877_6655, .clock = 6 },
};

fn testPublicData() public_data_mod.PublicData {
    var initial_regs = [_]u32{0} ** 32;
    initial_regs[1] = 0x8000_0001;
    var final_regs = initial_regs;
    final_regs[2] = 9;
    var reg_last_clock = [_]u32{0} ** 32;
    reg_last_clock[2] = 7;
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = public_data_mod.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{
            .input_start = 0x20_0000,
            .input_len = 5,
            .input_words = &test_input_words,
            .output_len = 4,
            .output_len_addr = 0x10_0004,
            .output_data_addr = 0x10_0008,
            .output_words = &test_output_words,
        },
    };
}

fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn geometryColumnCount(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

fn ownedRow(row: u8) bool {
    return row < bundle.PREFIX_ROW_COUNT or row == bundle.SHARED_PROVIDER_ROW;
}

fn expectOwnedTreeZero(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    columns: []const []M31,
) !void {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        if (!ownedRow(row)) continue;
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        for (columns[offset..][0..count]) |column| {
            for (column) |value| try std.testing.expect(value.isZero());
        }
    }
}

fn expectOwnedTreeHasData(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    columns: []const []M31,
) !void {
    var nonzero = false;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        if (!ownedRow(row)) continue;
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        for (columns[offset..][0..count]) |column| {
            for (column) |value| nonzero = nonzero or !value.isZero();
        }
    }
    try std.testing.expect(nonzero);
}

fn expectUnownedTreeZero(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    columns: []const []M31,
) !void {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        if (ownedRow(row)) continue;
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        for (columns[offset..][0..count]) |column| {
            for (column) |value| try std.testing.expect(value.isZero());
        }
    }
}
