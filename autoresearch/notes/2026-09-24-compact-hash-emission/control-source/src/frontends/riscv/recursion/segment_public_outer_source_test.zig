//! Integration, mutation, alias, and allocation gates for rows 12--17.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const source_mod = @import("segment_public_outer_source.zig");
const leaf_authority = @import("segment_leaf_authority.zig");
const vm_claim = @import("vm_public_claim.zig");
const public_data = @import("../air/public_data.zig");
const native_relations_mod = @import("../air/relation_challenges.zig");
const semantics = @import("vm_public_semantics_circuit.zig");
const fixed_profile = @import("fixed_profile.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");
const air = @import("air/mod.zig");
const schedule = air.verifier_schedule;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;
const manifest_mod = air.universal_adapter_manifest;
const roster = air.universal_roster;
const lowering = air.verifier_arithmetic_lowering;

const SHAPE = vm_claim.Shape{ .max_input_words = 3, .max_output_words = 3 };

test "R-012 rows 12 through 17 share one leaf authority and two lowering lanes" {
    const allocator = std.testing.allocator;
    const data = testPublicData();
    var leaf_pp = try leaf_authority.Preprocessing.init(allocator, SHAPE);
    defer leaf_pp.deinit();
    var leaf = try leaf_authority.Prepared.init(allocator, &leaf_pp, &data);
    defer leaf.deinit();
    var plans = try Plans.init(allocator);
    defer plans.deinit();
    var source = try source_mod.Source.init(
        allocator,
        &plans.vm,
        &plans.recursion,
        &leaf_pp,
        1,
    );
    defer source.deinit();
    const native_relations = native_relations_mod.Relations.dummy();
    const sums = [_]QM31{try semantics.expectedClaimedSum(&data, &native_relations)};
    var prepared = try source_mod.Prepared.init(
        allocator,
        &source,
        &leaf_pp,
        &leaf,
        &data,
        &native_relations,
        &sums,
    );
    defer prepared.deinit();

    try prepared.validateAgainst(&source, &leaf_pp, &leaf, &data);
    const lanes = source.loweringLanes();
    const evaluations = prepared.loweringEvaluations(&source);
    try std.testing.expectEqual(@as(usize, 2), lanes.len);
    try std.testing.expectEqual(source_mod.CLAIM_CIRCUIT_ID, lanes[0].circuit_id);
    try std.testing.expectEqual(source_mod.PUBLIC_LOGUP_CIRCUIT_ID, lanes[1].circuit_id);
    for (lanes, evaluations) |lane, evaluation| {
        try lane.graph.validate();
        try std.testing.expectEqual(lane.graph.nodes.len, evaluation.values.len);
        try std.testing.expectEqual(lane.circuit_identity, evaluation.circuit_identity);
    }

    const lowering_lanes = [_]lowering.Lane{
        lanes[0],
        lanes[1],
        .{
            .circuit_id = source_mod.PUBLIC_LOGUP_CIRCUIT_ID + 1,
            .active_in = .binary,
            .circuit_identity = source.claim_reference.authority_digest,
            .graph = source.claim_graph.graph,
        },
    };
    const reference = try lowering.Reference.seal(&lowering_lanes);
    var plan = try lowering.Plan.init(allocator, reference);
    defer plan.deinit();
    try std.testing.expect(plan.counts(.segment_leaf).multiply > 0);
    try std.testing.expect(plan.counts(.segment_leaf).inverse > 0);
    try std.testing.expect(plan.counts(.segment_leaf).linear > 0);
    try std.testing.expectEqual(
        leaf.poseidonCallCount(),
        prepared.poseidonCallCount(&leaf),
    );
    const calls = try allocator.alloc(
        @import("air/vm_public_claim_hash_witness.zig").PoseidonCall,
        prepared.poseidonCallCount(&leaf),
    );
    defer allocator.free(calls);
    try prepared.appendPoseidonCallsInto(&leaf, calls);
    try std.testing.expectEqualSlices(
        @import("air/vm_public_claim_hash_witness.zig").PoseidonCall,
        leaf.claim_hash.poseidon_calls,
        calls[0..leaf.claim_hash.poseidon_calls.len],
    );
}

test "R-012 rows 12 through 17 fill all three trees transactionally" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const manifest = try fixture.manifest();
    const relations = universal.UniversalRelations.dummy();

    var preprocessed = try Tree.init(allocator, &manifest, .preprocessed);
    defer preprocessed.deinit();
    var main = try Tree.init(allocator, &manifest, .main);
    defer main.deinit();
    var interaction = try Tree.init(allocator, &manifest, .interaction);
    defer interaction.deinit();
    try fixture.source.fillPreprocessedInto(
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &manifest,
        preprocessed.columns,
    );
    try fixture.source.fillMainInto(
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.leaf,
        &fixture.prepared,
        &fixture.data,
        &manifest,
        main.columns,
    );
    const claims = try fixture.source.fillInteractionInto(
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.leaf,
        &fixture.prepared,
        &fixture.data,
        &manifest,
        &relations,
        interaction.columns,
    );
    const domain_audits = try fixture.source.auditInteractionDomains(
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.leaf,
        &fixture.prepared,
        &fixture.data,
        &relations,
        claims,
        null,
    );
    for (domain_audits, claims.asArray()) |audit, claim|
        try std.testing.expect(audit.total.eql(claim));
    _ = try fixture.source.initComponents(&manifest, &relations, claims);
    for (claims.asArray()) |claim| try std.testing.expect(!claim.isZero());

    // Mutation rejection occurs before the caller-owned tree is changed.
    main.fill(M31.fromCanonical(0x5151));
    const saved = fixture.prepared.claim_input_rows[0][0];
    fixture.prepared.claim_input_rows[0][0] = saved.add(M31.one());
    try std.testing.expectError(
        error.PreparedAuthorityMismatch,
        fixture.source.fillMainInto(
            &fixture.plans.vm,
            &fixture.plans.recursion,
            &fixture.leaf_pp,
            &fixture.leaf,
            &fixture.prepared,
            &fixture.data,
            &manifest,
            main.columns,
        ),
    );
    fixture.prepared.claim_input_rows[0][0] = saved;
    try main.expectFilled(M31.fromCanonical(0x5151));

    // A sink alias is rejected before the staging slab commits.
    const placement = try manifest.placement(.vm_public_claim_input);
    const first: usize = placement.preprocessed_offset;
    const original = preprocessed.columns[first + 1];
    preprocessed.columns[first + 1] = preprocessed.columns[first];
    defer preprocessed.columns[first + 1] = original;
    try std.testing.expectError(
        error.DestinationAlias,
        fixture.source.fillPreprocessedInto(
            &fixture.plans.vm,
            &fixture.plans.recursion,
            &fixture.leaf_pp,
            &manifest,
            preprocessed.columns,
        ),
    );
}

test "R-012 prepared rows 12 through 17 release every allocation failure" {
    const allocator = std.testing.allocator;
    const data = testPublicData();
    var leaf_pp = try leaf_authority.Preprocessing.init(allocator, SHAPE);
    defer leaf_pp.deinit();
    var leaf = try leaf_authority.Prepared.init(allocator, &leaf_pp, &data);
    defer leaf.deinit();
    var plans = try Plans.init(allocator);
    defer plans.deinit();
    var source = try source_mod.Source.init(
        allocator,
        &plans.vm,
        &plans.recursion,
        &leaf_pp,
        1,
    );
    defer source.deinit();
    const native_relations = native_relations_mod.Relations.dummy();
    const sums = [_]QM31{try semantics.expectedClaimedSum(&data, &native_relations)};
    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareFailureCase,
        .{ &source, &leaf_pp, &leaf, &data, &native_relations, &sums },
    );
}

fn prepareFailureCase(
    allocator: std.mem.Allocator,
    source: *const source_mod.Source,
    leaf_pp: *const leaf_authority.Preprocessing,
    leaf: *const leaf_authority.Prepared,
    data: *const public_data.PublicData,
    native_relations: *const native_relations_mod.Relations,
    sums: []const QM31,
) !void {
    var prepared = try source_mod.Prepared.init(
        allocator,
        source,
        leaf_pp,
        leaf,
        data,
        native_relations,
        sums,
    );
    defer prepared.deinit();
}

const Plans = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Plans {
        const shape = try scheduleShape();
        var vm = try schedule.Plan.initShape(
            allocator,
            try schedule.vmProgramSpec(SHAPE.max_input_words, SHAPE.max_output_words),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try schedule.Plan.initShape(
                allocator,
                schedule.RECURSION_PROGRAM_SPEC_V1,
                shape,
            ),
        };
    }

    fn deinit(self: *Plans) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    data: public_data.PublicData,
    leaf_pp: leaf_authority.Preprocessing,
    leaf: leaf_authority.Prepared,
    plans: Plans,
    source: source_mod.Source,
    prepared: source_mod.Prepared,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const data = testPublicData();
        var leaf_pp = try leaf_authority.Preprocessing.init(allocator, SHAPE);
        errdefer leaf_pp.deinit();
        var leaf = try leaf_authority.Prepared.init(allocator, &leaf_pp, &data);
        errdefer leaf.deinit();
        var plans = try Plans.init(allocator);
        errdefer plans.deinit();
        var source = try source_mod.Source.init(
            allocator,
            &plans.vm,
            &plans.recursion,
            &leaf_pp,
            1,
        );
        errdefer source.deinit();
        const native_relations = native_relations_mod.Relations.dummy();
        const sums = [_]QM31{try semantics.expectedClaimedSum(&data, &native_relations)};
        var prepared = try source_mod.Prepared.init(
            allocator,
            &source,
            &leaf_pp,
            &leaf,
            &data,
            &native_relations,
            &sums,
        );
        errdefer prepared.deinit();
        return .{
            .allocator = allocator,
            .data = data,
            .leaf_pp = leaf_pp,
            .leaf = leaf,
            .plans = plans,
            .source = source,
            .prepared = prepared,
        };
    }

    fn deinit(self: *Fixture) void {
        self.prepared.deinit();
        self.source.deinit();
        self.plans.deinit();
        self.leaf.deinit();
        self.leaf_pp.deinit();
        self.* = undefined;
    }

    fn manifest(self: *const Fixture) !manifest_mod.Manifest {
        var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
        self.source.installLogSizes(&logs);
        logs[@intFromEnum(roster.Component.range_check_8_8)] = 16;
        return universal_manifest.build(logs);
    }
};

const TreeKind = enum { preprocessed, main, interaction };

const Tree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        kind: TreeKind,
    ) !Tree {
        const count: usize = switch (kind) {
            .preprocessed => manifest.total_preprocessed_columns,
            .main => manifest.total_main_columns,
            .interaction => manifest.total_interaction_columns,
        };
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        var total: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row_value| {
            const placement = manifest.placements[row_value].?;
            const column_count: usize = switch (kind) {
                .preprocessed => placement.geometry.preprocessed_columns,
                .main => placement.geometry.main_columns,
                .interaction => placement.geometry.interaction_columns,
            };
            total = try std.math.add(
                usize,
                total,
                try std.math.mul(
                    usize,
                    column_count,
                    @as(usize, 1) << @intCast(placement.geometry.log_size),
                ),
            );
        }
        const storage = try allocator.alloc(M31, total);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var column_cursor: usize = 0;
        var storage_cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row_value| {
            const placement = manifest.placements[row_value].?;
            const column_count: usize = switch (kind) {
                .preprocessed => placement.geometry.preprocessed_columns,
                .main => placement.geometry.main_columns,
                .interaction => placement.geometry.interaction_columns,
            };
            const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (0..column_count) |_| {
                columns[column_cursor] = storage[storage_cursor..][0..row_count];
                column_cursor += 1;
                storage_cursor += row_count;
            }
        }
        std.debug.assert(column_cursor == columns.len and storage_cursor == storage.len);
        return .{ .allocator = allocator, .columns = columns, .storage = storage };
    }

    fn deinit(self: *Tree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    fn fill(self: *Tree, value: M31) void {
        @memset(self.storage, value);
    }

    fn expectFilled(self: *const Tree, value: M31) !void {
        for (self.storage) |actual| try std.testing.expect(actual.eql(value));
    }
};

fn scheduleShape() !schedule.ScheduleShape {
    return .{
        .protocol_id = channel.hashBytes("segment-public-outer-protocol", 0x5343),
        .shape_id = channel.hashBytes("segment-public-outer-shape", 0x5348),
        .interaction_pow_bits = 0,
        .pcs_pow_bits = 0,
        .query_count = 2,
        .table_count = 4,
        .claimed_sum_count = 1,
        .sampled_value_count = 4,
        .tree_heights = .{ 5, 5, 5, 5 },
        .fri = try fixed_profile.FriSchedule.init(4, protocol.PCS_CONFIG.fri_config),
    };
}

const test_input_words = [_]u32{ 0x4433_2211, 0x55 };
const test_output_words = [_]public_data.OutputWord{
    .{ .addr = 0x10_0004, .value = 4, .clock = 5 },
    .{ .addr = 0x10_0008, .value = 0x8877_6655, .clock = 6 },
};

fn testPublicData() public_data.PublicData {
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
        .completion = public_data.Completion.canonicalSelfLoop(0x1004),
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
