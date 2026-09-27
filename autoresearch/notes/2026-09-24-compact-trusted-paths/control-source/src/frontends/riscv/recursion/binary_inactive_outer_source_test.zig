//! Focused authority, transaction, mutation, and tuple-closure gates for the
//! binary-node rows 12--17 source.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const source_mod = @import("binary_inactive_outer_source.zig");
const segment_source = @import("segment_public_outer_source.zig");
const leaf_authority = @import("segment_leaf_authority.zig");
const vm_claim = @import("vm_public_claim.zig");
const fixed_profile = @import("fixed_profile.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");

const air = @import("air/mod.zig");
const binding = air.universal_relation_binding;
const manifest_mod = air.universal_adapter_manifest;
const relation = @import("../air/lang/relation.zig");
const relation_interaction = air.relation_interaction;
const roster = air.universal_roster;
const schedule = air.verifier_schedule;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;

const ControlRelation = binding.Binding(air.control);
const SHAPE = vm_claim.Shape{ .max_input_words = 3, .max_output_words = 3 };

test "R-013 binary VM-public cohort freezes five inactive rows and live row17" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    try std.testing.expectEqual(@as(usize, 12), source_mod.FIRST_ROW);
    try std.testing.expectEqual(@as(usize, 16), source_mod.LAST_INACTIVE_ROW);
    try std.testing.expectEqual(@as(usize, 17), source_mod.CONTROL_ROW);
    try std.testing.expectEqual(@as(usize, 0), source_mod.POSEIDON_CALLS_PER_BINARY_NODE);
    try std.testing.expectEqual(@as(usize, 0), fixture.prepared.claim_hash.poseidon_calls.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.prepared.io_hash.poseidon_calls.len);

    for (fixture.prepared.claim_input.rows) |row| {
        try std.testing.expect(row.value.isZero());
        try std.testing.expect(row.low_byte.isZero());
        try std.testing.expect(row.high_byte.isZero());
    }
    for (fixture.prepared.claim_hash.rows) |row|
        for (row.values()) |value| try std.testing.expect(value.isZero());
    for (fixture.prepared.io_hash.rows) |row|
        for (row.values()) |value| try std.testing.expect(value.isZero());
    for (fixture.prepared.claim_semantics.rows) |row|
        try std.testing.expect(row.value.isZero());
    for (fixture.prepared.public_logup.rows) |row|
        try std.testing.expect(row.value.isZero());

    try std.testing.expectEqual(
        2 * @as(usize, fixture.plans.recursion.spec.public_logup_term_count + 1),
        fixture.typed.public_logup_control.activeStepCount(.binary_node),
    );
    var active_control_rows: usize = 0;
    for (
        fixture.typed.public_logup_control.rows,
        fixture.source.public_logup_control_rows,
    ) |metadata, logical| {
        const binary_active = !logical[logical.len - 1].isZero();
        const expected = metadata.verifier_id != controlVerifierIdSegment();
        active_control_rows += @intFromBool(binary_active and expected);
    }
    try std.testing.expectEqual(@as(usize, 2), active_control_rows);
}

test "R-013 binary inactive source fills and audits exact typed rows" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const manifest = try fixture.manifest();
    const relations = universal.UniversalRelations.dummy();

    var preprocessed = try Tree.init(std.testing.allocator, &manifest, .preprocessed);
    defer preprocessed.deinit();
    var main = try Tree.init(std.testing.allocator, &manifest, .main);
    defer main.deinit();
    var interaction = try Tree.init(std.testing.allocator, &manifest, .interaction);
    defer interaction.deinit();

    try fixture.source.fillPreprocessedInto(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &manifest,
        preprocessed.columns,
    );
    try fixture.source.fillMainInto(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.prepared,
        &manifest,
        main.columns,
    );
    const claims = try fixture.source.fillInteractionInto(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.prepared,
        &manifest,
        &relations,
        interaction.columns,
    );
    try claims.validateInactive();
    try std.testing.expect(!claims.public_logup_control.isZero());

    var ledger = relation_interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    const audits = try fixture.source.auditInteractionDomains(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.prepared,
        &relations,
        claims,
        &ledger,
    );
    for (audits, claims.asArray()) |audit, claim|
        try std.testing.expect(audit.total.eql(claim));
    try std.testing.expectEqual(@as(usize, 2), ledger.contributions.items.len);
    for (ledger.contributions.items) |contribution| {
        try std.testing.expectEqual(relation.Domain.recursion_step, contribution.domain);
        try std.testing.expectEqual(relation.Role.consume, contribution.role);
        try std.testing.expectEqual(
            @as(u8, @intCast(source_mod.CONTROL_ROW)),
            contribution.component,
        );
    }

    var claim_vector = try manifest_mod.ClaimVector.init(&manifest);
    try claims.bindInto(&claim_vector);
    const expected_mask = ((@as(u64, 1) << source_mod.ROW_COUNT) - 1) <<
        source_mod.FIRST_ROW;
    try std.testing.expectEqual(expected_mask, claim_vector.bound_mask);
    _ = try fixture.source.initComponents(
        &fixture.typed,
        &manifest,
        &relations,
        claims,
    );
}

test "R-013 binary inactive source pins cold and hot allocation budgets" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var cold = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var prepared = try source_mod.Prepared.init(
        cold.allocator(),
        &fixture.source,
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
    );
    try std.testing.expectEqual(
        source_mod.COLD_PREPARE_HEAP_ALLOCATIONS,
        cold.alloc_index,
    );
    prepared.deinit();
    try std.testing.expectEqual(cold.allocated_bytes, cold.freed_bytes);

    const manifest = try fixture.manifest();
    const relations = universal.UniversalRelations.dummy();
    var preprocessed = try Tree.init(std.testing.allocator, &manifest, .preprocessed);
    defer preprocessed.deinit();
    var main = try Tree.init(std.testing.allocator, &manifest, .main);
    defer main.deinit();
    var interaction = try Tree.init(std.testing.allocator, &manifest, .interaction);
    defer interaction.deinit();

    var hot = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const saved_allocator = fixture.source.allocator;
    fixture.source.allocator = hot.allocator();
    defer fixture.source.allocator = saved_allocator;
    try fixture.source.fillPreprocessedInto(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &manifest,
        preprocessed.columns,
    );
    try std.testing.expectEqual(source_mod.HOT_TREE_HEAP_ALLOCATIONS[0], hot.alloc_index);
    try fixture.source.fillMainInto(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.prepared,
        &manifest,
        main.columns,
    );
    try std.testing.expectEqual(
        source_mod.HOT_TREE_HEAP_ALLOCATIONS[0] +
            source_mod.HOT_TREE_HEAP_ALLOCATIONS[1],
        hot.alloc_index,
    );
    _ = try fixture.source.fillInteractionInto(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.prepared,
        &manifest,
        &relations,
        interaction.columns,
    );
    try std.testing.expectEqual(
        source_mod.HOT_ALL_TREES_HEAP_ALLOCATIONS,
        hot.alloc_index,
    );
    try std.testing.expectEqual(hot.allocated_bytes, hot.freed_bytes);
}

test "R-013 row17 is required to close the exact binary row0 schedule tuples" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const manifest = try fixture.manifest();
    const relations = universal.UniversalRelations.dummy();
    var interaction = try Tree.init(std.testing.allocator, &manifest, .interaction);
    defer interaction.deinit();
    const claims = try fixture.source.fillInteractionInto(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.prepared,
        &manifest,
        &relations,
        interaction.columns,
    );

    var control_definition = try air.control.build(std.testing.allocator);
    defer control_definition.deinit();
    const control_plan = try ControlRelation.authenticate(&control_definition);
    var control_preprocessing = try air.control_witness.Preprocessed.init(
        std.testing.allocator,
        &fixture.plans.vm,
        &fixture.plans.recursion,
    );
    defer control_preprocessing.deinit();
    const producer_rows = try publicControlProducerRows(
        std.testing.allocator,
        &control_preprocessing,
        fixture.typed.public_logup_control.rows,
    );
    defer std.testing.allocator.free(producer_rows);

    var missing = relation_interaction.TupleLedger.init(std.testing.allocator);
    defer missing.deinit();
    try control_plan.appendPreparedTupleContributions(
        &missing,
        0,
        producer_rows,
        relation_interaction.allDomainMask(),
    );
    const red = missing.classify();
    try std.testing.expectEqual(@as(usize, 2), red.unmatched_tuple_count);
    try std.testing.expectEqual(
        @as(usize, 2),
        red.unmatched_by_domain[@intFromEnum(relation.Domain.recursion_step)],
    );

    var closed = relation_interaction.TupleLedger.init(std.testing.allocator);
    defer closed.deinit();
    try control_plan.appendPreparedTupleContributions(
        &closed,
        0,
        producer_rows,
        relation_interaction.allDomainMask(),
    );
    _ = try fixture.source.auditInteractionDomains(
        &fixture.typed,
        &fixture.plans.vm,
        &fixture.plans.recursion,
        &fixture.leaf_pp,
        &fixture.prepared,
        &relations,
        claims,
        &closed,
    );
    try std.testing.expect(closed.classify().isClosed());
}

test "R-013 binary inactive source rejects mutation and destination alias atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const manifest = try fixture.manifest();
    var main = try Tree.init(std.testing.allocator, &manifest, .main);
    defer main.deinit();
    const sentinel = M31.fromCanonical(0x5151);
    main.fill(sentinel);

    const saved = fixture.prepared.claim_input_rows[0][0];
    fixture.prepared.claim_input_rows[0][0] = saved.add(M31.one());
    try std.testing.expectError(
        error.PreparedAuthorityMismatch,
        fixture.source.fillMainInto(
            &fixture.typed,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            &fixture.leaf_pp,
            &fixture.prepared,
            &manifest,
            main.columns,
        ),
    );
    fixture.prepared.claim_input_rows[0][0] = saved;
    try main.expectFilled(sentinel);

    const first = try manifest.placement(.vm_public_claim_input);
    try std.testing.expect(first.geometry.main_columns >= 2);
    const alias_index = first.main_offset + 1;
    const alias_original = main.columns[alias_index];
    main.columns[alias_index] = main.columns[first.main_offset];
    try std.testing.expectError(
        error.DestinationAlias,
        fixture.source.fillMainInto(
            &fixture.typed,
            &fixture.plans.vm,
            &fixture.plans.recursion,
            &fixture.leaf_pp,
            &fixture.prepared,
            &manifest,
            main.columns,
        ),
    );
    main.columns[alias_index] = alias_original;
    try main.expectFilled(sentinel);
}

fn controlVerifierIdSegment() u32 {
    return air.control_slice_witness.SEGMENT_VERIFIER_ID;
}

fn publicControlProducerRows(
    allocator: std.mem.Allocator,
    control: *const air.control_witness.Preprocessed,
    selected: []const air.control_slice_witness.Row,
) ![]ControlRelation.Row {
    var count: usize = 0;
    for (selected) |wanted| {
        if (wanted.verifier_id != controlVerifierIdSegment()) count += 1;
    }
    const rows = try allocator.alloc(ControlRelation.Row, count);
    errdefer allocator.free(rows);
    var at: usize = 0;
    for (selected) |wanted| {
        if (wanted.verifier_id == controlVerifierIdSegment()) continue;
        const source = for (control.rows) |candidate| {
            if (candidate.verifier_id == wanted.verifier_id and
                candidate.sequence == wanted.sequence and
                candidate.tag == wanted.tag and
                std.meta.eql(candidate.args, wanted.args))
            {
                break candidate;
            }
        } else return error.ControlTupleMissing;
        rows[at] = air.control_witness.logicalRow(source, .binary_node);
        at += 1;
    }
    std.debug.assert(at == rows.len);
    return rows;
}

const Plans = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Plans {
        const shape = try scheduleShape();
        var vm = try schedule.Plan.initShape(
            allocator,
            try schedule.vmProgramSpec(
                SHAPE.max_input_words,
                SHAPE.max_output_words,
            ),
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
    leaf_pp: leaf_authority.Preprocessing,
    plans: Plans,
    typed: segment_source.Source,
    source: source_mod.Source,
    prepared: source_mod.Prepared,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var leaf_pp = try leaf_authority.Preprocessing.init(allocator, SHAPE);
        errdefer leaf_pp.deinit();
        var plans = try Plans.init(allocator);
        errdefer plans.deinit();
        var typed = try segment_source.Source.init(
            allocator,
            &plans.vm,
            &plans.recursion,
            &leaf_pp,
            1,
        );
        errdefer typed.deinit();
        var source = try source_mod.Source.init(
            allocator,
            &typed,
            &plans.vm,
            &plans.recursion,
            &leaf_pp,
        );
        errdefer source.deinit();
        var prepared = try source_mod.Prepared.init(
            allocator,
            &source,
            &typed,
            &plans.vm,
            &plans.recursion,
            &leaf_pp,
        );
        errdefer prepared.deinit();
        return .{
            .allocator = allocator,
            .leaf_pp = leaf_pp,
            .plans = plans,
            .typed = typed,
            .source = source,
            .prepared = prepared,
        };
    }

    fn deinit(self: *Fixture) void {
        self.prepared.deinit();
        self.source.deinit();
        self.typed.deinit();
        self.plans.deinit();
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
            const row_count = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            for (0..column_count) |_| {
                columns[column_cursor] = storage[storage_cursor..][0..row_count];
                column_cursor += 1;
                storage_cursor += row_count;
            }
        }
        std.debug.assert(
            column_cursor == columns.len and storage_cursor == storage.len,
        );
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
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
        .protocol_id = channel.hashBytes("binary-inactive-protocol", 0x4249),
        .shape_id = channel.hashBytes("binary-inactive-shape", 0x4253),
        .interaction_pow_bits = 0,
        .pcs_pow_bits = 0,
        .query_count = 2,
        .table_count = 4,
        .claimed_sum_count = 1,
        .sampled_value_count = 4,
        .tree_heights = .{ 5, 5, 5, 5 },
        .fri = try fixed_profile.FriSchedule.init(
            4,
            protocol.PCS_CONFIG.fri_config,
        ),
    };
}
