//! Focused custody, transaction, mutation, and allocation gates for binary
//! universal transcript rows 0--9.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;

const authority = @import("binary_pair_authority.zig");
const fixture_mod = @import("binary_pair_test_fixture.zig");
const source_mod = @import("binary_transcript_outer_source.zig");

const air = @import("air/mod.zig");
const manifest_mod = air.universal_adapter_manifest;
const relation_interaction = air.relation_interaction;
const roster = air.universal_roster;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;

const DIMENSIONS = fixture_mod.DIMENSIONS;
const Source = source_mod.Source(DIMENSIONS);
const Prepared = authority.Prepared(DIMENSIONS);

test "R-014 binary transcript source borrows exact authenticated rows 0--9" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const plans = fixture.recursionPlans();
    try fixture.prepared.validateAgainst(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
        &fixture.pair.statement_preprocessing,
        &fixture.pair.semantics,
        &fixture.pair.validation_workspace,
        fixture.pair.pair_inputs.root_pin,
    );
    try fixture.prepared.validateTranscriptSnapshots(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
    );
    try fixture.source.validateAgainst(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
        &fixture.prepared,
    );
    try std.testing.expectEqual(@as(usize, 0), source_mod.FIRST_ROW);
    try std.testing.expectEqual(@as(usize, 9), source_mod.LAST_ROW);
    try std.testing.expectEqual(@as(usize, 0), source_mod.HOT_PAIR_AUTHENTICATIONS_PER_TREE);
    const expected = source_mod.Parameters.binaryNode();
    try std.testing.expectEqual(expected, fixture.source.parameters);
    try std.testing.expect(fixture.source.parameters.control[0].isZero());
    try std.testing.expect(fixture.source.parameters.control[1].eql(M31.one()));
}

test "R-014 binary transcript source fills audits and instantiates typed rows" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const manifest = try fixture.manifest();
    const relations = universal.UniversalRelations.dummy();
    const plans = fixture.recursionPlans();

    var preprocessed = try Tree.init(std.testing.allocator, &manifest, .preprocessed);
    defer preprocessed.deinit();
    var main = try Tree.init(std.testing.allocator, &manifest, .main);
    defer main.deinit();
    var interaction = try Tree.init(std.testing.allocator, &manifest, .interaction);
    defer interaction.deinit();

    try fixture.source.fillPreprocessedInto(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
        &fixture.prepared,
        &manifest,
        preprocessed.columns,
    );
    try fixture.source.fillMainInto(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
        &fixture.prepared,
        &manifest,
        main.columns,
    );
    const claims = try fixture.source.fillInteractionInto(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
        &fixture.prepared,
        &manifest,
        &relations,
        interaction.columns,
    );
    var ledger = relation_interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    const audits = try fixture.source.auditInteractionDomains(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
        &fixture.prepared,
        &relations,
        claims,
        &ledger,
    );
    for (audits, claims.asArray()) |audit, claim|
        try std.testing.expect(audit.total.eql(claim));
    _ = try fixture.source.initComponents(&manifest, &relations, claims);
}

test "R-014 binary transcript source rejects plan selector root statement and seal drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const plans = fixture.recursionPlans();

    var foreign = fixture.pair.recursion_plans[0];
    foreign.authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        fixture.source.validateAgainst(
            &fixture.pair.vm_plan,
            .{ &foreign, plans[1] },
            &fixture.pair.transcript_preprocessing,
            &fixture.prepared,
        ),
    );
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        fixture.source.validateAgainst(
            &fixture.pair.vm_plan,
            .{ plans[0], &foreign },
            &fixture.pair.transcript_preprocessing,
            &fixture.prepared,
        ),
    );

    const selector = fixture.source.parameters.control[0];
    fixture.source.parameters.control[0] = M31.one();
    try expectSourceAuthorityError(&fixture);
    fixture.source.parameters.control[0] = selector;

    fixture.prepared.authenticated_root.pair.node_id[0] ^= 1;
    try expectSourceAuthorityError(&fixture);
    fixture.prepared.authenticated_root.pair.node_id[0] ^= 1;

    const statement_word = fixture.prepared.left_words[0];
    fixture.prepared.left_words[0] = statement_word.add(M31.one());
    try expectSourceAuthorityError(&fixture);
    fixture.prepared.left_words[0] = statement_word;

    fixture.source.authority_seal[0] ^= 1;
    try expectSourceAuthorityError(&fixture);
    fixture.source.authority_seal[0] ^= 1;
    try fixture.source.validateAgainst(
        &fixture.pair.vm_plan,
        plans,
        &fixture.pair.transcript_preprocessing,
        &fixture.prepared,
    );
}

test "R-014 binary transcript source rejects alias and rolls destination back" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const manifest = try fixture.manifest();
    const plans = fixture.recursionPlans();
    var main = try Tree.init(std.testing.allocator, &manifest, .main);
    defer main.deinit();
    const sentinel = M31.fromCanonical(0x514);
    main.fill(sentinel);

    const saved = fixture.prepared.transcript_air.rows[0];
    fixture.prepared.transcript_air.rows[0].enabler =
        1 - fixture.prepared.transcript_air.rows[0].enabler;
    try std.testing.expectError(
        error.InvalidWitnessRow,
        fixture.source.fillMainInto(
            &fixture.pair.vm_plan,
            plans,
            &fixture.pair.transcript_preprocessing,
            &fixture.prepared,
            &manifest,
            main.columns,
        ),
    );
    fixture.prepared.transcript_air.rows[0] = saved;
    try main.expectFilled(sentinel);

    const placement = try manifest.placement(.transcript_air);
    try std.testing.expect(placement.geometry.main_columns >= 2);
    const alias_index = placement.main_offset + 1;
    const original = main.columns[alias_index];
    main.columns[alias_index] = main.columns[placement.main_offset];
    try std.testing.expectError(
        error.DestinationAlias,
        fixture.source.fillMainInto(
            &fixture.pair.vm_plan,
            plans,
            &fixture.pair.transcript_preprocessing,
            &fixture.prepared,
            &manifest,
            main.columns,
        ),
    );
    main.columns[alias_index] = original;
    try main.expectFilled(sentinel);
}

test "R-014 binary transcript source measures cold and hot allocations" {
    var pair = try fixture_mod.HonestFixture.init(std.testing.allocator);
    defer pair.deinit();
    const plans = [2]*const air.verifier_schedule.Plan{
        &pair.recursion_plans[0],
        &pair.recursion_plans[1],
    };
    var prepared = try Prepared.init(
        std.testing.allocator,
        .sealed_candidate,
        &pair.vm_plan,
        plans,
        &pair.transcript_preprocessing,
        &pair.statement_preprocessing,
        &pair.semantics,
        &pair.validation_workspace,
        pair.pair_inputs,
        pair.children(),
    );
    defer prepared.deinit();
    const logs = try prepared.minimumLogSizes(
        &pair.vm_plan,
        &pair.recursion_plans[0],
        &pair.transcript_preprocessing,
        &pair.statement_preprocessing,
    );
    const pow_logs = try source_mod.PowLogSizes.init(
        @max(source_mod.MIN_LOG_SIZE, logs[6]),
        @max(source_mod.MIN_LOG_SIZE, logs[7]),
    );

    var cold = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var source = try Source.init(
        cold.allocator(),
        &pair.vm_plan,
        plans,
        &pair.transcript_preprocessing,
        &prepared,
        pow_logs,
    );
    var source_owned = true;
    const source_allocator = source.allocator;
    defer if (source_owned) {
        source.allocator = source_allocator;
        source.deinit();
    };
    try std.testing.expectEqual(
        source_mod.COLD_SOURCE_HEAP_ALLOCATIONS,
        cold.alloc_index,
    );

    var all_logs = [_]u32{4} ** roster.COMPONENT_COUNT;
    source.installLogSizes(&all_logs);
    all_logs[@intFromEnum(roster.Component.range_check_8_8)] = 16;
    const manifest = try universal_manifest.build(all_logs);
    const relations = universal.UniversalRelations.dummy();
    var preprocessed = try Tree.init(std.testing.allocator, &manifest, .preprocessed);
    defer preprocessed.deinit();
    var main = try Tree.init(std.testing.allocator, &manifest, .main);
    defer main.deinit();
    var interaction = try Tree.init(std.testing.allocator, &manifest, .interaction);
    defer interaction.deinit();

    var hot = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    source.allocator = hot.allocator();
    try source.fillPreprocessedInto(
        &pair.vm_plan,
        plans,
        &pair.transcript_preprocessing,
        &prepared,
        &manifest,
        preprocessed.columns,
    );
    const preprocessed_allocations = hot.alloc_index;
    try std.testing.expectEqual(
        source_mod.HOT_TREE_HEAP_ALLOCATIONS[0],
        preprocessed_allocations,
    );
    try source.fillMainInto(
        &pair.vm_plan,
        plans,
        &pair.transcript_preprocessing,
        &prepared,
        &manifest,
        main.columns,
    );
    const main_allocations = hot.alloc_index - preprocessed_allocations;
    try std.testing.expectEqual(
        source_mod.HOT_TREE_HEAP_ALLOCATIONS[1],
        main_allocations,
    );
    const compatibility_claims = try source.fillInteractionInto(
        &pair.vm_plan,
        plans,
        &pair.transcript_preprocessing,
        &prepared,
        &manifest,
        &relations,
        interaction.columns,
    );
    const interaction_allocations = hot.alloc_index -
        preprocessed_allocations - main_allocations;
    try std.testing.expectEqual(
        source_mod.HOT_TREE_HEAP_ALLOCATIONS[2],
        interaction_allocations,
    );
    try std.testing.expectEqual(source_mod.HOT_ALL_TREES_HEAP_ALLOCATIONS, hot.alloc_index);
    try std.testing.expectEqual(hot.allocated_bytes, hot.freed_bytes);

    var workspace_meter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var workspace = try Source.InteractionWorkspace.init(
        workspace_meter.allocator(),
        &source,
        &pair.transcript_preprocessing,
        &prepared,
    );
    var workspace_owned = true;
    defer if (workspace_owned) workspace.deinit();
    try std.testing.expectEqual(
        source_mod.INTERACTION_WORKSPACE_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index,
    );

    var reused_interaction = try Tree.init(
        std.testing.allocator,
        &manifest,
        .interaction,
    );
    defer reused_interaction.deinit();
    var second_reused_interaction = try Tree.init(
        std.testing.allocator,
        &manifest,
        .interaction,
    );
    defer second_reused_interaction.deinit();

    var reused_hot = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    source.allocator = reused_hot.allocator();
    const reused_claims = try source.fillInteractionIntoWithWorkspace(
        &workspace,
        &pair.vm_plan,
        plans,
        &pair.transcript_preprocessing,
        &prepared,
        &manifest,
        &relations,
        reused_interaction.columns,
    );
    try std.testing.expectEqual(
        source_mod.HOT_REUSED_TREE_HEAP_ALLOCATIONS[2],
        reused_hot.alloc_index,
    );
    for (compatibility_claims.asArray(), reused_claims.asArray()) |expected, actual|
        try std.testing.expect(expected.eql(actual));
    try std.testing.expectEqualSlices(
        M31,
        interaction.storage,
        reused_interaction.storage,
    );

    const second_reused_claims = try source.fillInteractionIntoWithWorkspace(
        &workspace,
        &pair.vm_plan,
        plans,
        &pair.transcript_preprocessing,
        &prepared,
        &manifest,
        &relations,
        second_reused_interaction.columns,
    );
    try std.testing.expectEqual(
        source_mod.HOT_REUSED_ALL_TREES_HEAP_ALLOCATIONS,
        reused_hot.alloc_index,
    );
    for (reused_claims.asArray(), second_reused_claims.asArray()) |expected, actual|
        try std.testing.expect(expected.eql(actual));
    try std.testing.expectEqualSlices(
        M31,
        reused_interaction.storage,
        second_reused_interaction.storage,
    );

    workspace.deinit();
    workspace_owned = false;
    try std.testing.expectEqual(
        workspace_meter.allocated_bytes,
        workspace_meter.freed_bytes,
    );
    source.allocator = source_allocator;
    source.deinit();
    source_owned = false;
    try std.testing.expectEqual(cold.allocated_bytes, cold.freed_bytes);
}

fn expectSourceAuthorityError(fixture: *Fixture) !void {
    try std.testing.expectError(
        error.PreparedAuthorityMismatch,
        fixture.source.validateAgainst(
            &fixture.pair.vm_plan,
            fixture.recursionPlans(),
            &fixture.pair.transcript_preprocessing,
            &fixture.prepared,
        ),
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    pair: fixture_mod.HonestFixture,
    prepared: Prepared,
    source: Source,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var pair = try fixture_mod.HonestFixture.init(allocator);
        errdefer pair.deinit();
        const plans = [2]*const air.verifier_schedule.Plan{
            &pair.recursion_plans[0],
            &pair.recursion_plans[1],
        };
        var prepared = try Prepared.init(
            allocator,
            .sealed_candidate,
            &pair.vm_plan,
            plans,
            &pair.transcript_preprocessing,
            &pair.statement_preprocessing,
            &pair.semantics,
            &pair.validation_workspace,
            pair.pair_inputs,
            pair.children(),
        );
        errdefer prepared.deinit();
        const logs = try prepared.minimumLogSizes(
            &pair.vm_plan,
            &pair.recursion_plans[0],
            &pair.transcript_preprocessing,
            &pair.statement_preprocessing,
        );
        var source = try Source.init(
            allocator,
            &pair.vm_plan,
            plans,
            &pair.transcript_preprocessing,
            &prepared,
            try source_mod.PowLogSizes.init(
                @max(source_mod.MIN_LOG_SIZE, logs[6]),
                @max(source_mod.MIN_LOG_SIZE, logs[7]),
            ),
        );
        errdefer source.deinit();
        return .{
            .allocator = allocator,
            .pair = pair,
            .prepared = prepared,
            .source = source,
        };
    }

    fn deinit(self: *Fixture) void {
        self.source.deinit();
        self.prepared.deinit();
        self.pair.deinit();
        self.* = undefined;
    }

    fn recursionPlans(self: *Fixture) [2]*const air.verifier_schedule.Plan {
        return .{ &self.pair.recursion_plans[0], &self.pair.recursion_plans[1] };
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
