//! Focused shard of binary_fri_outer_source_test.zig; import that suite facade.

const dependency_0 = @import("binary_fri_outer_source_test_capture_fixture.zig");
const dependency_1 = @import("binary_fri_outer_source_test_fixture.zig");
const dependency_2 = @import("binary_fri_outer_source_test_expect_arithmetic_plan_parity.zig");

const Fixture = dependency_1.Fixture;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const RIGHT_CHILD = dependency_2.RIGHT_CHILD;
const Source = dependency_0.Source;
const Tree = dependency_1.Tree;
const air = dependency_0.air;
const expectArithmeticPlanParity = dependency_2.expectArithmeticPlanParity;
const expectZeroPadding = dependency_2.expectZeroPadding;
const source_mod = dependency_0.source_mod;
const std = dependency_0.std;

test "R-015 binary FRI rows 30--32 lower exact child graphs with zero hot allocations" {
    var fixture = try Fixture.initWithComposition(std.testing.allocator);
    defer fixture.deinit();
    try fixture.source.requireCompositionAuthorities();
    const logs = try fixture.source.arithmeticLogSizes();

    var workspace_meter = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var workspace = try Source.ArithmeticWorkspace.init(
        workspace_meter.allocator(),
        &fixture.source,
    );
    defer workspace.deinit();
    try std.testing.expectEqual(
        source_mod.ROWS_30_32_WORKSPACE_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index,
    );

    var preprocessed = try Tree.init(
        std.testing.allocator,
        logs,
        source_mod.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW,
    );
    defer preprocessed.deinit();
    var main = try Tree.init(
        std.testing.allocator,
        logs,
        source_mod.ARITHMETIC_MAIN_COLUMNS_PER_ROW,
    );
    defer main.deinit();
    try fixture.source.fillArithmeticPreprocessedInto(
        &workspace,
        preprocessed.columns,
    );
    try fixture.source.fillArithmeticMainInto(&workspace, main.columns);
    try std.testing.expect(preprocessed.anyNonZero());
    try std.testing.expect(main.anyNonZero());
    try expectArithmeticPlanParity(&fixture.source, &workspace, &preprocessed, &main);

    const hot_before = workspace_meter.alloc_index;
    try fixture.source.fillArithmeticPreprocessedInto(
        &workspace,
        preprocessed.columns,
    );
    try fixture.source.fillArithmeticMainInto(&workspace, main.columns);
    try std.testing.expectEqual(
        source_mod.ROWS_30_32_REUSED_HOT_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index - hot_before,
    );

    const sentinel = M31.fromCanonical(4_242);
    main.fill(sentinel);
    const original_value = @constCast(
        fixture.capture_children[RIGHT_CHILD].capture.evaluation.values,
    )[0];
    @constCast(fixture.capture_children[RIGHT_CHILD].capture.evaluation.values)[0] =
        original_value.add(QM31.one());
    try std.testing.expectError(
        error.InvalidWitness,
        fixture.source.fillArithmeticMainInto(&workspace, main.columns),
    );
    @constCast(fixture.capture_children[RIGHT_CHILD].capture.evaluation.values)[0] =
        original_value;
    try main.expectFilled(sentinel);

    const original_column = main.columns[1];
    main.columns[1] = main.columns[0];
    try std.testing.expectError(
        error.DestinationAlias,
        fixture.source.fillArithmeticMainInto(&workspace, main.columns),
    );
    main.columns[1] = original_column;
    try main.expectFilled(sentinel);

    workspace.arithmetic_authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.WorkspaceAuthorityMismatch,
        fixture.source.fillArithmeticMainInto(&workspace, main.columns),
    );
    workspace.arithmetic_authority_digest[0] ^= 1;
    try main.expectFilled(sentinel);
}

test "R-015 binary FRI rows 33--34 retain exact paths and shared provider calls" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var fri_workspace = try Source.Workspace.init(
        std.testing.allocator,
        &fixture.source,
    );
    defer fri_workspace.deinit();
    var fri_main = try Tree.init(
        std.testing.allocator,
        fixture.source.friLogSizes(),
        source_mod.MAIN_COLUMNS_PER_ROW,
    );
    defer fri_main.deinit();
    try fixture.source.fillFriMainInto(&fri_workspace, fri_main.columns);

    var workspace_meter = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var workspace = try Source.MerkleWorkspace.init(
        workspace_meter.allocator(),
        &fixture.source,
    );
    defer workspace.deinit();
    try std.testing.expectEqual(
        source_mod.ROW_33_WORKSPACE_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index,
    );
    try fixture.source.prepareMerkleWorkspace(&fri_workspace, &workspace);

    const merkle_logs = [1]u32{try fixture.source.merkleLogSize()};
    const merkle_columns = [1]usize{source_mod.MERKLE_PATH_MAIN_COLUMN_COUNT};
    var main = try Tree.init(
        std.testing.allocator,
        merkle_logs,
        merkle_columns,
    );
    defer main.deinit();
    try fixture.source.fillMerkleMainInto(
        &fri_workspace,
        &workspace,
        main.columns,
    );
    try std.testing.expect(main.anyNonZero());
    try expectMerkleParity(&fixture.source, &fri_workspace, &workspace, &main);

    const hot_before = workspace_meter.alloc_index;
    try fixture.source.prepareMerkleWorkspace(&fri_workspace, &workspace);
    try fixture.source.fillMerkleMainInto(
        &fri_workspace,
        &workspace,
        main.columns,
    );
    _ = try fixture.source.merklePoseidonCalls(&fri_workspace, &workspace);
    try std.testing.expectEqual(
        source_mod.ROW_33_REUSED_HOT_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index - hot_before,
    );

    const sentinel = M31.fromCanonical(7_777);
    main.fill(sentinel);
    workspace.invocations[0].step.direction ^= 1;
    try std.testing.expectError(
        error.WorkspaceAuthorityMismatch,
        fixture.source.fillMerkleMainInto(
            &fri_workspace,
            &workspace,
            main.columns,
        ),
    );
    workspace.invocations[0].step.direction ^= 1;
    try main.expectFilled(sentinel);

    const original_column = main.columns[1];
    main.columns[1] = main.columns[0];
    try std.testing.expectError(
        error.DestinationAlias,
        fixture.source.fillMerkleMainInto(
            &fri_workspace,
            &workspace,
            main.columns,
        ),
    );
    main.columns[1] = original_column;
    try main.expectFilled(sentinel);
}

pub const ManifestTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const air.universal_adapter_manifest.Manifest,
        tree: usize,
    ) !ManifestTree {
        const total_columns: usize = switch (tree) {
            air.universal_adapter_manifest.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
            air.universal_adapter_manifest.MAIN_TREE_INDEX => manifest.total_main_columns,
            air.universal_adapter_manifest.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
            else => return error.InvalidTreeIndex,
        };
        const columns = try allocator.alloc([]M31, total_columns);
        errdefer allocator.free(columns);
        var total_storage: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const count: usize = switch (tree) {
                0 => placement.geometry.preprocessed_columns,
                1 => placement.geometry.main_columns,
                2 => placement.geometry.interaction_columns,
                else => unreachable,
            };
            total_storage += count *
                (@as(usize, 1) << @intCast(placement.geometry.log_size));
        }
        const storage = try allocator.alloc(M31, total_storage);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var storage_at: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = switch (tree) {
                0 => placement.preprocessed_offset,
                1 => placement.main_offset,
                2 => placement.interaction_offset,
                else => unreachable,
            };
            const count: usize = switch (tree) {
                0 => placement.geometry.preprocessed_columns,
                1 => placement.geometry.main_columns,
                2 => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const row_count = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            for (columns[offset..][0..count]) |*column| {
                column.* = storage[storage_at..][0..row_count];
                storage_at += row_count;
            }
        }
        std.debug.assert(storage_at == storage.len);
        return .{ .allocator = allocator, .columns = columns, .storage = storage };
    }

    fn deinit(self: *ManifestTree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    fn anyNonZero(self: *const ManifestTree) bool {
        for (self.storage) |value| if (!value.isZero()) return true;
        return false;
    }

    fn allZero(self: *const ManifestTree) bool {
        return !self.anyNonZero();
    }
};

/// Evaluates the exact row-18 trace through the same allocation-free base-row
/// kernel used by the prover adapter. This closes the gap between a successful
/// tuple-ledger audit and the stronger requirement that every direct and
/// framework recurrence root vanish on the committed witness.
pub fn validateCompositionInputBaseRows(
    component: anytype,
    rows: []const air.vm_air_composition_input_relation.Row,
    preprocessed_columns: []const []M31,
    main_columns: []const []M31,
    interaction_columns: []const []M31,
) !void {
    const Adapter = @TypeOf(component.*);
    const Row = air.vm_air_composition_input_relation.Row;
    const trace_size = @as(usize, 1) << @intCast(component.log_size);
    if (rows.len > trace_size) return error.InvalidTraceShape;

    for (0..trace_size) |logical_row| {
        const committed = air.framework_interaction.committedRow(
            logical_row,
            component.log_size,
        );
        const previous = air.framework_interaction.committedRow(
            (logical_row + trace_size - 1) % trace_size,
            component.log_size,
        );
        var row: Row = undefined;
        for (
            row[0..air.vm_air_composition_input.PHYSICAL_MAIN_COLUMN_COUNT],
            main_columns[component.placement.main_offset..][0..air.vm_air_composition_input.PHYSICAL_MAIN_COLUMN_COUNT],
        ) |*value, column| value.* = column[committed];
        const preprocessed_start =
            air.vm_air_composition_input.PHYSICAL_MAIN_COLUMN_COUNT;
        for (
            row[preprocessed_start..][0..air.vm_air_composition_input.PREPROCESSED_COLUMN_COUNT],
            preprocessed_columns[component.placement.preprocessed_offset..][0..air.vm_air_composition_input.PREPROCESSED_COLUMN_COUNT],
        ) |*value, column| value.* = column[committed];
        @memcpy(
            row[row.len - Adapter.PARAMETER_COLUMN_COUNT ..],
            &component.parameters,
        );

        var expected: Row = [_]M31{M31.zero()} **
            air.vm_air_composition_input.LOGICAL_INPUT_COUNT;
        if (logical_row < rows.len) expected = rows[logical_row] else @memcpy(
            expected[expected.len - Adapter.PARAMETER_COLUMN_COUNT ..],
            &component.parameters,
        );
        if (!std.meta.eql(row, expected)) {
            for (row, expected, 0..) |actual, wanted, column| {
                if (!actual.eql(wanted)) {
                    std.debug.print(
                        "row-18 committed trace mismatch logical_row={d} column={d} actual={d} expected={d}\n",
                        .{ logical_row, column, actual.toU32(), wanted.toU32() },
                    );
                    break;
                }
            }
            return error.ConstraintsNotSatisfied;
        }

        var current: [Adapter.INTERACTION_BATCH_COUNT]QM31 = undefined;
        for (&current, 0..) |*value, batch| value.* = secureColumnAt(
            interaction_columns,
            component.placement.interaction_offset + 4 * batch,
            committed,
        );
        const final_previous = secureColumnAt(
            interaction_columns,
            component.placement.interaction_offset +
                4 * (Adapter.INTERACTION_BATCH_COUNT - 1),
            previous,
        );
        var roots: [Adapter.CONSTRAINT_COUNT_TOTAL]QM31 = undefined;
        try component.evaluateBaseRowInto(
            row,
            current,
            final_previous,
            &roots,
        );
        for (roots, 0..) |root, constraint| if (!root.isZero()) {
            if (constraint < air.vm_air_composition_input.DIRECT_CONSTRAINT_COUNT) {
                std.debug.print(
                    "row-18 base root failed logical_row={d} constraint={d} ({s}) root={any}\n",
                    .{
                        logical_row,
                        constraint,
                        air.vm_air_composition_input.CONSTRAINT_NAMES[constraint],
                        root.toM31Array(),
                    },
                );
            } else {
                std.debug.print(
                    "row-18 LogUp root failed logical_row={d} batch={d} root={any}\n",
                    .{
                        logical_row,
                        constraint - air.vm_air_composition_input.DIRECT_CONSTRAINT_COUNT,
                        root.toM31Array(),
                    },
                );
            }
            return error.ConstraintsNotSatisfied;
        };
    }
}

pub fn secureColumnAt(
    columns: []const []M31,
    offset: usize,
    row: usize,
) QM31 {
    return QM31.fromM31Array(.{
        columns[offset][row],
        columns[offset + 1][row],
        columns[offset + 2][row],
        columns[offset + 3][row],
    });
}

pub fn expectMerkleParity(
    source: *const Source,
    fri_workspace: *const Source.Workspace,
    workspace: *const Source.MerkleWorkspace,
    main: *const Tree,
) !void {
    const retained = try source.merkleRelationRows(fri_workspace, workspace);
    const calls = try source.merklePoseidonCalls(fri_workspace, workspace);
    const outputs = try source.merklePoseidonOutputs(fri_workspace, workspace);
    try std.testing.expectEqual(workspace.invocations.len, retained.len);
    try std.testing.expectEqual(calls.len, outputs.len);
    try std.testing.expect(calls.len >= workspace.invocations.len);
    try std.testing.expect(
        calls.len <= @as(usize, 1) << @intCast(workspace.provider_log_size),
    );
    var transcript_at: usize = 0;
    for (source.pair.executions) |execution| {
        for (execution.poseidon_calls) |expected| {
            for (expected.input, calls[transcript_at].input) |lhs, rhs|
                try std.testing.expectEqual(lhs.toU32(), rhs);
            for (expected.output, outputs[transcript_at]) |lhs, rhs|
                try std.testing.expectEqual(lhs.toU32(), rhs);
            transcript_at += 1;
        }
    }
    const path_base = calls.len - workspace.invocations.len;
    try std.testing.expect(path_base >= transcript_at);
    for (workspace.invocations, retained, 0..) |
        invocation,
        row,
        row_index,
    | {
        const expected_row = try air.merkle_path_witness.logicalRow(invocation);
        try std.testing.expectEqualSlices(M31, &expected_row, &row);
        const expected_call = try air.merkle_path_poseidon_bridge.call(invocation);
        try std.testing.expect(std.meta.eql(
            expected_call,
            calls[path_base + row_index],
        ));
        const committed = air.framework_interaction.committedRow(
            row_index,
            workspace.log_size,
        );
        for (row, main.columns) |value, column|
            try std.testing.expect(column[committed].eql(value));
        _ = try source.merkle_rows.relation.entries(
            &source.merkle_rows.definition.arena,
            air.merkle_path.SEMANTIC_DIGEST,
            source.merkle_rows.definition.events,
            row,
        );
    }
    try expectZeroPadding(
        main.columns,
        0,
        source_mod.MERKLE_PATH_MAIN_COLUMN_COUNT,
        retained.len,
        workspace.log_size,
    );
}
