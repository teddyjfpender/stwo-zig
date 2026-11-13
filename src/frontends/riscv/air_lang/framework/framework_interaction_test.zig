//! Independent framework writer parity and failure-atomicity qualification.

const std = @import("std");
const stwo_core = @import("stwo_core");
const logup = @import("../shared/air/logup.zig");
const universal = @import("universal_challenges.zig");
const committedRow = @import("framework_interaction.zig").committedRow;
const secureAt = @import("framework_interaction_row.zig").secureAt;
const Runtime = @import("framework_interaction.zig").Runtime;
const fields = stwo_core.fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;

test "R-012 framework interaction is source-exact, two-allocation, and failure atomic" {
    const std_testing = std.testing;
    const control = @import("control.zig");
    const control_relation = @import("control_relation.zig");
    const control_witness = @import("control_row.zig");
    const proof_kind = @import("proof_kind.zig");

    var definition = try control.build(std_testing.allocator);
    defer definition.deinit();
    const plan = try control_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const rows = [_]control_relation.Row{
        control_witness.logicalRow(.{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 0,
            .tag = 7,
            .args = .{ 11, 13, 17, 19 },
            .terminal_mask = 0,
        }, proof_kind.ProofKind.segment_leaf),
        control_witness.logicalRow(.{
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 1,
            .tag = 23,
            .args = .{ 29, 31, 37, 41 },
            .terminal_mask = 1,
        }, proof_kind.ProofKind.segment_leaf),
    };
    const Framework = Runtime(control_relation.Runtime);

    var measured = std_testing.FailingAllocator.init(std_testing.allocator, .{});
    {
        var generated = try Framework.generatePrepared(
            measured.allocator(),
            &plan,
            &rows,
            4,
            &relations,
        );
        defer generated.deinit(measured.allocator());
        try std_testing.expectEqual(@as(usize, 2), measured.alloc_index);
        try Framework.validatePrepared(
            std_testing.allocator,
            &plan,
            &rows,
            4,
            &relations,
            &generated,
        );

        // Non-final columns are same-row partial sums. The final column is the
        // shifted prefix and therefore closes to zero on the final logical row.
        const first_pairs = try plan.preparedRowPairs(rows[0], &relations);
        const first_expected = try pairValue(first_pairs[0]);
        try std_testing.expect(secureAt(
            &generated.columns,
            0,
            committedRow(0, 4),
        ).eql(first_expected));
        try std_testing.expect(secureAt(
            &generated.columns,
            Framework.BATCH_COUNT - 1,
            committedRow(15, 4),
        ).isZero());

        generated.columns[0][committedRow(0, 4)] =
            generated.columns[0][committedRow(0, 4)].add(M31.one());
        try std_testing.expectError(
            error.InteractionColumnMismatch,
            Framework.validatePrepared(
                std_testing.allocator,
                &plan,
                &rows,
                4,
                &relations,
                &generated,
            ),
        );
    }
    try std_testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std_testing.checkAllAllocationFailures(
        std_testing.allocator,
        frameworkFailureCase,
        .{ &plan, &rows, &relations },
    );
}

test "R-012 framework workspace is equivalent, zero-allocation, fail-atomic, and alias-safe" {
    const std_testing = std.testing;
    const control = @import("control.zig");
    const control_relation = @import("control_relation.zig");
    const control_witness = @import("control_row.zig");
    const proof_kind = @import("proof_kind.zig");
    const Framework = Runtime(control_relation.Runtime);
    const log_size: u32 = 4;
    const size: usize = 1 << log_size;

    var definition = try control.build(std_testing.allocator);
    defer definition.deinit();
    const plan = try control_relation.authenticate(&definition);
    var relations = universal.UniversalRelations.dummy();
    const rows = [_]control_relation.Row{
        control_witness.logicalRow(.{
            .segment_mask = 0,
            .binary_mask = 1,
            .verifier_id = 1,
            .sequence = 0,
            .tag = 43,
            .args = .{ 47, 53, 59, 61 },
            .terminal_mask = 0,
        }, proof_kind.ProofKind.binary_node),
        control_witness.logicalRow(.{
            .segment_mask = 0,
            .binary_mask = 1,
            .verifier_id = 1,
            .sequence = 1,
            .tag = 67,
            .args = .{ 71, 73, 79, 83 },
            .terminal_mask = 1,
        }, proof_kind.ProofKind.binary_node),
    };

    var expected = try Framework.generatePrepared(
        std_testing.allocator,
        &plan,
        &rows,
        log_size,
        &relations,
    );
    defer expected.deinit(std_testing.allocator);

    var fixed_storage: [64 * 1024]u8 align(@alignOf(QM31)) = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&fixed_storage);
    var workspace = try Framework.Workspace.init(fixed.allocator(), log_size);
    defer workspace.deinit();

    const sentinel = M31.fromCanonical(0x5a5a);
    var output = [_]M31{sentinel} ** (Framework.INTERACTION_COLUMN_COUNT * size);
    var columns: [Framework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = output[index * size ..][0..size];

    const allocation_cursor = fixed.end_index;
    const actual_claim = try Framework.generatePreparedInto(
        &workspace,
        &plan,
        &rows,
        log_size,
        &relations,
        &columns,
    );
    try std_testing.expectEqual(allocation_cursor, fixed.end_index);
    try std_testing.expect(actual_claim.eql(expected.claimed_sum));
    try std_testing.expectEqualSlices(M31, expected.storage, &output);

    // Domain decomposition reuses the same scratch and matches the independent
    // cold audit, including padding, without changing any committed column.
    @memset(&output, sentinel);
    const second_claim = try Framework.generatePreparedIntoWithDomainSums(
        &workspace,
        &plan,
        &rows,
        log_size,
        &relations,
        &columns,
    );
    try std_testing.expectEqual(allocation_cursor, fixed.end_index);
    try std_testing.expect(second_claim.claimed_sum.eql(expected.claimed_sum));
    const domain_audit = try plan.auditPreparedDomainSums(
        std_testing.allocator,
        &rows,
        &relations,
        expected.claimed_sum,
    );
    try std_testing.expectEqualDeep(domain_audit.values, second_claim.by_domain);
    try std_testing.expectEqualSlices(M31, expected.storage, &output);

    // Force a denominator to zero only after row evaluation has begun. The
    // full caller destination must retain its exact pre-call bytes.
    const first_pairs = try plan.preparedRowPairs(rows[0], &relations);
    const first_domain = @intFromEnum(plan.events[plan.batches[0].first].domain);
    relations.elements[first_domain].z = relations.elements[first_domain].z.add(
        first_pairs[0].d1,
    );
    @memset(&output, sentinel);
    try std_testing.expectError(
        error.ZeroDenominator,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    try std_testing.expectEqualSlices(
        M31,
        &([_]M31{sentinel} ** output.len),
        &output,
    );
    try std_testing.expectError(
        error.ZeroDenominator,
        Framework.generatePreparedIntoWithDomainSums(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    try std_testing.expectEqualSlices(
        M31,
        &([_]M31{sentinel} ** output.len),
        &output,
    );
    relations = universal.UniversalRelations.dummy();

    // Pairwise destination overlap is rejected before scratch or output work.
    const second_column = columns[1];
    columns[1] = columns[0];
    try std_testing.expectError(
        error.DestinationAlias,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    columns[1] = second_column;
    try std_testing.expectEqualSlices(
        M31,
        &([_]M31{sentinel} ** output.len),
        &output,
    );

    // A destination may not borrow the workspace's QM31 backing storage.
    const first_column = columns[0];
    columns[0] = @as([*]M31, @ptrCast(workspace.scratch.ptr))[0..size];
    try std_testing.expectError(
        error.DestinationAlias,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    columns[0] = first_column;

    // Geometry tampering fails closed without making the retained workspace
    // impossible to deinitialize after the admission check.
    const full_scratch = workspace.scratch;
    workspace.scratch = workspace.scratch[0 .. workspace.scratch.len - 1];
    try std_testing.expectError(
        error.WorkspaceCapacityMismatch,
        Framework.generatePreparedInto(
            &workspace,
            &plan,
            &rows,
            log_size,
            &relations,
            &columns,
        ),
    );
    workspace.scratch = full_scratch;
}

fn pairValue(pair: logup.RowPair) !QM31 {
    return pair.n1.mul(try pair.d1.inv())
        .add(pair.n2.mul(try pair.d2.inv()));
}

fn frameworkFailureCase(
    allocator: std.mem.Allocator,
    plan: *const @import("control_relation.zig").Plan,
    rows: []const @import("control_relation.zig").Row,
    relations: *const universal.UniversalRelations,
) !void {
    const Framework = Runtime(@import("control_relation.zig").Runtime);
    var generated = try Framework.generatePrepared(
        allocator,
        plan,
        rows,
        4,
        relations,
    );
    defer generated.deinit(allocator);
}

test "R-012 framework tiled owned output preserves columns and releases partial allocations" {
    const a = std.testing.allocator;
    const control = @import("control.zig");
    const relation = @import("control_relation.zig");
    const witness = @import("control_row.zig");
    const kind = @import("proof_kind.zig").ProofKind;
    const F = Runtime(relation.Runtime);
    var definition = try control.build(a);
    defer definition.deinit();
    const plan = try relation.authenticate(&definition);
    const rows = [_]relation.Row{
        witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 0, .tag = 7, .args = .{ 11, 13, 17, 19 }, .terminal_mask = 0 }, kind.segment_leaf),
        witness.logicalRow(.{ .segment_mask = 1, .binary_mask = 0, .verifier_id = 0, .sequence = 1, .tag = 23, .args = .{ 29, 31, 37, 41 }, .terminal_mask = 1 }, kind.segment_leaf),
    };
    var relations = universal.UniversalRelations.dummy();
    var oracle = try F.generatePrepared(a, &plan, &rows, 4, &relations);
    defer oracle.deinit(a);
    const view = F.ColumnRows{ .columns = @splat(&.{}), .count = rows.len, .main_count = 0, .metadata = &rows };
    for (0..5) |tile_log| {
        var workspace = try F.Workspace.init(a, @intCast(tile_log));
        defer workspace.deinit();
        try std.testing.checkAllAllocationFailures(a, tiledFailureCase, .{ &workspace, &plan, view, &relations, &oracle });
    }
    var workspace = try F.Workspace.init(a, 0);
    defer workspace.deinit();
    var helper = try F.Workspace.init(a, 0);
    defer helper.deinit();
    const workers = [_]*F.Workspace{ &workspace, &helper };
    try std.testing.checkAllAllocationFailures(a, scheduledFailureCase, .{ &workers, &plan, view, &relations, &oracle });
    try std.testing.expectError(error.DestinationAlias, F.generatePreparedOwnedColumnsScheduled(a, &.{ &workspace, &workspace }, &plan, view, 4, &relations, null, ReverseTiles{}));
    const pairs = try plan.preparedRowPairs(rows[0], &relations);
    const domain = @intFromEnum(plan.events[plan.batches[0].first].domain);
    relations.elements[domain].z = relations.elements[domain].z.add(pairs[0].d1);
    try std.testing.expectError(error.ZeroDenominator, F.generatePreparedOwnedColumnsTiledWithWorkspace(a, &workspace, &plan, view, 4, &relations, null));
    try std.testing.expectError(error.ZeroDenominator, F.generatePreparedOwnedColumnsScheduled(a, &workers, &plan, view, 4, &relations, null, ReverseTiles{}));
}
fn tiledFailureCase(a: std.mem.Allocator, workspace: *Runtime(@import("control_relation.zig").Runtime).Workspace, plan: *const @import("control_relation.zig").Plan, view: Runtime(@import("control_relation.zig").Runtime).ColumnRows, relations: *const universal.UniversalRelations, oracle: *const Runtime(@import("control_relation.zig").Runtime).Interaction) !void {
    const F = Runtime(@import("control_relation.zig").Runtime);
    var actual = try F.generatePreparedOwnedColumnsTiledWithWorkspace(a, workspace, plan, view, 4, relations, null);
    defer actual.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(actual.claimed_sum));
    for (oracle.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M31, left, right);
}

// Reverse completion order checks that prefix construction cannot depend on
// scheduling order. Production pool execution is also checked by proof parity.
const ReverseTiles = struct {
    pub fn run(_: @This(), contexts: anytype) void {
        var i = contexts.len;
        while (i != 0) {
            i -= 1;
            contexts[i].run();
        }
    }
};
fn scheduledFailureCase(a: std.mem.Allocator, workspaces: []const *Runtime(@import("control_relation.zig").Runtime).Workspace, plan: *const @import("control_relation.zig").Plan, view: Runtime(@import("control_relation.zig").Runtime).ColumnRows, relations: *const universal.UniversalRelations, oracle: *const Runtime(@import("control_relation.zig").Runtime).Interaction) !void {
    const F = Runtime(@import("control_relation.zig").Runtime);
    var actual = try F.generatePreparedOwnedColumnsScheduled(a, workspaces, plan, view, 4, relations, null, ReverseTiles{});
    defer actual.deinit(a);
    try std.testing.expect(oracle.claimed_sum.eql(actual.claimed_sum));
    for (oracle.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M31, left, right);
}
