//! Shared assertions for the opcode composition manifest suites.

const std = @import("std");
const circle = @import("stwo_core").circle;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const subject = @import("opcode_composition_manifest.zig");
const constraint_program = @import("../constraint_program.zig");
const SemanticComponent = @import("../semantic_component.zig").SemanticComponent;
const opcode_component = @import("../lookups/opcode_component.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const statement_mod = @import("../statement.zig");
const base_component_assembly = @import("../../prover/base_component_assembly.zig");
const proof_finalize = @import("../../prover/proof_finalize.zig");
const proof_workspace = @import("../../prover/proof_workspace.zig");
const verifier = @import("../../prover/verifier.zig");
const trace = @import("../../runner/trace.zig");

pub fn expectCanonicalMasks(item: *const subject.Descriptor) !void {
    try std.testing.expectEqual(subject.Tree.preprocessed, item.semantic_masks.preprocessed.tree);
    try std.testing.expectEqual(@as(usize, 1), item.semantic_masks.preprocessed.columns);
    try std.testing.expectEqual(@as(usize, 1), item.semantic_masks.preprocessed.declared_columns);
    try std.testing.expectEqual(subject.RowWindow.current, item.semantic_masks.preprocessed.window);
    try std.testing.expectEqual(subject.Tree.main, item.semantic_masks.main.tree);
    try std.testing.expectEqual(item.main_columns, item.semantic_masks.main.columns);
    try std.testing.expectEqual(item.main_columns, item.semantic_masks.main.declared_columns);
    try std.testing.expectEqual(@as(usize, 0), item.semantic_masks.interaction.columns);
    try std.testing.expectEqual(@as(usize, 0), item.semantic_masks.interaction.declared_columns);

    try std.testing.expectEqual(subject.Tree.preprocessed, item.lookup_masks.preprocessed.tree);
    try std.testing.expectEqual(@as(usize, 1), item.lookup_masks.preprocessed.columns);
    try std.testing.expectEqual(@as(usize, 1), item.lookup_masks.preprocessed.declared_columns);
    try std.testing.expectEqual(subject.Tree.main, item.lookup_masks.main.tree);
    try std.testing.expectEqual(item.main_columns, item.lookup_masks.main.columns);
    try std.testing.expectEqual(@as(usize, 0), item.lookup_masks.main.declared_columns);
    try std.testing.expectEqual(subject.Tree.interaction, item.lookup_masks.interaction.tree);
    try std.testing.expectEqual(item.interaction_columns, item.lookup_masks.interaction.columns);
    try std.testing.expectEqual(
        item.interaction_columns,
        item.lookup_masks.interaction.declared_columns,
    );
    try std.testing.expectEqual(
        subject.RowWindow.current_and_previous,
        item.lookup_masks.interaction.window,
    );
    try std.testing.expectEqual(
        2 * item.interaction_columns,
        try item.lookup_masks.interaction.sampledValues(),
    );
}

pub fn expectBoundGeometry(
    actual: []const []u32,
    expected: *const subject.AdapterMasks,
    log_size: u32,
) !void {
    try std.testing.expectEqual(@as(usize, 3), actual.len);
    const geometries = [_]subject.TreeMask{
        expected.preprocessed,
        expected.main,
        expected.interaction,
    };
    for (actual, geometries) |tree, geometry| {
        try std.testing.expectEqual(geometry.declared_columns, tree.len);
        for (tree) |bound| try std.testing.expectEqual(log_size, bound);
    }
}

pub fn expectMaskGeometry(
    actual: []const [][]circle.CirclePointQM31,
    expected: *const subject.AdapterMasks,
    current: circle.CirclePointQM31,
    previous: circle.CirclePointQM31,
) !void {
    try std.testing.expectEqual(@as(usize, 3), actual.len);
    const geometries = [_]subject.TreeMask{
        expected.preprocessed,
        expected.main,
        expected.interaction,
    };
    for (actual, geometries) |tree, geometry| {
        try std.testing.expectEqual(geometry.declared_columns, tree.len);
        for (tree) |column| {
            try std.testing.expectEqual(
                @as(usize, @intFromEnum(geometry.window)),
                column.len,
            );
            try expectPointEqual(current, column[0]);
            if (column.len == 2) try expectPointEqual(previous, column[1]);
        }
    }
}

pub fn expectPointEqual(
    expected: circle.CirclePointQM31,
    actual: circle.CirclePointQM31,
) !void {
    try std.testing.expect(expected.x.eql(actual.x));
    try std.testing.expect(expected.y.eql(actual.y));
}

pub fn expectPlacement(
    actual: subject.PlacementCursor.Placement,
    family: subject.Family,
    component_index: usize,
    semantic_adapter_index: usize,
    lookup_adapter_index: usize,
    is_first_column: usize,
    is_active_column: usize,
    main_column_offset: usize,
    interaction_column_offset: usize,
    main_columns: usize,
    interaction_columns: usize,
) !void {
    try std.testing.expectEqualDeep(subject.PlacementCursor.Placement{
        .family = family,
        .component_index = component_index,
        .semantic_adapter_index = semantic_adapter_index,
        .lookup_adapter_index = lookup_adapter_index,
        .is_first_column = is_first_column,
        .is_active_column = is_active_column,
        .main_column_offset = main_column_offset,
        .interaction_column_offset = interaction_column_offset,
        .main_columns = main_columns,
        .interaction_columns = interaction_columns,
    }, actual);
}

pub fn populateCanonicalInfrastructure(statement: *statement_mod.RiscVStatement) void {
    const kinds = base_component_assembly.CANONICAL_INFRASTRUCTURE_ORDER;
    statement.initial_pc = 0x1000;
    statement.total_steps = 1;
    statement.n_infra = @intCast(kinds.len);
    for (kinds, 0..) |kind, index| {
        const item = base_component_assembly.infrastructureDescriptor(kind);
        statement.infra_descs[index] = .{
            .kind = kind,
            .log_size = 4,
            .n_rows = 1,
            .n_columns = @intCast(item.main_columns),
        };
    }
}

pub fn expectInfrastructureOffsets(
    value: anytype,
    placement: base_component_assembly.InfrastructureCursor.Placement,
) !void {
    try std.testing.expectEqual(
        placement.preprocessed_column_offset,
        value.is_first_col_idx,
    );
    try std.testing.expectEqual(
        placement.main_column_offset,
        value.main_col_offset,
    );
    try std.testing.expectEqual(
        placement.interaction_column_offset,
        value.interaction_col_offset,
    );
}

pub fn expectHandleContext(ctx: *const anyopaque, value: anytype) !void {
    try std.testing.expectEqual(@intFromPtr(value), @intFromPtr(ctx));
}

pub fn expectAssemblyRejectsAtomically(
    prover_workspace: *proof_workspace.ProofWorkspace,
    verifier_workspace: *proof_workspace.VerificationWorkspace,
    claim: *const statement_mod.RiscVInteractionClaim,
    relations: *const relations_mod.Relations,
) !void {
    const n_main: usize = @intCast(prover_workspace.statement.nMainColumns());
    const n_interaction: usize = @intCast(
        prover_workspace.statement.nInteractionColumns(),
    );
    try std.testing.expectError(
        error.InvalidStatement,
        proof_finalize.assemble(
            prover_workspace,
            relations,
            claim,
            n_main,
            n_interaction,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), prover_workspace.components.active().len);
    try std.testing.expectEqual(@as(usize, 0), prover_workspace.components.n_hash);

    try std.testing.expectError(
        error.InvalidStatement,
        verifier.assembleComponents(
            verifier_workspace,
            &prover_workspace.statement,
            claim,
            relations,
            n_main,
            n_interaction,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), verifier_workspace.components.active().len);
    try std.testing.expectEqual(@as(usize, 0), verifier_workspace.components.n_hash);
}

pub fn containsPointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .array => |info| containsPointer(info.child),
        .optional => |info| containsPointer(info.child),
        .@"struct" => |info| blk: {
            inline for (info.fields) |field| {
                if (containsPointer(field.type)) break :blk true;
            }
            break :blk false;
        },
        else => false,
    };
}

pub fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

pub fn expectAbsent(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) == null);
}
