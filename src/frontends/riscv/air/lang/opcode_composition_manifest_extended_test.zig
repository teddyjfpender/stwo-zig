//! Extended mask, placement, and fixed-storage manifest tests.

const std = @import("std");
const circle = @import("stwo_core").circle;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const subject = @import("opcode_composition_manifest.zig");
const compat_manifest = @import("compat_manifest.zig");
const static_registry = @import("static_profile_registry.zig");
const constraint_program = @import("../constraint_program.zig");
const component_order = @import("../component_order.zig");
const SemanticComponent = @import("../semantic_component.zig").SemanticComponent;
const opcode_component = @import("../lookups/opcode_component.zig");
const entry = @import("../lookups/entry.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const statement_mod = @import("../statement.zig");
const base_component_assembly = @import("../../prover/base_component_assembly.zig");
const proof_finalize = @import("../../prover/proof_finalize.zig");
const proof_workspace = @import("../../prover/proof_workspace.zig");
const verifier = @import("../../prover/verifier.zig");
const trace = @import("../../runner/trace.zig");
const witness_layout = @import("../../witness_layout.zig");
const support = @import("opcode_composition_manifest_test_support.zig");

const expectCanonicalMasks = support.expectCanonicalMasks;
const expectBoundGeometry = support.expectBoundGeometry;
const expectMaskGeometry = support.expectMaskGeometry;
const expectPointEqual = support.expectPointEqual;
const expectPlacement = support.expectPlacement;
const populateCanonicalInfrastructure = support.populateCanonicalInfrastructure;
const expectInfrastructureOffsets = support.expectInfrastructureOffsets;
const expectHandleContext = support.expectHandleContext;
const expectAssemblyRejectsAtomically = support.expectAssemblyRejectsAtomically;
const containsPointer = support.containsPointer;
const expectContains = support.expectContains;
const expectAbsent = support.expectAbsent;

test "E-022 live semantic and lookup masks exactly materialize all 17 manifest descriptors" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const max_log_degree_bound: u32 = 7;
    const previous = logup.prevRowPoint(max_log_degree_bound, point);
    const relations = relations_mod.Relations.dummy();
    const zero_claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;

    inline for (0..subject.FAMILY_COUNT) |family_index| {
        const family: subject.Family = @enumFromInt(family_index);
        const item = subject.descriptor(family);
        const semantic = try SemanticComponent.init(family, log_size, 7, 11);
        const lookup = try opcode_component.OpcodeLookupComponent.initVerifier(
            family,
            log_size,
            13,
            17,
            19,
            &relations,
            zero_claims[0..subject.lookupBatchCount(family)],
        );

        {
            var bounds = try semantic.traceLogDegreeBounds(allocator);
            defer bounds.deinitDeep(allocator);
            try expectBoundGeometry(
                bounds.items,
                &item.semantic_masks,
                log_size,
            );
        }
        {
            var masks = try semantic.maskPoints(
                allocator,
                point,
                max_log_degree_bound,
            );
            defer masks.deinitDeep(allocator);
            try expectMaskGeometry(
                masks.items,
                &item.semantic_masks,
                point,
                previous,
            );
        }
        {
            const indices = try semantic.preprocessedColumnIndices(allocator);
            defer allocator.free(indices);
            try std.testing.expectEqualSlices(usize, &.{7}, indices);
        }

        {
            var bounds = try lookup.traceLogDegreeBounds(allocator);
            defer bounds.deinitDeep(allocator);
            try expectBoundGeometry(
                bounds.items,
                &item.lookup_masks,
                log_size,
            );
        }
        {
            var masks = try lookup.maskPoints(
                allocator,
                point,
                max_log_degree_bound,
            );
            defer masks.deinitDeep(allocator);
            try expectMaskGeometry(
                masks.items,
                &item.lookup_masks,
                point,
                previous,
            );
        }
        {
            const indices = try lookup.preprocessedColumnIndices(allocator);
            defer allocator.free(indices);
            try std.testing.expectEqualSlices(usize, &.{13}, indices);
        }
    }
}

test "E-022 maximum-width mask metadata preserves exact allocation ceilings" {
    const family: subject.Family = .div;
    const item = subject.descriptor(family);
    const relations = relations_mod.Relations.dummy();
    const zero_claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const semantic = try SemanticComponent.init(family, 4, 7, 11);
    const lookup = try opcode_component.OpcodeLookupComponent.initVerifier(
        family,
        4,
        13,
        17,
        19,
        &relations,
        zero_claims[0..subject.lookupBatchCount(family)],
    );
    var meter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = meter.allocator();

    {
        const before = meter.alloc_index;
        var bounds = try semantic.traceLogDegreeBounds(allocator);
        defer bounds.deinitDeep(allocator);
        try std.testing.expectEqual(@as(usize, 3), meter.alloc_index - before);
    }
    {
        const before = meter.alloc_index;
        var masks = try semantic.maskPoints(
            allocator,
            circle.SECURE_FIELD_CIRCLE_GEN,
            7,
        );
        defer masks.deinitDeep(allocator);
        try std.testing.expectEqual(
            item.semantic_masks.main.declared_columns + 4,
            meter.alloc_index - before,
        );
    }
    {
        const before = meter.alloc_index;
        const indices = try semantic.preprocessedColumnIndices(allocator);
        defer allocator.free(indices);
        try std.testing.expectEqual(@as(usize, 1), meter.alloc_index - before);
    }
    {
        const before = meter.alloc_index;
        var bounds = try lookup.traceLogDegreeBounds(allocator);
        defer bounds.deinitDeep(allocator);
        try std.testing.expectEqual(@as(usize, 3), meter.alloc_index - before);
    }
    {
        const before = meter.alloc_index;
        var masks = try lookup.maskPoints(
            allocator,
            circle.SECURE_FIELD_CIRCLE_GEN,
            7,
        );
        defer masks.deinitDeep(allocator);
        try std.testing.expectEqual(
            item.lookup_masks.interaction.declared_columns + 4,
            meter.alloc_index - before,
        );
    }
    {
        const before = meter.alloc_index;
        const indices = try lookup.preprocessedColumnIndices(allocator);
        defer allocator.free(indices);
        try std.testing.expectEqual(@as(usize, 1), meter.alloc_index - before);
    }
}

test "E-022 component mask builders retired handwritten production geometry" {
    const semantic_source = @embedFile("../semantic_component.zig");
    const lookup_source = @embedFile("../lookups/opcode_component.zig");

    try expectContains(
        semantic_source,
        "const row_window = @import(\"lang/row_window.zig\");",
    );
    try expectContains(
        semantic_source,
        "row_window.SemanticMaskBinding.init(family)",
    );
    try expectContains(
        semantic_source,
        "self.mask_binding.owned_main_current_columns",
    );
    try expectAbsent(
        semantic_source,
        "composition_manifest.semanticMasks(self.family)",
    );
    try expectAbsent(
        semantic_source,
        "const preprocessed = try allocator.dupe(u32, &.{self.log_size});",
    );
    try expectAbsent(
        semantic_source,
        "const main = try allocator.alloc(u32, self.mainColumnCount());",
    );
    try expectAbsent(
        semantic_source,
        "const interaction = try allocator.alloc(u32, 0);",
    );

    try expectContains(
        lookup_source,
        "const composition_manifest = @import(\"../lang/opcode_composition_manifest.zig\");",
    );
    try expectContains(
        lookup_source,
        "const authority = composition_manifest.lookupMasks(self.family).*;",
    );
    try expectAbsent(
        lookup_source,
        "const main = try allocator.alloc(u32, 0);",
    );
    try expectAbsent(
        lookup_source,
        "const secure = try allocator.alloc(u32, self.interactionColumnCount());",
    );
    try expectAbsent(
        lookup_source,
        "const main = try currentPointColumns(allocator, 0, point);",
    );
}

test "E-022 statement claim projection preserves the frozen mapping for all 17 families" {
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = @intCast(subject.FAMILY_COUNT);
    statement.n_infra = 0;

    inline for (0..subject.FAMILY_COUNT) |family_index| {
        const family: subject.Family = @enumFromInt(family_index);
        statement.component_descs[family_index] = .{
            .family = family,
            .log_size = @intCast(8 + family_index),
            .n_rows = 1,
            .n_columns = @intCast(subject.mainColumnCount(family)),
        };
    }

    const main = statement.canonicalMainClaim();
    inline for (0..subject.FAMILY_COUNT) |family_index| {
        const family: subject.Family = @enumFromInt(family_index);
        try std.testing.expectEqual(
            @as(u32, @intCast(8 + family_index)),
            main.get(subject.transcriptComponent(family)),
        );
    }

    const interaction = try std.testing.allocator.create(
        statement_mod.RiscVInteractionClaim,
    );
    defer std.testing.allocator.destroy(interaction);
    interaction.initZeroInto();
    interaction.n_components = @intCast(subject.FAMILY_COUNT);
    interaction.n_infra = 0;

    inline for (0..subject.FAMILY_COUNT) |family_index| {
        interaction.opcode_claims[family_index][0] = QM31.fromU32Unchecked(
            @intCast(family_index + 1),
            0,
            0,
            0,
        );
    }
    const canonical = try interaction.canonical(&statement);
    const canonical_view = canonical.view();
    inline for (0..subject.FAMILY_COUNT) |family_index| {
        const family: subject.Family = @enumFromInt(family_index);
        const expected = QM31.fromU32Unchecked(
            @intCast(family_index + 1),
            0,
            0,
            0,
        );
        try std.testing.expect(
            canonical_view.get(subject.transcriptComponent(family)).eql(expected),
        );
    }
    try std.testing.expectEqual(@as(usize, 620), canonical.n_log_sizes);
}

test "E-022 composition metadata is pointer-free fixed storage" {
    try std.testing.expect(!comptime containsPointer(subject.Descriptor));
    try std.testing.expect(!comptime containsPointer(subject.PlacementCursor));
    try std.testing.expect(!comptime containsPointer(subject.PlacementCursor.Placement));
    try std.testing.expect(!comptime containsPointer(
        base_component_assembly.InfrastructureDescriptor,
    ));
    try std.testing.expect(!comptime containsPointer(
        base_component_assembly.InfrastructureCursor,
    ));
    try std.testing.expect(!comptime containsPointer(
        base_component_assembly.InfrastructureCursor.Placement,
    ));
}
