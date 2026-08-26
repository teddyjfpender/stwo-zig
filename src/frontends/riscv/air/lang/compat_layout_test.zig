const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_component = @import("../lookups/opcode_component.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const relations_mod = @import("../relation_challenges.zig");
const semantic_component = @import("../semantic_component.zig");
const trace = @import("../../runner/trace.zig");
const witness_layout = @import("../../witness_layout.zig");
const compat_layout = @import("compat_layout.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");

test "compat-v1 maps every production column in exact local order" {
    try std.testing.expectEqualStrings(
        "stwo.riscv.opcode.compat-v1",
        compat_layout.policy_id,
    );
    try std.testing.expectEqual(@as(u16, 1), compat_layout.policy_version);
    inline for (@typeInfo(trace.OpcodeFamily).@"enum".fields) |family_field| {
        const family: trace.OpcodeFamily = @enumFromInt(family_field.value);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        try layout.validate(&imported);

        const Layout = witness_layout.LayoutFor(family);
        const production_names = comptime fieldNames(Layout);
        try std.testing.expectEqual(production_names.len, layout.main().len);
        try std.testing.expectEqual(
            opcode_entries.interactionColumnCount(family),
            layout.interactions().len,
        );
        for (layout.main(), production_names, 0..) |column, name, index| {
            try std.testing.expectEqualStrings(name, column.physical_name);
            try std.testing.expect(column.logical_name.len != 0);
            try std.testing.expectEqual(
                compat_layout.Tree.main,
                column.reference.tree,
            );
            try std.testing.expectEqual(@as(u32, @intCast(index)), column.reference.local_index);
            try std.testing.expectEqual(compat_layout.Window.current, column.window);
            try std.testing.expectEqual(
                column.reference,
                layout.referenceForValue(column.value).?,
            );
        }
        try std.testing.expectEqual(
            layout.preprocessed[1].reference,
            layout.referenceForValue(imported.selector).?,
        );

        for (layout.interactions(), 0..) |column, index| {
            const expected_batch = index / 4;
            try std.testing.expectEqual(
                @as(u32, @intCast(expected_batch)),
                column.batch,
            );
            try std.testing.expectEqual(
                @as(u8, @intCast(index % 4)),
                @intFromEnum(column.coordinate),
            );
            try std.testing.expectEqual(
                compat_layout.Window.current_and_previous,
                column.window,
            );
        }
    }
}

test "compat-v1 main mapping reproduces the Sail-authoritative layout receipt" {
    try std.testing.expectEqual(
        witness_layout.digest(),
        try mappedWitnessDigest(),
    );
}

test "compat-v1 local references resolve to current backend capability geometry" {
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** 25;
    const offsets = compat_layout.TreeOffsets{
        .preprocessed = 7,
        .main = 113,
        .interaction = 997,
    };
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);

        const active = try layout.preprocessed[1].reference.resolve(offsets);
        const first_main = try layout.main()[0].reference.resolve(offsets);
        const first_interaction = try layout.interactions()[0].reference.resolve(offsets);
        const semantic = try semantic_component.SemanticComponent.init(
            family,
            10,
            active.index,
            first_main.index,
        );
        const semantic_prover = semantic.asProverComponent();
        const semantic_capability = semantic_prover.backend_composition_capability orelse
            return error.MissingBackendCapability;
        switch (semantic_capability) {
            .base_polynomial_v1 => |capability| {
                try std.testing.expectEqual(
                    @as(usize, @intFromEnum(compat_layout.Tree.preprocessed)),
                    capability.selector_tree_index,
                );
                try std.testing.expectEqual(active.index, capability.selector_column);
                try std.testing.expectEqual(
                    @as(usize, @intFromEnum(compat_layout.Tree.main)),
                    capability.main_tree_index,
                );
                try std.testing.expectEqual(first_main.index, capability.first_main_column);
                try std.testing.expectEqual(layout.main().len, capability.main_column_count);
            },
            else => return error.UnexpectedBackendCapability,
        }

        const first = try layout.preprocessed[0].reference.resolve(offsets);
        const lookup = try opcode_component.OpcodeLookupComponent.initVerifier(
            family,
            10,
            first.index,
            first_main.index,
            first_interaction.index,
            &relations,
            claims[0..imported.batchCount()],
        );
        const lookup_prover = lookup.asProverComponent();
        const lookup_capability = lookup_prover.backend_composition_capability orelse
            return error.MissingBackendCapability;
        switch (lookup_capability) {
            .lookup_polynomial_v1 => |capability| {
                try std.testing.expectEqual(
                    @as(usize, @intFromEnum(compat_layout.Tree.preprocessed)),
                    capability.selector_tree_index,
                );
                try std.testing.expectEqual(first.index, capability.selector_column);
                try std.testing.expectEqual(
                    @as(usize, @intFromEnum(compat_layout.Tree.main)),
                    capability.main_tree_index,
                );
                try std.testing.expectEqual(first_main.index, capability.first_main_column);
                try std.testing.expectEqual(layout.main().len, capability.main_column_count);
                try std.testing.expectEqual(
                    @as(usize, @intFromEnum(compat_layout.Tree.interaction)),
                    capability.interaction_tree_index,
                );
                try std.testing.expectEqual(
                    first_interaction.index,
                    capability.first_interaction_column,
                );
                try std.testing.expectEqual(
                    layout.interactions().len,
                    capability.interaction_column_count,
                );
            },
            else => return error.UnexpectedBackendCapability,
        }
    }
}

test "compat-v1 validator rejects corrupted physical mappings" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    var corrupted = layout;
    corrupted.family = .div;
    try std.testing.expectError(error.InvalidFamily, corrupted.validate(&imported));

    corrupted = layout;
    corrupted.preprocessed[1].name = "active";
    try std.testing.expectError(
        error.InvalidPreprocessedLayout,
        corrupted.validate(&imported),
    );

    corrupted = layout;
    corrupted.main_count -= 1;
    try std.testing.expectError(error.InvalidMainLayout, corrupted.validate(&imported));

    corrupted = layout;
    corrupted.main_storage[0].reference.local_index = 1;
    try std.testing.expectError(error.InvalidMainLayout, corrupted.validate(&imported));

    corrupted = layout;
    corrupted.main_storage[0].value = imported.selector;
    try std.testing.expectError(error.InvalidMainLayout, corrupted.validate(&imported));

    corrupted = layout;
    corrupted.main_storage[corrupted.main_count].physical_name = "hidden";
    try std.testing.expectError(error.InvalidMainLayout, corrupted.validate(&imported));

    corrupted = layout;
    corrupted.interaction_count -= 1;
    try std.testing.expectError(
        error.InvalidInteractionLayout,
        corrupted.validate(&imported),
    );

    corrupted = layout;
    corrupted.interaction_storage[0].coordinate = .c1_b;
    try std.testing.expectError(
        error.InvalidInteractionLayout,
        corrupted.validate(&imported),
    );

    corrupted = layout;
    corrupted.interaction_storage[0].first_lookup = 1;
    try std.testing.expectError(
        error.InvalidInteractionLayout,
        corrupted.validate(&imported),
    );

    corrupted = layout;
    corrupted.interaction_storage[corrupted.interaction_count].entry_count = 1;
    try std.testing.expectError(
        error.InvalidInteractionLayout,
        corrupted.validate(&imported),
    );
}

test "compat-v1 column resolution rejects global index overflow" {
    const reference = compat_layout.ColumnRef{
        .tree = .main,
        .local_index = 1,
    };
    try std.testing.expectError(
        error.ColumnIndexOverflow,
        reference.resolve(.{
            .preprocessed = 0,
            .main = std.math.maxInt(usize),
            .interaction = 0,
        }),
    );
}

fn mappedWitnessDigest() ![32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (witness_layout.canonical_families) |family| {
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var prefix: [96]u8 = undefined;
        const rendered = try std.fmt.bufPrint(
            &prefix,
            "family={s} columns={d}\nnames=",
            .{ @tagName(family), layout.main().len },
        );
        hasher.update(rendered);
        for (layout.main(), 0..) |column, index| {
            if (index != 0) hasher.update(",");
            hasher.update(column.physical_name);
        }
        hasher.update("\n");
    }
    return hasher.finalResult();
}

fn fieldNames(
    comptime Layout: type,
) [@typeInfo(Layout).@"struct".fields.len][]const u8 {
    const fields = @typeInfo(Layout).@"struct".fields;
    var result: [fields.len][]const u8 = undefined;
    inline for (fields, &result) |field, *name| name.* = field.name;
    return result;
}
