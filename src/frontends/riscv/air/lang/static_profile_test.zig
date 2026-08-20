const std = @import("std");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const public_air = @import("mod.zig");
const source = @import("source.zig");
const static_profile = @import("static_profile.zig");
const typed_addi = @import("typed_addi.zig");
const types = @import("types.zig");

const Synthetic = struct {
    arena: ir.Arena,
    root: types.ValueId,

    fn init(allocator: std.mem.Allocator) !Synthetic {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const generated = source.SourceSpan.generated();
        const lhs = try arena.input("profile.lhs", .felt, generated);
        const rhs = try arena.input("profile.rhs", .felt, generated);
        const product = try arena.mul(lhs, rhs, generated);
        const root = try arena.mul(product, product, generated);
        // A valid canonical node outside both constraint/effect closures.
        _ = try arena.sub(lhs, rhs, generated);
        _ = try arena.assertZero(
            "profile.root.first",
            root,
            null,
            .semantic,
            generated,
        );
        _ = try arena.assertZero(
            "profile.root.second",
            root,
            null,
            .boundary,
            generated,
        );
        return .{ .arena = arena, .root = root };
    }

    fn deinit(self: *Synthetic) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn plan(
        self: *const Synthetic,
        allocator: std.mem.Allocator,
    ) !materializer.Plan {
        return materializer.plan(allocator, &self.arena, .{
            .roots = &.{self.root},
            .gate = null,
        });
    }
};

test "AIR static profile: typed ADDI records exact logical and supplied physical geometry" {
    try std.testing.expectEqualStrings(
        static_profile.SCHEMA,
        public_air.static_profile.SCHEMA,
    );
    var generated = try typed_addi.build(std.testing.allocator, .generated);
    defer generated.deinit();
    const context = static_profile.Context{
        .physical_main_columns = typed_addi.MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = typed_addi.RELATION_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    };
    const profile = try static_profile.collect(
        std.testing.allocator,
        &generated.arena,
        context,
    );
    try profile.validate();
    try std.testing.expectEqualStrings(
        "34057a4cdcb0b42caeeec0eadd99cf86309d5eb0405f3fbd3bb0c69829d62fb4",
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );

    try std.testing.expectEqual(@as(?u32, 35), profile.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 36), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 22), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 16), profile.effects);
    try std.testing.expectEqual(@as(u32, 16), profile.lookup_events);
    try std.testing.expectEqual(@as(u32, 0), profile.non_lookup_effects);
    try std.testing.expectEqual(@as(?u8, 2), profile.lookup_batch_size);
    try std.testing.expectEqual(@as(?u32, 8), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u8, 4), profile.interaction_coordinates_per_batch);
    try std.testing.expectEqual(@as(?u32, 32), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_denominator_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(?u32, null), profile.materializations);
    try std.testing.expectEqual(@as(?u32, null), profile.source_expression_nodes);
    try std.testing.expectEqual(@as(?u32, null), profile.cse_merges);

    var located = try typed_addi.build(std.testing.allocator, .{ .file = .{
        .path = "moved/profile/addi.air",
        .start = .{ .byte_offset = 10, .line = 2, .column = 3 },
        .end = .{ .byte_offset = 20, .line = 2, .column = 13 },
    } });
    defer located.deinit();
    const replay = try static_profile.collect(
        std.testing.allocator,
        &located.arena,
        context,
    );
    try std.testing.expectEqualDeep(profile, replay);
    try std.testing.expect(!std.mem.allEqual(u8, &profile.profile_digest, 0));
}

test "AIR static profile: materialization DAG sharing closure and CSE provenance stay distinct" {
    var fixture = try Synthetic.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.plan(std.testing.allocator);
    defer plan.deinit();

    const profile = try static_profile.collect(
        std.testing.allocator,
        &fixture.arena,
        .{
            .physical_main_columns = 4,
            .source_expression_nodes = 7,
            .materialization_plan = &plan,
        },
    );
    try profile.validate();

    try std.testing.expectEqual(@as(u32, 5), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 6), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 3), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 2), profile.expression_dag_max_fanout);
    try std.testing.expectEqual(@as(u32, 4), profile.constraint_effect_reachable_nodes);
    try std.testing.expectEqual(@as(u32, 1), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqual(@as(u32, 2), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 1), profile.unique_constraint_root_values);
    try std.testing.expectEqual(@as(u32, 1), profile.duplicate_constraint_root_references);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_value_degree);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 2), profile.materializations);
    try std.testing.expectEqual(@as(?u32, 1), profile.materialization_outputs);
    try std.testing.expectEqual(@as(?u32, 1), profile.materialization_dependency_edges);
    try std.testing.expectEqual(@as(?u32, 1), profile.materializations_with_structural_reuse);
    try std.testing.expectEqual(@as(?u32, 2), profile.maximum_materialization_body_degree);
    try std.testing.expectEqual(@as(?u32, 2), profile.maximum_materialization_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 7), profile.source_expression_nodes);
    try std.testing.expectEqual(@as(?u32, 2), profile.cse_merges);
}

test "AIR static profile: canonical JSON and TSV are deterministic valid and allocation free" {
    var authored = try typed_addi.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const profile = try static_profile.collect(
        std.testing.allocator,
        &authored.arena,
        .{
            .physical_main_columns = typed_addi.MAIN_COLUMN_COUNT,
            .lookup_layout = .{
                .batch_size = 2,
                .interaction_coordinates_per_batch = 4,
            },
        },
    );

    var json_storage: [4096]u8 = undefined;
    var json_writer = std.Io.Writer.fixed(&json_storage);
    try static_profile.writeJson(&json_writer, &profile);
    const json = json_writer.buffered();
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, json, "\n"));
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        json,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        static_profile.SCHEMA,
        parsed.value.object.get("schema").?.string,
    );
    try std.testing.expectEqual(
        @as(i64, static_profile.SCHEMA_VERSION),
        parsed.value.object.get("schema_version").?.integer,
    );
    try std.testing.expectEqual(
        @as(i64, 32),
        parsed.value.object.get("interaction_columns").?.integer,
    );
    try std.testing.expect(parsed.value.object.get("materializations").? == .null);

    var replay_storage: [4096]u8 = undefined;
    var replay_writer = std.Io.Writer.fixed(&replay_storage);
    try static_profile.writeJson(&replay_writer, &profile);
    try std.testing.expectEqualStrings(json, replay_writer.buffered());

    var header_storage: [4096]u8 = undefined;
    var header_writer = std.Io.Writer.fixed(&header_storage);
    try static_profile.writeTsvHeader(&header_writer);
    var row_storage: [4096]u8 = undefined;
    var row_writer = std.Io.Writer.fixed(&row_storage);
    try static_profile.writeTsvRecord(&row_writer, &profile);
    try std.testing.expectEqual(
        std.mem.count(u8, header_writer.buffered(), "\t"),
        std.mem.count(u8, row_writer.buffered(), "\t"),
    );
    try std.testing.expect(std.mem.endsWith(u8, header_writer.buffered(), "\n"));
    try std.testing.expect(std.mem.endsWith(u8, row_writer.buffered(), "\n"));
}

test "AIR static profile: malformed context and record corruption fail closed" {
    var fixture = try Synthetic.init(std.testing.allocator);
    defer fixture.deinit();

    try std.testing.expectError(
        error.InvalidLookupLayout,
        static_profile.collect(std.testing.allocator, &fixture.arena, .{
            .lookup_layout = .{
                .batch_size = 3,
                .interaction_coordinates_per_batch = 4,
            },
        }),
    );
    try std.testing.expectError(
        error.InvalidProfileInput,
        static_profile.collect(std.testing.allocator, &fixture.arena, .{
            .source_expression_nodes = 4,
        }),
    );

    const profile = try static_profile.collect(
        std.testing.allocator,
        &fixture.arena,
        .{},
    );
    var corrupted = profile;
    corrupted.constraint_roots += 1;
    try std.testing.expectError(error.InvalidProfile, corrupted.validate());
    var storage: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    try std.testing.expectError(
        error.InvalidProfile,
        static_profile.writeJson(&writer, &corrupted),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);

    corrupted = profile;
    corrupted.profile_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidProfile, corrupted.validate());
}

test "AIR static profile: collection cleans every temporary allocation failure" {
    var fixture = try Synthetic.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try fixture.plan(std.testing.allocator);
    defer plan.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        collectFailureCase,
        .{ &fixture.arena, &plan },
    );
}

fn collectFailureCase(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    plan: *const materializer.Plan,
) !void {
    const profile = try static_profile.collect(allocator, arena, .{
        .physical_main_columns = 4,
        .materialization_plan = plan,
    });
    try profile.validate();
}
