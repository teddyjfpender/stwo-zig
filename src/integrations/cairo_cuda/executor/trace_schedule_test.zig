const std = @import("std");
const adapter = @import("stwo_cairo_frontend").adapter;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const fixed_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
const product_aot = @import("stwo_cuda_backend").aot.product_registry;
const catalog_module = @import("../base_writer_plan/catalog.zig");
const schedule_module = @import("trace_schedule.zig");

test "SN2 trace schedule is the exact canonical 58-entry graph" {
    const allocator = std.testing.allocator;
    const path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_ADAPTED_INPUT",
    ) catch return error.SkipZigTest;
    defer allocator.free(path);
    var input = try adapter.adapted_input.readFile(allocator, path);
    defer input.deinit(allocator);
    var components = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer components.deinit();
    var witnesses = try witness_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    var feeds = try feed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_multiplicity_feeds.bin",
    );
    defer feeds.deinit();
    var fixed = try fixed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    var proof = try proof_plan.CairoProofPlan.fromSemanticArtifacts(
        allocator,
        witnesses,
        feeds,
        fixed,
        components,
        &input,
    );
    defer proof.deinit();
    var registry = try product_aot.Registry.initProduct(allocator);
    defer registry.deinit();
    var catalog = try catalog_module.compile(
        allocator,
        &proof,
        components,
        witnesses,
        fixed,
        &input,
        registry,
    );
    defer catalog.deinit();
    var schedule = try schedule_module.compile(
        allocator,
        &proof,
        catalog,
    );
    defer schedule.deinit();

    try std.testing.expectEqual(
        @as(usize, schedule_module.expected_entry_count),
        schedule.entries.len,
    );
    try std.testing.expectEqual(
        @as(usize, schedule_module.expected_launch_count),
        schedule.launch_order.len,
    );
    for (schedule.entries, 0..) |entry, ordinal| {
        try std.testing.expectEqual(
            @as(u32, @intCast(ordinal)),
            entry.canonical_ordinal,
        );
        try std.testing.expectEqual(
            proof.canonical_order[ordinal],
            entry.component_index,
        );
        try std.testing.expectEqual(
            catalog.find(entry.name, entry.instance).?.identity,
            entry.catalog_identity,
        );
    }

    const ec = schedule.find("ec_op_builtin", 0).?;
    const partial = schedule.find("partial_ec_mul_generic", 0).?;
    try std.testing.expectEqual(
        schedule_module.Execution.composite_root,
        ec.execution,
    );
    try std.testing.expectEqual(
        schedule_module.PrepareApi.native_ec_prepare,
        ec.prepare_api,
    );
    try std.testing.expectEqual(ec.component_index, ec.launch_owner);
    try std.testing.expectEqual(
        ec.component_index,
        ec.buffers.native_partial_workspace.?,
    );
    try std.testing.expectEqual(
        schedule_module.Execution.composite_member,
        partial.execution,
    );
    try std.testing.expectEqual(
        schedule_module.PrepareApi.native_ec_member,
        partial.prepare_api,
    );
    try std.testing.expectEqual(ec.component_index, partial.launch_owner);
    try std.testing.expectEqual(
        ec.component_index,
        partial.buffers.native_partial_inputs.?,
    );
    try expectNativeDependency(partial.dependencies, ec.component_index);
    try expectLaunchesExactlyOnce(schedule, partial.component_index);

    std.debug.print(
        "SN2 trace schedule identity={s} ec={d} partial={d}\n",
        .{
            std.fmt.bytesToHex(schedule.identity, .lower),
            ec.component_index,
            partial.component_index,
        },
    );
}

test "trace schedule fails closed on a missing base writer" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    fixture.catalog.entries[fixture.catalog.entries.len - 1]
        .component_index = 999;
    try std.testing.expectError(
        error.MissingBaseWriter,
        schedule_module.compile(
            allocator,
            &fixture.proof,
            fixture.catalog,
        ),
    );
}

test "trace schedule fails closed on a duplicate base writer" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    fixture.catalog.entries[fixture.catalog.entries.len - 1]
        .component_index =
        fixture.catalog.entries[fixture.catalog.entries.len - 2]
            .component_index;
    try std.testing.expectError(
        error.DuplicateBaseWriter,
        schedule_module.compile(
            allocator,
            &fixture.proof,
            fixture.catalog,
        ),
    );
}

test "trace schedule never launches the native EC member twice" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var schedule = try schedule_module.compile(
        allocator,
        &fixture.proof,
        fixture.catalog,
    );
    defer schedule.deinit();
    const partial = schedule.find("partial_ec_mul_generic", 0).?;
    const ec = schedule.find("ec_op_builtin", 0).?;
    try expectNativeDependency(partial.dependencies, ec.component_index);
    try expectLaunchesExactlyOnce(schedule, partial.component_index);
}

fn expectNativeDependency(
    dependencies: []const schedule_module.Dependency,
    ec_index: u32,
) !void {
    var found: usize = 0;
    for (dependencies) |dependency| {
        if (dependency.kind == .native_ec_workspace) {
            try std.testing.expectEqual(
                ec_index,
                dependency.producer_component_index,
            );
            found += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), found);
}

fn expectLaunchesExactlyOnce(
    schedule: schedule_module.Schedule,
    excluded_component: u32,
) !void {
    var seen = [_]bool{false} ** schedule_module.expected_entry_count;
    for (schedule.launch_order) |component_index| {
        try std.testing.expect(component_index < seen.len);
        try std.testing.expect(component_index != excluded_component);
        try std.testing.expect(!seen[component_index]);
        seen[component_index] = true;
    }
    for (seen, 0..) |was_seen, component_index| {
        try std.testing.expectEqual(
            component_index != excluded_component,
            was_seen,
        );
    }
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    proof: proof_plan.CairoProofPlan,
    catalog: catalog_module.Catalog,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const components = try allocator.alloc(
            proof_plan.Component,
            schedule_module.expected_entry_count,
        );
        defer allocator.free(components);
        const names = try allocator.alloc(
            []u8,
            schedule_module.expected_entry_count,
        );
        var names_initialized: usize = 0;
        defer {
            for (names[0..names_initialized]) |name| allocator.free(name);
            allocator.free(names);
        }

        const rows = [_]proof_plan.TracePart{.{
            .id = .main,
            .rows = .{ .real_rows = 16, .padded_rows = 16 },
        }};
        while (names_initialized < names.len) : (names_initialized += 1) {
            const index = names_initialized;
            names[index] = try componentName(allocator, index);
            components[index] = .{
                .name = names[index],
                .canonical_ordinal = @intCast(index),
                .writer = writerFor(index),
                .trace_parts = &rows,
                .producer_edges = &.{},
                .capacity_feeds = &.{},
            };
        }
        var proof = try proof_plan.CairoProofPlan.init(
            allocator,
            components,
        );
        errdefer proof.deinit();
        const entries = try allocator.alloc(
            catalog_module.Entry,
            schedule_module.expected_entry_count,
        );
        errdefer allocator.free(entries);
        var counts =
            [_]u32{0} ** std.meta.fields(proof_plan.WriterKind).len;
        for (proof.components, entries, 0..) |component, *entry, index| {
            var identity = [_]u8{0} ** 32;
            std.mem.writeInt(
                u32,
                identity[0..4],
                @intCast(index + 1),
                .little,
            );
            entry.* = .{
                .component_index = @intCast(index),
                .name = component.name,
                .instance = component.instance,
                .writer = component.writer,
                .identity = identity,
            };
            counts[@intFromEnum(component.writer)] += 1;
        }
        var catalog_identity = [_]u8{0} ** 32;
        catalog_identity[0] = 1;
        return .{
            .allocator = allocator,
            .proof = proof,
            .catalog = .{
                .allocator = allocator,
                .entries = entries,
                .writer_counts = counts,
                .identity = catalog_identity,
            },
        };
    }

    fn deinit(self: *Fixture) void {
        self.catalog.deinit();
        self.proof.deinit();
        self.* = undefined;
    }
};

fn componentName(
    allocator: std.mem.Allocator,
    index: usize,
) ![]u8 {
    return switch (index) {
        32 => allocator.dupe(u8, "ec_op_builtin"),
        33 => allocator.dupe(u8, "partial_ec_mul_generic"),
        55 => allocator.dupe(u8, "memory_address_to_id"),
        56 => allocator.dupe(u8, "memory_id_to_big"),
        57 => allocator.dupe(u8, "memory_id_to_small"),
        else => if (index < 32)
            std.fmt.allocPrint(allocator, "recorded_{d}", .{index})
        else
            std.fmt.allocPrint(allocator, "fixed_{d}", .{index}),
    };
}

fn writerFor(index: usize) proof_plan.WriterKind {
    if (index < 32) return .recorded_aot;
    if (index < 34) return .native_backend;
    if (index < 55) return .fixed_table;
    return .memory_trace;
}
