//! Original PAGE context and early complete-factory bounds, no commitment run.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Context = @import("../recursion/block_v5_memory_source_page_forest_fixed_context_v1.zig");
const Plan = @import("../recursion/block_v5_memory_source_page_forest_plan_v1.zig");
const Factory = @import("../recursion/block_v5_source_ram_forest_join_fixed_assembly_v1.zig");
test "compact memory fixed assembly: PAGE16 exact original namespace graph closure contexts" {
    const n = Plan.Node{ .children = @splat(.{ .leaf = 0 }), .child_count = 1, .range = .{ .first = 4, .count = 7 } };
    const child = Base.Context{ .child_key_id = @splat(0), .child_config = Base.CSP_CONFIG, .graph_ids = .{ @splat(3), @splat(4), @splat(5) }, .transcript_plan_id = @splat(6) };
    var actual = Context.Owned.init(2, n, @splat(1), @splat(2));
    var expected: [5]core.channel.blake3.Channel = @splat(.{});
    for (&expected, 0..) |*c, i| {
        c.mixU32s(&.{ 0x50474652, 1, @intCast(i), 2, 4, 7 });
        c.mixRoot(@splat(1));
        c.mixRoot(@splat(2));
        c.mixRoot(@splat(7));
    }
    for (expected[1..4], child.graph_ids) |*c, id| c.mixRoot(id);
    expected[4].mixRoot(child.transcript_plan_id);
    for (&expected) |*c| {
        c.mixRoot(@splat(8));
        c.mixRoot(@splat(9));
    }
    actual.child(@splat(7), child);
    actual.attachment(@splat(8));
    actual.attachment(@splat(9));
    const result = actual.finish(Base.CSP_CONFIG);
    try std.testing.expectEqualDeep(Base.Context{ .child_key_id = expected[0].digestBytes(), .child_config = Base.CSP_CONFIG, .graph_ids = .{ expected[1].digestBytes(), expected[2].digestBytes(), expected[3].digestBytes() }, .transcript_plan_id = expected[4].digestBytes() }, result);
    var changed = n;
    changed.range.count += 1;
    var mutated = Context.Owned.init(2, changed, @splat(1), @splat(2));
    mutated.child(@splat(7), child);
    mutated.attachment(@splat(8));
    mutated.attachment(@splat(9));
    try std.testing.expect(!std.meta.eql(result, mutated.finish(Base.CSP_CONFIG)));
}
test "compact memory fixed assembly: V20 original independent forests required and resource guards first" {
    const F = Factory.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    try std.testing.expectError(error.SourceRamFixedResourceLimit, F.derive(std.testing.allocator, undefined, @splat(0), undefined, @splat(0), 0, .csp_q70_pow26, .{}));
    try std.testing.expectError(error.SourceRamFixedResourceLimit, F.derive(std.testing.allocator, undefined, @splat(0), undefined, @splat(0), 1, .csp_q70_pow26, .{ .max_metadata_bytes = 0 }));
    try std.testing.expectError(error.SourceRamFixedResourceLimit, (Factory.Limits{ .max_rows_per_cohort = (1 << 24) + 1 }).validate(1));
    try std.testing.expect(!Factory.Owned.complete_block_authority);
}

// Deliberately incomplete catalogue values exercise guards BEFORE any recipe,
// original policy, key or forest is dereferenced. They confer no acceptance.
test "compact memory fixed assembly: borrowed catalogues reject controls and missing independent semantic claims before recipes" {
    const P = @import("../recursion/block_v5_memory_source_page_forest_fixed_assembly_v1.zig");
    const R = @import("../recursion/block_v5_ram_range_forest_fixed_assembly_v1.zig");
    const F = Factory.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    var page: P.Catalogue = undefined;
    page.capacity = 2;
    page.profile = .csp_q70_pow26;
    page.limits = .{};
    page.leaf_catalogue = null;
    var memory: R.Catalogue = undefined;
    memory.capacity = 2;
    memory.profile = .csp_q70_pow26;
    memory.limits = .{};
    try std.testing.expectError(error.SourceRamFixedResourceLimit, F.deriveFromCatalogues(std.testing.allocator, &page, @splat(0), &memory, @splat(0), 0, .csp_q70_pow26, .{}));
    try std.testing.expectError(error.UnpairedSourceRamFixedCatalogues, F.deriveFromCatalogues(std.testing.allocator, &page, @splat(0), &memory, @splat(0), 1, .csp_q70_pow26, .{}));
    try std.testing.expectError(error.UnpairedSourceRamFixedCatalogues, F.deriveFromCatalogues(std.testing.allocator, &page, @splat(0), &memory, @splat(0), 2, .diagnostic_q8_pow0, .{}));
    var changed: Factory.Limits = .{};
    changed.page.max_live_bytes += 1;
    try std.testing.expectError(error.UnpairedSourceRamFixedCatalogues, F.deriveFromCatalogues(std.testing.allocator, &page, @splat(0), &memory, @splat(0), 2, .csp_q70_pow26, changed));
    try std.testing.expectError(error.MissingIndependentPageSemanticClaims, F.deriveFromCatalogues(std.testing.allocator, &page, @splat(0), &memory, @splat(0), 2, .csp_q70_pow26, .{}));
    try std.testing.expectError(error.MissingIndependentPageSemanticClaims, P.ForBackend(@import("stwo_cpu_backend").CpuBackend).derive(std.testing.allocator, undefined, @splat(0), 2, .csp_q70_pow26, .{}));
}
fn scheduleCustody(a: std.mem.Allocator) !void {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const Public = @import("../recursion/block_v5_requester_public_fixed_assembly_v1.zig");
    const Final = @import("../recursion/block_v5_requester_memory_fixed_assembly_v1.zig");
    const creator = try Budget.createRetainingParent(a, 4096);
    var creator_owned = true;
    defer if (creator_owned) creator.destroy();
    const allocator = creator.allocator();
    // No key is read or accepted: exercise the real result destructors and
    // retained allocator lease after creator custody releases, including OOM.
    const public_words = try allocator.alloc(@import("../recursion/block_v5_requester_public_bus_v1.zig").Wire, 1);
    var public_result = Public.KeyAndSchedule{ .allocator = allocator, .lease = creator.retain(), .key = undefined, .wires = public_words };
    defer public_result.deinit();
    const final_words = try allocator.alloc(@import("../recursion/block_v5_requester_memory_public_v1.zig").Wire, 0);
    var final_result = Final.KeyAndSchedule{ .allocator = allocator, .lease = creator.retain(), .key = undefined, .wires = final_words };
    defer final_result.deinit();
    creator.destroy();
    creator_owned = false;
    const byte = try allocator.alloc(u8, 1);
    defer allocator.free(byte);
    byte[0] = 17;
    try std.testing.expectEqual(@as(u8, 17), byte[0]);
}
test "compact memory fixed assembly: direct result allocator custody and all metadata allocation failures" {
    try scheduleCustody(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, scheduleCustody, .{});
}
