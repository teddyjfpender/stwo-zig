//! Source-only leaf reconstruction shared by outer recursion protocols.
//! All view buffers are borrowed during a synchronous visitor call. This is
//! source construction, never execution acceptance or native verification.
const std = @import("std");
const Runtime = @import("pure_p2_op_runtime.zig");
const Receiver = @import("pure_p2_op_root_receiver.zig");
const Templates = @import("pure_p2_gkr_templates_wire.zig");
const Gkr = @import("pure_p2_gkr_template.zig");
const Skeleton = @import("pure_p2_trace_skeleton.zig");
const CPU = @import("pure_p2_cpu_leaf_test.zig");
const Catalog = @import("pure_p2_truth_leaf_test.zig");
const Miller = @import("pure_p2_tower_leaf_test.zig");
const LocalCatalog = @import("truth_local_gkr/leaf_test.zig");
const LocalMiller = @import("miller_local_gkr/leaf_test.zig");
const Views = @import("pure_p2_root_source_view.zig");
/// Validate the entire source-derived template roster before any key factory.
pub fn decodeTemplates(a: std.mem.Allocator, source: Runtime.SourceDirectory, plan: *const Receiver.Plan, bytes: []const u8) !Templates.Owned {
    var count: usize = source.setups.len;
    for (source.inventory.truth_local_keys) |key| if (key != null) {
        count += 1;
    };
    const allow_local_miller = if (source.source_suite) |suite| blk: {
        try suite.validate();
        break :blk suite.miller == .local_gkr;
    } else false;
    for (source.miller) |item| {
        if ((item.local_key != null) != allow_local_miller) return error.OpRootLeafSourceAuthority;
        if (item.local_key != null) count += 1;
    }
    var out = try Templates.decode(a, bytes, count);
    errdefer out.deinit(a);
    for (plan.inventory.workers[0..source.setups.len], out.shapes[0..source.setups.len]) |expected, shape| try Gkr.validate(expected.local_instances orelse return error.MissingOpRootLocalAuthority, shape);
    var at = source.setups.len;
    for (source.truths, 0..) |truth, j| {
        if (if (source.inventory.truth_local_keys.len == 0) null else source.inventory.truth_local_keys[j]) |_| {
            const shapes = try @import("truth_local_gkr/authority.zig").shapes(truth);
            const instances = @import("truth_local_gkr/native.zig").instances(shapes);
            try Gkr.Truth.validate(&instances, out.shapes[at]);
            at += 1;
        }
    }
    for (source.miller) |item| if (item.local_key) |key| {
        const instances = try (try key.geometry(item.span)).instances();
        try Gkr.validateFor(&instances, out.shapes[at]);
        at += 1;
    };
    if (at != out.shapes.len) return error.OpRootTemplateCoverage;
    return out;
}
pub fn visit(a: std.mem.Allocator, source: Runtime.SourceDirectory, profile: @import("op_profile.zig").Profile, plan: *const Receiver.Plan, root_metadata: Receiver.Metadata, templates: *const Templates.Owned, sink: Views.SourceSink) !void {
    if (root_metadata.leaves.len != plan.inventory.workers.len) return error.OpRootLeafCoverage;
    var made: usize = 0;
    for (source.setups, source.requests, source.metadata.spans, source.cpu_keys, templates.shapes[0..source.setups.len], 0..) |setup, request, span, key, shape_advice, i| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const expected = plan.inventory.workers[i];
        const instances = expected.local_instances orelse return error.MissingOpRootLocalAuthority;
        // Only coefficient-vector lengths vary. Every other dimension is
        // independently derived from this exact trusted instance roster.
        const local = try Gkr.skeleton(arena.allocator(), instances, shape_advice);
        const shape = try @import("../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), setup, profile.config());
        const values = try Skeleton.init(arena.allocator(), &shape);
        const metadata = root_metadata.leaves[i];
        const view = CPU.ShapeView{ .op_span = span, .setup = setup, .request = request, .first = plan.inventory.first_ids[i], .expected = expected, .key = key, .manifest = plan.manifest, .main = metadata.main, .receipt = metadata.receipt orelse return error.MissingOpRootLocalAuthority, .claims = metadata.claims, .child = &local, .shape = &shape, .values = &values };
        try sink.run(a, made, .{ .cpu = view });
        made += 1;
    }
    var template_index = source.setups.len;
    for (source.truths, source.truth_keys, 0..) |truth, key, j| {
        const i = source.setups.len + j;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        if (if (source.inventory.truth_local_keys.len == 0) null else source.inventory.truth_local_keys[j]) |local_key| {
            const shapes = try @import("truth_local_gkr/authority.zig").shapes(truth);
            const instances = @import("truth_local_gkr/native.zig").instances(shapes);
            const local = try Gkr.Truth.skeleton(arena.allocator(), &instances, templates.shapes[template_index]);
            template_index += 1;
            const shape = try @import("truth_local_gkr/statement.zig").geometry(arena.allocator(), local_key, truth);
            const values = try Skeleton.init(arena.allocator(), &shape);
            const metadata = root_metadata.leaves[i];
            if (metadata.claims.len != 2) return error.OpRootTruthClaims;
            const view = LocalCatalog.View{ .key = local_key, .truth = truth, .expected = plan.inventory.workers[i], .manifest = plan.manifest, .main = metadata.main, .receipt = metadata.receipt orelse return error.MissingOpRootLocalAuthority, .claims = metadata.claims[0..2].*, .local = &local, .shape = &shape, .values = &values };
            try sink.run(a, made, .{ .local_catalog = view });
            made += 1;
            continue;
        }
        const shape = try @import("pure_p2_truth_statement.zig").geometry(arena.allocator(), key, truth);
        const values = try Skeleton.init(arena.allocator(), &shape);
        const metadata = root_metadata.leaves[i];
        const view = Catalog.View{ .key = key, .truth = truth, .expected = plan.inventory.workers[i], .manifest = plan.manifest, .main = metadata.main, .claims = metadata.claims, .shape = &shape, .values = &values };
        try sink.run(a, made, .{ .catalog = view });
        made += 1;
    }
    for (source.miller, 0..) |miller, j| {
        const i = source.setups.len + source.truths.len + j;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const metadata = root_metadata.leaves[i];
        if (miller.local_key) |key| {
            const instances = try (try key.geometry(miller.span)).instances();
            const local = try Gkr.skeletonFor(arena.allocator(), &instances, templates.shapes[template_index]);
            template_index += 1;
            const shape = try @import("miller_local_gkr/statement.zig").geometry(arena.allocator(), key, miller.span);
            const values = try Skeleton.init(arena.allocator(), &shape);
            if (metadata.claims.len != 2) return error.OpRootTruthClaims;
            const view = LocalMiller.View{ .key = key, .span = miller.span, .expected = plan.inventory.workers[i], .manifest = plan.manifest, .main = metadata.main, .receipt = metadata.receipt orelse return error.MissingOpRootLocalAuthority, .claims = metadata.claims[0..2].*, .local = &local, .shape = &shape, .values = &values };
            try sink.run(a, made, .{ .local_miller = view });
            made += 1;
            continue;
        }
        const shape = try @import("pure_p2_tower_statement.zig").geometry(arena.allocator(), miller.key);
        const values = try Skeleton.init(arena.allocator(), &shape);
        if (metadata.claims.len != 4) return error.OpRootTruthClaims;
        const view = Miller.View{ .key = miller.key, .span = miller.span, .expected = plan.inventory.workers[i], .manifest = plan.manifest, .main = metadata.main, .claims = metadata.claims[0..4].*, .shape = &shape, .values = &values };
        try sink.run(a, made, .{ .miller = view });
        made += 1;
    }
    if (template_index != templates.shapes.len) return error.OpRootTemplateCoverage;

    if (made != plan.inventory.workers.len) return error.OpRootLeafCoverage;
}
