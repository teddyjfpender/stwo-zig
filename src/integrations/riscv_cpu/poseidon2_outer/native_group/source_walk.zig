//! Independent concrete native-source reconstruction for grouped roots. No
//! native PCS/local-GKR proof bytes, proposed key or source hash is accepted.
//! Only bounded polynomial coefficient lengths enter as layout-class advice.
const std = @import("std");
const A = @import("../sponge_cpu/root_admission.zig");
const Views = @import("../sponge_cpu/captured_source.zig");
const Gkr = @import("../pure_p2_gkr_template.zig");
const Templates = @import("../pure_p2_gkr_templates_wire.zig");
const Skeleton = @import("../pure_p2_trace_skeleton.zig");
fn validate(authority: A.Authority, shapes: []const []const u8) !void {
    var count = authority.cpus.len + authority.detached.len;
    for (authority.catalog) |s| if (s.local_key != null) {
        count += 1;
    };
    for (authority.towers) |s| if (s.local_key != null) {
        count += 1;
    };
    if (shapes.len != count) return error.OpRootTemplateCoverage;
    var at: usize = 0;
    for (authority.inventory.rosters) |roster| {
        try Gkr.validateFor(roster.instances, shapes[at]);
        at += 1;
    }
    for (authority.detached) |s| {
        try Gkr.validateFor(&(try s.geometry.instances()), shapes[at]);
        at += 1;
    }
    for (authority.catalog) |s| if (s.local_key != null) {
        const instances = @import("../truth_local_gkr/native.zig").instances(try @import("../truth_local_gkr/authority.zig").shapes(s.truth));
        try Gkr.Truth.validate(&instances, shapes[at]);
        at += 1;
    };
    for (authority.towers) |s| if (s.local_key) |key| {
        try Gkr.validateFor(&(try (try key.geometry(s.span)).instances()), shapes[at]);
        at += 1;
    };
    if (at != count) return error.OpRootTemplateCoverage;
}
pub fn decodeTemplates(a: std.mem.Allocator, authority: A.Authority, bytes: []const u8) !Templates.Owned {
    const count = try Templates.preflight(bytes);
    var out = try Templates.decode(a, bytes, count);
    errdefer out.deinit(a);
    try validate(authority, out.shapes);
    return out;
}
/// Preparation must already have established metadata/manifest/global/terminal
/// obligations. Their frames remain unauthenticated until physical root verify.
pub fn visit(a: std.mem.Allocator, authority: A.Authority, prepared: *const A.Prepared, metadata: A.Metadata, templates: *const Templates.Owned, sink: Views.Sink) !void {
    if (metadata.leaves.len != authority.inventory.workers.len or prepared.outputs.len != metadata.leaves.len or !std.mem.eql(u8, &prepared.execution, &authority.inventory.execution) or !std.mem.eql(u8, &prepared.execution, &metadata.execution) or !std.mem.eql(u8, &prepared.manifest, &metadata.manifest)) return error.OpRootLeafCoverage;
    try validate(authority, templates.shapes);
    var at: usize = 0;
    for (authority.cpus, authority.inventory.rosters, 0..) |s, roster, i| {
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        const local = try Gkr.skeletonFor(scratch, roster.instances, templates.shapes[at]);
        at += 1;
        const shape = try @import("../sponge_cpu/capture.zig").geometry(scratch, s.setup, s.key);
        const values = try Skeleton.init(scratch, &shape);
        const leaf = metadata.leaves[i];
        try sink.visit(sink.context, a, .{ .cpu = .{ .setup = s.setup, .request = s.request, .span = s.span, .first = authority.inventory.first_ids[i], .key = s.key, .expected = .{ .ordinal = @intCast(i), .statement = authority.inventory.workers[i].authority.statement }, .manifest = prepared.manifest, .main = leaf.main, .receipt = leaf.receipt orelse return error.MissingOpRootLocalAuthority, .claims = leaf.claims, .child = &local, .shape = &shape, .values = &values } });
    }
    for (authority.detached, 0..) |s, j| {
        const i = authority.cpus.len + j;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        const local = try Gkr.skeletonFor(scratch, &(try s.geometry.instances()), templates.shapes[at]);
        at += 1;
        const shape = try @import("../sponge_local_gkr/capture.zig").geometry(scratch, s.geometry, s.key);
        const values = try Skeleton.init(scratch, &shape);
        const leaf = metadata.leaves[i];
        if (leaf.claims.len != 24) return error.DetachedClaimCount;
        var claims: [8][3]@import("../full_p2_common.zig").O = undefined;
        for (&claims, 0..) |*row, k| @memcpy(row, leaf.claims[3 * k ..][0..3]);
        try sink.visit(sink.context, a, .{ .detached = .{ .key = s.key, .geometry = s.geometry, .ordinal = @intCast(i), .manifest = prepared.manifest, .main = leaf.main, .receipt = leaf.receipt orelse return error.MissingOpRootLocalAuthority, .claims = claims, .child = &local, .shape = &shape, .values = &values } });
    }
    for (authority.catalog, 0..) |s, j| {
        const i = authority.cpus.len + authority.detached.len + j;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        const leaf = metadata.leaves[i];
        if (s.local_key) |key| {
            const instances = @import("../truth_local_gkr/native.zig").instances(try @import("../truth_local_gkr/authority.zig").shapes(s.truth));
            const local = try Gkr.Truth.skeleton(scratch, &instances, templates.shapes[at]);
            at += 1;
            const shape = try @import("../truth_local_gkr/statement.zig").geometry(scratch, key, s.truth);
            const values = try Skeleton.init(scratch, &shape);
            if (leaf.claims.len != 2) return error.OpRootTruthClaims;
            try sink.visit(sink.context, a, .{ .truth = .{ .key = key, .truth = s.truth, .expected = try key.expected(s.truth, @intCast(i)), .manifest = prepared.manifest, .main = leaf.main, .receipt = leaf.receipt orelse return error.MissingOpRootLocalAuthority, .claims = leaf.claims[0..2].*, .local = &local, .shape = &shape, .values = &values } });
        } else {
            const shape = try @import("../pure_p2_truth_statement.zig").geometry(scratch, s.key, s.truth);
            const values = try Skeleton.init(scratch, &shape);
            try sink.visit(sink.context, a, .{ .classic_truth = .{ .key = s.key, .truth = s.truth, .expected = try s.key.expected(s.truth, @intCast(i)), .manifest = prepared.manifest, .main = leaf.main, .claims = leaf.claims, .shape = &shape, .values = &values } });
        }
    }
    for (authority.towers, 0..) |s, j| {
        const i = authority.cpus.len + authority.detached.len + authority.catalog.len + j;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const scratch = arena.allocator();
        const leaf = metadata.leaves[i];
        if (s.local_key) |key| {
            const instances = try (try key.geometry(s.span)).instances();
            const local = try Gkr.skeletonFor(scratch, &instances, templates.shapes[at]);
            at += 1;
            const shape = try @import("../miller_local_gkr/statement.zig").geometry(scratch, key, s.span);
            const values = try Skeleton.init(scratch, &shape);
            if (leaf.claims.len != 2) return error.OpRootLocalMillerClosure;
            try sink.visit(sink.context, a, .{ .local_miller = .{ .key = key, .span = s.span, .expected = try key.expected(s.span, @intCast(i)), .manifest = prepared.manifest, .main = leaf.main, .receipt = leaf.receipt orelse return error.MissingOpRootLocalAuthority, .claims = leaf.claims[0..2].*, .local = &local, .shape = &shape, .values = &values } });
        } else {
            const shape = try @import("../pure_p2_tower_statement.zig").geometry(scratch, s.key);
            const values = try Skeleton.init(scratch, &shape);
            if (leaf.claims.len != 4) return error.OpRootLocalMillerClosure;
            try sink.visit(sink.context, a, .{ .classic_miller = .{ .key = s.key, .span = s.span, .expected = try s.key.expected(s.span, @intCast(i)), .manifest = prepared.manifest, .main = leaf.main, .claims = leaf.claims[0..4].*, .shape = &shape, .values = &values } });
        }
    }
    if (at != templates.shapes.len) return error.OpRootTemplateCoverage;
}
