//! Original PAGE child masks/placement union without constructing components.
//! Static callbacks share every live mask body; no relations/claims/proof handles.
const std = @import("std");
const core = @import("stwo_core");
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("../../prover/block_v5_memory_source_unified_page_components_v1.zig");
const Original = @import("../../prover/block_v5_memory_source_page_composition_v1.zig");
const ArithAirs = @import("arithmetic_fusion_fixed_columns_v1.zig").Airs;
const ArithRoster = @import("universal_component_roster.zig").ForAirs(ArithAirs, &.{ "dot4", "fma", "inverse", "linear" });
const Tables = @import("../../air/lookups/tables/schema.zig");
const Point = core.circle.CirclePointQM31;
const Masks = core.air.components.MaskPoints;
const Child = struct {
    factory: *const fn (u32, std.mem.Allocator, Point, u32) anyerror!Masks,
    log_size: u32,
    placements: []const Original.Placement,
    pub fn maskPoints(self: @This(), a: std.mem.Allocator, point: Point, max_log: u32) !Masks {
        return self.factory(self.log_size, a, point, max_log);
    }
};
fn tableFactory(comptime kind: Tables.Kind) type {
    return struct {
        fn masks(_: u32, a: std.mem.Allocator, point: Point, max_log: u32) !Masks {
            return @import("../../air/lookups/tables/component.zig").LookupTableComponent.staticMaskPoints(kind, a, point, max_log);
        }
    };
}
pub fn derive(comptime kind: Semantic.Kind, a: std.mem.Allocator, geometry: Components.ForKind(kind).Geometry, logs: [9][]const u32, limits: Original.Limits, point: Point, max_log: u32) !Masks {
    const C = Components.ForKind(kind);
    const roster = C.placementRoster();
    var children: [C.CHILD_COUNT]Child = undefined;
    var next: usize = 0;
    inline for (C.CoreAirs, 0..) |Air, index| {
        children[next] = .{ .factory = C.CoreRoster.Component(Air).staticMaskPoints, .log_size = geometry.core_logs[index], .placements = roster.placements[next][0..roster.lengths[next]] };
        next += 1;
    }
    inline for (.{ Tables.Kind.bitwise, Tables.Kind.range_check_8_8 }) |table_kind| {
        children[next] = .{ .factory = tableFactory(table_kind).masks, .log_size = Tables.logSize(table_kind), .placements = roster.placements[next][0..roster.lengths[next]] };
        next += 1;
    }
    const Capture = if (kind == .raw) @import("../../prover/block_v5_memory_source_sha_connector_component_v1.zig").ForSourceFixed(C.SOURCE_FIXED) else @import("../../prover/block_v5_memory_source_blake_capture_component_v1.zig").Component;
    children[next] = .{ .factory = Capture.staticMaskPoints, .log_size = geometry.capture_log, .placements = roster.placements[next][0..roster.lengths[next]] };
    next += 1;
    const Canon = @import("../../prover/block_v5_memory_source_page_canonical_component_v1.zig").ForKind(kind).Component;
    children[next] = .{ .factory = Canon.staticMaskPoints, .log_size = geometry.source_log, .placements = roster.placements[next][0..roster.lengths[next]] };
    next += 1;
    children[next] = .{ .factory = C.SourceInput.Component.staticMaskPoints, .log_size = geometry.source_log, .placements = roster.placements[next][0..roster.lengths[next]] };
    next += 1;
    children[next] = .{ .factory = C.CaptureInput.Component.staticMaskPoints, .log_size = geometry.capture_log, .placements = roster.placements[next][0..roster.lengths[next]] };
    next += 1;
    inline for (ArithAirs, 0..) |Air, index| {
        children[next] = .{ .factory = ArithRoster.Component(Air).staticMaskPoints, .log_size = geometry.arithmetic_logs[index], .placements = roster.placements[next][0..roster.lengths[next]] };
        next += 1;
    }
    if (next != C.CHILD_COUNT) return error.InvalidPageShapeMaskRoster;
    return Original.unionMaskPoints(a, logs, &children, limits, point, max_log);
}
