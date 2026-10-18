//! Native trace-column geometry reconstructed from an admitted detached key.
//! No proof, capture, or witness field participates in this derivation.
const std = @import("std");
const authority = @import("detached_segment_authority_boundary_v1.zig");
const statement = @import("../air/statement.zig");
const lookup_physical = @import("../air/lang/lookup_physical_manifest_v2.zig");
const segment_profile = @import("segment_profile.zig");
const Layout = @import("sample_point_layout.zig").Layout;
const pcs = @import("air/pcs_deep_circuit_circuit.zig");
const transcript_shape = @import("transcript_shape.zig");
const protocol = @import("protocol.zig");

pub const Geometry = struct {
    allocator: std.mem.Allocator,
    /// Lifted log sizes in native verifier commitment order, Tree0–Tree2.
    trees: [3][]u32,
    /// Exact OODS mask order across Tree0–Tree3 (composition is last).
    sample_layouts: []Layout,
    composition_logs: []u32,
    pcs_trees: [4]pcs.TreeProfile,
    lifting_log_size: u32,
    blowup: u32,

    pub fn deinit(self: *Geometry) void {
        for (self.trees) |tree| self.allocator.free(tree);
        self.allocator.free(self.sample_layouts);
        self.allocator.free(self.composition_logs);
        self.* = undefined;
    }

    pub fn validateCaptured(self: *const Geometry, captured: []const []const u32) !void {
        if (captured.len != self.pcs_trees.len) return error.NativeColumnGeometryMismatch;
        for (self.trees, captured[0..self.trees.len]) |derived, actual|
            if (!std.mem.eql(u32, derived, actual)) return error.NativeColumnGeometryMismatch;
        if (!std.mem.eql(u32, self.composition_logs, captured[3]))
            return error.NativeColumnGeometryMismatch;
    }

    pub fn validateSampleLayouts(self: *const Geometry, captured: []const Layout) !void {
        if (!std.mem.eql(Layout, self.sample_layouts, captured))
            return error.NativeColumnGeometryMismatch;
    }

    pub fn pcsProfile(self: *const Geometry, query_count: u32) !pcs.Profile {
        const profile = pcs.Profile{
            .trees = &self.pcs_trees,
            .sample_layouts = self.sample_layouts,
            .lifting_log_size = self.lifting_log_size,
            .log_blowup_factor = self.blowup,
            .query_count = query_count,
        };
        try profile.validate();
        return profile;
    }

    /// The q193 scheduled-verifier shape is determined by the key's native
    /// roster and protocol constants, not the captured FRI or claim vectors.
    pub fn q193ScheduleShape(
        self: *const Geometry,
        descriptors: authority.DescriptorsV1,
    ) !@import("air/verifier_schedule.zig").ScheduleShape {
        if (self.lifting_log_size != segment_profile.LIFTING_LOG_SIZE or
            self.blowup != protocol.FRI_LOG_BLOWUP_FACTOR)
            return error.NativeColumnGeometryMismatch;
        var heights: [4]u32 = undefined;
        var queried_columns: usize = 0;
        for (self.pcs_trees, &heights) |tree, *height| {
            height.* = 0;
            for (tree.column_log_sizes) |log_size| height.* = @max(height.*, log_size);
            queried_columns = try add(queried_columns, tree.column_log_sizes.len);
        }
        const lookup_manifest = lookup_physical.Manifest.native();
        var physical_claims: usize = 0;
        for (descriptors.components) |desc|
            physical_claims = try add(physical_claims, lookup_manifest.entryForFamily(desc.family).detailed_claim_count);
        for (descriptors.infrastructure) |desc|
            physical_claims = try add(physical_claims, statement.nClaimedSumsForInfra(desc.kind));
        const sample_count = try (try self.pcsProfile(protocol.FRI_QUERY_COUNT)).sampleCount();
        return transcript_shape.derive(segment_profile.circuitProfile(), heights, .{
            .sampled_value_count = std.math.cast(u32, sample_count) orelse return error.NativeColumnGeometryMismatch,
            .queried_values_per_query = std.math.cast(u32, queried_columns) orelse return error.NativeColumnGeometryMismatch,
            .claimed_sum_count = segment_profile.CLAIMED_SUM_COUNT,
            .physical_claimed_sum_count = std.math.cast(u32, physical_claims) orelse return error.NativeColumnGeometryMismatch,
            .physical_component_count = std.math.cast(u32, descriptors.components.len) orelse return error.NativeColumnGeometryMismatch,
            .physical_infra_count = std.math.cast(u32, descriptors.infrastructure.len) orelse return error.NativeColumnGeometryMismatch,
            .interaction_pow_bits = protocol.INTERACTION_POW_BITS,
            .pcs_pow_bits = protocol.PCS_POW_BITS,
        });
    }
};

/// Derive the first three PCS trees exactly as the native verifier orders
/// them. The composition tree depends on the AIR's composition degree bound
/// and is checked separately by the frozen segment profile.
pub fn init(
    allocator: std.mem.Allocator,
    descriptors: authority.DescriptorsV1,
    blowup: u32,
) !Geometry {
    if (descriptors.components.len == 0 or
        descriptors.components.len > statement.MAX_COMPONENTS or
        descriptors.infrastructure.len > statement.MAX_INFRA_COMPONENTS or
        blowup == 0 or blowup > 8)
        return error.InvalidNativeDescriptorGeometry;
    var counts: [3]usize = .{ 0, 0, 0 };
    var max_log: u32 = 0;
    const lookup_manifest = lookup_physical.Manifest.native();
    for (descriptors.components) |desc| {
        try validateLog(desc.log_size, blowup);
        max_log = @max(max_log, desc.log_size);
        if (desc.n_columns == 0 or desc.n_columns > 1024)
            return error.InvalidNativeDescriptorGeometry;
        counts[0] = try add(counts[0], 2);
        counts[1] = try add(counts[1], desc.n_columns);
        counts[2] = try add(counts[2], lookup_manifest.entryForFamily(desc.family).interaction_column_count);
    }
    for (descriptors.infrastructure) |desc| {
        try validateLog(desc.log_size, blowup);
        max_log = @max(max_log, desc.log_size);
        if (desc.n_columns == 0 or desc.n_columns > 1024)
            return error.InvalidNativeDescriptorGeometry;
        counts[0] = try add(counts[0], statement.nPreprocessedColumnsForInfra(desc.kind));
        counts[1] = try add(counts[1], desc.n_columns);
        counts[2] = try add(counts[2], statement.nInteractionColsForInfra(desc.kind));
    }
    if (counts[0] == 0 or counts[1] == 0 or counts[2] == 0 or
        counts[0] > 8192 or counts[1] > 8192 or counts[2] > 8192)
        return error.InvalidNativeDescriptorGeometry;

    var trees: [3][]u32 = undefined;
    for (&trees, counts, 0..) |*tree, count, index| {
        tree.* = allocator.alloc(u32, count) catch |err| {
            for (trees[0..index]) |allocated| allocator.free(allocated);
            return err;
        };
    }
    errdefer for (trees) |tree| allocator.free(tree);
    var offsets: [3]usize = .{ 0, 0, 0 };
    for (descriptors.components) |desc| {
        fill(trees[0], &offsets[0], 2, desc.log_size + blowup);
        fill(trees[1], &offsets[1], desc.n_columns, desc.log_size + blowup);
        fill(trees[2], &offsets[2], lookup_manifest.entryForFamily(desc.family).interaction_column_count, desc.log_size + blowup);
    }
    for (descriptors.infrastructure) |desc| {
        fill(trees[0], &offsets[0], statement.nPreprocessedColumnsForInfra(desc.kind), desc.log_size + blowup);
        fill(trees[1], &offsets[1], desc.n_columns, desc.log_size + blowup);
        fill(trees[2], &offsets[2], statement.nInteractionColsForInfra(desc.kind), desc.log_size + blowup);
    }
    std.debug.assert(std.meta.eql(offsets, counts));
    const sampled_columns = try add(try add(try add(counts[0], counts[1]), counts[2]), segment_profile.COMPOSITION_COLUMN_COUNT);
    const sample_layouts = try allocator.alloc(Layout, sampled_columns);
    errdefer allocator.free(sample_layouts);
    @memset(sample_layouts[0 .. counts[0] + counts[1]], .current);
    @memset(sample_layouts[counts[0] + counts[1] .. counts[0] + counts[1] + counts[2]], .current_previous);
    @memset(sample_layouts[counts[0] + counts[1] + counts[2] ..], .current);
    const composition_logs = try allocator.alloc(u32, segment_profile.COMPOSITION_COLUMN_COUNT);
    @memset(composition_logs, max_log + blowup);
    return .{
        .allocator = allocator,
        .trees = trees,
        .sample_layouts = sample_layouts,
        .composition_logs = composition_logs,
        .pcs_trees = .{
            .{ .column_log_sizes = trees[0] },
            .{ .column_log_sizes = trees[1] },
            .{ .column_log_sizes = trees[2] },
            .{ .column_log_sizes = composition_logs },
        },
        .lifting_log_size = max_log + blowup,
        .blowup = blowup,
    };
}

fn validateLog(log_size: u32, blowup: u32) !void {
    // The detached native lane is capped at the segment profile's trace size.
    // Check this before rootForDescriptors allocates fixed columns.
    if (log_size == 0 or log_size > segment_profile.COLUMN_LOG_DEGREE or
        log_size + blowup > 31)
        return error.InvalidNativeDescriptorGeometry;
}

fn add(lhs: usize, rhs: usize) !usize {
    return std.math.add(usize, lhs, rhs) catch error.InvalidNativeDescriptorGeometry;
}

fn fill(tree: []u32, offset: *usize, count: usize, log_size: u32) void {
    @memset(tree[offset.* .. offset.* + count], log_size);
    offset.* += count;
}

test "native PCS trace logs follow the verifier's descriptor order without proof input" {
    const descriptors = authority.DescriptorsV1{
        .components = &.{.{ .family = .base_alu_imm, .log_size = 4, .n_rows = 8, .n_columns = 35 }},
        .infrastructure = &.{.{ .kind = .program, .log_size = 6, .n_rows = 32, .n_columns = 10 }},
    };
    var geometry = try init(std.testing.allocator, descriptors, 1);
    defer geometry.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 5, 5, 7, 7 }, geometry.trees[0]);
    try std.testing.expectEqual(@as(usize, 45), geometry.trees[1].len);
    try std.testing.expect(std.mem.allEqual(u32, geometry.trees[1][0..35], 5));
    try std.testing.expect(std.mem.allEqual(u32, geometry.trees[1][35..], 7));
    const interaction_start = geometry.trees[0].len + geometry.trees[1].len;
    try std.testing.expect(std.mem.allEqual(Layout, geometry.sample_layouts[0..interaction_start], .current));
    try std.testing.expect(std.mem.allEqual(Layout, geometry.sample_layouts[interaction_start .. interaction_start + geometry.trees[2].len], .current_previous));
    try std.testing.expect(std.mem.allEqual(Layout, geometry.sample_layouts[interaction_start + geometry.trees[2].len ..], .current));
    const pcs_profile = try geometry.pcsProfile(3);
    try std.testing.expectEqual(@as(usize, 4), pcs_profile.trees.len);
    try std.testing.expectEqual(@as(u32, 7), pcs_profile.lifting_log_size);
    var prepared = try @import("air/pcs_deep_circuit.zig").Prepared.init(std.testing.allocator, pcs_profile);
    defer prepared.deinit();
    try prepared.validate();
    const mutated_layouts = try std.testing.allocator.dupe(Layout, geometry.sample_layouts);
    defer std.testing.allocator.free(mutated_layouts);
    mutated_layouts[interaction_start] = .previous_current;
    try std.testing.expectError(error.NativeColumnGeometryMismatch, geometry.validateSampleLayouts(mutated_layouts));
    try std.testing.expectError(error.NativeColumnGeometryMismatch, geometry.validateCaptured(&.{
        &.{ 5, 5, 7, 6 }, geometry.trees[1], geometry.trees[2], geometry.composition_logs,
    }));
    try geometry.validateCaptured(&.{ geometry.trees[0], geometry.trees[1], geometry.trees[2], geometry.composition_logs });
    try std.testing.expectError(error.InvalidNativeDescriptorGeometry, init(std.testing.allocator, descriptors, 32));
    var oversized = descriptors;
    oversized.infrastructure = &.{.{ .kind = .program, .log_size = 21, .n_rows = 32, .n_columns = 10 }};
    try std.testing.expectError(error.InvalidNativeDescriptorGeometry, init(std.testing.allocator, oversized, 1));
}
