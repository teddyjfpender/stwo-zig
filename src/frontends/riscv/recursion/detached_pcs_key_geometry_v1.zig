//! Exact PCS column logs and ordered masks reconstructed from an admitted
//! detached child key. No proof capture, sampled value, or query enters here.
const std = @import("std");
const capture_layout = @import("recursion_air_composition_capture_layout_v3.zig");
const pcs = @import("air/pcs_deep_circuit.zig");
const SampleLayout = @import("sample_point_layout.zig").Layout;

pub const GeometryV1 = struct {
    allocator: std.mem.Allocator,
    column_logs: [capture_layout.TREE_COUNT][]u32,
    sample_layouts: []SampleLayout,
    tree_profiles: [capture_layout.TREE_COUNT]pcs.TreeProfile,
    lifting_log_size: u32,
    blowup: u32,
    query_count: u32,

    pub fn init(allocator: std.mem.Allocator, key: anytype) !GeometryV1 {
        const Layout = capture_layout.CaptureLayoutV3;
        var from_key = if (comptime @hasField(@TypeOf(key.*), "source_manifest"))
            try Layout.initSegmentFromKey(allocator, &key.manifest, key.pcs_config.fri_config.log_blowup_factor)
        else
            try Layout.initDetachedParentFromKey(allocator, &key.manifest, key.pcs_config.fri_config.log_blowup_factor);
        defer from_key.deinit();
        const heights = try from_key.treeHeightsFromManifest(&key.manifest);

        var column_logs: [capture_layout.TREE_COUNT][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (column_logs[0..initialized]) |logs| allocator.free(logs);
        for (from_key.tree_column_counts, &column_logs) |count, *logs| {
            logs.* = try allocator.alloc(u32, count);
            @memset(logs.*, 0);
            initialized += 1;
        }
        const blowup = key.pcs_config.fri_config.log_blowup_factor;
        for (key.manifest.roster_rows[0..key.manifest.roster_count]) |row| {
            const placement = key.manifest.placements[row].?;
            const size = std.math.add(u32, placement.geometry.log_size, blowup) catch return error.InvalidKeyPcsGeometry;
            const ranges = [_]struct { tree: usize, start: u32, count: u16 }{
                .{ .tree = 0, .start = placement.preprocessed_offset, .count = placement.geometry.preprocessed_columns },
                .{ .tree = 1, .start = placement.main_offset, .count = placement.geometry.main_columns },
                .{ .tree = 2, .start = placement.interaction_offset, .count = placement.geometry.interaction_columns },
            };
            for (ranges) |range| {
                const start: usize = range.start;
                const end = std.math.add(usize, start, range.count) catch return error.InvalidKeyPcsGeometry;
                if (end > column_logs[range.tree].len) return error.InvalidKeyPcsGeometry;
                for (column_logs[range.tree][start..end]) |*log| {
                    if (log.* != 0) return error.InvalidKeyPcsGeometry;
                    log.* = size;
                }
            }
        }
        const composition_height = std.math.add(u32, from_key.quotient_max_log_degree_bound, blowup) catch return error.InvalidKeyPcsGeometry;
        @memset(column_logs[capture_layout.COMPOSITION_TREE_INDEX], composition_height);
        for (column_logs, heights) |logs, height| {
            var maximum: u32 = 0;
            for (logs) |log| {
                if (log == 0 or log > height) return error.InvalidKeyPcsGeometry;
                maximum = @max(maximum, log);
            }
            if (maximum != height) return error.InvalidKeyPcsGeometry;
        }

        const sample_layouts = try from_key.sampleLayoutsFromKey(allocator, &key.manifest);
        errdefer allocator.free(sample_layouts);
        var result = GeometryV1{
            .allocator = allocator,
            .column_logs = column_logs,
            .sample_layouts = sample_layouts,
            .tree_profiles = undefined,
            .lifting_log_size = heights[capture_layout.COMPOSITION_TREE_INDEX],
            .blowup = blowup,
            .query_count = std.math.cast(u32, key.pcs_config.fri_config.n_queries) orelse return error.InvalidKeyPcsGeometry,
        };
        for (column_logs, &result.tree_profiles) |logs, *tree|
            tree.* = .{ .column_log_sizes = logs };
        try result.pcsProfile().validate();
        return result;
    }

    pub fn deinit(self: *GeometryV1) void {
        for (self.column_logs) |logs| self.allocator.free(logs);
        self.allocator.free(self.sample_layouts);
        self.* = undefined;
    }

    pub fn pcsProfile(self: *const GeometryV1) pcs.Profile {
        return .{
            .trees = &self.tree_profiles,
            .sample_layouts = self.sample_layouts,
            .lifting_log_size = self.lifting_log_size,
            .log_blowup_factor = self.blowup,
            .query_count = self.query_count,
        };
    }

    pub fn validateCaptured(self: *const GeometryV1, capture: anytype) !void {
        if (capture.column_log_sizes.len != self.column_logs.len or
            capture.circuit.lifting_log_size != self.lifting_log_size or
            capture.circuit.query_count != self.query_count or
            !std.mem.eql(SampleLayout, self.sample_layouts, capture.sample_layouts))
            return error.KeyPcsGeometryMismatch;
        for (self.column_logs, capture.column_log_sizes) |expected, actual|
            if (!std.mem.eql(u32, expected, actual)) return error.KeyPcsGeometryMismatch;
    }

    pub fn buildPcsCircuit(self: *const GeometryV1, allocator: std.mem.Allocator) !pcs.Prepared {
        return pcs.Prepared.init(allocator, self.pcsProfile());
    }
};
