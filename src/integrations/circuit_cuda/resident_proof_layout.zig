//! Mixed-height proof-decoder layout for the circuit AIR. The shared CUDA
//! decoder consumes this without applying its uniform Cairo/Fibonacci policy.
const std = @import("std");
const core = @import("stwo_core");
const shared = @import("stwo_native_cuda_integration").common.uniform_layout;
const geometry_module = @import("geometry.zig");
const oods_module = @import("resident_oods.zig");

pub const Layout = ForCommitments(4);

/// Finite original protocols; access witness keeps a distinct fifth tree.
pub fn ForCommitments(comptime N: usize) type {
    if (N != 4 and N != 5) @compileError("resident proof layout requires four or five commitments");
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        trace_trees: [N]shared.TraceTree,
        fri_trees: []shared.FriTree,
        sample_counts: [N][]u8,
        sample_total: usize,
        allow_empty_masks: bool = false,

        pub fn init(
            allocator: std.mem.Allocator,
            geometry: anytype,
            oods: *const oods_module.Plan,
            config: anytype,
        ) !Self {
            return initWithMaskPolicy(allocator, geometry, oods, config, false);
        }

        pub fn initForOriginalMasks(
            allocator: std.mem.Allocator,
            geometry: anytype,
            oods: *const oods_module.Plan,
            config: anytype,
        ) !Self {
            return initWithMaskPolicy(allocator, geometry, oods, config, true);
        }

        fn initWithMaskPolicy(
            allocator: std.mem.Allocator,
            geometry: anytype,
            oods: *const oods_module.Plan,
            config: anytype,
            allow_empty_masks: bool,
        ) !Self {
            if (geometry.fri_layers.len == 0 or oods.sources.len != oods.offsets.len or
                config.fri_config.fold_step == 0)
                return error.InvalidCircuitProofLayout;
            var trees: [N]shared.TraceTree = undefined;
            var counts: [N][]u8 = undefined;
            var initialized: usize = 0;
            errdefer for (counts[0..initialized]) |owned| allocator.free(owned);
            var source_first: usize = 0;
            for (geometry.trees, &trees, &counts, 0..) |tree, *target, *count_slice, index| {
                if (tree.column_logs.len == 0) return error.InvalidCircuitProofLayout;
                const max_log = std.mem.max(u32, tree.column_logs);
                if (max_log + config.fri_config.log_blowup_factor > tree.lifted_log)
                    return error.InvalidCircuitProofLayout;
                target.* = .{
                    .role = roleAt(index),
                    .column_count = tree.column_logs.len,
                    .column_log_size = max_log,
                    .commitment_log_size = tree.lifted_log,
                    .sampled = true,
                    .decommitted = true,
                };
                const owned = try allocator.alloc(u8, tree.column_logs.len);
                @memset(owned, 0);
                count_slice.* = owned;
                initialized += 1;
                const source_end = try std.math.add(usize, source_first, tree.column_logs.len);
                for (oods.sources) |source| {
                    if (source >= source_first and source < source_end) {
                        const count = &owned[source - source_first];
                        if (count.* == 2) return error.InvalidCircuitProofLayout;
                        count.* += 1;
                    }
                }
                for (owned) |count| if (count == 0 and !allow_empty_masks) return error.InvalidCircuitProofLayout;
                source_first = source_end;
            }
            const fri = try allocator.alloc(shared.FriTree, geometry.fri_layers.len);
            errdefer allocator.free(fri);
            for (geometry.fri_layers, fri, 0..) |layer, *target, index| target.* = .{
                .tree_index = N + index,
                .evaluation_log_size = layer.evaluation_log,
                .cumulative_fold = layer.cumulative_fold,
                .fold_step = layer.fold_step,
                .log_rows_per_leaf = layer.evaluation_log - layer.leaf_log,
            };
            const result = Self{
                .allocator = allocator,
                .trace_trees = trees,
                .fri_trees = fri,
                .sample_counts = counts,
                .sample_total = oods.sources.len,
                .allow_empty_masks = allow_empty_masks,
            };
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self, _: std.mem.Allocator) void {
            for (self.sample_counts) |owned| self.allocator.free(owned);
            self.allocator.free(self.fri_trees);
            self.* = undefined;
        }

        pub fn validate(self: Self) !void {
            if (self.fri_trees.len == 0) return error.InvalidCircuitProofLayout;
            var samples: usize = 0;
            for (self.trace_trees, self.sample_counts, 0..) |tree, counts, index| {
                const expected_role = roleAt(index);
                if (tree.role != expected_role or !tree.sampled or !tree.decommitted or
                    counts.len != tree.column_count or tree.column_log_size > tree.commitment_log_size)
                    return error.InvalidCircuitProofLayout;
                for (counts) |count| {
                    if ((count == 0 and !self.allow_empty_masks) or count > 2) return error.InvalidCircuitProofLayout;
                    samples += count;
                }
            }
            if (samples != self.sample_total) return error.InvalidCircuitProofLayout;
            for (self.fri_trees, 0..) |tree, index| {
                if (tree.tree_index != N + index or tree.fold_step == 0 or
                    tree.fold_step > 4 or tree.log_rows_per_leaf != @as(u32, if (tree.fold_step > 1 and tree.evaluation_log_size >= 2) 2 else 0))
                    return error.InvalidCircuitProofLayout;
            }
        }

        pub fn sampleCount(self: *const Self, tree_index: usize, column_index: usize) !usize {
            if (tree_index >= N or column_index >= self.sample_counts[tree_index].len)
                return error.InvalidCircuitProofLayout;
            return self.sample_counts[tree_index][column_index];
        }
        fn roleAt(index: usize) shared.TraceRole {
            if (N == 5) return ([_]shared.TraceRole{ .preprocessed, .main, .main, .interaction, .composition })[index];
            return ([_]shared.TraceRole{ .preprocessed, .main, .interaction, .composition })[index];
        }
    };
}

test "resident circuit proof layout preserves mixed column logs and double samples" {
    const circuit = @import("stwo_circuit_frontend");
    const cpu = @import("stwo_circuit_cpu_integration");
    const air = @import("air_aot.zig");
    const allocator = std.testing.allocator;
    const encoded = try std.fs.cwd().readFileAlloc(allocator, cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air.build(allocator, encoded);
    defer catalog.deinit();
    const columns = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(cpu.air.recorded_sizes);
    var bound = try cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&columns), &columns);
    defer bound.deinit();
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    const config = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, columns.traceLogSize());
    var geometry = try geometry_module.Geometry.init(allocator, &columns, &bound, &catalog, config);
    defer geometry.deinit();
    var oods = try oods_module.Plan.init(allocator, &bound, &geometry, fri.log_blowup_factor);
    defer oods.deinit();
    var layout = try Layout.init(allocator, &geometry, &oods, config);
    defer layout.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), layout.trace_trees.len);
    try std.testing.expectEqual(geometry.fri_layers.len, layout.fri_trees.len);
    try std.testing.expectEqual(oods.offsets.len, layout.sample_total);
    try std.testing.expectEqual(@as(usize, 1), try layout.sampleCount(0, 0));
    var doubles: usize = 0;
    for (layout.sample_counts) |counts| for (counts) |count| {
        doubles += @intFromBool(count == 2);
    };
    try std.testing.expect(doubles > 0);
}
