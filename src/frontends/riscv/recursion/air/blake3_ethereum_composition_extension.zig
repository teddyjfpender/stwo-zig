//! B3EH layout adapter for the shared fourteen-component equation recorder.
const core = @import("stwo_core");
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const geometry_mod = @import("../ethereum_composition_extension_geometry_v2.zig");
const Adapter = struct {
    pub const Scalar = S;
    pub const accumulate = r.accumulate;
    pub const quotientDenominator = r.quotientDenominator;
    pub fn diagnosticCheckpoint(_: []const u8, _: usize, _: u32, _: S) void {}
};
pub fn record(geometry: *const geometry_mod.GeometryV2, samples: anytype, claims: []const S, base_relations: anytype, draws: [13][2]S, randomness: S, point: core.circle.CirclePoint(S), max_log: u32, cache: *r.DenominatorCache, accumulated: *S) !usize {
    const Samples = @TypeOf(samples);
    const Layout = struct {
        geometry: *const geometry_mod.GeometryV2,
        samples: Samples,
        pub fn atExtension(self: *const @This(), tree: usize, column: usize, row: i8) !S {
            if (tree >= 3 or column >= self.geometry.columns[tree].len) return error.InvalidExecutionComposition;
            const shape = self.geometry.columns[tree][column];
            for (shape.row_offsets[0..shape.sample_count], 0..) |offset, i| {
                if (row == offset) return self.samples.at(tree, self.geometry.base_column_counts[tree] + column, i);
            }
            return error.InvalidExecutionComposition;
        }
        pub fn sampledExtensionSecure(self: *const @This(), column: usize, row: i8) !S {
            var partials: [4]S = undefined;
            for (&partials, 0..) |*value, i| value.* = try self.atExtension(2, column + i, row);
            return r.fromPartialEvals(partials);
        }
    };
    const Relations = @import("../ethereum_composition_relations_v2.zig").ForScalar(S, @TypeOf(base_relations)).Bundle;
    const relations = Relations.fromBase(base_relations, draws);
    const layout = Layout{ .geometry = geometry, .samples = samples };
    const result = try @import("../ethereum_vm_composition_graph_extension_v2.zig").ForRecorder(Adapter, Layout, Relations).record(geometry, &layout, claims, &relations, point, randomness, max_log, cache, accumulated.*);
    accumulated.* = result.accumulation;
    return result.instruction_count;
}
