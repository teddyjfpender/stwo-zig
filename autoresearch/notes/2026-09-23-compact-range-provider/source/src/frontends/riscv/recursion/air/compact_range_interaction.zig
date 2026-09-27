//! Persistent authenticated interaction preparation for compact range providers.
//! One caller at a time; independent owners can be scheduled independently.
const std = @import("std");
const core = @import("stwo_core");
const schema = @import("../../air/lookups/tables/schema.zig");
const geometry = @import("compact_range_geometry.zig");
const provider = @import("compact_range_provider.zig");
const witness_mod = @import("compact_range_witness.zig");
const binding = @import("universal_relation_binding.zig");
const framework = @import("framework_interaction.zig");
const universal = @import("universal_challenges.zig");
pub fn Prepared(comptime kind: schema.Kind) type {
    const Air = provider.Provider(kind);
    const Binding = binding.Binding(Air);
    const Runtime = framework.Runtime(Binding.Runtime);
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        geometry_id: [32]u8,
        shape: geometry.Shape,
        definition: Air.Definition,
        plan: Binding.Plan,
        workspace: ?Runtime.Workspace = null,
        pub fn init(a: std.mem.Allocator, admitted: geometry.Plan, expected: [32]u8) !*Self {
            return initMode(a, admitted, expected, true);
        }
        pub fn initVerifier(a: std.mem.Allocator, admitted: geometry.Plan, expected: [32]u8) !*Self {
            return initMode(a, admitted, expected, false);
        }
        fn initMode(a: std.mem.Allocator, admitted: geometry.Plan, expected: [32]u8, proving: bool) !*Self {
            try admitted.admit(expected);
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.allocator = a;
            self.geometry_id = expected;
            self.shape = admitted.shapes[try geometry.kindIndex(kind)];
            self.definition = try Air.build(a);
            errdefer self.definition.deinit();
            self.plan = try Binding.authenticate(&self.definition);
            self.workspace = if (proving) try Runtime.Workspace.init(a, @min(self.shape.log_size, framework.OWNED_TILE_LOG_SIZE)) else null;
            return self;
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            if (self.workspace) |*workspace| workspace.deinit();
            self.definition.deinit();
            a.destroy(self);
        }
        /// Read final committed columns directly, without reconstructing row arrays.
        /// New output belongs to the caller; the inversion workspace is retained.
        pub fn generate(self: *Self, witness: *const witness_mod.Owner(kind), relations: *const universal.UniversalRelations) !Runtime.OwnedColumns {
            const workspace = if (self.workspace) |*value| value else return error.VerifierOnlyCompactRangePreparation;
            if (witness.log_size != self.shape.log_size or witness.n_rows != self.shape.n_rows) return error.CompactRangeWitnessGeometryMismatch;
            var view = Runtime.ColumnRows{
                .columns = @splat(&.{}),
                .count = @as(usize, 1) << @intCast(self.shape.log_size),
                .main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT,
            };
            for (&view.columns, witness.columns) |*destination, source| destination.* = source;
            return Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(self.allocator, workspace, &self.plan, view, self.shape.log_size, relations, @as(Air.Row, @splat(core.fields.m31.M31.zero())));
        }
    };
}
