//! Shared typed component placement; protocol-specific wrappers own AIR order.
const std = @import("std");
const binding = @import("universal_relation_binding.zig");
const typed = @import("universal_typed_component.zig");
pub fn ForAirs(comptime Definitions: anytype, comptime names: []const [:0]const u8) type {
    return struct {
        const Self = @This();
        pub const Airs = Definitions;
        pub const TREE_COUNT = 3;
        pub const PREPROCESSED_TREE_INDEX = 0;
        pub const MAIN_TREE_INDEX = 1;
        pub const INTERACTION_TREE_INDEX = 2;
        pub const ComponentKey = blk: {
            var fields: [Airs.len]std.builtin.Type.EnumField = undefined;
            for (&fields, 0..) |*field, i| field.* = .{ .name = if (i < names.len) names[i] else std.fmt.comptimePrint("extra_{d}", .{i}), .value = i };
            break :blk @Type(.{ .@"enum" = .{ .tag_type = u8, .fields = &fields, .decls = &.{}, .is_exhaustive = true } });
        };
        pub const Geometry = @import("universal_manifest_contract.zig").Geometry;
        pub const Placement = @import("universal_manifest_contract.zig").Placement;
        pub fn keyIndex(key: ComponentKey) u8 {
            return @intFromEnum(key);
        }
        pub const Origin = struct {
            columns: [4]u32 = @splat(0),
            claimed_sum_index: u8 = 0,
        };
        pub const Manifest = struct {
            log_sizes: [Airs.len]u32,
            origin: Origin = .{},
            pub fn placement(self: *const Manifest, key: ComponentKey) !Placement {
                var offsets = self.origin.columns;
                inline for (Airs, 0..) |Air, i| {
                    const geometry = @import("universal_typed_geometry.zig").manifestGeometryForAir(Air, Self, @enumFromInt(i), self.log_sizes[i]);
                    const start = offsets;
                    offsets[0] = try std.math.add(u32, offsets[0], Air.PREPROCESSED_COLUMN_COUNT);
                    offsets[1] = try std.math.add(u32, offsets[1], Air.PHYSICAL_MAIN_COLUMN_COUNT);
                    offsets[2] = try std.math.add(u32, offsets[2], Air.INTERACTION_COLUMN_COUNT);
                    offsets[3] = try std.math.add(u32, offsets[3], Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT);
                    if (@intFromEnum(key) == i) return .{ .geometry = geometry, .preprocessed_offset = start[0], .main_offset = start[1], .interaction_offset = start[2], .constraint_offset = start[3], .claimed_sum_index = try std.math.add(u8, self.origin.claimed_sum_index, @intCast(i)) };
                }
                return error.InvalidFixtureComponent;
            }
        };
        pub fn Component(comptime Air: type) type {
            return typed.ComponentForManifest(Air, binding.Binding(Air), Self);
        }
        pub fn Tuple(comptime kind: enum { definition, plan, component }) type {
            var types: [Airs.len]type = undefined;
            for (Airs, &types) |Air, *T| T.* = switch (kind) {
                .definition => Air.Definition,
                .plan => binding.Binding(Air).Plan,
                .component => Component(Air),
            };
            return std.meta.Tuple(&types);
        }
    };
}
