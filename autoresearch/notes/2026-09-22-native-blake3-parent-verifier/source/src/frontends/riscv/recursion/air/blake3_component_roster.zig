//! Typed BLAKE3 roster projection shared by proving and independent verification.
const std = @import("std");
const binding = @import("universal_relation_binding.zig");
const typed = @import("universal_typed_component.zig");
pub fn Fixture(comptime with_private_input: bool) type {
    return WithBridge(if (with_private_input) @import("blake3_input_bridge.zig") else null);
}
pub fn WithBridge(comptime Bridge: ?type) type {
    return WithExtras(if (Bridge) |Air| .{Air} else .{});
}
pub fn WithExtras(comptime Extras: anytype) type {
    return struct {
        const Self = @This();
        pub const Airs = .{ @import("blake3_g_call.zig"), @import("blake3_xor_call.zig"), @import("blake3_boundary.zig") } ++ Extras;
        pub const TREE_COUNT = 3;
        pub const PREPROCESSED_TREE_INDEX = 0;
        pub const MAIN_TREE_INDEX = 1;
        pub const INTERACTION_TREE_INDEX = 2;
        pub const ComponentKey = blk: {
            const names = [_][:0]const u8{ "g", "xor", "boundary", "input", "auxiliary", "query", "arithmetic" };
            var fields: [Airs.len]std.builtin.Type.EnumField = undefined;
            for (&fields, 0..) |*field, i| field.* = .{ .name = if (i < names.len) names[i] else std.fmt.comptimePrint("extra_{d}", .{i}), .value = i };
            break :blk @Type(.{ .@"enum" = .{ .tag_type = u8, .fields = &fields, .decls = &.{}, .is_exhaustive = true } });
        };
        pub const Geometry = @import("universal_manifest_contract.zig").Geometry;
        pub const Placement = @import("universal_manifest_contract.zig").Placement;
        pub fn keyIndex(key: ComponentKey) u8 {
            return @intFromEnum(key);
        }
        pub const Manifest = struct {
            log_sizes: [Airs.len]u32,
            pub fn placement(self: *const Manifest, key: ComponentKey) !Placement {
                var offsets: [4]u32 = @splat(0);
                inline for (Airs, 0..) |Air, i| {
                    const geometry = @import("universal_typed_geometry.zig").manifestGeometryForAir(Air, Self, @enumFromInt(i), self.log_sizes[i]);
                    if (@intFromEnum(key) == i) return .{ .geometry = geometry, .preprocessed_offset = offsets[0], .main_offset = offsets[1], .interaction_offset = offsets[2], .constraint_offset = offsets[3], .claimed_sum_index = i };
                    offsets[0] += Air.PREPROCESSED_COLUMN_COUNT;
                    offsets[1] += Air.PHYSICAL_MAIN_COLUMN_COUNT;
                    offsets[2] += Air.INTERACTION_COLUMN_COUNT;
                    offsets[3] += Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT;
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
