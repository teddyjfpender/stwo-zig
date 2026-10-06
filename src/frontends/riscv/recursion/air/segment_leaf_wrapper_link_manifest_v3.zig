//! Pinned typed-AIR geometry for the three V3 leaf-link rows after V2's 39.
//!
//! This is an extension manifest, not an accepted recursive leaf proof. It
//! admits the generic component adapter for source, projection and arithmetic
//! while the child-field, hash-provider and global LogUp closure remain absent.
const std = @import("std");
const base = @import("universal_manifest_contract.zig");
const v2_manifest = @import("segment_outer_adapter_manifest_v2.zig");
const typed = @import("universal_typed_component.zig");
const binding = @import("universal_relation_binding.zig");
const program_mod = @import("../ethereum_leaf_link_program_v1.zig");
const source_air = @import("ethereum_leaf_link_source_v1.zig");
const projection_air = @import("ethereum_leaf_link_projection_v1.zig");
const arithmetic_air = @import("ethereum_leaf_link_arithmetic_v1.zig");

pub const FORMAT_VERSION: u16 = 3;
pub const V2_COMPONENT_COUNT: usize = v2_manifest.COMPONENT_COUNT;
pub const LINK_COMPONENT_COUNT: usize = 3;
pub const COMPONENT_COUNT: usize = V2_COMPONENT_COUNT + LINK_COMPONENT_COUNT;
pub const TREE_COUNT: usize = 3;
pub const PREPROCESSED_TREE_INDEX: usize = 0;
pub const MAIN_TREE_INDEX: usize = 1;
pub const INTERACTION_TREE_INDEX: usize = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const COMPLETE_WRAPPER_PROOF_AVAILABLE = false;
pub const DOMAIN = "stwo-zig/riscv-v3-link-extension-manifest/v1\x00";

comptime {
    if (V2_COMPONENT_COUNT != 39)
        @compileError("V3 link extension must follow the frozen 39-row V2 cohort");
}

pub const ComponentKey = enum(u8) {
    link_source = 39,
    link_projection = 40,
    link_arithmetic = 41,
};
pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}
pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = @import("universal_adapter_manifest.zig").AdapterBinding;
pub const SourceAdapter = typed.ComponentForManifest(source_air, binding.Binding(source_air), @This());
pub const ProjectionAdapter = typed.ComponentForManifest(projection_air, binding.Binding(projection_air), @This());
pub const ArithmeticAdapter = typed.ComponentForManifest(arithmetic_air, binding.Binding(arithmetic_air), @This());

pub const Manifest = struct {
    format_version: u16 = FORMAT_VERSION,
    roster_rows: [LINK_COMPONENT_COUNT]u8 = .{ 39, 40, 41 },
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    pub fn build(allocator: std.mem.Allocator, program: *const program_mod.ProgramV1) !Manifest {
        try program.validate();
        // Cold typed-program admission precedes every geometry projection.
        inline for (.{ source_air, projection_air, arithmetic_air }) |Air| {
            var definition = try Air.build(allocator);
            defer definition.deinit();
            _ = try binding.Binding(Air).authenticate(&definition);
        }
        const geometry = geometries(program.source_log_size, program.projection_log_size);
        var placements: [COMPONENT_COUNT]?Placement = @splat(null);
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (geometry, 0..) |item, index| {
            try item.validateForComponentCount(COMPONENT_COUNT);
            placements[V2_COMPONENT_COUNT + index] = .{
                .geometry = item,
                .preprocessed_offset = pp,
                .main_offset = main,
                .interaction_offset = interaction,
                .constraint_offset = constraints,
                .claimed_sum_index = @intCast(V2_COMPONENT_COUNT + index),
            };
            pp = try std.math.add(u32, pp, item.preprocessed_columns);
            main = try std.math.add(u32, main, item.main_columns);
            interaction = try std.math.add(u32, interaction, item.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, item.direct_constraints) + item.interaction_batches);
        }
        var result = Manifest{
            .placements = placements,
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .seal = undefined,
        };
        result.seal = digest(&result);
        try result.validateAgainst(program);
        return result;
    }

    pub fn validate(self: *const Manifest) !void {
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.roster_rows, .{ 39, 40, 41 }))
            return error.InvalidV3LinkManifest;
        for (self.placements[0..V2_COMPONENT_COUNT]) |item|
            if (item != null) return error.InvalidV3LinkManifest;
        const source = self.placements[keyIndex(.link_source)] orelse return error.InvalidV3LinkManifest;
        const projection = self.placements[keyIndex(.link_projection)] orelse return error.InvalidV3LinkManifest;
        const expected = geometries(source.geometry.log_size, projection.geometry.log_size);
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (expected, 0..) |geometry, index| {
            const row = V2_COMPONENT_COUNT + index;
            const item = self.placements[row] orelse return error.InvalidV3LinkManifest;
            if (!std.meta.eql(item.geometry, geometry) or
                item.preprocessed_offset != pp or item.main_offset != main or
                item.interaction_offset != interaction or
                item.constraint_offset != constraints or
                item.claimed_sum_index != row)
                return error.InvalidV3LinkManifest;
            try geometry.validateForComponentCount(COMPONENT_COUNT);
            pp = try std.math.add(u32, pp, geometry.preprocessed_columns);
            main = try std.math.add(u32, main, geometry.main_columns);
            interaction = try std.math.add(u32, interaction, geometry.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, geometry.direct_constraints) + geometry.interaction_batches);
        }
        if (self.total_preprocessed_columns != pp or
            self.total_main_columns != main or
            self.total_interaction_columns != interaction or
            self.total_constraints != constraints or
            !std.mem.eql(u8, &self.seal, &digest(self)))
            return error.InvalidV3LinkManifest;
    }

    pub fn validateAgainst(self: *const Manifest, program: *const program_mod.ProgramV1) !void {
        try program.validate();
        try self.validate();
        if (self.placements[keyIndex(.link_source)].?.geometry.log_size != program.source_log_size or
            self.placements[keyIndex(.link_projection)].?.geometry.log_size != program.projection_log_size)
            return error.InvalidV3LinkManifest;
    }

    pub fn placement(self: *const Manifest, key: ComponentKey) !Placement {
        try self.validate();
        return self.placements[keyIndex(key)] orelse error.InvalidV3LinkManifest;
    }

    pub fn requireCompleteWrapperProof(_: *const Manifest) error{V3WrapperProofUnavailable}!void {
        return error.V3WrapperProofUnavailable;
    }
};

fn geometries(source_log_size: u32, projection_log_size: u32) [LINK_COMPONENT_COUNT]Geometry {
    return .{
        SourceAdapter.manifestGeometry(.link_source, source_log_size),
        ProjectionAdapter.manifestGeometry(.link_projection, projection_log_size),
        ArithmeticAdapter.manifestGeometry(.link_arithmetic, 4),
    };
}

fn digest(value: *const Manifest) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.roster_rows);
    for (value.placements[V2_COMPONENT_COUNT..]) |maybe| {
        const item = maybe orelse return @splat(0);
        const geometry = item.geometry;
        hashInt(&hash, u8, geometry.roster_row);
        hashInt(&hash, u32, geometry.log_size);
        inline for (.{ geometry.preprocessed_columns, geometry.main_columns, geometry.interaction_columns, geometry.direct_constraints, geometry.interaction_batches }) |n|
            hashInt(&hash, u16, n);
        hashInt(&hash, u8, geometry.protocol_constraint_degree);
        hashInt(&hash, u8, geometry.profiled_constraint_degree);
        hash.update(&geometry.semantic_digest);
        inline for (.{ item.preprocessed_offset, item.main_offset, item.interaction_offset, item.constraint_offset }) |n|
            hashInt(&hash, u32, n);
        hashInt(&hash, u8, item.claimed_sum_index);
    }
    inline for (.{ value.total_preprocessed_columns, value.total_main_columns, value.total_interaction_columns, value.total_constraints }) |n|
        hashInt(&hash, u32, n);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
