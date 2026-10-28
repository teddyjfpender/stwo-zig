//! Parent Tree0 recipe. Every field is checked against independently pinned
//! child keys; serialized values are never an authority for fixed-row shape.
const std = @import("std");
const section = @import("detached_section_profile_v1.zig");
const memory = @import("detached_memory_profile_v1.zig");
const segment_boundary = @import("detached_boundary_key_shape_v1.zig");
const key_shape = @import("detached_pcs_key_shape_v1.zig");
const key_template = @import("detached_pcs_key_template_v1.zig");
const segment_manifest = @import("air/segment_outer_adapter_manifest_v2.zig");
const Digest = @import("poseidon2_channel.zig").Digest;

pub const VERSION: u32 = 1;
pub const ChildFamily = enum(u8) { segment = 1, parent = 2 };
pub const SegmentBoundaryShape = struct {
    sections: [2]section.SectionProfileV1,
    memory: [2]memory.MemoryProfileV1,
};
pub const BoundaryShape = union(ChildFamily) {
    segment: SegmentBoundaryShape,
    parent: void,
};
pub const ChildFixedShape = struct {
    key_identity: [32]u8,
    preprocessed_root: Digest,
    manifest_seal: [32]u8,
    composition_layout_manifest_id: [32]u8,
    vm_schedule_digest: Digest,
    recursion_schedule_digest: Digest,
    pcs_graph_identity_digest: [32]u8,
    sampled_value_count: u32,
    trace_tree_heights: [4]u32,
    fri_layer_count: u32,
    last_layer_coefficient_count: u32,
};
pub const FixedRecipeV1 = struct {
    version: u32 = VERSION,
    boundary: BoundaryShape,
    children: [2]ChildFixedShape,

    pub fn fromChildKeys(comptime family: ChildFamily, allocator: std.mem.Allocator, keys: anytype) !FixedRecipeV1 {
        const boundary: BoundaryShape = if (family == .segment) blk: {
            var sections: [2]section.SectionProfileV1 = undefined;
            var memories: [2]memory.MemoryProfileV1 = undefined;
            inline for (keys, 0..) |key, index| {
                const shape = try segment_boundary.SegmentShapeV1.init(allocator, key);
                sections[index] = .{ .counts = key.retained_section_counts };
                memories[index] = shape.memory;
            }
            break :blk .{ .segment = .{ .sections = sections, .memory = memories } };
        } else .{ .parent = {} };
        var children: [2]ChildFixedShape = undefined;
        inline for (0..2) |index| children[index] = try childShape(family, allocator, keys[index]);
        return .{ .boundary = boundary, .children = children };
    }

    pub fn validateAgainstChildKeys(self: *const FixedRecipeV1, comptime family: ChildFamily, allocator: std.mem.Allocator, keys: anytype) !void {
        if (self.version != VERSION or std.meta.activeTag(self.boundary) != family)
            return error.DetachedParentFixedRecipeMismatch;
        const derived = try fromChildKeys(family, allocator, keys);
        if (family == .segment) {
            const claimed = self.boundary.segment;
            const actual = derived.boundary.segment;
            for (claimed.sections, actual.sections, claimed.memory, actual.memory) |lhs_section, rhs_section, lhs_memory, rhs_memory| {
                if (!std.meta.eql(lhs_section, rhs_section) or lhs_memory.version != rhs_memory.version or
                    !std.mem.eql(u32, lhs_memory.entry_addresses, rhs_memory.entry_addresses) or
                    !std.mem.eql(u32, lhs_memory.exit_addresses, rhs_memory.exit_addresses))
                    return error.DetachedParentBoundaryShapeMismatch;
            }
        }
        for (self.children, derived.children) |claimed, actual| {
            if (!std.meta.eql(claimed, actual)) return error.DetachedParentFixedRecipeMismatch;
        }
    }
};

fn childShape(comptime family: ChildFamily, allocator: std.mem.Allocator, key: anytype) !ChildFixedShape {
    try key.validate();
    const shape = try key_shape.scheduleShape(allocator, key);
    var vm = try key_shape.planFromKey(allocator, key, .vm);
    defer vm.deinit();
    var recursive = try key_shape.planFromKey(allocator, key, .recursion);
    defer recursive.deinit();
    var template = try key_template.TemplateV1.init(allocator, key);
    defer template.deinit();
    if (shape.tree_heights.len != 4) return error.DetachedParentFixedRecipeMismatch;
    return .{
        .key_identity = try key.identity(),
        .preprocessed_root = key.preprocessed_root,
        .manifest_seal = key.manifest.seal,
        .composition_layout_manifest_id = if (family == .segment)
            segment_manifest.programGeometryShaId(&key.manifest)
        else
            key.manifest.seal,
        .vm_schedule_digest = vm.authority_digest,
        .recursion_schedule_digest = recursive.authority_digest,
        .pcs_graph_identity_digest = template.pcs_circuit.view().identity_digest,
        .sampled_value_count = shape.sampled_value_count,
        .trace_tree_heights = shape.tree_heights,
        .fri_layer_count = shape.fri.count,
        .last_layer_coefficient_count = shape.fri.last_layer_coefficient_count,
    };
}
