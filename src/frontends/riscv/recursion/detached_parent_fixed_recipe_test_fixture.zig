//! Non-admitted placeholders for geometry-only unit tests. Never use as keys.
const recipe = @import("detached_parent_fixed_recipe_v1.zig");

pub fn placeholder() recipe.FixedRecipeV1 {
    const child = recipe.ChildFixedShape{
        .key_identity = @splat(1),
        .preprocessed_root = @splat(1),
        .manifest_seal = @splat(1),
        .composition_layout_manifest_id = @splat(1),
        .vm_schedule_digest = @splat(1),
        .recursion_schedule_digest = @splat(1),
        .pcs_graph_identity_digest = @splat(1),
        .sampled_value_count = 1,
        .trace_tree_heights = @splat(4),
        .fri_layer_count = 1,
        .last_layer_coefficient_count = 1,
    };
    return .{ .boundary = .{ .parent = {} }, .children = .{ child, child } };
}
