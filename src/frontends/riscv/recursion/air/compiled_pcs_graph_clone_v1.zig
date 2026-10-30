//! Owned copies of independently compiled PCS graphs. No graph is inferred from
//! a proof or accepted by a digest alone. Evaluation still checks fresh inputs.
const std = @import("std");
const Deep = @import("pcs_deep_circuit.zig");
const Fri = @import("fri_verifier_circuit.zig");
pub fn deep(a: std.mem.Allocator, original: *const Deep.Circuit) !Deep.Circuit {
    var result = original.*;
    result.allocator = a;
    result.trees = try a.alloc(Deep.TreeProfile, original.trees.len);
    errdefer a.free(result.trees);
    result.column_log_storage = try a.dupe(u32, original.column_log_storage);
    errdefer a.free(result.column_log_storage);
    var offset: usize = 0;
    for (original.trees, result.trees) |tree, *out| {
        const end = try std.math.add(usize, offset, tree.column_log_sizes.len);
        if (end > result.column_log_storage.len) return error.InvalidCompiledGraph;
        out.* = .{ .column_log_sizes = result.column_log_storage[offset..end] };
        offset = end;
    }
    if (offset != result.column_log_storage.len) return error.InvalidCompiledGraph;
    result.sample_layouts = try a.dupe(@TypeOf(original.sample_layouts[0]), original.sample_layouts);
    errdefer a.free(result.sample_layouts);
    result.mask_log_sizes = try a.dupe(u32, original.mask_log_sizes);
    errdefer a.free(result.mask_log_sizes);
    result.nodes = try a.dupe(@TypeOf(original.nodes[0]), original.nodes);
    errdefer a.free(result.nodes);
    result.outputs = try a.dupe(u32, original.outputs);
    errdefer a.free(result.outputs);
    result.bindings = try a.dupe(@TypeOf(original.bindings[0]), original.bindings);
    return result;
}
pub fn fri(a: std.mem.Allocator, original: *const Fri.Circuit) !Fri.Circuit {
    var result = original.*;
    result.allocator = a;
    result.fold_widths = try a.dupe(u32, original.fold_widths);
    errdefer a.free(result.fold_widths);
    result.nodes = try a.dupe(@TypeOf(original.nodes[0]), original.nodes);
    errdefer a.free(result.nodes);
    result.outputs = try a.dupe(u32, original.outputs);
    errdefer a.free(result.outputs);
    result.bindings = try a.dupe(@TypeOf(original.bindings[0]), original.bindings);
    return result;
}
