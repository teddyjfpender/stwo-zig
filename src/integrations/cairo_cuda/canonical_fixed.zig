//! Project authenticated fixed writer metadata onto the selected public variant.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const fixed = cairo.witness.fixed_table_bundle;

/// Allocations belong to the source assembler's arena. All arithmetic/table
/// recipes are retained; only W9 public column names and domain change.
pub fn project(allocator: std.mem.Allocator, source: fixed.Bundle, spec: cairo.preprocessed.trace.Spec) !fixed.Bundle {
    const identities = try allocator.alloc([]u8, spec.columns.len);
    for (spec.columns, identities) |column, *identity| identity.* = try allocator.dupe(u8, column.identity);
    const entries = try allocator.alloc(fixed.Entry, source.entries.len);
    for (source.entries, entries) |original, *entry| {
        entry.* = original;
        const small = spec.variant == .canonical_small and std.mem.eql(u8, original.component, "pedersen_points_table_window_bits_18");
        entry.component = try allocator.dupe(u8, if (small) "pedersen_points_table_window_bits_9" else original.component);
        entry.trace_multiplicity_columns = try allocator.dupe(u32, original.trace_multiplicity_columns);
        entry.lookup_descriptors = try allocator.dupe(u32, original.lookup_descriptors);
        entry.preprocessed_sources = try allocator.alloc([]u8, original.preprocessed_sources.len);
        for (original.preprocessed_sources, entry.preprocessed_sources) |identity, *projected| {
            projected.* = if (small and std.mem.eql(u8, identity, "seq_23")) try allocator.dupe(u8, "seq_15") else if (small and std.mem.startsWith(u8, identity, "pedersen_points_"))
                try std.fmt.allocPrint(allocator, "pedersen_points_small_{s}", .{identity["pedersen_points_".len..]})
            else
                try allocator.dupe(u8, identity);
        }
        if (small) {
            entry.log_size = 15;
            entry.row_count = 1 << 15;
        }
    }
    return .{ .allocator = allocator, .format_version = fixed.projected_version, .graph_hash = source.graph_hash, .preprocessed_identities = identities, .entries = entries };
}
