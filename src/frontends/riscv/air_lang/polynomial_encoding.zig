//! Ownership conversion for canonical symbolic constraint/lookup DAGs.
const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const symbolic = @import("shared/air/extract/symbolic.zig");
const entry = @import("shared/air/lookups/entry.zig");
const SymbolicLookupList = entry.Builder(symbolic.Scalar).List;

pub fn ownDirectProgram(
    allocator: std.mem.Allocator,
    arena: *const symbolic.Arena,
    direct: []const symbolic.Scalar,
    main_column_count: usize,
) !prover_component.OwnedBasePolynomialProgram {
    // Scalar arithmetic cannot return allocation errors. Never read/copy its
    // inert fallback IDs, validate them or publish ownership after latched OOM.
    try arena.checkAllocation();
    const nodes = try allocator.alloc(
        prover_component.BasePolynomialNode,
        arena.nodes.items.len,
    );
    errdefer allocator.free(nodes);
    for (arena.nodes.items, nodes) |source, *destination| {
        destination.* = .{
            .op = @enumFromInt(@intFromEnum(source.op)),
            .lhs = source.lhs,
            .rhs = source.rhs,
            .value = source.value,
        };
    }

    const roots = try allocator.alloc(u32, direct.len);
    errdefer allocator.free(roots);
    for (direct, roots) |constraint, *root|
        root.* = constraint.id;

    const result = prover_component.OwnedBasePolynomialProgram{
        .allocator = allocator,
        .nodes = nodes,
        .roots = roots,
        .column_count = main_column_count + 1,
    };
    try result.validate();
    return result;
}

pub fn ownLookupProgram(
    allocator: std.mem.Allocator,
    arena: *const symbolic.Arena,
    lookups: *const SymbolicLookupList,
    main_column_count: usize,
) !prover_component.OwnedLookupPolynomialProgram {
    try arena.checkAllocation();
    const nodes = try copyNodes(allocator, arena.nodes.items);
    errdefer allocator.free(nodes);
    const entries = try allocator.alloc(
        prover_component.LookupPolynomialEntry,
        lookups.len,
    );
    errdefer allocator.free(entries);
    for (lookups.entries[0..lookups.len], entries) |source, *destination| {
        destination.* = .{
            .numerator = source.numerator.id,
            .arity = source.arity,
        };
        for (source.values[0..source.arity], destination.values[0..source.arity]) |value, *root|
            root.* = value.id;
    }
    const result = prover_component.OwnedLookupPolynomialProgram{
        .allocator = allocator,
        .nodes = nodes,
        .entries = entries,
        .column_count = main_column_count,
        .batch_size = lookups.batch_size,
    };
    try result.validate();
    return result;
}

fn copyNodes(
    allocator: std.mem.Allocator,
    source_nodes: []const symbolic.Node,
) ![]prover_component.BasePolynomialNode {
    const nodes = try allocator.alloc(
        prover_component.BasePolynomialNode,
        source_nodes.len,
    );
    for (source_nodes, nodes) |source, *destination| {
        destination.* = .{
            .op = @enumFromInt(@intFromEnum(source.op)),
            .lhs = source.lhs,
            .rhs = source.rhs,
            .value = source.value,
        };
    }
    return nodes;
}
