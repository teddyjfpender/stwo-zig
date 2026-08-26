//! Backend-neutral runtime export of validated `compat-v1` programs.
//!
//! This module performs no algebra and makes no layout decisions. It copies the
//! canonical direct or lookup polynomial program into the prover capability
//! types after revalidation. Lookup tails receive deterministic sentinels even
//! though the backend reads only `values[0..arity]`.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const production_entry = @import("../lookups/entry.zig");
const symbolic = @import("../extract/symbolic.zig");
const compat_layout = @import("compat_layout.zig");
const lower_constraint = @import("lower_constraint.zig");
const lower_lookup = @import("lower_lookup.zig");
const shadow_program = @import("shadow_program.zig");

const no_node = std.math.maxInt(u32);

pub fn buildDirect(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !prover_component.OwnedBasePolynomialProgram {
    var lowered = try lower_constraint.lower(allocator, imported, layout);
    defer lowered.deinit();
    return exportDirect(allocator, &lowered);
}

pub fn exportDirect(
    allocator: std.mem.Allocator,
    lowered: *const lower_constraint.Program,
) !prover_component.OwnedBasePolynomialProgram {
    try lowered.validate();
    const nodes = try copyNodes(allocator, lowered.nodes);
    errdefer allocator.free(nodes);
    const roots = try allocator.dupe(u32, lowered.roots);
    errdefer allocator.free(roots);
    const result = prover_component.OwnedBasePolynomialProgram{
        .allocator = allocator,
        .nodes = nodes,
        .roots = roots,
        .column_count = lowered.columnCount(),
    };
    try result.validate();
    return result;
}

pub fn buildLookups(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !prover_component.OwnedLookupPolynomialProgram {
    var lowered = try lower_lookup.lower(allocator, imported, layout);
    defer lowered.deinit();
    return exportLookups(allocator, &lowered);
}

pub fn exportLookups(
    allocator: std.mem.Allocator,
    lowered: *const lower_lookup.Program,
) !prover_component.OwnedLookupPolynomialProgram {
    try lowered.validate();
    const nodes = try copyNodes(allocator, lowered.polynomials.nodes);
    errdefer allocator.free(nodes);
    const entries = try allocator.alloc(
        prover_component.LookupPolynomialEntry,
        lowered.events.len,
    );
    errdefer allocator.free(entries);
    for (lowered.events, entries) |event, *entry| {
        const values = event.valueSlice() orelse
            return error.InvalidEventRoot;
        entry.* = .{
            .numerator = event.numerator,
            .values = .{no_node} ** prover_component.MAX_LOOKUP_POLYNOMIAL_ARITY,
            .arity = event.arity,
        };
        @memcpy(entry.values[0..values.len], values);
    }
    const result = prover_component.OwnedLookupPolynomialProgram{
        .allocator = allocator,
        .nodes = nodes,
        .entries = entries,
        .column_count = lowered.polynomials.columnCount(),
        .batch_size = lowered.batch_size,
    };
    try result.validate();
    return result;
}

fn copyNodes(
    allocator: std.mem.Allocator,
    source: []const symbolic.Node,
) ![]prover_component.BasePolynomialNode {
    const nodes = try allocator.alloc(
        prover_component.BasePolynomialNode,
        source.len,
    );
    for (source, nodes) |from, *to| {
        to.* = .{
            .op = @enumFromInt(@intFromEnum(from.op)),
            .lhs = from.lhs,
            .rhs = from.rhs,
            .value = from.value,
        };
    }
    return nodes;
}

comptime {
    if (@typeInfo(prover_component.BasePolynomialOp).@"enum".fields.len !=
        @typeInfo(symbolic.Op).@"enum".fields.len)
    {
        @compileError("runtime exporter requires the pinned six polynomial operations");
    }
    for (@typeInfo(symbolic.Op).@"enum".fields) |field| {
        const target = std.meta.stringToEnum(
            prover_component.BasePolynomialOp,
            field.name,
        ) orelse @compileError("runtime polynomial operation name mismatch");
        if (@intFromEnum(target) != field.value)
            @compileError("runtime polynomial operation tag mismatch");
    }
    if (prover_component.MAX_LOOKUP_POLYNOMIAL_ARITY < production_entry.MAX_ARITY)
        @compileError("runtime lookup target cannot represent production tuples");
}
