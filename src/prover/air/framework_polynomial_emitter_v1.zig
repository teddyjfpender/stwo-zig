//! Exact backend-neutral framework equation emitter. Inputs are authenticated
//! production DAGs; only field helper spellings and a C-compatible kernel ABI
//! are assumed. CUDA and Metal share every root, signed tuple and recurrence.
const std = @import("std");
const component = @import("component_programs.zig");
const Program = component.OwnedFrameworkPolynomialProgramV1;
const Node = component.BasePolynomialNode;
pub fn fingerprint() [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(@embedFile("framework_polynomial_emitter_v1.zig"), &result, .{});
    return result;
}
pub fn emitBody(allocator: std.mem.Allocator, writer: anytype, program: *const Program) !void {
    const total_roots = program.direct.roots.len + program.batches.len;
    try emitNodes(allocator, writer, program, program.direct.nodes, program.direct.roots, "d", total_roots);

    const parameter = try emitLookupTerms(allocator, writer, program);
    if (program.layout == .independent_prefix_v1) {
        const slot = program.is_first_input.?;
        const column = program.inputs[slot].trace_column;
        try writer.print("    uint is_first = tree{}[column_offsets[{}u] + row];\n", .{ column.tree_index, slot });
    }
    for (program.batches, 0..) |batch, index| {
        try emitSecureLoad(writer, program, "current", index, batch.interaction_column_start, "row");
        switch (program.layout) {
            .same_row_prefix_v1 => {
                if (index == 0) {
                    try writer.print("    RiscvQm31 delta{} = current{};\n", .{ index, index });
                } else {
                    try writer.print("    RiscvQm31 delta{} = riscv_qm_sub(current{}, current{});\n", .{ index, index, index - 1 });
                }
                if (index + 1 == program.batches.len) {
                    try emitSecureLoad(writer, program, "previous", index, batch.interaction_column_start, "previous_row");
                    try writer.print("    delta{} = riscv_qm_add(riscv_qm_sub(delta{}, previous{}), riscv_load_qm31(relation_parameters, {}u));\n", .{ index, index, index, 4 * parameter });
                }
            },
            .independent_prefix_v1 => {
                try emitSecureLoad(writer, program, "previous", index, batch.interaction_column_start, "previous_row");
                try writer.print("    RiscvQm31 delta{} = riscv_qm_add(riscv_qm_sub(current{}, previous{}), riscv_qm_mul_base(riscv_load_qm31(relation_parameters, {}u), is_first));\n", .{ index, index, index, 4 * (parameter + index) });
            },
        }
        const first: usize = batch.first_entry;
        const numerator = program.entries[first].numerator;
        if (batch.entry_count > 2) {
            try emitWideFraction(writer, program, batch, index);
            try writer.print("    RiscvQm31 constraint{} = riscv_qm_sub(riscv_qm_mul(delta{}, wide_d{}), wide_n{});\n", .{ index, index, index, index });
        } else if (batch.entry_count == 1) {
            try writer.print("    RiscvQm31 constraint{} = riscv_qm_sub(riscv_qm_mul(delta{}, denominator{}), RiscvQm31{{ l{}, 0u, 0u, 0u }});\n", .{ index, index, first, numerator });
        } else {
            try writer.print("    RiscvQm31 constraint{} = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta{}, denominator{}), denominator{}), riscv_qm_mul_base(denominator{}, l{})), riscv_qm_mul_base(denominator{}, l{}));\n", .{ index, index, first, first + 1, first + 1, numerator, first, program.entries[first + 1].numerator });
        }
        try writer.print("    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, {}u), constraint{}));\n", .{ 4 * (program.batches.len - 1 - index), index });
    }
    try writer.writeAll(
        \\    uint denominator_index = row / (row_count / denominator_count);
        \\    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
        \\    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
        \\    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
        \\    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
        \\    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
        \\}
        \\
    );
}

/// Shared lowering for composition and interaction generation. Returns the
/// QM31 relation-parameter cursor immediately after the final entry's powers.
/// The caller admits the complete program before entering this emitter.
pub fn emitLookupTerms(allocator: std.mem.Allocator, writer: anytype, program: *const Program) !usize {
    var lookup_roots = std.ArrayList(u32).empty;
    defer lookup_roots.deinit(allocator);
    for (program.entries) |relation| {
        try lookup_roots.append(allocator, relation.numerator);
        try lookup_roots.appendSlice(allocator, relation.values[0..relation.arity]);
    }
    try emitNodes(allocator, writer, program, program.lookup_nodes, lookup_roots.items, "l", null);
    var parameter: usize = 0;
    for (program.entries, 0..) |relation, index| {
        try writer.print("    RiscvQm31 denominator{} = {{ 0u, 0u, 0u, 0u }};\n", .{index});
        for (relation.values[0..relation.arity], 0..) |root, coordinate| {
            try writer.print("    denominator{} = riscv_qm_add(denominator{}, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, {}u), l{}));\n", .{ index, index, 4 * (parameter + 1 + coordinate), root });
        }
        try writer.print("    denominator{} = riscv_qm_sub(denominator{}, riscv_load_qm31(relation_parameters, {}u));\n", .{ index, index, 4 * parameter });
        parameter += 1 + relation.arity;
    }
    return parameter;
}

fn emitSecureLoad(writer: anytype, program: *const Program, prefix: []const u8, index: usize, first: usize, row: []const u8) !void {
    try writer.print("    RiscvQm31 {s}{} = {{ ", .{ prefix, index });
    for (program.interaction_columns[first..][0..4], 0..) |column, coordinate| {
        if (coordinate != 0) try writer.writeAll(", ");
        try writer.print("tree{}[column_offsets[{}u] + {s}]", .{ column.tree_index, program.inputs.len + first + coordinate, row });
    }
    try writer.writeAll(" };\n");
}

fn emitNodes(allocator: std.mem.Allocator, writer: anytype, program: *const Program, nodes: []const Node, roots: []const u32, prefix: []const u8, total_roots: ?usize) !void {
    const reachable = try allocator.alloc(bool, nodes.len);
    defer allocator.free(reachable);
    @memset(reachable, false);
    for (roots) |root| reachable[root] = true;
    var cursor = nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
    for (nodes, 0..) |node, index| {
        if (!reachable[index]) continue;
        try writer.print("    uint {s}{} = ", .{ prefix, index });
        switch (node.op) {
            .constant => try writer.print("{}u", .{node.value}),
            .column => switch (program.inputs[node.value]) {
                .trace_column => |column| try writer.print("tree{}[column_offsets[{}u] + row]", .{ column.tree_index, node.value }),
                .profile_parameter => |parameter| try writer.print("profile_parameters[{}u]", .{parameter}),
            },
            .add, .sub, .mul => try writer.print("riscv_m31_{s}({s}{}, {s}{})", .{ @tagName(node.op), prefix, node.lhs, prefix, node.rhs }),
            .neg => try writer.print("riscv_m31_neg({s}{})", .{ prefix, node.lhs }),
        }
        try writer.writeAll(";\n");
        if (total_roots) |count| for (roots, 0..) |root, root_index| {
            if (root == index) try writer.print("    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, {}u), {s}{}));\n", .{ 4 * (count - 1 - root_index), prefix, root });
        };
    }
}

/// Wider batches use the same fraction sum for composition and interaction.
pub fn emitWideFraction(writer: anytype, program: *const Program, batch: anytype, index: usize) !void {
    const first: usize = batch.first_entry;
    try writer.print(" RiscvQm31 wide_n{} = {{l{},0u,0u,0u}}, wide_d{} = denominator{};\n", .{ index, program.entries[first].numerator, index, first });
    for (first + 1..first + batch.entry_count) |entry| {
        try writer.print(" wide_n{} = riscv_qm_add(riscv_qm_mul(wide_n{},denominator{}),riscv_qm_mul_base(wide_d{},l{}));\n", .{ index, index, entry, index, program.entries[entry].numerator });
        try writer.print(" wide_d{} = riscv_qm_mul(wide_d{},denominator{});\n", .{ index, index, entry });
    }
}
