//! Metal source for the authenticated recursive framework polynomial contract.
//!
//! No AIR is transcribed here: direct roots and relation tuple expressions come
//! from the shared program. This generator owns only the versioned framework
//! recurrence and its resident-buffer ABI. Runtime integration/device parity
//! are separate gates; emitting source is not evidence of GPU execution.
const std = @import("std");
const component = @import("stwo_prover_engine").air.component_prover;
const field_codegen = @import("lookup_polynomial_codegen.zig");
const Program = component.OwnedFrameworkPolynomialProgramV1;
const Node = component.BasePolynomialNode;

pub const codegen_version: u16 = 3;
pub const identity_domain = "stwo/metal/framework-polynomial-codegen/v3\x00";
// Codegen v3 retains the v1 buffer ABI; layout selects the claim payload. Exact emitter/helper bytes additionally
// invalidate cached kernels when a source change accidentally omits a bump.
const emitter_source = @embedFile("framework_polynomial_codegen.zig");

pub const Entry = struct {
    program: *const Program,
    tree_column_counts: []const usize,
};

/// Cold admission checks actual tree geometry and the immutable program seal.
/// Invocation offsets still must be checked against actual resident buffers.
pub fn validate(entry: Entry) !void {
    try entry.program.validate(entry.tree_column_counts);
    for (entry.program.inputs) |input| switch (input) {
        .trace_column => |column| if (column.tree_index > 2) return error.UnsupportedFrameworkPolynomialTree,
        .profile_parameter => {},
    };
    for (entry.program.interaction_columns) |column|
        if (column.tree_index > 2) return error.UnsupportedFrameworkPolynomialTree;
}

/// Kernel identity binds executable equations, not their physical placement.
/// emitKernel still validates the complete placement-bound program before
/// producing the canonical body. The original program seal remains unchanged
/// and must be retained separately by runtime job admission.
pub fn codegenIdentity(allocator: std.mem.Allocator, entry: Entry) ![32]u8 {
    var canonical = std.ArrayList(u8).empty;
    defer canonical.deinit(allocator);
    try emitKernel(allocator, canonical.writer(allocator), "stwo_framework_canonical", entry);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    var version: [2]u8 = undefined;
    std.mem.writeInt(u16, &version, codegen_version, .little);
    hash.update(&version);
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(emitter_source, &source_digest, .{});
    hash.update(&source_digest);
    std.crypto.hash.sha2.Sha256.hash(field_codegen.preamble, &source_digest, .{});
    hash.update(&source_digest);
    std.crypto.hash.sha2.Sha256.hash(canonical.items, &source_digest, .{});
    hash.update(&source_digest);
    return hash.finalResult();
}

pub fn kernelName(allocator: std.mem.Allocator, entry: Entry) ![]u8 {
    return nameForIdentity(allocator, try codegenIdentity(allocator, entry));
}

fn nameForIdentity(allocator: std.mem.Allocator, identity: [32]u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "stwo_zig_framework_poly_v1_{s}", .{
        std.fmt.bytesToHex(identity, .lower),
    });
}

pub fn generateLibrary(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    if (entries.len == 0) return error.InvalidFrameworkPolynomialProgram;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    var emitted = std.AutoHashMap([32]u8, void).init(allocator);
    defer emitted.deinit();
    const writer = source.writer(allocator);
    try writer.writeAll(field_codegen.preamble);
    for (entries) |entry| {
        // Admission precedes deduplication: an invalid relocated entry cannot
        // borrow admission from another job with the same executable body.
        const identity = try codegenIdentity(allocator, entry);
        const slot = try emitted.getOrPut(identity);
        if (slot.found_existing) continue;
        const name = try nameForIdentity(allocator, identity);
        defer allocator.free(name);
        try emitKernel(allocator, writer, name, entry);
    }
    return source.toOwnedSlice(allocator);
}

/// Resident ABI, all offsets measured in M31 words:
/// 0..2: already expanded PCS tree arenas; 3: u64 column offsets in program
/// input order followed by interaction-column order (parameter slots unused);
/// 4: profile M31 parameters; 5: relation QM31 words, followed by the derived
/// claimedSumShift() for same-row-prefix or per-batch claims for independent
/// prefixes; 6: QM31 coefficient powers for this whole component;
/// 7: additive secure output; 8..10: evaluation rows and vanishing inverses.
///
/// Runtime must bind parameters.trace_log_size to admitted geometry, derive the
/// shift, validate every offset/extent and supply the correctly shifted global
/// coefficient window. Values and parameters never enter kernel identity.
pub fn emitKernel(allocator: std.mem.Allocator, writer: anytype, name: []const u8, entry: Entry) !void {
    try validate(entry);
    const program = entry.program;
    try writer.print(
        \\kernel void {s}(
        \\    device const uint *tree0 [[buffer(0)]],
        \\    device const uint *tree1 [[buffer(1)]],
        \\    device const uint *tree2 [[buffer(2)]],
        \\    device const ulong *column_offsets [[buffer(3)]],
        \\    device const uint *profile_parameters [[buffer(4)]],
        \\    device const uint *relation_parameters [[buffer(5)]],
        \\    device const uint *powers [[buffer(6)]],
        \\    device uint *output [[buffer(7)]],
        \\    constant uint &row_count [[buffer(8)]],
        \\    constant uint *denominator_inverses [[buffer(9)]],
        \\    constant uint &denominator_count [[buffer(10)]],
        \\    uint row [[thread_position_in_grid]]) {{
        \\    if (row >= row_count) return;
        \\    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
        \\    RiscvQm31 folded = {{ 0u, 0u, 0u, 0u }};
        \\
    , .{name});
    const total_roots = program.direct.roots.len + program.batches.len;
    try emitNodes(allocator, writer, program, program.direct.nodes, program.direct.roots, "d", total_roots);

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
        if (batch.entry_count == 1) {
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
