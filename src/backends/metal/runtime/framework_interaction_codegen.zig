//! Independent-prefix interaction generation from admitted framework lookup DAGs.
//! Composition and interaction generation share tuple/numerator lowering. This
//! emits no AIR definition and never replaces typed padding by a row-count mask.
const std = @import("std");
const polynomial = @import("framework_polynomial_codegen.zig");
const field = @import("lookup_polynomial_codegen.zig");
pub const Entry = polynomial.Entry;
pub const version: u16 = 1;
pub const scan_source = @embedFile("framework_interaction_scan.metal");
pub const preamble = "#define STWO_ZIG_AMALGAMATED\n" ++
    @embedFile("../shaders/include/base.metal") ++
    @embedFile("../shaders/include/m31.metal") ++
    @embedFile("../shaders/include/extension_fields.metal") ++ field.preamble ++ scan_source;

pub fn validate(entry: Entry) !void {
    try polynomial.validate(entry);
    if (entry.program.layout != .independent_prefix_v1) return error.UnsupportedFrameworkInteractionLayout;
    // Interaction generation precedes Tree2 commitment; its relation inputs
    // must be supplied witness/profile words, never its own output columns.
    for (entry.program.inputs) |input| switch (input) {
        .trace_column => |column| if (column.tree_index > 1) return error.UnsupportedFrameworkInteractionInput,
        .profile_parameter => {},
    };
}

pub fn kernelName(allocator: std.mem.Allocator, entry: Entry) ![]u8 {
    var source = std.ArrayList(u8).empty;
    defer source.deinit(allocator);
    try emitKernel(allocator, source.writer(allocator), "framework_interaction_canonical", entry);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/metal/framework-interaction-codegen/v1\x00");
    hash.update(@embedFile("framework_interaction_codegen.zig"));
    hash.update(preamble);
    hash.update(source.items);
    return std.fmt.allocPrint(allocator, "stwo_zig_framework_interaction_v1_{s}", .{std.fmt.bytesToHex(hash.finalResult(), .lower)});
}

pub fn generateLibrary(allocator: std.mem.Allocator, entry: Entry) ![]u8 {
    const name = try kernelName(allocator, entry);
    defer allocator.free(name);
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(allocator);
    try source.appendSlice(allocator, preamble);
    try emitKernel(allocator, source.writer(allocator), name, entry);
    return source.toOwnedSlice(allocator);
}

/// Shared resident ABI: two immutable input arenas, explicit u64 offsets in
/// program-input order, canonical profile and per-entry relation words. Output
/// planes/claims remain private until the device status is checked by runtime.
pub fn emitKernel(allocator: std.mem.Allocator, writer: anytype, name: []const u8, entry: Entry) !void {
    try validate(entry);
    const program = entry.program;
    try writer.print(
        \\kernel void {s}(
        \\ device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
        \\ device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
        \\ device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
        \\ device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
        \\ uint row [[thread_position_in_grid]]) {{
        \\ if (row >= row_count) return;
        \\
    , .{name});
    const selector = program.is_first_input.?;
    try writer.print(" if (tree0[column_offsets[{}u]+row] != uint(row == 0u)) atomic_fetch_or_explicit(status, 2u, memory_order_relaxed);\n", .{selector});
    // All trace reads are already bounded by immutable runtime metadata.
    for (program.inputs, 0..) |input, index| switch (input) {
        .trace_column => |column| try writer.print(" if (tree{}[column_offsets[{}u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);\n", .{ column.tree_index, index }),
        .profile_parameter => {},
    };
    _ = try polynomial.emitLookupTerms(allocator, writer, program);
    for (program.batches, 0..) |batch, index| {
        const first = batch.first_entry;
        const second = first + 1;
        if (batch.entry_count == 1) {
            try writer.print(" RiscvQm31 n{} = {{l{},0u,0u,0u}}, d{} = denominator{};\n", .{ index, program.entries[first].numerator, index, first });
        } else {
            try writer.print(" RiscvQm31 n{} = riscv_qm_add(riscv_qm_mul_base(denominator{},l{}),riscv_qm_mul_base(denominator{},l{})), d{} = riscv_qm_mul(denominator{},denominator{});\n", .{ index, second, program.entries[first].numerator, first, program.entries[second].numerator, index, first, second });
        }
        try writer.print(" if ((d{}.a|d{}.b|d{}.c|d{}.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);\n", .{ index, index, index, index });
        try writer.print(" RiscvQm31 f{} = riscv_qm_mul(n{},framework_interaction_inverse(d{}));\n framework_interaction_store(output,row_count,{}u,row,f{});\n", .{ index, index, index, index, index });
    }
    try writer.writeAll("}\n");
}
