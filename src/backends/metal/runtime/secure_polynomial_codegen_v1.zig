//! Real QM31 device equations/fractions lowered from authenticated typed AIR.
//! The polynomial dispatch reuses a buffer ABI, never the old framework AIR.
const std = @import("std");
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v1;
const interaction = @import("framework_interaction_codegen.zig");
pub const VERSION: u16 = 1;
pub const MAX_ENTRIES = 16;
pub const mean_symbol = "stwo_zig_secure_interaction_mean_v1";
pub const scan_symbols = [_][]const u8{ "stwo_zig_framework_interaction_block_scan_v1", "stwo_zig_framework_interaction_scan_blocks_v1", "stwo_zig_framework_interaction_finalize_v1", mean_symbol };
pub const mean_source = @embedFile("secure_interaction_mean_v1.metal");
pub const witness_symbols = [_][]const u8{ "stwo_zig_word_memory_witness_v4", "stwo_zig_range16_witness_v4", "stwo_zig_range16_inverse_table_v1", "stwo_zig_ram_lanes_witness_v1" };
pub const witness_source = @embedFile("word_memory_witness_v4.metal");
pub const lane_witness_source = @embedFile("ram_lanes_witness_v1.metal");
pub const preamble = interaction.preamble ++ mean_source ++ witness_source ++ lane_witness_source;

pub fn identity(program: *const ir.Program) ![32]u8 {
    try program.validate();
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/metal/secure-polynomial/v1\x00");
    h.update(&program.identity);
    h.update(&@import("stwo_prover_engine").air.secure_polynomial_emitter_v1.fingerprint());
    h.update(@embedFile("secure_polynomial_codegen_v1.zig"));
    h.update(preamble);
    return h.finalResult();
}
pub fn kernelName(a: std.mem.Allocator, program: *const ir.Program) ![]u8 {
    return std.fmt.allocPrint(a, "{s}{s}", .{ if (ir.isFraction(program.kind)) "stwo_zig_secure_interaction_v1_" else "stwo_zig_framework_poly_v1_", std.fmt.bytesToHex(try identity(program), .lower) });
}
pub fn generateLibrary(a: std.mem.Allocator, programs: []const *const ir.Program) ![]u8 {
    if (programs.len == 0 or programs.len > MAX_ENTRIES) return error.InvalidSecureKernelCatalog;
    var source = std.ArrayList(u8).empty;
    errdefer source.deinit(a);
    const w = source.writer(a);
    try w.writeAll(preamble);
    var seen: [MAX_ENTRIES][32]u8 = undefined;
    var count: usize = 0;
    for (programs) |program| {
        const id = try identity(program);
        var duplicate = false;
        for (seen[0..count]) |prior| if (std.mem.eql(u8, &prior, &id)) {
            duplicate = true;
            break;
        };
        if (duplicate) continue;
        seen[count] = id;
        count += 1;
        const name = try kernelName(a, program);
        defer a.free(name);
        try emitKernel(w, name, program);
    }
    return source.toOwnedSlice(a);
}
pub fn emitKernel(w: anytype, name: []const u8, program: *const ir.Program) !void {
    try program.validate();
    const fractions = ir.isFraction(program.kind);
    if (fractions) {
        try w.print(
            \\kernel void {s}(device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
            \\ device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
            \\ device const uint *reserved [[buffer(4)]], device uint *output [[buffer(5)]],
            \\ device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]], device const uint *range_inverses [[buffer(8)]], uint row [[thread_position_in_grid]]) {{
            \\ if (row >= row_count) return;
            \\ uint bits = ctz(row_count), circle = riscv_bit_reverse(row, bits);
            \\ uint logical = circle < row_count/2u ? 2u*circle : 2u*(row_count-1u-circle)+1u;
            \\ uint previous_logical = (logical+row_count-1u)%row_count;
            \\ uint previous_row = framework_interaction_row(previous_logical,row_count);
            \\
        , .{name});
    } else {
        try w.print(
            \\kernel void {s}(device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]], device const uint *tree2 [[buffer(2)]],
            \\ device const ulong *column_offsets [[buffer(3)]], device const uint *profile_parameters [[buffer(4)]], device const uint *reserved [[buffer(5)]],
            \\ device const uint *powers [[buffer(6)]], device uint *output [[buffer(7)]], constant uint &row_count [[buffer(8)]],
            \\ constant uint *denominator_inverses [[buffer(9)]], constant uint &denominator_count [[buffer(10)]], uint row [[thread_position_in_grid]]) {{
            \\ if (row >= row_count) return;
            \\ uint previous_row = riscv_previous_circle_row(row,row_count,denominator_count);
            \\
        , .{name});
    }
    try emitNodes(w, program);
    if (fractions) {
        for (program.roots, 0..) |root, batch| try w.print(" framework_interaction_store(output,row_count,{}u,row,v{});\n", .{ batch, root });
    } else {
        try w.writeAll(" RiscvQm31 folded={0u,0u,0u,0u};\n");
        for (program.roots, 0..) |root, i| try w.print(" folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,{}u),v{}));\n", .{ 4 * (program.roots.len - 1 - i), root });
        try w.writeAll(
            \\ RiscvQm31 result=riscv_qm_mul_base(folded,denominator_inverses[row/(row_count/denominator_count)]);
            \\ output[ulong(row)]=riscv_m31_add(output[ulong(row)],result.a);
            \\ output[ulong(row_count)+row]=riscv_m31_add(output[ulong(row_count)+row],result.b);
            \\ output[2ul*row_count+row]=riscv_m31_add(output[2ul*row_count+row],result.c);
            \\ output[3ul*row_count+row]=riscv_m31_add(output[3ul*row_count+row],result.d);
            \\
        );
    }
    try w.writeAll("}\n");
}

pub const emitNodes = @import("stwo_prover_engine").air.secure_polynomial_emitter_v1.emitNodes;
