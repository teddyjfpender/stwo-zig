//! CUDA kernels from the same typed secure DAG. Strict AOT runtime/product
//! registry admission is a separate integration step; this emits real device
//! equations, not a CPU fallback or a claim of hardware execution.
const std = @import("std");
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v1;
const lowering = @import("stwo_prover_engine").air.secure_polynomial_emitter_v1;
pub const MAX_ENTRIES = 16;
pub const preamble = @embedFile("native/secure_polynomial_v1.cuh");
pub fn identity(program: *const ir.Program) ![32]u8 {
    try program.validate();
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/cuda/secure-polynomial/v1\x00");
    h.update(&program.identity);
    h.update(@embedFile("secure_polynomial_codegen_v1.zig"));
    h.update(preamble);
    h.update(@embedFile("native/oods/field.cuh"));
    // Shared instruction emitter bytes are part of executable authentication.
    h.update(&lowering.fingerprint());
    return h.finalResult();
}
pub fn kernelName(a: std.mem.Allocator, program: *const ir.Program) ![]u8 {
    return std.fmt.allocPrint(a, "stwo_cuda_secure_v1_{s}", .{std.fmt.bytesToHex(try identity(program), .lower)});
}
pub fn generateLibrary(a: std.mem.Allocator, programs: []const *const ir.Program) ![]u8 {
    if (programs.len == 0 or programs.len > MAX_ENTRIES) return error.InvalidSecureKernelCatalog;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(a);
    const w = out.writer(a);
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
        try w.print(
            \\extern "C" __global__ void {s}(const uint *tree0,const uint *tree1,const uint *tree2,
            \\ const ulong *column_offsets,const uint *profile_parameters,const uint *powers,
            \\ uint *output,uint *status,uint row_count,const uint *denominator_inverses,uint denominator_count,const uint *range_inverses) {{
            \\ uint row=blockIdx.x*blockDim.x+threadIdx.x;
            \\ if(row>=row_count) return;
            \\
        , .{name});
        if (ir.isFraction(program.kind)) try w.writeAll(
            \\ uint circle=riscv_bit_reverse(row,ctz(row_count));
            \\ uint logical=circle<row_count/2u?2u*circle:2u*(row_count-1u-circle)+1u;
            \\ uint previous_row=framework_interaction_row((logical+row_count-1u)%row_count,row_count);
            \\
        ) else try w.writeAll(" uint previous_row=riscv_previous_circle_row(row,row_count,denominator_count);\n");
        try lowering.emitNodes(w, program);
        if (ir.isFraction(program.kind)) {
            for (program.roots, 0..) |root, batch| try w.print(" framework_interaction_store(output,row_count,{}u,row,v{});\n", .{ batch, root });
        } else {
            try w.writeAll(" RiscvQm31 folded={0u,0u,0u,0u};\n");
            for (program.roots, 0..) |root, i| try w.print(" folded=riscv_qm_add(folded,riscv_qm_mul(riscv_load_qm31(powers,{}u),v{}));\n", .{ 4 * (program.roots.len - 1 - i), root });
            try w.writeAll(
                \\ RiscvQm31 result=riscv_qm_mul_base(folded,denominator_inverses[row/(row_count/denominator_count)]);
                \\ output[row]=riscv_m31_add(output[row],result.a);
                \\ output[ulong(row_count)+row]=riscv_m31_add(output[ulong(row_count)+row],result.b);
                \\ output[2ull*row_count+row]=riscv_m31_add(output[2ull*row_count+row],result.c);
                \\ output[3ull*row_count+row]=riscv_m31_add(output[3ull*row_count+row],result.d);
                \\
            );
        }
        try w.writeAll("}\n");
    }
    return out.toOwnedSlice(a);
}
