//! CUDA row emission for exact native projection graphs. No AIR equations live
//! here: the only operations are the authenticated graph's secure field ops.
const std = @import("std");
const P = @import("resident_native_projection_program_v1.zig");
const Shared = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const preamble = Shared.preamble;
pub const PARAMETER_COUNT = 3;
pub const Output = enum { roots, folded_quotient };
pub fn emit(a: std.mem.Allocator, writer: anytype, name: []const u8, p: *const P.Owned, output: Output) !void {
    _ = a;
    try p.validate();
    if (p.bindings.len != p.circuit.input_count or (output == .folded_quotient and p.mode != .equation)) return error.InvalidNativeProjectionProgram;
    if (name.len == 0) return error.InvalidNativeProjectionProgram;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidNativeProjectionProgram;
    try writer.print(
        \\extern "C" __global__ void {s}(const uint* main,const uint* witness,const uint* interaction,
        \\ const uint* parameters,uint* output,uint row_count,uint trace_rows,
        \\ const uint* powers,const uint* denominator_inverses,uint denominator_count){{
        \\ uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=row_count)return;
        \\ uint previous_row;
        \\ if(row_count==trace_rows){{
        \\  uint bits=uint(__ffs(row_count)-1),circle=__brev(row)>>(32u-bits);
        \\  uint logical=circle<row_count/2u?2u*circle:2u*(row_count-1u-circle)+1u;
        \\  uint prior=(logical+row_count-1u)&(row_count-1u);
        \\  uint prior_circle=(prior&1u)?row_count-1u-prior/2u:prior/2u;
        \\  previous_row=__brev(prior_circle)>>(32u-bits);
        \\ }}else previous_row=riscv_previous_circle_row(row,row_count,row_count/trace_rows);
        \\
    , .{name});
    var input: usize = 0;
    for (p.circuit.nodes, 0..) |node, index| {
        try writer.print("RiscvQm31 v{d}=", .{index});
        switch (node.op) {
            .input => {
                const binding = p.bindings[input];
                input += 1;
                switch (binding.kind) {
                    .main, .current, .previous => try writer.print("RiscvQm31{{{s}[ulong({d}u)*row_count+{s}],0u,0u,0u}}", .{
                        switch (binding.kind) {
                            .main => "main",
                            else => "interaction",
                        },
                        binding.index,
                        if (binding.kind == .previous) "previous_row" else "row",
                    }),
                    else => {
                        const offset: usize = switch (binding.kind) {
                            .z => 0,
                            .alpha => 1,
                            .normalized => 2,
                            else => unreachable,
                        };
                        try writer.print("riscv_load_qm31(parameters,{d}u)", .{4 * (offset + binding.index)});
                    },
                }
            },
            .constant => |words| try writer.print("RiscvQm31{{{d}u,{d}u,{d}u,{d}u}}", .{ words[0], words[1], words[2], words[3] }),
            .add, .sub, .mul => |operands| try writer.print("riscv_qm_{s}(v{d},v{d})", .{ @tagName(node.op), operands.lhs, operands.rhs }),
            .neg => |operand| try writer.print("riscv_qm_sub(RiscvQm31{{0u,0u,0u,0u}},v{d})", .{operand}),
            .inverse => return error.NonPolynomialNativeProjectionProgram,
        }
        try writer.writeAll(";\n");
    }
    switch (output) {
        .roots => for (p.circuit.outputs, 0..) |root, i| {
            inline for (.{ "a", "b", "c", "d" }, 0..) |limb, j| try writer.print("output[ulong({d}u)*row_count+row]=v{d}.{s};\n", .{ 4 * i + j, root, limb });
        },
        .folded_quotient => {
            try writer.writeAll("RiscvQm31 folded={0u,0u,0u,0u};\n");
            for (p.circuit.outputs, 0..) |root, i| try writer.print("folded=riscv_qm_add(folded,riscv_qm_mul(v{d},riscv_load_qm31(powers,{d}u)));\n", .{ root, 4 * (p.circuit.outputs.len - 1 - i) });
            try writer.writeAll("folded=riscv_qm_mul_base(folded,denominator_inverses[row/(row_count/denominator_count)]);\n");
            inline for (.{ "a", "b", "c", "d" }, 0..) |limb, i| try writer.print("output[ulong({d}u)*row_count+row]=folded.{s};\n", .{ i, limb });
        },
    }
    try writer.writeAll("}\n");
}
