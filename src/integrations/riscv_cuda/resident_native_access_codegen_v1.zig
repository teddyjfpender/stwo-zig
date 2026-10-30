//! CUDA row emission for exact native access graphs. No AIR equations live
//! here: the only operations are the authenticated graph's secure field ops.
const std = @import("std");
const P = @import("resident_native_access_program_v1.zig");
const Shared = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const preamble = Shared.preamble;
pub const Output = enum { roots, folded_quotient };
pub fn emit(a: std.mem.Allocator, writer: anytype, name: []const u8, p: *const P.Owned, output: Output) !void {
    _ = a;
    try p.validate();
    if (p.bindings.len != p.circuit.input_count or (output == .folded_quotient and p.mode != .equations)) return error.InvalidNativeAccessProgram;
    if (name.len == 0) return error.InvalidNativeAccessProgram;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidNativeAccessProgram;
    try writer.print(
        \\extern "C" __global__ void {s}(const uint* main,const uint* witness,const uint* interaction,
        \\ const uint* parameters,uint* output,uint row_count,uint trace_rows,
        \\ const uint* powers,const uint* denominator_inverses,uint denominator_count){{
        \\ uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=row_count)return;
        \\ uint previous_row=riscv_previous_circle_row(row,row_count,row_count/trace_rows);
        \\ if(row_count==trace_rows){{uint bits=__ffs(row_count)-1u;uint circle=__brev(row)>>(32u-bits);uint logical=circle<row_count/2u?2u*circle:2u*(row_count-1u-circle)+1u;uint prior=(logical+row_count-1u)&(row_count-1u);uint pc=(prior&1u)?row_count-1u-prior/2u:prior/2u;previous_row=__brev(pc)>>(32u-bits);}}
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
                    .main, .witness, .current, .previous => try writer.print("RiscvQm31{{{s}[ulong({d}u)*row_count+{s}],0u,0u,0u}}", .{
                        switch (binding.kind) {
                            .main => "main",
                            .witness => "witness",
                            else => "interaction",
                        },
                        binding.index,
                        if (binding.kind == .previous) "previous_row" else "row",
                    }),
                    else => {
                        const offset: usize = switch (binding.kind) {
                            .clock => 0,
                            .transition => 8,
                            .range => 20,
                            .memory => 23,
                            .normalized => 31,
                            else => unreachable,
                        };
                        try writer.print("riscv_load_qm31(parameters,{d}u)", .{4 * (offset + binding.index)});
                    },
                }
            },
            .constant => |words| try writer.print("RiscvQm31{{{d}u,{d}u,{d}u,{d}u}}", .{ words[0], words[1], words[2], words[3] }),
            .add, .sub, .mul => |operands| try writer.print("riscv_qm_{s}(v{d},v{d})", .{ @tagName(node.op), operands.lhs, operands.rhs }),
            .neg => |operand| try writer.print("riscv_qm_sub(RiscvQm31{{0u,0u,0u,0u}},v{d})", .{operand}),
            .inverse => return error.NonPolynomialNativeAccessProgram,
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

pub fn exportOracle(a: std.mem.Allocator, path: []const u8) !void {
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    const w = &source.writer;
    try w.writeAll("#include <cuda_runtime.h>\n#include <cstdio>\n#include <cstdlib>\n#include <vector>\n");
    try w.writeAll(preamble);
    for ([_]u8{ 1, 2 }) |slot| for ([_]P.Mode{ .equations, .denominators }) |mode| {
        var p = try P.Owned.init(a, slot, mode);
        defer p.deinit();
        const name = try std.fmt.allocPrint(a, "native_access_{d}_{s}", .{ slot, @tagName(mode) });
        defer a.free(name);
        try emit(a, w, name, &p, .roots);
    };
    try w.writeAll("#define CHECK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,\"CUDA %s line %d\\n\",cudaGetErrorString(e),__LINE__);return 2;}}while(0)\nint main(){unsigned words=0;\n");
    for ([_]u8{ 1, 2 }) |slot| for ([_]P.Mode{ .equations, .denominators }) |mode| for ([_]u32{ 1, 2, 3 }) |trace_log| {
        const roots: usize = if (mode == .equations) 68 else 18;
        const expected = try a.alloc(u32, roots * 4 * 8);
        defer a.free(expected);
        for (0..8) |row| {
            var inputs: P.Inputs(Q) = undefined;
            const previous = core.utils.previousBitReversedCircleDomainIndex(row, trace_log, 3);
            for (&inputs.main, 0..) |*out, col| out.* = Q.fromBase(M.fromU64(col * 13 + row * 19 + 7));
            for (&inputs.witness, 0..) |*out, col| out.* = Q.fromBase(M.fromU64(col * 23 + row * 29 + 11));
            for (&inputs.current, &inputs.previous, 0..) |*out, *prior, col| {
                out.* = Q.fromBase(M.fromU64(col * 31 + row * 37 + 17));
                prior.* = Q.fromBase(M.fromU64(col * 31 + previous * 37 + 17));
            }
            var cursor: usize = 0;
            inline for (.{ "clock", "transition", "range", "memory", "normalized" }) |field| for (&@field(inputs, field)) |*out| {
                const offset = cursor * 4;
                out.* = Q.fromM31Array(.{ M.fromU64(offset * 41 + 43), M.fromU64((offset + 1) * 41 + 43), M.fromU64((offset + 2) * 41 + 43), M.fromU64((offset + 3) * 41 + 43) });
                cursor += 1;
            };
            switch (mode) {
                .equations => for (try P.equations(Q, slot, &inputs), 0..) |value, i| {
                    for (value.toM31Array(), 0..) |limb, j| expected[(4 * i + j) * 8 + row] = limb.toU32();
                },
                .denominators => for (try P.denominators(Q, slot, &inputs), 0..) |value, i| {
                    for (value.toM31Array(), 0..) |limb, j| expected[(4 * i + j) * 8 + row] = limb.toU32();
                },
            }
        }
        try w.print("{{constexpr unsigned width={d},outwords={d};std::vector<uint> main(width*8),witness(48*8),interaction(49*8),parameters({d}),out(outwords);\n", .{ P.MAIN_COUNT, expected.len, P.PARAMETER_COUNT * 4 });
        try w.writeAll("for(unsigned c=0;c<width;c++)for(unsigned r=0;r<8;r++)main[c*8+r]=c*13+r*19+7;for(unsigned c=0;c<48;c++)for(unsigned r=0;r<8;r++)witness[c*8+r]=c*23+r*29+11;for(unsigned c=0;c<49;c++)for(unsigned r=0;r<8;r++)interaction[c*8+r]=c*31+r*37+17;for(unsigned i=0;i<parameters.size();i++)parameters[i]=i*41+43;const uint expected[]={");
        for (expected, 0..) |value, i| try w.print("{s}{d}u", .{ if (i == 0) "" else ",", value });
        try w.writeAll("};uint *dm,*dw,*di,*dp,*dout;CHECK(cudaMalloc(&dm,main.size()*4));CHECK(cudaMalloc(&dw,witness.size()*4));CHECK(cudaMalloc(&di,interaction.size()*4));CHECK(cudaMalloc(&dp,parameters.size()*4));CHECK(cudaMalloc(&dout,outwords*4));CHECK(cudaMemcpy(dm,main.data(),main.size()*4,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(dw,witness.data(),witness.size()*4,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(di,interaction.data(),interaction.size()*4,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(dp,parameters.data(),parameters.size()*4,cudaMemcpyHostToDevice));\n");
        try w.print("native_access_{d}_{s}<<<1,32>>>(dm,dw,di,dp,dout,8,{d},nullptr,nullptr,1);CHECK(cudaGetLastError());CHECK(cudaMemcpy(out.data(),dout,outwords*4,cudaMemcpyDeviceToHost));for(unsigned i=0;i<outwords;i++)if(out[i]!=expected[i]){{fprintf(stderr,\"FAIL slot={d} mode={s} trace={d} word=%u got=%u expected=%u\\n\",i,out[i],expected[i]);return 3;}}words+=outwords;\n", .{ slot, @tagName(mode), @as(u32, 1) << @intCast(trace_log), slot, @tagName(mode), trace_log });
        try w.writeAll("CHECK(cudaFree(dm));CHECK(cudaFree(dw));CHECK(cudaFree(di));CHECK(cudaFree(dp));CHECK(cudaFree(dout));}\n");
    };
    try w.writeAll("printf(\"PASS native access GPU bothslots all68roots17denominators words=%u\\n\",words);return 0;}\n");
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(source.written());
}
