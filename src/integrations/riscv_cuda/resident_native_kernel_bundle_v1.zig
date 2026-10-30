//! Finite native-program CUDA bundle. Each dispatch index is the independently
//! compiled original component's position; zero phase is interaction roots,
//! one phase is its original folded quotient. No component may be omitted.
const std = @import("std");
const Program = @import("resident_native_program_v1.zig");
const Direct = @import("resident_native_direct_codegen_v1.zig");
const Projection = @import("resident_native_projection_codegen_v1.zig");
const Access = @import("resident_native_access_codegen_v1.zig");
const PI = @import("resident_native_projection_interaction_v1.zig");
const AI = @import("resident_native_access_interaction_v1.zig");
const Scan = @import("../../backends/cuda/framework_interaction_codegen_v1.zig");
const Counter = @import("resident_native_projection_counter_v1.zig");
const R = @import("../../frontends/riscv/recursion/air/composition_graph_recorder.zig");

fn infrastructure(writer: anytype, name: []const u8, c: *const Program.Component, graph: *const R.Circuit) !void {
    const expected = c.main_width + @as(usize, if (c.kind == .frame) 2 else 1);
    if (graph.input_count != expected or graph.outputs.len != c.constraints) return error.InvalidNativeInfrastructureKernel;
    try graph.validate();
    try writer.print("extern \"C\" __global__ void {s}(const uint*fixed,const uint*main,const uint*interaction,const uint*powers,uint*output,uint rows,const uint*denominators,uint denominator_count){{uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;\n", .{name});
    var input: usize = 0;
    for (graph.nodes, 0..) |node, i| {
        try writer.print("RiscvQm31 v{d}=", .{i});
        switch (node.op) {
            .input => {
                if (c.kind == .frame and input == 0 or c.kind == .clock and input == c.main_width)
                    try writer.writeAll("RiscvQm31{fixed[row],0,0,0}")
                else if (c.kind == .frame and input == expected - 1)
                    try writer.writeAll("RiscvQm31{interaction[row],0,0,0}")
                else
                    try writer.print("RiscvQm31{{main[ulong({d})*rows+row],0,0,0}}", .{input - @intFromBool(c.kind == .frame)});
                input += 1;
            },
            .constant => |v| try writer.print("RiscvQm31{{{d}u,{d}u,{d}u,{d}u}}", .{ v[0], v[1], v[2], v[3] }),
            .add, .sub, .mul => |v| try writer.print("riscv_qm_{s}(v{d},v{d})", .{ @tagName(node.op), v.lhs, v.rhs }),
            .neg => |v| try writer.print("riscv_qm_sub(RiscvQm31{{0,0,0,0}},v{d})", .{v}),
            .inverse => return error.NonPolynomialNativeInfrastructure,
        }
        try writer.writeAll(";\n");
    }
    try writer.writeAll("RiscvQm31 folded={0,0,0,0};\n");
    for (graph.outputs, 0..) |root, i| try writer.print("folded=riscv_qm_add(folded,riscv_qm_mul(v{d},riscv_load_qm31(powers,{d}u)));\n", .{ root, 4 * (graph.outputs.len - 1 - i) });
    try writer.writeAll("folded=riscv_qm_mul_base(folded,denominators[row/(rows/denominator_count)]);output[row]=folded.a;output[rows+row]=folded.b;output[2ul*rows+row]=folded.c;output[3ul*rows+row]=folded.d;}\n");
}

/// The neutral-identity CUDA source covers every emitted body, public constant
/// and dispatch entry, while excluding request-only statement/epoch identity.
pub fn codeIdentity(comptime N: usize, a: std.mem.Allocator, owned: *const Program.ForCommitments(N).Owned) ![32]u8 {
    var source = std.Io.Writer.Allocating.init(a);
    defer source.deinit();
    try emitWithIdentity(N, a, &source.writer, owned, @splat(0));
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-zig/native-cuda/exact-code/v1\x00");
    h.update(source.written());
    return h.finalResult();
}
pub fn emit(comptime N: usize, a: std.mem.Allocator, writer: anytype, owned: *const Program.ForCommitments(N).Owned) !void {
    const identity = try codeIdentity(N, a, owned);
    if (!std.mem.eql(u8, &identity, &owned.view().code_identity)) return error.MutatedNativeDeviceCode;
    return emitWithIdentity(N, a, writer, owned, identity);
}
fn emitWithIdentity(comptime N: usize, a: std.mem.Allocator, writer: anytype, owned: *const Program.ForCommitments(N).Owned, code_identity: [32]u8) !void {
    const data = owned.view();
    if (data.components.len == 0 or data.components.len > 65536) return error.InvalidNativeKernelInventory;
    try writer.writeAll("#include <cuda_runtime.h>\n");
    try writer.writeAll(Direct.preamble);
    // Reuse exact resident powers/add helpers; native linking needs no parent
    // profile-specific utility object or duplicate implementation.
    try writer.writeAll(@embedFile("resident_parent_framework_util_v1.cuh"));
    try PI.emit(writer);
    var interaction: std.Io.Writer.Allocating = .init(a);
    defer interaction.deinit();
    try AI.emit(&interaction.writer);
    if (!std.mem.startsWith(u8, interaction.written(), Scan.helper_source)) return error.InvalidNativeKernelPreamble;
    try writer.writeAll(interaction.written()[Scan.helper_source.len..]);
    for (data.components, 0..) |*c, i| {
        const equation = try std.fmt.allocPrint(a, "native_component_{d}_equation", .{i});
        defer a.free(equation);
        const fraction = try std.fmt.allocPrint(a, "native_component_{d}_fractions", .{i});
        defer a.free(fraction);
        switch (c.program) {
            .opcode => |*p| try Direct.emit(a, writer, equation, p),
            .clock, .frame => |*p| try infrastructure(writer, equation, c, p),
            .projection => |*p| {
                try Projection.emit(a, writer, fraction, &p.fractions, .roots);
                try Projection.emit(a, writer, equation, &p.equation, .folded_quotient);
            },
            .access => |*p| {
                try Access.emit(a, writer, fraction, &p.denominators, .roots);
                try Access.emit(a, writer, equation, &p.equations, .folded_quotient);
            },
        }
    }
    try writer.writeAll(
        \\extern "C" int stwo_native_program_on(uint component,uint phase,const uint*fixed,const uint*main,const uint*witness,const uint*interaction,const uint*parameters,const ulong*offsets,const uint*powers,uint*output,uint rows,uint trace_rows,const uint*denominators,uint denominator_count,void*stream){
        \\ if(phase>1u||!main||!output||rows<2u||rows>(1u<<28)||(rows&(rows-1u))||trace_rows<2u||trace_rows>rows||(trace_rows&(trace_rows-1u)))return int(cudaErrorInvalidValue);
        \\ if(phase&&(!powers||!denominators||!denominator_count||denominator_count>rows||rows%denominator_count))return int(cudaErrorInvalidValue);
        \\ cudaStream_t s=static_cast<cudaStream_t>(stream);dim3 grid((rows+127u)/128u),block(128);switch(component){
        \\
    );
    for (data.components, 0..) |c, i| {
        try writer.print("case {d}:\n", .{i});
        switch (c.kind) {
            .opcode => try writer.print("if(!phase||!fixed||!offsets)return int(cudaErrorInvalidValue);native_component_{d}_equation<<<grid,block,0,s>>>(fixed,main,offsets,powers,output,rows,denominators,denominator_count);break;\n", .{i}),
            .clock, .frame => try writer.print("if(!phase||!fixed||!interaction)return int(cudaErrorInvalidValue);native_component_{d}_equation<<<grid,block,0,s>>>(fixed,main,interaction,powers,output,rows,denominators,denominator_count);break;\n", .{i}),
            .projection, .access => {
                try writer.print("if(!parameters||{s})return int(cudaErrorInvalidValue);if(phase)native_component_{d}_equation<<<grid,block,0,s>>>(main,witness,interaction,parameters,output,rows,trace_rows,powers,denominators,denominator_count);else native_component_{d}_fractions<<<grid,block,0,s>>>(main,witness,interaction,parameters,output,rows,trace_rows,powers,denominators,denominator_count);break;\n", .{ if (c.kind == .access) "!witness||(phase&&!interaction)" else "phase&&!interaction", i, i });
            },
        }
    }
    try writer.writeAll("default:return int(cudaErrorInvalidValue);}return int(cudaGetLastError());}\nextern \"C\" void stwo_native_code_identity(unsigned char*out){const unsigned char identity[32]={");
    for (code_identity, 0..) |value, i| try writer.print("{s}{d}", .{ if (i == 0) "" else ",", value });
    try writer.writeAll("};for(unsigned i=0;i<32;i++)out[i]=identity[i];}\n");
    for (data.components, 0..) |*c, i| if (c.kind == .projection) {
        _ = Counter.kind(c.program.projection.fractions.slot) catch continue;
        var p = try Counter.Owned.init(a, c.program.projection.fractions.slot);
        defer p.deinit();
        const name = try std.fmt.allocPrint(a, "native_component_{d}_counter", .{i});
        defer a.free(name);
        try Counter.emit(writer, name, &p);
    };
    try writer.writeAll("extern \"C\" int stwo_native_table_counts_on(uint component,const uint*main,uint*counter,uint rows,uint*status,void*stream){if(!main||!counter||!status||rows<2u||rows>(1u<<24)||(rows&(rows-1u)))return int(cudaErrorInvalidValue);cudaStream_t s=static_cast<cudaStream_t>(stream);switch(component){\n");
    for (data.components, 0..) |c, i| if (c.kind == .projection) {
        _ = Counter.kind(c.program.projection.fractions.slot) catch continue;
        try writer.print("case {d}:native_component_{d}_counter<<<(rows+127u)/128u,128,0,s>>>(main,counter,rows,status);break;\n", .{ i, i });
    };
    try writer.writeAll("default:return int(cudaErrorInvalidValue);}return int(cudaGetLastError());}\n");
}
