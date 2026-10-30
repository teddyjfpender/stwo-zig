//! One exact physical prefix per admitted projection. Fractions and buffers
//! are device-resident; the four-word claim remains device-resident too.
const std = @import("std");
const Scan = @import("../../backends/cuda/framework_interaction_codegen_v1.zig");
pub const Layout = struct {
    rows: u32,
    fraction_words: usize,
    output_words: usize,
    sum_words: usize,
    total_bytes: usize,
    pub fn init(log: u32, cap: usize) !Layout {
        if (log < 1 or log > 24) return error.InvalidNativeProjectionDomain;
        const rows: usize = @as(usize, 1) << @intCast(log);
        const fraction = 8 * rows;
        const output = 4 * rows + 4;
        const sums = 4 * ((rows + 255) / 256);
        const bytes = try std.math.mul(usize, fraction + output + sums + 1, 4);
        if (bytes > cap) return error.NativeProjectionResourceLimit;
        return .{ .rows = @intCast(rows), .fraction_words = fraction, .output_words = output, .sum_words = sums, .total_bytes = bytes };
    }
};
pub fn emit(writer: anytype) !void {
    try writer.writeAll(Scan.helper_source);
    try writer.writeAll(
        \\__global__ void native_projection_fraction_rows(const uint* fractions,uint*output,uint*status,uint rows){
        \\ uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;
        \\ RiscvQm31 n=framework_load(fractions,rows,0,row),d=framework_load(fractions,rows,1,row);
        \\ if(n.a>=0x7fffffffu||n.b>=0x7fffffffu||n.c>=0x7fffffffu||n.d>=0x7fffffffu||d.a>=0x7fffffffu||d.b>=0x7fffffffu||d.c>=0x7fffffffu||d.d>=0x7fffffffu){atomicOr(status,1u);return;}
        \\ if(!(d.a|d.b|d.c|d.d)){atomicOr(status,2u);return;}
        \\ framework_store(output,rows,0,row,riscv_qm_mul(n,framework_inverse(d)));
        \\}
        \\
    );
    // Select the exact Universal47 pair and normalize this physical claim on
    // device. The optional null claim is only the pre-interaction phase; it
    // sets normalized=0 while preserving the same z/alpha inputs.
    try writer.writeAll(
        \\__global__ void native_projection_parameters(const uint*draws,uint domain,const uint*claim,uint rows,uint*parameters,uint*status){
        \\ if(blockIdx.x||threadIdx.x)return;
        \\ for(uint i=0;i<8u;i++){uint v=draws[8u*domain+i];if(v>=0x7fffffffu){atomicOr(status,4u);return;}parameters[i]=v;}
        \\ RiscvQm31 value=claim?riscv_load_qm31(claim,0u):RiscvQm31{0u,0u,0u,0u};
        \\ if(value.a>=0x7fffffffu||value.b>=0x7fffffffu||value.c>=0x7fffffffu||value.d>=0x7fffffffu){atomicOr(status,8u);return;}
        \\ value=riscv_qm_mul_base(value,1u<<(31u-uint(__ffs(rows)-1)));
        \\ parameters[8]=value.a;parameters[9]=value.b;parameters[10]=value.c;parameters[11]=value.d;
        \\}
        \\extern "C" int stwo_native_projection_parameters_on(const uint*draws,uint draw_words,uint domain,const uint*claim,uint rows,uint*parameters,uint*status,void*stream){
        \\ if(!draws||!parameters||!status||draw_words<376u||domain>=47u||rows<2u||rows>(1u<<24)||(rows&(rows-1u)))return int(cudaErrorInvalidValue);
        \\ native_projection_parameters<<<1,1,0,static_cast<cudaStream_t>(stream)>>>(draws,domain,claim,rows,parameters,status);return int(cudaGetLastError());
        \\}
        \\
    );
    inline for (.{ Scan.Scan.blocks, Scan.Scan.totals, Scan.Scan.finalize }) |kind| try Scan.emitScan(writer, "native_projection_scan_" ++ @tagName(kind), kind);
    try writer.writeAll(
        \\extern "C" int stwo_native_projection_interactions_on(const uint*fractions,uint*output,RiscvQm31*sums,uint*status,uint rows,void*stream){
        \\ if(!fractions||!output||!sums||!status||rows<2u||rows>(1u<<24)||(rows&(rows-1)))return int(cudaErrorInvalidValue);
        \\ cudaStream_t s=static_cast<cudaStream_t>(stream);uint blocks=(rows+255u)/256u;
        \\ native_projection_fraction_rows<<<(rows+127u)/128u,128,0,s>>>(fractions,output,status,rows);
        \\ cudaError_t e=cudaGetLastError();if(e!=cudaSuccess)return int(e);
        \\ native_projection_scan_blocks<<<blocks,256,0,s>>>(output,sums,rows,blocks,1,1);
        \\ e=cudaGetLastError();if(e!=cudaSuccess)return int(e);
        \\ native_projection_scan_totals<<<1,32,0,s>>>(output,sums,rows,blocks,1,1);
        \\ e=cudaGetLastError();if(e!=cudaSuccess)return int(e);
        \\ native_projection_scan_finalize<<<(rows+127u)/128u,128,0,s>>>(output,sums,rows,blocks,1,1);
        \\ return int(cudaGetLastError());
        \\}
        \\
    );
}
