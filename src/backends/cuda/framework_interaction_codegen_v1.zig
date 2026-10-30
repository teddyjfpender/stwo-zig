//! CUDA interaction lowering from the exact existing framework lookup emitter.
//! This is a separate executable identity; composition catalog v1 is unchanged.
const std = @import("std");
const Base = @import("framework_polynomial_codegen_v1.zig");
const E = @import("stwo_prover_engine").air.framework_polynomial_emitter_v1;
pub const Entry = Base.Entry;
pub const helper_source = @embedFile("native/framework_interaction_v1.cuh");
pub const FractionArgumentCount: u32 = 8;
pub const ScanArgumentCount: u32 = 6;
pub const Scan = enum { blocks, totals, finalize };
pub fn validate(entry: Entry) !void {
    try Base.validate(entry);
    for (entry.program.inputs) |input| switch (input) {
        .trace_column => |column| if (column.tree_index > 1) return error.InvalidFrameworkInteractionInput,
        .profile_parameter => {},
    };
}
pub fn emitFraction(a: std.mem.Allocator, w: anytype, kernel_name: []const u8, entry: Entry) !void {
    try validate(entry);
    const p = entry.program;
    try w.print(
        \\extern "C" __global__ void {s}(const uint *tree0,const uint *tree1,const ulong *column_offsets,const uint *profile_parameters,const uint *relation_parameters,uint *output,uint *status,uint row_count) {{
        \\ uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=row_count)return;
        \\
    , .{kernel_name});
    if (p.is_first_input) |slot| try w.print(" if(tree0[column_offsets[{d}u]+row]!=uint(row==0u))atomicOr(status,2u);\n", .{slot});
    for (p.inputs, 0..) |input, i| switch (input) {
        .trace_column => |column| try w.print(" if(tree{d}[column_offsets[{d}u]+row]>=0x7fffffffu)atomicOr(status,4u);\n", .{ column.tree_index, i }),
        .profile_parameter => {},
    };
    _ = try E.emitLookupTerms(a, w, p);
    if (p.layout == .same_row_prefix_v1) try w.writeAll(" RiscvQm31 cumulative={0u,0u,0u,0u};\n");
    for (p.batches, 0..) |batch, i| {
        const first = batch.first_entry;
        if (batch.entry_count > 2) {
            try E.emitWideFraction(w, p, batch, i);
            try w.print(" RiscvQm31 n{d}=wide_n{d},d{d}=wide_d{d};\n", .{ i, i, i, i });
        } else if (batch.entry_count == 1) try w.print(" RiscvQm31 n{d}={{l{d},0u,0u,0u}},d{d}=denominator{d};\n", .{ i, p.entries[first].numerator, i, first }) else try w.print(" RiscvQm31 n{d}=riscv_qm_add(riscv_qm_mul_base(denominator{d},l{d}),riscv_qm_mul_base(denominator{d},l{d})),d{d}=riscv_qm_mul(denominator{d},denominator{d});\n", .{ i, first + 1, p.entries[first].numerator, first, p.entries[first + 1].numerator, i, first, first + 1 });
        try w.print(" if((d{d}.a|d{d}.b|d{d}.c|d{d}.d)==0u)atomicOr(status,1u);\n RiscvQm31 f{d}=riscv_qm_mul(n{d},framework_inverse(d{d}));\n", .{ i, i, i, i, i, i, i });
        if (p.layout == .same_row_prefix_v1) try w.print(" cumulative=riscv_qm_add(cumulative,f{d});framework_store(output,row_count,{d}u,row,cumulative);\n", .{ i, i }) else try w.print(" framework_store(output,row_count,{d}u,row,f{d});\n", .{ i, i });
    }
    try w.writeAll("}\n");
}
pub fn emitScan(w: anytype, kernel_name: []const u8, kind: Scan) !void {
    try w.print("extern \"C\" __global__ void {s}(uint *output,RiscvQm31 *sums,uint rows,uint blocks,uint batches,uint layout) {{\n", .{kernel_name});
    switch (kind) {
        .blocks => try w.writeAll(
            \\ uint group=blockIdx.x,lane=threadIdx.x,scan_batch=group/blocks,local=group%blocks,index=local*256u+lane;
            \\ uint batch=layout==1u?batches-1u:scan_batch;
            \\ __shared__ RiscvQm31 values[256];
            \\ values[lane]=index<rows?framework_load(output,rows,batch,framework_row(index,rows)):RiscvQm31{0u,0u,0u,0u};
            \\ __syncthreads();
            \\ for(uint offset=1u;offset<256u;offset<<=1u){RiscvQm31 q=values[lane];if(lane>=offset)q=riscv_qm_add(q,values[lane-offset]);__syncthreads();values[lane]=q;__syncthreads();}
            \\ if(index<rows)framework_store(output,rows,batch,framework_row(index,rows),values[lane]);
            \\ if(lane+1u==min(256u,rows-local*256u))sums[group]=values[lane];
            \\
        ),
        .totals => try w.writeAll(
            \\ uint batch=blockIdx.x*blockDim.x+threadIdx.x,scans=layout==1u?1u:batches;if(batch>=scans)return;
            \\ RiscvQm31 total={0u,0u,0u,0u};for(uint b=0;b<blocks;++b){uint i=batch*blocks+b;total=riscv_qm_add(total,sums[i]);sums[i]=total;}
            \\ ulong claim=ulong(batches)*4u*rows+batch*4u;output[claim]=total.a;output[claim+1]=total.b;output[claim+2]=total.c;output[claim+3]=total.d;
            \\
        ),
        .finalize => try w.writeAll(
            \\ uint index=blockIdx.x*blockDim.x+threadIdx.x,scan_batch=blockIdx.y,scans=layout==1u?1u:batches;if(index>=rows||scan_batch>=scans)return;
            \\ uint row=framework_row(index,rows),block=index/256u,batch=layout==1u?batches-1u:scan_batch;
            \\ RiscvQm31 q=framework_load(output,rows,batch,row);if(block!=0u)q=riscv_qm_add(q,sums[scan_batch*blocks+block-1u]);
            \\ if(layout==1u){ulong offset=ulong(batches)*4u*rows;RiscvQm31 claim={output[offset],output[offset+1],output[offset+2],output[offset+3]};uint factor=riscv_m31_mul(index+1u,1u<<(31u-uint(__ffs(rows)-1)));q=riscv_qm_sub(q,riscv_qm_mul_base(claim,factor));}
            \\ framework_store(output,rows,batch,row,q);
            \\
        ),
    }
    try w.writeAll("}\n");
}
fn initialHash() std.crypto.hash.sha2.Sha256 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/cuda/framework-interaction/v1\x00");
    h.update(@embedFile("framework_interaction_codegen_v1.zig"));
    h.update(&E.fingerprint());
    h.update(Base.preamble);
    h.update(helper_source);
    h.update(@embedFile("native/oods/field.cuh"));
    return h;
}
pub fn identity(a: std.mem.Allocator, entry: Entry) ![32]u8 {
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    try emitFraction(a, &source.writer, "framework_interaction_canonical", entry);
    var h = initialHash();
    h.update(source.written());
    return h.finalResult();
}
pub fn name(a: std.mem.Allocator, id: [32]u8) ![:0]u8 {
    return std.fmt.allocPrintSentinel(a, "stwo_cuda_framework_interaction_v1_{s}", .{std.fmt.bytesToHex(id, .lower)}, 0);
}
pub fn scanIdentity(a: std.mem.Allocator, kind: Scan) ![32]u8 {
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    try emitScan(&source.writer, "framework_scan_canonical", kind);
    var h = initialHash();
    h.update(@tagName(kind));
    h.update(source.written());
    return h.finalResult();
}
pub fn scanName(a: std.mem.Allocator, kind: Scan, id: [32]u8) ![:0]u8 {
    return std.fmt.allocPrintSentinel(a, "stwo_cuda_framework_scan_{s}_v1_{s}", .{ @tagName(kind), std.fmt.bytesToHex(id, .lower) }, 0);
}
/// Appended to an unchanged composition library, which already emits helpers.
pub fn appendLibrary(a: std.mem.Allocator, w: anytype, entries: []const Entry) !void {
    try w.writeAll(helper_source);
    var seen: std.AutoHashMap([32]u8, void) = .init(a);
    defer seen.deinit();
    for (entries) |entry| {
        const id = try identity(a, entry);
        const slot = try seen.getOrPut(id);
        if (slot.found_existing) continue;
        const n = try name(a, id);
        defer a.free(n);
        try emitFraction(a, w, n, entry);
    }
    inline for (std.meta.tags(Scan)) |kind| {
        const id = try scanIdentity(a, kind);
        const n = try scanName(a, kind, id);
        defer a.free(n);
        try emitScan(w, n, kind);
    }
}
