//! Native resident plumbing uses the unchanged framework lookup emitter.
//! Dead denominator expressions are not authority and no challenge is read:
//! the counter call supplies a device-zero dummy parameter buffer.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Base = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const Program = @import("resident_parent_program_v1.zig");
const E = engine.air.framework_polynomial_emitter_v1;
pub fn generate(a: std.mem.Allocator, program: *const Program.Owned) ![]u8 {
    var s: std.Io.Writer.Allocating = .init(a);
    defer s.deinit();
    const w = &s.writer;
    try w.writeAll(Base.preamble);
    try w.writeAll(@embedFile("resident_parent_framework_util_v1.cuh"));
    for (program.view().programs[0..Program.AIR_COUNT], 0..) |*p, i| {
        try w.print("__global__ void parent_framework_counts_{d}(const uint*tree0,const uint*tree1,const ulong*column_offsets,const uint*profile_parameters,const uint*relation_parameters,uint*bitwise,uint*range,uint*status,uint row_count){{uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=row_count)return;\n", .{i});
        _ = try E.emitLookupTerms(a, w, p);
        for (p.entries) |entry| {
            if (entry.domain == 6) {
                if (entry.arity != 4) return error.InvalidResidentCounterProgram;
                try w.print("parent_framework_count_bitwise(bitwise,status,l{d},l{d},l{d},l{d},l{d});\n", .{ entry.numerator, entry.values[0], entry.values[1], entry.values[2], entry.values[3] });
            } else if (entry.domain == 10) {
                if (entry.arity != 2) return error.InvalidResidentCounterProgram;
                try w.print("parent_framework_count_range(range,status,l{d},l{d},l{d});\n", .{ entry.numerator, entry.values[0], entry.values[1] });
            }
        }
        try w.writeAll("}\n");
    }
    try w.writeAll("extern \"C\" int stwo_resident_framework_counts_on(uint kind,const uint*source,const ulong*offsets,const uint*profile,const uint*dummy,uint*bitwise,uint*range,uint*status,uint rows,void*stream){if(!source||!offsets||!profile||!dummy||!bitwise||!range||!status||!rows)return int(cudaErrorInvalidValue);switch(kind){\n");
    for (0..Program.AIR_COUNT) |i| try w.print("case {d}:parent_framework_counts_{d}<<<(rows+127u)/128u,128u,0,static_cast<cudaStream_t>(stream)>>>(source,source,offsets,profile,dummy,bitwise,range,status,rows);break;\n", .{ i, i });
    try w.writeAll("default:return int(cudaErrorInvalidValue);}return int(cudaGetLastError());}\n");
    try w.writeAll(@embedFile("resident_parent_counter_wide_v1.cuh"));
    for (program.view().programs[0..Program.AIR_COUNT], 0..) |*p, i| {
        try w.print("__global__ void parent_framework_counts_wide_{d}(const uint*tree0,const uint*tree1,const ulong*column_offsets,const uint*profile_parameters,const uint*relation_parameters,unsigned long long*bitwise,unsigned long long*range,uint*status,uint row_count){{uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=row_count)return;\n", .{i});
        _ = try E.emitLookupTerms(a, w, p);
        for (p.entries) |entry| {
            if (entry.domain == 6) {
                if (entry.arity != 4) return error.InvalidResidentCounterProgram;
                try w.print("parent_framework_wide_bitwise(bitwise,status,l{d},l{d},l{d},l{d},l{d});\n", .{ entry.numerator, entry.values[0], entry.values[1], entry.values[2], entry.values[3] });
            } else if (entry.domain == 10) {
                if (entry.arity != 2) return error.InvalidResidentCounterProgram;
                try w.print("parent_framework_wide_range(range,status,l{d},l{d},l{d});\n", .{ entry.numerator, entry.values[0], entry.values[1] });
            }
        }
        try w.writeAll("}\n");
    }
    try w.writeAll("extern \"C\" int stwo_resident_framework_counts_wide_on(uint kind,const uint*source,const ulong*offsets,const uint*profile,const uint*dummy,unsigned long long*bitwise,unsigned long long*range,uint*status,uint rows,void*stream){if(!source||!offsets||!profile||!dummy||!bitwise||!range||!status||!rows)return int(cudaErrorInvalidValue);switch(kind){\n");
    for (0..Program.AIR_COUNT) |i| try w.print("case {d}:parent_framework_counts_wide_{d}<<<(rows+127u)/128u,128u,0,static_cast<cudaStream_t>(stream)>>>(source,source,offsets,profile,dummy,bitwise,range,status,rows);break;\n", .{ i, i });
    try w.writeAll("default:return int(cudaErrorInvalidValue);}return int(cudaGetLastError());}\n");
    return a.dupe(u8, s.written());
}
