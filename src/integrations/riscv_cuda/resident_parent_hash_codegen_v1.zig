//! Device witness author shares the canonical core G control flow. Numeric
//! carry/byte emission is checked against the separate original CPU witness.
const std = @import("std");
const Core = @import("stwo_core");
pub fn generate(a: std.mem.Allocator) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    const w = &out.writer;
    try w.writeAll(
        \\#include <cuda_runtime.h>
        \\#include <cstdint>
        \\using uint=std::uint32_t;using ulong=std::uint64_t;
        \\struct ParentHashSource{uint wire,kind,value,length;};
        \\struct ParentHashCall{uint initial[32],output[16],first_g,first_xor;};
        \\__device__ __forceinline__ uint parent_hash_row(uint i,uint log){uint rows=1u<<log,n=(i&1u)?rows-1u-i/2u:i/2u;return __brev(n)>>(32u-log);}
        \\__device__ __forceinline__ uint parent_rotr(uint x,uint n){return (x>>n)|(x<<(32u-n));}
        \\__device__ __forceinline__ void parent_hash_g(const uint input[6],uint result[4],uint*main,uint rows,uint row){
        \\
    );
    var writer = Writer{ .a = arena.allocator(), .w = w };
    const input = [6][]const u8{ "input[0]", "input[1]", "input[2]", "input[3]", "input[4]", "input[5]" };
    for (input) |x| try writer.word(x);
    const result = try Core.crypto.blake3_compression.g(Writer, &writer, input);
    if (writer.column != 82) return error.InvalidResidentGColumnRecipe;
    for (result, 0..) |x, i| try w.print("result[{d}]={s};\n", .{ i, x });
    try w.writeAll("}\n");
    try w.writeAll(
        \\extern "C" __global__ void stwo_resident_parent_hash_sources_v1(const unsigned char*input,uint input_bytes,const ParentHashSource*sources,uint count,uint*wires,uint wire_count,uint*status){
        \\ uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;ParentHashSource s=sources[i];
        \\ if(s.wire>=wire_count||s.kind>1u){atomicOr(status,1u);return;}uint v=s.value;
        \\ if(s.kind==1u){if(s.length==0u||s.length>4u||s.value>input_bytes||s.length>input_bytes-s.value){atomicOr(status,1u);return;}v=0;for(uint j=0;j<s.length;++j)v|=uint(input[s.value+j])<<(j*8u);}wires[s.wire]=v;
        \\}
        \\extern "C" __global__ void stwo_resident_parent_hash_calls_v1(uint*wires,uint wire_count,const ParentHashCall*calls,const uint*indices,uint count,uint*g_main,uint*x_main,uint g_log,uint x_log,uint*status){
        \\ uint job=blockIdx.x*blockDim.x+threadIdx.x;if(job>=count)return;ParentHashCall call=calls[indices[job]];
        \\ uint state[16],message[16],cv[8];for(uint i=0;i<32u;++i){if(call.initial[i]>=wire_count){atomicOr(status,1u);return;}uint v=wires[call.initial[i]];if(i<16u)state[i]=v;else message[i-16u]=v;if(i<8u)cv[i]=v;}
        \\ if(call.first_g>=(1u<<g_log)||56u>(1u<<g_log)-call.first_g||call.first_xor>=(1u<<x_log)||16u>(1u<<x_log)-call.first_xor){atomicOr(status,1u);return;}
        \\ for(uint round=0;round<7u;++round){
        \\
    );
    for (Core.crypto.blake3_compression.G_INDICES, 0..) |ix, i| {
        try w.print("{{uint input[6]={{state[{d}],state[{d}],state[{d}],state[{d}],message[{d}],message[{d}]}},result[4];parent_hash_g(input,result,g_main,1u<<g_log,parent_hash_row(call.first_g+round*8u+{d}u,g_log));", .{ ix[0], ix[1], ix[2], ix[3], i * 2, i * 2 + 1, i });
        for (ix, 0..) |target, j| try w.print("state[{d}]=result[{d}];", .{ target, j });
        try w.writeAll("}\n");
    }
    try w.writeAll("uint prior[16];for(uint i=0;i<16u;++i)prior[i]=message[i];\n");
    for (Core.crypto.blake3_compression.PERMUTATION, 0..) |source, i| try w.print("message[{d}]=prior[{d}];\n", .{ i, source });
    try w.writeAll(
        \\ }
        \\ for(uint i=0;i<16u;++i){uint a=state[i],b=i<8u?state[i+8u]:cv[i-8u],v=a^b,row=parent_hash_row(call.first_xor+i,x_log);if(call.output[i]>=wire_count){atomicOr(status,1u);return;}wires[call.output[i]]=v;
        \\ for(uint byte=0;byte<4u;++byte){x_main[ulong(byte)*(1u<<x_log)+row]=(a>>(byte*8u))&255u;x_main[ulong(4u+byte)*(1u<<x_log)+row]=(b>>(byte*8u))&255u;x_main[ulong(8u+byte)*(1u<<x_log)+row]=(v>>(byte*8u))&255u;}}
        \\}
        \\
    );
    try w.writeAll(
        \\extern "C" int stwo_resident_parent_hash_initialize_on(uint*wires,uint wire_count,uint*g_main,uint g_log,uint*x_main,uint x_log,void*stream){
        \\ cudaStream_t s=(cudaStream_t)stream;cudaError_t e=cudaMemsetAsync(wires,0,std::size_t(wire_count)*4,s);if(e!=cudaSuccess)return int(e);e=cudaMemsetAsync(g_main,0,(std::size_t(82)<<g_log)*4,s);if(e!=cudaSuccess)return int(e);return int(cudaMemsetAsync(x_main,0,(std::size_t(12)<<x_log)*4,s));
        \\}
        \\extern "C" int stwo_resident_parent_hash_source_range_on(const unsigned char*input,uint input_bytes,const ParentHashSource*sources,uint count,uint*wires,uint wire_count,uint*status,void*stream){if(!count)return int(cudaSuccess);stwo_resident_parent_hash_sources_v1<<<(count+127)/128,128,0,(cudaStream_t)stream>>>(input,input_bytes,sources,count,wires,wire_count,status);return int(cudaGetLastError());}
        \\extern "C" int stwo_resident_parent_hash_sources_on(const unsigned char*input,uint input_bytes,const ParentHashSource*sources,uint count,uint*wires,uint wire_count,uint*g_main,uint g_log,uint*x_main,uint x_log,uint*status,void*stream){
        \\ cudaStream_t s=(cudaStream_t)stream;cudaError_t e=cudaMemsetAsync(g_main,0,(std::size_t(82)<<g_log)*4,s);if(e!=cudaSuccess)return int(e);e=cudaMemsetAsync(x_main,0,(std::size_t(12)<<x_log)*4,s);if(e!=cudaSuccess)return int(e);e=cudaMemsetAsync(status,0,4,s);if(e!=cudaSuccess)return int(e);
        \\ stwo_resident_parent_hash_sources_v1<<<(count+127)/128,128,0,s>>>(input,input_bytes,sources,count,wires,wire_count,status);return int(cudaGetLastError());
        \\}
        \\extern "C" int stwo_resident_parent_hash_calls_on(uint*wires,uint wire_count,const ParentHashCall*calls,const uint*indices,uint count,uint*g_main,uint*x_main,uint g_log,uint x_log,uint*status,void*stream){
        \\ stwo_resident_parent_hash_calls_v1<<<(count+127)/128,128,0,(cudaStream_t)stream>>>(wires,wire_count,calls,indices,count,g_main,x_main,g_log,x_log,status);return int(cudaGetLastError());
        \\}
        \\
    );
    return a.dupe(u8, out.written());
}
const Writer = struct {
    pub const Word = []const u8;
    a: std.mem.Allocator,
    w: *std.Io.Writer,
    next: usize = 0,
    column: usize = 0,
    fn variable(self: *Writer, expr: []const u8) !Word {
        const name = try std.fmt.allocPrint(self.a, "v{d}", .{self.next});
        self.next += 1;
        try self.w.print("uint {s}={s};\n", .{ name, expr });
        return name;
    }
    fn value(self: *Writer, expr: []const u8) !void {
        try self.w.print("main[ulong({d})*rows+row]={s};\n", .{ self.column, expr });
        self.column += 1;
    }
    fn word(self: *Writer, expr: Word) !void {
        for (0..4) |i| try self.value(try std.fmt.allocPrint(self.a, "(({s}>>{d}u)&255u)", .{ expr, i * 8 }));
    }
    pub fn add(self: *Writer, a: Word, b: Word) !Word {
        const value_ = try self.variable(try std.fmt.allocPrint(self.a, "{s}+{s}", .{ a, b }));
        try self.word(value_);
        var carry: Word = "0u";
        for (0..2) |i| {
            carry = try self.variable(try std.fmt.allocPrint(self.a, "((({s}>>{d}u)&65535u)+(({s}>>{d}u)&65535u)+{s})>>16u", .{ a, i * 16, b, i * 16, carry }));
            try self.value(carry);
        }
        return value_;
    }
    pub fn add3(self: *Writer, a: Word, b: Word, c: Word) !Word {
        const value_ = try self.variable(try std.fmt.allocPrint(self.a, "{s}+{s}+{s}", .{ a, b, c }));
        try self.word(value_);
        var carry: Word = "0u";
        for (0..2) |i| {
            carry = try self.variable(try std.fmt.allocPrint(self.a, "((({s}>>{d}u)&65535u)+(({s}>>{d}u)&65535u)+(({s}>>{d}u)&65535u)+{s})>>16u", .{ a, i * 16, b, i * 16, c, i * 16, carry }));
            try self.value(try std.fmt.allocPrint(self.a, "{s}&1u", .{carry}));
            try self.value(try std.fmt.allocPrint(self.a, "{s}>>1u", .{carry}));
        }
        return value_;
    }
    pub fn xorRotate(self: *Writer, a: Word, b: Word, comptime rotation: u5) !Word {
        const x = try self.variable(try std.fmt.allocPrint(self.a, "{s}^{s}", .{ a, b }));
        try self.word(x);
        const value_ = try self.variable(try std.fmt.allocPrint(self.a, "parent_rotr({s},{d}u)", .{ x, rotation }));
        if (rotation == 16 or rotation == 8) return value_;
        try self.word(value_);
        const rotated = try self.variable(try std.fmt.allocPrint(self.a, "parent_rotr({s},8u)", .{x}));
        if (rotation == 7) {
            try self.value(try std.fmt.allocPrint(self.a, "({s}>>15u)&1u", .{rotated}));
            try self.value(try std.fmt.allocPrint(self.a, "{s}>>31u", .{rotated}));
        } else if (rotation == 12) {
            for (0..2) |i| {
                const low = try self.variable(try std.fmt.allocPrint(self.a, "({s}>>{d}u)&15u", .{ rotated, i * 16 }));
                try self.value(low);
                try self.value(try std.fmt.allocPrint(self.a, "{s}<<4u", .{low}));
            }
        } else @compileError("invalid G rotation");
        return value_;
    }
};
