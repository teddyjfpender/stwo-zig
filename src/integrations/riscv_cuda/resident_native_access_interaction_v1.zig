//! Proof-arena sizing and exact native physical interaction assembly emitter.
//! Inputs are DEVICE denominator roots, never host-produced witness columns.
const std = @import("std");
const Core = @import("stwo_core");
const Q = Core.fields.qm31.QM31;
const M = Core.fields.m31.M31;
const Scan = @import("../../backends/cuda/framework_interaction_codegen_v1.zig");
const Code = @import("resident_native_access_codegen_v1.zig");
pub const Layout = struct {
    rows: u32,
    denominator_words: usize,
    stream_words: usize,
    term_words: usize,
    sum_words: usize,
    output_words: usize,
    claim_words: usize = 40,
    total_bytes: usize,
    pub fn init(log: u32, cap: usize) !Layout {
        if (log < 1 or log > 24) return error.InvalidNativeAccessDomain;
        const rows: usize = @as(usize, 1) << @intCast(log);
        const denominators = 72 * rows;
        const streams = 10 * (4 * rows + 4);
        const terms = 12 * rows;
        const sums = 4 * ((rows + 255) / 256);
        const outputs = 49 * rows;
        const bytes = try std.math.mul(usize, denominators + streams + terms + sums + outputs + 41, 4);
        if (bytes > cap) return error.NativeAccessResourceLimit;
        return .{ .rows = @intCast(rows), .denominator_words = denominators, .stream_words = streams, .term_words = terms, .sum_words = sums, .output_words = outputs, .total_bytes = bytes };
    }
};
pub fn emit(writer: anytype) !void {
    try writer.writeAll(Scan.helper_source);
    try writer.writeAll(@embedFile("resident_native_access_interaction_v1.cuh"));
    const Domain = @import("../../frontends/riscv/air/lang/relation.zig").Domain;
    try writer.print(
        \\__global__ void native_access_parameters(const uint*draws,ulong base_clock,const uint*claims,uint rows,uint*parameters,uint*status){{
        \\ if(threadIdx.x||blockIdx.x)return;for(uint i=0;i<416u;i++)if(draws[i]>=2147483647u){{atomicOr(status,16u);return;}}
        \\ if(claims)for(uint i=0;i<40u;i++)if(claims[i]>=2147483647u){{atomicOr(status,16u);return;}}
        \\ RiscvQm31*result=reinterpret_cast<RiscvQm31*>(parameters);const RiscvQm31*input=reinterpret_cast<const RiscvQm31*>(draws);
        \\ for(uint i=0;i<8u;i++)result[i]=RiscvQm31{{uint((base_clock>>(8u*i))&255u),0,0,0}};
        \\ const uint first[3]={{94u,{d}u,{d}u}},dest[3]={{8u,20u,23u}},arity[3]={{11u,2u,7u}};
        \\ for(uint relation=0;relation<3;relation++){{result[dest[relation]]=input[first[relation]];RiscvQm31 power={{1,0,0,0}};for(uint i=0;i<arity[relation];i++){{result[dest[relation]+1u+i]=power;power=riscv_qm_mul(power,input[first[relation]+1u]);}}}}
        \\ RiscvQm31 inverse=framework_inverse(RiscvQm31{{rows,0,0,0}});const RiscvQm31*c=reinterpret_cast<const RiscvQm31*>(claims);
        \\ for(uint i=0;i<10u;i++)result[31u+i]=claims?riscv_qm_mul(c[i],inverse):RiscvQm31{{0,0,0,0}};
        \\}}
        \\extern "C" int stwo_native_access_parameters_on(const uint*draws,uint draw_words,ulong base_clock,const uint*claims,uint rows,uint*parameters,uint*status,void*stream){{
        \\ if(!draws||draw_words!=416u||!parameters||!status||rows<2u||rows>(1u<<24)||(rows&(rows-1)))return int(cudaErrorInvalidValue);
        \\ native_access_parameters<<<1,1,0,static_cast<cudaStream_t>(stream)>>>(draws,base_clock,claims,rows,parameters,status);return int(cudaGetLastError());
        \\}}
        \\
    , .{ 2 * @as(u32, @intFromEnum(Domain.range_check_8_8)), 2 * @as(u32, @intFromEnum(Domain.memory_access)) });
    inline for (.{ Scan.Scan.blocks, Scan.Scan.totals, Scan.Scan.finalize }) |kind| try Scan.emitScan(writer, "native_access_scan_" ++ @tagName(kind), kind);
    try writer.writeAll(
        \\extern "C" int stwo_native_access_interactions_on(const uint*denominators,uint*streams,uint*terms,RiscvQm31*sums,uint*output,uint*claims,uint*status,uint rows,void*stream){
        \\ if(!denominators||!streams||!terms||!sums||!output||!claims||!status||rows<2u||rows>(1u<<24)||(rows&(rows-1)))return int(cudaErrorInvalidValue);
        \\ cudaStream_t s=static_cast<cudaStream_t>(stream);uint blocks=(rows+255u)/256u;
        \\ native_access_fraction_rows<<<(rows+127u)/128u,128,0,s>>>(denominators,streams,terms,status,rows);
        \\ cudaError_t e=cudaGetLastError();if(e!=cudaSuccess)return int(e);
        \\ for(uint i=0;i<10u;i++){
        \\  uint*p=streams+ulong(i)*(4ul*rows+4u);
        \\  native_access_scan_blocks<<<blocks,256,0,s>>>(p,sums,rows,blocks,1,1);
        \\  e=cudaGetLastError();if(e!=cudaSuccess)return int(e);
        \\  native_access_scan_totals<<<1,32,0,s>>>(p,sums,rows,blocks,1,1);
        \\  e=cudaGetLastError();if(e!=cudaSuccess)return int(e);
        \\  native_access_scan_finalize<<<dim3((rows+127u)/128u,1),128,0,s>>>(p,sums,rows,blocks,1,1);
        \\  e=cudaGetLastError();if(e!=cudaSuccess)return int(e);
        \\ }
        \\ native_access_scatter_rows<<<(rows+127u)/128u,128,0,s>>>(streams,terms,output,claims,status,rows);
        \\ return int(cudaGetLastError());
        \\}
        \\
    );
}
const Access = @import("../../frontends/riscv/prover/block_execution_access_bridge_v2.zig");
const Integer = @import("../../frontends/riscv/prover/block_execution_integer_bridge_v2.zig");
const IA = @import("../../frontends/riscv/prover/block_execution_integer_algebra_v1.zig");
const Trace = struct {
    log_size: u32,
    inactive: bool,
    pub fn domainSize(self: *const @This()) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn pairAt(self: *const @This(), logical: usize) !Access.Pair(Q) {
        var before: [4]Q = undefined;
        var after: [4]Q = undefined;
        for (&before, &after, 0..) |*b, *e, i| {
            b.* = Q.fromBase(M.fromU64((logical * 19 + i * 37) % 256));
            e.* = Q.fromBase(M.fromU64((logical * 23 + i * 41 + 17) % 256));
        }
        return .{ .active = if (!self.inactive and logical % 7 != 0) Q.one() else Q.zero(), .space = Q.one(), .source_address = Q.fromBase(M.fromU64(101 + logical)), .local_clock = Q.fromBase(M.fromU64(4 * logical + 10)), .consume_clock = Q.fromBase(M.fromU64(4 * logical + 7)), .before = before, .after = after, .pair_residuals = @splat(Q.zero()), .access_ordinal = 0 };
    }
    pub fn witnessAt(self: *const @This(), logical: usize) !Integer.Witness {
        return Integer.Witness.fromPair(try self.pairAt(logical), 0x1_0000_0010);
    }
    pub fn row(self: *const @This(), logical: usize) !@import("../../frontends/riscv/prover/block_v5_word_execution_transition_v1.zig").Row {
        const pair = try self.pairAt(logical);
        if (!(try Access.decodePair(pair)).active) return .{ .active = false, .tuple = @splat(M.zero()) };
        const secure = Integer.transitionAtPoint(pair, try self.witnessAt(logical));
        var tuple: @import("../../frontends/riscv/prover/block_memory_relation_v2.zig").TransitionTuple = undefined;
        for (secure, &tuple) |value, *out| out.* = value.toM31Array()[0];
        return .{ .active = true, .tuple = tuple };
    }
};
fn array(writer: anytype, name: []const u8, words: []const M) !void {
    try writer.print("const uint {s}[]={{", .{name});
    for (words, 0..) |word, i| try writer.print("{s}{d}u", .{ if (i == 0) "" else ",", word.v });
    try writer.writeAll("};\n");
}
pub fn exportOracle(a: std.mem.Allocator, path: []const u8) !void {
    const Word = @import("../../frontends/riscv/prover/block_v5_word_memory_protocol_v1.zig");
    const Range = @import("../../frontends/riscv/prover/block_execution_byte_range_v2.zig");
    const Original = @import("../../frontends/riscv/prover/block_v7_native_access_interaction_v1.zig");
    const Counter = @import("../../frontends/riscv/air/lookups/tables/counter.zig").Counter;
    const Framework = @import("../../frontends/riscv/recursion/air/framework_interaction.zig");
    const Program = @import("resident_native_access_program_v1.zig");
    var channel = Core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x173591, 0x203701 });
    const challenges = try Word.Challenges.drawFromChannel(a, &channel);
    const transition = .{challenges.transition.z} ++ challenges.transition.alpha_powers;
    const range = .{challenges.universal_prefix.get(.range_check_8_8).z} ++ challenges.universal_prefix.get(.range_check_8_8).alpha_powers[0..2].*;
    const memory = .{challenges.universal_prefix.get(.memory_access).z} ++ challenges.universal_prefix.get(.memory_access).alpha_powers[0..7].*;
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    const w = &source.writer;
    try w.writeAll("#include <cuda_runtime.h>\n#include <cstdio>\n#include <vector>\n");
    try w.writeAll(Code.preamble);
    try emit(w);
    try w.writeAll("#define CHECK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,\"CUDA %s line%d\\n\",cudaGetErrorString(e),__LINE__);return 2;}}while(0)\nint main(){unsigned words=0;\n");
    var draws: [416]M = undefined;
    for (challenges.universal_prefix.elements, 0..) |relation, i| {
        @memcpy(draws[8 * i ..][0..4], &relation.z.toM31Array());
        @memcpy(draws[8 * i + 4 ..][0..4], &relation.alpha.toM31Array());
    }
    inline for (.{ challenges.transition, challenges.link, challenges.initial, challenges.endpoint, challenges.range16 }, 0..) |relation, i| {
        @memcpy(draws[376 + 8 * i ..][0..4], &relation.z.toM31Array());
        @memcpy(draws[380 + 8 * i ..][0..4], &relation.alpha.toM31Array());
    }
    try array(w, "draws", &draws);
    for ([_]Trace{ .{ .log_size = 1, .inactive = false }, .{ .log_size = 3, .inactive = false }, .{ .log_size = 9, .inactive = false }, .{ .log_size = 9, .inactive = true } }, 0..) |trace, case| {
        const layout = try Layout.init(trace.log_size, 1 << 30);
        var counter = try Counter.init(a, .range_check_8_8);
        defer counter.deinit(a);
        const snapshot = try Range.collectCounter(a, &trace, &counter);
        var original = try Original.generate(a, &trace, &challenges, snapshot);
        defer original.deinit(a);
        const den = try a.alloc(M, layout.denominator_words);
        defer a.free(den);
        for (0..layout.rows) |logical| {
            const row = Framework.committedRow(logical, trace.log_size);
            const witness = IA.Algebra(Q).Witness.fromColumns((try trace.witnessAt(logical)).columns());
            const ds = try Program.denominatorsFromPair(Q, try trace.pairAt(logical), witness, &transition, &range, &memory);
            for (ds, 0..) |value, i| for (value.toM31Array(), 0..) |limb, j| {
                den[(4 * i + j) * layout.rows + row] = limb;
            };
        }
        const expected = try a.alloc(M, layout.output_words);
        defer a.free(expected);
        for (original.columns, 0..) |col, i| @memcpy(expected[i * layout.rows ..][0..layout.rows], col);
        var claims: [40]M = undefined;
        const cq = .{ original.transition_sum, Q.fromBase(M.fromU64(original.active_count)) } ++ original.range_claims ++ .{original.universal_sum};
        for (cq, 0..) |value, i| @memcpy(claims[i * 4 ..][0..4], &value.toM31Array());
        var parameters: [164]M = undefined;
        for (0..8) |i| @memcpy(parameters[4 * i ..][0..4], &Q.fromBase(M.fromU64((@as(u64, 0x1_0000_0010) >> @intCast(8 * i)) & 255)).toM31Array());
        for (transition, 0..) |value, i| @memcpy(parameters[32 + 4 * i ..][0..4], &value.toM31Array());
        for (range, 0..) |value, i| @memcpy(parameters[80 + 4 * i ..][0..4], &value.toM31Array());
        for (memory, 0..) |value, i| @memcpy(parameters[92 + 4 * i ..][0..4], &value.toM31Array());
        for (cq, 0..) |value, i| @memcpy(parameters[124 + 4 * i ..][0..4], &(try value.divM31(M.fromU64(layout.rows))).toM31Array());
        try w.writeAll("{\n");
        try array(w, "input", den);
        try array(w, "expected", expected);
        try array(w, "expected_claims", &claims);
        try array(w, "expected_parameters", &parameters);
        try w.print("constexpr uint rows={d};uint *d,*streams,*terms,*out,*claims,*status;RiscvQm31*sums;CHECK(cudaMalloc(&d,sizeof(input)));CHECK(cudaMalloc(&streams,{d}));CHECK(cudaMalloc(&terms,{d}));CHECK(cudaMalloc(&sums,{d}));CHECK(cudaMalloc(&out,sizeof(expected)));CHECK(cudaMalloc(&claims,160));CHECK(cudaMalloc(&status,4));CHECK(cudaMemcpy(d,input,sizeof(input),cudaMemcpyHostToDevice));CHECK(cudaMemset(status,0,4));\n", .{ layout.rows, layout.stream_words * 4, layout.term_words * 4, layout.sum_words * 4 });
        try w.writeAll("CHECK(cudaError_t(stwo_native_access_interactions_on(d,streams,terms,sums,out,claims,status,rows,nullptr)));uint error=0;CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(error)return 3;std::vector<uint> actual(sizeof(expected)/4);CHECK(cudaMemcpy(actual.data(),out,sizeof(expected),cudaMemcpyDeviceToHost));uint claim[40];CHECK(cudaMemcpy(claim,claims,160,cudaMemcpyDeviceToHost));\n");
        try w.print("for(unsigned i=0;i<actual.size();i++)if(actual[i]!=expected[i]){{fprintf(stderr,\"FAIL case{d} columnword%u actual%u expected%u\\n\",i,actual[i],expected[i]);return 4;}}for(unsigned i=0;i<40;i++)if(claim[i]!=expected_claims[i])return 5;words+=actual.size()+40;\n", .{case});
        try w.writeAll("uint*ddraws,*params;CHECK(cudaMalloc(&ddraws,sizeof(draws)));CHECK(cudaMalloc(&params,sizeof(expected_parameters)));CHECK(cudaMemcpy(ddraws,draws,sizeof(draws),cudaMemcpyHostToDevice));CHECK(cudaError_t(stwo_native_access_parameters_on(ddraws,416,0x100000010ull,claims,rows,params,status,nullptr)));uint actual_parameters[164];CHECK(cudaMemcpy(actual_parameters,params,sizeof(actual_parameters),cudaMemcpyDeviceToHost));for(uint i=0;i<164;i++)if(actual_parameters[i]!=expected_parameters[i])return 7;words+=164;CHECK(cudaError_t(stwo_native_access_parameters_on(ddraws,416,0x100000010ull,nullptr,rows,params,status,nullptr)));CHECK(cudaMemcpy(actual_parameters,params,sizeof(actual_parameters),cudaMemcpyDeviceToHost));for(uint i=0;i<164;i++)if(actual_parameters[i]!=(i<124?expected_parameters[i]:0u))return 8;words+=164;uint noncanonical=2147483647u;CHECK(cudaMemcpy(ddraws,&noncanonical,4,cudaMemcpyHostToDevice));CHECK(cudaError_t(stwo_native_access_parameters_on(ddraws,416,0x100000010ull,claims,rows,params,status,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(!(error&16u))return 9;CHECK(cudaMemset(status,0,4));CHECK(cudaFree(ddraws));CHECK(cudaFree(params));\n");
        if (!trace.inactive) {
            const row = Framework.committedRow(1, trace.log_size);
            try w.print("uint zero=0;for(unsigned j=0;j<4;j++)CHECK(cudaMemcpy(d+j*rows+{d},&zero,4,cudaMemcpyHostToDevice));CHECK(cudaMemset(status,0,4));CHECK(cudaError_t(stwo_native_access_interactions_on(d,streams,terms,sums,out,claims,status,rows,nullptr)));CHECK(cudaMemcpy(&error,status,4,cudaMemcpyDeviceToHost));if(!(error&4u))return 6;\n", .{row});
        }
        try w.writeAll("CHECK(cudaFree(d));CHECK(cudaFree(streams));CHECK(cudaFree(terms));CHECK(cudaFree(sums));CHECK(cudaFree(out));CHECK(cudaFree(claims));CHECK(cudaFree(status));}\n");
    }
    try w.writeAll("printf(\"PASS native access GPU49columns10claims words=%u zero_denominator_hostiles=3\\n\",words);return 0;}\n");
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(source.written());
}

test "resident native access interaction arena rejects underbudget and invalid logs" {
    const layout = try Layout.init(9, 1 << 30);
    try std.testing.expectError(error.NativeAccessResourceLimit, Layout.init(9, layout.total_bytes - 1));
    try std.testing.expectEqual(layout.total_bytes, (try Layout.init(9, layout.total_bytes)).total_bytes);
    try std.testing.expectError(error.InvalidNativeAccessDomain, Layout.init(0, 1 << 30));
    try std.testing.expectError(error.InvalidNativeAccessDomain, Layout.init(25, 1 << 30));
}
