//! Numerical oracle exporter only. CPU source rows/answers are TEST vectors;
//! production emitters accept proof-owned resident MAIN/challenges/prefixes.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("resident_native_projection_program_v1.zig");
const Code = @import("resident_native_projection_codegen_v1.zig");
const Interaction = @import("resident_native_projection_interaction_v1.zig");
const Test = @import("resident_native_projection_test_v1.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Canonical = @import("../../frontends/riscv/prover/block_v7_native_relation_layout_v1.zig");
const Q2 = @import("../../frontends/riscv/prover/block_v7_degree_bounded_relation_layout_v1.zig");
const U = @import("../../frontends/riscv/recursion/air/universal_challenges.zig");
const Framework = @import("../../frontends/riscv/recursion/air/framework_interaction.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
fn array(w: anytype, name: []const u8, values: []const u32) !void {
    try w.print("const uint {s}[]={{", .{name});
    for (values, 0..) |v, i| try w.print("{s}{d}u", .{ if (i == 0) "" else ",", v });
    try w.writeAll("};\n");
}
pub fn exportOracle(a: std.mem.Allocator, path: []const u8) !void {
    var slots: std.ArrayList(P.Source.Slot) = .empty;
    defer slots.deinit(a);
    inline for (.{ Canonical, Q2 }, 0..) |Layout, mode| for (0..Trace.N_FAMILIES) |fi| {
        const family: Trace.OpcodeFamily = @enumFromInt(fi);
        if (mode == 1 and family != .mul) continue;
        var shape = Test.shapeFor(family);
        var layout = try Layout.Layout.init(a, &shape, 0, 1);
        defer layout.deinit();
        for (layout.slots) |slot| if (slot.kind == .program or family == .mul or family == .load_store) try slots.append(a, slot);
    };
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    const w = &source.writer;
    try w.writeAll("#include <cuda_runtime.h>\n#include <cstdio>\n#include <vector>\n");
    try w.writeAll(Code.preamble);
    try Interaction.emit(w);
    for (slots.items, 0..) |slot, i| for ([_]P.Mode{ .fractions, .equation }) |mode| {
        var p = try P.Owned.init(a, slot, mode);
        defer p.deinit();
        const name = try std.fmt.allocPrint(a, "projection_{d}_{s}", .{ i, @tagName(mode) });
        defer a.free(name);
        try Code.emit(a, w, name, &p, if (mode == .fractions) .roots else .folded_quotient);
    };
    try w.writeAll("#define CHECK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,\"CUDA %s line%d\\n\",cudaGetErrorString(e),__LINE__);return 2;}}while(0)\nint main(){unsigned words=0,attacks=0;\n");
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try U.UniversalRelations.draw(a, &channel);
    var raw_draws: [376]u32 = undefined;
    for (relations.elements, 0..) |element, i| {
        for ([_]Q{ element.z, element.alpha }, 0..) |q, j| for (q.toM31Array(), 0..) |limb, k| {
            raw_draws[8 * i + 4 * j + k] = limb.v;
        };
    }
    try array(w, "raw_draws", &raw_draws);
    try w.writeAll("uint*ddraw;CHECK(cudaMalloc(&ddraw,sizeof(raw_draws)));CHECK(cudaMemcpy(ddraw,raw_draws,sizeof(raw_draws),cudaMemcpyHostToDevice));\n");

    for (slots.items, 0..) |slot, id| {
        const main = try a.alloc(Q, slot.width);
        defer a.free(main);
        var fractions: [64]u32 = undefined;
        var prefix: [36]u32 = undefined;
        var forged: [32]u32 = undefined;
        var terms: [8]Q = undefined;
        var claim = Q.zero();
        const power = Q.fromM31Array(.{ M.fromCanonical(7), M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(17) });
        for (0..8) |logical| {
            const physical = Framework.committedRow(logical, 3);
            for (main, 0..) |*v, col| v.* = Q.fromBase(M.fromU64(col * 13 + physical * 19 + 7));
            const pair = try P.Source.fromCommittedMain(slot, main, &relations);
            const n = pair.numerator();
            const d = pair.denominator();
            terms[logical] = n.mul(try d.inv());
            claim = claim.add(terms[logical]);
            for (n.toM31Array(), d.toM31Array(), 0..) |nn, dd, limb| {
                fractions[limb * 8 + physical] = nn.v;
                fractions[(4 + limb) * 8 + physical] = dd.v;
            }
            for (d.mul(power).toM31Array(), 0..) |limb, j| forged[j * 8 + physical] = limb.v;
        }
        const mean = try claim.divM31(M.fromCanonical(8));
        var running = Q.zero();
        for (terms, 0..) |term, logical| {
            running = running.add(term).sub(mean);
            for (running.toM31Array(), 0..) |limb, j| prefix[j * 8 + Framework.committedRow(logical, 3)] = limb.v;
        }
        for (claim.toM31Array(), 0..) |limb, j| prefix[32 + j] = limb.v;
        const relation = relations.get(P.domain(slot));
        var params: [12]u32 = undefined;
        for ([3]Q{ relation.z, relation.alpha, mean }, 0..) |q, i| for (q.toM31Array(), 0..) |limb, j| {
            params[4 * i + j] = limb.v;
        };
        try w.print("{{constexpr unsigned width={d};std::vector<uint> main(width*8);for(unsigned c=0;c<width;c++)for(unsigned r=0;r<8;r++)main[c*8+r]=c*13+r*19+7;\n", .{slot.width});
        try array(w, "params", &params);
        try array(w, "want_fractions", &fractions);
        try array(w, "want_prefix", &prefix);
        try array(w, "want_forged", &forged);
        try w.writeAll("uint powers[4]={7,11,13,17},denom[8]={1,1,1,1,1,1,1,1};uint *dm,*dp,*df,*di,*ds,*dstatus,*dout,*dpow,*dd;uint got[64],status=0;cudaStream_t stream;CHECK(cudaStreamCreate(&stream));CHECK(cudaMalloc(&dm,main.size()*4));CHECK(cudaMalloc(&dp,48));CHECK(cudaMalloc(&df,256));CHECK(cudaMalloc(&di,144));CHECK(cudaMalloc(&ds,16));CHECK(cudaMalloc(&dstatus,4));CHECK(cudaMalloc(&dout,128));CHECK(cudaMalloc(&dpow,16));CHECK(cudaMalloc(&dd,32));CHECK(cudaMemset(dstatus,0,4));CHECK(cudaMemset(di,0,144));CHECK(cudaMemcpy(dm,main.data(),main.size()*4,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(dpow,powers,16,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(dd,denom,32,cudaMemcpyHostToDevice));\n");
        try w.print("CHECK((cudaError_t)stwo_native_projection_parameters_on(ddraw,376,{d},nullptr,8,dp,dstatus,stream));\n", .{@intFromEnum(P.domain(slot))});
        try w.print("projection_{d}_fractions<<<1,32,0,stream>>>(dm,nullptr,di,dp,df,8,8,nullptr,nullptr,1);CHECK(cudaGetLastError());CHECK(cudaStreamSynchronize(stream));CHECK(cudaMemcpy(got,df,256,cudaMemcpyDeviceToHost));for(unsigned i=0;i<64;i++)if(got[i]!=want_fractions[i]){{fprintf(stderr,\"fraction slot{d} word%u\\n\",i);return 3;}}words+=64;\n", .{ id, id });
        try w.print("CHECK((cudaError_t)stwo_native_projection_interactions_on(df,di,(RiscvQm31*)ds,dstatus,8,stream));CHECK(cudaStreamSynchronize(stream));CHECK(cudaMemcpy(got,di,144,cudaMemcpyDeviceToHost));for(unsigned i=0;i<36;i++)if(got[i]!=want_prefix[i]){{fprintf(stderr,\"prefix slot{d} word%u got%u want%u\\n\",i,got[i],want_prefix[i]);return 4;}}words+=36;\n", .{id});
        try w.print("CHECK((cudaError_t)stwo_native_projection_parameters_on(ddraw,376,{d},di+32,8,dp,dstatus,stream));CHECK(cudaStreamSynchronize(stream));CHECK(cudaMemcpy(got,dp,48,cudaMemcpyDeviceToHost));for(unsigned i=0;i<12;i++)if(got[i]!=params[i])return 9;words+=12;\n", .{@intFromEnum(P.domain(slot))});
        try w.print("projection_{d}_equation<<<1,32,0,stream>>>(dm,nullptr,di,dp,dout,8,8,dpow,dd,8);CHECK(cudaGetLastError());CHECK(cudaStreamSynchronize(stream));CHECK(cudaMemcpy(got,dout,128,cudaMemcpyDeviceToHost));for(unsigned i=0;i<32;i++)if(got[i]){{fprintf(stderr,\"equation slot{d} word%u got%u\\n\",i,got[i]);return 5;}}words+=32;\n", .{ id, id });
        const changed = mean.add(Q.one()).toM31Array();
        var change: [4]u32 = undefined;
        for (changed, 0..) |v, i| change[i] = v.v;
        try array(w, "changed", &change);
        try w.print("CHECK(cudaMemcpy(dp+8,changed,16,cudaMemcpyHostToDevice));projection_{d}_equation<<<1,32,0,stream>>>(dm,nullptr,di,dp,dout,8,8,dpow,dd,8);CHECK(cudaGetLastError());CHECK(cudaStreamSynchronize(stream));CHECK(cudaMemcpy(got,dout,128,cudaMemcpyDeviceToHost));for(unsigned i=0;i<32;i++)if(got[i]!=want_forged[i])return 6;words+=32;attacks++;CHECK(cudaMemcpy(&status,dstatus,4,cudaMemcpyDeviceToHost));if(status)return 7;\n", .{id});
        // Active or inactive zero denominator is rejected exactly as original inv().
        try w.writeAll("CHECK(cudaMemset(df+32,0,128));CHECK((cudaError_t)stwo_native_projection_interactions_on(df,di,(RiscvQm31*)ds,dstatus,8,stream));CHECK(cudaStreamSynchronize(stream));CHECK(cudaMemcpy(&status,dstatus,4,cudaMemcpyDeviceToHost));if(!(status&2))return 8;attacks++;CHECK(cudaFree(dm));CHECK(cudaFree(dp));CHECK(cudaFree(df));CHECK(cudaFree(di));CHECK(cudaFree(ds));CHECK(cudaFree(dstatus));CHECK(cudaFree(dout));CHECK(cudaFree(dpow));CHECK(cudaFree(dd));CHECK(cudaStreamDestroy(stream));}\n");
    }
    try w.print("CHECK(cudaFree(ddraw));printf(\"PASS native physical projections slots={d} words=%u attacks=%u\\n\",words,attacks);return 0;}}\n", .{slots.items.len});
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(source.written());
}
test "resident native projection CUDA oracle export" {
    const path = std.process.getEnvVarOwned(std.testing.allocator, "STWO_NATIVE_PROJECTION_CUDA") catch |err| if (err == error.EnvironmentVariableNotFound) return else return err;
    defer std.testing.allocator.free(path);
    try exportOracle(std.testing.allocator, path);
}
