//! Cold CUDA export of ORIGINAL native direct equations. This is a kernel
//! building block, not native-proof admission or a resident prover receipt.
//! Both legacy and x0 programs come from the production symbolic exporters.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Types = engine.air.component_prover;
const Emitter = engine.air.framework_polynomial_emitter_v1;
const Backend = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const Trace = @import("../../frontends/riscv/runner/trace.zig");
const Runtime = @import("../../frontends/riscv/air/extract/runtime_program.zig");
const X0 = @import("../../frontends/riscv/air/x0_native_envelope_v1.zig");
const Semantic = @import("../../frontends/riscv/air/semantic_eval.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;

pub const ARGUMENT_COUNT: u32 = 8;
pub const preamble = Backend.preamble;
pub fn program(a: std.mem.Allocator, family: Trace.OpcodeFamily, local_zero: bool) !Types.OwnedBasePolynomialProgram {
    return if (local_zero) X0.directProgram(a, family) else Runtime.build(a, family);
}

/// Same admitted base DAG, root order, secure powers and denominator convention
/// as the shared framework emitter. The temporary printer view is deliberately
/// NOT admitted as a framework component: no dummy lookup/claim is introduced.
pub fn emit(a: std.mem.Allocator, writer: anytype, name: []const u8, p: *const Types.OwnedBasePolynomialProgram) !void {
    try p.validate();
    if (p.column_count < 2 or p.column_count > Trace.MAX_FAMILY_COLUMNS + 1 or name.len == 0) return error.InvalidNativeDirectKernel;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidNativeDirectKernel;
    for (p.nodes) |n| if (n.op == .constant and n.value >= core.fields.m31.Modulus) return error.InvalidNativeDirectKernel;
    const inputs = try a.alloc(Types.TypedPolynomialInputV1, p.column_count);
    defer a.free(inputs);
    for (inputs[0 .. inputs.len - 1], 0..) |*input, i| input.* = .{ .trace_column = .{ .tree_index = 1, .column_index = @intCast(i) } };
    inputs[inputs.len - 1] = .{ .trace_column = .{ .tree_index = 0, .column_index = 0 } };
    const view = Types.OwnedFrameworkPolynomialProgramV1{
        .allocator = a,
        .semantic_digest = @splat(0),
        .registry_order_digest = @splat(0),
        .direct = p.*,
        .lookup_nodes = &.{},
        .entries = &.{},
        .batches = &.{},
        .inputs = inputs,
        .interaction_columns = &.{},
        .profile_parameter_count = 0,
        .layout = .same_row_prefix_v1,
        .identity = @splat(0),
    };
    try writer.print(
        \\extern "C" __global__ void {s}(const uint *tree0,const uint *tree1,
        \\ const ulong *column_offsets,const uint *powers,uint *output,uint row_count,
        \\ const uint *denominator_inverses,uint denominator_count){{
        \\ uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=row_count)return;
        \\ RiscvQm31 folded={{0u,0u,0u,0u}};
        \\
    , .{name});
    try Emitter.emitBody(a, writer, &view);
}

pub fn identity(a: std.mem.Allocator, p: *const Types.OwnedBasePolynomialProgram) ![32]u8 {
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    try emit(a, &source.writer, "stwo_native_direct_canonical_v1", p);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-resident-native-direct-v1");
    hash.update(preamble);
    hash.update(source.written());
    return hash.finalResult();
}

/// Standalone numerical oracle source. The host expected values are computed
/// by the ORIGINAL scalar evaluator, not by replaying the exported DAG.
pub fn exportOracle(a: std.mem.Allocator, path: []const u8) !void {
    var source: std.Io.Writer.Allocating = .init(a);
    defer source.deinit();
    const w = &source.writer;
    try w.writeAll("#include <cuda_runtime.h>\n#include <cstdio>\n#include <cstdlib>\n#include <vector>\n");
    try w.writeAll(preamble);
    for ([_]bool{ false, true }, 0..) |local_zero, recipe| for (0..Trace.N_FAMILIES) |fi| {
        var p = try program(a, @enumFromInt(fi), local_zero);
        defer p.deinit();
        const name = try std.fmt.allocPrint(a, "native_direct_{d}_{d}", .{ recipe, fi });
        defer a.free(name);
        try emit(a, w, name, &p);
    };
    try w.writeAll("#define CHECK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,\"CUDA %s line %d\\n\",cudaGetErrorString(e),__LINE__);return 2;}}while(0)\nint main(){unsigned words=0;\n");
    for ([_]bool{ false, true }, 0..) |local_zero, recipe| for (0..Trace.N_FAMILIES) |fi| {
        const family: Trace.OpcodeFamily = @enumFromInt(fi);
        var p = try program(a, family, local_zero);
        defer p.deinit();
        const width = p.column_count - 1;
        try w.print("{{constexpr unsigned rows=8,width={d},constraints={d};std::vector<uint> main(width*rows),selector(rows),powers(constraints*4),out(32),inverse(rows,1);std::vector<ulong> offsets(width+1);\n", .{ width, p.roots.len });
        try w.writeAll("for(unsigned c=0;c<width;c++){offsets[c]=c*rows;for(unsigned r=0;r<rows;r++)main[c*rows+r]=(c*8191u+r*65521u+17u)%2147483647u;}offsets[width]=0;for(unsigned r=0;r<rows;r++)selector[r]=r*19u+3u;for(unsigned i=0;i<constraints*4;i++)powers[i]=i*7u+11u;\n");
        const expected = try a.alloc(u32, 32);
        defer a.free(expected);
        const cells = try a.alloc(Q, width);
        defer a.free(cells);
        for (0..8) |row| {
            for (cells, 0..) |*cell, column| cell.* = Q.fromBase(M.fromU64(column * 8191 + row * 65521 + 17));
            var original: Semantic.Eval(Q).RecipeEvaluation = undefined;
            try Semantic.Eval(Q).evaluateForRecipeInto(family, cells, Q.fromBase(M.fromU64(row * 19 + 3)), local_zero, &original);
            var value = Q.zero();
            for (original.values[0..original.len], 0..) |constraint, ordinal| {
                const base = 4 * (original.len - 1 - ordinal);
                const power = Q.fromM31Array(.{ M.fromU64(base * 7 + 11), M.fromU64((base + 1) * 7 + 11), M.fromU64((base + 2) * 7 + 11), M.fromU64((base + 3) * 7 + 11) });
                value = value.add(constraint.mul(power));
            }
            for (value.toM31Array(), 0..) |limb, j| expected[j * 8 + row] = limb.toU32();
        }
        try w.writeAll("const uint expected[32]={");
        for (expected, 0..) |value, i| try w.print("{s}{d}u", .{ if (i == 0) "" else ",", value });
        try w.writeAll("};uint *dm,*ds,*dp,*di,*dout;ulong*offset;CHECK(cudaMalloc(&dm,main.size()*4));CHECK(cudaMalloc(&ds,32));CHECK(cudaMalloc(&dp,powers.size()*4));CHECK(cudaMalloc(&di,32));CHECK(cudaMalloc(&dout,128));CHECK(cudaMalloc(&offset,offsets.size()*8));CHECK(cudaMemcpy(dm,main.data(),main.size()*4,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(ds,selector.data(),32,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(dp,powers.data(),powers.size()*4,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(di,inverse.data(),32,cudaMemcpyHostToDevice));CHECK(cudaMemcpy(offset,offsets.data(),offsets.size()*8,cudaMemcpyHostToDevice));CHECK(cudaMemset(dout,0,128));\n");
        try w.print("native_direct_{d}_{d}<<<1,32>>>(ds,dm,offset,dp,dout,8,di,8);CHECK(cudaGetLastError());CHECK(cudaMemcpy(out.data(),dout,128,cudaMemcpyDeviceToHost));for(unsigned i=0;i<32;i++)if(out[i]!=expected[i]){{fprintf(stderr,\"FAIL recipe={d} family={d} word=%u got=%u expected=%u\\n\",i,out[i],expected[i]);return 3;}}words+=32;\n", .{ recipe, fi, recipe, fi });
        try w.writeAll("CHECK(cudaFree(dm));CHECK(cudaFree(ds));CHECK(cudaFree(dp));CHECK(cudaFree(di));CHECK(cudaFree(dout));CHECK(cudaFree(offset));}\n");
    };
    try w.writeAll("printf(\"PASS native direct GPU all17 bothrecipes words=%u\\n\",words);return 0;}\n");
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll(source.written());
}

fn replay(a: std.mem.Allocator, p: *const Types.OwnedBasePolynomialProgram, inputs: []const Q) ![]Q {
    if (inputs.len != p.column_count) return error.InvalidNativeDirectInput;
    const values = try a.alloc(Q, p.nodes.len);
    defer a.free(values);
    for (p.nodes, values) |node, *out| out.* = switch (node.op) {
        .constant => Q.fromBase(M.fromCanonical(node.value)),
        .column => inputs[node.value],
        .add => values[node.lhs].add(values[node.rhs]),
        .sub => values[node.lhs].sub(values[node.rhs]),
        .mul => values[node.lhs].mul(values[node.rhs]),
        .neg => values[node.lhs].neg(),
    };
    const roots = try a.alloc(Q, p.roots.len);
    for (p.roots, roots) |root, *out| out.* = values[root];
    return roots;
}

test "resident native direct export preserves all original roots and x0 recipes" {
    const a = std.testing.allocator;
    for ([_]bool{ false, true }) |local_zero| for (0..Trace.N_FAMILIES) |fi| {
        const family: Trace.OpcodeFamily = @enumFromInt(fi);
        var p = try program(a, family, local_zero);
        defer p.deinit();
        const inputs = try a.alloc(Q, p.column_count);
        defer a.free(inputs);
        for (0..3) |trial| {
            for (inputs, 0..) |*value, i| value.* = Q.fromM31Array(.{ M.fromU64(i * 13 + trial), M.fromU64(i + 19), M.fromU64(2 * i + 31), M.fromU64(trial + 43) });
            var original: Semantic.Eval(Q).RecipeEvaluation = undefined;
            try Semantic.Eval(Q).evaluateForRecipeInto(family, inputs[0 .. inputs.len - 1], inputs[inputs.len - 1], local_zero, &original);
            const roots = try replay(a, &p, inputs);
            defer a.free(roots);
            try std.testing.expectEqual(original.len, roots.len);
            for (roots, original.values[0..original.len]) |actual, expected| try std.testing.expect(actual.eql(expected));
        }
        var source: std.Io.Writer.Allocating = .init(a);
        defer source.deinit();
        try emit(a, &source.writer, "native_direct_test", &p);
        try std.testing.expect(std.mem.indexOf(u8, source.written(), "relation_parameters") == null);
        const before = try identity(a, &p);
        const old_root = p.roots[0];
        p.roots[0] = if (old_root == 0) 1 else 0;
        try std.testing.expect(!std.mem.eql(u8, &before, &try identity(a, &p)));
        p.roots[0] = old_root;
    };
}
