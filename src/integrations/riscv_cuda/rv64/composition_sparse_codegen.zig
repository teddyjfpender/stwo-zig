//! Numerical source for one source-validated signed-cover group. No new AIR.
const std = @import("std");
const C = @import("composition_codegen.zig");
const P = @import("composition_sparse.zig");
pub fn emit(a: std.mem.Allocator, w: anytype, p: *const C.Program, plan: *const P.Plan, group: u32, name: []const u8) !void {
    if (group >= plan.groups.len or name.len == 0) return error.InvalidSparseKernel;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidSparseKernel;
    const g = plan.groups[group];
    const terms = plan.terms[g.first..g.end];
    const roots = try a.alloc(u32, terms.len);
    defer a.free(roots);
    for (roots, terms) |*root, t| root.* = t.node;
    var subset = p.*;
    subset.roots = roots;
    const order = try C.schedule(a, &subset);
    defer a.free(order);
    const sorts = try p.sorts(a);
    defer a.free(sorts);
    const head = try a.alloc(u32, p.nodes.len);
    defer a.free(head);
    @memset(head, std.math.maxInt(u32));
    const next = try a.alloc(u32, terms.len);
    defer a.free(next);
    for (terms, 0..) |t, i| {
        next[i] = head[t.node];
        head[t.node] = @intCast(i);
    }
    try w.writeAll("#include \"rv64/composition.cuh\"\nusing namespace stwo::cuda::rv64;\n");
    try w.print("__device__ __noinline__ void {s}_part_0(const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,const uint64_t *column_offsets,const uint32_t *parameters,const uint32_t *powers,const uint32_t *denominator_inverses,uint32_t *output,uint32_t trace_log,uint32_t eval_log,uint32_t row){{\n OM31 folded=zero();\n", .{name});
    for (order) |i| {
        const n = p.nodes[i];
        if (n.op == .input) {
            const input = p.inputs[n.value];
            try w.print("const uint32_t v{}=tree{}[column_offsets[{}]+composition_mask_row(row,trace_log,eval_log,{})];\n", .{ i, input.tree, n.value, input.offset });
        } else try C.emitValue(w, p, sorts, i);
        var term = head[i];
        while (term != std.math.maxInt(u32)) : (term = next[term]) {
            const t = terms[term];
            const offset = 8 * (p.roots.len - 1 - t.root);
            try w.print("folded=add(folded,{s}(from_words(powers+{}u),", .{ if (sorts[i] == .base) "scale" else "mul", offset });
            if (t.negative) try w.print("{s}({s},v{})", .{ if (sorts[i] == .base) "q::sub" else "sub", if (sorts[i] == .base) "0u" else "zero()", i }) else try w.print("v{}", .{i});
            try w.writeAll("));\n");
        }
    }
    // Groups are ordered on one owner stream. Each kernel owns every row;
    // no atomics, host accumulators or intermediary quotient commitments.
    try w.writeAll("const OM31 result=scale(folded,denominator_inverses[row>>trace_log]);const uint64_t stride=uint64_t(1)<<eval_log;store(output,stride,row,add(load(output,stride,row),result));}\n");
    try w.print("extern \"C\" __global__ void {s}(const uint32_t *a,const uint32_t *b,const uint32_t *c,const uint64_t *offsets,const uint32_t *p,const uint32_t *powers,const uint32_t *inv,uint32_t *out,uint32_t tl,uint32_t el,uint32_t first,uint32_t rows){{uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=rows)return;{s}_part_0(a,b,c,offsets,p,powers,inv,out,tl,el,first+i);}}\n", .{ name, name });
}
