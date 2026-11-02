//! Cold OM31 composition code generation. No runtime compiler or proof fallback.
//! Input masks retain the global lifted-domain semantics of the native AIR.
const std = @import("std");
const core = @import("stwo_core");
pub const ir = @import("stwo_prover_engine").air.secure_polynomial_program_v2;
pub const O = core.fields.om31.OM31;
pub const Program = ir.ProgramFor(O);
const sources = @import("stwo_cuda_backend").rv64_numerical_sources;
pub fn identity(program: *const Program) ![32]u8 {
    try program.validate();
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/rv64/cuda/om31-composition/v1\x00");
    h.update(&program.identity);
    h.update(@embedFile("composition_codegen.zig"));
    h.update(sources.composition);
    h.update(sources.om31);
    h.update(sources.quartic);
    return h.finalResult();
}
pub fn kernelName(a: std.mem.Allocator, program: *const Program) ![]u8 {
    return std.fmt.allocPrint(a, "stwo_rv64_composition_{s}", .{std.fmt.bytesToHex(try identity(program), .lower)});
}
/// Iterative root-first postorder. Load masks close to their first use instead
/// of starting with every input column live; no recursive stack at large DAGs.
pub fn schedule(a: std.mem.Allocator, program: *const Program) ![]u32 {
    const seen = try a.alloc(bool, program.nodes.len);
    defer a.free(seen);
    @memset(seen, false);
    const stack = try a.alloc(u32, program.nodes.len);
    defer a.free(stack);
    var order: std.ArrayList(u32) = .empty;
    errdefer order.deinit(a);
    for (program.roots) |root| {
        var top: usize = 1;
        stack[0] = root;
        while (top != 0) {
            const index = stack[top - 1];
            if (seen[index]) {
                top -= 1;
                continue;
            }
            const node = program.nodes[index];
            const binary = node.op == .add or node.op == .sub or node.op == .mul;
            if ((binary or node.op == .neg) and !seen[node.lhs]) {
                stack[top] = node.lhs;
                top += 1;
                continue;
            }
            if (binary and !seen[node.rhs]) {
                stack[top] = node.rhs;
                top += 1;
                continue;
            }
            seen[index] = true;
            try order.append(a, index);
            top -= 1;
        }
    }
    return order.toOwnedSlice(a);
}
/// Geometry, all pointer ranges, column offsets and aliasing must be checked by
/// the invocation owner before enqueue. This emits the numerical kernel only.
/// Parameters/powers are AoS OM31; columns and result are coordinate-major M31.
/// Each invocation owns a disjoint output range or is ordered on one lane.
pub fn emit(a: std.mem.Allocator, w: anytype, program: *const Program, name: []const u8) !void {
    try program.validate();
    if (name.len == 0 or std.ascii.isDigit(name[0])) return error.InvalidKernelName;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidKernelName;
    const sorts = try program.sorts(a);
    defer a.free(sorts);
    // Emit each residual's RLC term as soon as its node is produced. Waiting
    // until the end keeps thousands of residual values live in wide providers.
    const head = try a.alloc(u32, program.nodes.len);
    defer a.free(head);
    @memset(head, std.math.maxInt(u32));
    const next = try a.alloc(u32, program.roots.len);
    defer a.free(next);
    for (program.roots, 0..) |root, j| {
        next[j] = head[root];
        head[root] = @intCast(j);
    }
    try w.writeAll("#include \"rv64/composition.cuh\"\nusing namespace stwo::cuda::rv64;\n");
    try w.print(
        \\extern "C" __global__ void {s}(const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,
        \\const uint64_t *column_offsets,const uint32_t *parameters,const uint32_t *powers,
        \\const uint32_t *denominator_inverses,uint32_t *output,uint32_t trace_log,uint32_t eval_log,
        \\uint32_t first_row,uint32_t rows) {{
        \\ const uint32_t local=blockIdx.x*blockDim.x+threadIdx.x;
        \\ if(local>=rows) return;
        \\ const uint32_t row=first_row+local;
        \\ OM31 folded=zero();
        \\
    , .{name});
    const order = try schedule(a, program);
    defer a.free(order);
    for (order) |i| {
        const node = program.nodes[i];
        const sort = sorts[i];
        if (node.op == .input) {
            const in = program.inputs[node.value];
            try w.print(" const uint32_t v{}=tree{}[column_offsets[{}]+composition_mask_row(row,trace_log,eval_log,{})];\n", .{ i, in.tree, node.value, in.offset });
        } else try emitValue(w, program, sorts, i);
        var root = head[i];
        while (root != std.math.maxInt(u32)) : (root = next[root]) {
            const power = 8 * (program.roots.len - 1 - root);
            if (sort == .base) try w.print(" folded=add(folded,scale(from_words(powers+{}u),v{}));\n", .{ power, i }) else try w.print(" folded=add(folded,mul(from_words(powers+{}u),v{}));\n", .{ power, i });
        }
    }
    try w.writeAll(
        \\ const OM31 result=scale(folded,denominator_inverses[row>>trace_log]);
        \\ const uint64_t stride=uint64_t(1)<<eval_log;
        \\ store(output,stride,row,add(load(output,stride,row),result));
        \\}
        \\
    );
}

/// Emit one arithmetic DAG node. Callers own input addressing and output laws.
pub fn emitValue(w: anytype, program: *const Program, sorts: []const ir.Sort, i: u32) !void {
    const node = program.nodes[i];
    const sort = sorts[i];
    switch (node.op) {
        .input => unreachable,
        .constant => {
            const words = program.constants[node.value];
            if (sort == .base) {
                try w.print(" const uint32_t v{}={}u;\n", .{ i, words[0] });
            } else {
                try w.print(" const uint32_t c{}[8]={{{}u,{}u,{}u,{}u,{}u,{}u,{}u,{}u}};\n", .{ i, words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7] });
                try w.print(" const OM31 v{}=from_words(c{});\n", .{ i, i });
            }
        },
        .parameter => try w.print(" const OM31 v{}=from_words(parameters+{}u);\n", .{ i, 8 * node.value }),
        .neg => if (sort == .base) {
            try w.print(" const uint32_t v{}=q::sub(0u,v{});\n", .{ i, node.lhs });
        } else {
            try w.print(" const OM31 v{}=sub(zero(),v{});\n", .{ i, node.lhs });
        },
        .add, .sub, .mul => {
            if (sort == .base) {
                try w.print(" const uint32_t v{}=q::{s}(v{},v{});\n", .{ i, @tagName(node.op), node.lhs, node.rhs });
            } else if (node.op == .mul and sorts[node.lhs] != sorts[node.rhs]) {
                try w.print(" const OM31 v{}=scale(v{},v{});\n", .{ i, if (sorts[node.lhs] == .secure) node.lhs else node.rhs, if (sorts[node.lhs] == .base) node.lhs else node.rhs });
            } else {
                try w.print(" const OM31 v{}={s}(", .{ i, @tagName(node.op) });
                if (sorts[node.lhs] == .base) try w.print("base(v{})", .{node.lhs}) else try w.print("v{}", .{node.lhs});
                try w.writeAll(",");
                if (sorts[node.rhs] == .base) try w.print("base(v{})", .{node.rhs}) else try w.print("v{}", .{node.rhs});
                try w.writeAll(");\n");
            }
        },
        .fraction, .range_fraction => unreachable,
    }
}

/// OODS masks are extension-field values. Recompute the DAG sorts with secure
/// inputs rather than reusing the base-field domain lowering. Every input is
/// the separately authenticated mask in Program.inputs order (AoS, eight words).
/// The caller owns transcript ordering, mask authentication and pointer ranges.
pub fn emitOods(a: std.mem.Allocator, w: anytype, program: *const Program, name: []const u8) !void {
    try program.validate();
    if (name.len == 0 or std.ascii.isDigit(name[0])) return error.InvalidKernelName;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_') return error.InvalidKernelName;
    const sorts = try program.sorts(a);
    defer a.free(sorts);
    for (program.nodes, sorts) |node, *sort| switch (node.op) {
        .input => sort.* = .secure,
        .add, .sub, .mul => sort.* = if (sorts[node.lhs] == .secure or sorts[node.rhs] == .secure) .secure else .base,
        .neg => sort.* = sorts[node.lhs],
        else => {},
    };
    const order = try schedule(a, program);
    defer a.free(order);
    // Streaming root accumulation keeps the same native reverse RLC ordering.
    const heads = try a.alloc(u32, program.nodes.len);
    defer a.free(heads);
    @memset(heads, std.math.maxInt(u32));
    const next = try a.alloc(u32, program.roots.len);
    defer a.free(next);
    for (program.roots, 0..) |root, j| {
        next[j] = heads[root];
        heads[root] = @intCast(j);
    }
    try w.writeAll("#include \"rv64/composition.cuh\"\nusing namespace stwo::cuda::rv64;\n");
    try w.print("extern \"C\" __global__ void {s}(const uint32_t *inputs,const uint32_t *parameters,const uint32_t *powers,const uint32_t *inverse,uint32_t *output) {{\n if(blockIdx.x || threadIdx.x) return;\n OM31 folded=zero();\n", .{name});
    for (order) |i| {
        const node = program.nodes[i];
        if (node.op == .input) {
            try w.print(" const OM31 v{}=from_words(inputs+{}u);\n", .{ i, 8 * node.value });
        } else try emitValue(w, program, sorts, i);
        var root = heads[i];
        while (root != std.math.maxInt(u32)) : (root = next[root]) {
            const power = 8 * (program.roots.len - 1 - root);
            if (sorts[i] == .base) try w.print(" folded=add(folded,scale(from_words(powers+{}u),v{}));\n", .{ power, i }) else try w.print(" folded=add(folded,mul(from_words(powers+{}u),v{}));\n", .{ power, i });
        }
    }
    try w.writeAll(" store(output,1,0,add(load(output,1,0),mul(folded,from_words(inverse))));\n}\n");
}
