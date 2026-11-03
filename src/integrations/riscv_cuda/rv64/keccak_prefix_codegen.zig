//! Numerical-only Keccak prefix lowering. The native constraint list, masks,
//! transcript and reverse RLC powers remain unchanged. One long additive
//! prefix is evaluated beside the inverse checks that already need its DAG.
const std = @import("std");
const C = @import("composition_codegen.zig");
const A = @import("stwo_riscv_frontend").rv64_air;
pub const group_size = 32;
pub const inverse_first = A.crypto.keccak.layout.DIRECT;
pub const inverse_count = (A.crypto.keccak.batch_policy.THROUGHPUT_LOOKUPS + 2) / 3;
pub const prefix_root = inverse_first + inverse_count;
pub const first_group = inverse_first / group_size;
pub const last_group = prefix_root / group_size;
pub const Plan = struct {
    rest: u32,
    terms: [inverse_count]u32,
    pub fn init(p: *const C.Program) !Plan {
        try p.validate();
        if (p.roots.len != 5650 or prefix_root != 5596) return error.UnexpectedKeccakPrefixAuthority;
        const root = p.nodes[p.roots[prefix_root]];
        if (root.op != .sub) return error.UnexpectedKeccakPrefixAuthority;
        var out = Plan{ .rest = root.lhs, .terms = undefined };
        var remaining = root.rhs;
        var i: usize = inverse_count;
        while (i > 1) {
            i -= 1;
            const n = p.nodes[remaining];
            if (n.op != .add) return error.UnexpectedKeccakPrefixAuthority;
            const left = matches(p, n.lhs, i);
            const right = matches(p, n.rhs, i);
            if (left == right) return error.UnexpectedKeccakPrefixAuthority;
            out.terms[i] = if (left) n.lhs else n.rhs;
            remaining = if (left) n.rhs else n.lhs;
        }
        if (!matches(p, remaining, 0)) return error.UnexpectedKeccakPrefixAuthority;
        out.terms[0] = remaining;
        return out;
    }
    fn matches(p: *const C.Program, term: u32, batch: usize) bool {
        const n = p.nodes[term];
        const check = p.nodes[p.roots[inverse_first + batch]];
        if (n.op != .mul or check.op != .sub) return false;
        const lhs = p.nodes[check.lhs];
        if (lhs.op != .mul) return false;
        return (n.lhs == lhs.lhs or n.lhs == lhs.rhs) != (n.rhs == lhs.lhs or n.rhs == lhs.rhs);
    }
};
fn emitChunk(a: std.mem.Allocator, w: anytype, p: *const C.Program, name: []const u8, group: usize, chunk: usize, plan: *const Plan) !void {
    const first = group * group_size + chunk * 8;
    const end = @min(p.roots.len, first + 8);
    const sorts = try p.sorts(a);
    defer a.free(sorts);
    var roots: std.ArrayList(u32) = .empty;
    defer roots.deinit(a);
    for (first..end) |r| {
        try roots.append(a, if (r == prefix_root) plan.rest else p.roots[r]);
        if (r >= inverse_first and r < prefix_root) try roots.append(a, plan.terms[r - inverse_first]);
    }
    var subset = p.*;
    subset.roots = roots.items;
    const order = try C.schedule(a, &subset);
    defer a.free(order);
    try w.print("__device__ __noinline__ OM31 {s}_prefix_{}_{}(const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,const uint64_t *column_offsets,const uint32_t *parameters,const uint32_t *powers,const uint32_t *denominator_inverses,uint32_t *output,uint32_t trace_log,uint32_t eval_log,uint32_t row){{\n OM31 folded=zero(),prefix_contribution=zero();\n", .{ name, group, chunk });
    for (order) |i| {
        const node = p.nodes[i];
        if (node.op == .input) {
            const input = p.inputs[node.value];
            try w.print(" const uint32_t v{}=tree{}[column_offsets[{}]+composition_mask_row(row,trace_log,eval_log,{})];\n", .{ i, input.tree, node.value, input.offset });
        } else try C.emitValue(w, p, sorts, i);
        for (first..end) |r| if ((if (r == prefix_root) plan.rest else p.roots[r]) == i) {
            const power = 8 * (p.roots.len - 1 - r);
            if (sorts[i] == .base) try w.print(" folded=add(folded,scale(from_words(powers+{}u),v{}));\n", .{ power, i }) else try w.print(" folded=add(folded,mul(from_words(powers+{}u),v{}));\n", .{ power, i });
        };
        for (first..end) |r| if (r >= inverse_first and r < prefix_root and plan.terms[r - inverse_first] == i) {
            if (sorts[i] != .secure) return error.UnexpectedKeccakPrefixAuthority;
            try w.print(" prefix_contribution=add(prefix_contribution,v{});\n", .{i});
        };
    }
    if (end > inverse_first and first < prefix_root) try w.print(" folded=sub(folded,mul(from_words(powers+{}u),prefix_contribution));\n", .{8 * (p.roots.len - 1 - prefix_root)});
    try w.writeAll(" return folded;\n}\n");
}
fn emitPart(a: std.mem.Allocator, w: anytype, p: *const C.Program, name: []const u8, group: usize, plan: *const Plan) !void {
    try w.print("// RV64_KECCAK_PREFIX_GROUP_BEGIN {}\n", .{group});
    for (0..4) |chunk| try emitChunk(a, w, p, name, group, chunk, plan);
    try w.print("__device__ __noinline__ void {s}_part_{}(const uint32_t *tree0,const uint32_t *tree1,const uint32_t *tree2,const uint64_t *column_offsets,const uint32_t *parameters,const uint32_t *powers,const uint32_t *denominator_inverses,uint32_t *output,uint32_t trace_log,uint32_t eval_log,uint32_t row){{\n OM31 folded=zero();\n", .{ name, group });
    for (0..4) |chunk| try w.print(" folded=add(folded,{s}_prefix_{}_{}(tree0,tree1,tree2,column_offsets,parameters,powers,denominator_inverses,output,trace_log,eval_log,row));\n", .{ name, group, chunk });
    try w.writeAll(" const OM31 result=scale(folded,denominator_inverses[row>>trace_log]); const uint64_t stride=uint64_t(1)<<eval_log;\n");
    for (0..8) |coordinate| try w.print(" {s}_add(output+{}u*stride+row,coordinate(result,{}u));\n", .{ name, coordinate, coordinate });
    try w.print("}}\n// RV64_KECCAK_PREFIX_GROUP_END {}\n", .{group});
}

pub fn emit(a: std.mem.Allocator, w: anytype, p: *const C.Program, name: []const u8) !void {
    const plan = try Plan.init(p);
    var original: std.ArrayList(u8) = .empty;
    defer original.deinit(a);
    try C.emitGrouped(a, original.writer(a), p, name, group_size);
    var offset: usize = 0;
    for (first_group..last_group + 1) |group| {
        const marker = try std.fmt.allocPrint(a, "__device__ __noinline__ void {s}_part_{}(", .{ name, group });
        defer a.free(marker);
        const start = std.mem.indexOfPos(u8, original.items, offset, marker) orelse return error.MissingKeccakPrefixGroup;
        const end = std.mem.indexOfPos(u8, original.items, start + marker.len, "__device__ __noinline__ void ") orelse return error.MissingKeccakPrefixGroup;
        try w.writeAll(original.items[offset..start]);
        try emitPart(a, w, p, name, group, &plan);
        offset = end;
    }
    try w.writeAll(original.items[offset..]);
}
test "Keccak prefix distribution preserves original constraint power and root authority" {
    const a = std.testing.allocator;
    var item = try @import("truth_domain_fixtures.zig").record(a, 0);
    defer item.artifact.deinit();
    const p = &item.artifact.program;
    const plan = try Plan.init(p);
    var roots: [inverse_count + 1]u32 = undefined;
    roots[0] = plan.rest;
    @memcpy(roots[1..], &plan.terms);
    var probe = p.*;
    probe.roots = &roots;
    probe.identity = probe.identityDigest();
    var rng = std.Random.DefaultPrng.init(0x627317);
    const input = try a.alloc(C.O, p.inputs.len);
    defer a.free(input);
    for (0..3) |round| {
        for (input) |*v| {
            var limbs: [8]@import("stwo_core").fields.m31.M31 = undefined;
            for (&limbs) |*limb| limb.* = @import("stwo_core").fields.m31.M31.fromCanonical(if (round == 0) 0 else if (round == 1) 1 else rng.random().uintLessThan(u32, 0x7fffffff));
            v.* = C.O.fromM31Array(limbs);
        }
        const expected = try p.evaluate(a, input);
        defer a.free(expected);
        const parts = try probe.evaluate(a, input);
        defer a.free(parts);
        var actual = parts[0];
        for (parts[1..]) |term| actual = actual.sub(term);
        try std.testing.expect(actual.eql(expected[prefix_root]));
    }
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(a);
    try emit(a, text.writer(a), p, "rv64_truth_domain_0");
    try std.testing.expectEqual(@as(usize, 20), std.mem.count(u8, text.items, "from_words(powers+424u)"));
}
