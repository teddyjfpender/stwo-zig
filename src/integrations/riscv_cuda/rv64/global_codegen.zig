//! Global paired fractions lowered from the same tuple emitters as native AIR.
//! Roots are N,D pairs; RAM and KIO/Wire retain separate centered claims.
const std = @import("std");
const J = @import("joined_codegen.zig");
const C = @import("composition_codegen.zig");
const X = @import("symbolic_external.zig");
const F = X.Lane;
pub const P = J.Parameters;
pub const Authority = J.Authority;
pub const Source = J.Source;
pub const Collector = struct {
    ram_n: [58]F = undefined,
    ram_d: [58]F = undefined,
    other_n: [50]F = undefined,
    other_d: [50]F = undefined,
    ram_count: usize = 0,
    other_count: usize = 0,
    invalid: bool = false,
    pub fn emit(self: *@This(), relation: Authority.Global.Relation, tuple: anytype, weight: F) void {
        const slot: u32 = switch (relation) {
            .ram => P.ram,
            .kio => P.kio,
            .wire => P.wire,
        };
        const expected: usize = switch (relation) {
            .ram => 14,
            .kio => 11,
            .wire => 35,
        };
        if (tuple.len != expected) {
            self.invalid = true;
            return;
        }
        var d = F.parameter(slot);
        for (tuple, 0..) |v, i| d = d.sub(F.parameter(slot + 1 + @as(u32, @intCast(i))).mul(v));
        if (relation == .ram) {
            if (self.ram_count == self.ram_n.len) {
                self.invalid = true;
                return;
            }
            self.ram_n[self.ram_count] = weight;
            self.ram_d[self.ram_count] = d;
            self.ram_count += 1;
        } else {
            if (self.other_count == self.other_n.len) {
                self.invalid = true;
                return;
            }
            self.other_n[self.other_count] = weight;
            self.other_d[self.other_count] = d;
            self.other_count += 1;
        }
    }
};
pub const Artifact = struct {
    a: std.mem.Allocator,
    descriptor: Source.Descriptor,
    program: C.Program,
    parameter_slots: []u32,
    ram_pairs: u32,
    other_pairs: u32,
    pub fn deinit(self: *@This()) void {
        self.program.deinit();
        self.a.free(self.parameter_slots);
        self.* = undefined;
    }
    pub fn identity(self: *const @This()) ![32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/cuda/global-native-pairs/v1");
        h.update(&self.program.identity);
        h.update(@embedFile("global_codegen.zig"));
        h.update(@embedFile("symbolic_external.zig"));
        for (self.parameter_slots) |slot| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, slot, .little);
            h.update(&bytes);
        }
        return h.finalResult();
    }
};
fn appendPairs(roots: *std.ArrayList(u32), a: std.mem.Allocator, n: []const F, d: []const F) !void {
    var i: usize = 0;
    while (i < n.len) : (i += 2) {
        const paired = i + 1 < n.len;
        const numerator = if (paired) n[i].mul(d[i + 1]).add(n[i + 1].mul(d[i])) else n[i];
        const denominator = if (paired) d[i].mul(d[i + 1]) else d[i];
        try roots.appendSlice(a, &.{ numerator.id, denominator.id });
    }
}
pub fn record(a: std.mem.Allocator, descriptor: Source.Descriptor) !Artifact {
    const shape = try Authority.shape(descriptor);
    const layout = Authority.Global.layout(descriptor.origin);
    if (layout.ram_queries == 0) return error.MissingGlobalRole;
    var r = X.Recording.init(a);
    defer r.deinit();
    r.begin();
    defer r.end();
    const fixed = try a.alloc(F, shape.fixed);
    defer a.free(fixed);
    const main = try a.alloc(F, shape.main);
    defer a.free(main);
    for (fixed, 0..) |*v, i| v.* = F.input(0, i, 0);
    for (main, 0..) |*v, i| v.* = F.input(1, i, 0);
    var sink = Collector{};
    try Authority.emitGlobalQueries(descriptor, F, fixed, main, F.parameter(P.source_public + Source.Public.sponge_first_id), &sink);
    if (sink.invalid or sink.ram_count != layout.ram_queries or sink.other_count != layout.other_queries) return error.InvalidGlobalQueryCount;
    var roots: std.ArrayList(u32) = .empty;
    defer roots.deinit(a);
    try appendPairs(&roots, a, sink.ram_n[0..sink.ram_count], sink.ram_d[0..sink.ram_count]);
    try appendPairs(&roots, a, sink.other_n[0..sink.other_count], sink.other_d[0..sink.other_count]);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64/native-global-pairs/v1");
    for (Source.Frame.originWords(descriptor.origin)) |tag| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, tag, .little);
        h.update(&b);
    }
    var p = try r.builder.finish(h.finalResult(), roots.items);
    errdefer p.deinit();
    const slots = try a.alloc(u32, p.parameters.len);
    errdefer a.free(slots);
    for (p.parameters, slots) |v, *slot| {
        const words = v.toM31Array();
        for (words[1..]) |w| if (!w.isZero()) return error.InvalidGlobalParameter;
        if (words[0].v == 0 or words[0].v > P.count) return error.InvalidGlobalParameter;
        slot.* = words[0].v - 1;
    }
    return .{ .a = a, .descriptor = descriptor, .program = p, .parameter_slots = slots, .ram_pairs = @intCast((sink.ram_count + 1) / 2), .other_pairs = @intCast((sink.other_count + 1) / 2) };
}
pub fn emit(a: std.mem.Allocator, w: anytype, artifact: *const Artifact, name: []const u8) !void {
    if (name.len == 0 or std.ascii.isDigit(name[0])) return error.InvalidKernelName;
    for (name) |v| if (!std.ascii.isAlphanumeric(v) and v != '_') return error.InvalidKernelName;
    const p = &artifact.program;
    try p.validate();
    const sorts = try p.sorts(a);
    defer a.free(sorts);
    try w.writeAll("#include \"rv64/projection.cuh\"\nusing namespace stwo::cuda::rv64;\n");
    try w.print("extern \"C\" __global__ void {s}(const uint32_t *tree0,const uint32_t *tree1,const uint64_t *offsets,const uint32_t *parameters,uint32_t *numerator,uint32_t *denominator,uint64_t stride,uint32_t rows,uint32_t *status){{\nconst uint32_t row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;switch(blockIdx.y){{\n", .{name});
    for (0..artifact.ram_pairs + artifact.other_pairs) |pair| {
        var subset = p.*;
        subset.roots = p.roots[2 * pair ..][0..2];
        const order = try C.schedule(a, &subset);
        defer a.free(order);
        const denominator_column = pair * 8 + @as(usize, if (pair >= artifact.ram_pairs) 8 else 0);
        try w.print("case {}u:{{\nstore(numerator+{}ull*stride,stride,row,zero());store(denominator+{}ull*stride,stride,row,one());\n", .{ pair, pair * 8, denominator_column });
        for (order) |i| {
            const node = p.nodes[i];
            if (node.op == .input) {
                const input = p.inputs[node.value];
                try w.print("const uint32_t v{}=tree{}[offsets[{}]+row];if(v{}>=q::kPrime){{atomicOr(status,2u);return;}}\n", .{ i, input.tree, node.value, i });
            } else try C.emitValue(w, p, sorts, i);
            for (subset.roots, 0..) |root, which| if (root == i) {
                try w.print("store({s}+{}ull*stride,stride,row,{s}v{}{s});\n", .{ if (which == 0) "numerator" else "denominator", if (which == 0) pair * 8 else denominator_column, if (sorts[i] == .base) "base(" else "", i, if (sorts[i] == .base) ")" else "" });
            };
        }
        try w.writeAll("return;}\n");
    }
    try w.writeAll("default:atomicOr(status,8u);return;}}\n");
}
