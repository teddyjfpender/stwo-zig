//! CPU C emission from an independently checked OM31 coordinate lowering.
//! The source identity is resolved outside this module; no producer programs.
const std = @import("std");
pub fn generate(a: std.mem.Allocator, source: anytype, lowered: anytype, ordinal: usize, w: *std.Io.Writer) !void {
    try source.validate();
    if (!std.mem.eql(u8, &source.identity, &lowered.source_identity) or source.inputs.len != lowered.kinds.len) return error.HybridSourceIdentityMismatch;
    try w.writeAll(@embedFile("prelude.h"));
    try w.writeAll(@embedFile("om31_prelude.h"));
    try w.writeAll(
        \\static inline O hybrid_oq(O a,Q b) {
        \\ Q lo=qm((Q){{a.x[0],a.x[1],a.x[2],a.x[3]}},b);
        \\ Q hi=qm((Q){{a.x[4],a.x[5],a.x[6],a.x[7]}},b);
        \\ return (O){{lo.x[0],lo.x[1],lo.x[2],lo.x[3],hi.x[0],hi.x[1],hi.x[2],hi.x[3]}};
        \\}
        \\
    );
    const sites = try a.alloc(usize, source.inputs.len);
    defer a.free(sites);
    var count: usize = 0;
    for (sites, lowered.kinds) |*site, kind| {
        site.* = count;
        count += switch (kind) {
            .zero => 0,
            .base => 1,
            .secure => 8,
        };
    }
    var offsets: std.ArrayList(i8) = .empty;
    defer offsets.deinit(a);
    for (lowered.nodes) |node| if (node.op == .input) {
        const offset = source.inputs[node.value / 8].offset;
        if (std.mem.indexOfScalar(i8, offsets.items, offset) == null) try offsets.append(a, offset);
    };
    try w.print("\nvoid rv64_hybrid_air_{d}(const ORange *r) {{\n", .{ordinal});
    for (lowered.nodes, lowered.invariant, 0..) |node, fixed, i| if (fixed) try emit(w, node, i, source, sites, offsets.items);
    try w.writeAll("for(size_t row=r->first;row<r->end;row+=4) {\n");
    for (offsets.items, 0..) |offset, i| {
        if (offset == 0) {
            try w.print("size_t p{d}[4]={{row,row+1,row+2,row+3}};\n", .{i});
        } else {
            try w.print("size_t p{d}[4];for(int lane=0;lane<4;lane++)p{d}[lane]=omapped_index(row+lane,r,{d});\n", .{ i, i, offset });
        }
    }
    for (lowered.nodes, lowered.invariant, 0..) |node, fixed, i| if (!fixed) try emit(w, node, i, source, sites, offsets.items);
    try w.writeAll("O acc=oz();\n");
    for (lowered.roots, 0..) |root, i| {
        if (std.mem.allEqual(u32, &root, 0)) continue;
        if (std.mem.allEqual(u32, root[1..], 0)) {
            try w.print("acc=oa(acc,omb(os(r->coefficients+{d}),v{d}));\n", .{ 8 * i, root[0] });
        } else if (std.mem.allEqual(u32, root[4..], 0)) {
            try w.print("acc=oa(acc,hybrid_oq(os(r->coefficients+{d}),(Q){{{{v{d},v{d},v{d},v{d}}}}}));\n", .{ 8 * i, root[0], root[1], root[2], root[3] });
        } else {
            try w.print("acc=oa(acc,om(os(r->coefficients+{d}),(O){{{{", .{8 * i});
            for (root, 0..) |id, j| try w.print("{s}v{d}", .{ if (j == 0) "" else ",", id });
            try w.writeAll("}}));\n");
        }
    }
    try w.writeAll("ostore(r,row,acc);\n}\n}\n");
}
fn emit(w: *std.Io.Writer, node: anytype, index: usize, source: anytype, sites: []const usize, offsets: []const i8) !void {
    try w.print("V v{d}=", .{index});
    switch (node.op) {
        .constant => try w.print("vs({d}U)", .{node.value}),
        .parameter => try w.print("vs(r->parameters[{d}])", .{node.value}),
        .input => {
            const input = source.inputs[node.value / 8];
            const offset = std.mem.indexOfScalar(i8, offsets, input.offset) orelse return error.MissingHybridOffset;
            try w.print("gather(r->sites[{d}],p{d})", .{ sites[node.value / 8] + node.value % 8, offset });
        },
        .add, .sub, .mul => try w.print("{s}(v{d},v{d})", .{ switch (node.op) {
            .add => "va",
            .sub => "vb",
            else => "vm",
        }, node.lhs, node.rhs }),
        .neg => try w.print("vn(v{d})", .{node.lhs}),
    }
    try w.writeAll(";\n");
}
