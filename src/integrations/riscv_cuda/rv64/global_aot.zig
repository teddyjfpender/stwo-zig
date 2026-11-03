//! Production global projection catalog. Only native equation authority enters
//! these kernels; qualification fixture values are never generated or consumed.
const std = @import("std");
const G = @import("global_codegen.zig");
const Catalog = @import("joined_fixture_support.zig");
pub fn name(a: std.mem.Allocator, artifact: *const G.Artifact) ![]u8 {
    return std.fmt.allocPrint(a, "stwo_rv64_global_contiguous_{s}", .{std.fmt.bytesToHex(try artifact.identity(), .lower)});
}
pub fn emit(a: std.mem.Allocator, dir: std.fs.Dir) !void {
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| a.free(n);
        names.deinit(a);
    }
    for (Catalog.descriptors()) |descriptor| {
        if (G.Authority.Global.layout(descriptor.origin).ram_queries == 0) continue;
        var artifact = try G.record(a, descriptor);
        defer artifact.deinit();
        const symbol = try name(a, &artifact);
        defer a.free(symbol);
        const kernel = try std.fmt.allocPrint(a, "{s}_kernel", .{symbol});
        defer a.free(kernel);
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(a);
        const w = text.writer(a);
        try G.emitContiguous(a, w, &artifact, kernel);
        const shape = try G.Authority.shape(descriptor);
        const pairs = artifact.ram_pairs + artifact.other_pairs;
        const width = 8 * (pairs + 1 + @as(u32, @intFromBool(artifact.other_pairs != 0)));
        try w.writeAll("\n#include \"rv64/custody.cuh\"\n");
        try w.print(
            \\extern "C" __attribute__((visibility("default"))) int {s}(void*ctx,uint32_t lane,const uint32_t*fixed,const uint32_t*main,const uint32_t*parameters,uint32_t*n,uint32_t*d,uint32_t*status,uint32_t log){{
            \\if(log<5||log>22)return int(cudaErrorInvalidValue);const uint64_t rows=1ull<<log;
            \\Custody c(ctx,lane);
            \\if(!c.range(fixed,rows*{}ull,false)||!c.range(main,rows*{}ull,false)||!c.range(parameters,{}ull,false)||!c.range(n,rows*{}ull,true)||!c.range(d,rows*{}ull,true)||!c.range(status,1,true))return c.status;
            \\{s}<<<dim3((rows+127)/128,{}u),128,0,c.stream>>>(fixed,main,nullptr,parameters,n,d,rows,uint32_t(rows),status);
            \\return int(cudaPeekAtLastError());}}
            \\
        , .{ symbol, shape.fixed, shape.main, artifact.parameter_slots.len * 8, pairs * 8, width, kernel, pairs });
        const filename = try std.fmt.allocPrint(a, "{s}.cu", .{symbol});
        defer a.free(filename);
        try dir.writeFile(.{ .sub_path = filename, .data = text.items });
        try names.append(a, try a.dupe(u8, symbol));
    }
    const manifest = try std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-resident-global-aot/v1", .symbols = names.items }, .{ .whitespace = .indent_2 });
    defer a.free(manifest);
    try dir.writeFile(.{ .sub_path = "required-symbols.json", .data = manifest });
}
